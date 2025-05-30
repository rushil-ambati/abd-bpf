//! abd/src/bin/abd_userspace.rs
//! -------------------------------------------------------------------------
//! High-performance userspace ABD node.
//!   • One SO_REUSEPORT socket per CPU core
//!   • Each worker parses and immediately tokio::spawn's the packet handler
//! -------------------------------------------------------------------------

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
};

use abd::get_iface_info;
use abd_common::{
    constants::{ABD_IFACE_NODE_PREFIX, ABD_UDP_PORT},
    message::{AbdMessage, AbdMessageData, AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag::{self, AbdTag},
};
use anyhow::{bail, Context, Result};
use clap::Parser;
use env_logger::Env;
use log::{info, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use rkyv::{
    access, deserialize,
    rancor::{self, Error as RkyvError},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    task::JoinSet,
};

pub fn new_udp_reuseport(local_addr: SocketAddr) -> Result<UdpSocket> {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )
    .context("failed to create socket")?;
    udp_sock
        .set_reuse_port(true)
        .context("failed to set SO_REUSEPORT")?;
    // from tokio-rs/mio/blob/master/src/sys/unix/net.rs
    udp_sock
        .set_cloexec(true)
        .context("failed to set CLOEXEC")?;
    udp_sock
        .set_nonblocking(true)
        .context("failed to set non-blocking")?;
    udp_sock
        .bind(&socket2::SockAddr::from(local_addr))
        .context("failed to bind socket")?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    let tokio_udp_sock = UdpSocket::from_std(udp_sock)
        .context("failed to convert std::net::UdpSocket to tokio::net::UdpSocket")?;
    Ok(tokio_udp_sock)
}

#[derive(Default)]
pub struct TaggedData {
    pub tag: AbdTag,
    pub data: AbdMessageData,
}

/// Replica-server state (one per node)
#[derive(Default)]
struct ServerState {
    /// (<role,node>) ▷ last observed counter
    counters: RwLock<HashMap<(AbdRole, u32), u64>>,
    /// Stored ⟨tag, data⟩ pair
    storage: Mutex<TaggedData>,
}

// --------------  READER  ---------------------------------------------------
#[derive(Default)]
struct ReaderState {
    status: AtomicU32,  // 0 idle │ 1 query │ 2 propagate
    counter: AtomicU64, // local op-counter
    ack_count: AtomicU32,
    max: Mutex<TaggedData>, // ⟨largest-tag, data⟩ seen in phase-1
    client: Mutex<Option<SocketAddr>>,
}

// --------------  WRITER  ---------------------------------------------------
#[derive(Default)]
struct WriterState {
    status: AtomicU32, // 0 idle │ 1 query │ 2 propagate
    counter: AtomicU64,
    ack_count: AtomicU32,
    buf: Mutex<TaggedData>, // (multi-writer) data kept between phases
    client: Mutex<Option<SocketAddr>>,
}

#[derive(Default)]
struct NodeState {
    server: ServerState,
    reader: ReaderState,
    writer: WriterState,
}

/// Everything a handler needs
#[derive(Clone)]
struct Ctx {
    id: u32,
    num_nodes: u32,
    peers: Arc<Vec<SocketAddr>>,
    sock: Arc<UdpSocket>,
    state: Arc<NodeState>,
}

#[derive(Parser, Debug)]
struct Args {
    /// This node’s ID (1 ≤ id ≤ N)
    #[arg(long)]
    node_id: u32,
    /// Total number of replicas
    #[arg(long)]
    num_nodes: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let Args { node_id, num_nodes } = Args::parse();

    if !(1..=num_nodes).contains(&node_id) {
        bail!("--node-id must be in 1..=num_nodes");
    }

    // --- build *read-only* peer list --------------------------------------
    let ifaces = NetworkInterface::show()?;
    let peers: Vec<_> = (1..=num_nodes)
        .map(|n| {
            SocketAddr::from((
                get_iface_info(&ifaces, &format!("{ABD_IFACE_NODE_PREFIX}{n}"))
                    .unwrap()
                    .ipv4,
                ABD_UDP_PORT,
            ))
        })
        .collect();

    // get my address from the list
    let bind_addr = peers
        .get((node_id - 1) as usize)
        .context("my address not found in peers list")?
        .clone();

    // --- spin one worker per physical core --------------------------------
    let state = Arc::<NodeState>::default();
    let peers = Arc::new(peers);
    let mut workers = JoinSet::new();

    for _core in 0..num_cpus::get() {
        let ctx = Ctx {
            id: node_id,
            num_nodes,
            peers: peers.clone(),
            sock: Arc::new(new_udp_reuseport(bind_addr)?),
            state: state.clone(),
        };
        workers.spawn(worker(ctx));
    }

    info!("node {node_id} listening on {bind_addr}");

    // join forever (propagate panics)
    while let Some(res) = workers.join_next().await {
        if let Err(e) = res? {
            bail!("worker error: {e}");
        }
    }
    Ok(())
}

async fn worker(ctx: Ctx) -> Result<()> {
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer) = ctx.sock.recv_from(&mut buf).await?;
        let msg = match parse_msg(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                warn!("{peer}: {e}");
                continue;
            }
        };

        match AbdRole::try_from(msg.recipient_role) {
            Ok(AbdRole::Server) => handle_server(&ctx, msg, peer).await,
            Ok(AbdRole::Reader) => handle_reader(&ctx, msg, peer).await,
            Ok(AbdRole::Writer) => handle_writer(&ctx, msg, peer).await,
            _ => warn!("unknown recipient role {}", msg.recipient_role),
        }
    }
}

async fn handle_server(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    use AbdMessageType::*;

    let sender_role = match AbdRole::try_from(msg.sender_role) {
        Ok(r @ (AbdRole::Reader | AbdRole::Writer)) => r,
        _ => return warn!("server: illegal sender_role {}", msg.sender_role),
    };

    match AbdMessageType::try_from(msg.type_) {
        Ok(Read) => server_read(&ctx, msg, peer, sender_role).await,
        Ok(Write) => server_write(&ctx, msg, peer, sender_role).await,
        _ => warn!("server: unexpected msg.type {}", msg.type_),
    }
}

async fn server_read(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr, sender_role: AbdRole) {
    let sender_id = msg.sender_id;
    info!("Server@{}  READ  from {} ({sender_role:?})", ctx.id, peer);

    // --- (1) counter freshness check --------------------------------------
    {
        let mut map = ctx.state.server.counters.write().await;
        let entry = map.entry((sender_role, sender_id)).or_default();
        if msg.counter <= *entry {
            warn!("Server: stale counter {:?} ≤ {:?}", msg.counter, *entry);
            return;
        }
        *entry = msg.counter;
    }

    // --- (2) build ReadAck -------------------------------------------------
    let store = ctx.state.server.storage.lock().await;
    info!(
        "Server@{}  ReadAck: tag={} data={}",
        ctx.id, store.tag, store.data
    );
    let reply = AbdMessage::new(
        msg.counter,
        store.data,
        sender_role, // back to original actor
        ctx.id,
        AbdRole::Server,
        store.tag,
        AbdMessageType::ReadAck,
    );
    drop(store); // release lock before sending

    if let Err(e) = send(&ctx.sock, &reply, peer).await {
        warn!("Server: send ReadAck -> {peer} failed: {e:?}");
    }
}

async fn server_write(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr, sender_role: AbdRole) {
    let sender_id = msg.sender_id;
    info!("Server@{}  WRITE from {} ({sender_role:?})", ctx.id, peer);

    // (1) counter check
    {
        let mut map = ctx.state.server.counters.write().await;
        let entry = map.entry((sender_role, sender_id)).or_default();
        if msg.counter <= *entry {
            warn!("Server: stale counter");
            return;
        }
        *entry = msg.counter;
    }

    // (2) maybe update stored ⟨tag,data⟩
    {
        let mut store = ctx.state.server.storage.lock().await;
        if tag::gt(msg.tag, store.tag) {
            store.tag = msg.tag;
            store.data = msg.data;
        }
    }

    // (3) WriteAck
    let reply = AbdMessage::new(
        msg.counter,
        msg.data,
        sender_role,
        ctx.id,
        AbdRole::Server,
        msg.tag,
        AbdMessageType::WriteAck,
    );
    if let Err(e) = send(&ctx.sock, &reply, peer).await {
        warn!("Server: send WriteAck -> {peer} failed: {e:?}");
    }
}

async fn handle_reader(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    match (
        AbdRole::try_from(msg.sender_role),
        AbdMessageType::try_from(msg.type_),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Read)) => rdr_start(ctx, msg, peer).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => rdr_on_readack(ctx, msg).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => rdr_on_writeack(ctx, msg).await,
        _ => {}
    }
}

// start Phase-1 (Client → Reader)
async fn rdr_start(ctx: &Ctx, mut msg: AbdMessage, client: SocketAddr) {
    let st = &ctx.state.reader;

    if st.status.load(Ordering::Relaxed) != 0 {
        warn!("reader busy – dropping");
        return;
    }
    st.status.store(1, Ordering::Relaxed);
    st.ack_count.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    st.max.lock().await.tag = 0;
    *st.client.lock().await = Some(client);

    // broadcast READ
    msg.counter = st.counter.load(Ordering::Relaxed);
    msg.sender_id = ctx.id;
    msg.sender_role = AbdRole::Reader.into();
    msg.recipient_role = AbdRole::Server.into();
    msg.type_ = AbdMessageType::Read.into();
    msg.tag = 0;

    for &p in ctx.peers.iter() {
        let _ = send(&ctx.sock, &msg, p).await;
    }
}

// handle R-ACKs during Phase-1
async fn rdr_on_readack(ctx: &Ctx, ack: AbdMessage) {
    let st = &ctx.state.reader;
    if st.status.load(Ordering::Relaxed) != 1 {
        return;
    }
    if ack.counter != st.counter.load(Ordering::Relaxed) {
        return;
    }

    info!("Reader@{}  READ ACK from {}", ctx.id, ack.sender_id);

    {
        let mut max = st.max.lock().await;
        if tag::gt(ack.tag, max.tag) {
            max.tag = ack.tag;
            max.data = ack.data;
        }
    }
    if st.ack_count.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.num_nodes) {
        return;
    }

    // ── phase-2 ───────────────────────────────────────────────────────────
    st.status.store(2, Ordering::Relaxed);
    st.ack_count.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);

    let max = st.max.lock().await;
    let prop = AbdMessage::new(
        st.counter.load(Ordering::Relaxed),
        max.data,
        AbdRole::Server,
        ctx.id,
        AbdRole::Reader,
        max.tag,
        AbdMessageType::Write,
    );
    drop(max);

    for &p in ctx.peers.iter() {
        let _ = send(&ctx.sock, &prop, p).await;
    }
}

// handle W-ACKs during Phase-2
async fn rdr_on_writeack(ctx: &Ctx, ack: AbdMessage) {
    let st = &ctx.state.reader;
    if st.status.load(Ordering::Relaxed) != 2 {
        return;
    }
    if ack.counter != st.counter.load(Ordering::Relaxed) {
        return;
    }
    if st.ack_count.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.num_nodes) {
        return;
    }

    // ── done, reply to client ─────────────────────────────────────────────
    let max = st.max.lock().await;
    let client = st.client.lock().await.take();
    st.status.store(0, Ordering::Relaxed); // idle again

    if let Some(dst) = client {
        let reply = AbdMessage::new(
            0,
            max.data,
            AbdRole::Reader,
            ctx.id,
            AbdRole::Client,
            max.tag,
            AbdMessageType::ReadAck,
        );
        let _ = send(&ctx.sock, &reply, dst).await;
    }
}

async fn handle_writer(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    match (
        AbdRole::try_from(msg.sender_role),
        AbdMessageType::try_from(msg.type_),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Write)) => wtr_start(ctx, msg, peer).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => wtr_on_readack(ctx, msg).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => wtr_on_writeack(ctx, msg).await,
        _ => {}
    }
}

#[cfg(not(feature = "multi-writer"))]
fn is_writer(id: u32) -> bool {
    id == 1
}
#[cfg(feature = "multi-writer")]
fn is_writer(_: u32) -> bool {
    true
}

async fn wtr_start(ctx: &Ctx, msg: AbdMessage, client: SocketAddr) {
    if !is_writer(ctx.id) {
        return;
    }
    info!("Writer@{}  WRITE from {}", ctx.id, client);
    let st = &ctx.state.writer;
    if st.status.load(Ordering::Relaxed) != 0 {
        warn!("writer busy");
        return;
    }

    st.status.store(1, Ordering::Relaxed);
    st.ack_count.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    *st.client.lock().await = Some(client);

    #[cfg(feature = "multi-writer")]
    {
        // phase-1 query identical to Reader
        msg.counter = st.counter.load(Ordering::Relaxed);
        msg.sender_id = ctx.id;
        msg.sender_role = AbdRole::Writer.into();
        msg.recipient_role = AbdRole::Server.into();
        msg.type_ = AbdMessageType::Read.into();
        msg.tag = 0;

        for &p in ctx.peers.iter() {
            let _ = send(&ctx.sock, &msg, p).await;
        }
    }

    #[cfg(not(feature = "multi-writer"))]
    {
        // single-writer: skip query, go straight to propagation
        let tag = {
            let mut buf = st.buf.lock().await;
            buf.tag = tag::pack(tag::seq(buf.tag) + 1, 0);
            buf.tag
        };
        propagate(ctx, st, msg.data, tag).await;
    }

    #[cfg(feature = "multi-writer")]
    {
        // stash the data until phase-2
        let mut buf = st.buf.lock().await;
        buf.data = msg.data;
    }
}

async fn wtr_on_readack(ctx: &Ctx, ack: AbdMessage) {
    #[cfg(not(feature = "multi-writer"))]
    {
        return;
    } // never happens
    let st = &ctx.state.writer;
    if st.status.load(Ordering::Relaxed) != 1 {
        return;
    }
    if st.counter.load(Ordering::Relaxed) != ack.counter {
        return;
    }

    {
        let mut buf = st.buf.lock().await;
        if tag::gt(ack.tag, buf.tag) {
            buf.tag = ack.tag;
        }
    }
    if st.ack_count.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.num_nodes) {
        return;
    }

    // build new tag (> any seen)
    let tag = {
        let mut buf = st.buf.lock().await;
        buf.tag = tag::pack(tag::seq(buf.tag) + 1, ctx.id);
        buf.tag
    };
    let data = st.buf.lock().await.data;
    propagate(ctx, st, data, tag).await;
}

async fn propagate(ctx: &Ctx, st: &WriterState, data: AbdMessageData, tag: AbdTag) {
    st.status.store(2, Ordering::Relaxed);
    st.ack_count.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);

    let msg = AbdMessage::new(
        st.counter.load(Ordering::Relaxed),
        data,
        AbdRole::Server,
        ctx.id,
        AbdRole::Writer,
        tag,
        AbdMessageType::Write,
    );
    for &p in ctx.peers.iter() {
        info!("Writer@{}  propagating WRITE to {}", ctx.id, p);
        let _ = send(&ctx.sock, &msg, p).await;
    }
}

async fn wtr_on_writeack(ctx: &Ctx, ack: AbdMessage) {
    info!("Writer@{}  WRITE ACK from {}", ctx.id, ack.sender_id);

    let st = &ctx.state.writer;
    if st.status.load(Ordering::Relaxed) != 2 {
        return;
    }
    if ack.counter != st.counter.load(Ordering::Relaxed) {
        return;
    }
    if st.ack_count.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.num_nodes) {
        return;
    }

    st.status.store(0, Ordering::Relaxed); // idle
    let tag = {
        let buf = st.buf.lock().await;
        buf.tag
    };
    if let Some(dst) = st.client.lock().await.take() {
        let reply = AbdMessage::new(
            0,
            ack.data,
            AbdRole::Writer,
            ctx.id,
            AbdRole::Client,
            tag,
            AbdMessageType::WriteAck,
        );
        let _ = send(&ctx.sock, &reply, dst).await;
    }
}

fn parse_msg(pkt: &[u8]) -> Result<AbdMessage, &'static str> {
    let a = access::<ArchivedAbdMessage, RkyvError>(pkt).map_err(|_| "rkyv")?;
    deserialize::<AbdMessage, rancor::Error>(a).map_err(|_| "deserialize")
}

async fn send(sock: &UdpSocket, msg: &AbdMessage, peer: SocketAddr) -> Result<()> {
    let bytes = rkyv::to_bytes::<RkyvError>(msg)?;
    sock.send_to(&bytes, peer).await?;
    Ok(())
}

#[inline]
fn majority(n: u32) -> u32 {
    (n >> 1) + 1
}
