//! `abd/src/bin/abd_userspace.rs`
//! ---------------------------------------------------------------------------
//! Userspace ABD replica.
//!
//!  • one `SO_REUSEPORT` UDP socket per physical core
//!  • lock–free receive loop dispatches to   Server / Reader / Writer
//!  • “busy ⇒ drop” semantics, identical to the eBPF implementation
//!
//! Feature flags
//! -------------
//! • *default* (single-writer) – node 1 is the sole writer; all other nodes
//!   proxy client WRITEs to it and forward the resulting ACK.
//! • *multi-writer* – every node may issue writes.
//! ---------------------------------------------------------------------------

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
use anyhow::{bail, Result};
use clap::Parser;
use env_logger::Env;
use log::{debug, error, info, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use rkyv::{access, deserialize, rancor::Error as RkyvError};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    task::JoinSet,
};

/// Majority helper.
#[inline(always)]
const fn majority(n: u32) -> u32 {
    (n >> 1) + 1
}

// ────────────────────────────────────────────────────────────────────────────
// Socket helpers
// ────────────────────────────────────────────────────────────────────────────

fn new_reuseport_socket(local: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};

    let domain = if local.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, None)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&local.into())?;

    Ok(UdpSocket::from_std(sock.into())?)
}

// ────────────────────────────────────────────────────────────────────────────
// Shared data structures
// ────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy)]
struct TagAndData {
    tag: AbdTag,
    data: AbdMessageData,
}

/// Per-node replica store (Server role).
#[derive(Default)]
struct ReplicaStore {
    counters: RwLock<HashMap<(AbdRole, u32), u64>>,
    value: Mutex<TagAndData>,
}

/// Reader state-machine.
#[derive(Default)]
struct Reader {
    phase: AtomicU32,   // 0 idle │ 1 query │ 2 propagate
    counter: AtomicU64, // local monotonic counter
    acks: AtomicU32,
    aggregate: Mutex<TagAndData>, // max(tag) & data from phase-1
    client: Mutex<Option<SocketAddr>>,
}

/// Writer state-machine.
#[derive(Default)]
struct Writer {
    phase: AtomicU32, // 0 idle │ 1 query | 2 propagate │ 3 proxy-wait (single-writer)
    counter: AtomicU64,
    acks: AtomicU32,
    buffer: Mutex<TagAndData>,         // carried between phases
    client: Mutex<Option<SocketAddr>>, // also used for proxy slot
}

#[derive(Default)]
struct NodeState {
    server: ReplicaStore,
    reader: Reader,
    writer: Writer,
}

/// Lightweight context cloned into every async task / handler.
#[derive(Clone)]
struct Ctx {
    id: u32,
    replicas: u32,
    peers: Arc<Vec<SocketAddr>>, // index == node_id-1
    sock: Arc<UdpSocket>,
    state: Arc<NodeState>,
}

// ────────────────────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
struct Cli {
    /// This node’s identifier (1‥=N).
    #[arg(long)]
    node_id: u32,

    /// Total number of replicas.
    #[arg(long)]
    num_nodes: u32,
}

// ────────────────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let Cli { node_id, num_nodes } = Cli::parse();

    if !(1..=num_nodes).contains(&node_id) {
        bail!("--node-id must be in 1‥={num_nodes}");
    }

    // Resolve every node’s IPv4 address (host view).
    let ifaces = NetworkInterface::show()?;
    let peers: Vec<_> = (1..=num_nodes)
        .map(|id| {
            let ip = get_iface_info(&ifaces, &format!("{ABD_IFACE_NODE_PREFIX}{id}"))?.ipv4;
            Ok(SocketAddr::from((ip, ABD_UDP_PORT)))
        })
        .collect::<Result<_>>()?;

    let bind_addr = peers[(node_id - 1) as usize];
    let peers = Arc::new(peers);
    let state = Arc::<NodeState>::default();

    // Spawn one worker per physical core.
    let mut workers = JoinSet::new();
    for core in 0..num_cpus::get() {
        let ctx = Ctx {
            id: node_id,
            replicas: num_nodes,
            peers: peers.clone(),
            sock: Arc::new(new_reuseport_socket(bind_addr)?),
            state: state.clone(),
        };
        workers.spawn(async move {
            if let Err(e) = worker(ctx).await {
                error!("worker #{core} stopped: {e}");
            }
        });
    }

    info!("ABD node {node_id}/{num_nodes} listening on {bind_addr}");
    while workers.join_next().await.is_some() {}
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// High-rate receive loop
// ────────────────────────────────────────────────────────────────────────────

async fn worker(ctx: Ctx) -> Result<()> {
    let mut buf = vec![0u8; 65_536];

    loop {
        let (n, peer) = ctx.sock.recv_from(&mut buf).await?;

        let Ok(msg) = access::<ArchivedAbdMessage, RkyvError>(&buf[..n])
            .and_then(deserialize::<AbdMessage, RkyvError>)
        else {
            warn!("{peer}: malformed ABD message");
            continue;
        };

        match AbdRole::try_from(msg.recipient_role) {
            Ok(AbdRole::Server) => handle_server(&ctx, msg, peer).await,
            Ok(AbdRole::Reader) => handle_reader(&ctx, msg, peer).await,
            Ok(AbdRole::Writer) => handle_writer(&ctx, msg, peer).await,
            #[cfg(not(feature = "multi-writer"))]
            Ok(AbdRole::Client) => handle_proxy_ack(&ctx, msg).await,
            _ => warn!("invalid recipient_role {}", msg.recipient_role),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SERVER role
// ────────────────────────────────────────────────────────────────────────────

async fn handle_server(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    match AbdMessageType::try_from(msg.type_) {
        Ok(AbdMessageType::Read) => srv_on_read(ctx, msg, peer).await,
        Ok(AbdMessageType::Write) => srv_on_write(ctx, msg, peer).await,
        _ => warn!("server: unknown type {}", msg.type_),
    }
}

async fn srv_on_read(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    let Ok(sender_role @ (AbdRole::Reader | AbdRole::Writer)) = AbdRole::try_from(msg.sender_role)
    else {
        return warn!("server: illegal sender_role {}", msg.sender_role);
    };

    // freshness check
    {
        let mut c = ctx.state.server.counters.write().await;
        let ent = c.entry((sender_role, msg.sender_id)).or_default();
        if msg.counter <= *ent {
            return;
        }
        *ent = msg.counter;
    }

    let val = ctx.state.server.value.lock().await;
    let reply = AbdMessage::new(
        msg.counter,
        val.data,
        sender_role,
        ctx.id,
        AbdRole::Server,
        val.tag,
        AbdMessageType::ReadAck,
    );
    drop(val); // unlock
    debug!("server: READ-ACK → {peer}");
    let _ = send(&ctx.sock, &reply, peer).await;
}

async fn srv_on_write(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    let Ok(sender_role @ (AbdRole::Reader | AbdRole::Writer)) = AbdRole::try_from(msg.sender_role)
    else {
        return warn!("server: illegal sender_role {}", msg.sender_role);
    };

    {
        let mut c = ctx.state.server.counters.write().await;
        let ent = c.entry((sender_role, msg.sender_id)).or_default();
        if msg.counter <= *ent {
            return;
        }
        *ent = msg.counter;
    }

    {
        let mut v = ctx.state.server.value.lock().await;
        if tag::gt(msg.tag, v.tag) {
            v.tag = msg.tag;
            v.data = msg.data;
        }
    }

    let ack = AbdMessage::new(
        msg.counter,
        msg.data,
        sender_role,
        ctx.id,
        AbdRole::Server,
        msg.tag,
        AbdMessageType::WriteAck,
    );
    debug!("server: WRITE-ACK → {peer}");
    let _ = send(&ctx.sock, &ack, peer).await;
}

// ────────────────────────────────────────────────────────────────────────────
// READER role
// ────────────────────────────────────────────────────────────────────────────

async fn handle_reader(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    match (
        AbdRole::try_from(msg.sender_role),
        AbdMessageType::try_from(msg.type_),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Read)) => rdr_start(ctx, msg, peer).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => rdr_on_read_ack(ctx, msg).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => rdr_on_write_ack(ctx, msg).await,
        _ => {}
    }
}

async fn rdr_start(ctx: &Ctx, mut req: AbdMessage, client: SocketAddr) {
    let rdr = &ctx.state.reader;
    if rdr
        .phase
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        warn!("reader busy – client READ dropped");
        return;
    }

    rdr.acks.store(0, Ordering::Relaxed);
    rdr.counter.fetch_add(1, Ordering::Relaxed);
    rdr.aggregate.lock().await.tag = 0;
    *rdr.client.lock().await = Some(client);

    req.counter = rdr.counter.load(Ordering::Relaxed);
    req.sender_id = ctx.id;
    req.sender_role = AbdRole::Reader.into();
    req.recipient_role = AbdRole::Server.into();
    req.type_ = AbdMessageType::Read.into();
    req.tag = 0;

    info!("reader: READ from client {client}");
    for &replica in ctx.peers.iter() {
        let _ = send(&ctx.sock, &req, replica).await;
    }
}

async fn rdr_on_read_ack(ctx: &Ctx, ack: AbdMessage) {
    let rdr = &ctx.state.reader;
    if rdr.phase.load(Ordering::Relaxed) != 1 || ack.counter != rdr.counter.load(Ordering::Relaxed)
    {
        return;
    }

    {
        let mut agg = rdr.aggregate.lock().await;
        if tag::gt(ack.tag, agg.tag) {
            agg.tag = ack.tag;
            agg.data = ack.data;
        }
    }
    if rdr.acks.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.replicas) {
        info!(
            "reader: got {} READ-ACKs, waiting for majority ({})",
            rdr.acks.load(Ordering::Relaxed),
            majority(ctx.replicas)
        );
        return;
    }

    // phase-2
    rdr.phase.store(2, Ordering::Relaxed);
    rdr.acks.store(0, Ordering::Relaxed);
    rdr.counter.fetch_add(1, Ordering::Relaxed);

    let agg = rdr.aggregate.lock().await;
    let prop = AbdMessage::new(
        rdr.counter.load(Ordering::Relaxed),
        agg.data,
        AbdRole::Server,
        ctx.id,
        AbdRole::Reader,
        agg.tag,
        AbdMessageType::Write,
    );
    drop(agg);

    info!(
        "reader: propagating tag <{},{}>",
        tag::seq(prop.tag),
        tag::wid(prop.tag)
    );
    for &replica in ctx.peers.iter() {
        let _ = send(&ctx.sock, &prop, replica).await;
    }
}

async fn rdr_on_write_ack(ctx: &Ctx, ack: AbdMessage) {
    let rdr = &ctx.state.reader;
    if rdr.phase.load(Ordering::Relaxed) != 2 || ack.counter != rdr.counter.load(Ordering::Relaxed)
    {
        return;
    }
    if rdr.acks.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.replicas) {
        return;
    }

    rdr.phase.store(0, Ordering::Release);
    let client = rdr.client.lock().await.take();
    let agg = rdr.aggregate.lock().await;

    if let Some(dst) = client {
        let reply = AbdMessage::new(
            0,
            agg.data,
            AbdRole::Client,
            ctx.id,
            AbdRole::Reader,
            agg.tag,
            AbdMessageType::ReadAck,
        );
        drop(agg); // unlock
        info!("reader: READ-ACK → client {dst}");
        let _ = send(&ctx.sock, &reply, dst).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WRITER role
// ────────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "multi-writer"))]
#[inline(always)]
const fn is_writer(node_id: u32) -> bool {
    node_id == 1
}

#[cfg(feature = "multi-writer")]
#[inline(always)]
const fn is_writer(_: u32) -> bool {
    true
}

async fn handle_writer(ctx: &Ctx, msg: AbdMessage, peer: SocketAddr) {
    match (
        AbdRole::try_from(msg.sender_role),
        AbdMessageType::try_from(msg.type_),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Write)) => wtr_start(ctx, msg, peer).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => wtr_on_read_ack(ctx, msg).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => wtr_on_write_ack(ctx, msg).await,
        _ => {}
    }
}

async fn wtr_start(ctx: &Ctx, req: AbdMessage, client: SocketAddr) {
    #[cfg(feature = "multi-writer")]
    let mut req = req;

    let wtr = &ctx.state.writer;

    // -------------------------------------------------- proxy path
    if !is_writer(ctx.id) {
        if wtr
            .phase
            .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            warn!("proxy busy – dropping client WRITE");
            return;
        }
        *wtr.client.lock().await = Some(client);
        info!("proxy: forwarding WRITE from client {client} → writer #1");
        let _ = send(&ctx.sock, &req, ctx.peers[0]).await;
        return;
    }
    // -------------------------------------------------- true writer
    if wtr
        .phase
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        warn!("writer busy – client WRITE dropped");
        return;
    }

    info!("writer: received WRITE from client {client}");

    wtr.acks.store(0, Ordering::Relaxed);
    wtr.counter.fetch_add(1, Ordering::Relaxed);
    *wtr.client.lock().await = Some(client);

    #[cfg(feature = "multi-writer")]
    {
        // phase-1 query
        req.counter = wtr.counter.load(Ordering::Relaxed);
        req.sender_id = ctx.id;
        req.sender_role = AbdRole::Writer.into();
        req.recipient_role = AbdRole::Server.into();
        req.type_ = AbdMessageType::Read.into();
        req.tag = 0;

        {
            let mut buf = wtr.buffer.lock().await;
            buf.data = req.data;
            buf.tag = 0;
        }

        for &replica in ctx.peers.iter() {
            let _ = send(&ctx.sock, &req, replica).await;
        }
    }

    #[cfg(not(feature = "multi-writer"))]
    {
        // choose next tag locally
        let next_tag = {
            let mut buf = wtr.buffer.lock().await;
            buf.tag = tag::pack(tag::seq(buf.tag) + 1, 0);
            buf.tag
        };
        propagate_write(ctx, wtr, &req.data, next_tag).await;
    }
}

#[cfg(feature = "multi-writer")]
async fn wtr_on_read_ack(ctx: &Ctx, ack: AbdMessage) {
    let wtr = &ctx.state.writer;
    if wtr.phase.load(Ordering::Relaxed) != 1 || ack.counter != wtr.counter.load(Ordering::Relaxed)
    {
        return;
    }

    {
        let mut buf = wtr.buffer.lock().await;
        if tag::gt(ack.tag, buf.tag) {
            buf.tag = ack.tag;
        }
    }
    if wtr.acks.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.replicas) {
        info!(
            "writer: got {} READ-ACKs, waiting for majority ({})",
            wtr.acks.load(Ordering::Relaxed),
            majority(ctx.replicas)
        );
        return;
    }

    let (tag, data) = {
        let mut buf = wtr.buffer.lock().await;
        buf.tag = tag::pack(tag::seq(buf.tag) + 1, ctx.id);
        (buf.tag, buf.data)
    };
    propagate_write(ctx, wtr, &data, tag).await;
}

#[cfg(not(feature = "multi-writer"))]
#[allow(clippy::unused_async)]
async fn wtr_on_read_ack(_: &Ctx, _: AbdMessage) { /* never called */
}

async fn propagate_write(ctx: &Ctx, wtr: &Writer, data: &AbdMessageData, tag: AbdTag) {
    wtr.phase.store(2, Ordering::Relaxed);
    wtr.acks.store(0, Ordering::Relaxed);
    wtr.counter.fetch_add(1, Ordering::Relaxed);

    let prop = AbdMessage::new(
        wtr.counter.load(Ordering::Relaxed),
        *data,
        AbdRole::Server,
        ctx.id,
        AbdRole::Writer,
        tag,
        AbdMessageType::Write,
    );

    info!(
        "writer: propagating tag <{},{}>",
        tag::seq(tag),
        tag::wid(tag)
    );
    for &replica in ctx.peers.iter() {
        let _ = send(&ctx.sock, &prop, replica).await;
    }
}

async fn wtr_on_write_ack(ctx: &Ctx, ack: AbdMessage) {
    let wtr = &ctx.state.writer;
    if wtr.phase.load(Ordering::Relaxed) != 2 || ack.counter != wtr.counter.load(Ordering::Relaxed)
    {
        return;
    }
    if wtr.acks.fetch_add(1, Ordering::Relaxed) + 1 < majority(ctx.replicas) {
        return;
    }

    wtr.phase.store(0, Ordering::Release);
    let tag = wtr.buffer.lock().await.tag;
    let maybe_client = wtr.client.lock().await.take();
    if let Some(client) = maybe_client {
        let reply = AbdMessage::new(
            0,
            ack.data,
            AbdRole::Client,
            ctx.id,
            AbdRole::Writer,
            tag,
            AbdMessageType::WriteAck,
        );
        info!("writer: WRITE-ACK → client {client}");
        let _ = send(&ctx.sock, &reply, client).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PROXY ACK handling  (single-writer mode)
// ────────────────────────────────────────────────────────────────────────────
#[cfg(not(feature = "multi-writer"))]
async fn handle_proxy_ack(ctx: &Ctx, msg: AbdMessage) {
    if is_writer(ctx.id) {
        return;
    } // writers never proxy
    if msg.type_ != AbdMessageType::WriteAck as u32 {
        return;
    }

    info!("proxy: received WRITE-ACK from writer #1");

    let wtr = &ctx.state.writer;
    if wtr.phase.load(Ordering::Relaxed) != 3 {
        return;
    }

    let maybe_client = wtr.client.lock().await.take();
    let Some(client) = maybe_client else { return };
    wtr.phase.store(0, Ordering::Release);

    let ack = AbdMessage::new(
        0,
        msg.data,
        AbdRole::Writer,
        msg.sender_id,
        AbdRole::Client,
        msg.tag,
        AbdMessageType::WriteAck,
    );
    info!("proxy: WRITE-ACK → client {client}");
    let _ = send(&ctx.sock, &ack, client).await;
}

// ────────────────────────────────────────────────────────────────────────────
// Serialization helpers
// ────────────────────────────────────────────────────────────────────────────

async fn send(sock: &UdpSocket, msg: &AbdMessage, peer: SocketAddr) -> Result<()> {
    let bytes = rkyv::to_bytes::<RkyvError>(msg)?;
    sock.send_to(&bytes, peer).await?;
    Ok(())
}
