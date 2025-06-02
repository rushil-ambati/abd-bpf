//! Userspace ABD replica – behaviourally identical to the in‑kernel TC + XDP reference
//! -----------------------------------------------------------------------------
//!  • One `SO_REUSEPORT` UDP socket per physical core (Tokio + epoll)
//!  • Exact role/state machine parity with the eBPF implementation
//!  • Single‑writer **default** (node 1 is the writer) and `multi‑writer` feature
//!  • No self‑broadcast, no double tag bump, correct proxy‑forward semantics
//!  • Majority/ACK counting matches kernel side byte‑for‑byte
//! -----------------------------------------------------------------------------

#![allow(clippy::needless_pass_by_value)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
};

use abd::ClusterConfig;
use abd_common::{
    constants::ABD_UDP_PORT,
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage, ArchivedAbdMessageData},
    tag::{self, AbdTag},
};
use anyhow::{bail, Result};
use clap::Parser;
use env_logger::Env;
use log::{info, warn};
use rkyv::{access_mut, rancor, rend::u64_le};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    task::JoinSet,
};

/// Majority helper identical to eBPF: ceil(n/2) + 0
#[inline(always)]
const fn majority(n: u32) -> u32 {
    (n >> 1) + 1
}

// ──────────────────────────────────────────────────────────────────────────
// Socket helper – SO_REUSEPORT, non‑blocking
// ──────────────────────────────────────────────────────────────────────────
fn new_reuseport_socket(bind: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(
        if bind.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

// ──────────────────────────────────────────────────────────────────────────
// Shared state (struct layout mirrors kernel maps)
// ──────────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct TagAndData {
    tag: AbdTag,
    data: ArchivedAbdMessageData,
}

#[derive(Default)]
struct ReplicaStore {
    /// per‑sender counter guard  (key = (role, node id))
    counters: RwLock<HashMap<(AbdRole, u32), u64>>,
    value: Mutex<TagAndData>,
}

#[derive(Default)]
struct NodeState {
    phase: AtomicU32,   // 0 idle │ 1 query │ 2 prop │ 3 proxy‑wait
    counter: AtomicU64, // local monotonic per‑op counter
    acks: AtomicU32,
    tag: Mutex<AbdTag>,
    data: Mutex<ArchivedAbdMessageData>,
    client: Mutex<Option<SocketAddr>>, // saved client addr or proxy target
}

#[derive(Default)]
struct GlobalState {
    server: ReplicaStore,
    reader: NodeState,
    writer: NodeState,
}

#[derive(Clone)]
struct Ctx {
    id: u32,
    replicas: u32,
    peers: Arc<Vec<SocketAddr>>, // peer[i] = node i+1
    sock: Arc<UdpSocket>,
    state: Arc<GlobalState>,
}

// ──────────────────────────────────────────────────────────────────────────
// CLI
// ──────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    node_id: u32,
    #[arg(long)]
    config: String,
}

// ──────────────────────────────────────────────────────────────────────────
//  main
// ──────────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let Cli { node_id, config } = Cli::parse();

    let cfg = ClusterConfig::load_from_file(&config)?;
    if !(1..=cfg.num_nodes).contains(&node_id) {
        bail!("--node-id must be in 1..={}", cfg.num_nodes);
    }

    let peers: Vec<_> = cfg
        .nodes
        .iter()
        .map(|n| SocketAddr::from((n.ipv4, ABD_UDP_PORT)))
        .collect();
    let bind = peers[(node_id - 1) as usize];

    let mut workers = JoinSet::new();
    let gstate = Arc::<GlobalState>::default();
    let peers = Arc::new(peers);

    for core in 0..num_cpus::get() {
        let ctx = Ctx {
            id: node_id,
            replicas: cfg.num_nodes,
            peers: peers.clone(),
            sock: Arc::new(new_reuseport_socket(bind)?),
            state: gstate.clone(),
        };
        workers.spawn(async move {
            if let Err(e) = run_worker(ctx).await {
                warn!("worker #{core} terminated: {e}");
            }
        });
    }

    info!("ABD node {node_id}/{} listening on {bind}", cfg.num_nodes);
    while workers.join_next().await.is_some() {}
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Fast receive loop
// ──────────────────────────────────────────────────────────────────────────
async fn run_worker(ctx: Ctx) -> Result<()> {
    let mut buf = vec![0u8; 65_536].into_boxed_slice();
    loop {
        let (n, peer) = ctx.sock.recv_from(&mut buf).await?;
        // Safety: packet is always exactly ArchivedAbdMessage size
        let msg = access_mut::<ArchivedAbdMessage, rancor::Error>(&mut buf[..n])?.unseal();

        match AbdRole::try_from(msg.recipient_role.to_native()) {
            Ok(AbdRole::Server) => handle_server(&ctx, msg, peer).await,
            Ok(AbdRole::Reader) => handle_node(&ctx, msg, peer, AbdRole::Reader).await,
            Ok(AbdRole::Writer) => handle_node(&ctx, msg, peer, AbdRole::Writer).await,
            #[cfg(not(feature = "multi-writer"))]
            Ok(AbdRole::Client) => proxy_ack(&ctx, msg).await,
            _ => {}
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  SERVER role (identical to XDP path)
// ──────────────────────────────────────────────────────────────────────────
async fn freshness_pass(store: &ReplicaStore, sender_role: AbdRole, sender: u32, c: u64) -> bool {
    let mut guard = store.counters.write().await;
    let cur = guard.entry((sender_role, sender)).or_default();
    if c <= *cur {
        return false;
    }
    *cur = c;
    true
}

async fn handle_server(ctx: &Ctx, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    let Ok(mtype) = AbdMessageType::try_from(msg.type_.to_native()) else {
        return;
    };
    let Ok(s_role @ (AbdRole::Reader | AbdRole::Writer)) =
        AbdRole::try_from(msg.sender_role.to_native())
    else {
        return;
    };

    if !freshness_pass(
        &ctx.state.server,
        s_role,
        msg.sender_id.to_native(),
        msg.counter.to_native(),
    )
    .await
    {
        return;
    }

    match mtype {
        AbdMessageType::Read => server_read(ctx, msg, peer).await,
        AbdMessageType::Write => server_write(ctx, msg, peer).await,
        _ => {}
    }
}

async fn server_read(ctx: &Ctx, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    let val = ctx.state.server.value.lock().await;
    msg.data = val.data.clone();
    msg.tag = val.tag.into();
    drop(val);

    msg.recipient_role = msg.sender_role;
    msg.sender_role = AbdRole::Server.into();
    msg.sender_id = ctx.id.into();
    msg.type_ = AbdMessageType::ReadAck.into();

    let _ = send(&ctx.sock, msg, peer).await;
}

async fn server_write(ctx: &Ctx, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    {
        let mut v = ctx.state.server.value.lock().await;
        if tag::gt(msg.tag.into(), v.tag) {
            v.tag = msg.tag.into();
            v.data = msg.data.clone();
        }
    }

    msg.recipient_role = msg.sender_role;
    msg.sender_role = AbdRole::Server.into();
    msg.sender_id = ctx.id.into();
    msg.type_ = AbdMessageType::WriteAck.into();
    let _ = send(&ctx.sock, msg, peer).await;
}

// ──────────────────────────────────────────────────────────────────────────
//  NODE (Reader / Writer)
// ──────────────────────────────────────────────────────────────────────────
async fn handle_node(ctx: &Ctx, msg: &mut ArchivedAbdMessage, peer: SocketAddr, role: AbdRole) {
    match (
        AbdRole::try_from(msg.sender_role.to_native()),
        AbdMessageType::try_from(msg.type_.to_native()),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Read)) if role == AbdRole::Reader => {
            start_op(ctx, msg, peer, role).await;
        }
        (Ok(AbdRole::Client), Ok(AbdMessageType::Write)) if role == AbdRole::Writer => {
            start_op(ctx, msg, peer, role).await;
        }
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => on_read_ack(ctx, msg, role).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => on_write_ack(ctx, msg, role).await,
        _ => {}
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  Writer / Reader START  (phase‑0 → phase‑1/2)
// ──────────────────────────────────────────────────────────────────────────
async fn start_op(ctx: &Ctx, msg: &mut ArchivedAbdMessage, client: SocketAddr, role: AbdRole) {
    if role == AbdRole::Writer && !is_writer(ctx.id) {
        // ───── proxy to writer node #1 ─────
        proxy_forward(ctx, msg, client).await;
        return;
    }

    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };

    #[cfg(not(feature = "multi-writer"))]
    // single-writer mode directly propagates
    let new_phase = if role == AbdRole::Writer { 2 } else { 1 };
    #[cfg(feature = "multi-writer")]
    let new_phase = 1;

    if st
        .phase
        .compare_exchange(0, new_phase, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        warn!("{role:?} busy – drop");
        return;
    }

    st.acks.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    *st.client.lock().await = Some(client);

    // tag & data bookkeeping
    let init_tag = if role == AbdRole::Writer {
        #[cfg(not(feature = "multi-writer"))]
        {
            let mut t = ctx.state.server.value.lock().await;
            t.tag = tag::pack(tag::seq(t.tag) + 1, 0);
            t.tag
        }
        #[cfg(feature = "multi-writer")]
        {
            tag::pack(0, ctx.id)
        }
    } else {
        0
    };
    *st.tag.lock().await = init_tag;
    #[cfg(feature = "multi-writer")]
    {
        if role == AbdRole::Writer {
            // store data to propagate later
            *st.data.lock().await = msg.data.clone();
        }
    }

    if role == AbdRole::Writer {
        #[cfg(not(feature = "multi-writer"))]
        {
            // single‑writer - propagate straight away (WRITE)
            build_write(ctx, msg, init_tag, st.counter.load(Ordering::Relaxed));
        }
        #[cfg(feature = "multi-writer")]
        {
            // multi‑writer – phase‑1 query (READ)
            build_read_query(ctx, msg, st.counter.load(Ordering::Relaxed), role);
        }
    } else {
        // reader – phase‑1 query (READ)
        build_read_query(ctx, msg, st.counter.load(Ordering::Relaxed), role);
    }

    broadcast(ctx, msg).await;
}

#[inline(always)]
fn build_read_query(ctx: &Ctx, m: &mut ArchivedAbdMessage, counter: u64, role: AbdRole) {
    m.counter = counter.into();
    m.recipient_role = AbdRole::Server.into();
    m.sender_role = role.into();
    m.sender_id = ctx.id.into();
    m.type_ = AbdMessageType::Read.into();
    m.tag = 0.into();
}

#[cfg(not(feature = "multi-writer"))]
#[inline(always)]
fn build_write(ctx: &Ctx, m: &mut ArchivedAbdMessage, tag: AbdTag, counter: u64) {
    m.counter = counter.into();
    m.recipient_role = AbdRole::Server.into();
    m.sender_role = AbdRole::Writer.into();
    m.sender_id = ctx.id.into();
    m.type_ = AbdMessageType::Write.into();
    m.tag = tag.into();
}

async fn broadcast(ctx: &Ctx, msg: &ArchivedAbdMessage) {
    for &peer in ctx.peers.iter() {
        let _ = send(&ctx.sock, msg, peer).await;
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  Proxy ‑ forward WRITE to writer#1
// ──────────────────────────────────────────────────────────────────────────
async fn proxy_forward(ctx: &Ctx, msg: &mut ArchivedAbdMessage, client: SocketAddr) {
    let st = &ctx.state.writer;
    st.phase.store(3, Ordering::Release);
    *st.client.lock().await = Some(client);

    msg.sender_id = ctx.id.into(); // proxy id
                                   // sender_role stays Client, recipient_role stays Writer (unchanged)
    let writer = ctx.peers[0]; // node 1
    let _ = send(&ctx.sock, msg, writer).await;
}

// ──────────────────────────────────────────────────────────────────────────
//  READ‑ACK  (phase‑1 → phase‑2)
// ──────────────────────────────────────────────────────────────────────────
async fn on_read_ack(ctx: &Ctx, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };
    if st.phase.load(Ordering::Acquire) != 1
        || msg.counter != u64_le::from(st.counter.load(Ordering::Relaxed))
    {
        return;
    }

    {
        let mut tag = st.tag.lock().await;
        let mut data = st.data.lock().await;
        if tag::gt(msg.tag.into(), *tag) {
            *tag = msg.tag.into();
            if role == AbdRole::Reader {
                *data = msg.data.clone();
            }
        }
    }

    if st.acks.fetch_add(1, Ordering::AcqRel) + 1 < majority(ctx.replicas) {
        return;
    }

    // majority – enter phase‑2 propagate
    st.phase.store(2, Ordering::Release);
    st.acks.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    let max_tag = *st.tag.lock().await;
    let prop_tag = if role == AbdRole::Reader {
        max_tag
    } else {
        tag::pack(tag::seq(max_tag) + 1, ctx.id)
    };
    let data = st.data.lock().await.clone();

    msg.counter = st.counter.load(Ordering::Relaxed).into();
    msg.data = data;
    msg.recipient_role = AbdRole::Server.into();
    msg.sender_role = role.into();
    msg.sender_id = ctx.id.into();
    msg.tag = prop_tag.into();
    msg.type_ = AbdMessageType::Write.into();

    broadcast(ctx, msg).await;
}

// ──────────────────────────────────────────────────────────────────────────
//  WRITE‑ACK (phase‑2 → commit)
// ──────────────────────────────────────────────────────────────────────────
async fn on_write_ack(ctx: &Ctx, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };
    if st.phase.load(Ordering::Acquire) != 2
        || msg.counter != u64_le::from(st.counter.load(Ordering::Relaxed))
    {
        return;
    }
    if st.acks.fetch_add(1, Ordering::AcqRel) + 1 < majority(ctx.replicas) {
        return;
    }
    st.phase.store(0, Ordering::Release);

    // send ACK to client
    let value = st.client.lock().await.take();
    if let Some(client) = value {
        msg.counter = 0.into();
        msg.recipient_role = AbdRole::Client.into();
        msg.sender_role = role.into();
        msg.sender_id = ctx.id.into();
        // tag an data are the same as in the WRITE
        if role == AbdRole::Reader {
            msg.type_ = AbdMessageType::ReadAck.into();
        }

        let _ = send(&ctx.sock, msg, client).await;
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  PROXY path (single‑writer)
// ──────────────────────────────────────────────────────────────────────────
#[cfg(not(feature = "multi-writer"))]
async fn proxy_ack(ctx: &Ctx, msg: &mut ArchivedAbdMessage) {
    if ctx.id == 1 || msg.type_.to_native() != AbdMessageType::WriteAck as u32 {
        return;
    }
    let st = &ctx.state.writer;
    if st.phase.load(Ordering::Acquire) != 3 {
        return;
    }
    let value = st.client.lock().await.take();
    if let Some(client) = value {
        st.phase.store(0, Ordering::Release);
        msg.recipient_role = AbdRole::Client.into();
        msg.sender_role = AbdRole::Writer.into();
        let _ = send(&ctx.sock, msg, client).await;
    }
}

// ──────────────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────────────
#[cfg(not(feature = "multi-writer"))]
#[inline(always)]
const fn is_writer(id: u32) -> bool {
    id == 1
}
#[cfg(feature = "multi-writer")]
#[inline(always)]
const fn is_writer(_: u32) -> bool {
    true
}

async fn send(sock: &UdpSocket, msg: &ArchivedAbdMessage, peer: SocketAddr) -> Result<()> {
    let ptr = std::ptr::from_ref(msg).cast::<u8>();
    let len = core::mem::size_of::<ArchivedAbdMessage>();
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    sock.send_to(bytes, peer).await?;
    Ok(())
}
