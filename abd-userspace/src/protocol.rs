//! Core ABD protocol state

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64},
        Arc,
    },
};

use abd_common::{
    message::{AbdRole, ArchivedAbdMessage, ArchivedAbdMessageData},
    tag::AbdTag,
};
use anyhow::Result;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
};

/// Majority helper: ceil(n/2) + 0
#[must_use]
#[inline(always)]
pub const fn majority(n: u32) -> u32 {
    (n >> 1) + 1
}

#[derive(Default)]
pub struct TagAndData {
    pub tag: AbdTag,
    pub data: ArchivedAbdMessageData,
}

#[derive(Default)]
pub struct ReplicaStore {
    pub counters: RwLock<HashMap<(AbdRole, u32), u64>>,
    pub value: Mutex<TagAndData>,
}

#[derive(Default)]
pub struct NodeState {
    pub phase: AtomicU32,   // 0 idle │ 1 query │ 2 prop (3 no longer used)
    pub counter: AtomicU64, // local monotonic per‑op counter
    pub acks: AtomicU32,
    pub tag: Mutex<AbdTag>,
    pub data: Mutex<ArchivedAbdMessageData>,
    pub client: Mutex<Option<SocketAddr>>, // saved client addr or proxy target
}

#[derive(Default)]
pub struct GlobalState {
    pub server: ReplicaStore,
    pub reader: NodeState,
    pub writer: NodeState,
    #[cfg(not(feature = "multi-writer"))]
    pub proxy_client: Mutex<Option<SocketAddr>>,
}

#[derive(Clone)]
pub struct Context {
    pub id: u32,
    pub replicas: u32,
    pub peers: Arc<Vec<SocketAddr>>, // peer[i] = node i+1
    pub socket: Arc<UdpSocket>,
    pub state: Arc<GlobalState>,
}

impl Context {
    pub fn new(
        node_id: u32,
        num_replicas: u32,
        peers: Arc<Vec<SocketAddr>>,
        bind_addr: SocketAddr,
        state: Arc<GlobalState>,
    ) -> Result<Self> {
        let socket = Arc::new(crate::network::create_socket(bind_addr)?);
        Ok(Self {
            id: node_id,
            replicas: num_replicas,
            peers,
            socket,
            state,
        })
    }
}

pub async fn send(sock: &UdpSocket, msg: &ArchivedAbdMessage, peer: SocketAddr) -> Result<()> {
    let ptr = std::ptr::from_ref(msg).cast::<u8>();
    let len = core::mem::size_of::<ArchivedAbdMessage>();
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    sock.send_to(bytes, peer).await?;
    Ok(())
}

pub async fn broadcast(ctx: &Context, msg: &ArchivedAbdMessage) {
    for &peer in ctx.peers.iter() {
        let _ = send(&ctx.socket, msg, peer).await;
    }
}

#[cfg(not(feature = "multi-writer"))]
#[must_use]
#[inline(always)]
pub const fn is_writer(id: u32) -> bool {
    id == 1
}

#[cfg(feature = "multi-writer")]
#[must_use]
#[inline(always)]
pub const fn is_writer(_: u32) -> bool {
    true
}
