//! Core ABD protocol definitions and state management
//!
//! This module contains the fundamental types and state structures that implement
//! the ABD protocol, including message handling, tag management, and
//! state machine coordination.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
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

/// Node identifier type (1-based indexing as per ABD protocol)
pub type NodeId = u32;

/// Calculate majority threshold for ABD protocol: ceil(n/2)
/// This matches the eBPF implementation exactly
#[inline(always)]
#[must_use]
pub const fn majority(n: u32) -> u32 {
    (n >> 1) + 1
}

pub type Majority = fn(u32) -> u32;

/// Configuration for the ABD cluster
#[derive(Debug, Clone)]
pub struct Config {
    inner: abd::ClusterConfig,
}

impl Config {
    /// Load configuration from a JSON file
    pub fn from_file(path: &str) -> Result<Self> {
        Ok(Self {
            inner: abd::ClusterConfig::load_from_file(path)?,
        })
    }

    /// Get the total number of nodes in the cluster
    #[must_use]
    pub const fn num_nodes(&self) -> u32 {
        self.inner.num_nodes
    }

    /// Get the socket address for a specific node
    pub fn node_address(&self, node_id: NodeId) -> Result<SocketAddr> {
        if !(1..=self.num_nodes()).contains(&node_id) {
            anyhow::bail!("Invalid node_id: {}", node_id);
        }

        let node = &self.inner.nodes[(node_id - 1) as usize];
        Ok(SocketAddr::from((
            node.ipv4,
            abd_common::constants::ABD_UDP_PORT,
        )))
    }

    /// Get all node addresses in the cluster
    pub fn all_addresses(&self) -> Result<Vec<SocketAddr>> {
        self.inner
            .nodes
            .iter()
            .map(|n| {
                Ok(SocketAddr::from((
                    n.ipv4,
                    abd_common::constants::ABD_UDP_PORT,
                )))
            })
            .collect()
    }
}

/// Combined tag and data storage matching the eBPF map structure
#[derive(Default, Debug)]
pub struct TaggedData {
    pub tag: AbdTag,
    pub data: ArchivedAbdMessageData,
}

/// Server replica state that mirrors the eBPF server maps
#[derive(Default, Debug)]
pub struct ReplicaStore {
    /// Freshness counters by (`sender_role`, `sender_id`) to prevent replay attacks
    /// This directly mirrors the `server_counters` BPF map
    counters: RwLock<HashMap<(AbdRole, u32), u64>>,

    /// Current stored value with its associated tag
    /// This mirrors the `server_store` BPF map
    value: Mutex<TaggedData>,
}

impl ReplicaStore {
    /// Check if a message passes the freshness test and update counter if so
    /// Returns true if the message is fresh (counter > stored counter)
    pub async fn check_and_update_freshness(
        &self,
        sender_role: AbdRole,
        sender_id: u32,
        counter: u64,
    ) -> bool {
        let mut counters = self.counters.write().await;
        let current = counters.entry((sender_role, sender_id)).or_insert(0);

        if counter <= *current {
            return false;
        }

        *current = counter;
        true
    }

    /// Get the current stored value and tag
    pub async fn get_value(&self) -> TaggedData {
        let value = self.value.lock().await;
        TaggedData {
            tag: value.tag,
            data: value.data.clone(),
        }
    }

    /// Update the stored value and tag
    pub async fn set_value(&self, tag: AbdTag, data: ArchivedAbdMessageData) {
        let mut value = self.value.lock().await;
        value.tag = tag;
        value.data = data;
    }
}

/// Node state for reader/writer operations
/// This mirrors the `node_state` BPF maps
#[derive(Default, Debug)]
pub struct NodeState {
    /// Current operation phase:
    /// - 0: idle
    /// - 1: query phase (collecting R-ACKs)
    /// - 2: propagation phase (collecting W-ACKs)
    /// - 3: proxy wait (single-writer mode only)
    pub phase: AtomicU32,

    /// Monotonic counter for this node's operations
    pub counter: AtomicU64,

    /// Number of acknowledgments received in current phase
    pub acks: AtomicU32,

    /// Current operation's tag
    pub tag: Mutex<AbdTag>,

    /// Current operation's data
    pub data: Mutex<ArchivedAbdMessageData>,

    /// Client address for response (or proxy target in single-writer mode)
    pub client: Mutex<Option<SocketAddr>>,
}

impl NodeState {
    /// Reset the node state for a new operation
    pub async fn reset(&self) {
        self.phase.store(0, Ordering::Release);
        self.acks.store(0, Ordering::Release);
        *self.client.lock().await = None;
    }

    /// Start a new operation with the given phase
    pub fn start_phase(&self, phase: u32) {
        self.acks.store(0, Ordering::Release);
        self.phase.store(phase, Ordering::Release);
    }

    /// Check if we have received a majority of acknowledgments
    pub fn has_majority(&self, total_nodes: u32) -> bool {
        self.acks.load(Ordering::Acquire) >= majority(total_nodes)
    }

    /// Increment acknowledgment counter and return new count
    pub fn increment_acks(&self) -> u32 {
        self.acks.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// Global state combining all protocol components
#[derive(Default, Debug)]
pub struct GlobalState {
    /// Server role state for handling READ/WRITE requests
    pub server: ReplicaStore,

    /// Reader role state for READ operations
    pub reader: NodeState,

    /// Writer role state for WRITE operations
    pub writer: NodeState,
}

impl GlobalState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Execution context shared across all protocol handlers
#[derive(Clone)]
pub struct Context {
    /// This node's ID (1-based)
    pub node_id: NodeId,

    /// Total number of replicas in the cluster
    pub num_replicas: u32,

    /// Addresses of all peer nodes (index = `node_id` - 1)
    pub peers: Arc<Vec<SocketAddr>>,

    /// UDP socket for communication
    pub socket: Arc<UdpSocket>,

    /// Shared protocol state
    pub state: Arc<GlobalState>,
}

impl Context {
    /// Create a new protocol context
    pub fn new(
        node_id: NodeId,
        num_replicas: u32,
        peers: Arc<Vec<SocketAddr>>,
        bind_addr: SocketAddr,
        state: Arc<GlobalState>,
    ) -> Result<Self> {
        let socket = Arc::new(crate::network::create_socket(bind_addr)?);

        Ok(Self {
            node_id,
            num_replicas,
            peers,
            socket,
            state,
        })
    }

    /// Check if this node is a writer in the current configuration
    #[cfg(not(feature = "multi-writer"))]
    #[must_use]
    pub const fn is_writer(&self) -> bool {
        self.node_id == 1
    }

    #[cfg(feature = "multi-writer")]
    #[must_use]
    pub const fn is_writer(&self) -> bool {
        true
    }

    /// Send a message to a peer node
    pub async fn send_to_peer(
        &self,
        msg: &ArchivedAbdMessage,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        crate::network::send_message(&self.socket, msg, peer_addr).await
    }

    /// Broadcast a message to all peer nodes
    pub async fn broadcast(&self, msg: &ArchivedAbdMessage) -> Result<()> {
        for &peer_addr in self.peers.iter() {
            self.send_to_peer(msg, peer_addr).await?;
        }
        Ok(())
    }
}
