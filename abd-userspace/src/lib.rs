//! # ABD Userspace Implementation
//!
//! This crate provides a userspace implementation of the ABD (Attiya, Bar-Noy, Dolev)
//! consensus protocol that is behaviorally identical to the in-kernel eBPF reference implementation.
//!
//! ## Features
//!
//! - **High Performance**: Uses `SO_REUSEPORT` UDP sockets with one socket per CPU core
//! - **Protocol Compliance**: Exact role/state machine parity with the eBPF implementation
//! - **Multi-Writer Support**: Configurable single-writer (default) or multi-writer modes
//! - **Lock-Free Design**: Atomic operations and careful synchronization for performance
//!
//! ## Architecture
//!
//! The implementation is structured around several key components:
//!
//! - [`protocol`]: Core ABD protocol state machines and message handling
//! - [`server`]: Server role implementation with replica storage
//! - [`node`]: Reader and writer node implementations
//! - [`network`]: Network layer with UDP socket management
//!
//! ## Usage
//!
//! ```rust,no_run
//! use abd_userspace::{AbdNode, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_file("cluster_config.json")?;
//!     let node = AbdNode::new(1, config).await?;
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

pub mod network;
pub mod node;
pub mod protocol;
pub mod server;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
pub use protocol::{Config, Majority, NodeId};
use tokio::task::JoinSet;

/// Main ABD node that coordinates all components
pub struct AbdNode {
    node_id: NodeId,
    config: Config,
    bind_addr: SocketAddr,
}

impl AbdNode {
    /// Create a new ABD node with the given ID and configuration
    pub fn new(node_id: NodeId, config: Config) -> Result<Self> {
        if !(1..=config.num_nodes()).contains(&node_id) {
            anyhow::bail!("node_id must be in range 1..={}", config.num_nodes());
        }

        let bind_addr = config.node_address(node_id)?;

        Ok(Self {
            node_id,
            config,
            bind_addr,
        })
    }

    /// Run the ABD node, starting worker tasks for each CPU core
    pub async fn run(self) -> Result<()> {
        let mut workers = JoinSet::new();
        let protocol_state = Arc::new(protocol::GlobalState::new());
        let peers = Arc::new(self.config.all_addresses()?);

        // Create one worker per CPU core for optimal performance
        for core_id in 0..num_cpus::get() {
            let ctx = protocol::Context::new(
                self.node_id,
                self.config.num_nodes(),
                peers.clone(),
                self.bind_addr,
                protocol_state.clone(),
            )
            .await?;

            workers.spawn(async move {
                if let Err(e) = network::run_worker(ctx).await {
                    log::warn!("Worker #{} terminated: {}", core_id, e);
                }
            });
        }

        log::info!(
            "ABD node {}/{} listening on {}",
            self.node_id,
            self.config.num_nodes(),
            self.bind_addr
        );

        // Wait for all workers to complete
        while workers.join_next().await.is_some() {}

        Ok(())
    }
}
