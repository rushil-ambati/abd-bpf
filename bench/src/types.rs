//! Type definitions and data structures for ABD benchmarking
//!
//! This module contains all the core data structures used throughout the benchmarking
//! system, including configuration types, result structures, and error definitions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type for benchmark operations
pub type BenchmarkResult<T> = Result<T, BenchmarkError>;

/// Comprehensive error types for benchmark operations
#[derive(Error, Debug)]
pub enum BenchmarkError {
    #[error("Initialization error: {0}")]
    Initialization(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Namespace error: {0}")]
    Namespace(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("General error: {0}")]
    General(#[from] anyhow::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Complete results from a latency benchmark run
#[derive(Serialize, Deserialize, Debug)]
pub struct LatencyResults {
    /// ISO 8601 timestamp of when the benchmark was run
    pub timestamp: String,
    /// Number of nodes in the cluster
    pub num_nodes: u32,
    /// Number of iterations performed per operation
    pub iterations: u32,
    /// Write latencies per node (node_id -> latencies in microseconds)
    pub write_latencies: HashMap<u32, Vec<f64>>,
    /// Read latencies per node (node_id -> latencies in microseconds)
    pub read_latencies: HashMap<u32, Vec<f64>>,
    /// Aggregated summary statistics
    pub summary: LatencySummary,
}

/// Statistical summary of latency benchmark results
///
/// All values are in microseconds (μs)
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct LatencySummary {
    /// Average write latency
    pub write_avg: f64,
    /// 50th percentile write latency
    pub write_p50: f64,
    /// 95th percentile write latency
    pub write_p95: f64,
    /// 99th percentile write latency
    pub write_p99: f64,
    /// Average read latency
    pub read_avg: f64,
    /// 50th percentile read latency
    pub read_p50: f64,
    /// 95th percentile read latency
    pub read_p95: f64,
    /// 99th percentile read latency
    pub read_p99: f64,
}

/// Per-thread statistics for throughput benchmarks
#[derive(Serialize, Deserialize, Debug)]
pub struct ThreadThroughputStats {
    /// ID of the node this thread was targeting
    pub node_id: u32,
    /// Thread identifier within the node
    pub thread_id: usize,
    /// Total number of requests sent
    pub sent: u64,
    /// Total number of successful responses received
    pub received: u64,
    /// Total number of requests that timed out
    pub timeouts: u64,
}

/// Complete results from a throughput benchmark run
#[derive(Serialize, Deserialize, Debug)]
pub struct ThroughputResults {
    /// ISO 8601 timestamp of when the benchmark was run
    pub timestamp: String,
    /// Number of nodes in the cluster
    pub num_nodes: u32,
    /// Number of threads per node
    pub threads_per_node: usize,
    /// Duration of the benchmark in seconds
    pub duration_secs: u64,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Per-thread statistics
    pub stats: Vec<ThreadThroughputStats>,
    /// Aggregated summary statistics
    pub summary: ThroughputSummary,
}

/// Statistical summary of throughput benchmark results
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct ThroughputSummary {
    /// Total requests sent across all threads
    pub total_sent: u64,
    /// Total successful responses received
    pub total_received: u64,
    /// Total requests that timed out
    pub total_timeouts: u64,
    /// Requests per second (successful responses / duration)
    pub rps: f64,
    /// Success rate as a fraction (0.0 to 1.0)
    pub success_rate: f64,
}

/// Internal configuration for benchmark operations
#[derive(Debug)]
pub struct BenchmarkConfig {
    /// Whether to use network namespaces (eBPF mode)
    pub use_netns: bool,
    /// Mapping of node ID to IP address
    pub node_ips: HashMap<u32, std::net::Ipv4Addr>,
    /// Mapping of node ID to network interface name
    pub node_interfaces: HashMap<u32, String>,
    /// Total number of nodes in the cluster
    pub num_nodes: u32,
}

impl BenchmarkConfig {
    /// Create a new benchmark configuration from a cluster config
    pub fn from_cluster_config(cluster_config: &abd::ClusterConfig) -> Self {
        let node_ips = cluster_config
            .nodes
            .iter()
            .map(|n| (n.node_id, n.ipv4))
            .collect();

        let node_interfaces = cluster_config
            .nodes
            .iter()
            .map(|n| (n.node_id, n.interface.clone()))
            .collect();

        let use_netns = cluster_config.mode.as_deref() == Some("ebpf");

        Self {
            use_netns,
            node_ips,
            node_interfaces,
            num_nodes: cluster_config.num_nodes,
        }
    }
}
