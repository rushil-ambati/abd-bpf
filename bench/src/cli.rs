//! Command-line interface definitions for the ABD benchmark utility

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// ABD Benchmark Utility
///
/// Comprehensive benchmarking tool for the ABD (Attiya-Bar-Noy-Dolev) distributed storage protocol.
/// Supports both latency and throughput testing across userspace and eBPF implementations.
#[derive(Parser, Debug)]
#[command(
    version,
    about = "ABD Benchmark Utility - Performance testing for distributed ABD protocol",
    long_about = "
The ABD Benchmark Utility provides comprehensive performance testing capabilities
for the ABD (Attiya-Bar-Noy-Dolev) distributed storage protocol implementation.

Features:
- Latency benchmarking with statistical analysis
- Throughput benchmarking with configurable concurrency
- Support for both userspace and eBPF implementations
- Network namespace isolation for eBPF mode
- Structured JSON output for analysis

The tool assumes that test environments are already set up and ABD nodes are running.
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: BenchCommand,
}

/// Available benchmark commands
#[derive(Subcommand, Debug)]
pub enum BenchCommand {
    /// Run latency benchmarks
    ///
    /// Measures round-trip time for read and write operations across all nodes
    /// in the cluster. Provides detailed statistical analysis including percentiles.
    Latency(LatencyArgs),

    /// Run throughput benchmarks
    ///
    /// Measures maximum requests per second using configurable concurrency.
    /// Each thread sends requests in a tight loop for the specified duration.
    Throughput(ThroughputArgs),
}

/// Arguments for latency benchmark command
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct LatencyArgs {
    /// Path to cluster configuration file (JSON format)
    ///
    /// The configuration file should contain node definitions with IP addresses
    /// and network interface information.
    #[arg(long, value_name = "FILE")]
    pub config: String,

    /// Number of nodes in the cluster
    ///
    /// The number of nodes to include in the benchmark test. This should match
    /// the number of nodes configured in the cluster configuration file.
    #[arg(long, default_value = "3", value_name = "COUNT")]
    pub num_nodes: u32,

    /// Number of iterations per operation type
    ///
    /// Each node will be tested with this many read and write operations.
    /// Higher values provide more accurate statistical results but take longer.
    #[arg(long, default_value = "1000", value_name = "COUNT")]
    pub iterations: u32,

    /// Output file for results (JSON format)
    ///
    /// Results include raw latency data and statistical summaries.
    #[arg(long, default_value = "latency_results.json", value_name = "FILE")]
    pub output: String,

    /// Number of warmup iterations before measuring
    ///
    /// Warmup iterations help stabilize performance by allowing JIT compilation,
    /// cache warming, and connection establishment.
    #[arg(long, default_value = "10", value_name = "COUNT")]
    pub warmup: u32,
}

/// Arguments for throughput benchmark command
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputArgs {
    /// Path to cluster configuration file (JSON format)
    ///
    /// The configuration file should contain node definitions with IP addresses
    /// and network interface information.
    #[arg(long, value_name = "FILE")]
    pub config: String,

    /// Number of nodes in the cluster
    ///
    /// The number of nodes to include in the benchmark test. This should match
    /// the number of nodes configured in the cluster configuration file.
    #[arg(long, default_value = "3", value_name = "COUNT")]
    pub num_nodes: u32,

    /// Duration of the benchmark in seconds
    ///
    /// Each thread will send requests continuously for this duration.
    /// Longer durations provide more stable throughput measurements.
    #[arg(long, default_value = "30", value_name = "SECONDS")]
    pub duration: u64,

    /// Number of concurrent threads per node
    ///
    /// Higher thread counts can increase throughput but may also increase
    /// contention and reduce individual thread performance.
    #[arg(long, default_value = "1", value_name = "COUNT")]
    pub threads_per_node: usize,

    /// Request timeout in milliseconds
    ///
    /// Requests that don't receive a response within this time are considered
    /// timeouts. This should be set based on expected network latency.
    #[arg(long, default_value = "100", value_name = "MS")]
    pub timeout_ms: u64,

    /// Ramp-up duration in seconds
    ///
    /// Gradual load increase to avoid overwhelming the system.
    #[arg(long, default_value = "0", value_name = "SECONDS")]
    pub ramp_up: u64,

    /// Ratio of write operations (0.0 to 1.0)
    ///
    /// Controls the mix of write vs read operations, e.g. 0.1 means 10% writes, 90% reads.
    #[arg(long, default_value = "0.1", value_name = "RATIO")]
    pub write_ratio: f64,

    /// Maximum in-flight requests per thread
    ///
    /// Limits concurrent requests to prevent buffer overflows and enable fair comparisons.
    #[arg(long, default_value = "16", value_name = "COUNT")]
    pub max_in_flight: usize,

    /// Load sweep mode: test multiple load levels
    ///
    /// When enabled, automatically sweeps through load levels from `start_rps` to `max_rps`.
    #[arg(long)]
    pub sweep_load: bool,

    /// Starting RPS for load sweep
    #[arg(long, default_value = "1000", value_name = "RPS")]
    pub start_rps: u64,

    /// Maximum RPS for load sweep
    #[arg(long, default_value = "5000", value_name = "RPS")]
    pub max_rps: u64,

    /// RPS increment for load sweep
    #[arg(long, default_value = "500", value_name = "RPS")]
    pub rps_step: u64,

    /// Target RPS for fixed-rate mode (alternative to max throughput)
    ///
    /// When set, threads will pace requests to achieve this target rate.
    #[arg(long, value_name = "RPS")]
    pub target_rps: Option<u64>,

    /// Temporal resolution for RPS tracking (seconds)
    ///
    /// Track per-interval RPS to reveal jitter and performance cliffs.
    #[arg(long, default_value = "1", value_name = "SECONDS")]
    pub rps_interval: u64,

    /// Output file for results (JSON format)
    ///
    /// Results include per-thread statistics and aggregated summaries.
    #[arg(long, default_value = "throughput_results.json", value_name = "FILE")]
    pub output: String,
}
