//! Command-line interface definitions for the ABD benchmark utility

use clap::{Parser, Subcommand};

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
#[derive(Parser, Debug)]
pub struct LatencyArgs {
    /// Path to cluster configuration file (JSON format)
    ///
    /// The configuration file should contain node definitions with IP addresses
    /// and network interface information.
    #[arg(long, value_name = "FILE")]
    pub config: String,

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
#[derive(Parser, Debug)]
pub struct ThroughputArgs {
    /// Path to cluster configuration file (JSON format)
    ///
    /// The configuration file should contain node definitions with IP addresses
    /// and network interface information.
    #[arg(long, value_name = "FILE")]
    pub config: String,

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
    #[arg(long, default_value = "4", value_name = "COUNT")]
    pub threads_per_node: usize,

    /// Request timeout in milliseconds
    ///
    /// Requests that don't receive a response within this time are considered
    /// timeouts. This should be set based on expected network latency.
    #[arg(long, default_value = "100", value_name = "MS")]
    pub timeout_ms: u64,

    /// Ramp-up duration in seconds (currently unused)
    ///
    /// Reserved for future implementation of gradual load increase.
    #[arg(long, default_value = "5", value_name = "SECONDS")]
    pub ramp_up: u64,

    /// Output file for results (JSON format)
    ///
    /// Results include per-thread statistics and aggregated summaries.
    #[arg(long, default_value = "throughput_results.json", value_name = "FILE")]
    pub output: String,
}
