//! ABD Benchmark Utility
//!
//! This benchmark utility performs comprehensive latency and throughput testing on ABD clusters.
//! It supports both userspace and eBPF implementations with proper network namespace handling.
//!
//! ## Usage
//!
//! ### Latency Benchmarks
//! ```bash
//! cargo run --bin bench -- latency --config cluster.json --iterations 1000 --warmup 10
//! ```
//!
//! ### Throughput Benchmarks
//! ```bash
//! cargo run --bin bench -- throughput --config cluster.json --duration 30 --threads-per-node 4
//! ```
//!
//! ## Features
//!
//! - **Comprehensive Metrics**: Detailed latency percentiles and throughput statistics
//! - **Network Namespace Support**: Full compatibility with eBPF mode networking
//! - **Robust Error Handling**: Graceful degradation and detailed error reporting
//! - **JSON Output**: Structured results for analysis and visualization
//! - **Configurable Benchmarks**: Flexible parameters for different testing scenarios

use bench::{
    cli::{BenchCommand, Cli},
    init_logging,
    latency::run_latency_benchmark,
    throughput::run_throughput_benchmark,
    types::BenchmarkResult,
};
use clap::Parser;
use log::{error, info};

fn main() -> BenchmarkResult<()> {
    // Initialize logging system
    init_logging()?;

    info!("Starting ABD Benchmark Utility");

    // Parse command line arguments
    let cli = Cli::parse();

    // Execute the appropriate benchmark based on command
    let result = match cli.command {
        BenchCommand::Latency(args) => {
            info!("Executing latency benchmark");
            run_latency_benchmark(&args).map(|results| {
                info!("Latency benchmark completed successfully");
                info!("Results saved to: {}", args.output);
                info!(
                    "Summary - Write avg: {:.2}μs, Read avg: {:.2}μs",
                    results.summary.write_avg, results.summary.read_avg
                );
            })
        }
        BenchCommand::Throughput(args) => {
            info!("Executing throughput benchmark");
            run_throughput_benchmark(&args).map(|results| {
                info!("Throughput benchmark completed successfully");
                info!("Results saved to: {}", args.output);
                info!(
                    "Summary - RPS: {:.2}, Success rate: {:.1}%",
                    results.summary.rps,
                    results.summary.success_rate * 100.0
                );
            })
        }
    };

    // Handle any errors that occurred during benchmarking
    if let Err(ref e) = result {
        error!("Benchmark failed: {e}");

        // Print additional context for common error types
        match e {
            bench::BenchmarkError::Configuration(_) => {
                error!("Please check your cluster configuration file and ensure it's valid");
            }
            bench::BenchmarkError::Network(_) => {
                error!("Please ensure the ABD nodes are running and accessible");
            }
            bench::BenchmarkError::Namespace(_) => {
                error!(
                    "Please check that network namespaces are properly configured for eBPF mode"
                );
            }
            _ => {}
        }

        std::process::exit(1);
    }

    info!("ABD Benchmark Utility completed successfully");
    Ok(())
}
