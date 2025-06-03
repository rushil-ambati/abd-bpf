//! ABD Benchmark Library
//!
//! This library provides comprehensive benchmarking capabilities for the ABD (Attiya-Bar-Noy-Dolev)
//! distributed storage protocol. It supports both latency and throughput benchmarking across
//! userspace and eBPF implementations.
//!
//! ## Features
//!
//! - **Latency Benchmarking**: Measures round-trip time for read/write operations
//! - **Throughput Benchmarking**: Measures maximum requests per second with configurable concurrency
//! - **Network Namespace Support**: Handles eBPF mode with proper netns isolation
//! - **Robust Error Handling**: Comprehensive error reporting and recovery
//! - **Structured Results**: JSON output with detailed statistics and summaries
//!
//! ## Architecture
//!
//! The benchmark library is organized into several modules:
//! - `types`: Core data structures and configuration types
//! - `operations`: Low-level network operations for ABD protocol
//! - `latency`: Latency benchmark implementation
//! - `throughput`: Throughput benchmark implementation
//! - `utils`: Utility functions for statistics and file I/O

pub mod cli;
pub mod latency;
pub mod operations;
pub mod throughput;
pub mod types;
pub mod utils;

// Re-export commonly used types for convenience
// Re-export benchmark functions
pub use latency::run_latency_benchmark;
pub use throughput::run_throughput_benchmark;
pub use types::{
    BenchmarkError, BenchmarkResult, LatencyResults, LatencySummary, ThreadThroughputStats,
    ThroughputResults, ThroughputSummary,
};

/// Initialize logging for the benchmark application
///
/// Sets up structured logging with appropriate filters and formatting
/// for both console output and potential file logging.
pub fn init_logging() -> BenchmarkResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .format_module_path(false)
        .format_target(false)
        .try_init()
        .map_err(|e| {
            BenchmarkError::Initialization(format!("Failed to initialize logging: {}", e))
        })?;

    Ok(())
}
