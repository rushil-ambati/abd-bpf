//! Throughput Benchmark Module
//!
//! This module implements high-performance throughput benchmarking for the ABD protocol.
//! It measures maximum requests per second under sustained load using multiple threads
//! per node with configurable concurrency and timeouts.
//!
//! ## Features
//!
//! - **Multi-threaded testing**: Configurable thread count per node for load generation
//! - **Sustained load**: Runs for a specified duration to measure steady-state performance
//! - **Per-thread statistics**: Detailed breakdown of performance by thread and node
//! - **Timeout handling**: Configurable request timeouts with proper error categorization
//! - **Ramp-up support**: Gradual load increase to avoid overwhelming the system
//! - **Network namespace support**: Full compatibility with eBPF mode networking
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use abd_benchmark::{cli::ThroughputArgs, run_throughput_benchmark};
//!
//! let args = ThroughputArgs {
//!     config: "cluster.json".to_string(),
//!     duration: 30,
//!     threads_per_node: 4,
//!     timeout_ms: 100,
//!     ramp_up: 5,
//!     output: "throughput_results.json".to_string(),
//! };
//!
//! let results = run_throughput_benchmark(&args)?;
//! println!("Achieved {} RPS with {:.1}% success rate",
//!          results.summary.rps, results.summary.success_rate * 100.0);
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use abd::ClusterConfig;
use log::{error, info, warn};
use netns_rs::NetNs;

use crate::{
    cli::ThroughputArgs,
    operations::perform_write_operation_fast,
    types::{
        BenchmarkError, BenchmarkResult, ThreadThroughputStats, ThroughputResults,
        ThroughputSummary,
    },
    utils::save_json_results,
};

/// Runs a comprehensive throughput benchmark across all nodes in the cluster
///
/// This function orchestrates a multi-threaded throughput test that:
/// 1. Loads cluster configuration
/// 2. Spawns multiple threads per node for concurrent load generation
/// 3. Runs sustained load for the specified duration
/// 4. Aggregates statistics from all threads
/// 5. Calculates overall throughput metrics
/// 6. Saves detailed results
///
/// # Arguments
///
/// * `opts` - Configuration options for the throughput benchmark
///
/// # Returns
///
/// Returns complete benchmark results including per-thread statistics and aggregated metrics
///
/// # Errors
///
/// This function will return an error if:
/// - The cluster configuration cannot be loaded
/// - Network namespace operations fail (in eBPF mode)
/// - Thread spawning or coordination fails
/// - Results cannot be saved to the output file
pub fn run_throughput_benchmark(opts: &ThroughputArgs) -> BenchmarkResult<ThroughputResults> {
    // Load cluster configuration
    let cluster_config = ClusterConfig::load_from_file(&opts.config).map_err(|e| {
        BenchmarkError::Configuration(format!("Failed to load cluster config: {}", e))
    })?;

    let num_nodes = opts.num_nodes;
    info!(
        "Starting throughput benchmark with {} nodes, {} threads per node, {}s duration",
        num_nodes, opts.threads_per_node, opts.duration
    );

    // Build node mappings
    let node_ips: HashMap<u32, std::net::Ipv4Addr> = cluster_config
        .nodes
        .iter()
        .map(|n| (n.node_id, n.ipv4))
        .collect();

    let node_interfaces: HashMap<u32, String> = cluster_config
        .nodes
        .iter()
        .map(|n| (n.node_id, n.interface.clone()))
        .collect();

    let use_netns = cluster_config.mode.as_deref() == Some("ebpf");
    info!(
        "Network namespace mode: {}, Timeout: {}ms",
        if use_netns { "enabled" } else { "disabled" },
        opts.timeout_ms
    );

    // Shared statistics collection
    let stats = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    // Spawn worker threads for each node
    for (&node_id, &node_ip) in &node_ips {
        let iface = node_interfaces[&node_id].clone();

        for thread_id in 0..opts.threads_per_node {
            let stats_clone = Arc::clone(&stats);
            let duration = opts.duration;
            let timeout_ms = opts.timeout_ms;
            let ramp_up = opts.ramp_up;
            let use_netns = use_netns;
            let iface_clone = iface.clone();

            let handle = thread::spawn(move || {
                run_worker_thread(
                    node_id,
                    thread_id,
                    node_ip,
                    &iface_clone,
                    duration,
                    timeout_ms,
                    ramp_up,
                    use_netns,
                    stats_clone,
                )
            });

            handles.push(handle);
        }
    }

    // Wait for all threads to complete
    for handle in handles {
        if let Err(e) = handle.join() {
            error!("Thread panicked: {:?}", e);
        }
    }

    // Extract and aggregate results
    let thread_stats = Arc::try_unwrap(stats)
        .map_err(|_| BenchmarkError::Internal("Failed to extract thread statistics".to_string()))?
        .into_inner()
        .map_err(|e| BenchmarkError::Internal(format!("Mutex poisoned: {}", e)))?;

    // Calculate summary statistics
    let summary = calculate_throughput_summary(&thread_stats, opts.duration);

    let results = ThroughputResults {
        timestamp: chrono::Utc::now().to_rfc3339(),
        args: opts.clone(),
        stats: thread_stats,
        summary,
    };

    // Save results
    save_json_results(&results, &opts.output)?;

    // Print summary
    print_throughput_summary(&summary);

    Ok(results)
}

/// Runs a single worker thread for throughput testing
///
/// Each worker thread operates independently, sending continuous requests
/// to its assigned node and collecting statistics about success/failure rates.
///
/// # Arguments
///
/// * `node_id` - The target node ID
/// * `thread_id` - The thread identifier within the node
/// * `node_ip` - The target node's IP address
/// * `iface` - Network interface for netns operations
/// * `duration` - Test duration in seconds
/// * `timeout_ms` - Request timeout in milliseconds
/// * `ramp_up` - Ramp-up duration in seconds
/// * `use_netns` - Whether to use network namespaces
/// * `stats` - Shared statistics collection
fn run_worker_thread(
    node_id: u32,
    thread_id: usize,
    node_ip: std::net::Ipv4Addr,
    iface: &str,
    duration: u64,
    timeout_ms: u64,
    ramp_up: u64,
    use_netns: bool,
    stats: Arc<Mutex<Vec<ThreadThroughputStats>>>,
) {
    // Enter network namespace if required
    let _netns_guard = if use_netns {
        match NetNs::get(iface) {
            Ok(ns) => {
                if let Err(e) = ns.enter() {
                    error!(
                        "Thread {}/{} failed to enter netns {}: {}",
                        node_id, thread_id, iface, e
                    );
                    return;
                }
                Some(ns)
            }
            Err(e) => {
                error!(
                    "Thread {}/{} failed to get netns {}: {}",
                    node_id, thread_id, iface, e
                );
                return;
            }
        }
    } else {
        None
    };

    // Initialize thread-local statistics
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut timeouts = 0u64;

    let start_time = Instant::now();
    let test_duration = Duration::from_secs(duration);
    let ramp_up_duration = Duration::from_secs(ramp_up);

    info!("Thread {}/{} starting throughput test", node_id, thread_id);

    // Main test loop
    while start_time.elapsed() < test_duration {
        // Implement ramp-up by gradually increasing request rate
        let elapsed = start_time.elapsed();
        if elapsed < ramp_up_duration && ramp_up > 0 {
            let ramp_factor = elapsed.as_secs_f64() / ramp_up_duration.as_secs_f64();
            let delay_ms = ((1.0 - ramp_factor) * 10.0) as u64; // Max 10ms delay, decreasing to 0
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }

        // Perform write operation
        match perform_write_operation_fast(node_ip, timeout_ms) {
            Ok(_) => {
                sent += 1;
                received += 1;
            }
            Err(e) => {
                sent += 1;
                if e.to_string().contains("timeout") || e.to_string().contains("TimedOut") {
                    timeouts += 1;
                } else {
                    // Other errors also count as timeouts for throughput purposes
                    timeouts += 1;
                }
            }
        }

        // Brief yield to prevent completely starving other threads
        if sent % 1000 == 0 {
            thread::yield_now();
        }
    }

    // Report thread statistics
    let thread_stats = ThreadThroughputStats {
        node_id,
        thread_id,
        sent,
        received,
        timeouts,
    };

    info!(
        "Thread {}/{} completed: sent={}, received={}, timeouts={}, success_rate={:.1}%",
        node_id,
        thread_id,
        sent,
        received,
        timeouts,
        if sent > 0 {
            (received as f64 / sent as f64) * 100.0
        } else {
            0.0
        }
    );

    // Add to shared statistics
    if let Ok(mut stats_guard) = stats.lock() {
        stats_guard.push(thread_stats);
    } else {
        error!(
            "Thread {}/{} failed to update shared statistics",
            node_id, thread_id
        );
    }
}

/// Calculates aggregate throughput statistics from individual thread results
///
/// # Arguments
///
/// * `thread_stats` - Statistics from all worker threads
/// * `duration` - Test duration in seconds
///
/// # Returns
///
/// Returns aggregated throughput summary with key performance metrics
fn calculate_throughput_summary(
    thread_stats: &[ThreadThroughputStats],
    duration: u64,
) -> ThroughputSummary {
    let total_sent: u64 = thread_stats.iter().map(|s| s.sent).sum();
    let total_received: u64 = thread_stats.iter().map(|s| s.received).sum();
    let total_timeouts: u64 = thread_stats.iter().map(|s| s.timeouts).sum();

    let rps = if duration > 0 {
        total_received as f64 / duration as f64
    } else {
        0.0
    };

    let success_rate = if total_sent > 0 {
        total_received as f64 / total_sent as f64
    } else {
        0.0
    };

    ThroughputSummary {
        total_sent,
        total_received,
        total_timeouts,
        rps,
        success_rate,
    }
}

/// Prints a formatted summary of throughput benchmark results
///
/// Displays key performance metrics in a human-readable format.
///
/// # Arguments
///
/// * `summary` - The throughput summary to display
fn print_throughput_summary(summary: &ThroughputSummary) {
    info!("=== Throughput Benchmark Results ===");
    info!("Total sent:      {}", summary.total_sent);
    info!("Total received:  {}", summary.total_received);
    info!("Total timeouts:  {}", summary.total_timeouts);
    info!("Requests/sec:    {:.2}", summary.rps);
    info!("Success rate:    {:.2}%", summary.success_rate * 100.0);

    if summary.success_rate < 0.95 {
        warn!("Success rate below 95% - consider reducing load or increasing timeouts");
    }

    if summary.rps > 10000.0 {
        info!("High throughput achieved! System performing well under load.");
    }
}
