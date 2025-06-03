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
//! - **Realistic workload mix**: Configurable read/write ratios
//! - **Load sweep capability**: Automatic throughput-latency curve generation
//! - **Fine-grained latency tracking**: Per-operation latency measurement under load
//! - **Temporal resolution**: Per-interval RPS tracking to reveal performance jitter
//! - **Fairness**: Even load balancing across all nodes
//! - **Backpressure modeling**: Configurable in-flight request limits
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
//!     write_ratio: 0.1,
//!     max_in_flight: 16,
//!     output: "throughput_results.json".to_string(),
//!     ..Default::default()
//! };
//!
//! let results = run_throughput_benchmark(&args)?;
//! println!("Achieved {} RPS with {:.1}% success rate",
//!          results.summary.rps, results.summary.success_rate * 100.0);
//! ```

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use abd::ClusterConfig;
use log::{debug, error, info, warn};
use netns_rs::NetNs;
use rand::Rng;

use crate::{
    cli::ThroughputArgs,
    operations::{perform_read_operation_fast, perform_write_operation_fast},
    types::{
        BenchmarkError, BenchmarkMetadata, BenchmarkResult, FailureModes, LoadSweepPoint,
        RpsTimelineEntry, ThreadThroughputStats, ThroughputResults, ThroughputSummary,
    },
    utils::{build_latency_stats, get_git_commit, get_system_info, save_json_results},
};

/// Shared state for temporal RPS tracking
#[derive(Debug)]
struct TimelineTracker {
    intervals: Arc<Mutex<Vec<IntervalData>>>,
    interval_duration: Duration,
    start_time: Instant,
}

/// Data for a single time interval
#[derive(Debug, Clone)]
struct IntervalData {
    interval_start: u64,
    operations_completed: u64,
    operations_sent: u64,
    total_latency_us: f64,
    latency_samples: u64,
}

impl TimelineTracker {
    fn new(interval_duration: Duration) -> Self {
        Self {
            intervals: Arc::new(Mutex::new(Vec::new())),
            interval_duration,
            start_time: Instant::now(),
        }
    }

    fn record_operation(&self, latency_us: Option<f64>, success: bool) {
        let elapsed = self.start_time.elapsed();
        let interval_idx = elapsed.as_secs() / self.interval_duration.as_secs();

        if let Ok(mut intervals) = self.intervals.lock() {
            // Ensure we have enough intervals
            while intervals.len() <= interval_idx as usize {
                let new_interval_start = intervals.len() as u64 * self.interval_duration.as_secs();
                intervals.push(IntervalData {
                    interval_start: new_interval_start,
                    operations_completed: 0,
                    operations_sent: 0,
                    total_latency_us: 0.0,
                    latency_samples: 0,
                });
            }

            if let Some(interval) = intervals.get_mut(interval_idx as usize) {
                interval.operations_sent += 1;
                if success {
                    interval.operations_completed += 1;
                    if let Some(lat) = latency_us {
                        interval.total_latency_us += lat;
                        interval.latency_samples += 1;
                    }
                }
            }
        }
    }

    fn get_timeline(&self) -> Vec<RpsTimelineEntry> {
        if let Ok(intervals) = self.intervals.lock() {
            intervals
                .iter()
                .map(|interval| RpsTimelineEntry {
                    interval_start: interval.interval_start,
                    rps: interval.operations_completed as f64
                        / self.interval_duration.as_secs_f64(),
                    success_rate: if interval.operations_sent > 0 {
                        interval.operations_completed as f64 / interval.operations_sent as f64
                    } else {
                        0.0
                    },
                    avg_latency_us: if interval.latency_samples > 0 {
                        interval.total_latency_us / interval.latency_samples as f64
                    } else {
                        0.0
                    },
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

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
    // Validate configuration
    if opts.write_ratio < 0.0 || opts.write_ratio > 1.0 {
        return Err(BenchmarkError::Configuration(
            "write_ratio must be between 0.0 and 1.0".to_string(),
        ));
    }

    // Load cluster configuration
    let cluster_config = ClusterConfig::load_from_file(&opts.config).map_err(|e| {
        BenchmarkError::Configuration(format!("Failed to load cluster config: {}", e))
    })?;

    let use_netns = cluster_config.mode.as_deref() == Some("ebpf");

    info!(
        "Starting throughput benchmark: {} nodes, {} threads/node, {}s duration, {:.1}% writes",
        opts.num_nodes,
        opts.threads_per_node,
        opts.duration,
        opts.write_ratio * 100.0
    );

    info!(
        "Netns: {}, Timeout: {}ms, Max in-flight: {}, RPS interval: {}s",
        if use_netns { "enabled" } else { "disabled" },
        opts.timeout_ms,
        opts.max_in_flight,
        opts.rps_interval
    );

    // Handle load sweep mode
    if opts.sweep_load {
        return run_load_sweep_benchmark(opts, &cluster_config);
    }

    // Single load level benchmark
    run_single_load_benchmark(opts, &cluster_config)
}

/// Runs a load sweep benchmark across multiple RPS levels
fn run_load_sweep_benchmark(
    opts: &ThroughputArgs,
    cluster_config: &ClusterConfig,
) -> BenchmarkResult<ThroughputResults> {
    info!(
        "Running load sweep from {} to {} RPS",
        opts.start_rps, opts.max_rps
    );

    let mut sweep_results = Vec::new();
    let mut current_rps = opts.start_rps;

    while current_rps <= opts.max_rps {
        info!("Testing load level: {} RPS", current_rps);

        // Create modified opts for this RPS level
        let mut level_opts = opts.clone();
        level_opts.target_rps = Some(current_rps);

        match run_single_load_benchmark(&level_opts, cluster_config) {
            Ok(results) => {
                let sweep_point = LoadSweepPoint {
                    target_rps: current_rps,
                    actual_rps: results.summary.rps,
                    success_rate: results.summary.success_rate,
                    latency_stats: results.summary.latency_summary,
                };
                sweep_results.push(sweep_point);

                // Stop if success rate drops below 95%
                if results.summary.success_rate < 0.95 {
                    warn!(
                        "Success rate dropped below 95% at {} RPS, stopping sweep",
                        current_rps
                    );
                    break;
                }
            }
            Err(e) => {
                error!("Failed to run benchmark at {} RPS: {}", current_rps, e);
                break;
            }
        }

        current_rps += opts.rps_step;
    }

    // Return the final results with sweep data
    let final_opts = opts.clone();
    let baseline_results = run_single_load_benchmark(&final_opts, cluster_config)?;

    let results = ThroughputResults {
        timestamp: baseline_results.timestamp,
        args: opts.clone(),
        stats: baseline_results.stats,
        summary: baseline_results.summary,
        timeline: baseline_results.timeline,
        sweep_results: Some(sweep_results),
        metadata: baseline_results.metadata,
    };

    // Save results with sweep data
    save_json_results(&results, &opts.output)?;

    Ok(results)
}

/// Runs a single load level benchmark
fn run_single_load_benchmark(
    opts: &ThroughputArgs,
    cluster_config: &ClusterConfig,
) -> BenchmarkResult<ThroughputResults> {
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

    // Create shared timeline tracker
    let timeline = Arc::new(TimelineTracker::new(Duration::from_secs(opts.rps_interval)));

    // Shared statistics collection
    let stats = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    // Global stop flag for controlled shutdown
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Target RPS per thread calculation
    let total_threads = opts.num_nodes as usize * opts.threads_per_node;
    let target_rps_per_thread = opts.target_rps.map(|rps| rps as f64 / total_threads as f64);

    // Spawn worker threads for each node
    for (&node_id, &node_ip) in &node_ips {
        let iface = node_interfaces[&node_id].clone();

        for thread_id in 0..opts.threads_per_node {
            let stats_clone = Arc::clone(&stats);
            let timeline_clone = Arc::clone(&timeline);
            let stop_flag_clone = Arc::clone(&stop_flag);
            let node_ips_clone = node_ips.clone();

            let duration = opts.duration;
            let timeout_ms = opts.timeout_ms;
            let ramp_up = opts.ramp_up;
            let write_ratio = opts.write_ratio;
            let max_in_flight = opts.max_in_flight;
            let use_netns = use_netns;
            let iface_clone = iface.clone();

            let handle = thread::spawn(move || {
                run_worker_thread(
                    node_id,
                    thread_id,
                    node_ip,
                    &node_ips_clone,
                    &iface_clone,
                    duration,
                    timeout_ms,
                    ramp_up,
                    write_ratio,
                    max_in_flight,
                    target_rps_per_thread,
                    use_netns,
                    stats_clone,
                    timeline_clone,
                    stop_flag_clone,
                )
            });

            handles.push(handle);
        }
    }

    // Wait for test duration then signal stop
    thread::sleep(Duration::from_secs(opts.duration));
    stop_flag.store(true, Ordering::Relaxed);

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

    // Get timeline data
    let timeline_data = timeline.get_timeline();

    // Build metadata
    let metadata = BenchmarkMetadata {
        benchmark_version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: get_git_commit(),
        abd_mode: if use_netns {
            "ebpf".to_string()
        } else {
            "userspace".to_string()
        },
        system_info: get_system_info(),
    };

    let results = ThroughputResults {
        timestamp: chrono::Utc::now().to_rfc3339(),
        args: opts.clone(),
        stats: thread_stats,
        summary: summary.clone(),
        timeline: timeline_data,
        sweep_results: None,
        metadata,
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
/// with configurable read/write ratios and collecting detailed statistics.
#[allow(clippy::too_many_arguments)]
fn run_worker_thread(
    thread_node_id: u32,
    thread_id: usize,
    _thread_node_ip: std::net::Ipv4Addr,
    all_node_ips: &HashMap<u32, std::net::Ipv4Addr>,
    iface: &str,
    duration: u64,
    timeout_ms: u64,
    ramp_up: u64,
    write_ratio: f64,
    max_in_flight: usize,
    target_rps: Option<f64>,
    use_netns: bool,
    stats: Arc<Mutex<Vec<ThreadThroughputStats>>>,
    timeline: Arc<TimelineTracker>,
    stop_flag: Arc<AtomicBool>,
) {
    // Enter network namespace if required
    let _netns_guard = if use_netns {
        match NetNs::get(iface) {
            Ok(ns) => {
                if let Err(e) = ns.enter() {
                    error!(
                        "Thread {}/{} failed to enter netns {}: {}",
                        thread_node_id, thread_id, iface, e
                    );
                    return;
                }
                Some(ns)
            }
            Err(e) => {
                error!(
                    "Thread {}/{} failed to get netns {}: {}",
                    thread_node_id, thread_id, iface, e
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
    let mut writes_sent = 0u64;
    let mut reads_sent = 0u64;
    let mut writes_received = 0u64;
    let mut reads_received = 0u64;
    let mut failure_modes = FailureModes::default();
    let mut latency_samples = Vec::new();

    // Create list of target nodes for load balancing
    let target_nodes: Vec<(u32, std::net::Ipv4Addr)> =
        all_node_ips.iter().map(|(&id, &ip)| (id, ip)).collect();
    let mut rng = rand::rng();

    // In-flight request tracking for backpressure
    let in_flight = Arc::new(AtomicU64::new(0));

    // Rate limiting for target RPS
    let mut last_request_time = Instant::now();
    let request_interval = target_rps.map(|rps| Duration::from_secs_f64(1.0 / rps));

    let start_time = Instant::now();
    let test_duration = Duration::from_secs(duration);
    let ramp_up_duration = Duration::from_secs(ramp_up);

    info!(
        "Thread {}/{} starting with {} target nodes, max_in_flight={}",
        thread_node_id,
        thread_id,
        target_nodes.len(),
        max_in_flight
    );

    // Main test loop
    while !stop_flag.load(Ordering::Relaxed) && start_time.elapsed() < test_duration {
        // Implement ramp-up by gradually increasing request rate
        let elapsed = start_time.elapsed();
        if elapsed < ramp_up_duration && ramp_up > 0 {
            let ramp_factor = elapsed.as_secs_f64() / ramp_up_duration.as_secs_f64();
            let delay_ms = ((1.0 - ramp_factor) * 10.0) as u64; // Max 10ms delay, decreasing to 0
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }

        // Rate limiting for target RPS
        if let Some(interval) = request_interval {
            let now = Instant::now();
            let time_since_last = now.duration_since(last_request_time);
            if time_since_last < interval {
                let sleep_duration = interval - time_since_last;
                thread::sleep(sleep_duration);
                last_request_time = last_request_time + interval;
            } else {
                last_request_time = now;
            }
        }

        // Backpressure: wait if too many requests in flight
        while in_flight.load(Ordering::Relaxed) >= max_in_flight as u64 {
            thread::sleep(Duration::from_millis(1));
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
        }

        // Select target node for load balancing
        let (target_node_id, target_ip) = target_nodes[rng.random_range(0..target_nodes.len())];

        // Determine operation type based on write ratio
        let is_write = rng.random::<f64>() < write_ratio;

        // Track in-flight request
        in_flight.fetch_add(1, Ordering::Relaxed);

        // Perform operation with latency tracking
        let operation_start = Instant::now();
        let result = if is_write {
            perform_write_operation_fast(target_ip, timeout_ms)
        } else {
            perform_read_operation_fast(target_ip, timeout_ms)
        };
        let latency_us = operation_start.elapsed().as_secs_f64() * 1_000_000.0;

        // Update counters
        sent += 1;
        if is_write {
            writes_sent += 1;
        } else {
            reads_sent += 1;
        }

        match result {
            Ok(_) => {
                received += 1;
                if is_write {
                    writes_received += 1;
                } else {
                    reads_received += 1;
                }
                latency_samples.push(latency_us);
                timeline.record_operation(Some(latency_us), true);

                debug!(
                    "Thread {}/{} {} to node {} succeeded in {:.2}μs",
                    thread_node_id,
                    thread_id,
                    if is_write { "WRITE" } else { "READ" },
                    target_node_id,
                    latency_us
                );
            }
            Err(e) => {
                timeline.record_operation(Some(latency_us), false);

                // Categorize failure mode
                let error_str = e.to_string();
                if error_str.contains("timeout") || error_str.contains("TimedOut") {
                    failure_modes.network_timeouts += 1;
                } else if error_str.contains("Protocol") {
                    failure_modes.protocol_errors += 1;
                } else if error_str.contains("Network") {
                    failure_modes.dropped_responses += 1;
                } else {
                    failure_modes.other_errors += 1;
                }

                debug!(
                    "Thread {}/{} {} to node {} failed: {}",
                    thread_node_id,
                    thread_id,
                    if is_write { "WRITE" } else { "READ" },
                    target_node_id,
                    e
                );
            }
        }

        // Release in-flight slot
        in_flight.fetch_sub(1, Ordering::Relaxed);

        // Brief yield to prevent complete CPU starvation
        if sent % 100 == 0 {
            thread::yield_now();
        }
    }

    // Build latency statistics
    let latency_stats = build_latency_stats(&latency_samples);

    // Report thread statistics
    let thread_stats = ThreadThroughputStats {
        node_id: thread_node_id,
        thread_id,
        sent,
        received,
        timeouts: failure_modes.network_timeouts + failure_modes.dropped_responses,
        writes_sent,
        reads_sent,
        writes_received,
        reads_received,
        latency_stats: latency_stats.clone(),
        failure_modes,
    };

    let success_rate = if sent > 0 {
        (received as f64 / sent as f64) * 100.0
    } else {
        0.0
    };

    info!(
        "Thread {}/{} completed: sent={}, received={}, success_rate={:.1}%, avg_latency={:.1}μs",
        thread_node_id, thread_id, sent, received, success_rate, latency_stats.avg_us
    );

    // Add to shared statistics
    if let Ok(mut stats_guard) = stats.lock() {
        stats_guard.push(thread_stats);
    } else {
        error!(
            "Thread {}/{} failed to update shared statistics",
            thread_node_id, thread_id
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

    let total_writes_sent: u64 = thread_stats.iter().map(|s| s.writes_sent).sum();
    let total_reads_sent: u64 = thread_stats.iter().map(|s| s.reads_sent).sum();
    let total_writes_received: u64 = thread_stats.iter().map(|s| s.writes_received).sum();
    let total_reads_received: u64 = thread_stats.iter().map(|s| s.reads_received).sum();

    let duration_f64 = duration as f64;
    let rps = if duration > 0 {
        total_received as f64 / duration_f64
    } else {
        0.0
    };
    let write_rps = if duration > 0 {
        total_writes_received as f64 / duration_f64
    } else {
        0.0
    };
    let read_rps = if duration > 0 {
        total_reads_received as f64 / duration_f64
    } else {
        0.0
    };

    let success_rate = if total_sent > 0 {
        total_received as f64 / total_sent as f64
    } else {
        0.0
    };
    let write_success_rate = if total_writes_sent > 0 {
        total_writes_received as f64 / total_writes_sent as f64
    } else {
        0.0
    };
    let read_success_rate = if total_reads_sent > 0 {
        total_reads_received as f64 / total_reads_sent as f64
    } else {
        0.0
    };

    // Aggregate latency statistics (weighted average)
    let mut all_latencies = Vec::new();
    for stat in thread_stats {
        // Use sample count to weight the contribution
        let weight = stat.latency_stats.sample_count;
        if weight > 0 {
            // Add representative samples based on the thread's statistics
            for _ in 0..weight.min(1000) {
                // Cap to avoid memory issues
                all_latencies.push(stat.latency_stats.avg_us);
            }
        }
    }

    let latency_summary = build_latency_stats(&all_latencies);

    ThroughputSummary {
        total_sent,
        total_received,
        total_timeouts,
        total_writes_sent,
        total_reads_sent,
        total_writes_received,
        total_reads_received,
        rps,
        write_rps,
        read_rps,
        success_rate,
        write_success_rate,
        read_success_rate,
        latency_summary,
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
    info!("Total Operations:");
    info!(
        "  Sent:      {} ({} writes, {} reads)",
        summary.total_sent, summary.total_writes_sent, summary.total_reads_sent
    );
    info!(
        "  Received:  {} ({} writes, {} reads)",
        summary.total_received, summary.total_writes_received, summary.total_reads_received
    );
    info!("  Timeouts:  {}", summary.total_timeouts);

    info!("Throughput:");
    info!("  Total RPS:  {:.2}", summary.rps);
    info!("  Write RPS:  {:.2}", summary.write_rps);
    info!("  Read RPS:   {:.2}", summary.read_rps);

    info!("Success Rates:");
    info!("  Overall:    {:.2}%", summary.success_rate * 100.0);
    info!("  Writes:     {:.2}%", summary.write_success_rate * 100.0);
    info!("  Reads:      {:.2}%", summary.read_success_rate * 100.0);

    info!("Latency Under Load:");
    info!("  Average:    {:.2}μs", summary.latency_summary.avg_us);
    info!("  P50:        {:.2}μs", summary.latency_summary.p50_us);
    info!("  P95:        {:.2}μs", summary.latency_summary.p95_us);
    info!("  P99:        {:.2}μs", summary.latency_summary.p99_us);
    info!("  Max:        {:.2}μs", summary.latency_summary.max_us);

    // Performance warnings and insights
    if summary.success_rate < 0.95 {
        warn!("⚠️  Success rate below 95% - consider reducing load or increasing timeouts");
    }

    if summary.latency_summary.p99_us > summary.latency_summary.p50_us * 10.0 {
        warn!("⚠️  High tail latency (P99/P50 > 10x) - potential saturation or backpressure");
    }

    if summary.rps > 10000.0 {
        info!("✅ High throughput achieved! System performing well under load.");
    }

    if summary.write_success_rate < summary.read_success_rate * 0.9 {
        warn!("⚠️  Write success rate significantly lower than reads - potential bottleneck");
    }
}
