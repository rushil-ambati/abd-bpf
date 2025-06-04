//! Latency Benchmark Module
//!
//! This module implements comprehensive latency benchmarking for the ABD protocol.
//! It measures round-trip time for both read and write operations across all nodes
//! in the cluster, with support for network namespace isolation in eBPF mode.
//!
//! ## Features
//!
//! - **Per-node benchmarking**: Measures latency from each node's perspective
//! - **Warmup iterations**: Allows for JIT optimization and cache warming
//! - **Statistical analysis**: Calculates average, median, and percentiles
//! - **Network namespace support**: Handles eBPF mode networking correctly
//! - **Comprehensive error handling**: Graceful degradation on individual failures
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use abd_benchmark::{cli::LatencyArgs, run_latency_benchmark};
//!
//! let args = LatencyArgs {
//!     config: "cluster.json".to_string(),
//!     iterations: 1000,
//!     output: "results.json".to_string(),
//!     warmup: 10,
//! };
//!
//! let results = run_latency_benchmark(&args)?;
//! println!("Average write latency: {:.2}μs", results.summary.write_avg);
//! ```

use std::{collections::HashMap, str::FromStr, time::Duration};

use abd::ClusterConfig;
use abd_common::message::AbdMessageData;
use log::{debug, info, warn};
use netns_rs::NetNs;

use crate::{
    cli::LatencyArgs,
    operations::{perform_read_operation, perform_write_operation},
    types::{BenchmarkError, BenchmarkResult, LatencyResults, LatencySummary},
    utils::{calculate_average, calculate_percentile, save_json_results},
};

/// Runs a comprehensive latency benchmark across all nodes in the cluster
///
/// This function orchestrates the entire latency benchmarking process:
/// 1. Loads cluster configuration
/// 2. Benchmarks write operations from each node
/// 3. Benchmarks read operations to all nodes
/// 4. Calculates summary statistics
/// 5. Saves results to the specified output file
///
/// # Arguments
///
/// * `opts` - Configuration options for the latency benchmark
///
/// # Returns
///
/// Returns the complete benchmark results including per-node latencies and summary statistics
///
/// # Errors
///
/// This function will return an error if:
/// - The cluster configuration cannot be loaded
/// - Network namespace operations fail (in eBPF mode)
/// - Network operations consistently fail
/// - Results cannot be saved to the output file
pub fn run_latency_benchmark(opts: &LatencyArgs) -> BenchmarkResult<LatencyResults> {
    // Load cluster configuration
    let cluster_config = ClusterConfig::load_from_file(&opts.config).map_err(|e| {
        BenchmarkError::Configuration(format!("Failed to load cluster config: {e}"))
    })?;

    let num_nodes = opts.num_nodes;
    info!(
        "Starting latency benchmark with {} nodes, {} iterations",
        num_nodes, opts.iterations
    );

    // Build node mappings from config
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

    info!("Loaded {} node configurations", cluster_config.nodes.len());

    let use_netns = cluster_config.mode.as_deref() == Some("ebpf");
    info!(
        "Network namespace mode: {}",
        if use_netns { "enabled" } else { "disabled" }
    );

    // Initialize results structure
    let mut results = LatencyResults {
        timestamp: chrono::Utc::now().to_rfc3339(),
        args: opts.clone(),
        write_latencies: HashMap::new(),
        read_latencies: HashMap::new(),
        summary: LatencySummary::default(),
    };

    // Generate test data for write operations
    let base_value = "int=88 text=world ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334 duration=3600 point=(-0.3,4.1) person=(Alice,30)";

    // Benchmark each node
    for node_id in 1..=num_nodes {
        info!("Benchmarking node {node_id}");

        let node_ip = node_ips.get(&node_id).ok_or_else(|| {
            BenchmarkError::Configuration(format!("Missing IP for node {node_id}"))
        })?;

        let node_iface = node_interfaces.get(&node_id).ok_or_else(|| {
            BenchmarkError::Configuration(format!("Missing interface for node {node_id}"))
        })?;

        // Create test data for this node
        let test_value = format!(
            "{base_value} hashmap={{author:node{node_id};version:1.0;license:MIT}}"
        );
        let test_data =
            AbdMessageData::from_str(&test_value).unwrap_or_else(|_| AbdMessageData::default());

        // Benchmark writes from this node
        let write_latencies = benchmark_writes_from_node(
            node_id,
            *node_ip,
            node_iface,
            &test_data,
            opts.iterations,
            opts.warmup,
            use_netns,
        )?;
        results.write_latencies.insert(node_id, write_latencies);

        // Benchmark reads from all nodes (from this node's perspective)
        let read_latencies = benchmark_reads_from_all_nodes(
            &node_ips,
            &node_interfaces,
            opts.iterations,
            opts.warmup,
            use_netns,
        )?;
        results.read_latencies.insert(node_id, read_latencies);
    }

    // Calculate summary statistics
    results.summary = calculate_summary(&results.write_latencies, &results.read_latencies);

    // Save results
    save_json_results(&results, &opts.output)?;

    // Print summary
    print_summary(&results.summary);

    Ok(results)
}

/// Benchmarks write operations from a specific node
///
/// This function performs write operations from a single node, measuring
/// the round-trip time for each operation. It includes warmup iterations
/// to allow for JIT optimization and network stack warming.
///
/// # Arguments
///
/// * `node_id` - The ID of the node to benchmark
/// * `node_ipv4` - The IPv4 address of the target node
/// * `node_iface` - The network interface name for netns operations
/// * `data` - The test data to write
/// * `iterations` - Number of benchmark iterations
/// * `warmup` - Number of warmup iterations
/// * `use_netns` - Whether to use network namespaces
///
/// # Returns
///
/// Returns a vector of latencies in microseconds for successful operations
fn benchmark_writes_from_node(
    node_id: u32,
    node_ipv4: std::net::Ipv4Addr,
    node_iface: &str,
    data: &AbdMessageData,
    iterations: u32,
    warmup: u32,
    use_netns: bool,
) -> BenchmarkResult<Vec<f64>> {
    let mut latencies = Vec::new();

    // Get network namespace if needed
    let netns = if use_netns {
        Some(NetNs::get(node_iface).map_err(|e| {
            BenchmarkError::Namespace(format!("Failed to get netns {node_iface}: {e}"))
        })?)
    } else {
        None
    };

    // Warmup phase
    info!(
        "Warming up writes for node {node_id} ({warmup} iterations)"
    );
    for _ in 0..warmup {
        let result = if let Some(ref ns) = netns {
            ns.run(|_| perform_write_operation(node_ipv4, data, Duration::from_secs(5)))
                .map_err(|e| BenchmarkError::Namespace(format!("Netns run failed: {e}")))?
        } else {
            perform_write_operation(node_ipv4, data, Duration::from_secs(5))
        };

        // Ignore warmup results, just ensure operations work
        if let Err(e) = result {
            warn!("Warmup write failed for node {node_id}: {e}");
        }
    }

    // Actual benchmark
    info!(
        "Benchmarking writes for node {node_id} ({iterations} iterations)"
    );
    let mut failures = 0;

    for i in 0..iterations {
        if i > 0 && i % 100 == 0 {
            debug!("Write iteration {i}/{iterations} for node {node_id}");
        }

        let result = if let Some(ref ns) = netns {
            ns.run(|_| perform_write_operation(node_ipv4, data, Duration::from_secs(5)))
                .map_err(|e| BenchmarkError::Namespace(format!("Netns run failed: {e}")))?
        } else {
            perform_write_operation(node_ipv4, data, Duration::from_secs(5))
        };

        match result {
            Ok(latency) => latencies.push(latency),
            Err(e) => {
                failures += 1;
                if failures <= 5 {
                    // Only log first few failures to avoid spam
                    warn!(
                        "Write operation failed for node {node_id} iteration {i}: {e}"
                    );
                }
            }
        }
    }

    if failures > 0 {
        warn!(
            "Node {node_id} had {failures} failed write operations out of {iterations}"
        );
    }

    info!(
        "Completed {} successful write operations for node {}",
        latencies.len(),
        node_id
    );
    Ok(latencies)
}

/// Benchmarks read operations from all nodes in the cluster
///
/// This function performs read operations to all nodes in the cluster,
/// measuring the round-trip time for each operation. It aggregates
/// latencies from all nodes into a single dataset.
///
/// # Arguments
///
/// * `node_ips` - Map of node IDs to IP addresses
/// * `node_interfaces` - Map of node IDs to network interface names
/// * `iterations` - Number of read iterations per node
/// * `warmup` - Number of warmup iterations per node
/// * `use_netns` - Whether to use network namespaces
///
/// # Returns
///
/// Returns a vector of aggregated read latencies in microseconds
fn benchmark_reads_from_all_nodes(
    node_ips: &HashMap<u32, std::net::Ipv4Addr>,
    node_interfaces: &HashMap<u32, String>,
    iterations: u32,
    warmup: u32,
    use_netns: bool,
) -> BenchmarkResult<Vec<f64>> {
    let mut all_latencies = Vec::new();

    for (&read_node_id, &read_ip) in node_ips {
        let read_iface = node_interfaces.get(&read_node_id).ok_or_else(|| {
            BenchmarkError::Configuration(format!("Missing interface for node {read_node_id}"))
        })?;

        // Get network namespace if needed
        let netns = if use_netns {
            Some(NetNs::get(read_iface).map_err(|e| {
                BenchmarkError::Namespace(format!("Failed to get netns {read_iface}: {e}"))
            })?)
        } else {
            None
        };

        // Warmup for this node
        for _ in 0..warmup {
            let result = if let Some(ref ns) = netns {
                ns.run(|_| perform_read_operation(read_ip, Duration::from_secs(5)))
                    .map_err(|e| BenchmarkError::Namespace(format!("Netns run failed: {e}")))?
            } else {
                perform_read_operation(read_ip, Duration::from_secs(5))
            };

            if let Err(e) = result {
                warn!("Warmup read failed for node {read_node_id}: {e}");
            }
        }

        // Actual benchmark for this node
        debug!(
            "Benchmarking reads from node {read_node_id} ({iterations} iterations)"
        );
        let mut failures = 0;

        for _ in 0..iterations {
            let result = if let Some(ref ns) = netns {
                ns.run(|_| perform_read_operation(read_ip, Duration::from_secs(5)))
                    .map_err(|e| BenchmarkError::Namespace(format!("Netns run failed: {e}")))?
            } else {
                perform_read_operation(read_ip, Duration::from_secs(5))
            };

            match result {
                Ok(latency) => all_latencies.push(latency),
                Err(_) => {
                    failures += 1;
                }
            }
        }

        if failures > 0 {
            warn!(
                "Node {read_node_id} had {failures} failed read operations out of {iterations}"
            );
        }
    }

    info!("Completed {} total read operations", all_latencies.len());
    Ok(all_latencies)
}

/// Calculates summary statistics from collected latency data
///
/// This function computes comprehensive statistics including averages
/// and percentiles for both read and write operations.
///
/// # Arguments
///
/// * `write_latencies` - Map of node IDs to write latency vectors
/// * `read_latencies` - Map of node IDs to read latency vectors
///
/// # Returns
///
/// Returns a complete summary with all statistical measures
fn calculate_summary(
    write_latencies: &HashMap<u32, Vec<f64>>,
    read_latencies: &HashMap<u32, Vec<f64>>,
) -> LatencySummary {
    let all_writes: Vec<f64> = write_latencies.values().flatten().copied().collect();
    let all_reads: Vec<f64> = read_latencies.values().flatten().copied().collect();

    LatencySummary {
        write_avg: calculate_average(&all_writes),
        write_p50: calculate_percentile(&all_writes, 50.0),
        write_p95: calculate_percentile(&all_writes, 95.0),
        write_p99: calculate_percentile(&all_writes, 99.0),
        read_avg: calculate_average(&all_reads),
        read_p50: calculate_percentile(&all_reads, 50.0),
        read_p95: calculate_percentile(&all_reads, 95.0),
        read_p99: calculate_percentile(&all_reads, 99.0),
    }
}

/// Prints a formatted summary of the benchmark results
///
/// Displays key latency metrics in a human-readable format to the console.
///
/// # Arguments
///
/// * `summary` - The summary statistics to display
fn print_summary(summary: &LatencySummary) {
    info!("=== Latency Benchmark Results ===");
    info!("WRITE latencies (μs):");
    info!("  Average: {:.2}", summary.write_avg);
    info!("  P50:     {:.2}", summary.write_p50);
    info!("  P95:     {:.2}", summary.write_p95);
    info!("  P99:     {:.2}", summary.write_p99);
    info!("READ latencies (μs):");
    info!("  Average: {:.2}", summary.read_avg);
    info!("  P50:     {:.2}", summary.read_p50);
    info!("  P95:     {:.2}", summary.read_p95);
    info!("  P99:     {:.2}", summary.read_p99);
}
