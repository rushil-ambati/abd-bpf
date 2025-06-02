//! ABD Benchmark Utility
//!
//! This benchmark utility performs latency testing on the ABD cluster.
//! It assumes testenvs are already set up and nodes are running.
//!
//! Usage:
//!   cargo run --bin bench -- latency --num-nodes 3 --iterations 100

use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    str::FromStr,
    time::{Duration, Instant},
};

use abd::ClusterConfig;
use abd_common::{
    constants::ABD_UDP_PORT,
    message::{AbdMessage, AbdMessageData, AbdMessageType, AbdRole, ArchivedAbdMessage},
};
use anyhow::{self, Context};
use clap::{Parser, Subcommand};
use log::{debug, info, warn};
use netns_rs::NetNs;
use rkyv::{access, deserialize, rancor::Error as RkyvError};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(version, about = "ABD Benchmark Utility")]
struct Cli {
    #[command(subcommand)]
    command: BenchCommand,
}

#[derive(Subcommand, Debug)]
enum BenchCommand {
    /// Run latency benchmarks
    Latency(LatencyOpts),
    /// Run throughput benchmarks (future)
    #[allow(dead_code)]
    Throughput(ThroughputOpts),
}

#[derive(Parser, Debug)]
struct LatencyOpts {
    /// Path to cluster config file (JSON)
    #[arg(long)]
    config: String,

    /// Number of iterations per operation
    #[arg(long, default_value = "1000")]
    iterations: u32,

    /// Output file for results
    #[arg(long, default_value = "latency_results.json")]
    output: String,

    /// Warmup iterations before measuring
    #[arg(long, default_value = "10")]
    warmup: u32,
}

#[derive(Parser, Debug)]
#[allow(dead_code)]
struct ThroughputOpts {
    /// Path to cluster config file (JSON)
    #[arg(long)]
    config: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct LatencyResults {
    timestamp: String,
    num_nodes: u32,
    iterations: u32,
    write_latencies: HashMap<u32, Vec<f64>>, // node_id -> latencies in ms
    read_latencies: HashMap<u32, Vec<f64>>,  // node_id -> latencies in ms
    summary: LatencySummary,
}

/// All values are in milliseconds
#[derive(Serialize, Deserialize, Debug)]
struct LatencySummary {
    write_avg: f64,
    write_p50: f64,
    write_p95: f64,
    write_p99: f64,
    read_avg: f64,
    read_p50: f64,
    read_p95: f64,
    read_p99: f64,
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    match cli.command {
        BenchCommand::Latency(opts) => run_latency_benchmark(&opts),
        BenchCommand::Throughput(_opts) => {
            unimplemented!("Throughput benchmarks not yet implemented")
        }
    }
}

fn run_latency_benchmark(opts: &LatencyOpts) -> anyhow::Result<()> {
    // Load cluster config
    let cluster_config = ClusterConfig::load_from_file(&opts.config)?;
    let num_nodes = cluster_config.num_nodes;
    info!(
        "Starting latency benchmark with {} nodes, {} iterations",
        num_nodes, opts.iterations
    );

    // Build node_ips and node_interfaces from config
    let node_ips: HashMap<u32, Ipv4Addr> = cluster_config
        .nodes
        .iter()
        .map(|n| (n.node_id, n.ipv4))
        .collect();
    let node_interfaces: HashMap<u32, String> = cluster_config
        .nodes
        .iter()
        .map(|n| (n.node_id, n.interface.clone()))
        .collect();
    info!("Loaded node IPs from config: {node_ips:?}");

    let use_netns = cluster_config.mode.as_deref() == Some("ebpf");
    info!(
        "Using network namespaces: {}",
        if use_netns { "enabled" } else { "disabled" }
    );

    let mut results = LatencyResults {
        timestamp: chrono::Utc::now().to_rfc3339(),
        num_nodes,
        iterations: opts.iterations,
        write_latencies: HashMap::new(),
        read_latencies: HashMap::new(),
        summary: LatencySummary {
            write_avg: 0.0,
            write_p50: 0.0,
            write_p95: 0.0,
            write_p99: 0.0,
            read_avg: 0.0,
            read_p50: 0.0,
            read_p95: 0.0,
            read_p99: 0.0,
        },
    };

    // Base test data
    let base_value = "int=88 text=world ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334 duration=3600 point=(-0.3,4.1) person=(Alice,30)";

    // Benchmark each node
    for node_id in 1..=num_nodes {
        info!("Benchmarking node {node_id}");
        let node_ip = node_ips[&node_id];
        let node_iface = &node_interfaces[&node_id];

        // Create test data for this node
        let test_value =
            format!("{base_value} hashmap={{author:node{node_id};version:1.0;license:MIT}}");
        let test_data =
            AbdMessageData::from_str(&test_value).unwrap_or_else(|_| AbdMessageData::default());

        // Benchmark writes from this node
        let write_latencies = benchmark_writes_from_node(
            node_id,
            node_ip,
            node_iface,
            &test_data,
            opts.iterations,
            opts.warmup,
            use_netns,
        )?;
        results.write_latencies.insert(node_id, write_latencies);

        // Benchmark reads from all nodes
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
    save_results(&results, &opts.output)?;

    // Print summary
    print_summary(&results.summary);

    Ok(())
}

fn benchmark_writes_from_node(
    node_id: u32,
    node_ipv4: Ipv4Addr,
    node_iface: &str,
    data: &AbdMessageData,
    iterations: u32,
    warmup: u32,
    use_netns: bool,
) -> anyhow::Result<Vec<f64>> {
    let mut latencies = Vec::new();
    let netns = if use_netns {
        Some(
            NetNs::get(node_iface)
                .context(format!("Failed to get network namespace {node_iface}"))?,
        )
    } else {
        None
    };

    // Warmup
    info!("Warming up writes for node {node_id} ({warmup} iterations)");
    for _ in 0..warmup {
        let res = if let Some(ref ns) = netns {
            ns.run(|_| perform_write_operation(node_ipv4, data))?
        } else {
            perform_write_operation(node_ipv4, data).map(Ok)?
        };
        let _ = res?;
    }

    // Actual benchmark
    info!("Benchmarking writes for node {node_id} ({iterations} iterations)");
    for i in 0..iterations {
        if i % 10 == 0 {
            debug!(
                "Write iteration {}/{} for node {}",
                i + 1,
                iterations,
                node_id
            );
        }
        let res = if let Some(ref ns) = netns {
            ns.run(|_| perform_write_operation(node_ipv4, data))
                .context(format!(
                    "Failed to run write operation in netns for node {node_id}"
                ))?
        } else {
            perform_write_operation(node_ipv4, data)
        };
        if let Ok(latency) = res {
            latencies.push(latency);
        } else {
            warn!("Write operation failed for node {node_id} iteration {i}");
        }
    }

    info!(
        "Completed {} write operations for node {}",
        latencies.len(),
        node_id
    );
    Ok(latencies)
}

fn benchmark_reads_from_all_nodes(
    node_ips: &HashMap<u32, Ipv4Addr>,
    node_interfaces: &HashMap<u32, String>,
    iterations: u32,
    warmup: u32,
    use_netns: bool,
) -> anyhow::Result<Vec<f64>> {
    let mut all_latencies = Vec::new();
    for (&read_node_id, &read_ip) in node_ips {
        let read_iface = &node_interfaces[&read_node_id];
        let netns = if use_netns {
            Some(
                NetNs::get(read_iface)
                    .context(format!("Failed to get network namespace {read_iface}"))?,
            )
        } else {
            None
        };
        // Warmup
        for _ in 0..warmup {
            let res = if let Some(ref ns) = netns {
                ns.run(|_| perform_read_operation(read_ip))
                    .context(format!(
                        "Failed to run read operation in netns for node {read_node_id}"
                    ))?
            } else {
                perform_read_operation(read_ip)
            };
            let _ = res?;
        }
        // Actual benchmark
        debug!("Benchmarking reads from node {read_node_id} ({iterations} iterations)",);
        for _ in 0..iterations {
            let res = if let Some(ref ns) = netns {
                ns.run(|_| perform_read_operation(read_ip))
                    .context(format!(
                        "Failed to run read operation in netns for node {read_node_id}"
                    ))?
            } else {
                perform_read_operation(read_ip)
            };
            if let Ok(latency) = res {
                all_latencies.push(latency);
            }
        }
    }
    info!("Completed {} read operations total", all_latencies.len());
    Ok(all_latencies)
}

fn perform_write_operation(target_ip: Ipv4Addr, data: &AbdMessageData) -> anyhow::Result<f64> {
    let msg = AbdMessage::new(
        0,
        *data,
        AbdRole::Writer,
        0,
        AbdRole::Client,
        0,
        AbdMessageType::Write,
    );

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialize ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    let start = Instant::now();
    sock.send_to(&payload, target_addr)?;

    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .context("recv_from timeout or error")?;
    let elapsed = start.elapsed();

    // Verify response
    let archived = access::<ArchivedAbdMessage, RkyvError>(&buf[..n])
        .map_err(|e| anyhow::anyhow!("deserialize response: {e}"))?;
    let resp: AbdMessage = deserialize::<AbdMessage, RkyvError>(archived)
        .map_err(|e| anyhow::anyhow!("deserialize (stage 2): {e}"))?;

    // Check if it's a WriteAck
    if AbdMessageType::try_from(resp.type_) != Ok(AbdMessageType::WriteAck) {
        return Err(anyhow::anyhow!("Unexpected response type"));
    }

    Ok(elapsed.as_secs_f64() * 1000.0) // Convert to milliseconds
}

fn perform_read_operation(target_ip: Ipv4Addr) -> anyhow::Result<f64> {
    let msg = AbdMessage::new(
        0,                         // counter
        AbdMessageData::default(), // data (empty for reads)
        AbdRole::Reader,           // recipient_role
        0,                         // sender_id
        AbdRole::Client,           // sender_role
        0,                         // tag
        AbdMessageType::Read,
    );

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialize ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let target_addr = SocketAddrV4::new(target_ip, ABD_UDP_PORT);

    let start = Instant::now();
    sock.send_to(&payload, target_addr)?;

    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, _) = sock
        .recv_from(&mut buf)
        .context("recv_from timeout or error")?;
    let elapsed = start.elapsed();

    // Verify response
    let archived = access::<ArchivedAbdMessage, RkyvError>(&buf[..n])
        .map_err(|e| anyhow::anyhow!("deserialize response: {e}"))?;
    let resp: AbdMessage = deserialize::<AbdMessage, RkyvError>(archived)
        .map_err(|e| anyhow::anyhow!("deserialize (stage 2): {e}"))?;

    // Check if it's a ReadAck
    if AbdMessageType::try_from(resp.type_) != Ok(AbdMessageType::ReadAck) {
        return Err(anyhow::anyhow!("Unexpected response type"));
    }

    Ok(elapsed.as_secs_f64() * 1000.0) // Convert to milliseconds
}

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

fn calculate_average(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        let len = u32::try_from(values.len()).unwrap();
        values.iter().sum::<f64>() / f64::from(len)
    }
}

fn calculate_percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let len = u32::try_from(sorted.len()).unwrap();
    let idx_f = percentile / 100.0 * f64::from(len - 1);
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_truncation)]
    let index = idx_f.round() as u32;
    sorted[index.min(len - 1) as usize]
}

fn save_results(results: &LatencyResults, output_file: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;
    info!("Results saved to {output_file}");
    Ok(())
}

fn print_summary(summary: &LatencySummary) {
    info!("=== Latency Benchmark Results ===");
    info!("WRITE latencies (ms):");
    info!("  Average: {:.2}", summary.write_avg);
    info!("  P50:     {:.2}", summary.write_p50);
    info!("  P95:     {:.2}", summary.write_p95);
    info!("  P99:     {:.2}", summary.write_p99);
    info!("READ latencies (ms):");
    info!("  Average: {:.2}", summary.read_avg);
    info!("  P50:     {:.2}", summary.read_p50);
    info!("  P95:     {:.2}", summary.read_p95);
    info!("  P99:     {:.2}", summary.read_p99);
}
