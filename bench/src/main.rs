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

use abd::get_iface_info;
use abd_common::{
    constants::ABD_UDP_PORT,
    message::{AbdMessage, AbdMessageData, AbdMessageType, AbdRole, ArchivedAbdMessage},
};
use anyhow::{self, Context};
use clap::{Parser, Subcommand};
use log::{debug, info, warn};
use netns_rs::NetNs;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
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
    /// Number of nodes in the cluster
    #[arg(long, default_value = "3")]
    num_nodes: u32,

    /// Number of iterations per operation
    #[arg(long, default_value = "100")]
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
    /// Placeholder for future throughput benchmarks
    #[arg(long, default_value = "3")]
    num_nodes: u32,
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

#[derive(Serialize, Deserialize, Debug)]
struct LatencySummary {
    write_avg_ms: f64,
    write_p50_ms: f64,
    write_p95_ms: f64,
    write_p99_ms: f64,
    read_avg_ms: f64,
    read_p50_ms: f64,
    read_p95_ms: f64,
    read_p99_ms: f64,
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    match cli.command {
        BenchCommand::Latency(opts) => run_latency_benchmark(opts),
        BenchCommand::Throughput(_opts) => {
            unimplemented!("Throughput benchmarks not yet implemented")
        }
    }
}

fn run_latency_benchmark(opts: LatencyOpts) -> anyhow::Result<()> {
    info!(
        "Starting latency benchmark with {} nodes, {} iterations",
        opts.num_nodes, opts.iterations
    );

    // Discover node IPs
    let node_ips = discover_node_ips(opts.num_nodes)?;
    info!("Discovered node IPs: {:?}", node_ips);

    let mut results = LatencyResults {
        timestamp: chrono::Utc::now().to_rfc3339(),
        num_nodes: opts.num_nodes,
        iterations: opts.iterations,
        write_latencies: HashMap::new(),
        read_latencies: HashMap::new(),
        summary: LatencySummary {
            write_avg_ms: 0.0,
            write_p50_ms: 0.0,
            write_p95_ms: 0.0,
            write_p99_ms: 0.0,
            read_avg_ms: 0.0,
            read_p50_ms: 0.0,
            read_p95_ms: 0.0,
            read_p99_ms: 0.0,
        },
    };

    // Base test data
    let base_value = "int=88 text=world ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334 duration=3600 point=(-0.3,4.1) person=(Alice,30)";

    // Benchmark each node
    for node_id in 1..=opts.num_nodes {
        info!("Benchmarking node {}", node_id);
        let node_ip = node_ips[&node_id];

        // Create test data for this node
        let test_value = format!(
            "{} hashmap={{author:node{};version:1.0;license:MIT}}",
            base_value, node_id
        );
        let test_data =
            AbdMessageData::from_str(&test_value).unwrap_or_else(|_| AbdMessageData::default());

        // Benchmark writes from this node
        let write_latencies =
            benchmark_writes_from_node(node_id, node_ip, test_data, opts.iterations, opts.warmup)?;
        results.write_latencies.insert(node_id, write_latencies);

        // Benchmark reads from all nodes
        let read_latencies =
            benchmark_reads_from_all_nodes(&node_ips, opts.iterations, opts.warmup)?;
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

fn discover_node_ips(num_nodes: u32) -> anyhow::Result<HashMap<u32, Ipv4Addr>> {
    use abd_common::constants::ABD_IFACE_NODE_PREFIX;
    let ifaces = NetworkInterface::show()?;
    let mut node_ips = HashMap::new();

    for i in 1..=num_nodes {
        let iface_name = format!("{}{}", ABD_IFACE_NODE_PREFIX, i);
        let info = get_iface_info(&ifaces, &iface_name)?;
        node_ips.insert(i, info.ipv4);
    }

    Ok(node_ips)
}

fn benchmark_writes_from_node(
    node_id: u32,
    node_ip: Ipv4Addr,
    data: AbdMessageData,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<Vec<f64>> {
    let env_name = format!("node{}", node_id);
    let netns =
        NetNs::get(&env_name).context(format!("Failed to get network namespace {}", env_name))?;

    let mut latencies = Vec::new();

    // Warmup
    info!(
        "Warming up writes for node {} ({} iterations)",
        node_id, warmup
    );
    for _ in 0..warmup {
        let _ = netns.run(|_| perform_write_operation(node_ip, data));
    }

    // Actual benchmark
    info!(
        "Benchmarking writes for node {} ({} iterations)",
        node_id, iterations
    );
    for i in 0..iterations {
        if i % 10 == 0 {
            debug!(
                "Write iteration {}/{} for node {}",
                i + 1,
                iterations,
                node_id
            );
        }

        let result = netns.run(|_| perform_write_operation(node_ip, data))?;

        if let Ok(latency) = result {
            latencies.push(latency);
        } else {
            warn!(
                "Write operation failed for node {} iteration {}",
                node_id, i
            );
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
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<Vec<f64>> {
    let mut all_latencies = Vec::new();

    for (&read_node_id, &read_ip) in node_ips {
        let env_name = format!("node{}", read_node_id);
        let netns = NetNs::get(&env_name)
            .context(format!("Failed to get network namespace {}", env_name))?;

        // Warmup
        for _ in 0..warmup {
            let _ = netns.run(|_| perform_read_operation(read_ip));
        }

        // Actual benchmark
        debug!(
            "Benchmarking reads from node {} ({} iterations)",
            read_node_id, iterations
        );
        for _ in 0..iterations {
            let result = netns.run(|_| perform_read_operation(read_ip))?;

            if let Ok(latency) = result {
                all_latencies.push(latency);
            }
        }
    }

    info!("Completed {} read operations total", all_latencies.len());
    Ok(all_latencies)
}

fn perform_write_operation(target_ip: Ipv4Addr, data: AbdMessageData) -> anyhow::Result<f64> {
    let msg = AbdMessage::new(
        0,               // counter
        data,            // data
        AbdRole::Writer, // recipient_role
        0,               // sender_id
        AbdRole::Client, // sender_role
        0,               // tag
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
        write_avg_ms: calculate_average(&all_writes),
        write_p50_ms: calculate_percentile(&all_writes, 50.0),
        write_p95_ms: calculate_percentile(&all_writes, 95.0),
        write_p99_ms: calculate_percentile(&all_writes, 99.0),
        read_avg_ms: calculate_average(&all_reads),
        read_p50_ms: calculate_percentile(&all_reads, 50.0),
        read_p95_ms: calculate_percentile(&all_reads, 95.0),
        read_p99_ms: calculate_percentile(&all_reads, 99.0),
    }
}

fn calculate_average(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn calculate_percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let index = (percentile / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn save_results(results: &LatencyResults, output_file: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;
    info!("Results saved to {}", output_file);
    Ok(())
}

fn print_summary(summary: &LatencySummary) {
    info!("=== Latency Benchmark Results ===");
    info!("WRITE latencies (ms):");
    info!("  Average: {:.2}", summary.write_avg_ms);
    info!("  P50:     {:.2}", summary.write_p50_ms);
    info!("  P95:     {:.2}", summary.write_p95_ms);
    info!("  P99:     {:.2}", summary.write_p99_ms);
    info!("READ latencies (ms):");
    info!("  Average: {:.2}", summary.read_avg_ms);
    info!("  P50:     {:.2}", summary.read_p50_ms);
    info!("  P95:     {:.2}", summary.read_p95_ms);
    info!("  P99:     {:.2}", summary.read_p99_ms);
}
