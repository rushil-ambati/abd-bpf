use abd::{populate_nodes_map_from_config, ClusterConfig};
use anyhow::{bail, Context};
use aya::{
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    EbpfLoader,
};
use clap::Parser;
use log::{debug, info, logger, warn};
use tokio::signal;

/// Run an ABD eBPF node onto an interface.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// This node’s id (1‥N)
    #[arg(long)]
    node_id: u32,

    /// Path to cluster config file (JSON)
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp(None).init();

    let Args { node_id, config } = Args::parse();

    // Load cluster config
    let cluster_config = ClusterConfig::load_from_file(&config)?;
    let num_nodes = cluster_config.num_nodes;
    if !(1..=num_nodes).contains(&node_id) {
        bail!("--node-id must be in 1‥={num_nodes}");
    }

    let node_config = cluster_config
        .get_node(node_id)
        .ok_or_else(|| anyhow::anyhow!("Node {} not found in config", node_id))?;
    let iface = &node_config.interface;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf_xdp = EbpfLoader::new()
        .set_global("NUM_NODES", &num_nodes, true)
        .set_global("NODE_ID", &node_id, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/abd-xdp"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_xdp) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program_xdp: &mut Xdp = ebpf_xdp.program_mut("abd_xdp").unwrap().try_into()?;
    program_xdp.load()?;
    program_xdp.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut ebpf_tc = EbpfLoader::new()
        .set_global("NUM_NODES", &num_nodes, true)
        .set_global("NODE_ID", &node_id, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/abd-tc"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init_with_logger(&mut ebpf_tc, logger()) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(iface);
    let program_tc: &mut SchedClassifier = ebpf_tc.program_mut("abd_tc").unwrap().try_into()?;
    program_tc.load()?;
    program_tc.attach(iface, TcAttachType::Ingress)?;

    // Populate the node info maps from config
    let nodes_map_tc = ebpf_tc.map_mut("NODES").unwrap();
    let nodes_map_xdp = ebpf_xdp.map_mut("NODES").unwrap();
    populate_nodes_map_from_config(nodes_map_tc, &cluster_config)?;
    populate_nodes_map_from_config(nodes_map_xdp, &cluster_config)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
