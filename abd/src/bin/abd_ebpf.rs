use abd::populate_nodes_map;
use anyhow::Context;
use aya::{
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    EbpfLoader,
};
use clap::Parser;
use log::{debug, info, logger, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use tokio::signal;

/// Run an ABD eBPF node onto an interface.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface to attach to
    #[arg(long, default_value = "eth0")]
    iface: String,

    /// Total number of replicas
    #[arg(long)]
    num_nodes: u32,

    /// This node’s id (1‥N)
    #[arg(long)]
    node_id: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Args {
        iface,
        num_nodes,
        node_id,
    } = Args::parse();

    if node_id == 0 || node_id > num_nodes {
        return Err(anyhow::anyhow!(
            "node_id must be between 1 and num_nodes (inclusive)"
        ));
    }

    env_logger::builder().format_timestamp(None).init();

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
    program_xdp.attach(&iface, XdpFlags::default())
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
    let _ = tc::qdisc_add_clsact(&iface);
    let program_tc: &mut SchedClassifier = ebpf_tc.program_mut("abd_tc").unwrap().try_into()?;
    program_tc.load()?;
    program_tc.attach(&iface, TcAttachType::Ingress)?;

    // Populate the node info maps
    let network_interfaces = NetworkInterface::show().unwrap();
    let nodes_map_tc = ebpf_tc.map_mut("NODES").unwrap();
    populate_nodes_map(nodes_map_tc, &network_interfaces, num_nodes)?;
    let nodes_map_xdp = ebpf_xdp.map_mut("NODES").unwrap();
    populate_nodes_map(nodes_map_xdp, &network_interfaces, num_nodes)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
