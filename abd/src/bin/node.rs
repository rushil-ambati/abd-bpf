use std::io::Write;

use abd::populate_nodes_map;
use aya::{
    programs::{
        tc::{self, NlOptions, TcAttachOptions},
        SchedClassifier, TcAttachType,
    },
    EbpfLoader,
};
use clap::Parser;
use log::{debug, info, logger, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use tokio::signal;

/// Load and attach the ABD writer and reader to an interface.
#[derive(Parser, Debug)]
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

    // Check that the node_id is valid
    if node_id == 0 || node_id > num_nodes {
        return Err(anyhow::anyhow!(
            "node_id must be between 1 and num_nodes (inclusive)"
        ));
    }

    env_logger::builder()
        .format(move |buf, record| {
            writeln!(
                buf,
                "[{} {}{}] {}",
                record.level(),
                record.target(),
                node_id,
                record.args()
            )
        })
        .init();

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

    let mut ebpf_writer = EbpfLoader::new()
        .set_global("NUM_NODES", &num_nodes, true)
        .set_global("NODE_ID", &node_id, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/writer"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init_with_logger(&mut ebpf_writer, logger()) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let mut ebpf_reader = EbpfLoader::new()
        .set_global("NUM_NODES", &num_nodes, true)
        .set_global("NODE_ID", &node_id, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/reader"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init_with_logger(&mut ebpf_reader, logger()) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);

    let writer_program: &mut SchedClassifier =
        ebpf_writer.program_mut("writer").unwrap().try_into()?;
    writer_program.load()?;
    writer_program.attach_with_options(
        &iface,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions::default()),
    )?;

    let reader_program: &mut SchedClassifier =
        ebpf_reader.program_mut("reader").unwrap().try_into()?;
    reader_program.load()?;
    reader_program.attach_with_options(
        &iface,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions::default()),
    )?;

    // Populate the info maps
    let network_interfaces = NetworkInterface::show().unwrap();

    let writer_nodes_map = ebpf_writer.map_mut("NODES").unwrap();
    populate_nodes_map(writer_nodes_map, &network_interfaces, num_nodes)?;

    let reader_nodes_map = ebpf_reader.map_mut("NODES").unwrap();
    populate_nodes_map(reader_nodes_map, &network_interfaces, num_nodes)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
