use abd::helpers::map_utils::populate_nodes_map;
use abd_common::ABD_WRITER_ID;
use aya::{
    programs::{tc, SchedClassifier, TcAttachType},
    EbpfLoader,
};
use clap::Parser;
use log::{debug, info, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use tokio::signal;

/// A TC program which implements an ABD writer
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the network interface to attach the XDP program to
    #[arg(long, default_value = "eth0")]
    iface: String,

    /// Number of servers
    #[arg(long)]
    num_nodes: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();
    let Args { iface, num_nodes } = args;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = EbpfLoader::new()
        .set_global("SELF_ID", &ABD_WRITER_ID, true) // not used in writer
        .set_global("NUM_NODES", &num_nodes, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/writer"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("writer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;

    // Populate the info maps
    let network_interfaces = NetworkInterface::show().unwrap();
    let nodes_map = ebpf.map_mut("NODES").unwrap();
    populate_nodes_map(nodes_map, &network_interfaces, num_nodes)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
