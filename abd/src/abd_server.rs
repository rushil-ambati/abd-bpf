use abd::helpers::map_utils::{populate_server_info_map, populate_writer_info_map};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::EbpfLoader;
use clap::Parser;
use log::{debug, info, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::env;
use tokio::signal;

/// An XDP program which implements an ABD server
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface to attach the XDP program to
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// ABD server ID
    #[arg(short, long)]
    server_id: u8,

    /// Number of servers
    #[arg(long)]
    num_servers: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let Args {
        iface,
        server_id,
        num_servers,
    } = args;

    env_logger::init();

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
        .set_global("SERVER_ID", &server_id, true)
        .set_global("NUM_SERVERS", &num_servers, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/abd-server"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = ebpf.program_mut("abd_server").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Populate the info maps
    let network_interfaces = NetworkInterface::show().unwrap();
    let server_info_map = ebpf.map_mut("SERVER_INFO").unwrap();
    populate_server_info_map(server_info_map, &network_interfaces, num_servers)?;
    let writer_info_map = ebpf.map_mut("WRITER_INFO").unwrap();
    populate_writer_info_map(writer_info_map, &network_interfaces)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
