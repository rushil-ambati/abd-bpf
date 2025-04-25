use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::EbpfLoader;
use clap::Parser;
use log::info;
use log::{debug, warn};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::env;
use tokio::signal;

/// A TC program which implements an ABD writer
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the network interface to attach the XDP program to
    #[arg(long, default_value = "eth0")]
    iface: String,

    /// Name of the network interface to redirect the packet to
    #[arg(long)]
    redirect_iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let Args {
        iface,
        redirect_iface,
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

    // Retrieve the redirect interface's index and MAC address
    let network_interfaces = NetworkInterface::show().unwrap();
    let redirect_interface = network_interfaces
        .iter()
        .find(|iface| iface.name == redirect_iface)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", iface))?;
    // let redirect_mac_addr_str = redirect_interface
    //     .mac_addr
    //     .as_ref()
    //     .ok_or_else(|| anyhow::anyhow!("Interface {} does not have a MAC address", redirect_iface))?;
    // let redirect_mac_addr: [u8; 6] = redirect_mac_addr_str
    //     .split(':')
    //     .map(|s| u8::from_str_radix(s, 16).unwrap())
    //     .collect::<Vec<u8>>()
    //     .try_into()
    //     .map_err(|_| anyhow::anyhow!("Invalid MAC address format"))?;

    // Inner (veth0) of server1
    let redirect_mac_addr: [u8; 6] = [
        0x22, 0x39, 0x36, 0xda, 0x79, 0xc0,
    ];

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = EbpfLoader::new()
        .set_global("IFINDEX", &redirect_interface.index, true)
        .set_global("DST_MAC", &redirect_mac_addr, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/abd-writer"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("abd_writer").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
