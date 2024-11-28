use anyhow::Context as _;
use aya::maps::{HashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use std::net::{IpAddr, SocketAddr};
use std::{env, io};
use tokio::net::UdpSocket;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    to_send: Option<(usize, SocketAddr)>,
    map: HashMap<MapData, u32, u32>,
}

impl Server {
    async fn run(self) -> Result<(), io::Error> {
        let Server {
            socket,
            mut buf,
            mut to_send,
            mut map,
        } = self;

        loop {
            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            if let Some((size, peer)) = to_send {
                if let IpAddr::V4(ipv4) = peer.ip() {
                    let ipv4_as_u32: u32 = ipv4.into();

                    let msg = std::str::from_utf8(&buf[..size-1]).unwrap();
                    match msg {
                        "GET" => {
                            let count = map.get(&ipv4_as_u32, 0).unwrap_or(0);
                            // send the count back to the client
                            socket.send_to((count.to_string() + "\n").as_bytes(), &peer).await?;
                        }
                        "RST" => {
                            println!("[USERSPACE] Resetting counter for IP: {:?}", ipv4);
                            map.insert(&ipv4_as_u32, 0, 0).unwrap();
                        }
                        _ => (),
                    }
                }
            }

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            to_send = Some(socket.recv_from(&mut buf).await?);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-actors"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("ebpf_actors").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let count_map: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.take_map("COUNTERS").context("failed to take COUNTERS map")?,
    )?;

    // Userspace echo server
    let addr = "192.168.1.151:1337";
    let socket = UdpSocket::bind(&addr).await?;
    println!("Listening on: {}", socket.local_addr()?);
    let server = Server {
        socket,
        buf: vec![0; 1024],
        to_send: None,
        map: count_map,
    };
    // Spawn the echo server in a new asynchronous task
    let server_handle = task::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("Server error: {}", e);
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    server_handle.abort();

    Ok(())
}
