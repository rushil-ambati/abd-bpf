use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use abd_common::{
    constants::ABD_UDP_PORT,
    message::{AbdMessage, AbdMessageData, AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag::{self, AbdTag},
};
use clap::{Args, Parser, Subcommand};
use log::{debug, info, warn};
use rkyv::{deserialize, rancor::Error as RkyvError};

/// Simple command-line ABD client.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write a new value
    Write(Box<WriteOpts>),

    /// Read the stored value
    Read(ReadOpts),
}

#[derive(Args, Debug)]
struct CommonOpts {
    /// IPv4 address of the target node
    #[arg()]
    node: Ipv4Addr,

    /// Sender ID (0 = writer)
    #[arg(short = 's', long)]
    sender_id: Option<u32>,

    /// Monotonic counter
    #[arg(short = 'c', long)]
    counter: Option<u64>,

    /// Tag value
    #[arg(short = 't', long, value_parser = clap::value_parser!(AbdTag))]
    tag: Option<AbdTag>,

    /// Send to server instead of reader/writer
    #[arg(long, default_value_t = false)]
    server: bool,
}

#[derive(Args, Debug)]
struct WriteOpts {
    #[clap(flatten)]
    common: CommonOpts,

    /// Value to write (required positional argument)
    #[arg(value_parser = clap::value_parser!(AbdMessageData))]
    data: AbdMessageData,
}

#[derive(Args, Debug)]
struct ReadOpts {
    #[clap(flatten)]
    common: CommonOpts,
}

fn main() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp(None).init();

    let cli = Cli::parse();
    debug!("Parsed arguments: {cli:?}");

    let expected_ack = match cli.command {
        Command::Write(_) => AbdMessageType::WriteAck,
        Command::Read(_) => AbdMessageType::ReadAck,
    };

    let (node_addr, msg, label) = match cli.command {
        Command::Write(opts) => {
            let node = opts.common.node;
            let sender_id = opts.common.sender_id.unwrap_or_default();
            let counter = opts.common.counter.unwrap_or_default();
            let tag = opts.common.tag.unwrap_or_default();

            let recipient_role = if opts.common.server {
                AbdRole::Server
            } else {
                AbdRole::Writer
            };

            let sender_role = if opts.common.server {
                AbdRole::Writer
            } else {
                AbdRole::Client
            };

            let msg = AbdMessage::new(
                counter,
                opts.data,
                recipient_role,
                sender_id,
                sender_role,
                tag,
                AbdMessageType::Write,
            );
            let mut label = format!("WRITE({})", opts.data);

            if opts.common.tag.is_some() {
                let _ = write!(label, " tag={tag}");
            }
            if opts.common.counter.is_some() {
                let _ = write!(label, " counter={counter}");
            }
            if opts.common.sender_id.is_some() {
                let _ = write!(label, " sender={sender_id}");
            }

            (SocketAddrV4::new(node, ABD_UDP_PORT), msg, label)
        }

        Command::Read(opts) => {
            let node = opts.common.node;
            let sender_id = opts.common.sender_id.unwrap_or_default();
            let counter = opts.common.counter.unwrap_or_default();
            let tag = opts.common.tag.unwrap_or_default();

            let recipient_role = if opts.common.server {
                AbdRole::Server
            } else {
                AbdRole::Reader
            };

            let sender_role = if opts.common.server {
                AbdRole::Reader
            } else {
                AbdRole::Client
            };

            let msg = AbdMessage::new(
                counter,
                AbdMessageData::default(),
                recipient_role,
                sender_id,
                sender_role,
                tag,
                AbdMessageType::Read,
            );
            let mut label = "READ".to_string();

            if opts.common.tag.is_some() {
                let _ = write!(label, " tag={tag}");
            }
            if opts.common.counter.is_some() {
                let _ = write!(label, " counter={counter}");
            }
            if opts.common.sender_id.is_some() {
                let _ = write!(label, " sender={sender_id}");
            }

            (SocketAddrV4::new(node, ABD_UDP_PORT), msg, label)
        }
    };

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialise ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    info!("{label} -> {node_addr}");

    let start = Instant::now();
    sock.send_to(&payload, node_addr)?;
    debug!("Sent {} bytes", payload.len());

    let mut buf = vec![0u8; 65_535].into_boxed_slice();
    let (n, from) = sock.recv_from(&mut buf)?;
    let elapsed = start.elapsed();
    debug!("Got ({n} bytes) from {from}");

    let archived = rkyv::access::<ArchivedAbdMessage, RkyvError>(&buf[..n])
        .map_err(|e| anyhow::anyhow!("deserialise: {e}"))?;
    let resp: AbdMessage = deserialize::<AbdMessage, RkyvError>(archived)
        .map_err(|e| anyhow::anyhow!("deserialise (stage 2): {e}"))?;
    debug!("Deserialised response: {resp:?}");

    report(&resp, elapsed, expected_ack);
    Ok(())
}

fn report(resp: &AbdMessage, elapsed: Duration, expected: AbdMessageType) {
    match AbdMessageType::try_from(resp.type_) {
        Ok(received) if received == expected => {
            match received {
                AbdMessageType::ReadAck => {
                    info!(
                        "R-ACK({}) from @{}, took={elapsed:?}",
                        resp.data, resp.sender_id
                    );
                }
                AbdMessageType::WriteAck => {
                    info!("W-ACK from @{}, took={elapsed:?}", resp.sender_id);
                }
                _ => {}
            }
            debug!(
                "sender={} tag=<{},{}> value={:?} counter={}",
                resp.sender_id,
                tag::seq(resp.tag),
                tag::wid(resp.tag),
                resp.data,
                resp.counter
            );
        }
        Ok(unexpected) => {
            warn!(
                "Unexpected message type: {unexpected:?} (expected {expected:?}) from @{}",
                resp.sender_id
            );
        }
        Err(()) => {
            warn!(
                "Unknown message type: {} from @{}",
                resp.type_, resp.sender_id
            );
        }
    }
}
