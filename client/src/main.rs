use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use abd_common::{
    constants::ABD_UDP_PORT,
    msg::{AbdMessage, AbdMessageType, ArchivedAbdMessage},
    value::AbdValue,
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
    /// IPv4 address of the target server
    #[arg()]
    server: Ipv4Addr,

    /// Sender ID (0 = writer)
    #[arg(short = 's', long)]
    sender_id: Option<u32>,

    /// Monotonic counter
    #[arg(short = 'c', long)]
    counter: Option<u64>,

    /// Tag value
    #[arg(short = 't', long)]
    tag: Option<u64>,

    /// Use internal server port instead of node port
    #[arg(long)]
    server_mode: bool,
}

#[derive(Args, Debug)]
struct WriteOpts {
    #[clap(flatten)]
    common: CommonOpts,

    /// Value to write (required positional argument)
    #[arg(value_parser = clap::value_parser!(AbdValue))]
    value: AbdValue,
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

    let (server_addr, msg, label) = match cli.command {
        Command::Write(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or(0);
            let counter = opts.common.counter.unwrap_or(0);
            let tag = opts.common.tag.unwrap_or(0);

            let msg = AbdMessage::new(counter, sender_id, tag, AbdMessageType::Write, opts.value);
            let mut label = format!("WRITE({})", opts.value);

            if opts.common.tag.is_some() {
                let _ = write!(label, " tag={tag}");
            }
            if opts.common.counter.is_some() {
                let _ = write!(label, " counter={counter}");
            }
            if opts.common.sender_id.is_some() {
                let _ = write!(label, " sender={sender_id}");
            }

            let port = if opts.common.server_mode {
                abd_common::constants::ABD_SERVER_UDP_PORT
            } else {
                ABD_UDP_PORT
            };
            (SocketAddrV4::new(server, port), msg, label)
        }

        Command::Read(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or_default();
            let counter = opts.common.counter.unwrap_or_default();
            let tag = opts.common.tag.unwrap_or_default();

            let msg = AbdMessage::new(
                counter,
                sender_id,
                tag,
                AbdMessageType::Read,
                AbdValue::default(),
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

            let port = if opts.common.server_mode {
                abd_common::constants::ABD_SERVER_UDP_PORT
            } else {
                ABD_UDP_PORT
            };
            (SocketAddrV4::new(server, port), msg, label)
        }
    };

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialise ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    info!("{label} -> {}", server_addr);

    let start = Instant::now();
    sock.send_to(&payload, server_addr)?;
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
                        resp.value, resp.sender
                    );
                }
                AbdMessageType::WriteAck => {
                    info!("W-ACK from @{}, took={elapsed:?}", resp.sender);
                }
                _ => {}
            }
            debug!(
                "sender={} tag={} value={:?} counter={}",
                resp.sender, resp.tag, resp.value, resp.counter
            );
        }
        Ok(unexpected) => {
            warn!(
                "Unexpected message type: {unexpected:?} (expected {expected:?}) from @{}",
                resp.sender
            );
        }
        Err(()) => {
            warn!("Unknown message type: {} from @{}", resp.type_, resp.sender);
        }
    }
}
