use std::{
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use abd_common::{AbdMsg, AbdMsgType, AbdValue, ArchivedAbdMsg, ABD_UDP_PORT};
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
    Write(WriteOpts),

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
        Command::Write(_) => AbdMsgType::WriteAck,
        Command::Read(_) => AbdMsgType::ReadAck,
    };

    let (server_addr, msg, label) = match cli.command {
        Command::Write(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or(0);
            let counter = opts.common.counter.unwrap_or(0);
            let tag = opts.common.tag.unwrap_or(0);

            let msg = AbdMsg::new(sender_id, AbdMsgType::Write, tag, opts.value, counter);
            let mut label = format!("WRITE({:?})", opts.value);

            if opts.common.tag.is_some() {
                let _ = write!(label, " tag={tag}");
            }
            if opts.common.counter.is_some() {
                let _ = write!(label, " counter={counter}");
            }
            if opts.common.sender_id.is_some() {
                let _ = write!(label, " sender={sender_id}");
            }

            (SocketAddrV4::new(server, ABD_UDP_PORT), msg, label)
        }

        Command::Read(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or_default();
            let counter = opts.common.counter.unwrap_or_default();
            let tag = opts.common.tag.unwrap_or_default();

            let msg = AbdMsg::new(
                sender_id,
                AbdMsgType::Read,
                tag,
                AbdValue::default(),
                counter,
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

            (SocketAddrV4::new(server, ABD_UDP_PORT), msg, label)
        }
    };

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialise ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    info!("{label} -> {}", server_addr.ip());

    let start = Instant::now();
    sock.send_to(&payload, server_addr)?;
    debug!("Sent {} bytes", payload.len());

    let mut buf = [0u8; 1024];
    let (n, from) = sock.recv_from(&mut buf)?;
    let elapsed = start.elapsed();
    debug!("Got ({n} bytes) from {from}");

    let archived = rkyv::access::<ArchivedAbdMsg, RkyvError>(&buf[..n])
        .map_err(|e| anyhow::anyhow!("deserialise: {e}"))?;
    let resp: AbdMsg = deserialize::<AbdMsg, RkyvError>(archived)
        .map_err(|e| anyhow::anyhow!("deserialise (stage 2): {e}"))?;
    debug!("Deserialised response: {resp:?}");

    report(&resp, elapsed, expected_ack);
    Ok(())
}

fn report(resp: &AbdMsg, elapsed: Duration, expected: AbdMsgType) {
    match AbdMsgType::try_from(resp.type_) {
        Ok(received) if received == expected => {
            match received {
                AbdMsgType::ReadAck => {
                    info!(
                        "R-ACK({:?}) from @{}, took={elapsed:?}",
                        resp.value, resp.sender
                    );
                }
                AbdMsgType::WriteAck => {
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
