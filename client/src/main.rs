use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use abd_common::{AbdMsg, AbdMsgType, ArchivedAbdMsg, ABD_UDP_PORT};
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
    /// Send a WRITE request
    Write(WriteOpts),

    /// Send a READ request
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
    #[arg()]
    value: u64,
}

#[derive(Args, Debug)]
struct ReadOpts {
    #[clap(flatten)]
    common: CommonOpts,

    /// Optional value (visible if explicitly passed)
    #[arg(short = 'v', long)]
    value: Option<u64>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    debug!("Parsed arguments: {cli:?}");

    let (server_addr, msg, label) = match cli.command {
        Command::Write(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or(0);
            let counter = opts.common.counter.unwrap_or(0);
            let tag = opts.common.tag.unwrap_or(0);

            let msg = AbdMsg::new(sender_id, AbdMsgType::Write, tag, opts.value, counter);
            let mut label = format!("Write({})", opts.value);

            if opts.common.tag.is_some() {
                label.push_str(&format!(" tag={tag}"));
            }
            if opts.common.counter.is_some() {
                label.push_str(&format!(" counter={counter}"));
            }
            if opts.common.sender_id.is_some() {
                label.push_str(&format!(" sender={sender_id}"));
            }

            (SocketAddrV4::new(server, ABD_UDP_PORT), msg, label)
        }

        Command::Read(opts) => {
            let server = opts.common.server;
            let sender_id = opts.common.sender_id.unwrap_or(0);
            let counter = opts.common.counter.unwrap_or(0);
            let tag = opts.common.tag.unwrap_or(0);
            let value = opts.value.unwrap_or(0); // not required for read, but preserved

            let msg = AbdMsg::new(sender_id, AbdMsgType::Read, tag, value, counter);
            let mut label = "Read".to_string();

            if opts.common.tag.is_some() {
                label.push_str(&format!(" tag={tag}"));
            }
            if opts.common.counter.is_some() {
                label.push_str(&format!(" counter={counter}"));
            }
            if opts.common.sender_id.is_some() {
                label.push_str(&format!(" sender={sender_id}"));
            }
            if opts.value.is_some() {
                label.push_str(&format!(" value={value}"));
            }

            (SocketAddrV4::new(server, ABD_UDP_PORT), msg, label)
        }
    };

    let payload = rkyv::to_bytes::<RkyvError>(&msg)
        .map_err(|e| anyhow::anyhow!("serialise ABD message: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    info!("🚀  {label} → {}", server_addr.ip());

    let start = Instant::now();
    sock.send_to(&payload, server_addr)?;
    debug!("↗ Sent {} bytes", payload.len());

    let mut buf = [0u8; 1024];
    let (n, from) = sock.recv_from(&mut buf)?;
    let elapsed = start.elapsed();
    debug!("↙  response ({n} bytes) from {from}");

    let archived = rkyv::access::<ArchivedAbdMsg, RkyvError>(&buf[..n])
        .map_err(|e| anyhow::anyhow!("deserialise: {e}"))?;
    let resp: AbdMsg = deserialize::<AbdMsg, RkyvError>(archived)
        .map_err(|e| anyhow::anyhow!("deserialise (stage 2): {e}"))?;
    debug!("Deserialised response: {resp:?}");

    report(&resp, elapsed);
    Ok(())
}

fn report(resp: &AbdMsg, elapsed: Duration) {
    match resp.type_.try_into() {
        Ok(msg_type @ AbdMsgType::WriteAck) => {
            info!("✅  {msg_type:?}. Took {elapsed:?}");
            debug!(
                "sender={} tag={} value={} counter={}",
                resp.sender, resp.tag, resp.value, resp.counter
            );
        }
        Ok(msg_type @ AbdMsgType::ReadAck) => {
            info!(
                "✅  {msg_type:?} tag={} value={}. Took {elapsed:?}",
                resp.tag, resp.value
            );
            debug!(
                "sender={} tag={} value={} counter={}",
                resp.sender, resp.tag, resp.value, resp.counter
            );
        }
        Ok(other) => warn!(
            "❌  Unexpected message type: {other:?} from @{}",
            resp.sender
        ),
        Err(_) => warn!(
            "❌  Unknown message type: {} from @{}",
            resp.type_, resp.sender
        ),
    }
}
