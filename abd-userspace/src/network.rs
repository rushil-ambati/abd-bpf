//! Network layer for ABD protocol communication
//!
//! This module handles UDP socket creation, message serialization/deserialization,
//! and the main receive loop that dispatches messages to appropriate handlers.

use std::net::SocketAddr;

use abd_common::message::{AbdRole, ArchivedAbdMessage};
use anyhow::Result;
use log::{debug, warn};
use rkyv::{access_mut, rancor};
use tokio::net::UdpSocket;

use crate::{node, protocol::Context, server};

/// Create a new UDP socket with SO_REUSEPORT for load balancing across cores
pub fn create_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};

    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, None)?;

    // Enable SO_REUSEPORT for load balancing across multiple workers
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;

    Ok(UdpSocket::from_std(socket.into())?)
}

/// Send a message to a specific peer
pub async fn send_message(
    socket: &UdpSocket,
    msg: &ArchivedAbdMessage,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Convert message to bytes for transmission
    let ptr = msg as *const ArchivedAbdMessage as *const u8;
    let len = core::mem::size_of::<ArchivedAbdMessage>();
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };

    socket.send_to(bytes, peer_addr).await?;
    debug!("Sent message to {}: {:?}", peer_addr, msg.type_.to_native());

    Ok(())
}

/// Main worker loop that receives and dispatches messages
///
/// This is the core receive loop that:
/// 1. Receives UDP packets from the socket
/// 2. Deserializes them into ArchivedAbdMessage
/// 3. Dispatches to the appropriate handler based on recipient role
/// 4. Implements "busy => drop" semantics identical to eBPF
pub async fn run_worker(ctx: Context) -> Result<()> {
    const MAX_PACKET_SIZE: usize = 65_536;
    let mut buffer = vec![0u8; MAX_PACKET_SIZE].into_boxed_slice();

    log::info!("Starting network worker for node {}", ctx.node_id);

    loop {
        // Receive packet from network
        let (packet_size, peer_addr) = ctx.socket.recv_from(&mut buffer).await?;

        // Deserialize the message
        // Safety: The packet is always exactly ArchivedAbdMessage size from our protocol
        let msg = match access_mut::<ArchivedAbdMessage, rancor::Error>(&mut buffer[..packet_size])
        {
            Ok(msg) => msg.unseal(),
            Err(e) => {
                warn!("Failed to deserialize message from {}: {}", peer_addr, e);
                continue;
            }
        };

        debug!(
            "Received message from {}: type={:?}, recipient_role={:?}",
            peer_addr,
            msg.type_.to_native(),
            msg.recipient_role.to_native()
        );

        // Dispatch based on recipient role
        match AbdRole::try_from(msg.recipient_role.to_native()) {
            Ok(AbdRole::Server) => {
                server::handle_message(&ctx, msg, peer_addr).await;
            }
            Ok(AbdRole::Reader) => {
                node::handle_reader_message(&ctx, msg, peer_addr).await;
            }
            Ok(AbdRole::Writer) => {
                node::handle_writer_message(&ctx, msg, peer_addr).await;
            }
            #[cfg(not(feature = "multi-writer"))]
            Ok(AbdRole::Client) => {
                node::handle_proxy_ack(&ctx, msg).await;
            }
            _ => {
                debug!("Invalid recipient role: {}", msg.recipient_role.to_native());
            }
        }
    }
}
