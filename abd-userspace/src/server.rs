//! Server role implementation for the ABD protocol
//!
//! The server role is responsible for:
//! - Storing replicated data with associated tags
//! - Handling READ requests by returning current stored value
//! - Handling WRITE requests by updating stored value
//! - Enforcing freshness constraints to prevent replay attacks
//!
//! This implementation mirrors the eBPF XDP server path exactly.

use std::net::SocketAddr;

use abd_common::{
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag::{self, AbdTag},
};
use log::{debug, warn};

use crate::protocol::Context;

/// Handle incoming message directed to server role
pub async fn handle_message(ctx: &Context, msg: &mut ArchivedAbdMessage, peer_addr: SocketAddr) {
    let Ok(msg_type) = AbdMessageType::try_from(msg.type_.to_native()) else {
        warn!(
            "Invalid message type from {}: {}",
            peer_addr,
            msg.type_.to_native()
        );
        return;
    };

    let sender_role = if let Ok(AbdRole::Reader | AbdRole::Writer) =
        AbdRole::try_from(msg.sender_role.to_native())
    {
        AbdRole::try_from(msg.sender_role.to_native()).unwrap()
    } else {
        warn!(
            "Invalid sender role from {}: {}",
            peer_addr,
            msg.sender_role.to_native()
        );
        return;
    };

    let sender_id = msg.sender_id.to_native();
    let counter = msg.counter.to_native();

    // Freshness check: ensure this message is newer than what we've seen
    if !ctx
        .state
        .server
        .check_and_update_freshness(sender_role, sender_id, counter)
        .await
    {
        debug!(
            "Stale message from {}:{} (counter={}), dropping",
            sender_role as u8, sender_id, counter
        );
        return;
    }

    match msg_type {
        AbdMessageType::Read => handle_read_request(ctx, msg, peer_addr).await,
        AbdMessageType::Write => handle_write_request(ctx, msg, peer_addr).await,
        _ => {
            debug!("Unexpected message type for server: {msg_type:?}");
        }
    }
}

/// Handle READ request from a reader node
///
/// Protocol: Return current stored (tag, data) pair to the requesting reader
async fn handle_read_request(ctx: &Context, msg: &mut ArchivedAbdMessage, peer_addr: SocketAddr) {
    debug!("Handling READ request from {peer_addr}");

    // Get current stored value
    let stored = ctx.state.server.get_value().await;

    // Prepare READ-ACK response
    msg.data = stored.data;
    msg.tag = stored.tag.into();
    msg.type_ = (AbdMessageType::ReadAck as u32).into();
    msg.recipient_role = msg.sender_role; // Send back to the original sender
    msg.sender_role = (AbdRole::Server as u32).into();
    msg.sender_id = ctx.node_id.into();

    // Send response
    if let Err(e) = ctx.send_to_peer(msg, peer_addr).await {
        warn!("Failed to send READ ACK to {peer_addr}: {e}");
    } else {
        debug!("Sent READ-ACK to {peer_addr}");
    }
}

/// Handle WRITE request from a writer node
///
/// Protocol:
/// 1. Compare incoming tag with stored tag
/// 2. If incoming tag is greater, update stored value
/// 3. Send WRITE-ACK with the max tag back to writer
async fn handle_write_request(ctx: &Context, msg: &mut ArchivedAbdMessage, peer_addr: SocketAddr) {
    debug!("Handling WRITE request from {peer_addr}");

    let incoming_tag = AbdTag::from(msg.tag.to_native());
    let stored = ctx.state.server.get_value().await;

    // If incoming tag is greater or equal, update our stored value
    let new_tag = if tag::gt(incoming_tag, stored.tag) {
        debug!(
            "Updating stored value: tag {} -> {}",
            stored.tag, incoming_tag
        );
        ctx.state
            .server
            .set_value(incoming_tag, msg.data.clone())
            .await;
        incoming_tag
    } else {
        debug!(
            "Keeping existing value: incoming tag {} <= stored tag {}",
            incoming_tag, stored.tag
        );
        stored.tag // Use existing tag
    };

    // Prepare WRITE-ACK response with max tag
    msg.tag = new_tag.into();
    msg.type_ = (AbdMessageType::WriteAck as u32).into();
    msg.recipient_role = msg.sender_role; // Send back to the original sender
    msg.sender_role = (AbdRole::Server as u32).into();
    msg.sender_id = ctx.node_id.into();

    // Send response
    if let Err(e) = ctx.send_to_peer(msg, peer_addr).await {
        warn!("Failed to send write ACK to {peer_addr}: {e}");
    } else {
        debug!("Sent WRITE-ACK to {peer_addr} with tag {new_tag}");
    }
}
