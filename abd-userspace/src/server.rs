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
    tag,
};
use log::{debug, warn};

use crate::{error::AbdError, protocol::Context};

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

    let sender_role = match AbdRole::try_from(msg.sender_role.to_native()) {
        Ok(role @ (AbdRole::Reader | AbdRole::Writer)) => role,
        Ok(other) => {
            warn!("Unexpected sender role from {peer_addr}: {other:?}");
            return;
        }
        Err(()) => {
            warn!(
                "Invalid sender role from {peer_addr}: {}",
                msg.sender_role.to_native()
            );
            return;
        }
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
        AbdMessageType::Read => {
            if let Err(e) = handle_read_request(ctx, msg, peer_addr).await {
                warn!("Error handling READ request: {e}");
            }
        }
        AbdMessageType::Write => {
            if let Err(e) = handle_write_request(ctx, msg, peer_addr).await {
                warn!("Error handling WRITE request: {e}");
            }
        }
        _ => {
            debug!("Unexpected message type for server: {msg_type:?}");
        }
    }
}

/// Handle READ request from a reader node
///
/// Protocol: Return current stored (tag, data) pair to the requesting reader
async fn handle_read_request(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) -> Result<(), AbdError> {
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
        return Err(AbdError::network("Failed to send READ ACK", e));
    }
    debug!("Sent READ-ACK to {peer_addr}");
    Ok(())
}

/// Handle WRITE request from a writer node
///
/// Protocol:
/// 1. Compare incoming tag with stored tag
/// 2. If incoming tag is greater, update stored value
/// 3. Send WRITE-ACK with the max tag back to writer
async fn handle_write_request(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) -> Result<(), AbdError> {
    debug!("Handling WRITE request from {peer_addr}");

    let incoming_tag = msg.tag.to_native();
    let stored = ctx.state.server.get_value().await;

    // If incoming tag is greater or equal, update our stored value
    let new_tag = if tag::gt(incoming_tag, stored.tag) {
        debug!(
            "Updating stored value: tag <{},{}> -> <{},{}>",
            tag::seq(stored.tag),
            tag::wid(stored.tag),
            tag::seq(incoming_tag),
            tag::wid(incoming_tag)
        );
        ctx.state
            .server
            .set_value(incoming_tag, msg.data.clone())
            .await;
        incoming_tag
    } else {
        debug!(
            "Keeping existing value: incoming tag <{},{}> <= stored tag <{},{}>",
            tag::seq(incoming_tag),
            tag::wid(incoming_tag),
            tag::seq(stored.tag),
            tag::wid(stored.tag)
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
        return Err(AbdError::network("Failed to send WRITE ACK", e));
    }
    debug!(
        "Sent WRITE-ACK to {peer_addr} with tag <{},{}>",
        tag::seq(new_tag),
        tag::wid(new_tag)
    );
    Ok(())
}
