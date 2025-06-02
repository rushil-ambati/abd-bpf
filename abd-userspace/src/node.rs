//! Node role implementations for ABD protocol
//!
//! This module implements the reader and writer roles of the ABD protocol:
//!
//! ## Reader Protocol
//! 1. **Query Phase**: Send READ to all servers, collect READ-ACKs
//! 2. **Propagation Phase**: Send WRITE with max tag to all servers, collect WRITE-ACKs
//! 3. **Completion**: Return data to client
//!
//! ## Writer Protocol
//! 1. **Query Phase**: Send READ to all servers, collect READ-ACKs to find max tag
//! 2. **Propagation Phase**: Send WRITE with incremented tag to all servers, collect WRITE-ACKs
//! 3. **Completion**: Return success to client
//!
//! ## Single-Writer Mode
//! In single-writer mode, only node 1 can initiate writes. Other nodes proxy WRITE requests
//! to node 1 and forward the response back to the client.

use std::{net::SocketAddr, sync::atomic::Ordering};

use abd_common::{
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag,
};
use log::{debug, info, warn};

use crate::{
    error::AbdError,
    protocol::{majority, Context},
};

/// Handle message directed to reader role
pub async fn handle_reader_message(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) {
    let Ok(msg_type) = AbdMessageType::try_from(msg.type_.to_native()) else {
        warn!("Invalid message type: {}", msg.type_.to_native());
        return;
    };

    match msg_type {
        AbdMessageType::Read => {
            if let Err(e) = handle_client_read(ctx, msg, peer_addr).await {
                warn!("Error handling client READ: {e}");
            }
        }
        AbdMessageType::ReadAck => {
            if let Err(e) = handle_read_ack(ctx, msg, AbdRole::Reader).await {
                warn!("Error handling READ-ACK: {e}");
            }
        }
        AbdMessageType::WriteAck => {
            if let Err(e) = handle_write_ack(ctx, msg, AbdRole::Reader).await {
                warn!("Error handling WRITE-ACK: {e}");
            }
        }
        _ => {
            debug!("Unexpected message type for reader: {msg_type:?}");
        }
    }
}

/// Handle message directed to writer role
pub async fn handle_writer_message(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) {
    let Ok(msg_type) = AbdMessageType::try_from(msg.type_.to_native()) else {
        warn!("Invalid message type: {}", msg.type_.to_native());
        return;
    };

    match msg_type {
        AbdMessageType::Write => {
            if let Err(e) = handle_client_write(ctx, msg, peer_addr).await {
                warn!("Error handling client WRITE: {e}");
            }
        }
        AbdMessageType::ReadAck => {
            if let Err(e) = handle_read_ack(ctx, msg, AbdRole::Writer).await {
                warn!("Error handling READ-ACK: {e}");
            }
        }
        AbdMessageType::WriteAck => {
            if let Err(e) = handle_write_ack(ctx, msg, AbdRole::Writer).await {
                warn!("Error handling WRITE-ACK: {e}");
            }
        }
        _ => {
            debug!("Unexpected message type for writer: {msg_type:?}");
        }
    }
}

/// Handle READ request from client
async fn handle_client_read(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    client_addr: SocketAddr,
) -> Result<(), AbdError> {
    info!("Starting READ operation for client {client_addr}");

    let state = &ctx.state.reader;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Reader busy, dropping request from {client_addr}");
        return Err(AbdError::invalid_state("Reader busy"));
    }

    // Store client address for later response
    *state.client.lock().await = Some(client_addr);

    // Start query phase
    state.start_phase(1);
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Prepare READ message for servers
    msg.counter = counter.into();
    msg.recipient_role = AbdRole::Server.into();
    msg.sender_role = AbdRole::Reader.into();
    msg.sender_id = ctx.node_id.into();
    msg.type_ = AbdMessageType::Read.into();

    // Broadcast to all servers
    if let Err(e) = ctx.broadcast(msg).await {
        state.reset().await;
        return Err(AbdError::network("Failed to broadcast READ", e));
    }
    debug!("Broadcasted READ query to all servers");
    Ok(())
}

/// Handle WRITE request from client
async fn handle_client_write(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    client_addr: SocketAddr,
) -> Result<(), AbdError> {
    #[cfg(not(feature = "multi-writer"))]
    if !ctx.is_writer() {
        return handle_proxy_write(ctx, msg, client_addr).await;
    }

    info!("Starting WRITE operation for client {client_addr}");

    let state = &ctx.state.writer;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Writer busy, dropping request from {client_addr}");
        return Err(AbdError::invalid_state("Writer busy"));
    }

    #[cfg(not(feature = "multi-writer"))]
    // Skip query phase, go straight to propagation
    state.start_phase(2);
    #[cfg(feature = "multi-writer")]
    // Start query phase
    state.start_phase(1);

    // Prepare tag
    let mut tag_lock = state.tag.lock().await;
    #[cfg(feature = "multi-writer")]
    {
        // initial query tag for multi-writer is <0, writer_id>
        *tag_lock = tag::pack(0, ctx.node_id);

        // store data to be written for later propagation
        *state.data.lock().await = msg.data.clone();
    }
    #[cfg(not(feature = "multi-writer"))]
    {
        // increment the existing tag
        *tag_lock = tag::pack(tag::seq(*tag_lock) + 1, ctx.node_id);
    }

    // Store client info
    *state.client.lock().await = Some(client_addr);

    // Increment counter
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Prepare message fields
    msg.counter = counter.into();
    msg.sender_id = ctx.node_id.into();
    msg.sender_role = AbdRole::Writer.into();
    msg.recipient_role = AbdRole::Server.into();

    #[cfg(not(feature = "multi-writer"))]
    {
        msg.tag = (*tag_lock).into();
    }
    #[cfg(feature = "multi-writer")]
    {
        msg.type_ = AbdMessageType::Read.into();
    }

    // Broadcast
    if let Err(e) = ctx.broadcast(msg).await {
        state.reset().await;
        return Err(AbdError::network("Failed to broadcast", e));
    }

    debug!(
        "Broadcasted {} for write",
        if cfg!(feature = "multi-writer") {
            "READ"
        } else {
            "WRITE"
        }
    );
    Ok(())
}

/// Handle READ-ACK responses during query phase
async fn handle_read_ack(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    role: AbdRole,
) -> Result<(), AbdError> {
    let state = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => return Err(AbdError::protocol("Invalid role for read_ack", None)),
    };

    // Check if we're in query phase
    if state.phase.load(Ordering::Acquire) != 1 {
        debug!("{role:?}: Ignore READ-ACK, not in query phase");
        return Ok(());
    }

    // Ensure the counter matches
    let counter_now = state.counter.load(Ordering::Acquire);
    if msg.counter.to_native() != counter_now {
        return Err(AbdError::protocol(
            format!(
                "READ-ACK counter mismatch: expected {counter_now}, got {}",
                msg.counter.to_native()
            ),
            None,
        ));
    }

    debug!(
        "{role:?}: Received READ-ACK from {} with tag <{},{}>",
        msg.sender_id.to_native(),
        tag::seq(msg.tag.to_native()),
        tag::wid(msg.tag.to_native())
    );

    let incoming_tag = msg.tag.to_native();

    // Update our tag to be the maximum seen so far
    {
        let mut current_tag = state.tag.lock().await;
        if tag::gt(incoming_tag, *current_tag) {
            *current_tag = incoming_tag;

            // For readers, also update data to the value with highest tag
            if role == AbdRole::Reader {
                *state.data.lock().await = msg.data.clone();
            }
        }
    }

    // Check if we have majority of responses
    if state.increment_acks() < majority(ctx.num_replicas) {
        debug!(
            "{role:?}: Got {} READ-ACK(s), waiting for majority ({})...",
            state.acks.load(Ordering::Relaxed),
            majority(ctx.num_replicas)
        );
        return Ok(());
    }

    info!("{role:?}: Got majority READ-ACK(s)");

    // Start propagation phase
    state.start_phase(2);
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Calculate propagation tag
    let current_tag = *state.tag.lock().await;
    let prop_tag = match role {
        AbdRole::Reader => current_tag, // Readers propagate the max tag they found
        AbdRole::Writer => tag::pack(tag::seq(current_tag) + 1, ctx.node_id), // Writers increment sequence and use their node ID
        _ => return Err(AbdError::protocol("Invalid role for read_ack", None)),
    };

    // Prepare WRITE message for propagation
    msg.counter = counter.into();

    // Readers propagate what they received
    // Writers propagate original client data
    msg.data = state.data.lock().await.clone();

    msg.recipient_role = AbdRole::Server.into();
    msg.sender_role = role.into();
    msg.sender_id = ctx.node_id.into();
    msg.tag = prop_tag.into();
    msg.type_ = AbdMessageType::Write.into();

    if let Err(e) = ctx.broadcast(msg).await {
        state.reset().await;
        return Err(AbdError::network("Failed to broadcast WRITE", e));
    }
    info!(
        "{role:?}: Propagate tag <{},{}>",
        tag::seq(prop_tag),
        tag::wid(prop_tag)
    );
    Ok(())
}

/// Handle WRITE-ACK responses during propagation phase
async fn handle_write_ack(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    role: AbdRole,
) -> Result<(), AbdError> {
    let state = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => {
            #[cfg(not(feature = "multi-writer"))]
            if !ctx.is_writer() {
                return Err(AbdError::protocol(
                    "Proxy node cannot handle WRITE-ACK",
                    None,
                ));
            }

            &ctx.state.writer
        }
        _ => return Err(AbdError::protocol("Invalid role for write_ack", None)),
    };

    // Check if we're in propagation phase
    if state.phase.load(Ordering::Acquire) != 2 {
        return Err(AbdError::invalid_state(
            "Not in propagation phase for write_ack",
        ));
    }

    // Ensure the counter matches
    let counter_now = state.counter.load(Ordering::Acquire);
    if msg.counter.to_native() != counter_now {
        return Err(AbdError::protocol(
            format!(
                "WRITE-ACK counter mismatch: expected {counter_now}, got {}",
                msg.counter.to_native()
            ),
            None,
        ));
    }

    debug!(
        "{role:?}: Received WRITE-ACK from @{}",
        msg.sender_id.to_native()
    );

    // Check if we have majority of responses
    if state.increment_acks() < majority(ctx.num_replicas) {
        debug!(
            "{role:?}: Got {} WRITE-ACK(s), waiting for majority ({})...",
            state.acks.load(Ordering::Relaxed),
            majority(ctx.num_replicas)
        );
        return Ok(());
    }

    debug!("{role:?}: Committed");

    // Operation completed successfully
    state.phase.store(0, Ordering::Release);

    // Send response to client
    let value = state.client.lock().await.take();
    if let Some(client_addr) = value {
        msg.counter = 0.into();
        msg.recipient_role = AbdRole::Client.into();
        msg.sender_role = role.into();
        msg.sender_id = ctx.node_id.into();
        // tag and data are same as the original request
        if role == AbdRole::Reader {
            msg.type_ = AbdMessageType::ReadAck.into();
        }

        if let Err(e) = ctx.send_to_peer(msg, client_addr).await {
            return Err(AbdError::network("Failed to send response to client", e));
        }
        info!(
            "Completed {} operation for client {}",
            if role == AbdRole::Reader {
                "READ"
            } else {
                "WRITE"
            },
            client_addr
        );
    }
    Ok(())
}

/// Handle write request in single-writer mode (proxy to node 1)
#[cfg(not(feature = "multi-writer"))]
async fn handle_proxy_write(
    ctx: &Context,
    msg: &ArchivedAbdMessage,
    client_addr: SocketAddr,
) -> Result<(), AbdError> {
    info!("Proxying WRITE request from {client_addr} to writer node");

    let state = &ctx.state.writer;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Proxy busy, dropping request from {client_addr}");
        return Err(AbdError::invalid_state("Proxy busy"));
    }

    // Store client address for forwarding response
    *state.client.lock().await = Some(client_addr);
    state.start_phase(3); // Special proxy phase

    // Forward to writer node (node 1)
    let writer_addr = ctx.peers[0]; // Node 1 is at index 0

    if let Err(e) = ctx.send_to_peer(msg, writer_addr).await {
        state.reset().await;
        return Err(AbdError::network("Failed to proxy write to node 1", e));
    }
    debug!("Proxied write request to node 1");
    Ok(())
}

/// Handle proxy ACK in single-writer mode
#[cfg(not(feature = "multi-writer"))]
pub async fn handle_proxy_ack(ctx: &Context, msg: &mut ArchivedAbdMessage) -> Result<(), AbdError> {
    // Only non-writer nodes should receive proxy ACKs
    if ctx.is_writer() {
        return Err(AbdError::protocol(
            "Proxy ACK received by writer node",
            None,
        ));
    }

    let Ok(msg_type) = AbdMessageType::try_from(msg.type_.to_native()) else {
        return Err(AbdError::protocol(
            "Invalid message type for proxy ACK",
            None,
        ));
    };

    // Only handle WRITE-ACK messages
    if msg_type != AbdMessageType::WriteAck {
        return Ok(());
    }

    let state = &ctx.state.writer;

    // Check if we're waiting for proxy response
    if state.phase.load(Ordering::Acquire) != 3 {
        return Ok(());
    }

    info!("Received proxy WRITE-ACK from writer node");

    // Forward response to original client
    let value = state.client.lock().await.take();
    if let Some(client_addr) = value {
        state.phase.store(0, Ordering::Release);

        // Update message for client
        msg.recipient_role = AbdRole::Client.into();
        msg.sender_role = AbdRole::Writer.into();

        if let Err(e) = ctx.send_to_peer(msg, client_addr).await {
            return Err(AbdError::network(
                "Failed to forward write ACK to client",
                e,
            ));
        }
        info!("Forwarded WRITE-ACK to client {client_addr}");
    }
    Ok(())
}
