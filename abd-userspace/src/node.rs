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
    tag::{self, AbdTag},
};
use log::{debug, info, warn};

use crate::protocol::{majority, Context};

/// Handle message directed to reader role
pub async fn handle_reader_message(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) {
    let msg_type = match AbdMessageType::try_from(msg.type_.to_native()) {
        Ok(t) => t,
        Err(_) => {
            warn!("Invalid message type: {}", msg.type_.to_native());
            return;
        }
    };

    match msg_type {
        AbdMessageType::Read => handle_client_read(ctx, msg, peer_addr).await,
        AbdMessageType::ReadAck => handle_read_ack(ctx, msg, AbdRole::Reader).await,
        AbdMessageType::WriteAck => handle_write_ack(ctx, msg, AbdRole::Reader).await,
        _ => {
            debug!("Unexpected message type for reader: {:?}", msg_type);
        }
    }
}

/// Handle message directed to writer role
pub async fn handle_writer_message(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer_addr: SocketAddr,
) {
    let msg_type = match AbdMessageType::try_from(msg.type_.to_native()) {
        Ok(t) => t,
        Err(_) => {
            warn!("Invalid message type: {}", msg.type_.to_native());
            return;
        }
    };

    match msg_type {
        AbdMessageType::Write => handle_client_write(ctx, msg, peer_addr).await,
        AbdMessageType::ReadAck => handle_read_ack(ctx, msg, AbdRole::Writer).await,
        AbdMessageType::WriteAck => handle_write_ack(ctx, msg, AbdRole::Writer).await,
        _ => {
            debug!("Unexpected message type for writer: {:?}", msg_type);
        }
    }
}

/// Handle READ request from client
async fn handle_client_read(ctx: &Context, msg: &mut ArchivedAbdMessage, client_addr: SocketAddr) {
    info!("Starting READ operation for client {}", client_addr);

    let state = &ctx.state.reader;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Reader busy, dropping request from {}", client_addr);
        return;
    }

    // Store client address for later response
    *state.client.lock().await = Some(client_addr);

    // Start query phase
    state.start_phase(1);
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Prepare READ message for servers
    msg.counter = counter.into();
    msg.recipient_role = (AbdRole::Server as u32).into();
    msg.sender_role = (AbdRole::Reader as u32).into();
    msg.sender_id = ctx.node_id.into();
    msg.type_ = (AbdMessageType::Read as u32).into();

    // Broadcast to all servers
    if let Err(e) = ctx.broadcast(msg).await {
        warn!("Failed to broadcast READ: {}", e);
        state.reset().await;
    } else {
        debug!("Broadcasted READ query to all servers");
    }
}

/// Handle WRITE request from client
async fn handle_client_write(ctx: &Context, msg: &mut ArchivedAbdMessage, client_addr: SocketAddr) {
    // In single-writer mode, only node 1 can write
    #[cfg(not(feature = "multi-writer"))]
    if !ctx.is_writer() {
        handle_proxy_write(ctx, msg, client_addr).await;
        return;
    }

    info!("Starting WRITE operation for client {}", client_addr);

    let state = &ctx.state.writer;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Writer busy, dropping request from {}", client_addr);
        return;
    }

    // Store client data and address
    *state.data.lock().await = msg.data.clone();
    *state.client.lock().await = Some(client_addr);

    // Start query phase
    state.start_phase(1);
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Initialize writer tag based on mode
    #[cfg(feature = "multi-writer")]
    let initial_tag = tag::pack(0, ctx.node_id);
    #[cfg(not(feature = "multi-writer"))]
    let initial_tag = 0;

    *state.tag.lock().await = initial_tag;

    // Prepare READ message for query phase
    msg.counter = counter.into();
    msg.recipient_role = (AbdRole::Server as u32).into();
    msg.sender_role = (AbdRole::Writer as u32).into();
    msg.sender_id = ctx.node_id.into();
    msg.type_ = (AbdMessageType::Read as u32).into();

    // Broadcast to all servers
    if let Err(e) = ctx.broadcast(msg).await {
        warn!("Failed to broadcast READ for write: {}", e);
        state.reset().await;
    } else {
        debug!("Broadcasted read query for write operation");
    }
}

/// Handle READ-ACK responses during query phase
async fn handle_read_ack(ctx: &Context, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    let state = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => return,
    };

    // Check if we're in query phase
    if state.phase.load(Ordering::Acquire) != 1 {
        return;
    }

    let incoming_tag = AbdTag::from(msg.tag.to_native());

    // Update our tag to be the maximum seen so far
    {
        let mut current_tag = state.tag.lock().await;
        if tag::gt(incoming_tag, *current_tag) {
            *current_tag = incoming_tag;
        }
    }

    // For readers, also update data to the value with highest tag
    if role == AbdRole::Reader {
        let current_tag = *state.tag.lock().await;
        if incoming_tag == current_tag {
            *state.data.lock().await = msg.data.clone();
        }
    }

    // Check if we have majority of responses
    if state.increment_acks() < majority(ctx.num_replicas) {
        return;
    }

    debug!("Received majority READ-ACKs, starting propagation phase");

    // Start propagation phase
    state.start_phase(2);
    let counter = state.counter.fetch_add(1, Ordering::AcqRel) + 1;

    // Calculate propagation tag
    let current_tag = *state.tag.lock().await;
    let prop_tag = if role == AbdRole::Reader {
        current_tag // Readers propagate the max tag they found
    } else {
        // Writers increment sequence and use their node ID
        tag::pack(tag::seq(current_tag) + 1, ctx.node_id)
    };

    *state.tag.lock().await = prop_tag;

    // Get data to propagate
    let data_to_send = if role == AbdRole::Reader {
        state.data.lock().await.clone() // Readers propagate what they received
    } else {
        state.data.lock().await.clone() // Writers propagate original client data
    };

    // Prepare WRITE message for propagation
    msg.counter = counter.into();
    msg.data = data_to_send;
    msg.recipient_role = (AbdRole::Server as u32).into();
    msg.sender_role = (role as u32).into();
    msg.sender_id = ctx.node_id.into();
    msg.tag = prop_tag.into();
    msg.type_ = (AbdMessageType::Write as u32).into();

    // Broadcast to all servers
    if let Err(e) = ctx.broadcast(&msg).await {
        warn!("Failed to broadcast WRITE: {}", e);
        state.reset().await;
    } else {
        debug!("Broadcasted write with tag {} for propagation", prop_tag);
    }
}

/// Handle WRITE-ACK responses during propagation phase
async fn handle_write_ack(ctx: &Context, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    let state = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => return,
    };

    // Check if we're in propagation phase
    if state.phase.load(Ordering::Acquire) != 2 {
        return;
    }

    // Check if we have majority of responses
    if state.increment_acks() < majority(ctx.num_replicas) {
        return;
    }

    debug!("Received majority WRITE-ACKs, completing operation");

    // Operation completed successfully
    state.phase.store(0, Ordering::Release);

    // Send response to client
    if let Some(client_addr) = state.client.lock().await.take() {
        let data = state.data.lock().await.clone();
        let final_tag = *state.tag.lock().await;

        msg.counter = 0.into();
        msg.data = data;
        msg.recipient_role = (AbdRole::Client as u32).into();
        msg.sender_role = (role as u32).into();
        msg.sender_id = ctx.node_id.into();
        msg.tag = final_tag.into();
        msg.type_ = match role {
            AbdRole::Reader => AbdMessageType::ReadAck as u32,
            AbdRole::Writer => AbdMessageType::WriteAck as u32,
            _ => unreachable!(),
        }
        .into();

        if let Err(e) = ctx.send_to_peer(&msg, client_addr).await {
            warn!("Failed to send response to client {}: {}", client_addr, e);
        } else {
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
    }
}

/// Handle write request in single-writer mode (proxy to node 1)
#[cfg(not(feature = "multi-writer"))]
async fn handle_proxy_write(ctx: &Context, msg: &mut ArchivedAbdMessage, client_addr: SocketAddr) {
    info!("Proxying WRITE request from {} to writer node", client_addr);

    let state = &ctx.state.writer;

    // Check if already busy
    if state.phase.load(Ordering::Acquire) != 0 {
        debug!("Proxy busy, dropping request from {}", client_addr);
        return;
    }

    // Store client address for forwarding response
    *state.client.lock().await = Some(client_addr);
    state.start_phase(3); // Special proxy phase

    // Forward to writer node (node 1)
    let writer_addr = ctx.peers[0]; // Node 1 is at index 0

    if let Err(e) = ctx.send_to_peer(msg, writer_addr).await {
        warn!("Failed to proxy write to node 1: {}", e);
        state.reset().await;
    } else {
        debug!("Proxied write request to node 1");
    }
}

/// Handle proxy ACK in single-writer mode
#[cfg(not(feature = "multi-writer"))]
pub async fn handle_proxy_ack(ctx: &Context, msg: &mut ArchivedAbdMessage) {
    // Only non-writer nodes handle proxy ACKs
    if ctx.is_writer() {
        return;
    }

    // Only handle WRITE-ACK messages
    if msg.type_.to_native() != AbdMessageType::WriteAck as u32 {
        return;
    }

    let state = &ctx.state.writer;

    // Check if we're waiting for proxy response
    if state.phase.load(Ordering::Acquire) != 3 {
        return;
    }

    info!("Received proxy WRITE-ACK from writer node");

    // Forward response to original client
    if let Some(client_addr) = state.client.lock().await.take() {
        state.phase.store(0, Ordering::Release);

        // Update message for client
        msg.recipient_role = (AbdRole::Client as u32).into();
        msg.sender_role = (AbdRole::Writer as u32).into();

        if let Err(e) = ctx.send_to_peer(msg, client_addr).await {
            warn!(
                "Failed to forward write ACK to client {}: {}",
                client_addr, e
            );
        } else {
            info!("Forwarded WRITE-ACK to client {}", client_addr);
        }
    }
}
