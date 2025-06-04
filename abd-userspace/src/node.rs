//! Node role handlers

use std::{net::SocketAddr, sync::atomic::Ordering};

use abd_common::{
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag,
};
use log::warn;
use rkyv::rend::u64_le;

use crate::protocol::{broadcast, is_writer, majority, send, Context};

// NODE (Reader / Writer)
pub async fn handle_node(
    ctx: &Context,
    msg: &mut ArchivedAbdMessage,
    peer: SocketAddr,
    role: AbdRole,
) {
    match (
        AbdRole::try_from(msg.sender_role.to_native()),
        AbdMessageType::try_from(msg.type_.to_native()),
    ) {
        (Ok(AbdRole::Client), Ok(AbdMessageType::Read)) if role == AbdRole::Reader => {
            start_op(ctx, msg, peer, role).await;
        }
        (Ok(AbdRole::Client), Ok(AbdMessageType::Write)) if role == AbdRole::Writer => {
            start_op(ctx, msg, peer, role).await;
        }
        (Ok(AbdRole::Server), Ok(AbdMessageType::ReadAck)) => on_read_ack(ctx, msg, role).await,
        (Ok(AbdRole::Server), Ok(AbdMessageType::WriteAck)) => on_write_ack(ctx, msg, role).await,
        _ => {}
    }
}

// Writer / Reader START  (phase‑0 → phase‑1/2)
async fn start_op(ctx: &Context, msg: &mut ArchivedAbdMessage, client: SocketAddr, role: AbdRole) {
    if role == AbdRole::Writer && !is_writer(ctx.id) {
        // ───── proxy to writer node #1 ─────
        proxy_forward(ctx, msg, client).await;
        return;
    }

    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };

    #[cfg(not(feature = "multi-writer"))]
    // single-writer mode directly propagates
    let new_phase = if role == AbdRole::Writer { 2 } else { 1 };
    #[cfg(feature = "multi-writer")]
    let new_phase = 1;

    if st
        .phase
        .compare_exchange(0, new_phase, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // warn!("{role:?} busy – drop");
        return;
    }

    st.acks.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    *st.client.lock().await = Some(client);

    // tag & data bookkeeping
    let init_tag = if role == AbdRole::Writer {
        #[cfg(not(feature = "multi-writer"))]
        {
            let mut t = ctx.state.server.value.lock().await;
            t.tag = tag::pack(tag::seq(t.tag) + 1, 0);
            t.tag
        }
        #[cfg(feature = "multi-writer")]
        {
            tag::pack(0, ctx.id)
        }
    } else {
        0
    };
    *st.tag.lock().await = init_tag;
    #[cfg(feature = "multi-writer")]
    {
        if role == AbdRole::Writer {
            // store data to propagate later
            *st.data.lock().await = msg.data.clone();
        }
    }

    if role == AbdRole::Writer {
        #[cfg(not(feature = "multi-writer"))]
        {
            // single‑writer - propagate straight away (WRITE)
            build_write(ctx, msg, init_tag, st.counter.load(Ordering::Relaxed));
        }
        #[cfg(feature = "multi-writer")]
        {
            // multi‑writer – phase‑1 query (READ)
            build_read_query(ctx, msg, st.counter.load(Ordering::Relaxed), role);
        }
    } else {
        // reader – phase‑1 query (READ)
        build_read_query(ctx, msg, st.counter.load(Ordering::Relaxed), role);
    }

    broadcast(ctx, msg).await;
}

#[inline(always)]
fn build_read_query(ctx: &Context, m: &mut ArchivedAbdMessage, counter: u64, role: AbdRole) {
    m.counter = counter.into();
    m.recipient_role = AbdRole::Server.into();
    m.sender_role = role.into();
    m.sender_id = ctx.id.into();
    m.type_ = AbdMessageType::Read.into();
    m.tag = 0.into();
}

#[cfg(not(feature = "multi-writer"))]
#[inline(always)]
fn build_write(ctx: &Context, m: &mut ArchivedAbdMessage, tag: u64, counter: u64) {
    m.counter = counter.into();
    m.recipient_role = AbdRole::Server.into();
    m.sender_role = AbdRole::Writer.into();
    m.sender_id = ctx.id.into();
    m.type_ = AbdMessageType::Write.into();
    m.tag = tag.into();
}

// Proxy ‑ forward WRITE to writer#1 (stateless)
#[cfg(not(feature = "multi-writer"))]
async fn proxy_forward(ctx: &Context, msg: &mut ArchivedAbdMessage, client: SocketAddr) {
    // Store client address for this proxy request
    *ctx.state.proxy_client.lock().await = Some(client);

    msg.sender_id = ctx.id.into(); // proxy id
                                   // sender_role stays Client, recipient_role stays Writer (unchanged)
    let writer = ctx.peers[0]; // node 1
    let _ = send(&ctx.socket, msg, writer).await;
}

#[cfg(feature = "multi-writer")]
async fn proxy_forward(_ctx: &Context, _msg: &mut ArchivedAbdMessage, _client: SocketAddr) {
    // In multi-writer mode, proxy forwarding is not used.
    warn!("Proxy forwarding is not supported in multi-writer mode");
}

// READ‑ACK  (phase‑1 → phase‑2)
async fn on_read_ack(ctx: &Context, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    #[cfg(not(feature = "multi-writer"))]
    if role == AbdRole::Writer {
        // single-writer mode does not handle READ-ACK
        warn!("Unexpected READ-ACK for Writer role");
        return;
    }

    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };
    if st.phase.load(Ordering::Acquire) != 1
        || msg.counter != u64_le::from(st.counter.load(Ordering::Relaxed))
    {
        return;
    }

    {
        let mut tag = st.tag.lock().await;
        let mut data = st.data.lock().await;
        if tag::gt(msg.tag.into(), *tag) {
            *tag = msg.tag.into();
            if role == AbdRole::Reader {
                *data = msg.data.clone();
            }
        }
    }

    if st.acks.fetch_add(1, Ordering::AcqRel) + 1 < majority(ctx.replicas) {
        return;
    }

    // majority – enter phase‑2 propagate
    st.phase.store(2, Ordering::Release);
    st.acks.store(0, Ordering::Relaxed);
    st.counter.fetch_add(1, Ordering::Relaxed);
    let max_tag = *st.tag.lock().await;
    let prop_tag = if role == AbdRole::Reader {
        max_tag
    } else {
        tag::pack(tag::seq(max_tag) + 1, ctx.id)
    };
    let data = st.data.lock().await.clone();

    msg.counter = st.counter.load(Ordering::Relaxed).into();
    msg.data = data;
    msg.recipient_role = AbdRole::Server.into();
    msg.sender_role = role.into();
    msg.sender_id = ctx.id.into();
    msg.tag = prop_tag.into();
    msg.type_ = AbdMessageType::Write.into();

    broadcast(ctx, msg).await;
}

// WRITE‑ACK (phase‑2 → commit)
async fn on_write_ack(ctx: &Context, msg: &mut ArchivedAbdMessage, role: AbdRole) {
    let st = match role {
        AbdRole::Reader => &ctx.state.reader,
        AbdRole::Writer => &ctx.state.writer,
        _ => unreachable!(),
    };
    if st.phase.load(Ordering::Acquire) != 2
        || msg.counter != u64_le::from(st.counter.load(Ordering::Relaxed))
    {
        return;
    }
    if st.acks.fetch_add(1, Ordering::AcqRel) + 1 < majority(ctx.replicas) {
        return;
    }
    st.phase.store(0, Ordering::Release);

    // send ACK to client
    let value = st.client.lock().await.take();
    if let Some(client) = value {
        msg.counter = 0.into();
        msg.recipient_role = AbdRole::Client.into();
        msg.sender_role = role.into();
        msg.sender_id = ctx.id.into();
        // tag an data are the same as in the WRITE
        if role == AbdRole::Reader {
            msg.type_ = AbdMessageType::ReadAck.into();
        }

        let _ = send(&ctx.socket, msg, client).await;
    }
}

// PROXY path (single‑writer) - stateless
#[cfg(not(feature = "multi-writer"))]
pub async fn proxy_ack(ctx: &Context, msg: &mut ArchivedAbdMessage) {
    if ctx.id == 1 || msg.type_.to_native() != AbdMessageType::WriteAck as u32 {
        return;
    }

    // Check if we have a client waiting for this proxy response
    let client = ctx.state.proxy_client.lock().await.take();
    if let Some(client_addr) = client {
        let _ = send(&ctx.socket, msg, client_addr).await;
    }
}
