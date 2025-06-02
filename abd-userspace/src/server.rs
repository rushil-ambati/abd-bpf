//! Server role - implements XDP path

use std::net::SocketAddr;

use abd_common::{
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage},
    tag,
};

use crate::protocol::{send, Context};

// Freshness pass
async fn freshness_pass(
    store: &crate::protocol::ReplicaStore,
    sender_role: AbdRole,
    sender: u32,
    c: u64,
) -> bool {
    let mut guard = store.counters.write().await;
    let cur = guard.entry((sender_role, sender)).or_default();
    if c <= *cur {
        return false;
    }
    *cur = c;
    true
}

pub async fn handle_server(ctx: &Context, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    let Ok(mtype) = AbdMessageType::try_from(msg.type_.to_native()) else {
        return;
    };
    let Ok(s_role @ (AbdRole::Reader | AbdRole::Writer)) =
        AbdRole::try_from(msg.sender_role.to_native())
    else {
        return;
    };

    if !freshness_pass(
        &ctx.state.server,
        s_role,
        msg.sender_id.to_native(),
        msg.counter.to_native(),
    )
    .await
    {
        return;
    }

    match mtype {
        AbdMessageType::Read => server_read(ctx, msg, peer).await,
        AbdMessageType::Write => server_write(ctx, msg, peer).await,
        _ => {}
    }
}

async fn server_read(ctx: &Context, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    let val = ctx.state.server.value.lock().await;
    msg.data = val.data.clone();
    msg.tag = val.tag.into();
    drop(val);

    msg.recipient_role = msg.sender_role;
    msg.sender_role = AbdRole::Server.into();
    msg.sender_id = ctx.id.into();
    msg.type_ = AbdMessageType::ReadAck.into();

    let _ = send(&ctx.socket, msg, peer).await;
}

async fn server_write(ctx: &Context, msg: &mut ArchivedAbdMessage, peer: SocketAddr) {
    {
        let mut v = ctx.state.server.value.lock().await;
        if tag::gt(msg.tag.into(), v.tag) {
            v.tag = msg.tag.into();
            v.data = msg.data.clone();
        }
    }

    msg.recipient_role = msg.sender_role;
    msg.sender_role = AbdRole::Server.into();
    msg.sender_id = ctx.id.into();
    msg.type_ = AbdMessageType::WriteAck.into();
    let _ = send(&ctx.socket, msg, peer).await;
}
