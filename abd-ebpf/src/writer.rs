#![no_std]
#![no_main]

use abd_common::{
    constants::{ABD_MAX_NODES, ABD_UDP_PORT},
    map_types::{ClientInfo, Counter, NodeInfo, Status, Tag},
    message::{AbdMessageType, ArchivedAbdMessage},
};
use abd_ebpf::utils::{
    common::{
        map_increment_locked, map_update, map_update_locked, read_global,
        recompute_udp_csum_for_abd_update, try_parse_abd_packet, AbdContext,
    },
    error::AbdError,
    tc::{broadcast_to_nodes, redirect_to_client, store_client_info},
};
use aya_ebpf::{
    bindings::{BPF_F_RDONLY_PROG, TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_STOLEN},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info, warn};
use rkyv::munge::munge;

/// Set from userspace
#[no_mangle]
static NUM_NODES: u32 = 0;

/// Set from userspace
#[no_mangle]
static NODE_ID: u32 = 0;

/// Node information - populated from userspace (read-only)
#[map]
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_MAX_NODES, BPF_F_RDONLY_PROG);

/// Info about the client we're currently servicing
#[map]
static CLIENT_INFO: Array<ClientInfo> = Array::with_max_entries(1, 0);

/// Status byte: 0 = idle, 1 = writing
#[map]
static STATUS: Array<Status> = Array::with_max_entries(1, 0);

/// monotonically-increasing tag
#[map]
static TAG: Array<Tag> = Array::with_max_entries(1, 0);

/// monotonically-increasing
#[map]
static WRITE_COUNTER: Array<Counter> = Array::with_max_entries(1, 0);

/// acknowledgment count for current operation
#[map]
static ACK_COUNT: Array<Counter> = Array::with_max_entries(1, 0);

#[allow(clippy::needless_pass_by_value)]
#[classifier]
pub fn writer(ctx: TcContext) -> i32 {
    match try_writer(&ctx) {
        Ok(ret) => ret,
        Err(err) => {
            error!(&ctx, "{}", err.as_ref());
            TC_ACT_PIPE
        }
    }
}

fn try_writer(ctx: &TcContext) -> Result<i32, AbdError> {
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        return Err(AbdError::GlobalUnset);
    }

    let Some(pkt) = try_parse_abd_packet(ctx, ABD_UDP_PORT, num_nodes)? else {
        return Ok(TC_ACT_SHOT);
    };

    let msg_type = AbdMessageType::try_from(pkt.msg.type_.to_native())
        .map_err(|()| AbdError::InvalidMessageType)?;
    match msg_type {
        AbdMessageType::Write => handle_client_write(ctx, pkt),
        AbdMessageType::WriteAck => handle_write_ack(ctx, pkt),
        _ => Err(AbdError::UnexpectedMessageType),
    }
}

/// Handle WRITE request from a client
fn handle_client_write(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    // quick rejection that doesn't require locks
    if STATUS.get(0).map_or(0, |s| s.val) != 0 {
        warn!(ctx, "Busy – drop WRITE");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "WRITE from client");

    // set status to writing
    map_update_locked(&STATUS, 0, &1)?;

    // clear ACK count - note this doesn't need a lock as status is already set
    map_update(&ACK_COUNT, 0, &Counter::default())?;

    // remember the client
    store_client_info(ctx, &CLIENT_INFO, &pkt)?;

    // increment tag & write counter
    let new_tag = map_increment_locked(&TAG, 0)?;
    let new_wc = map_increment_locked(&WRITE_COUNTER, 0)?;

    // patch message in-place
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd_update(&tag, &new_tag.into(), &mut udp_csum)?;
    *tag = new_tag.into();

    recompute_udp_csum_for_abd_update(&counter, &new_wc.into(), &mut udp_csum)?;
    *counter = new_wc.into();

    pkt.udp.check = udp_csum;

    let num_nodes = read_global(&NUM_NODES);
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle W-ACK from replica
fn handle_write_ack(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    if STATUS.get(0).map_or(0, |s| s.val) == 0 {
        debug!(ctx, "No write in progress – drop W-ACK");
        return Ok(TC_ACT_SHOT);
    }

    // ensure the ACK is for the current operation
    let wc_now = WRITE_COUNTER.get(0).map_or(0, |c| c.val);
    if pkt.msg.counter.to_native() != wc_now {
        warn!(
            ctx,
            "W-ACK counter mismatch (expected {}, got {})",
            wc_now,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(ctx, "Received W-ACK from @{}", pkt.msg.sender.to_native());

    // bump ack counter
    let new_acks = map_increment_locked(&ACK_COUNT, 0)?;

    // check if we have enough ACKs
    let majority = u64::from(((read_global(&NUM_NODES)) >> 1) + 1);
    if new_acks < majority {
        debug!(
            ctx,
            "Got {} W-ACK(s), waiting for majority ({})...", new_acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Committed");

    // reset status back to idle
    map_update_locked(&STATUS, 0, &0)?;

    send_write_ack_to_client(ctx, pkt)
}

/// After write commit, send a W-ACK back to original client
fn send_write_ack_to_client(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, .. } = pkt.msg);

    // set ABD message values in-place (clearing internal fields)
    let mut udp_csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd_update(&tag, &0.into(), &mut udp_csum)?;
    *tag = 0.into();

    recompute_udp_csum_for_abd_update(&counter, &0.into(), &mut udp_csum)?;
    *counter = 0.into();
    pkt.udp.check = udp_csum;

    let client = CLIENT_INFO.get(0).ok_or(AbdError::MapLookupError)?;
    let me = NODES.get(my_id).ok_or(AbdError::MapLookupError)?;
    redirect_to_client(ctx, client, me).inspect(|_| {
        info!(ctx, "W-ACK -> {}", client.ipv4);
    })
}

#[cfg(not(test))]
#[panic_handler]
const fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
