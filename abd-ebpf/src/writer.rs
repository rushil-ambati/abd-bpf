#![no_std]
#![no_main]

use abd_common::{
    AbdMsgType, ArchivedAbdMsg, ClientInfo, NodeInfo, ABD_MAX_NODES, ABD_UDP_PORT, ABD_WRITER_ID,
};
use abd_ebpf::helpers::{
    common::{
        map_get_or_default, map_increment, map_insert, parse_abd_packet, read_global,
        update_abd_msg_field, AbdPacket, BpfResult,
    },
    tc::{broadcast_to_nodes, redirect_to_client, store_client_info},
};
use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_STOLEN},
    macros::{classifier, map},
    maps::{Array, HashMap},
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

/// Node information - populated from userspace
#[map]
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_MAX_NODES, 0);

/// Info about the client we're currently servicing
#[map]
static CLIENT_INFO: HashMap<u32, ClientInfo> = HashMap::with_max_entries(1, 0);

/// Flag: 0 = idle, 1 = write in progress
#[map]
static ACTIVE: HashMap<u32, bool> = HashMap::with_max_entries(1, 0);

/// monotonically-increasing tag
#[map]
static TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// monotonically-increasing
#[map]
static WRITE_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// acknowledgment count for current operation
#[map]
static ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[allow(clippy::needless_pass_by_value)]
#[classifier]
pub fn writer(ctx: TcContext) -> i32 {
    match try_writer(&ctx) {
        Ok(act) => act,
        Err(act) => i32::try_from(act).unwrap_or(TC_ACT_SHOT),
    }
}

fn try_writer(ctx: &TcContext) -> BpfResult<i32> {
    let num_nodes = unsafe { read_global(&NUM_NODES) };
    if num_nodes == 0 {
        error!(ctx, "NUM_NODES is not set");
        return Err(TC_ACT_SHOT.into());
    }
    let my_id = unsafe { read_global(&NODE_ID) };
    if my_id != ABD_WRITER_ID {
        error!(ctx, "NODE_ID is not set");
        return Err(TC_ACT_SHOT.into());
    }

    let pkt = parse_abd_packet(ctx, ABD_UDP_PORT, num_nodes)?;
    let sender = pkt.msg.sender.to_native();
    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMsgType::try_from(msg_type).map_err(|()| {
        error!(ctx, "Invalid message type {} from {}", msg_type, sender);
        TC_ACT_SHOT
    })?;
    match parsed_msg_type {
        AbdMsgType::Write => handle_client_write(ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(ctx, pkt),
        _ => {
            warn!(
                ctx,
                "Received unexpected message type: {} from @{}, dropping...", msg_type, sender
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle WRITE request from a client
fn handle_client_write(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    if map_get_or_default(&ACTIVE, &0) {
        warn!(ctx, "Busy – drop WRITE");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "WRITE({}) from client", pkt.msg.value.to_native());

    map_insert(ctx, &ACTIVE, &0, &true)?;
    map_insert(ctx, &ACK_COUNT, &0, &0)?;

    store_client_info(ctx, &CLIENT_INFO, &pkt)
        .inspect_err(|_| error!(ctx, "Failed to store client info"))?;

    // increment tag & write counter
    let new_tag = map_increment(ctx, &TAG, &0)?;
    let new_wc = map_increment(ctx, &WRITE_COUNTER, &0)?;

    // set ABD message values in-place
    munge!(let ArchivedAbdMsg { mut counter, mut sender, mut tag, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;
    let my_id = unsafe { read_global(&NODE_ID) };
    update_abd_msg_field(ctx, &mut sender, my_id.into(), &mut udp_csum)?;
    update_abd_msg_field(ctx, &mut tag, new_tag.into(), &mut udp_csum)?;
    update_abd_msg_field(ctx, &mut counter, new_wc.into(), &mut udp_csum)?;
    pkt.udph.check = udp_csum;

    let num_nodes = unsafe { read_global(&NUM_NODES) };
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast WRITE request"))
}

/// Handle W-ACK from replica
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    let sender = pkt.msg.sender.to_native();

    if !map_get_or_default(&ACTIVE, &0) {
        debug!(ctx, "No write in progress – drop W-ACK from @{}", sender);
        return Ok(TC_ACT_SHOT);
    }

    // ensure the ACK is for the current operation
    let counter = pkt.msg.counter.to_native();
    let wc = map_get_or_default(&WRITE_COUNTER, &0);
    if counter != wc {
        warn!(
            ctx,
            "W-ACK counter mismatch (expected {}, got {})", wc, counter
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(ctx, "Received W-ACK from @{}", sender);

    // bump ack counter
    let acks = map_increment(ctx, &ACK_COUNT, &0)?;

    // check if we have enough ACKs
    let majority = u64::from(((unsafe { read_global(&NUM_NODES) }) >> 1) + 1);
    if acks < majority {
        info!(
            ctx,
            "Got {} WRITE-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "WRITE committed, majority ({}) reached", majority);

    // clean up
    map_insert(ctx, &ACTIVE, &0, &false)?;
    map_insert(ctx, &ACK_COUNT, &0, &0)?;

    send_write_ack_to_client(ctx, pkt)
        .inspect_err(|_| error!(ctx, "Failed to redirect W-ACK to client"))
}

/// After write commit, send a W-ACK back to original client
fn send_write_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMsg { mut counter, mut sender, mut tag, .. } = pkt.msg);

    // set ABD message values in-place (clearing internal fields)
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { read_global(&NODE_ID) };
    update_abd_msg_field(ctx, &mut sender, my_id.into(), &mut udp_csum)?;
    update_abd_msg_field(ctx, &mut tag, 0.into(), &mut udp_csum)?;
    update_abd_msg_field(ctx, &mut counter, 0.into(), &mut udp_csum)?;

    pkt.udph.check = udp_csum;

    let client = unsafe { CLIENT_INFO.get(&0) }.ok_or_else(|| {
        error!(ctx, "Failed to get client info");
        TC_ACT_SHOT
    })?;
    let me = NODES.get(my_id).ok_or_else(|| {
        error!(ctx, "Failed to get info for self (@{})", my_id);
        TC_ACT_SHOT
    })?;
    redirect_to_client(ctx, client, me).inspect(|_| {
        info!(ctx, "W-ACK -> {}", client.ipv4);
    })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
