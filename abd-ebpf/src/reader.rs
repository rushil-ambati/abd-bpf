#![no_std]
#![no_main]

use abd_common::{
    constants::{ABD_MAX_NODES, ABD_UDP_PORT},
    maps::{ClientInfo, NodeInfo},
    msg::{AbdMessageType, ArchivedAbdMessage},
    value::ArchivedAbdValue,
};
use abd_ebpf::utils::{
    common::{
        map_get_or_default, map_increment, map_insert, overwrite_seal, parse_abd_packet,
        read_global, recompute_udp_csum_for_abd, AbdPacket, BpfResult,
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

/// 0 = idle, 1/2 = Phase-1/2
#[map]
static STATUS: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Aggregation results from Phase-1
#[map]
static MAX_TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);
#[map]
static MAX_VALUE: HashMap<u32, ArchivedAbdValue> = HashMap::with_max_entries(1, 0);

/// Monotonically-increasing
#[map]
static READ_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Acknowledgment count for current operation
#[map]
static ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[allow(clippy::needless_pass_by_value)]
#[classifier]
pub fn reader(ctx: TcContext) -> i32 {
    match try_reader(&ctx) {
        Ok(act) => act,
        Err(act) => i32::try_from(act).unwrap_or(TC_ACT_SHOT),
    }
}

fn try_reader(ctx: &TcContext) -> BpfResult<i32> {
    let num_nodes = unsafe { read_global(&NUM_NODES) };
    if num_nodes == 0 {
        error!(ctx, "Number of nodes is not set");
        return Err(TC_ACT_SHOT.into());
    }
    let my_id = unsafe { read_global(&NODE_ID) };
    if my_id == 0 {
        error!(ctx, "Node ID is not set");
        return Err(TC_ACT_SHOT.into());
    }

    let pkt = parse_abd_packet(ctx, ABD_UDP_PORT, num_nodes)?;

    let sender = pkt.msg.sender.to_native();
    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMessageType::try_from(msg_type).map_err(|()| {
        error!(ctx, "Invalid message type {} from {}", msg_type, sender);
        TC_ACT_SHOT
    })?;
    match parsed_msg_type {
        AbdMessageType::Read => handle_client_read(ctx, pkt),
        AbdMessageType::ReadAck => handle_read_ack(ctx, pkt),
        AbdMessageType::WriteAck => handle_write_ack(ctx, pkt),
        _ => {
            warn!(
                ctx,
                "@{}: Received unexpected message type {} from @{}, dropping...",
                my_id,
                msg_type,
                sender
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle READ request from a client (Phase-1)
fn handle_client_read(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    info!(ctx, "READ from client");

    // busy?
    if map_get_or_default(&STATUS, &0) != 0 {
        return Ok(TC_ACT_SHOT);
    }

    // initialise Phase-1 state
    map_insert(ctx, &STATUS, &0, &1)?;
    map_insert(ctx, &MAX_TAG, &0, &0)?;
    map_insert(ctx, &ACK_COUNT, &0, &0)?;

    // remember client
    store_client_info(ctx, &CLIENT_INFO, &pkt)
        .inspect_err(|_| error!(ctx, "Failed to store client info"))?;

    // increment read counter
    let new_rc = map_increment(ctx, &READ_COUNTER, &0)?;

    // set ABD message values in-place
    munge!(let ArchivedAbdMessage { mut counter, mut sender, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { read_global(&NODE_ID) };
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &counter, &new_rc.into(), &mut udp_csum)?;
    *counter = new_rc.into();

    pkt.udph.check = udp_csum;

    let num_nodes = unsafe { read_global(&NUM_NODES) };
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a R-ACK from a replica (Phase-1)
fn handle_read_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, value, .. } = pkt.msg);

    if map_get_or_default(&STATUS, &0) != 1 {
        debug!(
            ctx,
            "Dropping R-ACK from @{} (tag={}) - not in Phase-1",
            sender.to_native(),
            tag.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure the ACK is for the current operation
    let rc = map_get_or_default(&READ_COUNTER, &0);
    if counter.to_native() != rc {
        warn!(
            ctx,
            "R-ACK counter mismatch: expected {} but got {}",
            rc,
            counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-1: R-ACK from @{} (tag={})",
        sender.to_native(),
        tag.to_native()
    );

    // bump ack counter
    let acks = map_increment(ctx, &ACK_COUNT, &0)?;

    // update max tag & value
    let max_tag = map_get_or_default(&MAX_TAG, &0);
    if tag.to_native() > max_tag {
        map_insert(ctx, &MAX_TAG, &0, &tag.to_native())?;
        map_insert(ctx, &MAX_VALUE, &0, &value)?;
    }

    // check if we have enough ACKs
    let majority = u64::from(((unsafe { read_global(&NUM_NODES) }) >> 1) + 1);
    if acks < majority {
        info!(
            ctx,
            "Phase-1: got {} R-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-1 complete, majority ({}) reached", majority);

    // proceed to Phase-2
    map_insert(ctx, &STATUS, &0, &2)?;
    let new_rc = rc + 1;
    map_insert(ctx, &READ_COUNTER, &0, &new_rc)?;
    map_insert(ctx, &ACK_COUNT, &0, &0)?;

    // craft the WRITE message
    let max_tag = map_get_or_default(&MAX_TAG, &0);
    let max_value = unsafe { MAX_VALUE.get(&0) }.ok_or_else(|| {
        error!(ctx, "Failed to get value");
        TC_ACT_SHOT
    })?;
    let mut csum = pkt.udph.check;

    let my_id = unsafe { read_global(&NODE_ID) };
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &type_, &AbdMessageType::Write.into(), &mut csum)?;
    *type_ = AbdMessageType::Write.into();

    recompute_udp_csum_for_abd(ctx, &tag, &max_tag.into(), &mut csum)?;
    *tag = max_tag.into();

    recompute_udp_csum_for_abd(ctx, &value, max_value, &mut csum)?;
    overwrite_seal(value, max_value);

    recompute_udp_csum_for_abd(ctx, &counter, &new_rc.into(), &mut csum)?;
    *counter = new_rc.into();

    pkt.udph.check = csum;

    info!(ctx, "Phase-2: propagate tag={}", max_tag);

    let num_nodes = unsafe { read_global(&NUM_NODES) };
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a W-ACK from a replica (Phase-2)
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    if map_get_or_default(&STATUS, &0) != 2 {
        debug!(
            ctx,
            "Dropping W-ACK from @{} - not in Phase-2",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    let counter = pkt.msg.counter.to_native();
    let rc = map_get_or_default(&READ_COUNTER, &0);
    if counter != rc {
        warn!(
            ctx,
            "Phase-2: W-ACK counter mismatch: expected {} but got {}", rc, counter
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-2: received W-ACK from @{}",
        pkt.msg.sender.to_native(),
    );

    let acks = map_increment(ctx, &ACK_COUNT, &0)?;
    let majority = (unsafe { read_global(&NUM_NODES) } >> 1) + 1;
    if acks < u64::from(majority) {
        info!(
            ctx,
            "Phase-2: got {} W-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(
        ctx,
        "Phase-2 complete, majority ({}) reached", acks, majority
    );

    // clean up
    map_insert(ctx, &STATUS, &0, &0)?;
    map_insert(ctx, &ACK_COUNT, &0, &0)?;

    send_read_ack_to_client(ctx, pkt).inspect_err(|_| error!(ctx, "Failed to send R-ACK to client"))
}

/// After propagation (Phase-2), send a R-ACK to original client
fn send_read_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, value, .. } = pkt.msg);

    let max_tag = map_get_or_default(&MAX_TAG, &0);
    let max_value = unsafe { MAX_VALUE.get(&0) }.ok_or_else(|| {
        error!(ctx, "Failed to get value");
        TC_ACT_SHOT
    })?;

    // set ABD message values in-place
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { read_global(&NODE_ID) };
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &type_, &AbdMessageType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMessageType::ReadAck.into();

    recompute_udp_csum_for_abd(ctx, &tag, &max_tag.into(), &mut udp_csum)?;
    *tag = max_tag.into();

    recompute_udp_csum_for_abd(ctx, &value, max_value, &mut udp_csum)?;
    overwrite_seal(value, max_value);

    recompute_udp_csum_for_abd(ctx, &counter, &0.into(), &mut udp_csum)?;
    *counter = 0.into();

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
        info!(ctx, "R-ACK -> {}", client.ipv4);
    })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
