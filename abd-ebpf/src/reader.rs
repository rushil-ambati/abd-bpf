#![no_std]
#![no_main]

use abd_common::{
    constants::{ABD_MAX_NODES, ABD_UDP_PORT},
    map_types::{ClientInfo, Counter, NodeInfo, Status, TagValue},
    message::{AbdMessageType, ArchivedAbdMessage, ArchivedAbdMessageData},
};
use abd_ebpf::utils::{
    common::{
        map_get_mut, map_increment_locked, map_update, map_update_locked, overwrite_seal,
        parse_abd_packet, read_global, recompute_udp_csum_for_abd, AbdContext, BpfResult,
    },
    spinlock::{spin_lock_release, try_spin_lock_acquire},
    tc::{broadcast_to_nodes, redirect_to_client, store_client_info},
};
use aya_ebpf::{
    bindings::{BPF_F_RDONLY_PROG, TC_ACT_SHOT, TC_ACT_STOLEN},
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

/// 0 = idle, 1/2 = Phase-1/2
#[map]
static STATUS: Array<Status> = Array::with_max_entries(1, 0);

/// Phase-1 aggregation (largest tag & its data)
#[map]
static MAX_TAG_DATA: Array<TagValue> = Array::with_max_entries(1, 0);

/// Monotonically-increasing
#[map]
static READ_COUNTER: Array<Counter> = Array::with_max_entries(1, 0);

/// Acknowledgment count for current operation
#[map]
static ACK_COUNT: Array<Counter> = Array::with_max_entries(1, 0);

#[allow(clippy::needless_pass_by_value)]
#[classifier]
pub fn reader(ctx: TcContext) -> i32 {
    match try_reader(&ctx) {
        Ok(act) => act,
        Err(act) => i32::try_from(act).unwrap_or(TC_ACT_SHOT),
    }
}

fn try_reader(ctx: &TcContext) -> BpfResult<i32> {
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        error!(ctx, "Number of nodes is not set");
        return Err(TC_ACT_SHOT.into());
    }
    let my_id = read_global(&NODE_ID);
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
fn handle_client_read(ctx: &TcContext, pkt: AbdContext) -> BpfResult<i32> {
    // quick rejection that doesn't require locks
    if STATUS.get(0).map(|s| s.val).unwrap_or(0) != 0 {
        debug!(ctx, "Busy – drop READ");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "READ from client");

    // set status to Phase-1
    map_update_locked(ctx, &STATUS, 0, &1)?;

    // initialise Phase-1 state
    map_update(ctx, &ACK_COUNT, 0, &Counter::default())?;
    {
        // initialise MAX_TAG_VALUE (under its tag's lock)
        let max = map_get_mut(ctx, &MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(ctx, &mut max.tag.lock)?;
        max.tag.val = 0;
        spin_lock_release(&mut max.tag.lock);
    }

    // remember client
    store_client_info(ctx, &CLIENT_INFO, &pkt)
        .inspect_err(|_| error!(ctx, "Failed to store client info"))?;

    // increment read counter
    let new_rc = map_increment_locked(ctx, &READ_COUNTER, 0)?;

    // patch message in-place
    munge!(let ArchivedAbdMessage { mut counter, mut sender, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &counter, &new_rc.into(), &mut udp_csum)?;
    *counter = new_rc.into();

    pkt.udph.check = udp_csum;

    let num_nodes = read_global(&NUM_NODES);
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a R-ACK from a replica (Phase-1)
fn handle_read_ack(ctx: &TcContext, pkt: AbdContext) -> BpfResult<i32> {
    // quick phase check
    if STATUS.get(0).map(|s| s.val).unwrap_or(0) != 1 {
        debug!(
            ctx,
            "Dropping R-ACK from @{} - not in Phase-1",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure counter matches this round
    let rc_now = READ_COUNTER.get(0).map(|c| c.val).unwrap_or(0);
    if pkt.msg.counter.to_native() != rc_now {
        warn!(
            ctx,
            "Phase-1: R-ACK counter mismatch: expected {} but got {}",
            rc_now,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-1: R-ACK from @{} (tag={})",
        pkt.msg.sender.to_native(),
        pkt.msg.tag.to_native()
    );

    // maybe update max tag & data
    {
        let max = map_get_mut(ctx, &MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(ctx, &mut max.tag.lock)?;
        if pkt.msg.tag.to_native() > max.tag.val {
            max.tag.val = pkt.msg.tag.to_native();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::from_ref::<ArchivedAbdMessageData>(&pkt.msg.data).cast::<u8>(),
                    &raw const max.data as *mut u8,
                    size_of::<ArchivedAbdMessageData>(),
                );
            }
        }
        spin_lock_release(&mut max.tag.lock);
    }

    // bump ack counter
    let acks = map_increment_locked(ctx, &ACK_COUNT, 0)?;
    let majority = u64::from(((read_global(&NUM_NODES)) >> 1) + 1);
    if acks < majority {
        info!(
            ctx,
            "Phase-1: got {} R-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-1 complete, majority ({}) reached", majority);

    // proceed to Phase-2
    map_update_locked(ctx, &STATUS, 0, &2)?;
    let new_rc = map_increment_locked(ctx, &READ_COUNTER, 0)?;
    map_update_locked(ctx, &ACK_COUNT, 0, &0)?;

    // craft the WRITE message
    let max = MAX_TAG_DATA.get(0).ok_or_else(|| {
        error!(ctx, "Failed to get max tag and data");
        TC_ACT_SHOT
    })?;

    // craft Phase-2 WRITE packet
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, data, .. } = pkt.msg);
    let mut csum = pkt.udph.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &type_, &AbdMessageType::Write.into(), &mut csum)?;
    *type_ = AbdMessageType::Write.into();

    let max_tag = max.tag.val;
    recompute_udp_csum_for_abd(ctx, &tag, &max_tag.into(), &mut csum)?;
    *tag = max_tag.into();

    recompute_udp_csum_for_abd(ctx, &data, &max.data, &mut csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd(ctx, &counter, &new_rc.into(), &mut csum)?;
    *counter = new_rc.into();

    pkt.udph.check = csum;

    info!(ctx, "Phase-2: propagate tag={}", max_tag);

    let num_nodes = read_global(&NUM_NODES);
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a W-ACK from a replica (Phase-2)
fn handle_write_ack(ctx: &TcContext, pkt: AbdContext) -> BpfResult<i32> {
    // quick phase check
    if STATUS.get(0).map(|s| s.val).unwrap_or(0) != 2 {
        debug!(
            ctx,
            "Dropping W-ACK from @{} - not in Phase-2",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    let counter = pkt.msg.counter.to_native();
    let rc_now = READ_COUNTER.get(0).map(|c| c.val).unwrap_or(0);
    if counter != rc_now {
        warn!(
            ctx,
            "Phase-2: W-ACK counter mismatch: expected {} but got {}", rc_now, counter
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-2: received W-ACK from @{}",
        pkt.msg.sender.to_native(),
    );

    let acks = map_increment_locked(ctx, &ACK_COUNT, 0)?;
    let majority = u64::from((read_global(&NUM_NODES) >> 1) + 1);
    if acks < majority {
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
    map_update_locked(ctx, &STATUS, 0, &0)?;

    send_read_ack_to_client(ctx, pkt).inspect_err(|_| error!(ctx, "Failed to send R-ACK to client"))
}

/// After propagation (Phase-2), send a R-ACK to original client
fn send_read_ack_to_client(ctx: &TcContext, pkt: AbdContext) -> BpfResult<i32> {
    let max = MAX_TAG_DATA.get(0).ok_or_else(|| {
        error!(ctx, "Failed to get max tag and data");
        TC_ACT_SHOT
    })?;

    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, data, .. } = pkt.msg);

    // set ABD message values in-place
    let mut udp_csum = pkt.udph.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &type_, &AbdMessageType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMessageType::ReadAck.into();

    recompute_udp_csum_for_abd(ctx, &tag, &max.tag.val.into(), &mut udp_csum)?;
    *tag = max.tag.val.into();

    recompute_udp_csum_for_abd(ctx, &data, &max.data, &mut udp_csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd(ctx, &counter, &0.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udph.check = udp_csum;

    let client = CLIENT_INFO.get(0).ok_or_else(|| {
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
