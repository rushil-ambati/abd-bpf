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
        read_global, recompute_udp_csum_for_abd_update, try_parse_abd_packet, AbdContext,
    },
    error::AbdError,
    spinlock::{spin_lock_release, try_spin_lock_acquire},
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
        Ok(ret) => ret,
        Err(err) => {
            error!(&ctx, "{}", err.as_ref());
            TC_ACT_PIPE
        }
    }
}

fn try_reader(ctx: &TcContext) -> Result<i32, AbdError> {
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        return Err(AbdError::GlobalUnset);
    }
    let my_id = read_global(&NODE_ID);
    if my_id == 0 {
        return Err(AbdError::GlobalUnset);
    }

    let Some(pkt) = try_parse_abd_packet(ctx, ABD_UDP_PORT, num_nodes)? else {
        return Ok(TC_ACT_SHOT);
    };

    let msg_type = AbdMessageType::try_from(pkt.msg.type_.to_native())
        .map_err(|()| AbdError::InvalidMessageType)?;
    match msg_type {
        AbdMessageType::Read => handle_client_read(ctx, pkt),
        AbdMessageType::ReadAck => handle_read_ack(ctx, pkt),
        AbdMessageType::WriteAck => handle_write_ack(ctx, pkt),
        _ => Err(AbdError::UnexpectedMessageType),
    }
}

/// Handle READ request from a client (Phase-1)
fn handle_client_read(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    if STATUS.get(0).map_or(0, |s| s.val) != 0 {
        warn!(ctx, "Busy – drop READ");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "READ from client");

    // set status to Phase-1
    map_update_locked(&STATUS, 0, &1)?;

    // initialise Phase-1 state
    map_update(&ACK_COUNT, 0, &Counter::default())?;
    {
        // initialise MAX_TAG_VALUE (under its tag's lock)
        let max = map_get_mut(&MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(&mut max.tag.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
        max.tag.val = 0;
        spin_lock_release(&mut max.tag.lock);
    }

    // remember client
    store_client_info(ctx, &CLIENT_INFO, &pkt)?;

    // increment read counter
    let new_rc = map_increment_locked(&READ_COUNTER, 0)?;

    // patch message in-place
    munge!(let ArchivedAbdMessage { mut counter, mut sender, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd_update(&counter, &new_rc.into(), &mut udp_csum)?;
    *counter = new_rc.into();

    pkt.udp.check = udp_csum;

    let num_nodes = read_global(&NUM_NODES);
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a R-ACK from a replica (Phase-1)
fn handle_read_ack(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    // quick phase check
    if STATUS.get(0).map_or(0, |s| s.val) != 1 {
        debug!(
            ctx,
            "Ignore R-ACK from @{} - not in Phase-1",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure counter matches this round
    let rc_now = READ_COUNTER.get(0).map_or(0, |c| c.val);
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
        let max = map_get_mut(&MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(&mut max.tag.lock)?;
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
    let acks = map_increment_locked(&ACK_COUNT, 0)?;
    let majority = u64::from(((read_global(&NUM_NODES)) >> 1) + 1);
    if acks < majority {
        debug!(
            ctx,
            "Phase-1: got {} R-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-1: got majority R-ACKs");

    // proceed to Phase-2
    map_update_locked(&STATUS, 0, &2)?;
    let new_rc = map_increment_locked(&READ_COUNTER, 0)?;
    map_update_locked(&ACK_COUNT, 0, &0)?;

    // craft the WRITE message
    let max = MAX_TAG_DATA.get(0).ok_or(AbdError::MapLookupError)?;

    // craft Phase-2 WRITE packet
    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, data, .. } = pkt.msg);
    let mut csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender, &my_id.into(), &mut csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd_update(&type_, &AbdMessageType::Write.into(), &mut csum)?;
    *type_ = AbdMessageType::Write.into();

    let max_tag = max.tag.val;
    recompute_udp_csum_for_abd_update(&tag, &max_tag.into(), &mut csum)?;
    *tag = max_tag.into();

    recompute_udp_csum_for_abd_update(&data, &max.data, &mut csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd_update(&counter, &new_rc.into(), &mut csum)?;
    *counter = new_rc.into();

    pkt.udp.check = csum;

    info!(ctx, "Phase-2: propagate tag={}", max_tag);

    let num_nodes = read_global(&NUM_NODES);
    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a W-ACK from a replica (Phase-2)
fn handle_write_ack(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    // quick phase check
    if STATUS.get(0).map_or(0, |s| s.val) != 2 {
        debug!(
            ctx,
            "Ignore W-ACK from @{} - not in Phase-2",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    let counter = pkt.msg.counter.to_native();
    let rc_now = READ_COUNTER.get(0).map_or(0, |c| c.val);
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

    let acks = map_increment_locked(&ACK_COUNT, 0)?;
    let majority = u64::from((read_global(&NUM_NODES) >> 1) + 1);
    if acks < majority {
        debug!(
            ctx,
            "Phase-2: got {} W-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-2: committed");

    // clean up
    map_update_locked(&STATUS, 0, &0)?;

    send_read_ack_to_client(ctx, pkt)
}

/// After propagation (Phase-2), send a R-ACK to original client
fn send_read_ack_to_client(ctx: &TcContext, pkt: AbdContext) -> Result<i32, AbdError> {
    let max = MAX_TAG_DATA.get(0).ok_or(AbdError::MapLookupError)?;

    munge!(let ArchivedAbdMessage { mut counter, mut sender, mut tag, mut type_, data, .. } = pkt.msg);

    // set ABD message values in-place
    let mut udp_csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd_update(&type_, &AbdMessageType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMessageType::ReadAck.into();

    recompute_udp_csum_for_abd_update(&tag, &max.tag.val.into(), &mut udp_csum)?;
    *tag = max.tag.val.into();

    recompute_udp_csum_for_abd_update(&data, &max.data, &mut udp_csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd_update(&counter, &0.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udp.check = udp_csum;

    let client = CLIENT_INFO.get(0).ok_or(AbdError::MapLookupError)?;
    let me = NODES.get(my_id).ok_or(AbdError::MapLookupError)?;
    redirect_to_client(ctx, client, me).inspect(|_| {
        info!(ctx, "R-ACK -> {}", client.ipv4);
    })
}

#[cfg(not(test))]
#[panic_handler]
const fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
