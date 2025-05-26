#![no_std]
#![no_main]

use abd_common::{
    constants::ABD_MAX_NODES,
    map_types::{ClientInfo, Counter, NodeInfo, Status, TaggedData},
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage, ArchivedAbdMessageData},
    tag,
};
use abd_ebpf::utils::{
    common::{
        map_get_mut, map_increment_locked, map_update_locked, overwrite_seal, read_global,
        recompute_udp_csum_for_abd_update, try_parse_abd_packet, AbdContext,
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
static MAX_TAG_DATA: Array<TaggedData> = Array::with_max_entries(1, 0);

/// Monotonically-increasing
#[map]
static COUNTER: Array<Counter> = Array::with_max_entries(1, 0);

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
    let my_id = read_global(&NODE_ID);
    if my_id == 0 {
        return Err(AbdError::GlobalUnset);
    }

    let Some(pkt) = try_parse_abd_packet(ctx)? else {
        return Ok(TC_ACT_PIPE);
    };

    // Validate recipient role and sender ID
    // Sender role is validated below depending on the message type
    let recipient_role = AbdRole::try_from(pkt.msg.recipient_role.to_native())
        .map_err(|()| AbdError::InvalidReceiverRole)?;
    if recipient_role != AbdRole::Reader {
        return Ok(TC_ACT_PIPE);
    }
    let sender_role = AbdRole::try_from(pkt.msg.sender_role.to_native())
        .map_err(|()| AbdError::InvalidSenderRole)?;
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        return Err(AbdError::GlobalUnset);
    }
    if pkt.msg.sender_id > num_nodes {
        return Err(AbdError::InvalidSenderID);
    }

    let msg_type = AbdMessageType::try_from(pkt.msg.type_.to_native())
        .map_err(|()| AbdError::InvalidMessageType)?;
    match msg_type {
        AbdMessageType::Read => {
            if sender_role != AbdRole::Client {
                return Err(AbdError::InvalidSenderRole);
            }

            handle_read(ctx, pkt, my_id, num_nodes)
        }
        AbdMessageType::ReadAck => {
            if sender_role != AbdRole::Server {
                return Err(AbdError::InvalidSenderRole);
            }

            handle_read_ack(ctx, pkt, my_id, num_nodes)
        }
        AbdMessageType::WriteAck => {
            if sender_role != AbdRole::Server {
                return Err(AbdError::InvalidSenderRole);
            }

            handle_write_ack(ctx, pkt, my_id, num_nodes)
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

/// Handle a READ request from a client (Phase-1)
fn handle_read(
    ctx: &TcContext,
    pkt: AbdContext,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    if STATUS.get(0).map_or(0, |s| s.val) != 0 {
        warn!(ctx, "Busy – drop READ");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "READ from client");

    // set status to Phase-1
    map_update_locked(&STATUS, 0, &1)?;

    // initialise Phase-1 state
    map_update_locked(&ACK_COUNT, 0, &0)?;
    {
        // reset MAX_TAG_DATA (under its tag's lock)
        let max = map_get_mut(&MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(&mut max.tag.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
        max.tag.val = 0;
        spin_lock_release(&mut max.tag.lock);
    }

    // remember client
    store_client_info(ctx, &CLIENT_INFO, &pkt)?;

    // increment counter
    let new_counter = map_increment_locked(&COUNTER, 0)?;

    // craft query packet
    munge!(let ArchivedAbdMessage { mut counter, mut recipient_role, mut sender_id, mut sender_role, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let new_recipient_role = AbdRole::Server.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role, &mut udp_csum)?;
    *recipient_role = new_recipient_role;

    let new_sender_role = AbdRole::Reader.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role, &mut udp_csum)?;
    *sender_role = new_sender_role;

    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    recompute_udp_csum_for_abd_update(&counter, &new_counter.into(), &mut udp_csum)?;
    *counter = new_counter.into();

    pkt.udp.check = udp_csum;

    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a R-ACK from a replica (Phase-1)
fn handle_read_ack(
    ctx: &TcContext,
    pkt: AbdContext,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    if STATUS.get(0).map_or(0, |s| s.val) != 1 {
        debug!(
            ctx,
            "Ignore R-ACK from @{} - not in Phase-1",
            pkt.msg.sender_id.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure counter matches
    let counter_now = COUNTER.get(0).map_or(0, |c| c.val);
    if pkt.msg.counter.to_native() != counter_now {
        warn!(
            ctx,
            "Phase-1: R-ACK counter mismatch: expected {} but got {}",
            counter_now,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-1: R-ACK from @{} (tag=<{},{}>)",
        pkt.msg.sender_id.to_native(),
        tag::seq(pkt.msg.tag.to_native()),
        tag::wid(pkt.msg.tag.to_native())
    );

    // maybe update max tag & data
    {
        let max = map_get_mut(&MAX_TAG_DATA, 0)?;
        try_spin_lock_acquire(&mut max.tag.lock)?;
        if tag::gt(pkt.msg.tag.to_native(), max.tag.val) {
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

    // bump ACK count
    let acks = map_increment_locked(&ACK_COUNT, 0)?;
    let majority = u64::from(((num_nodes) >> 1) + 1);
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
    let new_counter = map_increment_locked(&COUNTER, 0)?;
    map_update_locked(&ACK_COUNT, 0, &0)?;

    // craft propagation packet
    munge!(let ArchivedAbdMessage { mut counter, data, mut recipient_role, mut sender_id, mut sender_role, mut tag, mut type_, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let new_sender_role: u32 = AbdRole::Reader.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role.into(), &mut udp_csum)?;
    *sender_role = new_sender_role.into();

    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    let new_recipient_role: u32 = AbdRole::Server.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role.into(), &mut udp_csum)?;
    *recipient_role = new_recipient_role.into();

    let new_type = AbdMessageType::Write.into();
    recompute_udp_csum_for_abd_update(&type_, &new_type, &mut udp_csum)?;
    *type_ = new_type;

    let max = MAX_TAG_DATA.get(0).ok_or(AbdError::MapLookupError)?;
    let max_tag = max.tag.val;
    recompute_udp_csum_for_abd_update(&tag, &max_tag.into(), &mut udp_csum)?;
    *tag = max_tag.into();

    recompute_udp_csum_for_abd_update(&data, &max.data, &mut udp_csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd_update(&counter, &new_counter.into(), &mut udp_csum)?;
    *counter = new_counter.into();

    pkt.udp.check = udp_csum;

    info!(
        ctx,
        "Phase-2: propagate tag=<{},{}>",
        max_tag,
        tag::seq(max_tag),
        tag::wid(max_tag)
    );

    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a W-ACK from a replica (Phase-2)
fn handle_write_ack(
    ctx: &TcContext,
    pkt: AbdContext,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    if STATUS.get(0).map_or(0, |s| s.val) != 2 {
        debug!(
            ctx,
            "Ignore W-ACK from @{} - not in Phase-2",
            pkt.msg.sender_id.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    let counter = pkt.msg.counter.to_native();
    let counter_now = COUNTER.get(0).map_or(0, |c| c.val);
    if counter != counter_now {
        warn!(
            ctx,
            "Phase-2: W-ACK counter mismatch: expected {} but got {}", counter_now, counter
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-2: received W-ACK from @{}",
        pkt.msg.sender_id.to_native(),
    );

    let acks = map_increment_locked(&ACK_COUNT, 0)?;
    let majority = u64::from((num_nodes >> 1) + 1);
    if acks < majority {
        debug!(
            ctx,
            "Phase-2: got {} W-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-2: committed");

    // back to idle
    map_update_locked(&STATUS, 0, &0)?;

    // craft ACK to client
    munge!(let ArchivedAbdMessage { mut counter, mut recipient_role, mut sender_id, mut sender_role, mut type_, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let new_sender_role: u32 = AbdRole::Reader.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role.into(), &mut udp_csum)?;
    *sender_role = new_sender_role.into();

    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    let new_recipient_role: u32 = AbdRole::Client.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role.into(), &mut udp_csum)?;
    *recipient_role = new_recipient_role.into();

    let new_type = AbdMessageType::ReadAck.into();
    recompute_udp_csum_for_abd_update(&type_, &new_type, &mut udp_csum)?;
    *type_ = new_type;

    // tag and value should be the same as the original write

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
