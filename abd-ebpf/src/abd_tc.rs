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
    tc::{self, broadcast_to_nodes, redirect_to_client, store_client_info, ABD_R_IDX, ABD_W_IDX},
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
static CLIENT_INFO: Array<ClientInfo> = Array::with_max_entries(2, 0);

/// 0 = idle, 1 = query phase, 2 = propagation phase
#[map]
static STATUS: Array<Status> = Array::with_max_entries(2, 0);

/// Reader: largest tag and corresponding data from query aggregation
/// Single-writer: tag = current tag, data unused
/// Multi-writer: largest tag from query aggregation, data to be written
#[map]
static TAG_DATA: Array<TaggedData> = Array::with_max_entries(2, 0);

/// Monotonically-increasing
#[map]
static COUNTER: Array<Counter> = Array::with_max_entries(2, 0);

/// Acknowledgment count for current operation
#[map]
static ACK_COUNT: Array<Counter> = Array::with_max_entries(2, 0);

#[allow(clippy::needless_pass_by_value)]
#[classifier]
pub fn abd_tc(ctx: TcContext) -> i32 {
    match try_abd_tc(&ctx) {
        Ok(ret) => ret,
        Err(err) => {
            error!(&ctx, "{}", err.as_ref());
            TC_ACT_PIPE
        }
    }
}

fn try_abd_tc(ctx: &TcContext) -> Result<i32, AbdError> {
    let my_id = read_global(&NODE_ID);
    if my_id == 0 {
        return Err(AbdError::GlobalUnset);
    }

    let Some(pkt) = try_parse_abd_packet(ctx)? else {
        return Ok(TC_ACT_PIPE);
    };

    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        return Err(AbdError::GlobalUnset);
    }
    if pkt.msg.sender_id > num_nodes {
        return Err(AbdError::InvalidSenderID);
    }

    let msg_type = AbdMessageType::try_from(pkt.msg.type_.to_native())
        .map_err(|()| AbdError::InvalidMessageType)?;
    let recipient_role = AbdRole::try_from(pkt.msg.recipient_role.to_native())
        .map_err(|()| AbdError::InvalidReceiverRole)?;
    let sender_role = AbdRole::try_from(pkt.msg.sender_role.to_native())
        .map_err(|()| AbdError::InvalidSenderRole)?;

    match (msg_type, recipient_role, sender_role) {
        (AbdMessageType::Read, AbdRole::Reader, AbdRole::Client) => {
            // info!(ctx, "received READ request");
            handle_client_read(ctx, pkt, my_id, num_nodes)
        }
        (AbdMessageType::Write, AbdRole::Writer, AbdRole::Client) => {
            // info!(ctx, "received WRITE request");
            handle_client_write(ctx, pkt, my_id, num_nodes)
        }
        (AbdMessageType::ReadAck, AbdRole::Reader, AbdRole::Server) => {
            handle_read_ack(ctx, pkt, recipient_role, my_id, num_nodes)
        }
        #[cfg(feature = "multi-writer")]
        (AbdMessageType::ReadAck, AbdRole::Writer, AbdRole::Server) => {
            handle_read_ack(ctx, pkt, recipient_role, my_id, num_nodes)
        }
        (AbdMessageType::WriteAck, AbdRole::Reader | AbdRole::Writer, AbdRole::Server) => {
            handle_write_ack(ctx, pkt, recipient_role, my_id, num_nodes)
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

/// Handle a READ request from a client
fn handle_client_read(
    ctx: &TcContext,
    pkt: AbdContext,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    let i = ABD_R_IDX;

    if STATUS.get(i).map_or(0, |s| s.val) != 0 {
        // warn!(ctx, "drop READ, busy", itos(i));
        return Ok(TC_ACT_SHOT);
    }

    map_update_locked(&STATUS, i, &1)?;

    map_update_locked(&ACK_COUNT, i, &0)?;

    let max_tag_data = map_get_mut(&TAG_DATA, i)?;
    try_spin_lock_acquire(&mut max_tag_data.tag.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
    max_tag_data.tag.val = 0;
    spin_lock_release(&mut max_tag_data.tag.lock);

    // remember client
    store_client_info(&NODES, my_id, &CLIENT_INFO, i, &pkt)?;

    // increment counter
    let new_counter = map_increment_locked(&COUNTER, i)?;

    // craft query packet
    munge!(let ArchivedAbdMessage { mut counter, mut recipient_role, mut sender_id, mut sender_role, .. } = pkt.msg);

    let mut udp_csum = pkt.udp.check;

    recompute_udp_csum_for_abd_update(&counter, &new_counter.into(), &mut udp_csum)?;
    *counter = new_counter.into();

    let new_recipient_role = AbdRole::Server.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role, &mut udp_csum)?;
    *recipient_role = new_recipient_role;

    let new_sender_role = AbdRole::Reader.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role, &mut udp_csum)?;
    *sender_role = new_sender_role;

    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    pkt.udp.check = udp_csum;

    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a WRITE message from a client.
fn handle_client_write(
    ctx: &TcContext,
    pkt: AbdContext,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    #[cfg(not(feature = "multi-writer"))]
    if my_id != 1 {
        // forward the request to the sole writer
        munge!(let ArchivedAbdMessage { mut sender_id, .. } = pkt.msg);

        let mut udp_csum = pkt.udp.check;

        // set sender_id to my_id, so writer knows it's a proxied request
        recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
        *sender_id = my_id.into();

        pkt.udp.check = udp_csum;

        let writer = NODES.get(1).ok_or(AbdError::MapLookupError)?;
        // info!(ctx, "forwarding WRITE to writer");
        return tc::redirect_to_node(ctx, writer);
    }

    if STATUS.get(ABD_W_IDX).map_or(0, |s| s.val) != 0 {
        // warn!(ctx, "drop WRITE, busy");
        return Ok(TC_ACT_SHOT);
    }

    #[cfg(not(feature = "multi-writer"))]
    map_update_locked(&STATUS, ABD_W_IDX, &2)?; // no query phase, go straight to propagation
    #[cfg(feature = "multi-writer")]
    map_update_locked(&STATUS, ABD_W_IDX, &1)?;

    // initialise state
    map_update_locked(&ACK_COUNT, ABD_W_IDX, &0)?;

    let tag_data = map_get_mut(&TAG_DATA, ABD_W_IDX)?;
    try_spin_lock_acquire(&mut tag_data.tag.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
    #[cfg(not(feature = "multi-writer"))]
    {
        // increment tag seq
        tag_data.tag.val = tag::pack(tag::seq(tag_data.tag.val) + 1, 0);
    }
    #[cfg(feature = "multi-writer")]
    {
        // initial tag = <0,w>
        tag_data.tag.val = tag::pack(0, my_id);

        // store the data to be written for later, in the propagation phase
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref::<ArchivedAbdMessageData>(&pkt.msg.data).cast::<u8>(),
                &raw const tag_data.data as *mut u8,
                size_of::<ArchivedAbdMessageData>(),
            );
        }
    }
    spin_lock_release(&mut tag_data.tag.lock);

    // remember client
    store_client_info(&NODES, my_id, &CLIENT_INFO, ABD_W_IDX, &pkt)?;

    // increment counter
    let new_counter = map_increment_locked(&COUNTER, ABD_W_IDX)?;

    // craft query packet
    #[cfg(not(feature = "multi-writer"))]
    munge!(let ArchivedAbdMessage { mut counter, mut recipient_role, mut sender_id, mut sender_role, mut tag, .. } = pkt.msg);
    #[cfg(feature = "multi-writer")]
    munge!(let ArchivedAbdMessage { mut counter, mut recipient_role, mut sender_id, mut sender_role, mut type_, .. } = pkt.msg);

    let mut udp_csum = pkt.udp.check;

    recompute_udp_csum_for_abd_update(&counter, &new_counter.into(), &mut udp_csum)?;
    *counter = new_counter.into();

    let new_recipient_role = AbdRole::Server.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role, &mut udp_csum)?;
    *recipient_role = new_recipient_role;

    let new_sender_role = AbdRole::Writer.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role, &mut udp_csum)?;
    *sender_role = new_sender_role;

    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    #[cfg(not(feature = "multi-writer"))]
    {
        let new_tag = tag_data.tag.val;
        recompute_udp_csum_for_abd_update(&tag, &new_tag.into(), &mut udp_csum)?;
        *tag = new_tag.into();
    }
    #[cfg(feature = "multi-writer")]
    {
        let new_msg_type = AbdMessageType::Read.into();
        recompute_udp_csum_for_abd_update(&type_, &new_msg_type, &mut udp_csum)?;
        *type_ = new_msg_type;
    }

    pkt.udp.check = udp_csum;

    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a READ-ACK from a replica (query phase)
fn handle_read_ack(
    ctx: &TcContext,
    pkt: AbdContext,
    my_role: AbdRole,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    let i = match my_role {
        AbdRole::Reader => ABD_R_IDX,
        AbdRole::Writer => ABD_W_IDX,
        _ => return Err(AbdError::InvalidSenderRole),
    };

    if STATUS.get(i).map_or(0, |s| s.val) != 1 {
        // debug!(
        //     ctx,
        //     "{}: ignore READ-ACK from @{}, not in phase 1",
        //     tc::itos(i),
        //     pkt.msg.sender_id.to_native()
        // );
        return Ok(TC_ACT_SHOT);
    }

    // ensure counter matches
    let counter_now = COUNTER.get(i).map_or(0, |c| c.val);
    if pkt.msg.counter.to_native() != counter_now {
        warn!(
            ctx,
            "{}: READ-ACK counter mismatch, expected {} but got {}",
            tc::itos(i),
            counter_now,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // debug!(
    //     ctx,
    //     "{}: READ-ACK from @{}, tag=<{},{}>",
    //     tc::itos(i),
    //     pkt.msg.sender_id.to_native(),
    //     tag::seq(pkt.msg.tag.to_native()),
    //     tag::wid(pkt.msg.tag.to_native())
    // );

    // maybe update max tag & data
    let max = map_get_mut(&TAG_DATA, i)?;
    try_spin_lock_acquire(&mut max.tag.lock)?;
    if tag::gt(pkt.msg.tag.to_native(), max.tag.val) {
        max.tag.val = pkt.msg.tag.to_native();

        // writer ignores the data
        if my_role == AbdRole::Reader {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::from_ref::<ArchivedAbdMessageData>(&pkt.msg.data).cast::<u8>(),
                    &raw const max.data as *mut u8,
                    size_of::<ArchivedAbdMessageData>(),
                );
            }
        }
    }
    spin_lock_release(&mut max.tag.lock);

    // bump ACK count and check for majority
    let acks = map_increment_locked(&ACK_COUNT, i)?;
    let majority = u64::from(((num_nodes) >> 1) + 1);
    if acks < majority {
        // debug!(
        //     ctx,
        //     "{}: Got {} READ-ACK(s), waiting for majority ({})...",
        //     tc::itos(i),
        //     acks,
        //     majority
        // );
        return Ok(TC_ACT_SHOT);
    }

    // info!(ctx, "{}: Got majority READ-ACK(s)", tc::itos(i));

    // proceed to phase 2
    map_update_locked(&STATUS, i, &2)?;
    let new_counter = map_increment_locked(&COUNTER, i)?;
    map_update_locked(&ACK_COUNT, i, &0)?;

    // craft propagation packet
    munge!(let ArchivedAbdMessage { mut counter, data, mut recipient_role, mut sender_id, mut sender_role, mut tag, mut type_, .. } = pkt.msg);

    let mut udp_csum = pkt.udp.check;

    let new_sender_role: u32 = my_role.into();
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

    let max = TAG_DATA.get(i).ok_or(AbdError::MapLookupError)?;
    let prop_tag = match my_role {
        AbdRole::Reader => max.tag.val,
        AbdRole::Writer => {
            // new tag must be larger than any tag seen - bump seq and set our wid
            tag::pack(tag::seq(max.tag.val) + 1, my_id)
        }
        _ => return Err(AbdError::InvalidSenderRole),
    };
    recompute_udp_csum_for_abd_update(&tag, &prop_tag.into(), &mut udp_csum)?;
    *tag = prop_tag.into();

    recompute_udp_csum_for_abd_update(&data, &max.data, &mut udp_csum)?;
    overwrite_seal(data, &max.data);

    recompute_udp_csum_for_abd_update(&counter, &new_counter.into(), &mut udp_csum)?;
    *counter = new_counter.into();

    pkt.udp.check = udp_csum;

    // info!(
    //     ctx,
    //     "{}: Propagate tag <{},{}>",
    //     tc::itos(i),
    //     tag::seq(prop_tag),
    //     tag::wid(prop_tag)
    // );

    broadcast_to_nodes(ctx, my_id, &NODES, num_nodes).map(|()| TC_ACT_STOLEN)
}

/// Handle a WRITE-ACK from a replica
fn handle_write_ack(
    ctx: &TcContext,
    pkt: AbdContext,
    my_role: AbdRole,
    my_id: u32,
    num_nodes: u32,
) -> Result<i32, AbdError> {
    let i = match my_role {
        AbdRole::Reader => ABD_R_IDX,
        AbdRole::Writer => {
            #[cfg(not(feature = "multi-writer"))]
            if my_id != 1 {
                warn!(ctx, "drop WRITE-ACK, not writer");
                return Ok(TC_ACT_SHOT);
            }

            ABD_W_IDX
        }
        _ => return Err(AbdError::InvalidSenderRole),
    };

    if STATUS.get(i).map_or(0, |s| s.val) != 2 {
        // debug!(
        //     ctx,
        //     "{}: Ignore WRITE-ACK from @{}, not in phase 2",
        //     tc::itos(i),
        //     pkt.msg.sender_id.to_native()
        // );
        return Ok(TC_ACT_SHOT);
    }

    let counter = pkt.msg.counter.to_native();
    let counter_now = COUNTER.get(i).map_or(0, |c| c.val);
    if counter != counter_now {
        warn!(
            ctx,
            "{}: WRITE-ACK counter mismatch, expected {} but got {}",
            tc::itos(i),
            counter_now,
            counter
        );
        return Ok(TC_ACT_SHOT);
    }

    // debug!(
    //     ctx,
    //     "{}: Received WRITE-ACK from @{}",
    //     tc::itos(i),
    //     pkt.msg.sender_id.to_native(),
    // );

    let acks = map_increment_locked(&ACK_COUNT, i)?;
    let majority = u64::from((num_nodes >> 1) + 1);
    if acks < majority {
        // debug!(
        //     ctx,
        //     "{}: Got {} WRITE-ACK(s), waiting for majority ({})...",
        //     tc::itos(i),
        //     acks,
        //     majority
        // );
        return Ok(TC_ACT_SHOT);
    }

    // info!(ctx, "{}: Committed", tc::itos(i));

    // back to idle
    map_update_locked(&STATUS, i, &0)?;

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

    if my_role == AbdRole::Reader {
        let new_type = AbdMessageType::ReadAck.into();
        recompute_udp_csum_for_abd_update(&type_, &new_type, &mut udp_csum)?;
        *type_ = new_type;
    }

    // tag and value are be the same as the original write

    recompute_udp_csum_for_abd_update(&counter, &0.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udp.check = udp_csum;

    let client = CLIENT_INFO.get(i).ok_or(AbdError::MapLookupError)?;
    let me = NODES.get(my_id).ok_or(AbdError::MapLookupError)?;
    redirect_to_client(ctx, client, me).inspect(|_| {
        // info!(ctx, "{}: ACK -> {}", tc::itos(i), client.ipv4);
    })
}

#[cfg(not(test))]
#[panic_handler]
const fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
