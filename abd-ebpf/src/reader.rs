#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{
    AbdMsgType, ArchivedAbdMsg, ClientInfo, NodeInfo, ABD_NODE_MAX, ABD_SERVER_UDP_PORT,
    ABD_UDP_PORT,
};
use abd_ebpf::helpers::{
    offsets::{ETH_DST_OFF, ETH_SRC_OFF},
    tc::{set_ipv4_dst_addr, set_ipv4_src_addr, set_udp_dst_port, set_udp_src_port, store},
    utils::{calculate_udp_csum_update, parse_abd_packet, AbdPacket, BpfResult},
};
use aya_ebpf::{
    bindings::{TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_STOLEN},
    helpers::r#gen::bpf_redirect,
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
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_NODE_MAX, 0);

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
static MAX_VALUE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Monotonically-increasing
#[map]
static READ_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Acknowledgment count for current operation
#[map]
static ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[classifier]
pub fn reader(ctx: TcContext) -> i32 {
    match try_reader(ctx) {
        Ok(act) => act,
        Err(act) => act as i32,
    }
}

fn try_reader(ctx: TcContext) -> BpfResult<i32> {
    let num_nodes = unsafe { core::ptr::read_volatile(&NUM_NODES) };
    if num_nodes == 0 {
        error!(&ctx, "Number of nodes is not set");
        return Err(TC_ACT_SHOT.into());
    }
    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    if my_id == 0 {
        error!(&ctx, "Node ID is not set");
        return Err(TC_ACT_SHOT.into());
    }

    let pkt = parse_abd_packet(&ctx, ABD_UDP_PORT, num_nodes)?;

    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMsgType::try_from(msg_type).map_err(|_| {
        error!(
            &ctx,
            "Invalid message type {} from {}",
            msg_type,
            pkt.msg.sender.to_native()
        );
        TC_ACT_SHOT
    })?;
    match parsed_msg_type {
        AbdMsgType::Read => handle_client_read(&ctx, pkt),
        AbdMsgType::ReadAck => handle_read_ack(&ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(&ctx, pkt),
        _ => {
            warn!(
                &ctx,
                "@{}: Received unexpected message type {} from @{}, dropping...",
                my_id,
                msg_type,
                pkt.msg.sender.to_native()
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle READ request from a client (Phase-1)
fn handle_client_read(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    info!(ctx, "READ from client");

    if is_not_status(0)? {
        return Ok(TC_ACT_SHOT);
    }

    STATUS.insert(&0, &1, 0).map_err(|_| {
        error!(ctx, "Failed to set status to Phase-1");
        TC_ACT_SHOT
    })?;
    MAX_TAG.insert(&0, &0, 0).map_err(|_| {
        error!(ctx, "Failed to reset max tag");
        TC_ACT_SHOT
    })?;
    MAX_VALUE.insert(&0, &0, 0).map_err(|_| {
        error!(ctx, "Failed to reset max value");
        TC_ACT_SHOT
    })?;
    ACK_COUNT.insert(&0, &0, 0).map_err(|_| {
        error!(ctx, "Failed to reset ack count");
        TC_ACT_SHOT
    })?;

    // remember client
    let client = ClientInfo {
        ipv4: Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
        ifindex: (unsafe { *ctx.skb.skb }).ingress_ifindex,
        port: u16::from_be(pkt.udph.source),
        mac: pkt.eth.src_addr,
    };
    CLIENT_INFO.insert(&0, &client, 0).map_err(|_| {
        error!(ctx, "Failed to store client info");
        TC_ACT_SHOT
    })?;

    // increment read counter
    let new_rc = unsafe { READ_COUNTER.get(&0) }
        .unwrap_or(&0)
        .wrapping_add(1);
    READ_COUNTER.insert(&0, &new_rc, 0).ok();

    // set ABD message values in-place
    munge!(let ArchivedAbdMsg { mut sender, mut counter, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &counter, new_rc.into(), &mut udp_csum)?;
    *counter = new_rc.into();

    pkt.udph.check = udp_csum;

    broadcast_to_nodes(ctx)
        .map(|_| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a R-ACK from a replica (Phase-1)
fn handle_read_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, mut counter, .. } = pkt.msg);

    if is_not_status(1)? {
        debug!(
            ctx,
            "Dropping R-ACK from @{} (tag={} value={}) - not in Phase-1",
            sender.to_native(),
            tag.to_native(),
            value.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure the ACK is for the current operation
    let rc = *unsafe { READ_COUNTER.get(&0) }.unwrap_or(&0);
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
        "Phase-1: R-ACK from @{} (tag={} value={})",
        sender.to_native(),
        tag.to_native(),
        value.to_native()
    );

    // bump ack counter
    let acks = incr_acks(&ctx)?;

    // update max tag & value
    let max_tag = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    if tag.to_native() > max_tag {
        MAX_TAG.insert(&0, &tag.to_native(), 0).ok();
        let val = value.to_native();
        MAX_VALUE.insert(&0, &val, 0).ok();
    }

    // check if we have enough ACKs
    let majority = (unsafe { core::ptr::read_volatile(&NUM_NODES) } >> 1) + 1;
    if acks < (majority as u64) {
        info!(
            ctx,
            "Phase-1: got {} R-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "Phase-1 complete, majority ({}) reached", majority);

    // proceed to Phase-2
    STATUS.insert(&0, &2, 0).map_err(|_| {
        error!(ctx, "Failed to set status to Phase-2");
        TC_ACT_SHOT
    })?;
    let rc_incr = rc + 1;
    READ_COUNTER.insert(&0, &rc_incr, 0).map_err(|_| {
        error!(ctx, "Failed to increment read counter");
        TC_ACT_SHOT
    })?;
    ACK_COUNT.insert(&0, &0, 0).map_err(|_| {
        error!(ctx, "Failed to reset ack count");
        TC_ACT_SHOT
    })?;

    // craft the WRITE message
    let max_tag = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    let max_value = *unsafe { MAX_VALUE.get(&0) }.unwrap_or(&0);

    let mut csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::Write.into(), &mut csum)?;
    *type_ = AbdMsgType::Write.into();

    calculate_udp_csum_update(ctx, &tag, max_tag.into(), &mut csum)?;
    *tag = max_tag.into();

    calculate_udp_csum_update(ctx, &value, max_value.into(), &mut csum)?;
    *value = max_value.into();

    calculate_udp_csum_update(ctx, &counter, rc_incr.into(), &mut csum)?;
    *counter = rc_incr.into();

    pkt.udph.check = csum;

    info!(
        ctx,
        "Phase-2: propagate tag={} value={}", max_tag, max_value
    );

    broadcast_to_nodes(ctx)
        .map(|_| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast READ request"))
}

/// Handle a W-ACK from a replica (Phase-2)
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    if is_not_status(2)? {
        return Ok(TC_ACT_SHOT);
    }

    let rc = *unsafe { READ_COUNTER.get(&0) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != rc {
        warn!(
            ctx,
            "Phase-2: W-ACK counter mismatch: expected {} but got {}",
            rc,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(
        ctx,
        "Phase-2: received W-ACK from @{}",
        pkt.msg.sender.to_native(),
    );

    let acks = incr_acks(ctx)?;
    let majority = (unsafe { core::ptr::read_volatile(&NUM_NODES) } >> 1) + 1;
    if acks < (majority as u64) {
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
    STATUS.remove(&0).map_err(|_| {
        error!(ctx, "Failed to clear status");
        TC_ACT_SHOT
    })?;
    ACK_COUNT.remove(&0).map_err(|_| {
        error!(ctx, "Failed to clear ack count");
        TC_ACT_SHOT
    })?;

    send_read_ack_to_client(ctx, pkt).inspect_err(|_| error!(ctx, "Failed to send R-ACK to client"))
}

/// Broadcast the current packet to every replica
#[inline(always)]
fn broadcast_to_nodes(ctx: &TcContext) -> BpfResult<()> {
    // servers must reply on our UDP port
    set_udp_src_port(ctx, ABD_UDP_PORT).map_err(|e| {
        error!(ctx, "Failed to update source UDP port: {}", e);
        TC_ACT_SHOT
    })?;

    // send on server port
    set_udp_dst_port(ctx, ABD_SERVER_UDP_PORT).map_err(|e| {
        error!(ctx, "Failed to update destination UDP port: {}", e);
        TC_ACT_SHOT
    })?;

    // set L3/L2 source addresses as our own
    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    let me = NODES.get(my_id).ok_or_else(|| {
        error!(ctx, "Failed to get info for self (@{})", my_id);
        TC_ACT_SHOT
    })?;
    set_ipv4_src_addr(ctx, me.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to update source IP address: {}", *e))?;
    store(ctx, ETH_SRC_OFF, &me.mac, 0)
        .inspect_err(|e| error!(ctx, "Failed to update source MAC address: {}", *e))?;

    let num_nodes = unsafe { core::ptr::read_volatile(&NUM_NODES) };
    for i in 1..=num_nodes {
        let peer = NODES.get(i).ok_or_else(|| {
            error!(ctx, "Failed to get info for @{}", i);
            TC_ACT_SHOT
        })?;

        // set L3/L2 destination addresses to the peer
        set_ipv4_dst_addr(ctx, peer.ipv4).map_err(|e| {
            error!(ctx, "Failed to update destination IP address: {}", e);
            TC_ACT_SHOT
        })?;
        store(ctx, ETH_DST_OFF, &peer.mac, 0).map_err(|e| {
            error!(ctx, "Failed to update destination MAC address: {}", e);
            TC_ACT_SHOT
        })?;

        ctx.clone_redirect(peer.ifindex, 0)
            .inspect_err(|e| error!(ctx, "Failed to clone and redirect to @{}: {}", i, *e))?;
        debug!(
            ctx,
            "clone_redirect -> @{} ({}@if{})", i, peer.ipv4, peer.ifindex
        );
    }
    Ok(())
}

/// After propagation (Phase-2), send a R-ACK to original client
fn send_read_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, mut counter, .. } = pkt.msg);

    let max_tag = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    let max_value = *unsafe { MAX_VALUE.get(&0) }.unwrap_or(&0);

    // set ABD message values in-place
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMsgType::ReadAck.into();

    calculate_udp_csum_update(ctx, &tag, max_tag.into(), &mut udp_csum)?;
    *tag = max_tag.into();

    calculate_udp_csum_update(ctx, &value, max_value.into(), &mut udp_csum)?;
    *value = max_value.into();

    calculate_udp_csum_update(ctx, &counter, 0u64.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udph.check = udp_csum;

    let me = unsafe { NODES.get(core::ptr::read_volatile(&NODE_ID)) }.ok_or_else(|| {
        error!(ctx, "Failed to get info for self (@{})", my_id);
        TC_ACT_SHOT
    })?;
    let client = unsafe { CLIENT_INFO.get(&0) }.ok_or_else(|| {
        error!(ctx, "Failed to get client info");
        TC_ACT_SHOT
    })?;

    // L2/L3/L4 back to client
    set_udp_dst_port(ctx, ABD_UDP_PORT)
        .inspect_err(|e| error!(ctx, "Failed to update the source UDP port: {}", *e))?;
    set_udp_dst_port(ctx, client.port)
        .inspect_err(|e| error!(ctx, "Failed to update the destination UDP port: {}", *e))?;

    set_ipv4_src_addr(ctx, me.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to update the source IP address: {}", *e))?;
    set_ipv4_dst_addr(ctx, client.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to update the destination IP address: {}", *e))?;

    store(ctx, ETH_SRC_OFF, &me.mac, 0)
        .inspect_err(|e| error!(ctx, "Failed to update the source MAC address: {}", *e))?;
    store(ctx, ETH_DST_OFF, &client.mac, 0)
        .inspect_err(|e| error!(ctx, "Failed to update the destination MAC address: {}", *e))?;

    let ret = unsafe { bpf_redirect(client.ifindex, 0) } as i32;
    match ret {
        TC_ACT_REDIRECT => {
            info!(ctx, "Sent R-ACK to client ({})", client.ipv4);
            Ok(ret)
        }
        _ => {
            error!(ctx, "bpf_redirect failed");
            Err(ret.into())
        }
    }
}

/// Returns true if the current status is not `want`.
#[inline]
fn is_not_status(want: u8) -> BpfResult<bool> {
    let status = unsafe { STATUS.get(&0) }.map_or(0, |v| *v);
    Ok(status != want)
}

/// Increment the acknowledgment count, returning the new value.
#[inline]
fn incr_acks(ctx: &TcContext) -> BpfResult<u64> {
    let new = unsafe { ACK_COUNT.get(&0) }.unwrap_or(&0).wrapping_add(1);
    ACK_COUNT.insert(&0, &new, 0).map_err(|_| {
        error!(ctx, "Failed to increment ack count");
        TC_ACT_SHOT
    })?;
    Ok(new)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
