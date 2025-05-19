#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{
    AbdMsgType, ArchivedAbdMsg, ClientInfo, NodeInfo, ABD_NODE_MAX, ABD_SERVER_UDP_PORT,
    ABD_UDP_PORT, ABD_WRITER_ID,
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
    let num_nodes = unsafe { core::ptr::read_volatile(&raw const NUM_NODES) };
    if num_nodes == 0 {
        error!(ctx, "NUM_NODES is not set");
        return Err(TC_ACT_SHOT.into());
    }
    let my_id = unsafe { core::ptr::read_volatile(&raw const NODE_ID) };
    if my_id != ABD_WRITER_ID {
        error!(ctx, "NODE_ID is not set");
        return Err(TC_ACT_SHOT.into());
    }

    let pkt = parse_abd_packet(ctx, ABD_UDP_PORT, num_nodes)?;

    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMsgType::try_from(msg_type).map_err(|()| {
        error!(
            ctx,
            "Invalid message type {} from {}",
            msg_type,
            pkt.msg.sender.to_native()
        );
        TC_ACT_SHOT
    })?;
    match parsed_msg_type {
        AbdMsgType::Write => handle_client_write(ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(ctx, pkt),
        _ => {
            warn!(
                ctx,
                "Received unexpected message type: {} from @{}, dropping...",
                msg_type,
                pkt.msg.sender.to_native()
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle WRITE request from a client
fn handle_client_write(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMsg { mut sender, mut tag, value, mut counter, .. } = pkt.msg);

    if active() {
        warn!(ctx, "Busy – drop WRITE");
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "WRITE({}) from client", value.to_native());

    ACTIVE.insert(&0, &true, 0).map_err(|_| {
        error!(ctx, "Failed to set active flag");
        TC_ACT_SHOT
    })?;
    ACK_COUNT.insert(&0, &0, 0).map_err(|_| {
        error!(ctx, "Failed to reset ack count");
        TC_ACT_SHOT
    })?;

    // remember client
    let client = ClientInfo::new(
        (unsafe { *ctx.skb.skb }).ingress_ifindex,
        Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
        pkt.eth.src_addr,
        u16::from_be(pkt.udph.source),
    );
    CLIENT_INFO.insert(&0, &client, 0).map_err(|_| {
        error!(ctx, "Failed to store client info");
        TC_ACT_SHOT
    })?;

    // increment tag & write counter
    let new_tag = unsafe { TAG.get(&0) }.unwrap_or(&0).wrapping_add(1);
    TAG.insert(&0, &new_tag, 0).map_err(|_| {
        error!(ctx, "Failed to increment tag");
        TC_ACT_SHOT
    })?;
    let new_wc = unsafe { WRITE_COUNTER.get(&0) }
        .unwrap_or(&0)
        .wrapping_add(1);
    WRITE_COUNTER.insert(&0, &new_wc, 0).map_err(|_| {
        error!(ctx, "Failed to increment write counter");
        TC_ACT_SHOT
    })?;

    // set ABD message values in-place
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&raw const NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &tag, new_tag.into(), &mut udp_csum)?;
    *tag = new_tag.into();

    calculate_udp_csum_update(ctx, &counter, new_wc.into(), &mut udp_csum)?;
    *counter = new_wc.into();

    pkt.udph.check = udp_csum;

    broadcast_to_nodes(ctx)
        .map(|()| TC_ACT_STOLEN)
        .inspect_err(|_| error!(ctx, "Failed to broadcast WRITE request"))
}

/// Handle W-ACK from replica
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    if !active() {
        debug!(
            ctx,
            "No write in progress – drop W-ACK from @{}",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // ensure the ACK is for the current operation
    let wc = *unsafe { WRITE_COUNTER.get(&0) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != wc {
        warn!(
            ctx,
            "W-ACK counter mismatch (expected {}, got {})",
            wc,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    debug!(ctx, "Received W-ACK from @{}", pkt.msg.sender.to_native());

    // bump ack counter
    let acks = incr_ack(ctx)?;

    // check if we have enough ACKs
    let majority = ((unsafe { core::ptr::read_volatile(&raw const NUM_NODES) }) >> 1) + 1;
    if acks < u64::from(majority) {
        info!(
            ctx,
            "Got {} WRITE-ACK(s), waiting for majority ({})...", acks, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    info!(ctx, "WRITE committed, majority ({}) reached", majority);

    // clean up
    ACTIVE.remove(&0).map_err(|_| {
        error!(ctx, "Failed to clear active flag");
        TC_ACT_SHOT
    })?;
    ACK_COUNT.remove(&0).map_err(|_| {
        error!(ctx, "Failed to clear ack count");
        TC_ACT_SHOT
    })?;

    send_write_ack_to_client(ctx, pkt)
        .inspect_err(|_| error!(ctx, "Failed to redirect W-ACK to client"))
}

/// Broadcast the current packet to every replica
#[inline]
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
    let my_id = unsafe { core::ptr::read_volatile(&raw const NODE_ID) };
    let me = NODES.get(my_id).ok_or_else(|| {
        error!(ctx, "Failed to get info for self (@{})", my_id);
        TC_ACT_SHOT
    })?;
    set_ipv4_src_addr(ctx, me.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to update source IP address: {}", *e))?;
    store(ctx, ETH_SRC_OFF, &me.mac, 0)
        .inspect_err(|e| error!(ctx, "Failed to update source MAC address: {}", *e))?;

    let num_nodes = unsafe { core::ptr::read_volatile(&raw const NUM_NODES) };
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

/// After write commit, send a W-ACK back to original client
fn send_write_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> BpfResult<i32> {
    munge!(let ArchivedAbdMsg { mut sender, mut tag, mut counter, .. } = pkt.msg);

    // set ABD message values in-place (clearing internal fields)
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&raw const NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &tag, 0.into(), &mut udp_csum)?;
    *tag = 0.into();

    calculate_udp_csum_update(ctx, &counter, 0.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udph.check = udp_csum;

    let my_id = unsafe { core::ptr::read_volatile(&raw const NODE_ID) };
    let me = NODES.get(my_id).ok_or_else(|| {
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

    let ret = i32::try_from(unsafe { bpf_redirect(client.ifindex, 0) }).map_err(|_| {
        error!(ctx, "bpf_redirect failed");
        TC_ACT_SHOT
    })?;
    if ret == TC_ACT_REDIRECT {
        info!(ctx, "Sent W-ACK to client ({})", client.ipv4);
        Ok(ret)
    } else {
        error!(ctx, "bpf_redirect failed");
        Err(ret.into())
    }
}

#[inline]
fn active() -> bool {
    unsafe { ACTIVE.get(&0) }.is_some_and(|v| *v)
}

#[inline]
fn incr_ack(ctx: &TcContext) -> BpfResult<u64> {
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
