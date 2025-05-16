#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{
    AbdActorInfo, AbdMsgType, ArchivedAbdMsg, ClientInfo, ABD_SERVER_UDP_PORT, ABD_UDP_PORT,
    ABD_WRITER_ID,
};
use abd_ebpf::helpers::{
    common::{calculate_udp_csum_update, parse_abd_packet, AbdPacket},
    offsets::{ETH_DST_OFF, ETH_SRC_OFF},
    tc::{set_ipv4_dst_addr, set_ipv4_src_addr, set_udp_dst_port, set_udp_src_port, store},
};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_STOLEN},
    helpers::r#gen::bpf_redirect,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::{error, info, warn};
use rkyv::munge::munge;

// TODO: move this to a common place
const MAX_SERVERS: u32 = 16;

/// set from userspace
#[no_mangle]
static NUM_SERVERS: u32 = 0;

#[map]
static SERVER_INFO: Array<AbdActorInfo> = Array::with_max_entries(MAX_SERVERS, 0);

#[map]
static SELF_INFO: Array<AbdActorInfo> = Array::with_max_entries(1, 0);

#[map]
static CLIENT_INFO: HashMap<u32, ClientInfo> = HashMap::with_max_entries(1, 0);

/// flag: 0 = idle, 1 = write in progress
#[map]
static WRITING_FLAG: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// monotonically-increasing tag
#[map]
static TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// monotonically-increasing write-counter
#[map]
static WRITE_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// ACK counter for current write
#[map]
static ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[classifier]
pub fn writer(ctx: TcContext) -> i32 {
    match try_writer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_writer(ctx: TcContext) -> Result<i32, ()> {
    let pkt = match parse_abd_packet(&ctx, ABD_UDP_PORT) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    match pkt.msg.type_.try_into()? {
        AbdMsgType::Write => handle_write(&ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(&ctx, pkt),
        _ => {
            warn!(
                &ctx,
                "Received unexpected message type: {} from @{}, dropping...",
                pkt.msg.type_.to_native(),
                pkt.msg.sender.to_native()
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle a write request
/// Pre: magic number is correct, type is WRITE
fn handle_write(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    munge!(let ArchivedAbdMsg { mut sender, mut tag, value, mut counter, .. } = pkt.msg);

    info!(
        ctx,
        "Received WRITE request from client (value={})",
        value.to_native()
    );

    // busy?
    let busy = unsafe { WRITING_FLAG.get(&0) }.map_or(0, |v| *v);
    if busy != 0 {
        warn!(ctx, "Writer busy – drop WRITE");
        return Ok(TC_ACT_SHOT);
    }

    // mark busy
    WRITING_FLAG.insert(&0, &1u8, 0).map_err(|_| {
        error!(ctx, "Failed to set busy flag");
    })?;

    // bump tag & counter
    let new_tag = unsafe { TAG.get(&0) }.unwrap_or(&0).wrapping_add(1);
    let new_wc = unsafe { WRITE_COUNTER.get(&0) }
        .unwrap_or(&0)
        .wrapping_add(1);
    TAG.insert(&0, &new_tag, 0).ok();
    WRITE_COUNTER.insert(&0, &new_wc, 0).ok();

    // reset ACK count
    let zero = 0;
    ACK_COUNT.insert(&0, &zero, 0).map_err(|_| {
        error!(ctx, "Failed to reset ACK count");
    })?;

    // record client info
    let client = ClientInfo {
        ipv4: Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
        ifindex: (unsafe { *ctx.skb.skb }).ingress_ifindex,
        port: u16::from_be(pkt.udph.source),
        mac: pkt.eth.src_addr,
    };
    CLIENT_INFO.insert(&0, &client, 0).ok();

    // modify ABD msg in-place
    let mut udp_csum = pkt.udph.check;

    let new_sender = 0;
    calculate_udp_csum_update(ctx, &sender, new_sender.into(), &mut udp_csum)?;
    *sender = new_sender.into();

    calculate_udp_csum_update(ctx, &tag, new_tag.into(), &mut udp_csum)?;
    *tag = new_tag.into();

    calculate_udp_csum_update(ctx, &counter, new_wc.into(), &mut udp_csum)?;
    *counter = new_wc.into();

    pkt.udph.check = udp_csum;

    broadcast_to_servers(ctx).inspect_err(|_| {
        error!(ctx, "Failed to broadcast WRITE request");
    })?;
    Ok(TC_ACT_STOLEN)
}

/// Handle a write acknowledgment
/// Pre: magic number is correct, type is WRITE_ACK
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    info!(
        ctx,
        "Received WriteAck from @{} (tag={}, value={}, counter={})",
        pkt.msg.sender.to_native(),
        pkt.msg.tag.to_native(),
        pkt.msg.value.to_native(),
        pkt.msg.counter.to_native()
    );

    // if there's no write in progress, ignore the ACK
    let busy = unsafe { WRITING_FLAG.get(&0) }.map_or(0, |v| *v);
    if busy == 0 {
        info!(
            ctx,
            "No write in progress – drop WriteAck from @{}",
            pkt.msg.sender.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // check if the ACK is for the current write
    let current_wc = unsafe { WRITE_COUNTER.get(&0) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != *current_wc {
        warn!(
            ctx,
            "WriteAck counter mismatch (expected {}, got {})",
            *current_wc,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // increment ACK counter
    let old_ack_cnt = unsafe { ACK_COUNT.get(&0) }.unwrap_or(&0);
    let new_ack_cnt = old_ack_cnt.wrapping_add(1);
    ACK_COUNT.insert(&0, &new_ack_cnt, 0).map_err(|_| {
        error!(ctx, "Failed to increment ACK count");
    })?;

    // check if we have enough ACKs
    let majority = ((unsafe { core::ptr::read_volatile(&NUM_SERVERS) }) >> 1) + 1;
    if new_ack_cnt >= (majority as u64) {
        WRITING_FLAG.remove(&0).ok(); // clear busy flag
        info!(ctx, "WRITE committed – {} ACKs", new_ack_cnt);

        // send ACK to the client
        redirect_write_ack_to_client(&ctx, pkt).inspect_err(|_| {
            error!(ctx, "Failed to redirect WriteAck to client");
        })
    } else {
        info!(
            ctx,
            "Got {} WriteAck(s), waiting for majority ({})...", new_ack_cnt, majority
        );
        Ok(TC_ACT_SHOT)
    }
}

/// Clone & redirect the packet to each server
fn broadcast_to_servers(ctx: &TcContext) -> Result<(), ()> {
    // servers must reply on our UDP port
    set_udp_src_port(ctx, ABD_UDP_PORT).map_err(|_| {
        error!(ctx, "Failed to update the source UDP port");
    })?;

    // set L4 destination port as server
    set_udp_dst_port(ctx, ABD_SERVER_UDP_PORT).map_err(|_| {
        error!(ctx, "Failed to update the destination UDP port");
    })?;

    let writer = SELF_INFO.get(0).ok_or_else(|| {
        error!(ctx, "Failed to get writer info");
    })?;

    // set L3/L2 source addresses as writer
    set_ipv4_src_addr(ctx, writer.ipv4).map_err(|_| {
        error!(ctx, "Failed to update the source IP address");
    })?;
    store(ctx, ETH_SRC_OFF, &writer.mac, 0).map_err(|_| {
        error!(ctx, "Failed to update the source MAC address");
    })?;

    let num_servers = unsafe { core::ptr::read_volatile(&NUM_SERVERS) };
    for i in 0..num_servers {
        let server = SERVER_INFO.get(i).ok_or_else(|| {
            error!(ctx, "Failed to get info for @{}", i + 1);
        })?;

        // set L3/L2 destination addresses as server
        set_ipv4_dst_addr(ctx, server.ipv4).map_err(|_| {
            error!(ctx, "Failed to update the destination IP address");
        })?;
        store(ctx, ETH_DST_OFF, &server.mac, 0).map_err(|_| {
            error!(ctx, "Failed to update the destination MAC address");
        })?;

        // clone+redirect
        ctx.clone_redirect(server.ifindex, 0).map_err(|ret| {
            error!(ctx, "Failed to clone+redirect to @{}, ret={}", i + 1, ret);
        })?;
        info!(
            ctx,
            "clone_redirect→server{} ({}@if{})",
            i + 1,
            server.ipv4,
            server.ifindex
        );
    }
    Ok(())
}

/// Send a write ACK to the client
fn redirect_write_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    let client = unsafe { CLIENT_INFO.get(&0) }.ok_or(())?;

    info!(
        ctx,
        "Sending WriteAck to client {}:{}@if{}", client.ipv4, client.port, client.ifindex
    );

    // ABD
    munge!(let ArchivedAbdMsg { mut sender, mut tag, mut counter, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;

    // clear internal message fields
    calculate_udp_csum_update(ctx, &sender, 0.into(), &mut udp_csum)?;
    *sender = ABD_WRITER_ID.into();

    calculate_udp_csum_update(ctx, &tag, 0.into(), &mut udp_csum)?;
    *tag = 0.into();

    calculate_udp_csum_update(ctx, &counter, 0.into(), &mut udp_csum)?;
    *counter = 0.into();

    pkt.udph.check = udp_csum;

    let writer = SELF_INFO.get(0).ok_or(())?;

    // L4
    set_udp_dst_port(ctx, ABD_UDP_PORT).map_err(|_| {
        error!(ctx, "Failed to update the source UDP port");
    })?;
    set_udp_dst_port(ctx, client.port).map_err(|_| {
        error!(ctx, "Failed to update the destination UDP port");
    })?;

    // L3
    set_ipv4_src_addr(ctx, writer.ipv4).map_err(|_| {
        error!(ctx, "Failed to update the source IP address");
    })?;
    set_ipv4_dst_addr(ctx, client.ipv4).map_err(|_| {
        error!(ctx, "Failed to update the destination IP address");
    })?;

    // L2
    store(ctx, ETH_SRC_OFF, &writer.mac, 0).map_err(|_| {
        error!(ctx, "Failed to update the source MAC address");
    })?;
    store(ctx, ETH_DST_OFF, &client.mac, 0).map_err(|_| {
        error!(ctx, "Failed to update the destination MAC address");
    })?;

    info!(
        ctx,
        "Client {}:{}@if{}, mac={:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        client.ipv4,
        client.port,
        client.ifindex,
        client.mac[0],
        client.mac[1],
        client.mac[2],
        client.mac[3],
        client.mac[4],
        client.mac[5]
    );

    // 5) redirect back to original ingress ifindex
    let ret = unsafe { bpf_redirect(client.ifindex, 0) } as i32;
    (ret == TC_ACT_REDIRECT).then_some(ret).ok_or(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
