#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{AbdActorInfo, AbdMsgType, ArchivedAbdMsg, ClientInfo, ABD_UDP_PORT};
use abd_ebpf::helpers::{
    common::{parse_abd_packet, AbdPacket},
    offsets::{ETH_DST_OFF, ETH_SRC_OFF, UDP_CSUM_OFF},
    tc::{set_ipv4_dst_addr, set_ipv4_src_addr, set_udp_dst_port, set_udp_src_port, store},
};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_STOLEN},
    helpers::r#gen::bpf_redirect,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info, warn};
use rkyv::munge::munge;

/// maximum number of replicas
const MAX_SERVERS: u32 = 16;

/// set from user-space loader
#[no_mangle]
static NUM_SERVERS: u32 = 0;

/// read-only array describing replicas
#[map]
static SERVER_INFO: Array<AbdActorInfo> = Array::with_max_entries(MAX_SERVERS, 0);

/// writer data
#[map]
static WRITER_INFO: Array<AbdActorInfo> = Array::with_max_entries(1, 0);

/// client data
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
static ACK_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

// TODO: investigate using proper errors rather than logging in-place and returning unit errors

#[classifier]
pub fn abd_writer(ctx: TcContext) -> i32 {
    match try_abd_writer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_abd_writer(ctx: TcContext) -> Result<i32, ()> {
    let pkt = match parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    match pkt.msg.type_.try_into()? {
        AbdMsgType::Write => handle_write(&ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(&ctx, pkt),
        _ => {
            warn!(
                &ctx,
                "Received unexpected message type: {} from sender {}, dropping...",
                pkt.msg.type_,
                pkt.msg.sender
            );
            Ok(TC_ACT_SHOT)
        }
    }
}

/// Handle a write request
/// Pre: magic number is correct, type is WRITE
fn handle_write(ctx: &TcContext, pkt: AbdPacket<'_>) -> Result<i32, ()> {
    munge!(let ArchivedAbdMsg { mut sender, mut tag, value, mut counter, .. } = pkt.msg);

    info!(
        ctx,
        "Received WRITE request from client (value={})",
        value.to_native()
    );

    let zero = 0u32;

    // busy?
    let busy = unsafe { WRITING_FLAG.get(&zero) }.map_or(0, |v| *v);
    if busy != 0 {
        warn!(ctx, "Writer busy – drop WRITE");
        return Ok(TC_ACT_SHOT);
    }

    // mark busy
    WRITING_FLAG.insert(&zero, &1u8, 0).map_err(|_| {
        error!(ctx, "Failed to set busy flag");
    })?;

    // bump tag & counter
    let new_tag = unsafe { TAG.get(&zero) }.unwrap_or(&0).wrapping_add(1);
    let new_wc = unsafe { WRITE_COUNTER.get(&zero) }
        .unwrap_or(&0)
        .wrapping_add(1);
    TAG.insert(&zero, &new_tag, 0).ok();
    WRITE_COUNTER.insert(&zero, &new_wc, 0).ok();

    // reset ACK count
    ACK_COUNT.insert(&zero, &zero, 0).map_err(|_| {
        error!(ctx, "Failed to reset ACK count");
    })?;

    // record client info
    let client = ClientInfo {
        ipv4: Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
        ifindex: (unsafe { *ctx.skb.skb }).ingress_ifindex,
        port: u16::from_be(pkt.udph.source),
        mac: pkt.eth.src_addr,
    };
    CLIENT_INFO.insert(&zero, &client, 0).ok();

    // modify ABD msg in-place
    *sender = 0;
    *tag = new_tag.into();
    *counter = new_wc.into();

    broadcast_to_servers(ctx).inspect_err(|_| {
        error!(ctx, "Failed to broadcast WRITE request");
    })?;
    Ok(TC_ACT_STOLEN)
}

/// Handle a write acknowledgment
/// Pre: magic number is correct, type is WRITE_ACK
fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket<'_>) -> Result<i32, ()> {
    info!(
        ctx,
        "Received W-ACK from server {} (tag={}, value={}, counter={})",
        pkt.msg.sender,
        pkt.msg.tag.to_native(),
        pkt.msg.value.to_native(),
        pkt.msg.counter.to_native()
    );

    let zero = 0u32;

    // if there's no write in progress, ignore the ACK
    let busy = unsafe { WRITING_FLAG.get(&zero) }.map_or(0, |v| *v);
    if busy == 0 {
        info!(
            ctx,
            "No write in progress – drop W-ACK from server {}", pkt.msg.sender
        );
        return Ok(TC_ACT_SHOT);
    }

    // check if the ACK is for the current write
    let current_wc = unsafe { WRITE_COUNTER.get(&zero) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != *current_wc {
        warn!(
            ctx,
            "W-ACK counter mismatch (expected {}, got {})",
            *current_wc,
            pkt.msg.counter.to_native()
        );
        return Ok(TC_ACT_SHOT);
    }

    // increment ACK counter
    let old_ack_cnt = unsafe { ACK_COUNT.get(&zero) }.unwrap_or(&0);
    let new_ack_cnt = old_ack_cnt.wrapping_add(1);
    ACK_COUNT.insert(&zero, &new_ack_cnt, 0).map_err(|_| {
        error!(ctx, "Failed to increment ACK count");
    })?;

    // check if we have enough ACKs
    let majority = ((unsafe { core::ptr::read_volatile(&NUM_SERVERS) }) >> 1) + 1;
    if new_ack_cnt >= majority {
        WRITING_FLAG.remove(&zero).ok(); // clear busy flag
        info!(ctx, "WRITE committed – {} ACKs", new_ack_cnt);

        // send ACK to the client
        redirect_write_ack_to_client(&ctx, pkt).inspect_err(|_| {
            error!(ctx, "Failed to redirect W-ACK to client");
        })
    } else {
        info!(
            ctx,
            "Got {} W-ACK(s), waiting for majority ({})...", new_ack_cnt, majority
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

    let writer = WRITER_INFO.get(0).ok_or_else(|| {
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
            error!(ctx, "Failed to get server info for server {}", i + 1);
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
            error!(
                ctx,
                "Failed to clone+redirect to server {}, ret={}",
                i + 1,
                ret
            );
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
fn redirect_write_ack_to_client(ctx: &TcContext, pkt: AbdPacket<'_>) -> Result<i32, ()> {
    let zero: u32 = 0u32;
    let client = unsafe { CLIENT_INFO.get(&zero) }.ok_or(())?;

    info!(
        ctx,
        "Sending W-ACK to client {}:{}@if{}", client.ipv4, client.port, client.ifindex
    );

    // clear internal message fields
    munge!(let ArchivedAbdMsg { mut sender, mut tag, mut counter, .. } = pkt.msg);
    *sender = 0;
    *tag = 0.into();
    *counter = 0.into();

    let writer = WRITER_INFO.get(0).ok_or(())?;

    // L2
    store(ctx, ETH_SRC_OFF, &writer.mac, 0).or_else(|_| {
        error!(ctx, "Failed to update the source MAC address");
        Err(())
    })?;
    store(ctx, ETH_DST_OFF, &client.mac, 0).or_else(|_| {
        error!(ctx, "Failed to update the destination MAC address");
        Err(())
    })?;

    // L3
    set_ipv4_src_addr(ctx, writer.ipv4).map_err(|_| {
        error!(ctx, "Failed to update the source IP address");
    })?;
    set_ipv4_dst_addr(ctx, client.ipv4).map_err(|_| {
        error!(ctx, "Failed to update the destination IP address");
    })?;

    // L4
    set_udp_src_port(ctx, ABD_UDP_PORT).map_err(|_| {
        error!(ctx, "Failed to update the source UDP port");
    })?;
    set_udp_dst_port(ctx, client.port).map_err(|_| {
        error!(ctx, "Failed to update the destination UDP port");
    })?;

    // TODO: remove once the server correctly sets the checksum
    store(ctx, UDP_CSUM_OFF, &0u16, 0).or_else(|_| {
        error!(ctx, "Failed to update the UDP checksum");
        Err(())
    })?;

    debug!(
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
