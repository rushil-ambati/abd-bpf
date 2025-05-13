#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{AbdActorInfo, AbdMsgType, ArchivedAbdMsg, ClientInfo};
use abd_ebpf::helpers::{
    disable_udp_csum, parse_abd_packet, set_dst_udp_port, set_eth_dst_mac, set_eth_src_mac,
    set_ipv4_ip_dst, set_ipv4_ip_src, set_src_udp_port, AbdPacket,
};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_STOLEN},
    helpers::r#gen::{bpf_clone_redirect, bpf_redirect},
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

// ---------------------------------------------------------
//  Entry-point
// ---------------------------------------------------------

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
        AbdMsgType::Write => {
            info!(
                &ctx,
                "Received WRITE request from client (value={})",
                pkt.msg.value.to_native()
            );

            let zero = 0u32;

            // busy?
            let busy = unsafe { WRITING_FLAG.get(&zero) }.map_or(0, |v| *v);
            if busy != 0 {
                warn!(&ctx, "Writer busy – drop WRITE");
                return Ok(TC_ACT_SHOT);
            }

            // mark busy
            WRITING_FLAG.insert(&zero, &1u8, 0).map_err(|_| ())?;

            // bump tag & counter
            let tag = unsafe { TAG.get(&zero) }.unwrap_or(&0).wrapping_add(1);
            let wc = unsafe { WRITE_COUNTER.get(&zero) }
                .unwrap_or(&0)
                .wrapping_add(1);
            TAG.insert(&zero, &tag, 0).ok();
            WRITE_COUNTER.insert(&zero, &wc, 0).ok();

            // reset ACK count
            ACK_COUNT.insert(&zero, &zero, 0).map_err(|_| ())?;

            // record client info
            let client = ClientInfo {
                ipv4: Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
                ifindex: (unsafe { *ctx.skb.skb }).ingress_ifindex,
                port: u16::from_be(pkt.udph.source),
                mac: pkt.eth.src_addr,
            };
            CLIENT_INFO.insert(&zero, &client, 0).ok();

            broadcast(&ctx, pkt, tag, wc)?;
            Ok(TC_ACT_STOLEN)
        }
        AbdMsgType::WriteAck => {
            info!(
                &ctx,
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
                    &ctx,
                    "No write in progress – drop W-ACK from server {}", pkt.msg.sender
                );
                return Ok(TC_ACT_SHOT);
            }

            // check if the ACK is for the current write
            let current_wc = unsafe { WRITE_COUNTER.get(&zero) }.unwrap_or(&0);
            if pkt.msg.counter.to_native() != *current_wc {
                warn!(
                    &ctx,
                    "W-ACK counter mismatch (expected {}, got {})",
                    *current_wc,
                    pkt.msg.counter.to_native()
                );
                return Ok(TC_ACT_SHOT);
            }

            // increment ACK counter
            let old_ack_cnt = unsafe { ACK_COUNT.get(&zero) }.unwrap_or(&0);
            let new_ack_cnt = old_ack_cnt.wrapping_add(1);
            ACK_COUNT.insert(&zero, &new_ack_cnt, 0).map_err(|_| ())?;

            // check if we have enough ACKs
            let majority = ((unsafe { core::ptr::read_volatile(&NUM_SERVERS) }) >> 1) + 1;
            if new_ack_cnt >= majority {
                WRITING_FLAG.remove(&zero).ok(); // clear busy flag
                info!(&ctx, "WRITE committed – {} ACKs", new_ack_cnt);

                // send ACK to the client
                Ok(send_write_ack(&ctx, pkt)?)
            } else {
                info!(
                    &ctx,
                    "Got {} W-ACK(s), waiting for majority ({})...", new_ack_cnt, majority
                );
                Ok(TC_ACT_SHOT)
            }
        }
        _ => {
            warn!(
                &ctx,
                "Received unexpected message type: {} from sender {}, dropping...",
                pkt.msg.type_,
                pkt.msg.sender
            );
            return Ok(TC_ACT_SHOT);
        }
    }
}

/// Clone & redirect the packet to each server interface
#[inline(always)]
fn broadcast(ctx: &TcContext, pkt: AbdPacket<'_>, new_tag: u64, new_wc: u64) -> Result<(), ()> {
    // modify ABD msg in-place
    munge!(let ArchivedAbdMsg { mut tag, mut counter, .. } = pkt.msg);
    *tag = new_tag.into();
    *counter = new_wc.into();

    // L4 tweaks
    set_src_udp_port(ctx, abd_common::ABD_UDP_PORT);
    disable_udp_csum(ctx);

    // writer IP/MAC->src
    let writer = WRITER_INFO.get(0).ok_or(())?;
    set_ipv4_ip_src(ctx, writer.ipv4);
    set_eth_src_mac(ctx, &writer.mac); // TODO: is this needed?

    let num_servers = unsafe { core::ptr::read_volatile(&NUM_SERVERS) };
    for i in 0..MAX_SERVERS {
        // TODO: will the verifier be OK with 1..num_servers?
        if i >= num_servers {
            break;
        }

        let server = SERVER_INFO.get(i).ok_or(())?;

        // IP dst
        let ret = set_ipv4_ip_dst(&ctx, server.ipv4);
        (ret == 0).then_some(()).ok_or(())?;
        if ret != 0 {
            error!(ctx, "Failed to update the destination IP address");
            return Err(());
        }

        // MAC dst
        set_eth_dst_mac(ctx, &server.mac);

        // clone+redirect
        let ret = unsafe { bpf_clone_redirect(ctx.skb.skb, server.ifindex, 0) } as i32;
        if ret != 0 {
            error!(ctx, "clone_redirect→srv{} failed, ret={}", i + 1, ret);
            return Err(());
        }
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
fn send_write_ack(ctx: &TcContext, pkt: AbdPacket<'_>) -> Result<i32, ()> {
    let zero: u32 = 0u32;
    let client = unsafe { CLIENT_INFO.get(&zero) }.ok_or(())?;

    info!(
        ctx,
        "Sending W-ACK to client {}:{}@if{}", client.ipv4, client.port, client.ifindex
    );

    // 1) modify ABD msg: sender=0, tag=0, counter=0
    munge!(let ArchivedAbdMsg { mut sender, mut tag, mut counter, .. } = pkt.msg);
    *sender = 0;
    *tag = 0.into();
    *counter = 0.into();

    let writer = WRITER_INFO.get(0).ok_or(())?;

    // 2) src=writer IP, dst=client IP
    set_ipv4_ip_src(ctx, writer.ipv4);
    set_ipv4_ip_dst(ctx, client.ipv4);

    // 3) update UDP ports
    set_src_udp_port(ctx, abd_common::ABD_UDP_PORT);
    set_dst_udp_port(ctx, client.port);
    disable_udp_csum(ctx); // TODO: recompute checksum

    // 4) L2 MACs: dst=client MAC, src=writer MAC
    set_eth_src_mac(ctx, &writer.mac);
    set_eth_dst_mac(ctx, &client.mac);

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
