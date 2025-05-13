#![no_std]
#![no_main]

use abd_common::{AbdActorInfo, AbdMsgType};
use abd_ebpf::helpers::{
    parse_abd_packet, ptr_at, set_eth_src_mac, set_ipv4_ip_dst, set_src_udp_port,
    swap_ipv4_addresses, AbdPacket, ETH_DST_OFF, IP_CSUM_OFF, IP_DST_OFF,
};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_STOLEN},
    cty::c_void,
    helpers::r#gen::{bpf_clone_redirect, bpf_skb_store_bytes},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use aya_log_ebpf::{error, info, warn};

const MAX_SERVERS: u32 = 16;

#[no_mangle]
static NUM_SERVERS: u32 = 0;

#[map]
static SERVER_INFO: Array<AbdActorInfo> = Array::with_max_entries(MAX_SERVERS, 0);

#[map]
static WRITER_INFO: Array<AbdActorInfo> = Array::with_max_entries(1, 0);

#[classifier]
pub fn abd_writer(ctx: TcContext) -> i32 {
    match try_abd_writer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_abd_writer(ctx: TcContext) -> Result<i32, ()> {
    let mut pkt = match parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    match pkt.msg.type_.try_into()? {
        AbdMsgType::Write | AbdMsgType::Read => {
            // Broadcast the packet to all servers
            match broadcast(&ctx, &mut pkt) {
                Ok(_) => {
                    info!(&ctx, "Successfully broadcasted WRITE");
                    return Ok(TC_ACT_STOLEN);
                }
                Err(_) => {
                    error!(&ctx, "Failed to broadcast packet");
                    return Err(());
                }
            }
        }
        AbdMsgType::WriteAck => {
            // TODO: Handle W-ACKs
            info!(
                &ctx,
                "Received W-ACK from server {} (value={})",
                pkt.msg.sender,
                pkt.msg.value.to_native()
            );
            return Ok(TC_ACT_SHOT);
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
fn broadcast(ctx: &TcContext, pkt: &mut AbdPacket<'_>) -> Result<(), ()> {
    info!(
        ctx,
        "Broadcasting WRITE (sender={}, tag={}, value={}, counter={})",
        pkt.msg.sender,
        pkt.msg.tag.to_native(),
        pkt.msg.value.to_native(),
        pkt.msg.counter.to_native()
    );

    // Set source UDP port to the writer's port and disable checksum
    set_src_udp_port(pkt.udph, abd_common::ABD_UDP_PORT);
    (*pkt.udph).check = 0; // TODO: Use bpf_l4_csum_replace() instead

    // Set source IP and MAC addresses to the writer's
    let writer_info = match WRITER_INFO.get(0) {
        Some(info) => {
            if info.ipv4.is_unspecified() || info.ifindex == 0 || info.mac == [0; 6] {
                error!(ctx, "No writer info found");
                return Err(());
            }
            *info
        }
        None => {
            error!(ctx, "Failed to get writer info");
            return Err(());
        }
    };
    // Set the source IP to the writer's IP
    swap_ipv4_addresses(pkt.iph); // pkt.iph.set_src_addr(writer_info.ipv4);
    set_eth_src_mac(pkt.eth, &writer_info.mac); // TODO: is this needed?

    let num_servers = unsafe { core::ptr::read_volatile(&NUM_SERVERS) };

    for i in 0..MAX_SERVERS {
        if i >= num_servers {
            break;
        }

        let info = match SERVER_INFO.get(i) {
            Some(info) => {
                if info.ipv4.is_unspecified() || info.ifindex == 0 || info.mac == [0; 6] {
                    error!(ctx, "Missing info for server {}", i + 1);
                    break;
                }
                *info
            }
            None => {
                error!(ctx, "Failed to get info for server {}", i + 1);
                break;
            }
        };

        // Update destination IP and adjust checksums atomically
        let ip_dst_ptr: *const u32 = match ptr_at::<TcContext, u32>(&ctx, IP_DST_OFF as usize) {
            Ok(p) => p,
            Err(_) => {
                error!(ctx, "packet too short to overwrite dst_addr");
                return Err(());
            }
        };
        let old_ip_dst = unsafe { *ip_dst_ptr };
        let new_ip_dst = u32::from(info.ipv4).to_be();
        let ret = set_ipv4_ip_dst(&ctx, IP_CSUM_OFF, &old_ip_dst, new_ip_dst);
        if ret != 0 {
            error!(ctx, "bpf_l3_csum_replace failed: {}", ret);
            return Err(());
        }

        // Set the destination MAC address to the server's MAC
        let ret = unsafe {
            bpf_skb_store_bytes(
                ctx.skb.skb,
                ETH_DST_OFF,
                &info.mac as *const [u8; 6] as *const c_void,
                core::mem::size_of::<[u8; 6]>() as u32,
                0,
            )
        };
        if ret != 0 {
            error!(ctx, "Failed to update the destination MAC address");
            return Err(());
        }

        // Perform the clone+redirect
        // let ret = unsafe { bpf_redirect(info.ifindex, 0) };
        let ret = unsafe { bpf_clone_redirect(ctx.skb.skb, info.ifindex, 0) } as i32;
        if ret != 0 {
            error!(
                ctx,
                "bpf_clone_redirect failed for server {}: ret={}", i, ret
            );
            return Err(());
        }
        info!(
            ctx,
            "Cloned packet to server {} ({}@if{})",
            i + 1,
            info.ipv4,
            info.ifindex
        );
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
