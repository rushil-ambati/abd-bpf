#![no_std]
#![no_main]

use abd_common::{AbdActorInfo, AbdMsgType, ArchivedAbdMsg};
use abd_ebpf::helpers::{
    parse_abd_packet, set_eth_dst_mac, swap_ipv4_addresses, swap_src_dst_mac, swap_udp_ports,
};
use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT},
    helpers::gen::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, info, warn};
use rkyv::{munge::munge, seal::Seal};

#[no_mangle]
static MAX_SERVERS: u32 = 16;

#[no_mangle]
static NUM_SERVERS: u32 = MAX_SERVERS;

#[no_mangle]
static SERVER_ID: u8 = 0;

#[map]
static WRITER_INFO: Array<AbdActorInfo> = Array::with_max_entries(1, 0);

#[map]
static SERVER_INFO: Array<AbdActorInfo> = Array::with_max_entries(MAX_SERVERS, 0);

#[map]
static TAG: Array<u32> = Array::<u32>::with_max_entries(1, 0);

#[map]
static VALUE: Array<u32> = Array::<u32>::with_max_entries(1, 0);

#[map]
static COUNTERS: HashMap<u8, u32> = HashMap::<u8, u32>::with_max_entries(256, 0);

#[xdp]
pub fn abd_server(ctx: XdpContext) -> u32 {
    match try_abd_server(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

fn try_abd_server(ctx: XdpContext) -> Result<u32, ()> {
    let server_id = unsafe { core::ptr::read_volatile(&SERVER_ID) };
    if server_id == 0 {
        error!(&ctx, "Server ID is not set");
        return Err(());
    }

    let pkt = match parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(XDP_PASS),
    };

    let (return_mac, return_ifindex) = match pkt.msg.type_.try_into()? {
        AbdMsgType::Read => handle_read(&ctx, pkt.msg, server_id)?,
        AbdMsgType::Write => handle_write(&ctx, pkt.msg, server_id)?,
        _ => {
            warn!(
                &ctx,
                "Server {}: Received unexpected message type {} from sender {}, dropping...",
                server_id,
                pkt.msg.type_,
                pkt.msg.sender
            );
            return Ok(XDP_DROP);
        }
    };

    debug!(
        &ctx,
        "Server {}: Redirecting to ifindex {}, MAC {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        server_id,
        return_ifindex,
        return_mac[0],
        return_mac[1],
        return_mac[2],
        return_mac[3],
        return_mac[4],
        return_mac[5]
    );

    // Swap UDP Ports and disable checksum
    swap_udp_ports(pkt.udph);
    (*pkt.udph).check = 0; // TODO: Use bpf_l4_csum_replace() instead

    // Flip IPs
    swap_ipv4_addresses(pkt.iph);

    // Swap Ethernet src/dst and set dst→writer
    swap_src_dst_mac(pkt.eth);
    set_eth_dst_mac(pkt.eth, &return_mac);

    // Send response
    let ret = unsafe { bpf_redirect(return_ifindex, 0) } as u32;
    if ret != XDP_REDIRECT {
        error!(&ctx, "Failed to redirect to if{}, ret={}", return_ifindex, ret);
        return Ok(XDP_ABORTED);
    }
    info!(
        &ctx,
        "Responding on if{}", return_ifindex
    );
    return Ok(ret);
}

/// Handle a read request
/// Pre: magic number is correct, type is READ
/// Returns the MAC and ifindex of the response recipient
#[inline(always)]
fn handle_read(
    ctx: &XdpContext,
    abd_msg: Seal<ArchivedAbdMsg>,
    server_id: u8,
) -> Result<([u8; 6], u32), ()> {
    munge!(let ArchivedAbdMsg { _magic, mut sender, mut type_, mut tag, mut value, counter } = abd_msg);

    info!(
        ctx,
        "Server {}: Received READ request from sender {}", server_id, *sender
    );

    let counter = (*counter).to_native();
    let counter_for_sender = unsafe { COUNTERS.get(&(*sender)) }.unwrap_or(&0);
    if counter <= *counter_for_sender {
        info!(
            ctx,
            "Server {}: Dropping READ request from sender {} due to counter (must be > {})",
            server_id,
            *sender,
            *counter_for_sender
        );
        return Err(());
    }

    let _ = COUNTERS.insert(&sender, &counter, 0);

    let (return_mac, return_ifindex) = get_response_info(ctx, *sender)?;

    unsafe { *sender = core::ptr::read_volatile(&SERVER_ID).into() };
    *type_ = AbdMsgType::ReadAck as u8;
    *tag = (*TAG.get(0).unwrap_or(&0)).into();
    *value = (*VALUE.get(0).unwrap_or(&0)).into();

    Ok((return_mac, return_ifindex))
}

/// Handle a write request
/// Pre: magic number is correct, type is WRITE
/// Returns the MAC and ifindex of the response recipient
#[inline(always)]
fn handle_write(
    ctx: &XdpContext,
    abd_msg: Seal<ArchivedAbdMsg>,
    server_id: u8,
) -> Result<([u8; 6], u32), ()> {
    munge!(let ArchivedAbdMsg { _magic, mut sender, mut type_, tag, value, counter } = abd_msg);

    info!(
        ctx,
        "Server {}: Received WRITE request from sender {}", server_id, *sender
    );

    let counter = (*counter).to_native();
    let counter_for_sender = unsafe { COUNTERS.get(&sender) }.unwrap_or(&0);
    if counter <= *counter_for_sender {
        info!(
            ctx,
            "Server {}: Dropping WRITE request from sender {} due to counter (must be > {})",
            server_id,
            *sender,
            *counter_for_sender
        );
        return Err(());
    }

    let _ = COUNTERS.insert(&sender, &counter, 0);

    let tag_ptr = TAG.get_ptr_mut(0).unwrap_or(&mut 0);
    let value_ptr = VALUE.get_ptr_mut(0).unwrap_or(&mut 0);

    if *tag <= unsafe { *tag_ptr } {
        info!(
            ctx,
            "Server {}: Dropping WRITE from sender {} due to tag (must be > {})",
            server_id,
            *sender,
            (*tag).to_native(),
            *tag_ptr
        );
        return Err(());
    }

    unsafe {
        *tag_ptr = (*tag).into();
        *value_ptr = (*value).into();
    }

    let (return_mac, return_ifindex) = get_response_info(ctx, *sender)?;

    unsafe { *sender = core::ptr::read_volatile(&SERVER_ID).into() };
    *type_ = AbdMsgType::WriteAck as u8;

    Ok((return_mac, return_ifindex))
}

#[inline(always)]
fn get_response_info(ctx: &XdpContext, sender_id: u8) -> Result<([u8; 6], u32), ()> {
    // sender id: 0 = writer, >0 = server
    let return_mac: [u8; 6];
    let return_ifindex: u32;
    if sender_id == 0 {
        // Get the writer info from the map
        let writer_info = match WRITER_INFO.get(0) {
            Some(info) => {
                if info.ipv4.is_unspecified() || info.ifindex == 0 || info.mac == [0; 6] {
                    error!(ctx, "Missing writer info");
                    return Err(());
                }
                *info
            }
            None => {
                error!(ctx, "Failed to get writer info");
                return Err(());
            }
        };
        return_mac = writer_info.mac;
        return_ifindex = writer_info.ifindex;
    } else {
        let server_info = match SERVER_INFO.get((sender_id - 1) as u32) {
            Some(info) => {
                if info.ipv4.is_unspecified() || info.ifindex == 0 || info.mac == [0; 6] {
                    error!(ctx, "Missing info for server {}", sender_id);
                    return Err(());
                }
                *info
            }
            None => {
                error!(ctx, "Failed to get info for server {}", sender_id);
                return Err(());
            }
        };
        return_mac = server_info.mac;
        return_ifindex = server_info.ifindex;
    }
    Ok((return_mac, return_ifindex))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
