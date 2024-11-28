#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static COUNTERS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn ebpf_actors(ctx: XdpContext) -> u32 {
    match try_ebpf_actors(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_ebpf_actors(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let udphdr: *const UdpHdr = match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let dest_port = u16::from_be(unsafe { (*udphdr).dest });
    if dest_port != 1337 {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
    let payload_len = ctx.data_end() - ctx.data() - payload_offset;

    let inc = b"INC";

    if payload_len < inc.len() + 1 {
        return Ok(xdp_action::XDP_PASS);
    }

    for i in 0..inc.len() {
        let byte: *const u8 = ptr_at(&ctx, payload_offset + i)?;
        if unsafe { *byte } != inc[i] {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let counter = unsafe {COUNTERS.get(&source_addr).unwrap_or(&0) };
    let new_counter = *counter + 1;
    let _ = COUNTERS.insert(&source_addr, &new_counter, 0);

    info!(
        &ctx,
        "Received INC from IP: {:i}, count: {}", source_addr, new_counter
    );

    Ok(xdp_action::XDP_DROP)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
