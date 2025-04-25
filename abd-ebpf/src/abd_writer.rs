#![no_std]
#![no_main]

mod helpers;
use abd_common::ArchivedAbdMsg;
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::gen::bpf_redirect,
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use helpers::parse_abd_packet;
use rkyv::munge::munge;

// TODO: Provide the writer with a map containing IPs of each server and make it bpf_fib_lookup and bpf_clone_redirect.
// TODO: Only broadcast write requests. Ignore read requests.
// TODO: Handle W-ACKs. Ignore R-ACKs.
#[no_mangle]
static DST_MAC: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[no_mangle]
static IFINDEX: u32 = 0;

#[classifier]
pub fn abd_writer(ctx: TcContext) -> i32 {
    match try_abd_writer(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_abd_writer(ctx: TcContext) -> Result<i32, ()> {
    let ifindex = unsafe { core::ptr::read_volatile(&IFINDEX) };
    if ifindex == 0 {
        error!(&ctx, "IFINDEX is not set");
        return Err(());
    }

    let pkt = match parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    munge!(let ArchivedAbdMsg { _magic, sender, type_, tag, value, counter } = pkt.msg);

    info!(
        &ctx,
        "Received ABD request (sender: {}, type: {}, tag: {}, value: {}, counter: {})",
        *sender,
        *type_,
        u32::from(*tag),
        u32::from(*value),
        u32::from(*counter),
    );

    debug!(&ctx, "Redirecting to ifindex: {}", ifindex);

    // Set the destination MAC address
    let redirect_dst_mac = unsafe { core::ptr::read_volatile(&DST_MAC) };
    helpers::overwrite_dst_mac(pkt.eth, &redirect_dst_mac);

    // Disable UDP checksum
    (*pkt.udph).check = 0;

    // Redirect the packet to the specified interface
    let ret = unsafe { bpf_redirect(ifindex, 0) };
    Ok(ret as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
