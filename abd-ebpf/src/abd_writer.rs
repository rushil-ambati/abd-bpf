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
use aya_log_ebpf::info;
use helpers::parse_abd_packet;
use rkyv::munge::munge;

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
        info!(&ctx, "IFINDEX is not set");
        return Err(());
    }

    let pkt = match parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    munge!(let ArchivedAbdMsg { _magic, sender, type_, tag, value, counter } = pkt.msg);

    info!(
        &ctx,
        "Redirecting ABD packet (sender: {}, type: {}, tag: {}, value: {}, counter: {}) to interface {}",
        *sender,
        *type_,
        u32::from(*tag),
        u32::from(*value),
        u32::from(*counter),
        ifindex
    );

    // Set the destination MAC address
    let redirect_dst_mac = unsafe { core::ptr::read_volatile(&DST_MAC) };
    helpers::overwrite_dst_mac(pkt.eth, &redirect_dst_mac);

    // Disable UDP checksum
    (*pkt.udph).check = 0;

    let ret = unsafe { bpf_redirect(ifindex, 0) };
    Ok(ret as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
