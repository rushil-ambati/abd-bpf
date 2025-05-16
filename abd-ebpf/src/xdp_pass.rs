#![no_std]
#![no_main]

use abd_ebpf::helpers::common::ptr_at;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::eth::EthHdr;

#[xdp]
pub fn xdp_pass(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_pass(ctx: XdpContext) -> Result<u32, ()> {
    // Ethernet → must be IPv4
    let eth: *const EthHdr = ptr_at(&ctx, 0)?;
    let src_mac = (*eth).src_addr;
    let dst_mac = (*eth).dst_addr;

    info!(&ctx, "Received packet, src_mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}, dst_mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
    );
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
