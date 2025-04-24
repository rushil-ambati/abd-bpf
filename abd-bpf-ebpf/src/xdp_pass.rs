#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn xdp_pass(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_pass(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_pass(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler] //
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
