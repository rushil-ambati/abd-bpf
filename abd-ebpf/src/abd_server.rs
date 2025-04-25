#![no_std]
#![no_main]

mod helpers;
use abd_common::{AbdMsgType, ArchivedAbdMsg};
use aya_ebpf::{
    bindings, macros::{map, xdp}, maps::{Array, HashMap}, programs::XdpContext
};
use aya_log_ebpf::{info, warn};
use rkyv::{munge::munge, seal::Seal};

// const AF_INET: u8 = 2;

#[no_mangle]
static SERVER_ID: u8 = 0;

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
        Err(_) => bindings::xdp_action::XDP_ABORTED,
    }
}

fn try_abd_server(ctx: XdpContext) -> Result<u32, ()> {
    let server_id = unsafe { core::ptr::read_volatile(&SERVER_ID) };
    if server_id == 0 {
        info!(&ctx, "Server ID is not set");
        return Err(());
    }

    let pkt = match helpers::parse_abd_packet(&ctx) {
        Ok(p) => p,
        Err(_) => return Ok(bindings::xdp_action::XDP_PASS),
    };

    match pkt.msg.type_.try_into() {
        Ok(AbdMsgType::Read) => {
            if handle_read(&ctx, pkt.msg, server_id).is_err() {
                return Ok(bindings::xdp_action::XDP_DROP);
            }
        }
        Ok(AbdMsgType::Write) => {
            if handle_write(&ctx, pkt.msg, server_id).is_err() {
                return Ok(bindings::xdp_action::XDP_DROP);
            }
        }
        Ok(AbdMsgType::ReadAck) => {
            warn!(
                &ctx,
                "Server {}: Unexpected R-ACK from sender {}, dropping...",
                server_id,
                pkt.msg.sender
            );
            return Ok(bindings::xdp_action::XDP_DROP);
        }
        Ok(AbdMsgType::WriteAck) => {
            warn!(
                &ctx,
                "Server {}: Unexpected W-ACK from sender {}, dropping...",
                server_id,
                pkt.msg.sender
            );
            return Ok(bindings::xdp_action::XDP_DROP);
        }
        _ => return Ok(bindings::xdp_action::XDP_PASS),
    }

    (*pkt.udph).check = 0;
    helpers::swap_src_dst_udp(pkt.udph);
    helpers::swap_src_dst_ipv4(pkt.iph);
    // helpers::swap_src_dst_mac(pkt.eth);

    // TODO: Use bpf_fib_lookup to set appropriate MACs & redirect the response to the correct interface
    // Params: https://github.com/torvalds/linux/blob/7deea5634a67700d04c2a0e6d2ffa0e2956fe8ad/include/uapi/linux/bpf.h#L7207
    // let mut fib_params = bindings::bpf_fib_lookup {
    //     family: AF_INET,
    //     l4_protocol: (*pkt.iph).proto as u8,
    //     sport: (*pkt.udph).source,
    //     dport: (*pkt.udph).dest,
    //     __bindgen_anon_1: bindings::bpf_fib_lookup__bindgen_ty_1 {
    //         tot_len: (*pkt.iph).tot_len,
    //     },
    //     __bindgen_anon_2: bindings::bpf_fib_lookup__bindgen_ty_2 {
    //         tos: (*pkt.iph).tos,
    //     },
    //     __bindgen_anon_3: bindings::bpf_fib_lookup__bindgen_ty_3 {
    //         ipv4_src: (*pkt.iph).src_addr,
    //     },
    //     __bindgen_anon_4: bindings::bpf_fib_lookup__bindgen_ty_4 {
    //         ipv4_dst: (*pkt.iph).dst_addr,
    //     },

    //     // unused
    //     __bindgen_anon_5: bindings::bpf_fib_lookup__bindgen_ty_5 {
    //         tbid: 0,
    //     },

    //     // outputs
    //     ifindex: 0,
    //     smac: [0; 6],
    //     dmac: [0; 6],
    // };
    // bpf_fib_lookup(&ctx, fib_params, size_of::<bindings::bpf_fib_lookup>() as u32, 0);

    Ok(bindings::xdp_action::XDP_TX)
}

/// Handle a read request
/// Pre: magic number is correct, type is READ
#[inline(always)]
fn handle_read(ctx: &XdpContext, abd_msg: Seal<ArchivedAbdMsg>, server_id: u8) -> Result<(), ()> {
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
            "Server {}: Dropping READ request from sender: {} due to counter (must be > {})",
            server_id,
            *sender,
            *counter_for_sender
        );
        return Err(());
    }

    let _ = COUNTERS.insert(&sender, &counter, 0);

    unsafe { *sender = core::ptr::read_volatile(&SERVER_ID).into() };
    *type_ = AbdMsgType::ReadAck as u8;
    *tag = (*TAG.get(0).unwrap_or(&0)).into();
    *value = (*VALUE.get(0).unwrap_or(&0)).into();

    Ok(())
}

/// Handle a write request
/// Pre: magic number is correct, type is WRITE
#[inline(always)]
fn handle_write(ctx: &XdpContext, abd_msg: Seal<ArchivedAbdMsg>, server_id: u8) -> Result<(), ()> {
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

    unsafe { *sender = core::ptr::read_volatile(&SERVER_ID).into() };
    *type_ = AbdMsgType::WriteAck as u8;

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
