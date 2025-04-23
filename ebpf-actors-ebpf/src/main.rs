#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use ebpf_actors_common::{AbdMsgType, ArchivedAbdMsg, ABD_MAGIC, ABD_UDP_PORT};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rkyv::{access_unchecked_mut, munge::munge, seal::Seal};

#[no_mangle]
static SERVER_ID: u8 = 0;

#[map]
static TAG: Array<u32> = Array::<u32>::with_max_entries(1, 0);

#[map]
static VALUE: Array<u32> = Array::<u32>::with_max_entries(1, 0);

#[map]
static COUNTERS: HashMap<u8, u32> = HashMap::<u8, u32>::with_max_entries(256, 0);

#[xdp]
pub fn ebpf_actors(ctx: XdpContext) -> u32 {
    match try_ebpf_actors(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn swap_src_dst_mac(eth: &mut EthHdr) {
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&eth.src_addr);
    eth.src_addr.copy_from_slice(&eth.dst_addr);
    eth.dst_addr.copy_from_slice(&tmp);
}

#[inline(always)]
fn swap_src_dst_ipv4(iph: &mut Ipv4Hdr) {
    let tmp = iph.src_addr;
    iph.src_addr = iph.dst_addr;
    iph.dst_addr = tmp;
}

#[inline(always)]
fn swap_src_dst_udp(udph: &mut UdpHdr) {
    let tmp = udph.source;
    udph.source = udph.dest;
    udph.dest = tmp;
}

#[inline(always)]
fn handle_read(ctx: &XdpContext, abd_msg: Seal<ArchivedAbdMsg>) -> Result<(), ()> {
    munge!(let ArchivedAbdMsg { magic, mut sender, mut type_, mut tag, mut value, counter } = abd_msg);

    if *magic != ABD_MAGIC {
        return Err(());
    }

    info!(ctx, "Received READ from sender: {}", *sender);

    let counter = (*counter).to_native();
    let counter_for_sender = unsafe { COUNTERS.get(&(*sender)) }.unwrap_or(&0);
    if counter <= *counter_for_sender {
        info!(
            ctx,
            "Dropping ABD message of type Read from sender: {} due to counter (must be > {})",
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

#[inline(always)]
fn handle_write(ctx: &XdpContext, abd_msg: Seal<ArchivedAbdMsg>) -> Result<(), ()> {
    munge!(let ArchivedAbdMsg { magic, mut sender, mut type_, tag, value, counter } = abd_msg);

    if *magic != ABD_MAGIC {
        return Err(());
    }

    info!(ctx, "Received WRITE from sender: {}", *sender);

    let counter = (*counter).to_native();
    let counter_for_sender = unsafe { COUNTERS.get(&sender) }.unwrap_or(&0);
    if counter <= *counter_for_sender {
        info!(
            ctx,
            "Dropping ABD message of type Write from sender: {} due to counter (must be > {})",
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
            "Dropping ABD message of type Write from sender: {} due to tag (must be > {})",
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

fn try_ebpf_actors(ctx: XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_at_mut(&ctx, 0)?;
    match unsafe { (*eth).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let iph: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    let udph: *mut UdpHdr = match unsafe { (*iph).proto } {
        IpProto::Udp => ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let dest_port = u16::from_be(unsafe { (*udph).dest });
    if dest_port != ABD_UDP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
    let payload_len = ctx.data_end() - ctx.data() - payload_offset;

    let msg_start: *mut u8 = ptr_at_mut(&ctx, payload_offset)?;
    let expected_len = mem::size_of::<ArchivedAbdMsg>();
    if payload_len < expected_len {
        return Ok(xdp_action::XDP_PASS);
    }

    let msg_contents = unsafe { core::slice::from_raw_parts_mut(msg_start, expected_len) };

    if ctx.data() + payload_offset + expected_len > ctx.data_end() {
        return Ok(xdp_action::XDP_PASS);
    }
    let abd_msg = unsafe { access_unchecked_mut::<ArchivedAbdMsg>(msg_contents) };

    match abd_msg.type_.try_into() {
        Ok(AbdMsgType::Read) => {
            if handle_read(&ctx, abd_msg).is_err() {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        Ok(AbdMsgType::Write) => {
            if handle_write(&ctx, abd_msg).is_err() {
                return Ok(xdp_action::XDP_DROP);
            }
        }
        Ok(AbdMsgType::ReadAck) => return Ok(xdp_action::XDP_DROP),
        Ok(AbdMsgType::WriteAck) => return Ok(xdp_action::XDP_DROP),
        _ => return Ok(xdp_action::XDP_PASS),
    }

    swap_src_dst_mac(unsafe { &mut *eth });
    swap_src_dst_ipv4(unsafe { &mut *iph });
    swap_src_dst_udp(unsafe { &mut *udph });
    unsafe { (*udph).check = 0 };

    Ok(xdp_action::XDP_TX)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
