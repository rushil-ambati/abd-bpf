#![no_std]
#![no_main]

use abd_common::{AbdMsgType, ArchivedAbdMsg, NodeInfo, ABD_NODE_MAX, ABD_SERVER_UDP_PORT};
use abd_ebpf::helpers::utils::{calculate_udp_csum_update, parse_abd_packet, AbdPacket, BpfResult};
use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_REDIRECT},
    helpers::gen::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, info, warn};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use rkyv::munge::munge;

/// Set from userspace
#[no_mangle]
static NUM_NODES: u32 = 0;

/// Set from userspace
#[no_mangle]
static NODE_ID: u32 = 0;

/// Node information - populated from userspace
#[map]
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_NODE_MAX, 0);

/// Current tag (timestamp) for the stored value
#[map]
static TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0); // key = 0

/// Current stored value
#[map]
static VALUE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0); // key = 0

/// Per-node request counter
#[map]
static COUNTERS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(ABD_NODE_MAX, 0);

/// Small struct for “where to send the reply”
struct Dest {
    mac: [u8; 6],
    ifindex: u32,
}

#[xdp]
pub fn server(ctx: XdpContext) -> u32 {
    match try_server(ctx) {
        Ok(act) => act,
        Err(act) => act as u32,
    }
}

fn try_server(ctx: XdpContext) -> BpfResult<u32> {
    let num_nodes = unsafe { core::ptr::read_volatile(&NUM_NODES) };
    if num_nodes == 0 {
        error!(&ctx, "Number of nodes is not set");
        return Err(XDP_ABORTED.into());
    }
    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    if my_id == 0 {
        error!(&ctx, "Node ID is not set");
        return Err(XDP_ABORTED.into());
    }

    let pkt = parse_abd_packet(&ctx, ABD_SERVER_UDP_PORT, num_nodes)?;

    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMsgType::try_from(msg_type).map_err(|_| {
        error!(
            &ctx,
            "Invalid message type {} from @{}",
            msg_type,
            pkt.msg.sender.to_native()
        );
        XDP_ABORTED
    })?;
    match parsed_msg_type {
        AbdMsgType::Read => handle_read(&ctx, pkt),
        AbdMsgType::Write => handle_write(&ctx, pkt),
        _ => {
            warn!(
                &ctx,
                "Received unexpected message type {} from @{}, dropping...",
                pkt.msg.type_.to_native(),
                pkt.msg.sender.to_native()
            );
            return Ok(XDP_DROP);
        }
    }
}

fn handle_read(ctx: &XdpContext, pkt: AbdPacket) -> BpfResult<u32> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, counter, .. } = pkt.msg);

    let sender_id = sender.to_native() as u32;
    info!(ctx, "READ from @{}", sender_id);

    // counter freshness check
    let counter = counter.to_native();
    let sender_counter = *unsafe { COUNTERS.get(&sender.to_native()) }.unwrap_or(&0);
    if counter <= sender_counter {
        warn!(
            ctx,
            "Drop READ from @{} - counter ({}) must be > {}", sender_id, counter, sender_counter
        );
        return Ok(XDP_DROP.into());
    }

    // update the counter for the sender
    COUNTERS
        .insert(&sender.to_native(), &counter, 0)
        .map_err(|_| {
            error!(ctx, "Failed to insert counter for @{}", sender_id);
            XDP_ABORTED
        })?;

    let dest = lookup_dest(ctx, sender_id)?;

    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMsgType::ReadAck.into();

    let stored_tag = unsafe { TAG.get(&0) }.unwrap_or(&0);
    calculate_udp_csum_update(ctx, &mut tag, stored_tag.into(), &mut udp_csum)?;
    *tag = stored_tag.into();

    let stored_value = unsafe { VALUE.get(&0) }.unwrap_or(&0);
    calculate_udp_csum_update(ctx, &mut value, stored_value.into(), &mut udp_csum)?;
    *value = stored_value.into();

    pkt.udph.check = udp_csum;

    finish_and_redirect(ctx, pkt.udph, pkt.iph, pkt.eth, dest)
}

fn handle_write(ctx: &XdpContext, pkt: AbdPacket) -> BpfResult<u32> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, tag, value, counter, .. } = pkt.msg);

    let sender_id = sender.to_native() as u32;

    info!(ctx, "Received WRITE request from @{}", sender_id,);

    let counter = (*counter).to_native();
    let counter_for_sender = *unsafe { COUNTERS.get(&sender_id) }.unwrap_or(&0);
    if counter <= counter_for_sender {
        warn!(
            ctx,
            "Drop WRITE request from @{}: {} (counter) <= {} (sender counter)",
            sender_id,
            counter,
            counter_for_sender
        );
        return Ok(XDP_DROP.into());
    }

    // update the counter for the sender
    COUNTERS.insert(&sender_id, &counter, 0).map_err(|_| {
        error!(ctx, "Failed to insert counter for @{}", sender_id);
        XDP_ABORTED
    })?;

    let stored_tag = unsafe { TAG.get(&0) }.unwrap_or(&0);

    if *tag > *stored_tag {
        TAG.insert(&0, &tag.to_native(), 0).map_err(|_| {
            error!(ctx, "Failed to insert tag {}", (*tag).to_native());
            XDP_ABORTED
        })?;
        VALUE.insert(&0, &value.to_native(), 0).map_err(|_| {
            error!(ctx, "Failed to insert value {}", (*value).to_native());
            XDP_ABORTED
        })?;
    } else {
        debug!(
            ctx,
            "Not updating tag: {} (new) <= {} (current)",
            (*tag).to_native(),
            *stored_tag
        )
    }

    // craft response
    let dest = lookup_dest(ctx, sender_id)?;
    let mut udp_csum = pkt.udph.check;

    let my_id = unsafe { core::ptr::read_volatile(&NODE_ID) };
    calculate_udp_csum_update(ctx, &sender, my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::WriteAck.into(), &mut udp_csum)?;
    *type_ = AbdMsgType::WriteAck.into();

    pkt.udph.check = udp_csum;

    finish_and_redirect(ctx, pkt.udph, pkt.iph, pkt.eth, dest)
}

/// Swap UDP ports, IPs, and MACs, then redirect to the destination
#[inline(always)]
fn finish_and_redirect(
    ctx: &XdpContext,
    udph: &mut UdpHdr,
    iph: &mut Ipv4Hdr,
    eth: &mut EthHdr,
    dest: Dest,
) -> BpfResult<u32> {
    // swap UDP ports and IPs
    core::mem::swap(&mut udph.source, &mut udph.dest);
    core::mem::swap(&mut iph.src_addr, &mut iph.dst_addr);

    // swap MACs and set the destination MAC to the destination node
    core::mem::swap(&mut eth.src_addr, &mut eth.dst_addr);
    eth.dst_addr.copy_from_slice(&dest.mac);

    info!(
        ctx,
        "Responding to {}:{}@if{}",
        iph.dst_addr(),
        u16::from_be(udph.dest),
        dest.ifindex
    );

    let ret = unsafe { bpf_redirect(dest.ifindex, 0) } as u32;
    match ret {
        XDP_REDIRECT => Ok(ret),
        _ => {
            error!(ctx, "bpf_redirect failed");
            Err(ret.into())
        }
    }
}

/// Get the MAC and ifindex of the response recipient
#[inline(always)]
fn lookup_dest(ctx: &XdpContext, sender_id: u32) -> BpfResult<Dest> {
    let node = NODES.get(sender_id).ok_or_else(|| {
        error!(ctx, "Failed to get node info for @{}", sender_id);
        XDP_ABORTED
    })?;
    Ok(Dest {
        mac: node.mac,
        ifindex: node.ifindex,
    })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
