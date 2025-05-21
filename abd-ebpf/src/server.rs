#![no_std]
#![no_main]

use core::mem::swap;

use abd_common::{
    constants::{ABD_MAX_NODES, ABD_SERVER_UDP_PORT},
    maps::NodeInfo,
    msg::{AbdMessageType, ArchivedAbdMessage},
    value::ArchivedAbdValue,
};
use abd_ebpf::utils::common::{
    map_get_or_default, map_update, overwrite_seal, parse_abd_packet, read_global,
    recompute_udp_csum_for_abd, AbdPacket, BpfResult,
};
use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_ABORTED, XDP_DROP, XDP_REDIRECT},
        BPF_F_RDONLY_PROG,
    },
    helpers::gen::bpf_redirect,
    macros::{map, xdp},
    maps::Array,
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
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_MAX_NODES, BPF_F_RDONLY_PROG);

/// Current tag (timestamp) for the stored value
#[map]
static TAG: Array<u64> = Array::with_max_entries(1, 0); // key = 0

/// Current stored value
#[map]
static VALUE: Array<ArchivedAbdValue> = Array::with_max_entries(1, 0); // key = 0

/// Per-node request counter
#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(ABD_MAX_NODES, 0);

/// Small struct for “where to send the reply”
#[derive(Clone, Copy)]
struct Dest {
    mac: [u8; 6],
    ifindex: u32,
}

#[allow(clippy::needless_pass_by_value)]
#[xdp]
pub fn server(ctx: XdpContext) -> u32 {
    match try_server(&ctx) {
        Ok(act) => act,
        Err(act) => u32::try_from(act).unwrap_or(XDP_ABORTED),
    }
}

fn try_server(ctx: &XdpContext) -> BpfResult<u32> {
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        error!(ctx, "Number of nodes is not set");
        return Err(XDP_ABORTED.into());
    }
    let my_id = read_global(&NODE_ID);
    if my_id == 0 {
        error!(ctx, "Node ID is not set");
        return Err(XDP_ABORTED.into());
    }

    let pkt = parse_abd_packet(ctx, ABD_SERVER_UDP_PORT, num_nodes)?;

    let sender = pkt.msg.sender.to_native();
    let msg_type = pkt.msg.type_.to_native();
    let parsed_msg_type = AbdMessageType::try_from(msg_type).map_err(|()| {
        error!(ctx, "Invalid message type {} from @{}", msg_type, sender);
        XDP_ABORTED
    })?;
    match parsed_msg_type {
        AbdMessageType::Read => handle_read(ctx, pkt),
        AbdMessageType::Write => handle_write(ctx, pkt),
        _ => {
            warn!(
                ctx,
                "Received unexpected message type {} from @{}, dropping...",
                msg_type as u32,
                sender
            );
            Ok(XDP_DROP)
        }
    }
}

fn handle_read(ctx: &XdpContext, pkt: AbdPacket) -> BpfResult<u32> {
    let sender = pkt.msg.sender.to_native();
    let counter = pkt.msg.counter.to_native();

    info!(ctx, "READ from @{}", sender);
    update_sender_counter_if_newer(ctx, sender, counter)?;

    let tag = map_get_or_default(&TAG, 0);
    let value = VALUE.get(0).ok_or_else(|| {
        error!(ctx, "Failed to get value");
        XDP_ABORTED
    })?;

    construct_and_send_ack(
        ctx,
        pkt,
        AbdMessageType::ReadAck,
        Some(tag),
        Some(value),
        lookup_dest(ctx, sender)?,
    )
}

fn handle_write(ctx: &XdpContext, pkt: AbdPacket) -> BpfResult<u32> {
    let sender = pkt.msg.sender.to_native();
    let counter = pkt.msg.counter.to_native();

    info!(ctx, "WRITE from @{}", sender);
    update_sender_counter_if_newer(ctx, sender, counter)?;

    let tag = pkt.msg.tag.to_native();
    store_tag_and_value_if_newer(ctx, tag, &pkt.msg.value)?;

    construct_and_send_ack(
        ctx,
        pkt,
        AbdMessageType::WriteAck,
        None,
        None,
        lookup_dest(ctx, sender)?,
    )
}

/// Updates the sender counter if the incoming counter is newer
#[allow(clippy::inline_always)]
#[inline(always)]
fn update_sender_counter_if_newer(ctx: &XdpContext, sender: u32, counter: u64) -> BpfResult<()> {
    let sender_counter = map_get_or_default(&COUNTERS, sender);
    if counter <= sender_counter {
        warn!(
            ctx,
            "Counter {} not fresher than {} for @{}", counter, sender_counter, sender
        );
        return Err(XDP_DROP.into());
    }
    map_update(ctx, &COUNTERS, sender, &counter)
}

/// Stores new tag and value if tag is newer
#[allow(clippy::inline_always)]
#[inline(always)]
fn store_tag_and_value_if_newer(
    ctx: &XdpContext,
    tag: u64,
    value: &ArchivedAbdValue,
) -> BpfResult<()> {
    let current_tag = map_get_or_default(&TAG, 0);
    if tag > current_tag {
        map_update(ctx, &TAG, 0, &tag)?;
        map_update(ctx, &VALUE, 0, value)?;
    } else {
        debug!(
            ctx,
            "Tag {} not newer than current {}, skipping update", tag, current_tag
        );
    }
    Ok(())
}

/// Builds a response packet by updating fields and checksum
#[allow(clippy::inline_always)]
#[inline(always)]
fn construct_and_send_ack(
    ctx: &XdpContext,
    pkt: AbdPacket,
    new_type: AbdMessageType,
    new_tag: Option<u64>,
    new_value: Option<&ArchivedAbdValue>,
    dest: Dest,
) -> BpfResult<u32> {
    munge!(let ArchivedAbdMessage { mut sender, mut tag, mut type_, value, .. } = pkt.msg);
    let mut udp_csum = pkt.udph.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd(ctx, &sender, &my_id.into(), &mut udp_csum)?;
    *sender = my_id.into();

    recompute_udp_csum_for_abd(ctx, &type_, &new_type.into(), &mut udp_csum)?;
    *type_ = new_type.into();

    if let Some(new_tag) = new_tag {
        recompute_udp_csum_for_abd(ctx, &tag, &new_tag.into(), &mut udp_csum)?;
        *tag = new_tag.into();
    }

    if let Some(new_value) = new_value {
        recompute_udp_csum_for_abd(ctx, &value, new_value, &mut udp_csum)?;
        overwrite_seal(value, new_value);
    }

    pkt.udph.check = udp_csum;
    redirect_to_dest(ctx, pkt.udph, pkt.iph, pkt.eth, dest)
}

/// Get the MAC and ifindex of the response recipient
#[inline]
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

/// Swap UDP ports, IPs, and MACs, then redirect to the destination
#[allow(clippy::inline_always)]
#[inline(always)]
fn redirect_to_dest(
    ctx: &XdpContext,
    udph: &mut UdpHdr,
    iph: &mut Ipv4Hdr,
    eth: &mut EthHdr,
    dest: Dest,
) -> BpfResult<u32> {
    // swap UDP ports and IPs
    swap(&mut udph.source, &mut udph.dest);
    swap(&mut iph.src_addr, &mut iph.dst_addr);

    // swap MACs and set the destination MAC to the destination node
    swap(&mut eth.src_addr, &mut eth.dst_addr);
    eth.dst_addr.copy_from_slice(&dest.mac);

    info!(
        ctx,
        "Responding to {}:{}@if{}",
        iph.dst_addr(),
        u16::from_be(udph.dest),
        dest.ifindex
    );

    let ret = u32::try_from(unsafe { bpf_redirect(dest.ifindex, 0) }).map_err(|_| {
        error!(ctx, "bpf_redirect failed");
        XDP_ABORTED
    })?;
    if ret == XDP_REDIRECT {
        Ok(ret)
    } else {
        error!(ctx, "bpf_redirect failed");
        Err(ret.into())
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
