#![no_std]
#![no_main]

use abd_common::{AbdMsgType, ArchivedAbdMsg, NodeInfo, ABD_NODE_MAX, ABD_SERVER_UDP_PORT};
use abd_ebpf::helpers::common::{calculate_udp_csum_update, parse_abd_packet, AbdPacket};
use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT},
    helpers::gen::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{error, info, warn};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use rkyv::munge::munge;

/// Total number of nodes in the system (set from userspace)
#[no_mangle]
static NUM_NODES: u32 = 0;

/// ID of this node (set from userspace)
#[no_mangle]
static SELF_ID: u32 = 0;

/// Nodes in the system (populated from userspace)
#[map]
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_NODE_MAX, 0);

/// Current tag (timestamp) for the stored value
#[map]
static TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0); // key = 0

/// Current stored value
#[map]
static VALUE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0); // key = 0

/// Per-sender request counter
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
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

fn try_server(ctx: XdpContext) -> Result<u32, ()> {
    let num_nodes = unsafe { core::ptr::read_volatile(&NUM_NODES) };
    if num_nodes == 0 {
        error!(&ctx, "NUM_NODES is not set");
        return Err(());
    }

    let self_id = unsafe { core::ptr::read_volatile(&SELF_ID) };
    if self_id == 0 {
        error!(&ctx, "Node ID is not set");
        return Err(());
    }

    let pkt = match parse_abd_packet(&ctx, ABD_SERVER_UDP_PORT, num_nodes) {
        Ok(p) => p,
        Err(_) => return Ok(XDP_PASS),
    };

    match pkt.msg.type_.to_native().try_into()? {
        AbdMsgType::Read => handle_read(&ctx, pkt, self_id),
        AbdMsgType::Write => handle_write(&ctx, pkt, self_id),
        _ => {
            warn!(
                &ctx,
                "Server {}: Received unexpected message type {} from @{}, dropping...",
                self_id,
                pkt.msg.type_.to_native(),
                pkt.msg.sender.to_native()
            );
            return Ok(XDP_DROP);
        }
    }
}

/// Handle a read request
/// Pre: magic number is correct, type is READ
/// Returns the MAC and ifindex of the response recipient
fn handle_read(ctx: &XdpContext, pkt: AbdPacket, node_id: u32) -> Result<u32, ()> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, counter, .. } = pkt.msg);

    let sender_id = sender.to_native() as u32;
    info!(
        ctx,
        "Server {}: Received READ request from @{}", node_id, sender_id
    );

    // counter freshness check
    let counter = (*counter).to_native();
    let counter_for_sender = *unsafe { COUNTERS.get(&(*sender).into()) }.unwrap_or(&0);
    if counter <= counter_for_sender {
        warn!(
            ctx,
            "Server {}: Drop READ request from @{} due to counter (must be > {})",
            node_id,
            sender_id,
            counter_for_sender
        );
        return Err(());
    }

    // update the counter for the sender
    COUNTERS
        .insert(&sender.to_native(), &counter, 0)
        .map_err(|_| {
            error!(ctx, "Failed to insert counter for @{}", sender_id);
            ()
        })?;

    let dest = lookup_dest(ctx, sender_id)?;

    let mut udp_csum = pkt.udph.check;

    calculate_udp_csum_update(ctx, &sender, node_id.into(), &mut udp_csum)?;
    *sender = node_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::ReadAck.into(), &mut udp_csum)?;
    *type_ = AbdMsgType::ReadAck.into();

    let tag_val = unsafe { TAG.get(&0) }.unwrap_or(&0);
    calculate_udp_csum_update(ctx, &mut tag, tag_val.into(), &mut udp_csum)?;
    *tag = tag_val.into();

    let value_val = unsafe { VALUE.get(&0) }.unwrap_or(&0);
    calculate_udp_csum_update(ctx, &mut value, value_val.into(), &mut udp_csum)?;
    *value = value_val.into();

    pkt.udph.check = udp_csum;

    finish_and_redirect(ctx, node_id, pkt.udph, pkt.iph, pkt.eth, dest)
}

/// Handle a write request
/// Pre: magic number is correct, type is WRITE
/// Returns the MAC and ifindex of the response recipient
fn handle_write(ctx: &XdpContext, pkt: AbdPacket, node_id: u32) -> Result<u32, ()> {
    munge!(let ArchivedAbdMsg { mut sender, mut type_, tag, value, counter, .. } = pkt.msg);

    let sender_id = sender.to_native() as u32;

    info!(
        ctx,
        "Server {}: Received WRITE request from @{}", node_id, sender_id,
    );

    let counter = (*counter).to_native();
    let counter_for_sender = *unsafe { COUNTERS.get(&sender_id) }.unwrap_or(&0);
    if counter <= counter_for_sender {
        warn!(
            ctx,
            "Server {}: Drop WRITE request from @{} due to counter (must be > {})",
            node_id,
            sender_id,
            counter_for_sender
        );
        return Err(());
    }

    // update the counter for the sender
    COUNTERS.insert(&sender_id, &counter, 0).map_err(|_| {
        error!(ctx, "Failed to insert counter for @{}", sender_id);
        ()
    })?;

    let stored_tag = unsafe { TAG.get(&0) }.unwrap_or(&0);

    if *tag > *stored_tag {
        TAG.insert(&0, &tag.to_native(), 0).map_err(|_| {
            error!(ctx, "Failed to insert tag {}", (*tag).to_native());
            ()
        })?;
        VALUE.insert(&0, &value.to_native(), 0).map_err(|_| {
            error!(ctx, "Failed to insert value {}", (*value).to_native());
            ()
        })?;
    } else {
        info!(
            ctx,
            "Server {}: Not updating tag ({} <= {})",
            node_id,
            (*tag).to_native(),
            *stored_tag
        )
    }

    // craft response
    let dest = lookup_dest(ctx, sender_id)?;
    let mut udp_csum = pkt.udph.check;

    calculate_udp_csum_update(ctx, &sender, node_id.into(), &mut udp_csum)?;
    *sender = node_id.into();

    calculate_udp_csum_update(ctx, &type_, AbdMsgType::WriteAck.into(), &mut udp_csum)?;
    *type_ = AbdMsgType::WriteAck.into();

    pkt.udph.check = udp_csum;

    finish_and_redirect(ctx, node_id, pkt.udph, pkt.iph, pkt.eth, dest)
}

/// Swap UDP ports, IPs, and MACs, then redirect to the destination
#[inline(always)]
fn finish_and_redirect(
    ctx: &XdpContext,
    node_id: u32,
    udph: &mut UdpHdr,
    iph: &mut Ipv4Hdr,
    eth: &mut EthHdr,
    dest: Dest,
) -> Result<u32, ()> {
    let _ = udph;
    // swap UDP ports (writer expects reply on ABD_UDP_PORT)
    core::mem::swap(&mut udph.source, &mut udph.dest);

    // swap IPs + MACs so that writer/reader becomes dst
    core::mem::swap(&mut iph.src_addr, &mut iph.dst_addr);
    // swap_eth_addrs(eth);
    core::mem::swap(&mut eth.src_addr, &mut eth.dst_addr);
    eth.dst_addr.copy_from_slice(&dest.mac);

    let act = unsafe { bpf_redirect(dest.ifindex, 0) } as u32;
    if act != XDP_REDIRECT {
        error!(ctx, "bpf_redirect failed: {}", act);
        return Err(());
    }

    info!(
        ctx,
        "Server {}: Responding to {}:{}@if{}",
        node_id,
        iph.dst_addr(),
        u16::from_be(udph.dest),
        dest.ifindex
    );

    Ok(act)
}

/// Get the MAC and ifindex of the response recipient
#[inline(always)]
fn lookup_dest(ctx: &XdpContext, sender_id: u32) -> Result<Dest, ()> {
    let node = NODES.get(sender_id).ok_or_else(|| {
        error!(ctx, "writer map empty");
        ()
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
