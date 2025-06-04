#![no_std]
#![no_main]

use core::mem;

use abd_common::{
    constants::ABD_MAX_NODES,
    map_types::{Counter, NodeInfo, TaggedData},
    message::{AbdMessageType, AbdRole, ArchivedAbdMessage, ArchivedAbdMessageData},
    tag,
};
use abd_ebpf::utils::{
    common::{
        map_get_mut, overwrite_seal, read_global, recompute_udp_csum_for_abd_update,
        try_parse_abd_packet, AbdContext,
    },
    error::AbdError,
    spinlock::{spin_lock_release, try_spin_lock_acquire},
};
use aya_ebpf::{
    bindings::{
        xdp_action::{self, XDP_PASS, XDP_REDIRECT},
        BPF_F_RDONLY_PROG,
    },
    helpers::gen::bpf_redirect,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use rkyv::munge::munge;

/// Set from userspace
#[no_mangle]
static NUM_NODES: u32 = 0;

/// Set from userspace
#[no_mangle]
static NODE_ID: u32 = 0;

/// Node information - populated from userspace (read-only)
#[map]
static NODES: Array<NodeInfo> = Array::with_max_entries(ABD_MAX_NODES, BPF_F_RDONLY_PROG);

/// Current stored tag (timestamp) and associated data
#[map]
static TAG_DATA: Array<TaggedData> = Array::with_max_entries(1, 0);

/// Per-reader/writer request counters
#[map]
static COUNTERS: Array<Counter> = Array::with_max_entries(ABD_MAX_NODES * 2, 0);

#[allow(clippy::needless_pass_by_value)]
#[xdp]
pub fn abd_xdp(ctx: XdpContext) -> u32 {
    match try_abd_xdp(&ctx) {
        Ok(ret) => ret,
        Err(err) => {
            error!(&ctx, "{}", err.as_ref());
            xdp_action::XDP_PASS
        }
    }
}

fn try_abd_xdp(ctx: &XdpContext) -> Result<u32, AbdError> {
    let my_id = read_global(&NODE_ID);
    if my_id == 0 {
        return Err(AbdError::GlobalUnset);
    }

    let Some(pkt) = try_parse_abd_packet(ctx)? else {
        return Ok(XDP_PASS);
    };

    let recipient_role = AbdRole::try_from(pkt.msg.recipient_role.to_native())
        .map_err(|()| AbdError::InvalidReceiverRole)?;
    if recipient_role != AbdRole::Server {
        return Ok(XDP_PASS);
    }
    let sender_role = AbdRole::try_from(pkt.msg.sender_role.to_native())
        .map_err(|()| AbdError::InvalidSenderRole)?;
    if sender_role != AbdRole::Reader && sender_role != AbdRole::Writer {
        return Err(AbdError::InvalidSenderRole);
    }
    let num_nodes = read_global(&NUM_NODES);
    if num_nodes == 0 {
        return Err(AbdError::GlobalUnset);
    }
    if pkt.msg.sender_id > num_nodes {
        return Err(AbdError::InvalidSenderID);
    }

    let msg_type = AbdMessageType::try_from(pkt.msg.type_.to_native())
        .map_err(|()| AbdError::InvalidMessageType)?;
    match msg_type {
        AbdMessageType::Read => handle_read(ctx, pkt, sender_role),
        AbdMessageType::Write => handle_write(ctx, pkt, sender_role),
        _ => Err(AbdError::InvalidMessageType),
    }
}

fn handle_read(ctx: &XdpContext, pkt: AbdContext, sender_role: AbdRole) -> Result<u32, AbdError> {
    let sender_id = pkt.msg.sender_id.to_native();
    let counter = pkt.msg.counter.to_native();

    // info!(ctx, "server: READ from @{}", sender_id);

    update_sender_counter_if_newer(sender_role, sender_id, counter)?;

    let entry = TAG_DATA.get(0).ok_or(AbdError::MapLookupError)?;

    construct_and_send_ack(
        pkt,
        AbdMessageType::ReadAck,
        Some(entry.tag.val),
        Some(&entry.data),
        sender_role,
        sender_id,
    )
}

fn handle_write(ctx: &XdpContext, pkt: AbdContext, sender_role: AbdRole) -> Result<u32, AbdError> {
    let sender_id = pkt.msg.sender_id.to_native();
    let counter = pkt.msg.counter.to_native();

    // info!(ctx, "server: WRITE from @{}", sender_id);

    update_sender_counter_if_newer(sender_role, sender_id, counter)?;

    let tag = pkt.msg.tag.to_native();
    store_tag_and_data_if_newer(tag, &pkt.msg.data)?;

    // leave the tag and data alone
    construct_and_send_ack(
        pkt,
        AbdMessageType::WriteAck,
        None,
        None,
        sender_role,
        sender_id,
    )
}

/// Updates the sender counter if the incoming counter is newer
#[inline(always)]
fn update_sender_counter_if_newer(
    sender_role: AbdRole,
    sender_id: u32,
    incoming_counter: u64,
) -> Result<(), AbdError> {
    let index = match sender_role {
        AbdRole::Reader => sender_id,
        AbdRole::Writer => sender_id + ABD_MAX_NODES,
        _ => return Err(AbdError::InvalidSenderRole),
    };
    let counter = map_get_mut(&COUNTERS, index)?;

    try_spin_lock_acquire(&mut counter.lock).map_err(|_| AbdError::LockRetryLimitHit)?;

    let res = if incoming_counter > counter.val {
        counter.val = incoming_counter;
        Ok(())
    } else {
        Err(AbdError::CounterNotNewer)
    };

    spin_lock_release(&mut counter.lock);

    res
}

/// Stores new tag and data if tag is newer
#[inline(always)]
fn store_tag_and_data_if_newer(
    new_tag: u64,
    new_data: &ArchivedAbdMessageData,
) -> Result<(), AbdError> {
    let stored = map_get_mut(&TAG_DATA, 0)?;

    try_spin_lock_acquire(&mut stored.tag.lock)?;
    if tag::gt(new_tag, stored.tag.val) {
        stored.tag.val = new_tag;
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(new_data).cast::<u8>(),
                &raw const stored.data as *mut u8,
                core::mem::size_of::<ArchivedAbdMessageData>(),
            );
        }
    }
    spin_lock_release(&mut stored.tag.lock);
    Ok(())
}

/// Builds a response packet by updating fields and checksum
#[inline(always)]
fn construct_and_send_ack(
    pkt: AbdContext,
    new_type: AbdMessageType,
    new_tag: Option<u64>,
    new_data: Option<&ArchivedAbdMessageData>,
    dest_role: AbdRole,
    dest_id: u32,
) -> Result<u32, AbdError> {
    munge!(let ArchivedAbdMessage { data, mut recipient_role, mut sender_id, mut sender_role, mut tag, mut type_, .. } = pkt.msg);
    let mut udp_csum = pkt.udp.check;

    let my_id = read_global(&NODE_ID);
    recompute_udp_csum_for_abd_update(&sender_id, &my_id.into(), &mut udp_csum)?;
    *sender_id = my_id.into();

    let new_sender_role = AbdRole::Server.into();
    recompute_udp_csum_for_abd_update(&sender_role, &new_sender_role, &mut udp_csum)?;
    *sender_role = new_sender_role;

    let new_recipient_role = dest_role.into();
    recompute_udp_csum_for_abd_update(&recipient_role, &new_recipient_role, &mut udp_csum)?;
    *recipient_role = new_recipient_role;

    recompute_udp_csum_for_abd_update(&type_, &new_type.into(), &mut udp_csum)?;
    *type_ = new_type.into();

    if let Some(new_tag) = new_tag {
        recompute_udp_csum_for_abd_update(&tag, &new_tag.into(), &mut udp_csum)?;
        *tag = new_tag.into();
    }

    if let Some(new_value) = new_data {
        recompute_udp_csum_for_abd_update(&data, new_value, &mut udp_csum)?;
        overwrite_seal(data, new_value);
    }

    pkt.udp.check = udp_csum;
    redirect_to_dest(pkt.udp, pkt.ip, pkt.eth, dest_id)
}

/// Swap UDP ports, IPs, and MACs, then redirect to the destination
#[inline(always)]
fn redirect_to_dest(
    udph: &mut UdpHdr,
    iph: &mut Ipv4Hdr,
    eth: &mut EthHdr,
    dest_id: u32,
) -> Result<u32, AbdError> {
    // swap UDP ports and IPs
    mem::swap(&mut udph.source, &mut udph.dest);
    mem::swap(&mut iph.src_addr, &mut iph.dst_addr);

    let dest = NODES.get(dest_id).ok_or(AbdError::MapLookupError)?;

    // swap MACs and set the destination MAC to the destination node
    mem::swap(&mut eth.src_addr, &mut eth.dst_addr);
    eth.dst_addr.copy_from_slice(&dest.mac);

    let ret = u32::try_from(unsafe { bpf_redirect(dest.ifindex, 0) })
        .map_err(|_| AbdError::CastFailed)?;
    (ret == XDP_REDIRECT)
        .then_some(ret)
        .ok_or(AbdError::RedirectFailed)
}

#[cfg(not(test))]
#[panic_handler]
const fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
