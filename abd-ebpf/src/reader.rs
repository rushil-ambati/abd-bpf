#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use abd_common::{
    AbdMsgType, ArchivedAbdMsg, ClientInfo, NodeInfo, ABD_NODE_MAX, ABD_SERVER_UDP_PORT,
    ABD_UDP_PORT,
};
use abd_ebpf::helpers::{
    common::{calculate_udp_csum_update, parse_abd_packet, AbdPacket},
    offsets::{ETH_DST_OFF, ETH_SRC_OFF},
    tc::{set_ipv4_dst_addr, set_ipv4_src_addr, set_udp_dst_port, set_udp_src_port, store},
};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_STOLEN},
    helpers::r#gen::bpf_redirect,
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::{error, info, warn};
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

/// Client we’re serving right now (key = 0)
#[map]
static CLIENT_INFO: HashMap<u32, ClientInfo> = HashMap::with_max_entries(1, 0);

// TODO: combine READING_FLAG and PHASE into a single value
/// 0 = idle, 1 = busy
#[map]
static READING_FLAG: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Phase: 1 or 2 (only valid while busy)
#[map]
static PHASE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Monotonic read-counter
#[map]
static READ_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// # acks seen in *current* phase
#[map]
static ACK_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/// Aggregation results from phase-1
#[map]
static MAX_TAG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);
#[map]
static MAX_VALUE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

// TODO: tidy up, match style of other files, better error handling, better logging
/* ------------------------------------------------------------------------- */
/*                               Entry point                                 */
/* ------------------------------------------------------------------------- */

#[classifier]
pub fn reader(ctx: TcContext) -> i32 {
    match try_reader(ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_reader(ctx: TcContext) -> Result<i32, ()> {
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

    let pkt = match parse_abd_packet(&ctx, ABD_UDP_PORT, num_nodes) {
        Ok(p) => p,
        Err(_) => return Ok(TC_ACT_PIPE),
    };

    match pkt.msg.type_.try_into()? {
        AbdMsgType::Read => handle_client_read(&ctx, pkt),
        AbdMsgType::ReadAck => handle_read_ack(&ctx, pkt),
        AbdMsgType::WriteAck => handle_write_ack(&ctx, pkt),
        // Any other message → not our job
        _ => {
            warn!(
                &ctx,
                "Server {}: Received unexpected message type {} from @{}, dropping...",
                self_id,
                pkt.msg.type_.to_native(),
                pkt.msg.sender.to_native()
            );
            return Ok(TC_ACT_SHOT);
        }
    }
}

/* ------------------------------------------------------------------------- */
/*                       Phase-0 :  request from client                      */
/* ------------------------------------------------------------------------- */

fn handle_client_read(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    // ---------- drop if busy ------------------------------------------------
    let busy = *unsafe { READING_FLAG.get(&0) }.unwrap_or(&0);
    if busy != 0 {
        warn!(ctx, "Reader busy – drop READ");
        return Ok(TC_ACT_SHOT);
    }

    // ---------- initialise state -------------------------------------------
    READING_FLAG.insert(&0, &1, 0).map_err(|_| ())?;
    PHASE.insert(&0, &1, 0).map_err(|_| ())?;
    ACK_COUNT.insert(&0, &0, 0).map_err(|_| ())?;
    MAX_TAG.insert(&0, &0, 0).map_err(|_| ())?;
    MAX_VALUE.insert(&0, &0, 0).map_err(|_| ())?;

    // bump read_counter
    let new_rc = unsafe { READ_COUNTER.get(&0) }
        .unwrap_or(&0)
        .wrapping_add(1);
    READ_COUNTER.insert(&0, &new_rc, 0).ok();

    // remember client
    CLIENT_INFO
        .insert(
            &0,
            &ClientInfo {
                ipv4: Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
                ifindex: unsafe { (*ctx.skb.skb).ingress_ifindex },
                port: u16::from_be(pkt.udph.source),
                mac: pkt.eth.src_addr,
            },
            0,
        )
        .ok();

    info!(ctx, "Begin READ (counter={}) – broadcasting query", new_rc);

    // keep message as-is, just set counter
    munge!(let ArchivedAbdMsg { mut sender, mut counter, .. } = pkt.msg);
    let mut csum = pkt.udph.check;
    calculate_udp_csum_update(ctx, &counter, new_rc.into(), &mut csum)?;
    *counter = new_rc.into();

    let self_id = unsafe { core::ptr::read_volatile(&SELF_ID) };
    calculate_udp_csum_update(ctx, &sender, self_id.into(), &mut csum)?;
    *sender = self_id.into();

    pkt.udph.check = csum;

    broadcast_to_nodes(ctx).map(|_| TC_ACT_STOLEN)
}

/* ------------------------------------------------------------------------- */
/*                       Phase-1 :  ReadAck from replicas                    */
/* ------------------------------------------------------------------------- */

fn handle_read_ack(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    // fast checks
    if is_not_busy_phase(1)? {
        return Ok(TC_ACT_SHOT);
    }

    let cur = *unsafe { READ_COUNTER.get(&0) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != cur {
        return Ok(TC_ACT_SHOT);
    }

    info!(
        ctx,
        "Phase-1: received ReadAck from @{} (tag={} value={})",
        pkt.msg.sender.to_native(),
        pkt.msg.tag.to_native(),
        pkt.msg.value.to_native()
    );

    // update max(tag,value)
    let tag = pkt.msg.tag.to_native();
    let max = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    if tag > max {
        MAX_TAG.insert(&0, &tag, 0).ok();
        let val = pkt.msg.value.to_native();
        MAX_VALUE.insert(&0, &val, 0).ok();
    }

    // bump ack counter
    let ack = incr_ack()?; // helper below
    let majority = (unsafe { core::ptr::read_volatile(&NUM_NODES) } >> 1) + 1;
    if ack < (majority as u64) {
        info!(
            ctx,
            "Got {} ReadAck(s), waiting for majority ({})...", ack, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    // ---- Majority reached → Phase-2 ---------------------------------------
    PHASE.insert(&0, &2, 0).ok();
    ACK_COUNT.insert(&0, &0, 0).ok(); // reset
    let cur2 = cur + 1;
    READ_COUNTER.insert(&0, &cur2, 0).ok();

    // craft WRITE propagation
    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, mut counter, .. } = pkt.msg);

    let max_tag = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    let max_value = *unsafe { MAX_VALUE.get(&0) }.unwrap_or(&0);

    let mut csum = pkt.udph.check;
    let self_id = unsafe { core::ptr::read_volatile(&SELF_ID) };
    calculate_udp_csum_update(ctx, &sender, self_id.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &type_, AbdMsgType::Write.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &tag, max_tag.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &value, max_value.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &counter, cur2.into(), &mut csum)?;

    *sender = self_id.into();
    *type_ = AbdMsgType::Write.into();
    *tag = max_tag.into();
    *value = max_value.into();
    *counter = cur2.into();
    pkt.udph.check = csum;

    info!(
        ctx,
        "Phase-2: propagate tag={} value={}", max_tag, max_value
    );

    broadcast_to_nodes(ctx).map(|_| TC_ACT_STOLEN)
}

/* ------------------------------------------------------------------------- */
/*                       Phase-2 :  WriteAck from replicas                   */
/* ------------------------------------------------------------------------- */

fn handle_write_ack(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    if is_not_busy_phase(2)? {
        return Ok(TC_ACT_SHOT);
    }

    let cur = *unsafe { READ_COUNTER.get(&0) }.unwrap_or(&0);
    if pkt.msg.counter.to_native() != cur {
        return Ok(TC_ACT_SHOT);
    }

    info!(
        ctx,
        "Phase-2: received WriteAck from @{}",
        pkt.msg.sender.to_native(),
    );

    let ack = incr_ack()?;
    let majority = (unsafe { core::ptr::read_volatile(&NUM_NODES) } >> 1) + 1;
    if ack < (majority as u64) {
        info!(
            ctx,
            "Got {} WriteAck(s), waiting for majority ({})...", ack, majority
        );
        return Ok(TC_ACT_SHOT);
    }

    // ---- Done -> reply to client & clean up --------------------------------
    PHASE.remove(&0).ok();
    READING_FLAG.remove(&0).ok();
    ACK_COUNT.remove(&0).ok();

    send_read_ack_to_client(ctx, pkt)
}

/* ------------------------------------------------------------------------- */
/*                                helpers                                    */
/* ------------------------------------------------------------------------- */

/// Broadcast the *current* packet to every replica.
/// `clone=true` -> use `bpf_clone_redirect`, leaves the original skb to continue
#[inline]
fn broadcast_to_nodes(ctx: &TcContext) -> Result<(), ()> {
    // servers must reply on our UDP port
    set_udp_src_port(ctx, ABD_UDP_PORT).ok();

    // send on the server port
    set_udp_dst_port(ctx, ABD_SERVER_UDP_PORT).ok();

    // ensure src = this node
    let me = unsafe { NODES.get(core::ptr::read_volatile(&SELF_ID)) }.ok_or_else(|| {
        error!(ctx, "self info missing");
        ()
    })?;
    set_ipv4_src_addr(ctx, me.ipv4).ok();
    store(ctx, ETH_SRC_OFF, &me.mac, 0).ok();

    let num = unsafe { core::ptr::read_volatile(&NUM_NODES) };
    for i in 1..=num {
        let peer = NODES.get(i).ok_or(())?;

        set_ipv4_dst_addr(ctx, peer.ipv4).ok();
        store(ctx, ETH_DST_OFF, &peer.mac, 0).ok();

        ctx.clone_redirect(peer.ifindex, 0).map_err(|_| ())?;
    }
    Ok(())
}

/// After phase-2 majority, send ReadAck to original client
fn send_read_ack_to_client(ctx: &TcContext, pkt: AbdPacket) -> Result<i32, ()> {
    let cli = unsafe { CLIENT_INFO.get(&0) }.ok_or(())?;

    info!(
        ctx,
        "Sending ReadAck to client @{} (tag={} value={})",
        cli.ipv4,
        pkt.msg.tag.to_native(),
        pkt.msg.value.to_native()
    );

    let max_tag = *unsafe { MAX_TAG.get(&0) }.unwrap_or(&0);
    let max_value = *unsafe { MAX_VALUE.get(&0) }.unwrap_or(&0);

    munge!(let ArchivedAbdMsg { mut sender, mut type_, mut tag, mut value, mut counter, .. } = pkt.msg);

    let mut csum = pkt.udph.check;
    let self_id = unsafe { core::ptr::read_volatile(&SELF_ID) };
    calculate_udp_csum_update(ctx, &sender, self_id.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &type_, AbdMsgType::ReadAck.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &tag, max_tag.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &value, max_value.into(), &mut csum)?;
    calculate_udp_csum_update(ctx, &counter, 0u64.into(), &mut csum)?;

    *sender = self_id.into();
    *type_ = AbdMsgType::ReadAck.into();
    *tag = max_tag.into();
    *value = max_value.into();
    *counter = 0.into();
    pkt.udph.check = csum;

    // L2/L3/L4 back to client
    let me = unsafe { NODES.get(core::ptr::read_volatile(&SELF_ID)) }.ok_or_else(|| {
        error!(ctx, "self info missing");
        ()
    })?;
    set_ipv4_src_addr(ctx, me.ipv4).ok();
    set_ipv4_dst_addr(ctx, cli.ipv4).ok();
    store(ctx, ETH_SRC_OFF, &me.mac, 0).ok();
    store(ctx, ETH_DST_OFF, &cli.mac, 0).ok();
    set_udp_dst_port(ctx, ABD_UDP_PORT).ok();
    set_udp_dst_port(ctx, cli.port).ok();

    let rc = unsafe { bpf_redirect(cli.ifindex, 0) } as i32;
    (rc == TC_ACT_REDIRECT).then_some(rc).ok_or(())
}

/* ------------------------------------------------------------------------- */

/// If not busy *or* in a different phase → return true (so caller can drop)
#[inline]
fn is_not_busy_phase(want: u8) -> Result<bool, ()> {
    let busy = *unsafe { READING_FLAG.get(&0) }.unwrap_or(&0);
    if busy == 0 {
        return Ok(true);
    }
    let phase = *unsafe { PHASE.get(&0) }.unwrap_or(&0);
    Ok(phase != want)
}

#[inline]
fn incr_ack() -> Result<u64, ()> {
    let new = unsafe { ACK_COUNT.get(&0) }.unwrap_or(&0).wrapping_add(1);
    ACK_COUNT.insert(&0, &new, 0).map_err(|_| ())?;
    Ok(new)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
