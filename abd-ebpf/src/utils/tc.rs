use core::net::Ipv4Addr;

use abd_common::{
    constants::{ABD_SERVER_UDP_PORT, ABD_UDP_PORT},
    maps::{ClientInfo, NodeInfo},
};
use aya_ebpf::{
    bindings::{BPF_F_PSEUDO_HDR, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::r#gen::{bpf_redirect, bpf_skb_store_bytes},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error};

use super::common::{
    map_insert, ptr_at, AbdPacket, BpfResult, ETH_DST_OFF, ETH_SRC_OFF, IPH_CSUM_OFF, IPH_DST_OFF,
    IPH_SRC_OFF, UDPH_CSUM_OFF, UDPH_DST_OFF, UDPH_SRC_OFF,
};

/// Broadcast the current packet to every replica
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn broadcast_to_nodes(
    ctx: &TcContext,
    my_id: u32,
    nodes_map: &Array<NodeInfo>,
    num_nodes: u32,
) -> BpfResult<()> {
    // servers must reply on main UDP port
    set_udp_src_port(ctx, ABD_UDP_PORT).map_err(|e| {
        error!(ctx, "Failed to update source UDP port: {}", e);
        TC_ACT_SHOT
    })?;

    // send on server port
    set_udp_dst_port(ctx, ABD_SERVER_UDP_PORT).map_err(|e| {
        error!(ctx, "Failed to update destination UDP port: {}", e);
        TC_ACT_SHOT
    })?;

    // set L3/L2 source addresses as our own
    let me = nodes_map.get(my_id).ok_or_else(|| {
        error!(ctx, "Failed to get info for self (@{})", my_id);
        TC_ACT_SHOT
    })?;
    set_ipv4_src_addr(ctx, me.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to update source IP address: {}", *e))?;
    skb_store(ctx, ETH_SRC_OFF, &me.mac, 0)
        .inspect_err(|e| error!(ctx, "Failed to update source MAC address: {}", *e))?;

    for i in 1..=num_nodes {
        let peer = nodes_map.get(i).ok_or_else(|| {
            error!(ctx, "Failed to get info for @{}", i);
            TC_ACT_SHOT
        })?;

        // set L3/L2 destination addresses to the peer
        set_ipv4_dst_addr(ctx, peer.ipv4).map_err(|e| {
            error!(ctx, "Failed to update destination IP address: {}", e);
            TC_ACT_SHOT
        })?;
        skb_store(ctx, ETH_DST_OFF, &peer.mac, 0).map_err(|e| {
            error!(ctx, "Failed to update destination MAC address: {}", e);
            TC_ACT_SHOT
        })?;

        ctx.clone_redirect(peer.ifindex, 0)
            .inspect_err(|e| error!(ctx, "Failed to clone and redirect to @{}: {}", i, *e))?;
        debug!(
            ctx,
            "clone_redirect -> @{} ({}@if{})", i, peer.ipv4, peer.ifindex
        );
    }
    Ok(())
}

/// Redirect the packet to the client.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn redirect_to_client(ctx: &TcContext, client: &ClientInfo, me: &NodeInfo) -> BpfResult<i32> {
    set_udp_src_port(ctx, ABD_UDP_PORT)
        .inspect_err(|e| error!(ctx, "Failed to set dst UDP: {}", *e))?;
    set_udp_dst_port(ctx, client.port)
        .inspect_err(|e| error!(ctx, "Failed to set src UDP: {}", *e))?;

    set_ipv4_src_addr(ctx, me.ipv4).inspect_err(|e| error!(ctx, "Failed to set src IP: {}", *e))?;
    set_ipv4_dst_addr(ctx, client.ipv4)
        .inspect_err(|e| error!(ctx, "Failed to set dst IP: {}", *e))?;

    set_eth_src_addr(ctx, &me.mac)
        .inspect_err(|e| error!(ctx, "Failed to update src MAC: {}", *e))?;
    set_eth_dst_addr(ctx, &client.mac)
        .inspect_err(|e| error!(ctx, "Failed to update dst MAC: {}", *e))?;

    let ret = i32::try_from(unsafe { bpf_redirect(client.ifindex, 0) }).map_err(|_| {
        error!(ctx, "bpf_redirect failed");
        TC_ACT_SHOT
    })?;

    if ret == TC_ACT_REDIRECT {
        Ok(ret)
    } else {
        error!(ctx, "bpf_redirect returned non-redirect value: {}", ret);
        Err(ret.into())
    }
}

/// Store the client information in the `client_map`.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn store_client_info(
    ctx: &TcContext,
    client_map: &HashMap<u32, ClientInfo>,
    pkt: &AbdPacket,
) -> BpfResult<()> {
    let client = ClientInfo::new(
        (unsafe { *ctx.skb.skb }).ingress_ifindex,
        Ipv4Addr::from(u32::from_be(pkt.iph.src_addr)),
        pkt.eth.src_addr,
        u16::from_be(pkt.udph.source),
    );
    map_insert(ctx, client_map, &0, &client)
}

/// Set the UDP source port in the packet header.
/// `port` is assumed to be in host byte order (little-endian).
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn set_udp_src_port(ctx: &TcContext, port: u16) -> BpfResult<()> {
    update_udp_port(ctx, UDPH_SRC_OFF, port)
}

/// Set the UDP destination port in the packet header.
/// `port` is assumed to be in host byte order (little-endian).
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn set_udp_dst_port(ctx: &TcContext, port: u16) -> BpfResult<()> {
    update_udp_port(ctx, UDPH_DST_OFF, port)
}

/// Overwrites the UDP port in the packet header at the given `offset`
/// and updates the checksums accordingly.
/// `port` is assumed to be in host byte order (little-endian).
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
fn update_udp_port(ctx: &TcContext, offset: usize, port: u16) -> BpfResult<()> {
    let old_port_ptr: *const u16 = ptr_at::<TcContext, u16>(ctx, offset).map_err(|_| {
        error!(ctx, "failed to get old port pointer");
        TC_ACT_SHOT
    })?;
    let old_port = unsafe { *old_port_ptr };
    let new_port = port.to_be();

    if old_port == new_port {
        return Ok(());
    }

    ctx.l4_csum_replace(
        UDPH_CSUM_OFF,
        u64::from(old_port),
        u64::from(new_port),
        size_of_val(&new_port) as u64,
    )
    .map_err(|e| {
        error!(ctx, "Failed to update the UDP checksum: {}", e);
        TC_ACT_SHOT
    })?;

    skb_store(ctx, offset, &port.to_be(), 0).inspect_err(|e| {
        error!(
            ctx,
            "Failed to update the UDP port in the packet header: {}", *e
        );
    })
}

/// Set the IPv4 source address in the packet header to the given `ip`.
/// This function assumes the packet contains a UDP header.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn set_ipv4_src_addr(ctx: &TcContext, ip: Ipv4Addr) -> BpfResult<()> {
    set_ipv4_addr(ctx, IPH_SRC_OFF, ip)
}

/// Set the IPv4 destination address in the packet header to the given `ip`.
/// This function assumes the packet contains a UDP header.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn set_ipv4_dst_addr(ctx: &TcContext, ip: Ipv4Addr) -> BpfResult<()> {
    set_ipv4_addr(ctx, IPH_DST_OFF, ip)
}

/// Overwrites the IPv4 address in the packet header at the given offset
/// and updates the checksums accordingly. This function assumes the packet contains a UDP header.
/// This function is a no-op if the new IP address is the same as the old one.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
fn set_ipv4_addr(ctx: &TcContext, offset: usize, ip: Ipv4Addr) -> BpfResult<()> {
    let old_ip_ptr: *const u32 = ptr_at::<TcContext, u32>(ctx, offset).map_err(|_| {
        error!(ctx, "failed to get old IP pointer");
        TC_ACT_SHOT
    })?;
    let old_ip = unsafe { *old_ip_ptr };
    let new_ip = u32::from(ip).to_be();

    if old_ip == new_ip {
        return Ok(());
    }

    // note: the IP address is part of the UDP pseudo header, hence BPF_F_PSEUDO_HDR is used
    ctx.l4_csum_replace(
        UDPH_CSUM_OFF,
        u64::from(old_ip),
        u64::from(new_ip),
        u64::from(BPF_F_PSEUDO_HDR) | (size_of_val(&new_ip) as u64),
    )
    .map_err(|e| {
        error!(ctx, "Failed to update the UDP checksum: {}", e);
        TC_ACT_SHOT
    })?;

    ctx.l3_csum_replace(
        IPH_CSUM_OFF,
        u64::from(old_ip),
        u64::from(new_ip),
        size_of_val(&new_ip) as u64,
    )
    .map_err(|e| {
        error!(ctx, "Failed to update the IP header checksum: {}", e);
        TC_ACT_SHOT
    })?;

    skb_store(ctx, offset, &ip, 0).inspect_err(|e: &i64| {
        error!(
            ctx,
            "Failed to update the destination IP address in the packet header: {}", *e
        );
    })
}

/// Set the Ethernet source MAC address in the packet header to the given `mac`.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn set_eth_src_addr(ctx: &TcContext, mac: &[u8; 6]) -> BpfResult<()> {
    set_eth_addr(ctx, ETH_SRC_OFF, mac)
}

/// Set the Ethernet destination address in the packet header to the given `mac`.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn set_eth_dst_addr(ctx: &TcContext, mac: &[u8; 6]) -> BpfResult<()> {
    set_eth_addr(ctx, ETH_DST_OFF, mac)
}

/// Overwrites the Ethernet MAC address in the packet header at the given offset.
/// This function is a no-op if the new MAC address is the same as the old one.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[expect(clippy::inline_always)]
#[inline(always)]
fn set_eth_addr(ctx: &TcContext, offset: usize, mac: &[u8; 6]) -> BpfResult<()> {
    let old_mac_ptr: *const [u8; 6] = ptr_at::<TcContext, [u8; 6]>(ctx, offset).map_err(|_| {
        error!(ctx, "failed to get old MAC pointer");
        TC_ACT_SHOT
    })?;
    let old_mac = unsafe { *old_mac_ptr };
    if old_mac == *mac {
        return Ok(());
    }

    skb_store(ctx, offset, mac, 0).inspect_err(|e| {
        error!(
            ctx,
            "Failed to update the MAC address in the packet header: {}", *e
        );
    })
}

/// Store a value `v` at the given `offset` in the SKB.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn skb_store<T>(ctx: &TcContext, offset: usize, v: &T, flags: u64) -> BpfResult<()> {
    let offset = u32::try_from(offset).map_err(|_| {
        error!(ctx, "failed to convert offset to u32");
        TC_ACT_SHOT
    })?;
    let len: u32 = size_of::<T>().try_into().map_err(|_| {
        error!(ctx, "failed to convert size to u32");
        TC_ACT_SHOT
    })?;
    unsafe {
        let ret = bpf_skb_store_bytes(
            ctx.skb.skb.cast(),
            offset,
            core::ptr::from_ref(v).cast(),
            len,
            flags,
        );
        if ret == 0 {
            Ok(())
        } else {
            Err(TC_ACT_SHOT.into())
        }
    }
}
