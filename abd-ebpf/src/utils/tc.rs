use core::net::Ipv4Addr;

use abd_common::{
    constants::ABD_UDP_PORT,
    map_types::{ClientInfo, NodeInfo},
};
use aya_ebpf::{
    bindings::TC_ACT_REDIRECT,
    helpers::r#gen::{bpf_redirect, bpf_skb_store_bytes},
    maps::Array,
    programs::TcContext,
};
use aya_log_ebpf::debug;

use super::{
    common::{
        map_update, AbdContext, PacketCtx, ETH_HDR_DST_ADDR_OFF, ETH_HDR_SRC_ADDR_OFF,
        IPV4_HDR_CSUM_OFF, IPV4_HDR_DST_ADDR_OFF, IPV4_HDR_SRC_ADDR_OFF, UDP_HDR_CSUM_OFF,
        UDP_HDR_DST_OFF, UDP_HDR_SRC_OFF,
    },
    error::AbdError,
};

/// Broadcasts the current packet to every replica.
#[inline(always)]
pub fn broadcast_to_nodes(
    ctx: &TcContext,
    my_id: u32,
    nodes_map: &Array<NodeInfo>,
    num_nodes: u32,
) -> Result<(), AbdError> {
    // servers must reply on main UDP port
    set_udp_src_port(ctx, ABD_UDP_PORT)?;

    // dest port is assumed to already be set to ABD_UDP_PORT

    // set L3/L2 source addresses as our own
    let me = nodes_map.get(my_id).ok_or(AbdError::MapLookupError)?;
    set_ipv4_src_addr(ctx, me.ipv4)?;
    skb_store(ctx, ETH_HDR_SRC_ADDR_OFF, &me.mac, 0)?;

    for i in 1..=num_nodes {
        let peer = nodes_map.get(i).ok_or(AbdError::MapLookupError)?;

        // set L3/L2 destination addresses to the peer
        set_ipv4_dst_addr(ctx, peer.ipv4)?;
        skb_store(ctx, ETH_HDR_DST_ADDR_OFF, &peer.mac, 0)?;

        ctx.clone_redirect(peer.ifindex, 0)
            .map_err(|_| AbdError::CloneRedirectFailed)?;
        debug!(
            ctx,
            "clone_redirect -> @{} ({}@if{})", i, peer.ipv4, peer.ifindex
        );
    }
    Ok(())
}

/// Redirects the packet to the given `client`.
#[inline(always)]
pub fn redirect_to_client(
    ctx: &TcContext,
    client: &ClientInfo,
    me: &NodeInfo,
) -> Result<i32, AbdError> {
    set_udp_src_port(ctx, ABD_UDP_PORT)?;
    set_udp_dst_port(ctx, client.port)?;

    set_ipv4_src_addr(ctx, me.ipv4)?;
    set_ipv4_dst_addr(ctx, client.ipv4)?;

    set_eth_src_addr(ctx, &me.mac)?;
    set_eth_dst_addr(ctx, &client.mac)?;

    let ret = i32::try_from(unsafe { bpf_redirect(client.ifindex, 0) })
        .map_err(|_| AbdError::CastFailed)?;
    (ret == TC_ACT_REDIRECT)
        .then_some(ret)
        .ok_or(AbdError::RedirectFailed)
}

/// Stores client information in the `client_map`.
#[inline(always)]
pub fn store_client_info(
    ctx: &TcContext,
    client_map: &Array<ClientInfo>,
    pkt: &AbdContext,
) -> Result<(), AbdError> {
    let client = ClientInfo::new(
        (unsafe { *ctx.skb.skb }).ingress_ifindex,
        Ipv4Addr::from(u32::from_be(pkt.ip.src_addr)),
        pkt.eth.src_addr,
        u16::from_be(pkt.udp.source),
    );
    map_update(client_map, 0, &client)
}

/// Set the UDP source port in the packet header.
/// `port` is assumed to be in host byte order (little-endian).
#[inline(always)]
pub fn set_udp_src_port(ctx: &TcContext, port: u16) -> Result<(), AbdError> {
    update_udp_port(ctx, UDP_HDR_SRC_OFF, port)
}

/// Set the UDP destination port in the packet header.
/// `port` is assumed to be in host byte order (little-endian).
#[inline(always)]
pub fn set_udp_dst_port(ctx: &TcContext, port: u16) -> Result<(), AbdError> {
    update_udp_port(ctx, UDP_HDR_DST_OFF, port)
}

/// Overwrites the UDP port in the packet header at the given `offset`
/// and updates the checksums accordingly.
/// `port` is assumed to be in host byte order (little-endian).
#[inline(always)]
fn update_udp_port(ctx: &TcContext, offset: usize, port: u16) -> Result<(), AbdError> {
    let old_port_ptr: *const u16 = ctx.ptr_at(offset).ok_or(AbdError::HeaderParsingError)?;
    let old_port = unsafe { *old_port_ptr };
    let new_port = port.to_be();

    if old_port == new_port {
        return Ok(());
    }

    let udp_csum: u16 = ctx
        .load(UDP_HDR_CSUM_OFF)
        .map_err(|_| AbdError::HeaderParsingError)?;
    if udp_csum != 0 {
        // if this fails, just disable the checksum
        ctx.l4_csum_replace(
            UDP_HDR_CSUM_OFF,
            u64::from(old_port),
            u64::from(new_port),
            size_of_val(&new_port) as u64,
        )
        .or_else(|_| skb_store(ctx, UDP_HDR_CSUM_OFF, &0u16, 0))?;
    }

    skb_store(ctx, offset, &port.to_be(), 0)
}

/// Set the IPv4 source address in the packet header to the given `ip`.
/// This function assumes the packet contains a UDP header.
#[inline(always)]
pub fn set_ipv4_src_addr(ctx: &TcContext, ip: Ipv4Addr) -> Result<(), AbdError> {
    set_ipv4_addr(ctx, IPV4_HDR_SRC_ADDR_OFF, ip)
}

/// Set the IPv4 destination address in the packet header to the given `ip`.
/// This function assumes the packet contains a UDP header.
#[inline(always)]
pub fn set_ipv4_dst_addr(ctx: &TcContext, ip: Ipv4Addr) -> Result<(), AbdError> {
    set_ipv4_addr(ctx, IPV4_HDR_DST_ADDR_OFF, ip)
}

/// Overwrites the IPv4 address in the packet header at the given offset
/// and updates the checksums accordingly. This function assumes the packet contains a UDP header.
/// This function is a no-op if the new IP address is the same as the old one.
#[inline(always)]
fn set_ipv4_addr(ctx: &TcContext, offset: usize, ip: Ipv4Addr) -> Result<(), AbdError> {
    let old_ip_ptr: *const u32 = ctx.ptr_at(offset).ok_or(AbdError::HeaderParsingError)?;
    let old_ip = unsafe { *old_ip_ptr };
    let new_ip = u32::from(ip).to_be();

    if old_ip == new_ip {
        return Ok(());
    }

    let udp_csum: u16 = ctx
        .load(UDP_HDR_CSUM_OFF)
        .map_err(|_| AbdError::HeaderParsingError)?;
    if udp_csum != 0 {
        // note: the IP address is part of the UDP pseudo header, hence BPF_F_PSEUDO_HDR is used
        // if this fails, just disable the checksum
        ctx.l4_csum_replace(
            UDP_HDR_CSUM_OFF,
            u64::from(old_ip),
            u64::from(new_ip),
            u64::from(aya_ebpf::bindings::BPF_F_PSEUDO_HDR) | (size_of_val(&new_ip) as u64),
        )
        .or_else(|_| skb_store(ctx, UDP_HDR_CSUM_OFF, &0u16, 0))?;
    }

    ctx.l3_csum_replace(
        IPV4_HDR_CSUM_OFF,
        u64::from(old_ip),
        u64::from(new_ip),
        size_of_val(&new_ip) as u64,
    )
    .map_err(|_| AbdError::ChecksumError)?;

    skb_store(ctx, offset, &ip, 0)
}

/// Set the Ethernet source MAC address in the packet header to the given `mac`.
#[inline(always)]
pub fn set_eth_src_addr(ctx: &TcContext, mac: &[u8; 6]) -> Result<(), AbdError> {
    set_eth_addr(ctx, ETH_HDR_SRC_ADDR_OFF, mac)
}

/// Set the Ethernet destination address in the packet header to the given `mac`.
#[inline(always)]
pub fn set_eth_dst_addr(ctx: &TcContext, mac: &[u8; 6]) -> Result<(), AbdError> {
    set_eth_addr(ctx, ETH_HDR_DST_ADDR_OFF, mac)
}

/// Overwrites the Ethernet MAC address in the packet header at the given offset.
/// This function is a no-op if the new MAC address is the same as the old one.
#[inline(always)]
fn set_eth_addr(ctx: &TcContext, offset: usize, mac: &[u8; 6]) -> Result<(), AbdError> {
    let old_mac_ptr: *const [u8; 6] = ctx.ptr_at(offset).ok_or(AbdError::HeaderParsingError)?;
    let old_mac = unsafe { *old_mac_ptr };
    if old_mac == *mac {
        return Ok(());
    }

    skb_store(ctx, offset, mac, 0)
}

/// Store a value `v` at the given `offset` in the SKB.
#[inline(always)]
pub fn skb_store<T>(ctx: &TcContext, offset: usize, v: &T, flags: u64) -> Result<(), AbdError> {
    let offset = u32::try_from(offset).map_err(|_| AbdError::CastFailed)?;
    let len: u32 = size_of::<T>()
        .try_into()
        .map_err(|_| AbdError::CastFailed)?;
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
            Err(AbdError::SkbStoreFailed)
        }
    }
}
