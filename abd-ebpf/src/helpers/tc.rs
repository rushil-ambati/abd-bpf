use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::BPF_F_PSEUDO_HDR, cty::c_long, helpers::r#gen::bpf_skb_store_bytes,
    programs::TcContext,
};
use aya_log_ebpf::error;

use super::{
    common::ptr_at,
    offsets::{IPH_CSUM_OFF, IPH_DST_OFF, IPH_SRC_OFF, UDPH_CSUM_OFF, UDPH_DST_OFF, UDPH_SRC_OFF},
};

/// Store a value `v` at the given `offset` in the packet header.
#[inline]
pub fn store<T>(ctx: &TcContext, offset: usize, v: &T, flags: u64) -> Result<(), c_long> {
    unsafe {
        let ret = bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            offset as u32,
            v as *const _ as *const _,
            size_of::<T>() as u32,
            flags,
        );
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

/// Set the UDP source port in the packet header.
/// `port` is assumed to be in host byte order (little-endian).
#[inline]
pub fn set_udp_src_port(ctx: &TcContext, port: u16) -> Result<(), c_long> {
    update_udp_port(ctx, UDPH_SRC_OFF, port)
}

/// Set the UDP destination port in the packet header.
/// `port`` is assumed to be in host byte order (little-endian).
#[inline]
pub fn set_udp_dst_port(ctx: &TcContext, port: u16) -> Result<(), c_long> {
    update_udp_port(ctx, UDPH_DST_OFF, port)
}

/// Overwrites the UDP port in the packet header at the given `offset`
/// and updates the checksums accordingly.
/// `port` is assumed to be in host byte order (little-endian).
fn update_udp_port(ctx: &TcContext, offset: usize, port: u16) -> Result<(), c_long> {
    let old_port_ptr: *const u16 =
        ptr_at::<TcContext, u16>(ctx, offset as usize).map_err(|_| {
            error!(ctx, "failed to get old port pointer");
            -1
        })?;
    let old_port = unsafe { *old_port_ptr };
    let new_port = port.to_be();

    if old_port == new_port {
        return Ok(());
    }

    ctx.l4_csum_replace(
        UDPH_CSUM_OFF,
        old_port as u64,
        new_port as u64,
        size_of_val(&new_port) as u64,
    )?;

    store(ctx, offset, &port.to_be(), 0)
}

/// Set the IPv4 source address in the packet header to the given `ip`.
#[inline]
pub fn set_ipv4_src_addr(ctx: &TcContext, ip: Ipv4Addr) -> Result<(), c_long> {
    set_ipv4_addr(ctx, IPH_SRC_OFF, ip)
}

/// Set the IPv4 destination address in the packet header to the given `ip`.
#[inline]
pub fn set_ipv4_dst_addr(ctx: &TcContext, ip: Ipv4Addr) -> Result<(), c_long> {
    set_ipv4_addr(ctx, IPH_DST_OFF, ip)
}

/// Overwrites the IPv4 address in the packet header at the given offset
/// and updates the checksums accordingly. This function assumes the packet contains a UDP header.
fn set_ipv4_addr(ctx: &TcContext, offset: usize, ip: Ipv4Addr) -> Result<(), c_long> {
    let old_ip_ptr: *const u32 = ptr_at::<TcContext, u32>(ctx, offset as usize).map_err(|_| {
        error!(ctx, "failed to get old IP pointer");
        -1
    })?;
    let old_ip = unsafe { *old_ip_ptr };
    let new_ip = u32::from(ip).to_be();

    if old_ip == new_ip {
        return Ok(());
    }

    // note: the IP address is part of the UDP pseudo header, hence BPF_F_PSEUDO_HDR is used
    ctx.l4_csum_replace(
        UDPH_CSUM_OFF,
        old_ip as u64,
        new_ip as u64,
        (BPF_F_PSEUDO_HDR as u64) | (size_of_val(&new_ip) as u64),
    )
    .inspect_err(|e| {
        error!(ctx, "Failed to update the UDP checksum, ret={}", *e);
    })?;

    ctx.l3_csum_replace(
        IPH_CSUM_OFF,
        old_ip as u64,
        new_ip as u64,
        core::mem::size_of_val(&new_ip) as u64,
    )
    .inspect_err(|e| {
        error!(ctx, "Failed to update the IP header checksum, ret={}", *e);
    })?;

    store(ctx, offset, &ip, 0).inspect_err(|e: &i64| {
        error!(
            ctx,
            "Failed to update the destination IP address in the packet header, ret={}", *e
        );
    })
}
