use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::{BPF_F_PSEUDO_HDR, TC_ACT_SHOT},
    helpers::r#gen::bpf_skb_store_bytes,
    programs::TcContext,
};
use aya_log_ebpf::error;

use super::{
    offsets::{IPH_CSUM_OFF, IPH_DST_OFF, IPH_SRC_OFF, UDPH_CSUM_OFF, UDPH_DST_OFF, UDPH_SRC_OFF},
    utils::{ptr_at, BpfResult},
};

/// Store a value `v` at the given `offset` in the packet header.
///
/// # Errors
///
/// Will return `TC_ACT_SHOT` if any error occurs.
#[inline]
pub fn store<T>(ctx: &TcContext, offset: usize, v: &T, flags: u64) -> BpfResult<()> {
    let offset = u32::try_from(offset).map_err(|_| {
        error!(ctx, "failed to convert offset to u32");
        TC_ACT_SHOT
    })?;
    let len: u32 = core::mem::size_of::<T>().try_into().map_err(|_| {
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

    store(ctx, offset, &port.to_be(), 0).inspect_err(|e| {
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
#[allow(clippy::inline_always)]
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
#[allow(clippy::inline_always)]
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
#[allow(clippy::inline_always)]
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
        core::mem::size_of_val(&new_ip) as u64,
    )
    .map_err(|e| {
        error!(ctx, "Failed to update the IP header checksum: {}", e);
        TC_ACT_SHOT
    })?;

    store(ctx, offset, &ip, 0).inspect_err(|e: &i64| {
        error!(
            ctx,
            "Failed to update the destination IP address in the packet header: {}", *e
        );
    })
}
