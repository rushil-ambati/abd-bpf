use core::{mem::offset_of, ptr::copy_nonoverlapping};

use abd_common::{constants::ABD_MAGIC, msg::ArchivedAbdMessage};
use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS},
        TC_ACT_PIPE, TC_ACT_SHOT,
    },
    maps::HashMap,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::error;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rkyv::{access_unchecked_mut, seal::Seal};

pub const ETH_SRC_OFF: usize = offset_of!(EthHdr, src_addr);
pub const ETH_DST_OFF: usize = offset_of!(EthHdr, dst_addr);

pub const IPH_OFF: usize = EthHdr::LEN;
pub const IPH_SRC_OFF: usize = IPH_OFF + offset_of!(Ipv4Hdr, src_addr);
pub const IPH_DST_OFF: usize = IPH_OFF + offset_of!(Ipv4Hdr, dst_addr);
pub const IPH_CSUM_OFF: usize = IPH_OFF + offset_of!(Ipv4Hdr, check);

pub const UDPH_OFF: usize = IPH_OFF + Ipv4Hdr::LEN;
pub const UDPH_SRC_OFF: usize = UDPH_OFF + offset_of!(UdpHdr, source);
pub const UDPH_DST_OFF: usize = UDPH_OFF + offset_of!(UdpHdr, dest);
pub const UDPH_CSUM_OFF: usize = UDPH_OFF + offset_of!(UdpHdr, check);
pub const UDP_PAYLOAD_OFF: usize = UDPH_OFF + UdpHdr::LEN;

// Alias for results from BPF functions
pub type BpfResult<T> = Result<T, i64>;

/// Anything with `data` & `data_end` pointers
pub trait PacketBuf: EbpfContext {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;

    const ABORT: i64;
    const IGNORE: i64;
    const DROP: i64;
}
impl PacketBuf for XdpContext {
    fn data(&self) -> usize {
        Self::data(self)
    }

    fn data_end(&self) -> usize {
        Self::data_end(self)
    }

    const ABORT: i64 = XDP_ABORTED as i64;
    const IGNORE: i64 = XDP_PASS as i64;
    const DROP: i64 = XDP_DROP as i64;
}
impl PacketBuf for TcContext {
    fn data(&self) -> usize {
        Self::data(self)
    }

    fn data_end(&self) -> usize {
        Self::data_end(self)
    }

    const ABORT: i64 = TC_ACT_SHOT as i64;
    const IGNORE: i64 = TC_ACT_PIPE as i64;
    const DROP: i64 = TC_ACT_SHOT as i64;
}

/// Bounds‐checked pointer into packet data
///
/// # Errors
///
/// Returns an error if the offset is out of bounds.
/// For XDP, returns `XDP_ABORTED` on error. For other program types, returns `TC_ACT_SHOT` on error.
#[inline]
pub fn ptr_at<C: PacketBuf, T>(ctx: &C, offset: usize) -> BpfResult<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(C::ABORT);
    }
    Ok((start + offset) as *mut T)
}

/// ABD packet headers and message
pub struct AbdPacket<'a> {
    pub eth: &'a mut EthHdr,
    pub iph: &'a mut Ipv4Hdr,
    pub udph: &'a mut UdpHdr,
    pub msg: Seal<'a, ArchivedAbdMessage>,
}

/// Parse an ABD packet from a context
///
/// # Errors
///
/// If the packet is not an ABD packet, returns `XDP_PASS` or `TC_ACT_PIPE` depending on the context.
/// If any other error occurs during packet parsing, returns `XDP_ABORTED` or `TC_ACT_SHOT` depending on the context.
pub fn parse_abd_packet<C: PacketBuf>(ctx: &C, port: u16, num_nodes: u32) -> BpfResult<AbdPacket> {
    // Ethernet → must be IPv4
    let eth_ptr: *mut EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth_ptr).ether_type } != EtherType::Ipv4 {
        return Err(C::IGNORE);
    }
    let eth = unsafe { &mut *eth_ptr };

    // IPv4 → must be UDP
    let iph_ptr: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    if unsafe { (*iph_ptr).proto } != IpProto::Udp {
        return Err(C::IGNORE);
    }
    let iph = unsafe { &mut *iph_ptr };

    // UDP → must be on our port
    let udph_ptr: *mut UdpHdr = ptr_at(ctx, UDPH_OFF)?;
    let dest_port = u16::from_be(unsafe { (*udph_ptr).dest });
    if dest_port != port {
        return Err(C::IGNORE);
    }
    let udph = unsafe { &mut *udph_ptr };

    // Bounds-check that the payload is exactly ArchivedAbdMessage
    let msg_len = size_of::<ArchivedAbdMessage>();
    let start = ctx.data();
    let end = ctx.data_end();
    if start + UDP_PAYLOAD_OFF + msg_len > end {
        return Err(C::IGNORE);
    }

    // Get a &mut [u8] pointing to the message bytes
    let msg_ptr = (start + UDP_PAYLOAD_OFF) as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(msg_ptr, msg_len) };
    let msg = unsafe { access_unchecked_mut::<ArchivedAbdMessage>(slice) };

    // Check the magic number
    let magic = msg.magic;
    if magic != ABD_MAGIC {
        return Err(C::IGNORE);
    }

    // Check the sender ID
    let sender = msg.sender;
    if sender > num_nodes {
        error!(ctx, "Invalid sender ID: {}", sender.to_native());
        return Err(C::IGNORE);
    }

    Ok(AbdPacket {
        eth,
        iph,
        udph,
        msg,
    })
}

#[cfg(feature = "l4_checksum")]
/// Recomputes the UDP checksum for a modification to the ABD message.
///
/// The existing checksum should be passed in as `udp_csum` and it will be updated with the new checksum.
/// After all modifications, the checksum should be written back to the UDP header by the caller.
///
/// The offset where `field` is located must have at least 4 bytes of space after it.
/// The size of `T` must be a multiple of 4 bytes, and be less than 256 bytes.
///
/// # Errors
///
/// For XDP, returns `XDP_ABORTED` on error. For other program types, returns `TC_ACT_SHOT` on error.
#[inline]
pub fn recompute_udp_csum_for_abd<C, T>(
    ctx: &C,
    field: &Seal<'_, T>,
    new_val: &T,
    udp_csum: &mut u16,
) -> BpfResult<()>
where
    C: PacketBuf,
{
    use aya_ebpf::helpers::r#gen::bpf_csum_diff;
    use aya_log_ebpf::info;

    let size = u32::try_from(size_of::<T>()).map_err(|_| {
        error!(
            ctx,
            "failed to convert size of {} ({}) to u32",
            core::any::type_name::<T>(),
            size_of::<T>()
        );
        C::ABORT
    })?;

    info!(
        ctx,
        "Recomputing UDP checksum for {}: size {}",
        core::any::type_name::<T>(),
        size,
    );

    let ret = unsafe {
        bpf_csum_diff(
            &raw const **field as *mut u32,
            size,
            &raw const *new_val as *mut u32,
            size,
            !u32::from(*udp_csum),
        )
    };
    if ret < 0 {
        error!(
            ctx,
            "bpf_csum_diff failed when recomputing UDP checksum: {}", ret
        );
        return Err(C::ABORT);
    }

    #[expect(clippy::cast_sign_loss)]
    let new_csum = csum_fold_helper(ret as u64);
    *udp_csum = new_csum;

    Ok(())
}

#[cfg(feature = "l4_checksum")]
/// Converts a checksum into u16
#[inline]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    #[expect(clippy::cast_possible_truncation)]
    return !(csum as u16);
}

#[cfg(not(feature = "l4_checksum"))]
/// Feature-gated version of `recompute_udp_csum_for_abd`
/// that simply disables the UDP checksum.
///
/// # Errors
///
/// Cannot fail.
#[inline]
pub const fn recompute_udp_csum_for_abd<C, T>(
    _ctx: &C,
    _field: &Seal<'_, T>,
    _new_val: &T,
    udp_csum: &mut u16,
) -> BpfResult<()>
where
    C: PacketBuf,
{
    *udp_csum = 0;
    Ok(())
}

/// Copies the contents of `src` into a sealed destination `Seal<'_, T>`.
///
/// # Safety
///
/// - The caller must ensure `seal` is valid and properly sized.
/// - The type `T` must be `Copy` or otherwise safe to memcpy.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn overwrite_seal<T>(seal: Seal<'_, T>, src: &T) {
    unsafe {
        copy_nonoverlapping(
            core::ptr::from_ref(src).cast::<u8>(),
            core::ptr::from_ref(seal.unseal_unchecked())
                .cast::<u8>()
                .cast_mut(),
            size_of::<T>(),
        );
    }
}

/// Reads a global variable `var` from within a BPF program using a volatile load.
///
/// # Safety
/// The caller must ensure that `var` is a valid pointer to a static variable.
#[must_use]
#[expect(clippy::inline_always)]
#[inline(always)]
pub unsafe fn read_global<T: Copy>(var: &'static T) -> T {
    core::ptr::read_volatile(&raw const *var)
}

/// Reads a value out of a `HashMap` at the given `key`, returning a default value if it is not found.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn map_get_or_default<K, V>(map: &HashMap<K, V>, key: &K) -> V
where
    K: Copy,
    V: Copy + Default,
{
    unsafe { map.get(key) }.map_or_else(V::default, |v| *v)
}

/// Inserts a value into a `HashMap` at the given `key`.
///
/// # Errors
///
/// If the insertion fails, returns `XDP_ABORTED` or `TC_ACT_SHOT` depending on the context.
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn map_insert<C, K, V>(ctx: &C, map: &HashMap<K, V>, key: &K, val: &V) -> BpfResult<()>
where
    C: PacketBuf,
{
    map.insert(key, val, 0).map_err(|_| {
        error!(ctx, "Failed to insert into map");
        C::ABORT
    })
}

/// Increments a value in a `HashMap` at the given `key` by 1, returning the new value.
///
/// # Errors
///
/// If the increment fails, returns `XDP_ABORTED` or `TC_ACT_SHOT` depending on the context.
#[inline]
pub fn map_increment<C, K, V>(ctx: &C, map: &HashMap<K, V>, key: &K) -> BpfResult<V>
where
    C: PacketBuf,
    K: Copy,
    V: Copy + core::ops::Add<Output = V> + From<u8> + Default,
{
    let val = map_get_or_default(map, key) + V::from(1);
    map.insert(key, &val, 0).map_err(|_| {
        error!(ctx, "Failed to increment map value");
        C::ABORT
    })?;
    Ok(val)
}

/// Removes a value from a `HashMap` at the given `key`.
///
/// # Errors
///
/// If the removal fails, returns `XDP_ABORTED` or `TC_ACT_SHOT` depending on the context.
#[inline]
pub fn map_remove<C, K, V>(ctx: &C, map: &HashMap<K, V>, key: &K) -> BpfResult<()>
where
    C: PacketBuf,
    K: Copy,
{
    map.remove(key).map_err(|_| {
        error!(ctx, "Failed to remove from map");
        C::ABORT
    })
}
