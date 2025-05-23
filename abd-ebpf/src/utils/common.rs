use core::{
    mem::{self, offset_of},
    ptr::copy_nonoverlapping,
    slice,
};

use abd_common::{constants::ABD_MAGIC, map_types::Locked, message::ArchivedAbdMessage};
use aya_ebpf::{
    helpers::r#gen::bpf_csum_diff,
    maps::Array,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rkyv::{access_unchecked_mut, seal::Seal};

use super::{
    error::AbdError,
    spinlock::{spin_lock_release, try_spin_lock_acquire},
};

pub const ETH_HDR_SRC_ADDR_OFF: usize = offset_of!(EthHdr, src_addr);
pub const ETH_HDR_DST_ADDR_OFF: usize = offset_of!(EthHdr, dst_addr);

pub const IPV4_HDR_OFF: usize = EthHdr::LEN;
pub const IPV4_HDR_SRC_ADDR_OFF: usize = IPV4_HDR_OFF + offset_of!(Ipv4Hdr, src_addr);
pub const IPV4_HDR_DST_ADDR_OFF: usize = IPV4_HDR_OFF + offset_of!(Ipv4Hdr, dst_addr);
pub const IPV4_HDR_CSUM_OFF: usize = IPV4_HDR_OFF + offset_of!(Ipv4Hdr, check);

pub const UDP_HDR_OFF: usize = IPV4_HDR_OFF + Ipv4Hdr::LEN;
pub const UDP_HDR_SRC_OFF: usize = UDP_HDR_OFF + offset_of!(UdpHdr, source);
pub const UDP_HDR_DST_OFF: usize = UDP_HDR_OFF + offset_of!(UdpHdr, dest);
pub const UDP_HDR_CSUM_OFF: usize = UDP_HDR_OFF + offset_of!(UdpHdr, check);
pub const UDP_PAYLOAD_OFF: usize = UDP_HDR_OFF + UdpHdr::LEN;

pub trait PacketCtx: EbpfContext {
    #[inline(always)]
    fn ptr_at<T>(&self, offset: usize) -> Option<*const T> {
        let start = self.data();
        let end = self.data_end();
        let item_len = mem::size_of::<T>();

        if start + offset + item_len > end {
            return None;
        }

        Some((start + offset) as *const T)
    }

    #[inline(always)]
    fn ptr_at_mut<T>(&self, offset: usize) -> Option<*mut T> {
        Some((self.ptr_at::<T>(offset)?).cast_mut())
    }

    fn data_end(&self) -> usize;

    fn data(&self) -> usize;
}

impl PacketCtx for XdpContext {
    #[inline(always)]
    fn data_end(&self) -> usize {
        self.data_end()
    }

    #[inline(always)]
    fn data(&self) -> usize {
        self.data()
    }
}

impl PacketCtx for TcContext {
    #[inline(always)]
    fn data_end(&self) -> usize {
        self.data_end()
    }

    #[inline(always)]
    fn data(&self) -> usize {
        self.data()
    }
}

/// ABD packet headers and message
#[repr(C)]
pub struct AbdContext<'a> {
    pub eth: &'a mut EthHdr,
    pub ip: &'a mut Ipv4Hdr,
    pub udp: &'a mut UdpHdr,
    pub msg: Seal<'a, ArchivedAbdMessage>,
}

/// Try to parse an ABD packet from a context.
///
pub fn try_parse_abd_packet<C: PacketCtx>(
    ctx: &C,
    udp_port: u16,
    num_nodes: u32,
) -> Result<Option<AbdContext>, AbdError> {
    let eth_hdr: *mut EthHdr = ctx.ptr_at_mut(0).ok_or(AbdError::HeaderParsingError)?;
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(None);
    }

    let ipv4_hdr: *mut Ipv4Hdr = ctx
        .ptr_at_mut(IPV4_HDR_OFF)
        .ok_or(AbdError::HeaderParsingError)?;
    if unsafe { (*ipv4_hdr).proto } != IpProto::Udp {
        return Ok(None);
    }

    let udp_hdr: *mut UdpHdr = ctx
        .ptr_at_mut(UDP_HDR_OFF)
        .ok_or(AbdError::HeaderParsingError)?;
    if u16::from_be(unsafe { (*udp_hdr).dest }) != udp_port {
        return Ok(None);
    }

    // Deserialize the message (zero-copy)
    let msg_ptr: *mut ArchivedAbdMessage = ctx
        .ptr_at_mut(UDP_PAYLOAD_OFF)
        .ok_or(AbdError::HeaderParsingError)?;
    let msg_bytes =
        unsafe { slice::from_raw_parts_mut(msg_ptr.cast(), size_of::<ArchivedAbdMessage>()) };
    let msg = unsafe { access_unchecked_mut::<ArchivedAbdMessage>(msg_bytes) };

    // Check the magic number
    if msg.magic != ABD_MAGIC {
        return Err(AbdError::InvalidMagicNumber);
    }

    // Check the sender ID
    if msg.sender > num_nodes {
        return Err(AbdError::InvalidSenderID);
    }

    // Convert all the header pointers to mutable references
    let eth = unsafe { eth_hdr.as_mut().ok_or(AbdError::HeaderParsingError) }?;
    let ipv4 = unsafe { ipv4_hdr.as_mut().ok_or(AbdError::HeaderParsingError) }?;
    let udp = unsafe { udp_hdr.as_mut().ok_or(AbdError::HeaderParsingError) }?;

    Ok(Some(AbdContext {
        eth,
        ip: ipv4,
        udp,
        msg,
    }))
}

/// Recomputes the UDP checksum for a modification to the ABD message.
///
/// The existing checksum should be passed in as `udp_csum` and it will be updated with the new checksum.
/// After all modifications, the checksum should be written back to the UDP header by the caller.
///
/// If the checksum passed in is zero, this function is a no-op.
/// If the checksum cannot be recomputed, it will be set to zero.
///
/// The offset where `field` is located must have at least 4 bytes of space after it.
/// The size of `T` must be a multiple of 4 bytes, and be less than 256 bytes.
#[inline(always)]
pub fn recompute_udp_csum_for_abd_update<T>(
    field: &Seal<'_, T>,
    new_val: &T,
    udp_csum: &mut u16,
) -> Result<(), AbdError> {
    if *udp_csum == 0 {
        return Ok(());
    }

    let size = u32::try_from(size_of::<T>()).map_err(|_| AbdError::CastFailed)?;

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
        // disable the checksum
        *udp_csum = 0;
        return Ok(());
    }

    #[expect(clippy::cast_sign_loss)]
    let new_csum = csum_fold_helper(ret as u64);
    *udp_csum = new_csum;

    Ok(())
}

/// Converts a checksum into u16
#[inline(always)]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    #[expect(clippy::cast_possible_truncation)]
    return !(csum as u16);
}

/// Copies the contents of `src` into a sealed destination `Seal<'_, T>`.
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
#[must_use]
#[inline(always)]
pub fn read_global<T>(var: &'static T) -> T {
    unsafe { core::ptr::read_volatile(&raw const *var) }
}

/// Get a mutable reference to a value from an `Array` map at the given `index`.
#[allow(clippy::mut_from_ref)]
#[inline(always)]
pub fn map_get_mut<V>(map: &Array<V>, index: u32) -> Result<&mut V, AbdError> {
    let value_ptr = map.get_ptr_mut(index).ok_or(AbdError::MapLookupError)?;
    unsafe { Ok(&mut *value_ptr) }
}

/// Reads a value out of an `Array` map at the given `index`, returning a default value if it is not found.
#[inline(always)]
pub fn map_get_or_default<V>(map: &Array<V>, index: u32) -> V
where
    V: Copy + Default,
{
    map.get(index).map_or_else(V::default, |v| *v)
}

/// Inserts a value into an `Array` map at the given `key`.
#[inline(always)]
pub fn map_update<V>(map: &Array<V>, index: u32, new_value: &V) -> Result<(), AbdError> {
    let value_ptr_mut = map.get_ptr_mut(index).ok_or(AbdError::MapLookupError)?;
    unsafe {
        copy_nonoverlapping(
            core::ptr::from_ref::<V>(new_value).cast::<u8>(),
            value_ptr_mut.cast::<u8>(),
            size_of::<V>(),
        );
    }
    Ok(())
}

/// Inserts a `Locked` value into an `Array` map at the given `key`
#[inline(always)]
pub fn map_update_locked<T>(arr: &Array<Locked<T>>, key: u32, new_value: &T) -> Result<(), AbdError>
where
    T: Copy,
{
    let entry = map_get_mut(arr, key)?;
    try_spin_lock_acquire(&mut entry.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
    entry.val = *new_value;
    spin_lock_release(&mut entry.lock);
    Ok(())
}

/// Increments a `Locked<T>` value in an `Array` map at the given `key`, returning the new value.
#[inline(always)]
pub fn map_increment_locked<T>(arr: &Array<Locked<T>>, key: u32) -> Result<T, AbdError>
where
    T: Copy + core::ops::Add<Output = T> + From<u8> + Default,
{
    let entry = map_get_mut(arr, key)?;
    try_spin_lock_acquire(&mut entry.lock).map_err(|_| AbdError::LockRetryLimitHit)?;
    let incremented_value = entry.val + T::from(1);
    entry.val = incremented_value;
    spin_lock_release(&mut entry.lock);
    Ok(incremented_value)
}
