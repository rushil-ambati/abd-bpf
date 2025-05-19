use core::mem::size_of;

use abd_common::{ArchivedAbdMsg, ABD_MAGIC};
use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS},
        TC_ACT_PIPE, TC_ACT_SHOT,
    },
    helpers::r#gen::bpf_csum_diff,
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

use super::offsets::{UDPH_OFF, UDP_PAYLOAD_OFF};

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
    let len = core::mem::size_of::<T>();

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
    pub msg: Seal<'a, ArchivedAbdMsg>,
}

/// Parse an ABD packet from a context
///
/// # Errors
///
/// If the packet is not an ABD packet, returns `C::IGNORE` (`XDP_PASS` or `TC_ACT_PIPE`).
/// If any other error occurs during packet parsing, returns `C::ABORT` (`XDP_ABORTED` or `TC_ACT_SHOT`).
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

    // Bounds-check that the payload is exactly ArchivedAbdMsg
    let msg_len = size_of::<ArchivedAbdMsg>();
    let start = ctx.data();
    let end = ctx.data_end();
    if start + UDP_PAYLOAD_OFF + msg_len > end {
        return Err(C::IGNORE);
    }

    // Get a &mut [u8] pointing to the message bytes
    let msg_ptr = (start + UDP_PAYLOAD_OFF) as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(msg_ptr, msg_len) };
    let msg = unsafe { access_unchecked_mut::<ArchivedAbdMsg>(slice) };

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

/// Calculate the new UDP checksum after changing a field in the packet
///
/// # Errors
///
/// For XDP, returns `XDP_ABORTED` on error. For other program types, returns `TC_ACT_SHOT` on error.
#[inline]
pub fn calculate_udp_csum_update<C: PacketBuf, T: PartialEq + Copy>(
    ctx: &C,
    field: &Seal<'_, T>,
    new_val: T,
    udp_csum: &mut u16,
) -> BpfResult<()> {
    if **field == new_val {
        return Ok(()); // no change
    }

    let from_size = u32::try_from(size_of::<T>()).map_err(|_| {
        error!(
            ctx,
            "failed to convert size of {} ({}) to u32",
            core::any::type_name::<T>(),
            size_of::<T>()
        );
        C::ABORT
    })?;
    let to_size = u32::try_from(size_of::<T>()).map_err(|_| {
        error!(
            ctx,
            "failed to convert size of {} ({}) to u32",
            core::any::type_name::<T>(),
            size_of::<T>()
        );
        C::ABORT
    })?;

    let ret = unsafe {
        bpf_csum_diff(
            &raw const **field as *mut u32,
            from_size,
            &raw const new_val as *mut u32,
            to_size,
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

    #[allow(clippy::cast_sign_loss)]
    let new_csum = csum_fold_helper(ret as u64);
    *udp_csum = new_csum;
    Ok(())
}

// Converts a checksum into u16
#[inline]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    #[allow(clippy::cast_possible_truncation)]
    !(csum as u16)
}
