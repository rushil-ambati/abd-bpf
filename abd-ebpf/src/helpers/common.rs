use core::mem::size_of;

use abd_common::{ArchivedAbdMsg, ABD_MAGIC};
use aya_ebpf::{
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

/// Anything with data & data_end pointers
pub trait PacketBuf: EbpfContext {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}
impl PacketBuf for XdpContext {
    fn data(&self) -> usize {
        XdpContext::data(self)
    }

    fn data_end(&self) -> usize {
        XdpContext::data_end(self)
    }
}
impl PacketBuf for TcContext {
    fn data(&self) -> usize {
        TcContext::data(self)
    }

    fn data_end(&self) -> usize {
        TcContext::data_end(self)
    }
}

/// ABD packet headers and message
pub struct AbdPacket<'a> {
    pub eth: &'a mut EthHdr,
    pub iph: &'a mut Ipv4Hdr,
    pub udph: &'a mut UdpHdr,
    pub msg: Seal<'a, ArchivedAbdMsg>,
}

/// Parse an ABD packet from a context
pub fn parse_abd_packet<C: PacketBuf>(ctx: &C, port: u16, num_nodes: u32) -> Result<AbdPacket, ()> {
    // Ethernet → must be IPv4
    let eth_ptr: *mut EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth_ptr).ether_type } != EtherType::Ipv4 {
        return Err(());
    }
    let eth = unsafe { &mut *eth_ptr };

    // IPv4 → must be UDP
    let iph_ptr: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    if unsafe { (*iph_ptr).proto } != IpProto::Udp {
        return Err(());
    }
    let iph = unsafe { &mut *iph_ptr };

    // UDP → must be on our port
    let udph_ptr: *mut UdpHdr = ptr_at(ctx, UDPH_OFF)?;
    let dest_port = u16::from_be(unsafe { (*udph_ptr).dest });
    if dest_port != port {
        return Err(());
    }
    let udph = unsafe { &mut *udph_ptr };

    // Bounds-check that the payload is exactly ArchivedAbdMsg
    let msg_len = size_of::<ArchivedAbdMsg>();
    let start = ctx.data();
    let end = ctx.data_end();
    if start + UDP_PAYLOAD_OFF + msg_len > end {
        return Err(());
    }

    // Get a &mut [u8] pointing to the message bytes
    let msg_ptr = (start + UDP_PAYLOAD_OFF) as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(msg_ptr, msg_len) };
    let msg = unsafe { access_unchecked_mut::<ArchivedAbdMsg>(slice) };

    // Check the magic number
    let magic = (*msg)._magic;
    if magic != ABD_MAGIC {
        return Err(());
    }

    // Check the sender ID
    let sender = (*msg).sender;
    if sender > num_nodes {
        error!(ctx, "Invalid sender ID: {}", sender.to_native());
        return Err(());
    }

    Ok(AbdPacket {
        eth,
        iph,
        udph,
        msg,
    })
}

/// Calculate the new UDP checksum after changing a field in the packet
#[inline(always)]
pub fn calculate_udp_csum_update<C: PacketBuf, T: PartialEq + Copy>(
    ctx: &C,
    field: &Seal<'_, T>,
    new_val: T,
    udp_csum: &mut u16,
) -> Result<(), ()> {
    if **field == new_val {
        return Ok(()); // no change
    }

    let ret = unsafe {
        bpf_csum_diff(
            &**field as *const _ as *mut u32,
            size_of::<T>() as u32,
            &new_val as *const _ as *mut u32,
            size_of::<T>() as u32,
            !(*udp_csum as u32),
        )
    };
    if ret < 0 {
        error!(ctx, "bpf_csum_diff failed: {}", ret);
        return Err(());
    }

    let new_csum = csum_fold_helper(ret as u64);
    *udp_csum = new_csum;
    Ok(())
}

/// Bounds‐checked pointer into packet data
#[inline]
pub fn ptr_at<C: PacketBuf, T>(ctx: &C, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

// Converts a checksum into u16
#[inline(always)]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}
