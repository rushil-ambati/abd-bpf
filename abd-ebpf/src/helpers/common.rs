use core::mem::{self, size_of};

use abd_common::{ArchivedAbdMsg, ABD_MAGIC, ABD_UDP_PORT};
use aya_ebpf::programs::{TcContext, XdpContext};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rkyv::{access_unchecked_mut, seal::Seal};

/// Anything with data & data_end pointers
pub trait PacketBuf {
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
pub fn parse_abd_packet<C: PacketBuf>(ctx: &C) -> Result<AbdPacket, ()> {
    // Ethernet → must be IPv4
    let eth_ptr: *mut EthHdr = ptr_at_mut(ctx, 0)?;
    if unsafe { (*eth_ptr).ether_type } != EtherType::Ipv4 {
        return Err(());
    }
    let eth = unsafe { &mut *eth_ptr };

    // IPv4 → must be UDP
    let iph_ptr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;
    if unsafe { (*iph_ptr).proto } != IpProto::Udp {
        return Err(());
    }
    let iph = unsafe { &mut *iph_ptr };

    // UDP → must be on our port
    let udph_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let udph_ptr: *mut UdpHdr = ptr_at_mut(ctx, udph_offset)?;
    let dest_port = u16::from_be(unsafe { (*udph_ptr).dest });
    if dest_port != ABD_UDP_PORT {
        return Err(());
    }
    let udph = unsafe { &mut *udph_ptr };

    // Bounds-check that the payload is exactly ArchivedAbdMsg
    let payload_offset = udph_offset + UdpHdr::LEN;
    let msg_len = size_of::<ArchivedAbdMsg>();
    let start = ctx.data();
    let end = ctx.data_end();
    if start + payload_offset + msg_len > end {
        return Err(());
    }

    // Get a &mut [u8] pointing to the message bytes
    let msg_ptr = (start + payload_offset) as *mut u8;
    let slice = unsafe { core::slice::from_raw_parts_mut(msg_ptr, msg_len) };
    let msg = unsafe { access_unchecked_mut::<ArchivedAbdMsg>(slice) };

    // Check the magic number
    if (*msg)._magic != ABD_MAGIC {
        return Err(());
    }

    Ok(AbdPacket {
        eth,
        iph,
        udph,
        msg,
    })
}

/// Bounds‐checked pointer into packet data
#[inline]
pub fn ptr_at<C: PacketBuf, T>(ctx: &C, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Bounds‐checked mutable pointer into packet data
#[inline]
pub fn ptr_at_mut<C: PacketBuf, T>(ctx: &C, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}
