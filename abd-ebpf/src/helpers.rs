use core::mem::{self, offset_of, size_of};

use abd_common::{ArchivedAbdMsg, ABD_MAGIC, ABD_UDP_PORT};
use aya_ebpf::{
    cty::{c_long, c_void},
    helpers::r#gen::{bpf_l3_csum_replace, bpf_skb_store_bytes},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rkyv::{access_unchecked_mut, seal::Seal};

pub const UDP_CSUM_OFF: u32 = (EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check)) as u32;

pub const AF_INET: u8 = 2;
pub const ETH_DST_OFF: u32 = offset_of!(EthHdr, dst_addr) as u32;
pub const IP_DST_OFF: u32 = (EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr)) as u32;
pub const IP_CSUM_OFF: u32 = (EthHdr::LEN + offset_of!(Ipv4Hdr, check)) as u32;
pub const IS_PSEUDO: u64 = 0x10;

/// Anything with data/data_end pointers
pub trait PacketBuf {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}

impl PacketBuf for XdpContext {
    #[inline(always)]
    fn data(&self) -> usize {
        XdpContext::data(self)
    }
    #[inline(always)]
    fn data_end(&self) -> usize {
        XdpContext::data_end(self)
    }
}

impl PacketBuf for TcContext {
    #[inline(always)]
    fn data(&self) -> usize {
        TcContext::data(self)
    }
    #[inline(always)]
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
#[inline(always)]
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

// Gives us raw pointers to a specific offset in the packet
#[inline(always)]
pub fn ptr_at<C: PacketBuf, T>(ctx: &C, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Safe bounds‐checked pointer into packet data
#[inline(always)]
pub fn ptr_at_mut<C: PacketBuf, T>(ctx: &C, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

/// Swap Ethernet src/dst MAC
#[inline(always)]
pub fn swap_src_dst_mac(eth: &mut EthHdr) {
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&eth.src_addr);
    eth.src_addr.copy_from_slice(&eth.dst_addr);
    eth.dst_addr.copy_from_slice(&tmp);
}

/// Swap IPv4 src/dst addrs
#[inline(always)]
pub fn swap_ipv4_addresses(iph: &mut Ipv4Hdr) {
    let tmp = iph.src_addr;
    iph.src_addr = iph.dst_addr;
    iph.dst_addr = tmp;
}

/// Swap UDP src/dst ports
#[inline(always)]
pub fn swap_udp_ports(udph: &mut UdpHdr) {
    let tmp = udph.source;
    udph.source = udph.dest;
    udph.dest = tmp;
}

/// Overwrite the UDP source port in the packet
#[inline(always)]
pub fn set_src_udp_port(udph: &mut UdpHdr, src_port: u16) {
    udph.source = src_port.to_be();
}

/// Overwrite the UDP destination port in the packet
#[inline(always)]
pub fn set_dst_udp_port(udph: &mut UdpHdr, dst_port: u16) {
    udph.dest = dst_port.to_be();
}

/// Ovewrwrite the source MAC address in the packet
#[inline(always)]
pub fn set_eth_src_mac(eth: &mut EthHdr, src_mac: &[u8; 6]) {
    eth.src_addr.copy_from_slice(src_mac);
}

/// Ovewrwrite the destination MAC address in the packet
#[inline(always)]
pub fn set_eth_dst_mac(eth: &mut EthHdr, dst_mac: &[u8; 6]) {
    eth.dst_addr.copy_from_slice(dst_mac);
}

// inspired by https://github.com/torvalds/linux/blob/master/samples/bpf/tcbpf1_kern.c
// update dst_addr in the ip_hdr
// recalculate the checksums
pub fn set_ipv4_ip_dst(
    ctx: &TcContext,
    _l4_csum_offset: u32,
    old_ip: &u32,
    new_dip: u32,
) -> c_long {
    let mut ret: c_long;
    // unsafe {
    //     ret = bpf_l4_csum_replace(
    //         ctx.skb.skb,
    //         l4_csum_offset,
    //         *old_ip as u64,
    //         new_dip as u64,
    //         IS_PSEUDO | (mem::size_of_val(&new_dip) as u64),
    //     );
    // }
    // if ret != 0 {
    //     info!(
    //         ctx,
    //         "Failed to update the UDP checksum after modifying the destination IP"
    //     );
    //     return ret;
    // }

    unsafe {
        ret = bpf_l3_csum_replace(
            ctx.skb.skb,
            IP_CSUM_OFF,
            *old_ip as u64,
            new_dip as u64,
            mem::size_of_val(&new_dip) as u64,
        );
    }
    if ret != 0 {
        info!(
            ctx,
            "Failed to update the IP header checksum after modifying the destination IP"
        );
        return ret;
    }

    unsafe {
        ret = bpf_skb_store_bytes(
            ctx.skb.skb,
            IP_DST_OFF,
            &new_dip as *const u32 as *const c_void,
            mem::size_of_val(&new_dip) as u32,
            0,
        );
    }
    if ret != 0 {
        info!(
            ctx,
            "Failed to update the destination IP address in the packet header"
        );
        return ret;
    }

    ret
}
