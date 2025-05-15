use core::mem::offset_of;

use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

pub const ETH_SRC_OFF: usize = offset_of!(EthHdr, src_addr);
pub const ETH_DST_OFF: usize = offset_of!(EthHdr, dst_addr);

pub const IP_OFF: usize = EthHdr::LEN;
pub const IP_SRC_OFF: usize = IP_OFF + offset_of!(Ipv4Hdr, src_addr);
pub const IP_DST_OFF: usize = IP_OFF + offset_of!(Ipv4Hdr, dst_addr);
pub const IP_CSUM_OFF: usize = IP_OFF + offset_of!(Ipv4Hdr, check);

pub const UDP_OFF: usize = IP_OFF + Ipv4Hdr::LEN;
pub const UDP_SRC_OFF: usize = UDP_OFF + offset_of!(UdpHdr, source);
pub const UDP_DST_OFF: usize = UDP_OFF + offset_of!(UdpHdr, dest);
pub const UDP_CSUM_OFF: usize = UDP_OFF + offset_of!(UdpHdr, check);
