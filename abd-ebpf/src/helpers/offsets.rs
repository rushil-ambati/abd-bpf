use core::mem::offset_of;

use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

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
