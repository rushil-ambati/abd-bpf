use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

/// Swap UDP src/dst ports
#[inline]
pub fn swap_udp_ports(udph: &mut UdpHdr) {
    let tmp = udph.source;
    udph.source = udph.dest;
    udph.dest = tmp;
}

/// Swap IPv4 src/dst addresses
#[inline]
pub fn swap_ipv4_addrs(iph: &mut Ipv4Hdr) {
    let tmp = iph.src_addr;
    iph.src_addr = iph.dst_addr;
    iph.dst_addr = tmp;
}

/// Swap Ethernet src/dst MAC
#[inline]
pub fn swap_eth_addrs(eth: &mut EthHdr) {
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&eth.src_addr);
    eth.src_addr.copy_from_slice(&eth.dst_addr);
    eth.dst_addr.copy_from_slice(&tmp);
}

/// Ovewrwrite the source MAC address in the packet via the raw header
#[inline]
pub fn set_eth_src_addr(eth: &mut EthHdr, src_mac: &[u8; 6]) {
    eth.src_addr.copy_from_slice(src_mac);
}

/// Ovewrwrite the destination MAC address in the packet via the raw header
#[inline]
pub fn set_eth_dst_addr(eth: &mut EthHdr, dst_mac: &[u8; 6]) {
    eth.dst_addr.copy_from_slice(dst_mac);
}
