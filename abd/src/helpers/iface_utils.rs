use std::process::Command;

use abd_common::NodeInfo;
use anyhow::Result;
use network_interface::NetworkInterface;

pub(crate) fn get_iface_info(
    ifaces: &[NetworkInterface],
    netns_name: &str,
) -> Result<NodeInfo, anyhow::Error> {
    let iface = ifaces
        .iter()
        .find(|iface| iface.name == netns_name)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", netns_name))?;

    let idx = iface.index;
    let ipv4_addr = iface
        .addr
        .iter()
        .find_map(|addr| match addr {
            network_interface::Addr::V4(v4) => Some(v4.ip),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", netns_name))?;

    let output = Command::new("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns_name)
        .arg("cat")
        .arg("/sys/class/net/veth0/address")
        .output()
        .expect("Failed to execute ip netns exec");

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to get MAC for {}: {}",
            netns_name,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mac = parse_mac(String::from_utf8_lossy(&output.stdout).trim())?;

    Ok(NodeInfo {
        ipv4: ipv4_addr,
        ifindex: idx,
        mac,
    })
}

fn parse_mac(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<_, _>>()?;
    if bytes.len() != 6 {
        Err(anyhow::anyhow!("Invalid MAC format: {}", mac_str))
    } else {
        Ok([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
    }
}
