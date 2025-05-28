use std::process::Command;

use abd_common::{constants::ABD_IFACE_NODE_PREFIX, map_types::NodeInfo};
use anyhow::Result;
use aya::maps::{Array, Map};
use network_interface::NetworkInterface;

#[allow(clippy::missing_errors_doc)]
pub fn get_iface_info(
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
            network_interface::Addr::V6(_) => None,
        })
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", netns_name))?;

    let output = Command::new("ip")
        .arg("netns")
        .arg("exec")
        .arg(netns_name)
        .arg("cat")
        .arg("/sys/class/net/veth0/address")
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute command: {}", e))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to get MAC for {}: {}",
            netns_name,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mac = parse_mac(String::from_utf8_lossy(&output.stdout).trim())?;

    Ok(NodeInfo::new(idx, ipv4_addr, mac))
}

fn parse_mac(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<_, _>>()?;
    if bytes.len() == 6 {
        Ok([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
    } else {
        Err(anyhow::anyhow!("Invalid MAC format: {}", mac_str))
    }
}

#[allow(clippy::missing_errors_doc)]
pub fn populate_nodes_map(
    map: &mut Map,
    interfaces: &[NetworkInterface],
    num_nodes: u32,
) -> Result<(), anyhow::Error> {
    let mut array_map: Array<_, NodeInfo> = Array::try_from(map)?;

    for i in 1..=num_nodes {
        let iface_name = format!("{ABD_IFACE_NODE_PREFIX}{i}");
        let info = get_iface_info(interfaces, &iface_name)?;
        array_map.set(i, info, 0)?;
    }

    Ok(())
}
