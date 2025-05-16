use abd_common::AbdActorInfo;
use abd_common::{ABD_NODE_IFACE_PREFIX, ABD_WRITER_IFACE_NAME};
use anyhow::Result;
use aya::maps::{Array, Map};
use network_interface::NetworkInterface;

use super::iface_utils::get_iface_info;

pub fn populate_nodes_map(
    map: &mut Map,
    interfaces: &Vec<NetworkInterface>,
    num_nodes: u32,
) -> Result<(), anyhow::Error> {
    let mut array_map: Array<_, AbdActorInfo> = Array::try_from(map)?;
    for i in 0..num_nodes {
        let iface_name = format!("{}{}", ABD_NODE_IFACE_PREFIX, i + 1);
        let info = get_iface_info(interfaces, &iface_name)?;
        array_map.set(i, &info, 0)?;
    }
    Ok(())
}

pub fn populate_writer_info_map(
    map: &mut Map,
    interfaces: &Vec<NetworkInterface>,
) -> Result<(), anyhow::Error> {
    let mut array_map: Array<_, AbdActorInfo> = Array::try_from(map)?;
    let info = get_iface_info(interfaces, ABD_WRITER_IFACE_NAME)?;
    array_map.set(0, &info, 0)?;
    Ok(())
}
