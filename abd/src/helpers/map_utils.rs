use abd_common::{NodeInfo, ABD_NODE_IFACE_PREFIX, ABD_WRITER_ID, ABD_WRITER_IFACE_NAME};
use anyhow::Result;
use aya::maps::{Array, Map};
use network_interface::NetworkInterface;

use super::iface_utils::get_iface_info;

pub fn populate_nodes_map(
    map: &mut Map,
    interfaces: &[NetworkInterface],
    num_nodes: u32,
) -> Result<(), anyhow::Error> {
    let mut array_map: Array<_, NodeInfo> = Array::try_from(map)?;

    let info = get_iface_info(interfaces, ABD_WRITER_IFACE_NAME)?;
    array_map.set(ABD_WRITER_ID, info, 0)?;

    for i in 1..=num_nodes {
        let iface_name = format!("{}{}", ABD_NODE_IFACE_PREFIX, i);
        let info = get_iface_info(interfaces, &iface_name)?;
        array_map.set(i, info, 0)?;
    }

    Ok(())
}
