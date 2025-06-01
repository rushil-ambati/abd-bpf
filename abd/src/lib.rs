use abd_common::map_types::NodeInfo;
use anyhow::Result;
use aya::maps::{Array, Map};

pub mod config;
pub use config::{ClusterConfig, NodeConfig};

/// Populate the nodes map from a cluster configuration file
#[allow(clippy::missing_errors_doc)]
pub fn populate_nodes_map_from_config(
    map: &mut Map,
    config: &ClusterConfig,
) -> Result<(), anyhow::Error> {
    let mut array_map: Array<_, NodeInfo> = Array::try_from(map)?;

    for node in &config.nodes {
        let info = node.to_node_info()?;
        array_map.set(node.node_id, info, 0)?;
    }

    Ok(())
}
