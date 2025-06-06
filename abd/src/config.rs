//! Configuration file support for ABD clusters
//!
//! This module provides configuration structures and parsing for ABD node
//! information, replacing the network namespace discovery approach.

use std::{fs, net::Ipv4Addr, path::Path};

use abd_common::map_types::NodeInfo;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Configuration for a single ABD node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node ID (1-based)
    pub node_id: u32,
    /// IPv4 address of the node
    pub ipv4: Ipv4Addr,
    /// MAC address of the node (as hex string like "00:11:22:33:44:55")
    pub mac: String,
    /// Network interface index
    pub ifindex: u32,
    /// Network interface name
    pub interface: String,
}

/// Configuration for the entire ABD cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Total number of nodes in the cluster
    pub num_nodes: u32,
    /// List of all node configurations
    pub nodes: Vec<NodeConfig>,
    /// Cluster mode: "ebpf" or "userspace"
    #[serde(default)]
    pub mode: Option<String>,
}

impl ClusterConfig {
    /// Load cluster configuration from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Save cluster configuration to a JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize configuration")?;

        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;

        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.nodes.len() != self.num_nodes as usize {
            anyhow::bail!(
                "Configuration mismatch: num_nodes={} but found {} node entries",
                self.num_nodes,
                self.nodes.len()
            );
        }

        // Check for duplicate node IDs
        let mut seen_node_ids = std::collections::HashSet::new();
        for node in &self.nodes {
            if node.node_id == 0 || node.node_id > self.num_nodes {
                anyhow::bail!(
                    "Invalid node_id {}: must be between 1 and {}",
                    node.node_id,
                    self.num_nodes
                );
            }

            if !seen_node_ids.insert(node.node_id) {
                anyhow::bail!("Duplicate node_id: {}", node.node_id);
            }
        }

        // Check for duplicate IP addresses
        let mut seen_ips = std::collections::HashSet::new();
        for node in &self.nodes {
            if !seen_ips.insert(node.ipv4) {
                anyhow::bail!("Duplicate IP address: {}", node.ipv4);
            }
        }

        Ok(())
    }

    /// Get configuration for a specific node ID
    #[must_use]
    pub fn get_node(&self, node_id: u32) -> Option<&NodeConfig> {
        self.nodes.iter().find(|node| node.node_id == node_id)
    }
}

impl NodeConfig {
    /// Convert this node configuration to a `NodeInfo` struct
    pub fn to_node_info(&self) -> Result<NodeInfo> {
        let mac = parse_mac(&self.mac)?;
        Ok(NodeInfo::new(self.ifindex, self.ipv4, mac))
    }
}

/// Parse a MAC address string into a 6-byte array
pub fn parse_mac(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|h| u8::from_str_radix(h, 16))
        .collect::<Result<_, _>>()
        .with_context(|| format!("Invalid MAC address format: {mac_str}"))?;

    if bytes.len() == 6 {
        Ok([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
    } else {
        anyhow::bail!("Invalid MAC address format: {mac_str}");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        assert!(parse_mac("invalid").is_err());
        assert!(parse_mac("00:11:22:33:44").is_err()); // too short
        assert!(parse_mac("00:11:22:33:44:55:66").is_err()); // too long
    }

    #[test]
    fn test_cluster_config_validation() {
        let config = ClusterConfig {
            num_nodes: 2,
            nodes: vec![
                NodeConfig {
                    node_id: 1,
                    ipv4: Ipv4Addr::new(10, 11, 1, 2),
                    mac: "00:11:22:33:44:55".to_string(),
                    ifindex: 1,
                    interface: "node1".to_string(),
                },
                NodeConfig {
                    node_id: 2,
                    ipv4: Ipv4Addr::new(10, 11, 2, 2),
                    mac: "00:11:22:33:44:56".to_string(),
                    ifindex: 2,
                    interface: "node2".to_string(),
                },
            ],
            mode: Some("ebpf".to_string()),
        };

        assert!(config.validate().is_ok());

        // Test duplicate node ID
        let mut bad_config = config.clone();
        bad_config.nodes[1].node_id = 1;
        assert!(bad_config.validate().is_err());

        // Test duplicate IP
        let mut bad_config = config.clone();
        bad_config.nodes[1].ipv4 = config.nodes[0].ipv4;
        assert!(bad_config.validate().is_err());

        // Test node count mismatch
        let mut bad_config = config;
        bad_config.num_nodes = 3;
        assert!(bad_config.validate().is_err());
    }
}
