//! Optimized ABD userspace replica

use std::{net::SocketAddr, sync::Arc};

use abd::ClusterConfig;
use abd_common::constants::ABD_UDP_PORT;
use abd_userspace::{
    network,
    protocol::{Context, GlobalState},
};
use anyhow::{bail, Result};
use clap::Parser;
use env_logger::Env;
use log::info;
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    node_id: u32,
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let Cli { node_id, config } = Cli::parse();

    let cfg = ClusterConfig::load_from_file(&config)?;
    if !(1..=cfg.num_nodes).contains(&node_id) {
        bail!("--node-id must be in 1..={}", cfg.num_nodes);
    }

    let peers: Vec<_> = cfg
        .nodes
        .iter()
        .map(|n| SocketAddr::from((n.ipv4, ABD_UDP_PORT)))
        .collect();
    let bind = peers[(node_id - 1) as usize];

    let mut workers = JoinSet::new();
    let gstate = Arc::<GlobalState>::default();
    let peers = Arc::new(peers);

    for core in 0..num_cpus::get() {
        let ctx = Context::new(node_id, cfg.num_nodes, peers.clone(), bind, gstate.clone())?;
        workers.spawn(async move {
            if let Err(e) = network::run_worker(ctx).await {
                log::warn!("worker #{core} terminated: {e}");
            }
        });
    }

    info!("ABD node {node_id}/{} listening on {bind}", cfg.num_nodes);
    while workers.join_next().await.is_some() {}
    Ok(())
}
