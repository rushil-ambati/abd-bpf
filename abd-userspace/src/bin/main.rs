#!/usr/bin/env cargo run --bin abd-userspace --
//! ABD Userspace Implementation CLI
//!
//! This binary provides the command-line interface for running ABD protocol nodes.
//! It supports both single-writer and multi-writer modes, with proper logging
//! and configuration management.

use std::process;

use abd_userspace::{AbdNode, Config};
use anyhow::Result;
use clap::Parser;
use env_logger::Env;

/// Command-line arguments for ABD node
#[derive(Parser, Debug)]
#[command(
    name = "abd-userspace",
    about = "Userspace implementation of ABD consensus protocol",
    version = env!("CARGO_PKG_VERSION"),
    author = "ABD Project"
)]
struct Args {
    /// Node ID (1-based, must be in range `1..=num_nodes` from config)
    #[arg(
        long,
        value_name = "ID",
        help = "Unique identifier for this node (1-based indexing)"
    )]
    node_id: u32,

    /// Path to cluster configuration file
    #[arg(
        long,
        value_name = "PATH",
        help = "JSON file containing cluster node configuration"
    )]
    config: String,

    /// Logging level
    #[arg(
        long,
        value_name = "LEVEL",
        default_value = "info",
        help = "Set logging level (error, warn, info, debug, trace)"
    )]
    log_level: String,

    /// Enable verbose output
    #[arg(
        short,
        long,
        help = "Enable verbose logging (equivalent to --log-level=debug)"
    )]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        "debug"
    } else {
        &args.log_level
    };

    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    // Run the ABD node
    if let Err(e) = run_node(args).await {
        log::error!("ABD node failed: {e}");
        process::exit(1);
    }
}

async fn run_node(args: Args) -> Result<()> {
    // Load configuration
    let config = Config::from_file(&args.config)?;

    log::info!(
        "Loaded cluster configuration with {} nodes",
        config.num_nodes()
    );

    // Create and run the ABD node
    let node = AbdNode::new(args.node_id, config)?;

    log::info!(
        "Starting ABD node {} in {} mode",
        args.node_id,
        if cfg!(feature = "multi-writer") {
            "multi-writer"
        } else {
            "single-writer"
        }
    );

    node.run().await?;

    Ok(())
}
