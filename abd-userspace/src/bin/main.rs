#!/usr/bin/env cargo run --bin abd-userspace --
//! ABD Userspace Implementation CLI
//!
//! This binary provides the command-line interface for running ABD protocol nodes.
//! It supports both single-writer and multi-writer modes, with proper logging
//! and configuration management.

use std::process;

use abd_userspace::{AbdNode, Config};
use anyhow::{Context, Result};
use clap::Parser;
use env_logger::Env;

/// Command-line arguments for ABD node
#[derive(Parser, Debug)]
#[command(
    name = "abd-userspace",
    about = "Userspace implementation of ABD protocol",
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

    // Initialize logging first so we can log errors properly
    let log_level = if args.verbose {
        "debug"
    } else {
        &args.log_level
    };

    if let Err(e) =
        env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).try_init()
    {
        eprintln!("Failed to initialize logger: {e}");
        process::exit(1);
    }

    // Run the ABD node with comprehensive error handling
    if let Err(e) = run_node(args).await {
        log::error!("ABD node failed: {e}");
        // Log the error chain for better debugging
        let mut source = e.source();
        while let Some(err) = source {
            log::error!("Caused by: {err}");
            source = err.source();
        }
        process::exit(1);
    }
}

async fn run_node(args: Args) -> Result<()> {
    // Validate node_id early
    if args.node_id == 0 {
        anyhow::bail!("Node ID must be greater than 0 (1-based indexing)");
    }

    // Load configuration with better error context
    let config = Config::from_file(&args.config)
        .with_context(|| format!("Failed to load configuration from '{}'", args.config))?;

    // Validate node_id against config
    if args.node_id > config.num_nodes() {
        anyhow::bail!(
            "Node ID {} exceeds maximum nodes {} in configuration",
            args.node_id,
            config.num_nodes()
        );
    }

    log::info!(
        "Loaded cluster configuration with {} nodes",
        config.num_nodes()
    );

    // Create ABD node with better error context
    let node = AbdNode::new(args.node_id, config)
        .with_context(|| format!("Failed to create ABD node with ID {}", args.node_id))?;

    log::info!(
        "Starting ABD node {} in {} mode",
        args.node_id,
        if cfg!(feature = "multi-writer") {
            "multi-writer"
        } else {
            "single-writer"
        }
    );

    // Set up graceful shutdown handling
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        log::info!("Received shutdown signal, stopping node...");
    };

    // Run node with graceful shutdown
    tokio::select! {
        result = node.run() => {
            result.with_context(|| format!("ABD node {} execution failed", args.node_id))
        }
        () = shutdown_signal => {
            log::info!("Node {} shutdown completed", args.node_id);
            Ok(())
        }
    }
}
