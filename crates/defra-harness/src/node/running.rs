use std::path::PathBuf;
use std::time::Duration;

use eyre::{Result, WrapErr};

use super::{DefraNode, NodeConfig};
use crate::divergences::NodeKind;
use crate::observe::patterns::{self, NamedPattern};
use crate::observe::LogTracker;

/// A running DefraDB node with its process handle and log tracker.
pub struct RunningNode {
    pub name: String,
    pub api_url: String,
    pub http_addr: String,
    pub binary_path: PathBuf,
    pub process: test_infra::ManagedProcess,
    pub log_tracker: LogTracker,
    pub rootdir: PathBuf,
    pub(crate) config: NodeConfig,
    pub(crate) kind: NodeKind,
}

/// Start a DefraDB node from config and wait for it to become ready.
pub async fn start_node(
    node: &dyn DefraNode,
    config: NodeConfig,
    ready_timeout: Duration,
) -> Result<RunningNode> {
    std::fs::create_dir_all(&config.rootdir)?;
    std::fs::create_dir_all(&config.log_dir)?;

    // Seed a cluster-shared searchable-encryption key into the keyring before
    // start so the node's getOrCreate (Go + Rust) finds the same key.
    super::seed_searchable_encryption_key(node.binary_path(), node.kind(), &config)
        .wrap_err_with(|| format!("{}: failed to seed searchable-encryption key", config.name))?;

    let api_url = format!("http://{}", config.http_addr);
    let named_patterns: Vec<NamedPattern> = if config.p2p_transport.as_deref() == Some("iroh") {
        patterns::iroh_patterns()
    } else {
        patterns::node_patterns()
    };

    let (program, args_owned, envs_owned) = node.command_parts(&config);
    let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let envs: Vec<(&str, &str)> = envs_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let stdout_path = config.log_dir.join("stdout.log");
    let log_tracker = LogTracker::start(stdout_path, patterns::DEFRA_READY_PATTERN, named_patterns);

    let process =
        test_infra::ManagedProcess::spawn(&config.name, &program, &args, &envs, &config.log_dir)?;

    log_tracker
        .wait_for_ready(ready_timeout)
        .await
        .wrap_err_with(|| format!("{}: did not become ready", config.name))?;

    Ok(RunningNode {
        name: config.name.clone(),
        api_url,
        http_addr: config.http_addr.clone(),
        binary_path: node.binary_path().to_path_buf(),
        process,
        log_tracker,
        rootdir: config.rootdir.clone(),
        config,
        kind: node.kind(),
    })
}
