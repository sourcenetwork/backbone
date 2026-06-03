use std::path::PathBuf;
use std::time::Duration;

use eyre::{Result, WrapErr};
use reqwest::Client;

use crate::client::DefraClient;
use crate::divergences::NodeKind;
use crate::node::{DefraNode, RunningNode, RustNode};
use crate::observe::patterns::{self, NamedPattern};
use crate::observe::LogTracker;
use sourcehub_harness::SourceHubNode;

use super::health::health_check;

/// A cluster of running DefraDB nodes.
///
/// Field order matters: `nodes` and `source_hub` are dropped before `run_dir`,
/// ensuring processes are killed before their data directories are removed.
pub struct TestCluster {
    pub nodes: Vec<RunningNode>,
    source_hub: Option<SourceHubNode>,
    #[allow(dead_code)]
    run_dir: test_infra::TestRunDir,
    startup_identity: Option<String>,
    node_identities: Vec<Option<String>>,
}

impl TestCluster {
    pub(crate) fn new(
        nodes: Vec<RunningNode>,
        run_dir: test_infra::TestRunDir,
        startup_identity: Option<String>,
        node_identities: Vec<Option<String>>,
        source_hub: Option<SourceHubNode>,
    ) -> Self {
        Self {
            nodes,
            source_hub,
            run_dir,
            startup_identity,
            node_identities,
        }
    }

    /// Return the private key hex used to start nodes (if any).
    ///
    /// In NAC mode, Go grants automatic admin access to the startup identity.
    /// Tests must use this identity for admin operations.
    pub fn startup_identity(&self) -> Option<&str> {
        self.startup_identity.as_deref()
    }

    /// Return the identity for a specific node (if set via per-node override).
    pub fn node_identity(&self, index: usize) -> Option<&str> {
        self.node_identities.get(index).and_then(|id| id.as_deref())
    }

    pub fn builder() -> super::builder::TestClusterBuilder {
        super::builder::TestClusterBuilder::new()
    }

    /// Return a CLI-based client for the node at `index`.
    pub fn client(&self, index: usize) -> DefraClient {
        let node = &self.nodes[index];
        DefraClient::new(&node.binary_path, &node.http_addr, node.kind)
    }

    pub fn api_url(&self, index: usize) -> &str {
        &self.nodes[index].api_url
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn source_hub(&self) -> Option<&SourceHubNode> {
        self.source_hub.as_ref()
    }

    /// Stop the SourceHub process. Drops the node, sending SIGTERM.
    pub fn stop_source_hub(&mut self) -> Result<()> {
        if self.source_hub.take().is_some() {
            Ok(())
        } else {
            eyre::bail!("no SourceHub node to stop")
        }
    }

    /// Wait for a named log pattern on the node at `index`.
    pub async fn wait_for_log(
        &self,
        index: usize,
        pattern: &str,
        timeout: Duration,
    ) -> Result<String> {
        self.nodes[index]
            .log_tracker
            .wait_for_pattern(pattern, timeout)
            .await
    }

    /// Restart the node at `index`, reusing its rootdir and ports.
    ///
    /// Drops the old process (sending SIGTERM), waits briefly, then respawns
    /// the same binary with the same config on the same data directory.
    pub async fn restart_node(&mut self, index: usize, timeout: Duration) -> Result<()> {
        let old = &self.nodes[index];
        let config = old.config.clone();
        let kind = old.kind;
        let name = old.name.clone();
        let api_url = old.api_url.clone();
        let binary_path = old.binary_path.clone();

        // Drop old node to kill the process
        let old_node = std::mem::replace(
            &mut self.nodes[index],
            // Placeholder — will be overwritten below
            RunningNode {
                name: String::new(),
                api_url: String::new(),
                http_addr: String::new(),
                binary_path: PathBuf::new(),
                process: test_infra::ManagedProcess::empty(),
                log_tracker: LogTracker::empty(),
                rootdir: PathBuf::new(),
                config: config.clone(),
                kind,
            },
        );
        drop(old_node);

        tokio::time::sleep(Duration::from_millis(200)).await;

        let is_iroh = config.p2p_transport.as_deref() == Some("iroh");
        let named_patterns: Vec<NamedPattern> = if is_iroh {
            patterns::iroh_patterns()
        } else {
            patterns::node_patterns()
        };

        let node: Box<dyn DefraNode> = match kind {
            // Respawn from the node's configured binary (e.g. a release artifact
            // or a downloaded version), not the default debug workspace path —
            // otherwise restart breaks whenever the node was not built via
            // `from_workspace()`.
            NodeKind::Rust => Box::new(RustNode::from_binary(binary_path.clone())),
            NodeKind::Go => Box::new(crate::node::GoNode::from_path()),
        };

        let (program, args_owned, envs_owned) = node.command_parts(&config);
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
        let envs: Vec<(&str, &str)> = envs_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let stdout_path = config.log_dir.join("stdout.log");
        let log_tracker =
            LogTracker::start(stdout_path, patterns::DEFRA_READY_PATTERN, named_patterns);

        let process =
            test_infra::ManagedProcess::spawn(&name, &program, &args, &envs, &config.log_dir)?;

        log_tracker
            .wait_for_ready(timeout)
            .await
            .wrap_err_with(|| format!("{}: did not become ready after restart", name))?;

        let client = Client::new();
        health_check(&client, &api_url, timeout)
            .await
            .wrap_err_with(|| format!("{}: health check failed after restart", name))?;

        self.nodes[index] = RunningNode {
            name,
            api_url,
            http_addr: config.http_addr.clone(),
            binary_path,
            process,
            log_tracker,
            rootdir: config.rootdir.clone(),
            config,
            kind,
        };

        Ok(())
    }
}
