//! Running test cluster with managed node processes.

use std::{path::PathBuf, time::Duration};

use test_infra::ManagedProcess;

use super::health::{self, HealthCheckConfig};
use crate::observe::{ClusterState, LogTracker, RpcPoller};

/// A running test cluster with managed node processes.
///
/// Field order matters: `nodes` must be dropped before `_run_dir` so
/// processes are killed before their data directory is removed.
pub struct TestCluster {
    pub(crate) nodes: Vec<TestNode>,
    pub(crate) chain_id: u64,
    pub(crate) _run_dir: test_infra::TestRunDir,
}

impl std::fmt::Debug for TestCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCluster")
            .field("nodes", &self.nodes)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

/// A single managed node in the test cluster.
pub struct TestNode {
    /// JSON-RPC port.
    pub rpc_port: u16,
    /// P2P port.
    pub p2p_port: u16,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Log directory for this node.
    pub log_dir: PathBuf,
    /// Managed child process.
    pub process: ManagedProcess,
}

impl std::fmt::Debug for TestNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestNode")
            .field("rpc_port", &self.rpc_port)
            .field("p2p_port", &self.p2p_port)
            .field("data_dir", &self.data_dir)
            .finish()
    }
}

impl TestNode {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.rpc_port)
    }
}

impl TestCluster {
    pub fn builder() -> super::builder::TestClusterBuilder {
        super::builder::TestClusterBuilder::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn node(&self, index: usize) -> &TestNode {
        &self.nodes[index]
    }

    pub fn node_mut(&mut self, index: usize) -> &mut TestNode {
        &mut self.nodes[index]
    }

    pub fn rpc_urls(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.rpc_url()).collect()
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub async fn wait_ready(&self, timeout: Duration) -> eyre::Result<()> {
        let config = HealthCheckConfig {
            poll_interval: Duration::from_millis(50),
            timeout,
        };
        health::wait_all_healthy(&self.rpc_urls(), &config).await
    }

    pub fn kill_node(&mut self, index: usize) {
        self.nodes[index].process.kill();
    }

    pub fn restart_node(&mut self, index: usize) -> eyre::Result<()> {
        self.nodes[index].process.respawn()
    }

    /// Create an observability handle for this cluster.
    pub fn observe(&self, poll_interval: Duration) -> ClusterState {
        let trackers: Vec<LogTracker> = self
            .nodes
            .iter()
            .map(|n| LogTracker::new(n.log_dir.join("stdout.log")))
            .collect();

        let poller = RpcPoller::new(self.rpc_urls(), poll_interval);
        ClusterState::new(trackers, poller)
    }
}
