//! Unified cluster state combining log tracking and RPC polling.

use std::time::Duration;

use super::{
    events::LogEvent, log_tracker::LogTracker, rpc_poller::RpcPoller, rpc_snapshot::NodeSnapshot,
};

/// Unified view of a running cluster's state.
#[derive(Debug)]
pub struct ClusterState {
    log_trackers: Vec<LogTracker>,
    rpc_poller: RpcPoller,
}

impl ClusterState {
    /// Create a new cluster state from log trackers and an RPC poller.
    pub const fn new(log_trackers: Vec<LogTracker>, rpc_poller: RpcPoller) -> Self {
        Self {
            log_trackers,
            rpc_poller,
        }
    }

    /// Get the snapshot for a specific node.
    pub fn node(&self, index: usize) -> NodeSnapshot {
        self.rpc_poller.snapshot(index)
    }

    /// Get snapshots for all nodes.
    pub fn all_nodes(&self) -> Vec<NodeSnapshot> {
        self.rpc_poller.all_snapshots()
    }

    /// Get the log tracker for a specific node.
    pub fn node_logs(&self, index: usize) -> &LogTracker {
        &self.log_trackers[index]
    }

    /// Restart the log tracker for a specific node after a process respawn.
    pub fn restart_node_logs(&mut self, index: usize) {
        self.log_trackers[index].restart();
    }

    /// Get all error events across all nodes.
    pub fn all_errors(&self) -> Vec<(usize, LogEvent)> {
        let mut all = Vec::new();
        for (i, tracker) in self.log_trackers.iter().enumerate() {
            for event in tracker.errors() {
                all.push((i, event));
            }
        }
        all
    }

    /// Wait until all healthy nodes reach at least the given block height.
    ///
    /// Uses `finalized_count` from `hub_nodeStatus` as the primary indicator,
    /// falling back to `latest_block_height` from `eth_getBlockByNumber` if available.
    pub async fn wait_for_height(&self, height: u64, timeout: Duration) -> eyre::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let snaps = self.rpc_poller.all_snapshots();
            let healthy: Vec<_> = snaps.iter().filter(|s| s.is_healthy).collect();

            if !healthy.is_empty() && healthy.iter().all(|s| s.effective_height() >= height) {
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                let heights: Vec<_> = snaps
                    .iter()
                    .map(|s| {
                        (
                            s.node_index,
                            s.effective_height(),
                            s.finalized_count,
                            s.latest_block_height,
                            s.is_healthy,
                        )
                    })
                    .collect();
                return Err(eyre::eyre!(
                    "timeout waiting for height {} (node states: {:?})",
                    height,
                    heights
                ));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until at least `min_nodes` are healthy (responding to RPC).
    pub async fn wait_for_healthy(&self, min_nodes: usize, timeout: Duration) -> eyre::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let healthy_count = self
                .rpc_poller
                .all_snapshots()
                .iter()
                .filter(|s| s.is_healthy)
                .count();

            if healthy_count >= min_nodes {
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "timeout waiting for {} healthy nodes (got {})",
                    min_nodes,
                    healthy_count
                ));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until at least `min_nodes` are healthy and not backfilling.
    pub async fn wait_for_synced(&self, min_nodes: usize, timeout: Duration) -> eyre::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let snaps = self.rpc_poller.all_snapshots();
            let synced_count = snaps
                .iter()
                .filter(|s| s.is_healthy && !s.backfilling)
                .count();

            if synced_count >= min_nodes {
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                let states: Vec<_> = snaps
                    .iter()
                    .map(|s| {
                        (
                            s.node_index,
                            s.is_healthy,
                            s.backfilling,
                            s.effective_height(),
                        )
                    })
                    .collect();
                return Err(eyre::eyre!(
                    "timeout waiting for {} synced nodes (got {}, states: {:?})",
                    min_nodes,
                    synced_count,
                    states
                ));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Assert the chain ID matches across all healthy nodes.
    pub fn assert_chain_id(&self, expected: u64) -> eyre::Result<()> {
        for snap in self.rpc_poller.all_snapshots() {
            if snap.is_healthy && snap.chain_id != expected {
                return Err(eyre::eyre!(
                    "node{} has chain_id {} (expected {})",
                    snap.node_index,
                    snap.chain_id,
                    expected
                ));
            }
        }
        Ok(())
    }

    /// Get a reference to the RPC poller.
    pub const fn rpc_poller(&self) -> &RpcPoller {
        &self.rpc_poller
    }
}
