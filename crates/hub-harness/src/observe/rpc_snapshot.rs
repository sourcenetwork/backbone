//! Per-node RPC state snapshot.

/// Latest known state of a single node from RPC polling.
///
/// Block height comes from two sources:
/// - `finalized_count` from `hub_nodeStatus` (always available)
/// - `latest_block_height` from `eth_getBlockByNumber` (requires IndexedStateProvider)
///
/// Use `effective_height()` to get the best available height.
#[derive(Clone, Debug, Default)]
pub struct NodeSnapshot {
    /// Node index in the cluster.
    pub node_index: usize,
    /// Chain ID reported by the node.
    pub chain_id: u64,
    /// Validator index reported by the node.
    pub validator_index: u32,
    /// Total number of validators.
    pub validator_count: u32,
    /// Seconds since the node started.
    pub uptime_secs: u64,
    /// Current consensus view.
    pub current_view: u64,
    /// Number of finalized blocks.
    pub finalized_count: u64,
    /// Number of proposed blocks.
    pub proposed_count: u64,
    /// Number of nullified rounds.
    pub nullified_count: u64,
    /// Number of connected peers.
    pub peer_count: u64,
    /// Whether this node is the current leader.
    pub is_leader: bool,
    /// Whether this node is backfilling historical blocks.
    pub backfilling: bool,
    /// Latest block height from eth_getBlockByNumber.
    pub latest_block_height: u64,
    /// Whether the node is reachable.
    pub is_healthy: bool,
}

impl NodeSnapshot {
    /// Best available block height.
    ///
    /// Prefers `latest_block_height` (from `eth_getBlockByNumber`) when available,
    /// falls back to `finalized_count` (from `hub_nodeStatus`).
    pub const fn effective_height(&self) -> u64 {
        if self.latest_block_height > self.finalized_count {
            self.latest_block_height
        } else {
            self.finalized_count
        }
    }
}
