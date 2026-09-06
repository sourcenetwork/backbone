//! Shared Vera proof and header types.

use std::sync::Arc;

use alloy_primitives::B256;

pub use hub_domain::{ConsensusPublicKey, GossipHeader, LightBlock, ModuleId, ModuleStateProof};

/// A value authenticated against one finalized module root.
#[derive(Debug, Clone)]
pub struct VerifiedRecord {
    pub value: Option<Arc<[u8]>>,
    pub module_state_root: B256,
    pub verified_at_height: u64,
    pub proof: Option<hub_permission::RecordProof>,
}
