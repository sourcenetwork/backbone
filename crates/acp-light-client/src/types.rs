//! Shared Vera proof and header types.

pub use hub_domain::{ConsensusPublicKey, GossipHeader, LightBlock, ModuleId, ModuleStateProof};

/// ACP access check result.
#[derive(Debug, Clone)]
pub struct AccessResult {
    pub allowed: bool,
    pub verified_at_height: u64,
    pub proof: Option<ModuleStateProof>,
}
