//! Shared Vera proof and header types.

use std::sync::Arc;

use alloy_primitives::B256;

pub use vera_domain::{
    ConsensusPublicKey, ExecutionReceipt, GossipHeader, LightBlock, ModuleId, ReceiptResponse,
    ReceiptResponseError, Refusal, RefusalKind, RefusingModule, TermCertificate,
};

/// A value authenticated against one finalized module root.
#[derive(Debug, Clone)]
pub struct VerifiedRecord {
    pub value: Option<Arc<[u8]>>,
    pub module_state_root: B256,
    pub verified_at_height: u64,
    pub proof: Option<vera_permission::RecordProof>,
}

/// A submission's receipt, committed by a revision authenticated against configured trust.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    pub receipt: ExecutionReceipt,
    pub revision: crate::SyncState,
}
