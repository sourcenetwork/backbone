//! Wire types matching hub.rs JSON-RPC responses.
//!
//! These types are serde-deserializable from hub.rs endpoints without
//! compile-time coupling to hub-domain. All hex fields use `0x` prefix.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Identifies which module tree a proof targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    Acp = 0,
    Bulletin = 1,
    Hub = 2,
    NativeNonce = 3,
}

impl ModuleId {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "acp" => Some(Self::Acp),
            "bulletin" => Some(Self::Bulletin),
            "hub" => Some(Self::Hub),
            "native_nonce" | "nonces" => Some(Self::NativeNonce),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Proof that a key-value pair exists (or doesn't exist) in a module's state,
/// verifiable against the block's `module_state_root`.
///
/// Returned by `hub_getStateProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStateProof {
    pub module: ModuleId,
    pub height: u64,
    /// Hex-encoded key bytes.
    pub key: String,
    /// Hex-encoded value bytes, or null for non-existence proofs.
    pub value: Option<String>,
    /// JMT sparse Merkle proof (borsh-serialized, hex-encoded).
    pub jmt_proof: String,
    /// Root hash of this module's JMT (hex-encoded).
    pub module_root: String,
    /// Root hashes of all 4 module trees (hex-encoded, order: acp, bulletin, hub, nonces).
    pub all_module_roots: [String; 4],
}

/// Signed finalized block header from `eth_subscribe("headers")`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipHeader {
    pub chain_id: u64,
    pub height: u64,
    pub block_hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub state_root: B256,
    pub module_state_root: B256,
    pub tx_count: u32,
    pub publisher_index: u32,
    pub signature: Vec<u8>,
}

/// Self-contained block snapshot for light client verification.
///
/// Returned by `hub_getLightBlock`. All binary fields are hex-encoded with
/// `0x` prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBlock {
    pub block_hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub state_root: String,
    pub module_state_root: String,

    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    /// SHA-256 of block_hash — the consensus payload digest (hex 32 bytes).
    pub proposal_payload: String,

    /// Indices of validators that signed the finalization certificate.
    pub signer_indices: Vec<u32>,
    /// Ed25519 signatures (hex 64 bytes each).
    pub signatures: Vec<String>,
    /// Ordered ed25519 validator public keys (hex 32 bytes each).
    pub validators: Vec<String>,
}

/// ACP access check result.
#[derive(Debug, Clone)]
pub struct AccessResult {
    pub allowed: bool,
    pub verified_at_height: u64,
    pub proof: Option<ModuleStateProof>,
}
