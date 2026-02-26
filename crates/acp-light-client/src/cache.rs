//! In-memory ACP cache with height-tagged entries.
//!
//! Each entry stores a verified key-value pair along with the block height
//! and module state root it was verified against. Entries become stale when
//! the finalized `module_state_root` changes.

use std::collections::HashMap;

use alloy_primitives::B256;
use parking_lot::RwLock;

use crate::types::AccessResult;

/// A single cached ACP state entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    value: Option<Vec<u8>>,
    verified_height: u64,
    module_state_root: B256,
}

/// In-memory cache of verified ACP state.
///
/// Entries are keyed by the hex-encoded ACP key. Each entry stores the
/// verified value (or `None` for proven non-existence) along with the
/// block height and module state root the proof was verified against.
pub struct AcpCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    staleness_threshold: u64,
}

impl AcpCache {
    /// Create a new cache.
    ///
    /// `staleness_threshold` is the maximum number of blocks behind the
    /// latest finalized height before an entry is considered stale.
    pub fn new(staleness_threshold: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            staleness_threshold,
        }
    }

    /// Look up a cached entry by its hex-encoded ACP key.
    ///
    /// Returns `Some(AccessResult)` if the entry exists and is fresh enough
    /// relative to `current_height`. Returns `None` if the entry is missing
    /// or stale.
    pub fn get(&self, key_hex: &str, current_height: u64) -> Option<AccessResult> {
        let entries = self.entries.read();
        let entry = entries.get(key_hex)?;

        if current_height.saturating_sub(entry.verified_height) > self.staleness_threshold {
            return None;
        }

        Some(AccessResult {
            allowed: entry.value.is_some(),
            verified_at_height: entry.verified_height,
            proof: None,
        })
    }

    /// Insert or update a cache entry after proof verification.
    pub fn insert(
        &self,
        key_hex: &str,
        value: Option<Vec<u8>>,
        verified_height: u64,
        module_state_root: B256,
    ) {
        self.entries.write().insert(
            key_hex.to_string(),
            CacheEntry {
                value,
                verified_height,
                module_state_root,
            },
        );
    }

    /// Mark all entries as stale whose `module_state_root` differs from
    /// `new_root`. Called when `HeaderChain` detects a new module state root.
    ///
    /// Returns the number of entries invalidated.
    pub fn invalidate_stale(&self, new_root: B256) -> usize {
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|_, entry| entry.module_state_root == new_root);
        before - entries.len()
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Remove all entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }
}

/// ACP key builder helpers.
///
/// These match hub-modules `acp::keys` patterns for constructing ACP
/// state keys to prove against.
pub mod keys {
    /// Build a policy record key: `"policy/objs/" + policy_id`.
    pub fn policy_key(policy_id: &str) -> Vec<u8> {
        let mut key = Vec::from(b"policy/objs/" as &[u8]);
        key.extend_from_slice(policy_id.as_bytes());
        key
    }

    /// Build a relationship key: `"relationship/" + policy_id + "/" + storage_key`.
    pub fn relationship_key(policy_id: &str, storage_key: &str) -> Vec<u8> {
        let mut key = Vec::from(b"relationship/" as &[u8]);
        key.extend_from_slice(policy_id.as_bytes());
        key.push(b'/');
        key.extend_from_slice(storage_key.as_bytes());
        key
    }

    /// Build an access decision key: `"access_decision/" + decision_id`.
    pub fn access_decision_key(decision_id: &str) -> Vec<u8> {
        let mut key = Vec::from(b"access_decision/" as &[u8]);
        key.extend_from_slice(decision_id.as_bytes());
        key
    }

    /// Hex-encode a key with `0x` prefix (for RPC calls).
    pub fn hex_encode_key(key: &[u8]) -> String {
        format!("0x{}", hex::encode(key))
    }
}
