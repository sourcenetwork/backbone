//! ACP Light Client — proof-validated ACP cache for the Source Network stack.
//!
//! Subscribes to hub.rs finalized block headers, fetches and verifies Merkle
//! inclusion proofs, and maintains a local ACP cache. Consumed by both
//! DefraDB (query gate) and Orbis (signing gate) for local ACP enforcement
//! without per-query RPC round-trips.
//!
//! # Architecture
//!
//! ```text
//! eth_subscribe("headers")  ──→  HeaderChain  ──→  height + module_state_root
//!                                                         │
//!                           hub_getStateProof  ──→  ProofClient  ──→  verify
//!                           hub_getLightBlock  ──→       │
//!                                                       ▼
//!                                                   AcpCache  ──→  check_access()
//! ```

pub mod cache;
pub mod header_sync;
pub mod proof_client;
pub mod rpc;
pub mod types;
pub mod verify;

pub use cache::AcpCache;
pub use header_sync::{HeaderChain, SyncState};
pub use proof_client::ProofClient;
pub use types::{AccessResult, GossipHeader, LightBlock, ModuleId, ModuleStateProof};
pub use verify::{verify_light_block, verify_module_state_proof, LightBlockError, ProofError};

use std::time::Duration;

use alloy_primitives::B256;
use tracing::{debug, info};

/// Top-level ACP light client.
///
/// Wires together header sync, proof fetching, and caching. Provides
/// `check_access()` as the primary entry point for ACP enforcement.
pub struct AcpLightClient {
    header_chain: HeaderChain,
    proof_client: ProofClient,
    cache: AcpCache,
    last_invalidation_root: parking_lot::Mutex<Option<B256>>,
}

impl AcpLightClient {
    /// Create a new light client connected to a hub.rs node.
    ///
    /// `rpc_url` — HTTP JSON-RPC endpoint (e.g., `http://127.0.0.1:9944`)
    /// `ws_url` — WebSocket endpoint (e.g., `ws://127.0.0.1:9944`)
    /// `staleness_threshold` — max blocks behind before a cached entry is stale
    pub async fn new(rpc_url: &str, ws_url: &str, staleness_threshold: u64) -> eyre::Result<Self> {
        let header_chain = HeaderChain::connect(ws_url).await?;
        let proof_client = ProofClient::new(rpc_url);
        let cache = AcpCache::new(staleness_threshold);

        Ok(Self {
            header_chain,
            proof_client,
            cache,
            last_invalidation_root: parking_lot::Mutex::new(None),
        })
    }

    /// Access to the underlying header chain for height tracking.
    pub fn header_chain(&self) -> &HeaderChain {
        &self.header_chain
    }

    /// Access to the underlying proof client.
    pub fn proof_client(&self) -> &ProofClient {
        &self.proof_client
    }

    /// Access to the underlying cache.
    pub fn cache(&self) -> &AcpCache {
        &self.cache
    }

    /// Check ACP access for a relationship key.
    ///
    /// 1. Build the ACP key from the relationship components
    /// 2. Check the cache — if fresh, return immediately
    /// 3. If stale/missing, fetch + verify a proof from hub.rs
    /// 4. Cache the result and return
    ///
    /// The `storage_key` is the relationship storage key within the policy
    /// (e.g., `"rel/document/doc1/reader/{subject_hash}"`).
    pub async fn check_access(
        &self,
        policy_id: &str,
        storage_key: &str,
    ) -> eyre::Result<AccessResult> {
        let key_bytes = cache::keys::relationship_key(policy_id, storage_key);
        let key_hex = cache::keys::hex_encode_key(&key_bytes);

        self.invalidate_if_root_changed();

        let current_height = self.header_chain.latest_height();
        if let Some(cached) = self.cache.get(&key_hex, current_height) {
            debug!(
                policy_id,
                storage_key,
                cached_height = cached.verified_at_height,
                "cache hit"
            );
            return Ok(cached);
        }

        let height = current_height.max(1);
        let sync = self.header_chain.state();

        let (proof, module_state_root) = if let Some(ref sync) = sync {
            let proof = self
                .proof_client
                .fetch_and_verify_proof_with_root(
                    "acp",
                    &key_hex,
                    sync.height,
                    sync.module_state_root,
                )
                .await?;
            (proof, sync.module_state_root)
        } else {
            self.proof_client
                .fetch_and_verify_proof("acp", &key_hex, height)
                .await?
        };

        let allowed = proof.value.is_some();
        let verified_height = proof.height;

        let value_bytes = proof.value.as_ref().map(|v| {
            let v = v.strip_prefix("0x").unwrap_or(v);
            hex::decode(v).unwrap_or_default()
        });

        self.cache
            .insert(&key_hex, value_bytes, verified_height, module_state_root);

        info!(
            policy_id,
            storage_key, allowed, verified_height, "proof verified and cached"
        );

        Ok(AccessResult {
            allowed,
            verified_at_height: verified_height,
            proof: Some(proof),
        })
    }

    /// Check whether a policy exists on hub.rs.
    pub async fn check_policy(&self, policy_id: &str) -> eyre::Result<AccessResult> {
        let key_bytes = cache::keys::policy_key(policy_id);
        let key_hex = cache::keys::hex_encode_key(&key_bytes);

        self.invalidate_if_root_changed();

        let current_height = self.header_chain.latest_height();
        if let Some(cached) = self.cache.get(&key_hex, current_height) {
            return Ok(cached);
        }

        let height = current_height.max(1);
        let sync = self.header_chain.state();

        let (proof, module_state_root) = if let Some(ref sync) = sync {
            let proof = self
                .proof_client
                .fetch_and_verify_proof_with_root(
                    "acp",
                    &key_hex,
                    sync.height,
                    sync.module_state_root,
                )
                .await?;
            (proof, sync.module_state_root)
        } else {
            self.proof_client
                .fetch_and_verify_proof("acp", &key_hex, height)
                .await?
        };

        let allowed = proof.value.is_some();
        let verified_height = proof.height;

        let value_bytes = proof.value.as_ref().map(|v| {
            let v = v.strip_prefix("0x").unwrap_or(v);
            hex::decode(v).unwrap_or_default()
        });

        self.cache
            .insert(&key_hex, value_bytes, verified_height, module_state_root);

        Ok(AccessResult {
            allowed,
            verified_at_height: verified_height,
            proof: Some(proof),
        })
    }

    /// Wait until the header chain reaches at least `target` height.
    pub async fn wait_for_height(&self, target: u64, timeout: Duration) -> eyre::Result<SyncState> {
        self.header_chain.wait_for_height(target, timeout).await
    }

    /// Wait until the module state root changes from `previous`.
    pub async fn wait_for_root_change(
        &self,
        previous: B256,
        timeout: Duration,
    ) -> eyre::Result<SyncState> {
        self.header_chain
            .wait_for_root_change(previous, timeout)
            .await
    }

    /// Invalidate cache entries if the module state root has changed
    /// since the last invalidation.
    fn invalidate_if_root_changed(&self) {
        if let Some(sync) = self.header_chain.state() {
            let mut last = self.last_invalidation_root.lock();
            if *last != Some(sync.module_state_root) {
                let invalidated = self.cache.invalidate_stale(sync.module_state_root);
                if invalidated > 0 {
                    info!(
                        invalidated,
                        new_root = %sync.module_state_root,
                        height = sync.height,
                        "cache entries invalidated after root change"
                    );
                }
                *last = Some(sync.module_state_root);
            }
        }
    }
}
