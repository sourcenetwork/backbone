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
pub use types::{
    AccessResult, ConsensusPublicKey, GossipHeader, LightBlock, ModuleId, ModuleStateProof,
};
pub use verify::{verify_light_block, verify_module_state_proof, LightBlockError, ProofError};

use std::time::Duration;

use alloy_primitives::B256;
use tracing::info;

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
    /// `trusted_key_hex` — consensus public key from operator configuration
    /// `staleness_threshold` — max blocks behind before a cached entry is stale
    pub async fn new(
        rpc_url: &str,
        ws_url: &str,
        trusted_key_hex: &str,
        staleness_threshold: u64,
    ) -> eyre::Result<Self> {
        let proof_client = ProofClient::new(rpc_url, trusted_key_hex)?;
        let header_chain = HeaderChain::connect(ws_url, proof_client.clone()).await?;
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

    /// Check whether a relationship record exists at the verified revision.
    pub async fn check_access(
        &self,
        policy_id: &str,
        storage_key: &str,
    ) -> eyre::Result<AccessResult> {
        self.check_key(cache::keys::relationship_key(policy_id, storage_key))
            .await
    }

    /// Check whether an access decision record exists at the verified revision.
    pub async fn check_access_decision(&self, decision_id: &str) -> eyre::Result<AccessResult> {
        self.check_key(cache::keys::access_decision_key(decision_id))
            .await
    }

    /// Check whether a policy exists at the verified revision.
    pub async fn check_policy(&self, policy_id: &str) -> eyre::Result<AccessResult> {
        self.check_key(cache::keys::policy_key(policy_id)).await
    }

    async fn check_key(&self, key: Vec<u8>) -> eyre::Result<AccessResult> {
        let key_hex = cache::keys::hex_encode_key(&key);
        self.invalidate_if_root_changed();
        let sync = self
            .header_chain
            .state()
            .ok_or_else(|| eyre::eyre!("no verified finalized state available"))?;
        if let Some(cached) = self
            .cache
            .get(&key_hex, sync.height, sync.module_state_root)
        {
            return Ok(cached);
        }
        let proof = self
            .proof_client
            .fetch_and_verify_proof_with_root("acp", &key_hex, sync.height, sync.module_state_root)
            .await?;
        let current = self
            .header_chain
            .state()
            .ok_or_else(|| eyre::eyre!("no verified finalized state available"))?;
        eyre::ensure!(
            current.module_state_root == sync.module_state_root,
            "ACP state changed during proof verification; retry the request"
        );
        let value = proof
            .value
            .as_ref()
            .map(|v| hex::decode(v.strip_prefix("0x").unwrap_or(v)))
            .transpose()?;
        let allowed = value.is_some();
        self.cache
            .insert(&key_hex, value, sync.height, sync.module_state_root);
        Ok(AccessResult {
            allowed,
            verified_at_height: sync.height,
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
