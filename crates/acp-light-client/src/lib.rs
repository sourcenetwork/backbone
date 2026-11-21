//! Authenticated ACP records and full permission evaluation at verified revisions.
//!
//! Header synchronization verifies finalization against configured consensus trust.
//! Record reads may use a root-bound cache; permission requests fetch complete
//! evidence and run the shared evaluator before returning a result.

pub mod cache;
mod freshness;
pub mod header_sync;
pub mod proof_client;
pub mod rpc;
mod term;
pub mod transport;
pub mod types;
pub mod verify;

pub use cache::AcpCache;
pub use freshness::FreshnessPolicy;
pub use header_sync::{HeaderChain, SyncState};
pub use proof_client::{AssignmentReadError, ProofClient};
pub use term::Voided;
pub use transport::{AcpTransport, HeaderStream, HttpWsTransport, TransportError};
pub use types::{
    ConsensusPublicKey, ExecutionReceipt, GossipHeader, LightBlock, ModuleId, ReceiptResponse,
    ReceiptResponseError, Refusal, RefusalKind, RefusingModule, TermCertificate, VerifiedReceipt,
    VerifiedRecord,
};
pub use vera_modules::acp::types::RelationPair;
pub use vera_permission::{
    AccessDecision, AccessRequest, Actor, AssignmentSelector, DecisionRequest, Object, Operation,
    PermissionProof, RecordProof, RecordResponse, Timestamp, PERMISSION_LIMITS,
};
pub use verify::{verify_finalized_block, verify_light_block, LightBlockError};

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use tracing::info;

/// Top-level ACP light client.
///
/// Wires together header sync, proof fetching, and caching.
/// `verify_access()` evaluates permission requests; record reads return data only.
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
    ///
    /// Revision freshness defaults to 30 seconds with up to 15 seconds of future clock skew.
    /// Disconnection or withheld headers do not extend this lifetime.
    pub async fn new(
        rpc_url: &str,
        ws_url: &str,
        trusted_key_hex: &str,
        staleness_threshold: u64,
    ) -> eyre::Result<Self> {
        Self::new_with_freshness(
            rpc_url,
            ws_url,
            trusted_key_hex,
            staleness_threshold,
            FreshnessPolicy::default(),
        )
        .await
    }

    /// Create a client with explicit local revision age and clock-skew bounds.
    pub async fn new_with_freshness(
        rpc_url: &str,
        ws_url: &str,
        trusted_key_hex: &str,
        staleness_threshold: u64,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        Self::with_transport(
            Arc::new(HttpWsTransport::new(rpc_url, ws_url)?),
            trusted_key_hex,
            staleness_threshold,
            freshness,
        )
    }

    /// Create a client that reaches the node through `transport`.
    ///
    /// Verification does not depend on the transport: every response and header
    /// is checked against `trusted_key_hex`. Must be called inside a Tokio runtime.
    ///
    /// This client follows a deployment whose active device never changes: it
    /// refuses a revision of any term above 0. See [`Self::for_deployment`].
    pub fn with_transport(
        transport: Arc<dyn AcpTransport>,
        trusted_key_hex: &str,
        staleness_threshold: u64,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        let proof_client = ProofClient::with_transport(transport.clone(), trusted_key_hex)?;
        Self::start(transport, proof_client, staleness_threshold, freshness)
    }

    /// Create a client of the deployment whose genesis block is `genesis_id`,
    /// which may switch its active device.
    ///
    /// A revision of a term above 0 is accepted once the certificate of its
    /// term verifies under the operator policy in certified state. When that
    /// term voids the revision this client had accepted, the revision is
    /// dropped and reported by [`HeaderChain::voided`], and the client goes on
    /// from the new term's blocks, which may be at a lower height.
    /// `genesis_id`, like the consensus key, must not come from the node.
    pub fn for_deployment(
        transport: Arc<dyn AcpTransport>,
        trusted_key_hex: &str,
        genesis_id: B256,
        staleness_threshold: u64,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        let proof_client = ProofClient::with_transport(transport.clone(), trusted_key_hex)?
            .for_deployment(genesis_id);
        Self::start(transport, proof_client, staleness_threshold, freshness)
    }

    fn start(
        transport: Arc<dyn AcpTransport>,
        proof_client: ProofClient,
        staleness_threshold: u64,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        let header_chain = HeaderChain::start(transport, proof_client.clone(), freshness)?;
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

    /// Evaluate current certified evidence at or beyond the latest verified revision.
    pub async fn verify_access(&self, policy: &str, request: &AccessRequest) -> eyre::Result<bool> {
        let minimum = self.header_chain.fresh_state()?.height;
        let (revision, allowed) = self
            .proof_client
            .verify_current_permission(policy, request, minimum)
            .await?;
        self.header_chain.accept_response(revision).await?;
        Ok(allowed)
    }

    /// Read the live owner or proven absence from fresh complete ownership evidence.
    pub async fn read_object_owner(
        &self,
        policy: &str,
        object: &Object,
    ) -> eyre::Result<Option<Actor>> {
        let minimum = self.header_chain.fresh_state()?.height;
        let (revision, owner) = self
            .proof_client
            .read_current_object_owner(policy, object, minimum)
            .await?;
        self.header_chain.accept_response(revision).await?;
        Ok(owner)
    }

    /// Read complete direct assignment evidence at a fresh active revision.
    pub async fn read_certified_assignments(
        &self,
        policy: &str,
        selector: &AssignmentSelector<'_>,
    ) -> Result<(SyncState, vera_permission::PolicyPrefixResponse), AssignmentReadError> {
        let minimum = self
            .header_chain
            .fresh_state()
            .map_err(|error| AssignmentReadError::Revision(error.to_string()))?
            .height;
        let evidence = self
            .proof_client
            .assignment_evidence(policy, selector, minimum)
            .await?;
        let revision = proof_client::revision_state(&evidence.revision)
            .map_err(|error| AssignmentReadError::Revision(error.to_string()))?;
        let accepted = match self.header_chain.accept_response(revision.clone()).await {
            Ok(accepted) => accepted,
            Err(error) => {
                if self
                    .header_chain
                    .fresh_state()
                    .is_ok_and(|current| current != revision)
                {
                    return Err(AssignmentReadError::Overtaken);
                }
                return Err(AssignmentReadError::Revision(error.to_string()));
            }
        };
        if accepted.term != revision.term {
            return Err(AssignmentReadError::Overtaken);
        }
        Ok((revision, evidence))
    }

    /// Read an exact generation-qualified relationship at a fresh certified revision.
    /// The same-root policy must authenticate both generation identities.
    pub async fn read_relationship(
        &self,
        policy_id: &str,
        generations: RelationPair,
        storage_key: &str,
    ) -> eyre::Result<VerifiedRecord> {
        let key = cache::keys::relationship_key(policy_id, generations, storage_key);
        let minimum = self.header_chain.fresh_state()?.height;
        let (revision, record) = self
            .proof_client
            .read_current_relationship(policy_id, &key, minimum)
            .await?;
        self.header_chain.accept_response(revision).await?;
        Ok(record)
    }

    /// Read an access decision record at the verified revision.
    pub async fn read_access_decision(&self, decision_id: &str) -> eyre::Result<VerifiedRecord> {
        self.read_key(cache::keys::access_decision_key(decision_id))
            .await
    }

    /// Verify a persisted successful decision for an exact submission at fresh authenticated state.
    /// This checks issuance and expiry, not permission changes after issuance or payload authorization.
    pub async fn verify_access_decision(
        &self,
        request: &DecisionRequest,
    ) -> eyre::Result<AccessDecision> {
        let record = self.read_access_decision(&request.id()?).await?;
        let state = self.header_chain.fresh_state()?;
        eyre::ensure!(
            record.module_state_root == state.module_state_root,
            "ACP state changed during decision verification; retry the request"
        );
        let bytes = record
            .value
            .as_deref()
            .ok_or_else(|| eyre::eyre!("access decision is absent at the verified revision"))?;
        Ok(request.verify_record(
            bytes,
            &Timestamp {
                seconds: state.timestamp,
                block_height: state.height,
            },
        )?)
    }

    /// Read a policy record at the verified revision.
    pub async fn read_policy(&self, policy_id: &str) -> eyre::Result<VerifiedRecord> {
        self.read_key(cache::keys::policy_key(policy_id)).await
    }

    async fn read_key(&self, key: Vec<u8>) -> eyre::Result<VerifiedRecord> {
        let key_hex = cache::keys::hex_encode_key(&key);
        self.invalidate_if_root_changed();
        let sync = self.header_chain.fresh_state()?;
        if let Some(cached) = self
            .cache
            .get(&key_hex, sync.height, sync.module_state_root)
        {
            return Ok(cached);
        }
        let response = self
            .proof_client
            .fetch_and_verify_record(ModuleId::Acp, &key, sync.height)
            .await?;
        let revision = proof_client::revision_state(&response.revision)?;
        self.header_chain.accept_response(revision.clone()).await?;
        let proof = response.record;
        let value = proof.value.as_ref().map(|v| Arc::<[u8]>::from(v.as_ref()));
        self.cache.insert(
            &key_hex,
            value.clone(),
            revision.height,
            revision.module_state_root,
        );
        Ok(VerifiedRecord {
            value,
            module_state_root: revision.module_state_root,
            verified_at_height: revision.height,
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
