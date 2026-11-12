//! Fetch state proofs against finality authenticated by a configured consensus key.

use std::sync::Arc;

use commonware_codec::DecodeExt as _;
use eyre::{ensure, WrapErr};

use crate::header_sync::SyncState;
use crate::rpc;
use crate::transport::{AcpTransport, HttpWsTransport};
use crate::types::{ConsensusPublicKey, LightBlock, ModuleId, VerifiedRecord};
use crate::verify;

/// JSON-RPC client with an independently configured consensus trust anchor.
#[derive(Clone)]
pub struct ProofClient {
    transport: Arc<dyn AcpTransport>,
    trusted_key: ConsensusPublicKey,
}

impl ProofClient {
    /// `trusted_key_hex` must come from operator configuration, not the RPC endpoint.
    pub fn new(rpc_url: &str, trusted_key_hex: &str) -> eyre::Result<Self> {
        let trusted_key = decode_trusted_key(trusted_key_hex)?;
        Ok(Self {
            transport: Arc::new(HttpWsTransport::calls_only(rpc_url)?),
            trusted_key,
        })
    }

    /// Fetch through `transport`. The trust anchor is still configured here, not by the node.
    pub fn with_transport(
        transport: Arc<dyn AcpTransport>,
        trusted_key_hex: &str,
    ) -> eyre::Result<Self> {
        Ok(Self {
            transport,
            trusted_key: decode_trusted_key(trusted_key_hex)?,
        })
    }

    /// Fetch a light block without verifying it.
    pub async fn get_light_block(&self, height: u64) -> eyre::Result<LightBlock> {
        rpc::light_block(self.transport.as_ref(), height).await
    }

    /// Authenticate the requested revision using the configured consensus key.
    pub async fn verified_state(&self, height: u64) -> eyre::Result<SyncState> {
        let light = self
            .get_light_block(height)
            .await
            .wrap_err("fetching light block")?;
        ensure!(
            light.height == height,
            "light block height differs from request"
        );
        let (_, module_state_root) = verify::verify_light_block(&light, &self.trusted_key)?;
        Ok(SyncState {
            height,
            timestamp: light.timestamp,
            module_state_root,
            block_hash: light.block_hash.parse()?,
        })
    }

    /// Verify a current permission response against independently configured trust.
    pub async fn verify_current_permission(
        &self,
        policy: &str,
        request: &vera_permission::AccessRequest,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, bool)> {
        vera_permission::validate_request(policy, request, vera_permission::PERMISSION_LIMITS)?;
        let response =
            rpc::permission_proof(self.transport.as_ref(), policy, request, minimum_height).await?;
        let allowed = response.verify(
            policy,
            request,
            minimum_height,
            &self.trusted_key,
            vera_permission::PERMISSION_LIMITS,
        )?;
        Ok((revision_state(&response.revision)?, allowed))
    }

    /// Verify complete ownership evidence and policy liveness at one certified revision.
    pub async fn read_current_object_owner(
        &self,
        policy: &str,
        object: &vera_permission::Object,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, Option<vera_permission::Actor>)> {
        let prefix = vera_permission::object_owner_prefix(policy, object)?;
        let response =
            rpc::policy_prefix_proof(self.transport.as_ref(), policy, &prefix, minimum_height)
                .await?;
        let owner =
            response.verify_object_owner(policy, object, minimum_height, &self.trusted_key)?;
        Ok((revision_state(&response.revision)?, owner))
    }

    /// Read an exact v5 relationship key only while its policy, relation generations
    /// and target object incarnation are current at the same certified revision.
    pub async fn read_current_relationship(
        &self,
        policy: &str,
        key: &[u8],
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, VerifiedRecord)> {
        let response =
            rpc::policy_prefix_proof(self.transport.as_ref(), policy, key, minimum_height).await?;
        let evidence = response.verify(
            policy,
            key,
            minimum_height,
            &self.trusted_key,
            vera_permission::RECORD_PROOF_BYTES,
        )?;
        let value = match evidence {
            None => None,
            Some(evidence) => {
                ensure!(
                    evidence.entries.len() <= 1,
                    "relationship selection is not an exact key"
                );
                evidence
                    .entries
                    .first()
                    .map(|entry| {
                        ensure!(entry.key == key, "relationship differs from requested key");
                        Ok::<_, eyre::Report>(Arc::<[u8]>::from(entry.value.as_ref()))
                    })
                    .transpose()?
            }
        };
        let revision = revision_state(&response.revision)?;
        let record = VerifiedRecord {
            value,
            module_state_root: revision.module_state_root,
            verified_at_height: revision.height,
            // A raw point proof does not authenticate policy, generation or incarnation liveness.
            proof: None,
        };
        Ok((revision, record))
    }

    /// Fetch and verify a native record and its finalized revision in one response.
    pub async fn fetch_and_verify_record(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
    ) -> eyre::Result<vera_permission::RecordResponse> {
        eyre::ensure!(
            key.len() <= vera_permission::current::MAX_KEY_BYTES,
            "record key exceeds limit"
        );
        let response =
            rpc::record_proof(self.transport.as_ref(), module, key, minimum_height).await?;
        response.verify(
            module,
            key,
            minimum_height,
            &self.trusted_key,
            vera_permission::RECORD_PROOF_BYTES,
        )?;
        Ok(response)
    }
}

pub(crate) fn revision_state(light: &LightBlock) -> eyre::Result<SyncState> {
    Ok(SyncState {
        height: light.height,
        timestamp: light.timestamp,
        module_state_root: light.module_state_root.parse()?,
        block_hash: light.block_hash.parse()?,
    })
}

fn decode_trusted_key(trusted_key_hex: &str) -> eyre::Result<ConsensusPublicKey> {
    let bytes = decode_hex(trusted_key_hex).wrap_err("invalid trusted consensus key hex")?;
    ConsensusPublicKey::decode(bytes).wrap_err("invalid trusted consensus key")
}

fn decode_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}
