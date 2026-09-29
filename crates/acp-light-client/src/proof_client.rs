//! Fetch state proofs against finality authenticated by a configured consensus key.

use std::time::Duration;

use commonware_codec::DecodeExt as _;
use eyre::{ensure, WrapErr};

use crate::header_sync::SyncState;
use crate::rpc;
use crate::types::{ConsensusPublicKey, LightBlock, ModuleId};
use crate::verify;

/// HTTP JSON-RPC client with an independently configured consensus trust anchor.
#[derive(Clone)]
pub struct ProofClient {
    client: reqwest::Client,
    rpc_url: String,
    trusted_key: ConsensusPublicKey,
}

impl ProofClient {
    /// `trusted_key_hex` must come from operator configuration, not the RPC endpoint.
    pub fn new(rpc_url: &str, trusted_key_hex: &str) -> eyre::Result<Self> {
        let bytes = decode_hex(trusted_key_hex).wrap_err("invalid trusted consensus key hex")?;
        let trusted_key =
            ConsensusPublicKey::decode(bytes).wrap_err("invalid trusted consensus key")?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            trusted_key,
        })
    }

    /// Fetch a light block without verifying it.
    pub async fn get_light_block(&self, height: u64) -> eyre::Result<LightBlock> {
        rpc::get_light_block(&self.client, &self.rpc_url, height).await
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
        let response = rpc::get_current_permission_proof(
            &self.client,
            &self.rpc_url,
            policy,
            request,
            minimum_height,
        )
        .await?;
        let allowed = response.verify(
            policy,
            request,
            minimum_height,
            &self.trusted_key,
            vera_permission::PERMISSION_LIMITS,
        )?;
        Ok((revision_state(&response.revision)?, allowed))
    }

    /// Verify complete ownership evidence for the requested object.
    pub async fn read_current_object_owner(
        &self,
        policy: &str,
        object: &vera_permission::Object,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, Option<vera_permission::Actor>)> {
        let prefix = vera_permission::object_owner_prefix(policy, object)?;
        let response = rpc::get_current_prefix_proof(
            &self.client,
            &self.rpc_url,
            ModuleId::Acp,
            &prefix,
            minimum_height,
        )
        .await?;
        let owner =
            response.verify_object_owner(policy, object, minimum_height, &self.trusted_key)?;
        Ok((revision_state(&response.revision)?, owner))
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
            rpc::get_current_record_proof(&self.client, &self.rpc_url, module, key, minimum_height)
                .await?;
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

fn decode_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}
