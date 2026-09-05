//! Fetch state proofs against finality authenticated by a configured consensus key.

use std::time::Duration;

use alloy_primitives::B256;
use commonware_codec::DecodeExt as _;
use eyre::{ensure, WrapErr};

use crate::header_sync::SyncState;
use crate::rpc;
use crate::types::{ConsensusPublicKey, LightBlock, ModuleId, ModuleStateProof};
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
        let trusted_key = ConsensusPublicKey::decode(bytes.as_slice())
            .wrap_err("invalid trusted consensus key")?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            trusted_key,
        })
    }

    /// Fetch a module state proof without verifying it.
    pub async fn get_state_proof(
        &self,
        module: &str,
        key_hex: &str,
        height: u64,
    ) -> eyre::Result<ModuleStateProof> {
        rpc::get_state_proof(&self.client, &self.rpc_url, module, key_hex, height).await
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
            module_state_root,
            block_hash: light.block_hash.parse()?,
        })
    }

    /// Fetch and verify finality and a state proof at the requested revision.
    pub async fn fetch_and_verify_proof(
        &self,
        module: &str,
        key_hex: &str,
        height: u64,
    ) -> eyre::Result<(ModuleStateProof, B256)> {
        let state = self.verified_state(height).await?;
        let proof = self
            .fetch_and_verify_proof_with_root(
                module,
                key_hex,
                state.height,
                state.module_state_root,
            )
            .await?;
        Ok((proof, state.module_state_root))
    }

    /// Verify a proof against a root authenticated by this client's header sync.
    pub(crate) async fn fetch_and_verify_proof_with_root(
        &self,
        module: &str,
        key_hex: &str,
        height: u64,
        module_state_root: B256,
    ) -> eyre::Result<ModuleStateProof> {
        let proof = self
            .get_state_proof(module, key_hex, height)
            .await
            .wrap_err("fetching state proof")?;
        verify_response(&proof, module, key_hex, height, module_state_root)?;
        Ok(proof)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}

fn verify_response(
    proof: &ModuleStateProof,
    module: &str,
    key_hex: &str,
    height: u64,
    root: B256,
) -> eyre::Result<()> {
    ensure!(
        Some(proof.module) == ModuleId::from_str_name(module),
        "proof module differs from request"
    );
    ensure!(proof.height == height, "proof height differs from request");
    ensure!(
        decode_hex(&proof.key)? == decode_hex(key_hex)?,
        "proof key differs from request"
    );
    verify::verify_module_state_proof(root, proof)?;
    Ok(())
}
