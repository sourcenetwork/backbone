//! Proof fetching + verification.
//!
//! Combines RPC fetching with standalone verification. Fetches a state proof
//! and a light block at the same height, verifies the light block's
//! finalization certificate, then verifies the state proof against the
//! trusted `module_state_root`.

use std::time::Duration;

use alloy_primitives::B256;
use eyre::WrapErr;

use crate::rpc;
use crate::types::{LightBlock, ModuleStateProof};
use crate::verify;

/// HTTP JSON-RPC client for fetching and verifying proofs.
pub struct ProofClient {
    client: reqwest::Client,
    rpc_url: String,
}

impl ProofClient {
    pub fn new(rpc_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");

        Self {
            client,
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Fetch a module state proof (unverified).
    pub async fn get_state_proof(
        &self,
        module: &str,
        key_hex: &str,
        height: u64,
    ) -> eyre::Result<ModuleStateProof> {
        rpc::get_state_proof(&self.client, &self.rpc_url, module, key_hex, height).await
    }

    /// Fetch a light block (unverified).
    pub async fn get_light_block(&self, height: u64) -> eyre::Result<LightBlock> {
        rpc::get_light_block(&self.client, &self.rpc_url, height).await
    }

    /// Fetch + verify a state proof at a given height.
    ///
    /// 1. Fetch light block → verify → get trusted `module_state_root`
    /// 2. Fetch state proof → verify against trusted root
    ///
    /// Returns `(proof, module_state_root)`.
    pub async fn fetch_and_verify_proof(
        &self,
        module: &str,
        key_hex: &str,
        height: u64,
    ) -> eyre::Result<(ModuleStateProof, B256)> {
        let light_block = self
            .get_light_block(height)
            .await
            .wrap_err("fetching light block")?;

        let (_state_root, module_state_root) = verify::verify_light_block(&light_block)
            .map_err(|e| eyre::eyre!("light block verification failed: {e}"))?;

        let proof = self
            .get_state_proof(module, key_hex, height)
            .await
            .wrap_err("fetching state proof")?;

        verify::verify_module_state_proof(module_state_root, &proof)
            .map_err(|e| eyre::eyre!("module state proof verification failed: {e}"))?;

        Ok((proof, module_state_root))
    }

    /// Fetch + verify a state proof using a pre-trusted `module_state_root`
    /// (e.g., from an already verified header).
    ///
    /// Skips the light block fetch when the caller already has a trusted root.
    pub async fn fetch_and_verify_proof_with_root(
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

        verify::verify_module_state_proof(module_state_root, &proof)
            .map_err(|e| eyre::eyre!("module state proof verification failed: {e}"))?;

        Ok(proof)
    }
}
