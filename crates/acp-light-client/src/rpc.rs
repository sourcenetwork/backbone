//! Bounded JSON-RPC transport for proof and finalized-revision responses.

use std::time::Duration;

use eyre::WrapErr;
use serde::de::DeserializeOwned;

use crate::types::{LightBlock, ModuleStateProof};

/// Maximum state-proof response, including its JSON-RPC envelope.
pub const STATE_PROOF_RESPONSE_BYTES: usize = (4 << 20) + 1024;
/// Maximum light-block response, including hex-encoded block and consensus material.
pub use hub_domain::LIGHT_BLOCK_RESPONSE_BYTES;
/// Maximum permission response, including its JSON-RPC envelope.
pub const PERMISSION_RESPONSE_BYTES: usize = hub_permission::PERMISSION_LIMITS.proof_bytes + 1024;

/// Fetch a module state proof. `key_hex` is the hex-encoded record key.
pub async fn get_state_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    module: &str,
    key_hex: &str,
    height: u64,
) -> eyre::Result<ModuleStateProof> {
    request(
        client,
        rpc_url,
        "hub_getStateProof",
        serde_json::json!([module, key_hex, height]),
        STATE_PROOF_RESPONSE_BYTES,
    )
    .await
}

/// Fetch a finalized block and its certificate.
pub async fn get_light_block(
    client: &reqwest::Client,
    rpc_url: &str,
    height: u64,
) -> eyre::Result<LightBlock> {
    request(
        client,
        rpc_url,
        "hub_getLightBlock",
        serde_json::json!([height]),
        LIGHT_BLOCK_RESPONSE_BYTES,
    )
    .await
}

/// Fetch complete permission evidence for the requested revision.
pub async fn get_permission_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    policy: &str,
    access: &hub_permission::AccessRequest,
    height: u64,
) -> eyre::Result<hub_permission::PermissionProof> {
    request(
        client,
        rpc_url,
        "hub_getPermissionProof",
        serde_json::json!([policy, access, height]),
        PERMISSION_RESPONSE_BYTES,
    )
    .await
}

async fn request<T: DeserializeOwned>(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
    maximum: usize,
) -> eyre::Result<T> {
    let mut response = client
        .post(rpc_url)
        .timeout(Duration::from_secs(10))
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .wrap_err_with(|| format!("{method} request"))?
        .error_for_status()?;
    eyre::ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= maximum as u64),
        "{method} response exceeds byte limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        eyre::ensure!(
            chunk.len() <= maximum - bytes.len(),
            "{method} response exceeds byte limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    eyre::ensure!(
        value["id"] == 1 && value["jsonrpc"] == "2.0",
        "{method} RPC response metadata mismatch"
    );
    eyre::ensure!(
        !(value.get("result").is_some() && value.get("error").is_some()),
        "{method} RPC response has both result and error"
    );
    if let Some(error) = value.get("error") {
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        return Err(eyre::eyre!("{method} RPC error ({code}): {message}"));
    }
    let result = value
        .get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| eyre::eyre!("{method} RPC response has no result"))?;
    serde_json::from_value(result).wrap_err_with(|| format!("deserializing {method} result"))
}
