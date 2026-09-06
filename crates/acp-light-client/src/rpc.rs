//! Bounded JSON-RPC transport for proof and finalized-revision responses.

use std::time::Duration;

use eyre::WrapErr;
use serde::de::DeserializeOwned;

use crate::types::{LightBlock, ModuleId};

/// Maximum light-block response, including hex-encoded block and consensus material.
pub use hub_domain::LIGHT_BLOCK_RESPONSE_BYTES;
/// Maximum current permission response, including finalization and the RPC envelope.
pub use hub_permission::PERMISSION_RESPONSE_BYTES;
/// Maximum native record response, including finalization and the RPC envelope.
pub use hub_permission::RECORD_RESPONSE_BYTES;

/// Fetch current record evidence paired with its finalized revision.
pub async fn get_current_record_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    module: ModuleId,
    key: &[u8],
    minimum_height: u64,
) -> eyre::Result<hub_permission::RecordResponse> {
    request(
        client,
        rpc_url,
        "hub_getCurrentRecordProof",
        serde_json::json!([module, format!("0x{}", hex::encode(key)), minimum_height]),
        RECORD_RESPONSE_BYTES,
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

/// Fetch current permission evidence paired with its finalized revision.
pub async fn get_current_permission_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    policy: &str,
    access: &hub_permission::AccessRequest,
    minimum_height: u64,
) -> eyre::Result<hub_permission::PermissionResponse> {
    request(
        client,
        rpc_url,
        "hub_getCurrentPermissionProof",
        serde_json::json!([policy, access, minimum_height]),
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
