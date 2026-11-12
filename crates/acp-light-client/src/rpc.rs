//! Bounded JSON-RPC transport for proof and finalized-revision responses.

use std::time::Duration;

use eyre::WrapErr;
use serde::de::DeserializeOwned;

use crate::transport::{AcpTransport, HttpWsTransport};
use crate::types::{LightBlock, ModuleId};

/// Maximum light-block response, including hex-encoded block and consensus material.
pub use vera_domain::LIGHT_BLOCK_RESPONSE_BYTES;
/// Maximum current permission response, including finalization and the RPC envelope.
pub use vera_permission::PERMISSION_RESPONSE_BYTES;
/// Maximum native record response, including finalization and the RPC envelope.
pub use vera_permission::RECORD_RESPONSE_BYTES;

/// Fetch current record evidence paired with its finalized revision.
pub async fn get_current_record_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    module: ModuleId,
    key: &[u8],
    minimum_height: u64,
) -> eyre::Result<vera_permission::RecordResponse> {
    record_proof(&http(client, rpc_url), module, key, minimum_height).await
}

/// Fetch complete current prefix evidence paired with its finalized revision.
pub async fn get_current_prefix_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    module: ModuleId,
    prefix: &[u8],
    minimum_height: u64,
) -> eyre::Result<vera_permission::PrefixResponse> {
    fetch(
        &http(client, rpc_url),
        "vera_getCurrentPrefixProof",
        serde_json::json!([module, format!("0x{}", hex::encode(prefix)), minimum_height]),
        RECORD_RESPONSE_BYTES,
    )
    .await
}

/// Fetch policy liveness and complete relationship evidence at the same finalized revision.
pub async fn get_current_policy_prefix_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    policy: &str,
    prefix: &[u8],
    minimum_height: u64,
) -> eyre::Result<vera_permission::PolicyPrefixResponse> {
    policy_prefix_proof(&http(client, rpc_url), policy, prefix, minimum_height).await
}

/// Fetch a finalized block and its certificate.
pub async fn get_light_block(
    client: &reqwest::Client,
    rpc_url: &str,
    height: u64,
) -> eyre::Result<LightBlock> {
    light_block(&http(client, rpc_url), height).await
}

/// Fetch current permission evidence paired with its finalized revision.
pub async fn get_current_permission_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    policy: &str,
    access: &vera_permission::AccessRequest,
    minimum_height: u64,
) -> eyre::Result<vera_permission::PermissionResponse> {
    permission_proof(&http(client, rpc_url), policy, access, minimum_height).await
}

pub(crate) async fn record_proof(
    transport: &dyn AcpTransport,
    module: ModuleId,
    key: &[u8],
    minimum_height: u64,
) -> eyre::Result<vera_permission::RecordResponse> {
    fetch(
        transport,
        "vera_getCurrentRecordProof",
        serde_json::json!([module, format!("0x{}", hex::encode(key)), minimum_height]),
        RECORD_RESPONSE_BYTES,
    )
    .await
}

pub(crate) async fn policy_prefix_proof(
    transport: &dyn AcpTransport,
    policy: &str,
    prefix: &[u8],
    minimum_height: u64,
) -> eyre::Result<vera_permission::PolicyPrefixResponse> {
    vera_permission::validate_policy_prefix(policy, prefix)?;
    fetch(
        transport,
        "vera_getCurrentPolicyPrefixProof",
        serde_json::json!([policy, format!("0x{}", hex::encode(prefix)), minimum_height]),
        RECORD_RESPONSE_BYTES,
    )
    .await
}

pub(crate) async fn light_block(
    transport: &dyn AcpTransport,
    height: u64,
) -> eyre::Result<LightBlock> {
    fetch(
        transport,
        "vera_getLightBlock",
        serde_json::json!([height]),
        LIGHT_BLOCK_RESPONSE_BYTES,
    )
    .await
}

pub(crate) async fn permission_proof(
    transport: &dyn AcpTransport,
    policy: &str,
    access: &vera_permission::AccessRequest,
    minimum_height: u64,
) -> eyre::Result<vera_permission::PermissionResponse> {
    fetch(
        transport,
        "vera_getCurrentPermissionProof",
        serde_json::json!([policy, access, minimum_height]),
        PERMISSION_RESPONSE_BYTES,
    )
    .await
}

fn http(client: &reqwest::Client, rpc_url: &str) -> HttpWsTransport {
    HttpWsTransport::from_client(client.clone(), rpc_url)
}

async fn fetch<T: DeserializeOwned>(
    transport: &dyn AcpTransport,
    method: &'static str,
    params: serde_json::Value,
    maximum: usize,
) -> eyre::Result<T> {
    let result = transport.call(method, params, maximum).await?;
    serde_json::from_value(result).wrap_err_with(|| format!("deserializing {method} result"))
}

pub(crate) async fn http_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
    maximum: usize,
) -> eyre::Result<serde_json::Value> {
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
    value
        .get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| eyre::eyre!("{method} RPC response has no result"))
}
