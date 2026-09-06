//! Low-level JSON-RPC helpers for hub.rs endpoints.

use eyre::WrapErr;

use crate::types::{LightBlock, ModuleStateProof};

/// Check for JSON-RPC error in response.
fn check_rpc_error(resp: &serde_json::Value, method: &str) -> eyre::Result<()> {
    if let Some(error) = resp.get("error") {
        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        return Err(eyre::eyre!("{method} RPC error ({code}): {message}"));
    }
    Ok(())
}

/// Fetch a module state proof via `hub_getStateProof`.
///
/// `key_hex` should be `0x`-prefixed hex-encoded key bytes.
pub async fn get_state_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    module: &str,
    key_hex: &str,
    height: u64,
) -> eyre::Result<ModuleStateProof> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "hub_getStateProof",
        "params": [module, key_hex, height],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("hub_getStateProof request")?
        .json()
        .await
        .wrap_err("hub_getStateProof response")?;

    check_rpc_error(&resp, "hub_getStateProof")?;

    serde_json::from_value(resp["result"].clone())
        .wrap_err("deserializing hub_getStateProof result")
}

/// Fetch a light block via `hub_getLightBlock`.
pub async fn get_light_block(
    client: &reqwest::Client,
    rpc_url: &str,
    height: u64,
) -> eyre::Result<LightBlock> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "hub_getLightBlock",
        "params": [height],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("hub_getLightBlock request")?
        .json()
        .await
        .wrap_err("hub_getLightBlock response")?;

    check_rpc_error(&resp, "hub_getLightBlock")?;

    serde_json::from_value(resp["result"].clone())
        .wrap_err("deserializing hub_getLightBlock result")
}

/// Fetch bounded complete permission evidence for the requested revision.
pub async fn get_permission_proof(
    client: &reqwest::Client,
    rpc_url: &str,
    policy: &str,
    request: &hub_permission::AccessRequest,
    height: u64,
) -> eyre::Result<hub_permission::PermissionProof> {
    let maximum = hub_permission::PERMISSION_LIMITS.proof_bytes + 1024;
    let mut response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "hub_getPermissionProof",
            "params": [policy, request, height],
        }))
        .send()
        .await?
        .error_for_status()?;
    eyre::ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= maximum as u64),
        "permission response exceeds byte limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        eyre::ensure!(
            chunk.len() <= maximum - bytes.len(),
            "permission response exceeds byte limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    eyre::ensure!(
        value["id"] == 1 && value["jsonrpc"] == "2.0",
        "permission RPC response metadata mismatch"
    );
    check_rpc_error(&value, "hub_getPermissionProof")?;
    let result = value
        .get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| eyre::eyre!("permission RPC response has no result"))?;
    Ok(serde_json::from_value(result)?)
}
