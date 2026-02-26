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
