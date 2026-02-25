//! Low-level JSON-RPC helpers for contract interactions.

use std::time::Duration;

use alloy_primitives::{Address, U256};
use eyre::WrapErr;

/// Get the transaction count (nonce) for an address.
pub async fn get_transaction_count(
    client: &reqwest::Client,
    rpc_url: &str,
    address: Address,
) -> eyre::Result<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [format!("{address:?}"), "latest"],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("eth_getTransactionCount request")?
        .json()
        .await
        .wrap_err("eth_getTransactionCount response")?;

    check_rpc_error(&resp, "eth_getTransactionCount")?;

    let hex = resp["result"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("eth_getTransactionCount: missing result"))?;
    hex_to_u64(hex)
}

/// Submit a signed transaction via `eth_sendRawTransaction`.
///
/// Returns the transaction hash as a hex string (with 0x prefix).
pub async fn send_raw_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    raw_tx: &[u8],
) -> eyre::Result<String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [format!("0x{}", hex::encode(raw_tx))],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("eth_sendRawTransaction request")?
        .json()
        .await
        .wrap_err("eth_sendRawTransaction response")?;

    check_rpc_error(&resp, "eth_sendRawTransaction")?;

    resp["result"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| eyre::eyre!("eth_sendRawTransaction: missing result"))
}

/// Poll for a transaction receipt until it appears or the attempt limit is reached.
pub async fn poll_receipt(
    client: &reqwest::Client,
    rpc_url: &str,
    tx_hash: &str,
    interval: Duration,
    max_attempts: u32,
) -> eyre::Result<serde_json::Value> {
    for _ in 0..max_attempts {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
        });

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .wrap_err("eth_getTransactionReceipt request")?
            .json()
            .await
            .wrap_err("eth_getTransactionReceipt response")?;

        check_rpc_error(&resp, "eth_getTransactionReceipt")?;

        if !resp["result"].is_null() {
            return Ok(resp["result"].clone());
        }

        tokio::time::sleep(interval).await;
    }

    Err(eyre::eyre!(
        "receipt not available after {max_attempts} attempts for tx {tx_hash}"
    ))
}

/// Read a storage slot via `eth_getStorageAt`.
pub async fn get_storage_at(
    client: &reqwest::Client,
    rpc_url: &str,
    address: Address,
    slot: U256,
) -> eyre::Result<U256> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [format!("{address:?}"), format!("{slot:#066x}"), "latest"],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("eth_getStorageAt request")?
        .json()
        .await
        .wrap_err("eth_getStorageAt response")?;

    check_rpc_error(&resp, "eth_getStorageAt")?;

    let hex = resp["result"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("eth_getStorageAt: missing result"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    // Left-pad to even length (hub may return "0x0" for zero slots).
    let padded = if hex.len() % 2 != 0 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes = hex::decode(&padded).wrap_err("decoding eth_getStorageAt result")?;
    Ok(U256::from_be_slice(&bytes))
}

/// Get the native ETH balance for an address via `eth_getBalance`.
pub async fn get_balance(
    client: &reqwest::Client,
    rpc_url: &str,
    address: Address,
) -> eyre::Result<U256> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [format!("{address:?}"), "latest"],
        "id": 1,
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("eth_getBalance request")?
        .json()
        .await
        .wrap_err("eth_getBalance response")?;

    check_rpc_error(&resp, "eth_getBalance")?;

    let hex = resp["result"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("eth_getBalance: missing result"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = if hex.len() % 2 != 0 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes = hex::decode(&padded).wrap_err("decoding eth_getBalance result")?;
    Ok(U256::from_be_slice(&bytes))
}

/// Parse a hex string (with optional 0x prefix) to u64.
pub fn hex_to_u64(hex: &str) -> eyre::Result<u64> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).wrap_err_with(|| format!("parsing hex {hex}"))
}

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
