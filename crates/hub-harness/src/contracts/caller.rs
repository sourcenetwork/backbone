//! State-changing contract calls via `eth_sendRawTransaction`.
//!
//! Callers provide an explicit nonce and are responsible for tracking
//! nonces across sequential transactions from the same account.

use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::WrapErr;

use super::rpc;

/// State-changing contract call via `eth_sendRawTransaction`.
///
/// `nonce` must be the sender's current nonce. Callers are responsible for
/// tracking nonces across sequential transactions from the same account.
///
/// Returns the transaction receipt as raw JSON.
pub async fn send(
    client: &reqwest::Client,
    rpc_url: &str,
    signer: &PrivateKeySigner,
    chain_id: u64,
    contract: Address,
    calldata: Vec<u8>,
    nonce: u64,
) -> eyre::Result<serde_json::Value> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 5_000_000,
        to: TxKind::Call(contract),
        value: U256::ZERO,
        input: Bytes::from(calldata),
    };

    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .wrap_err("signing contract call")?;
    let signed = tx.into_signed(sig);
    let raw = signed.encoded_2718();

    let tx_hash = rpc::send_raw_transaction(client, rpc_url, &raw).await?;
    rpc::poll_receipt(client, rpc_url, &tx_hash, Duration::from_millis(200), 100).await
}
