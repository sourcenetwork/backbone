//! Contract deployment via JSON-RPC.
//!
//! Builds a legacy CREATE transaction, signs it with a test account,
//! submits via `eth_sendRawTransaction`, and polls for the receipt.

use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::WrapErr;

use super::rpc;

/// Receipt from a successful contract deployment.
#[derive(Debug)]
pub struct DeployReceipt {
    /// Transaction hash.
    pub tx_hash: String,
    /// Deployed contract address.
    pub contract_address: Address,
    /// Block number the transaction was included in.
    pub block_number: u64,
}

/// Deploy a contract to the cluster.
///
/// Sends a CREATE transaction with the given `bytecode` signed by `signer`,
/// then polls until the receipt is available.
///
/// `nonce` must be the sender's current nonce. Callers are responsible for
/// tracking nonces across sequential transactions from the same account.
pub async fn deploy(
    client: &reqwest::Client,
    rpc_url: &str,
    signer: &PrivateKeySigner,
    chain_id: u64,
    bytecode: Vec<u8>,
    nonce: u64,
) -> eyre::Result<DeployReceipt> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 5_000_000,
        to: TxKind::Create,
        value: U256::ZERO,
        input: Bytes::from(bytecode),
    };

    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .wrap_err("signing deploy transaction")?;
    let signed = tx.into_signed(sig);
    let raw = signed.encoded_2718();

    let tx_hash = rpc::send_raw_transaction(client, rpc_url, &raw).await?;
    let receipt =
        rpc::poll_receipt(client, rpc_url, &tx_hash, Duration::from_millis(200), 50).await?;

    let status = receipt
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("deploy receipt missing status"))?;
    if status != "0x1" {
        return Err(eyre::eyre!("deploy transaction reverted (status={status})"));
    }

    let contract_address = receipt
        .get("contractAddress")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre::eyre!("receipt missing contractAddress"))?
        .parse::<Address>()
        .wrap_err("parsing contract address")?;

    let block_number = rpc::hex_to_u64(
        receipt
            .get("blockNumber")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("receipt missing blockNumber"))?,
    )?;

    Ok(DeployReceipt {
        tx_hash,
        contract_address,
        block_number,
    })
}
