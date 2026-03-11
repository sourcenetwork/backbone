#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, FixedBytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall};

pub const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const HARDHAT_KEY_1: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const ACP_PRECOMPILE_ADDRESS: &str = "0x0000000000000000000000000000000000000810";
const HUB_EVM_GAS_PRICE: u128 = 1_000_000_000;
const HUB_EVM_GAS_LIMIT: u64 = 5_000_000;

sol! {
    interface IAcpHarness {
        function batchCalls(bytes[] calls) external returns (bytes[] results);

        function setRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external returns (bool recordExisted, bytes record);

        function deleteRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external returns (bool recordFound);
    }
}

#[derive(Clone, Copy)]
pub enum AcpRelationshipTxKind {
    Set,
    Delete,
}

#[derive(Clone, Copy)]
pub struct AcpRelationshipTx<'a> {
    pub kind: AcpRelationshipTxKind,
    pub policy_id: &'a str,
    pub resource: &'a str,
    pub object_id: &'a str,
    pub relation: &'a str,
    pub actor: &'a str,
}

pub struct HubdCli {
    binary: PathBuf,
    rpc_url: String,
    chain_id: u64,
    key: String,
}

impl HubdCli {
    pub fn new(binary: PathBuf, rpc_url: &str, chain_id: u64, key: &str) -> Self {
        Self {
            binary,
            rpc_url: rpc_url.to_string(),
            chain_id,
            key: key.to_string(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.args([
            "client",
            "--url",
            &self.rpc_url,
            "--key",
            &self.key,
            "--client-chain-id",
            &self.chain_id.to_string(),
            "--compact",
        ]);
        cmd
    }

    fn exec(&self, args: &[&str]) -> eyre::Result<String> {
        let output = self.cmd().args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(eyre::eyre!(
                "hubd client {} failed ({}): stderr={}, stdout={}",
                args.join(" "),
                output.status,
                stderr.trim(),
                stdout.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn create_policy(&self, yaml: &str) -> eyre::Result<String> {
        let before: Vec<String> =
            serde_json::from_str(&self.exec(&["acp", "list-policies"])?).unwrap_or_default();

        self.exec(&["acp", "create-policy", yaml])?;

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let after_output = self.exec(&["acp", "list-policies"])?;
            let after: Vec<String> = serde_json::from_str(&after_output)
                .map_err(|e| eyre::eyre!("parse list-policies '{}': {}", after_output, e))?;
            let new_ids: Vec<&String> = after.iter().filter(|id| !before.contains(id)).collect();
            match new_ids.len() {
                1 => return Ok(new_ids[0].clone()),
                n if n > 1 => {
                    return Err(eyre::eyre!(
                        "expected 1 new policy ID, got {}: {:?}",
                        n,
                        new_ids
                    ))
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre::eyre!("no new policy ID found after 30s polling"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn list_policies(&self) -> eyre::Result<String> {
        self.exec(&["acp", "list-policies"])
    }

    pub fn register_object(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> eyre::Result<String> {
        self.exec(&["acp", "register-object", policy_id, resource, object_id])
    }

    pub fn set_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<String> {
        self.exec(&[
            "acp",
            "set-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor,
        ])
    }

    pub fn delete_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<String> {
        self.exec(&[
            "acp",
            "delete-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor,
        ])
    }

    pub fn register_namespace(&self, namespace: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "register-namespace", namespace])
    }

    pub fn add_collaborator(&self, namespace: &str, did: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "add-collaborator", namespace, did])
    }

    pub fn list_posts(&self, namespace: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "list-posts", "--namespace", namespace])
    }

    pub fn fund_evm_address(&self, to_address: &str, value_wei: &str) -> eyre::Result<String> {
        let nonce = self.get_evm_nonce(HARDHAT_KEY_1)?;
        let raw_tx = sign_eth_transfer(HARDHAT_KEY_1, to_address, value_wei, nonce, self.chain_id);
        let tx_hash = self.send_raw_evm_tx(&raw_tx)?;
        self.wait_for_tx_receipt(&tx_hash)?;
        Ok(tx_hash)
    }

    pub fn submit_batch_acp_calls_raw(&self, calls: Vec<Vec<u8>>) -> eyre::Result<String> {
        let nonce = self.get_evm_nonce(&self.key)?;
        let calldata = IAcpHarness::batchCallsCall {
            calls: calls.into_iter().map(Into::into).collect(),
        }
        .abi_encode();
        let raw_tx = sign_evm_call(
            &self.key,
            acp_precompile_address(),
            calldata.into(),
            nonce,
            self.chain_id,
        );
        self.send_raw_evm_tx(&raw_tx)
    }

    pub fn wait_for_tx_receipt(&self, tx_hash: &str) -> eyre::Result<()> {
        for _attempt in 0..400 {
            let body = format!(
                r#"{{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["{}"],"id":1}}"#,
                tx_hash
            );
            let output = Command::new("curl")
                .args([
                    "-s",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &body,
                    &self.rpc_url,
                ])
                .output()
                .map_err(|e| eyre::eyre!("curl eth_getTransactionReceipt: {}", e))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                if json.get("result").is_some_and(|v| !v.is_null()) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        eyre::bail!("receipt not available after 400 attempts for {}", tx_hash)
    }

    pub fn get_evm_nonce(&self, key_hex: &str) -> eyre::Result<u64> {
        let key_bytes = hex::decode(key_hex).map_err(|e| eyre::eyre!("invalid key hex: {}", e))?;
        let signer = PrivateKeySigner::from_slice(&key_bytes)
            .map_err(|e| eyre::eyre!("invalid signing key: {}", e))?;
        let address = format!("{:?}", signer.address());
        self.get_evm_nonce_for_address(&address)
    }

    fn send_raw_evm_tx(&self, raw_tx: &[u8]) -> eyre::Result<String> {
        let result = self.exec(&["tx", "send-raw", &hex::encode(raw_tx)])?;
        let json: serde_json::Value = serde_json::from_str(result.trim())
            .map_err(|e| eyre::eyre!("parse send-raw response: {}", e))?;
        json.get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("no tx_hash in send-raw response: {}", result))
            .map(|tx_hash| tx_hash.to_string())
    }

    fn get_evm_nonce_for_address(&self, address: &str) -> eyre::Result<u64> {
        let body = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{}","latest"],"id":1}}"#,
            address
        );
        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
                &self.rpc_url,
            ])
            .output()
            .map_err(|e| eyre::eyre!("curl eth_getTransactionCount: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|e| eyre::eyre!("parse nonce response '{}': {}", stdout.trim(), e))?;
        let hex_nonce = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("no result in nonce response: {}", stdout.trim()))?;
        let nonce = u64::from_str_radix(hex_nonce.trim_start_matches("0x"), 16)
            .map_err(|e| eyre::eyre!("parse hex nonce '{}': {}", hex_nonce, e))?;
        Ok(nonce)
    }
}

pub fn submit_acp_relationship_txs(
    hub_cli: &HubdCli,
    txs: &[AcpRelationshipTx<'_>],
) -> eyre::Result<String> {
    let calls = txs
        .iter()
        .map(|tx| match tx.kind {
            AcpRelationshipTxKind::Set => Ok(IAcpHarness::setRelationshipCall {
                policyId: parse_policy_id_bytes32(tx.policy_id)?,
                resource: tx.resource.to_string(),
                objectId: tx.object_id.to_string(),
                relation: tx.relation.to_string(),
                actor: tx.actor.to_string(),
            }
            .abi_encode()),
            AcpRelationshipTxKind::Delete => Ok(IAcpHarness::deleteRelationshipCall {
                policyId: parse_policy_id_bytes32(tx.policy_id)?,
                resource: tx.resource.to_string(),
                objectId: tx.object_id.to_string(),
                relation: tx.relation.to_string(),
                actor: tx.actor.to_string(),
            }
            .abi_encode()),
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    hub_cli.submit_batch_acp_calls_raw(calls)
}

pub fn evm_address_from_private_key(key_hex: &str) -> String {
    let key_bytes = hex::decode(key_hex).expect("valid hex key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("valid signing key");
    format!("{:#x}", signer.address())
}

fn sign_eth_transfer(
    from_key_hex: &str,
    to: &str,
    value_wei: &str,
    nonce: u64,
    chain_id: u64,
) -> Vec<u8> {
    let key_bytes = hex::decode(from_key_hex).expect("valid hex key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("valid signing key");

    let to_addr: Address = to.parse().expect("valid to address");
    let value = value_wei.parse::<U256>().expect("valid wei value");

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 0,
        gas_limit: 21_000,
        to: TxKind::Call(to_addr),
        value,
        input: Default::default(),
    };

    let sig_hash = tx.signature_hash();
    let sig = signer.sign_hash_sync(&sig_hash).expect("sign transfer");
    let signed = tx.into_signed(sig);
    signed.encoded_2718()
}

fn sign_evm_call(
    from_key_hex: &str,
    to: Address,
    calldata: Bytes,
    nonce: u64,
    chain_id: u64,
) -> Vec<u8> {
    let key_bytes = hex::decode(from_key_hex).expect("valid hex key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("valid signing key");

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: HUB_EVM_GAS_PRICE,
        gas_limit: HUB_EVM_GAS_LIMIT,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: calldata,
    };

    let sig_hash = tx.signature_hash();
    let sig = signer.sign_hash_sync(&sig_hash).expect("sign evm call");
    let signed = tx.into_signed(sig);
    signed.encoded_2718()
}

fn acp_precompile_address() -> Address {
    ACP_PRECOMPILE_ADDRESS
        .parse()
        .expect("valid ACP precompile address")
}

fn parse_policy_id_bytes32(policy_id: &str) -> eyre::Result<FixedBytes<32>> {
    let hex_policy_id = policy_id.strip_prefix("0x").unwrap_or(policy_id);
    let bytes = hex::decode(hex_policy_id)
        .map_err(|e| eyre::eyre!("decode policy id '{}': {}", policy_id, e))?;
    if bytes.len() != 32 {
        eyre::bail!(
            "policy id '{}' should be 32 bytes, got {}",
            policy_id,
            bytes.len()
        );
    }
    Ok(FixedBytes::<32>::from_slice(&bytes))
}
