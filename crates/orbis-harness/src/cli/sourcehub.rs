use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use eyre::{eyre, Result};
use sourcehub_harness::SourceHubNode;

/// Gas limit for every harness transaction.
///
/// The first `register-namespace` also creates the bulletin module's ACP
/// policy, which writes the whole policy and its relationships in one message.
/// The Cosmos gas meter panics rather than returning an error when a write
/// exceeds the limit, so an under-provisioned limit surfaces as an opaque
/// `recovered from panic: {WriteFlat}` rather than "out of gas".
const TX_GAS_LIMIT: u64 = 3_000_000;

/// Fee paid per harness transaction. The devnet's validator account is funded
/// with far more than the suite spends.
const TX_FEE_UOPEN: u64 = 300_000;

/// Default amount [`SourceHubCliClient::fund`] sends.
const DEFAULT_FUND_UOPEN: u128 = 1_000_000;

/// Outcome of broadcasting one transaction through `verad tx`.
enum TxOutcome {
    /// CheckTx accepted the transaction.
    Accepted,
    /// The signer's cached sequence was stale; retrying is worthwhile.
    SequenceMismatch,
    Failed(String),
}

pub struct SourceHubCliClient {
    binary_path: PathBuf,
    home_dir: PathBuf,
    node_url: String,
    chain_id: String,
}

impl SourceHubCliClient {
    pub fn from_node(node: &SourceHubNode) -> Result<Self> {
        Ok(Self {
            binary_path: sourcehub_harness::resolve_binary()?,
            home_dir: node.home_dir.clone(),
            node_url: node.comet_rpc_url.clone(),
            chain_id: node.chain_id.clone(),
        })
    }

    pub fn new(
        binary_path: impl Into<PathBuf>,
        home_dir: impl Into<PathBuf>,
        node_url: impl Into<String>,
        chain_id: impl Into<String>,
    ) -> Self {
        Self {
            binary_path: binary_path.into(),
            home_dir: home_dir.into(),
            node_url: node_url.into(),
            chain_id: chain_id.into(),
        }
    }

    fn tx_args(&self) -> Vec<String> {
        vec![
            "--home".to_string(),
            self.home_dir.display().to_string(),
            "--node".to_string(),
            self.node_url.clone(),
            "--chain-id".to_string(),
            self.chain_id.clone(),
            "--from".to_string(),
            "validator".to_string(),
            "--keyring-backend".to_string(),
            "test".to_string(),
            "-y".to_string(),
            "-o".to_string(),
            "json".to_string(),
            "--gas".to_string(),
            TX_GAS_LIMIT.to_string(),
            "--fees".to_string(),
            format!("{}uopen", TX_FEE_UOPEN),
        ]
    }

    fn query_args(&self) -> Vec<String> {
        vec![
            "--node".to_string(),
            self.node_url.clone(),
            "--chain-id".to_string(),
            self.chain_id.clone(),
            "-o".to_string(),
            "json".to_string(),
        ]
    }

    fn exec(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(&self.binary_path)
            .args(args)
            .output()
            .map_err(|e| {
                eyre!(
                    "failed to exec: {} {}: {}",
                    self.binary_path.display(),
                    args.join(" "),
                    e
                )
            })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(eyre!(
                "verad failed (exit {}): stderr={}, stdout={}",
                output.status,
                stderr.trim(),
                stdout.trim(),
            ))
        }
    }

    /// Broadcast a transaction, retrying a stale sequence, and return its
    /// **committed** result.
    ///
    /// A `verad tx` broadcast reports only CheckTx: code 0 means "accepted into
    /// the mempool", not "executed". An ACP denial, an out-of-gas, or any other
    /// execution failure appears only once the transaction is in a block. This
    /// waits for that and fails on a non-zero delivered code, so a caller that
    /// gets `Ok` knows the state change actually happened.
    fn exec_tx(&self, subcommand_args: &[&str]) -> Result<serde_json::Value> {
        for attempt in 0..5 {
            let tx_args = self.tx_args();
            let mut args: Vec<&str> = subcommand_args.to_vec();
            for a in &tx_args {
                args.push(a);
            }

            let broadcast = match self.exec(&args) {
                Ok(stdout) => Self::parse_broadcast(&stdout),
                Err(e) => {
                    if format!("{}", e).contains("account sequence mismatch") {
                        Err(TxOutcome::SequenceMismatch)
                    } else {
                        Err(TxOutcome::Failed(format!("{}", e)))
                    }
                }
            };

            match broadcast {
                Ok(tx_hash) => return self.wait_for_tx(&tx_hash),
                Err(TxOutcome::SequenceMismatch) if attempt < 4 => {
                    tracing::warn!(attempt, "exec_tx: sequence mismatch, retrying");
                    std::thread::sleep(Duration::from_secs(2));
                }
                Err(TxOutcome::SequenceMismatch) => {
                    return Err(eyre!(
                        "{}: account sequence mismatch after 5 attempts",
                        subcommand_args.join(" ")
                    ))
                }
                Err(TxOutcome::Failed(err)) => {
                    return Err(eyre!("{} failed: {}", subcommand_args.join(" "), err))
                }
                Err(TxOutcome::Accepted) => unreachable!("parse_broadcast returns a hash"),
            }
        }
        Err(eyre!("exec_tx: exhausted retries"))
    }

    /// Extract the transaction hash from a broadcast result, or classify why
    /// there is none.
    fn parse_broadcast(stdout: &str) -> std::result::Result<String, TxOutcome> {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            let code = v.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
            let raw_log = v.get("raw_log").and_then(|rl| rl.as_str()).unwrap_or("");
            if code != 0 {
                if raw_log.contains("account sequence mismatch") {
                    return Err(TxOutcome::SequenceMismatch);
                }
                return Err(TxOutcome::Failed(format!(
                    "broadcast rejected (code {}): {}",
                    code, raw_log
                )));
            }
            return match v.get("txhash").and_then(|h| h.as_str()) {
                Some(hash) => Ok(hash.to_string()),
                None => Err(TxOutcome::Failed(format!(
                    "broadcast result has no txhash: {}",
                    trimmed
                ))),
            };
        }
        Err(TxOutcome::Failed(format!(
            "no broadcast result in output: {}",
            stdout.trim()
        )))
    }

    /// Poll `query tx` until the transaction is in a block, then require a
    /// zero delivered code.
    fn wait_for_tx(&self, tx_hash: &str) -> Result<serde_json::Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(result) = self.exec_query(&["query", "tx", tx_hash]) {
                let code = result.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                if code != 0 {
                    let raw_log = result
                        .get("raw_log")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(no raw_log)");
                    return Err(eyre!("tx {} failed (code {}): {}", tx_hash, code, raw_log));
                }
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre!("tx {} was not committed within 60s", tx_hash));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn exec_query(&self, subcommand_args: &[&str]) -> Result<serde_json::Value> {
        let query_args = self.query_args();
        let mut args: Vec<&str> = subcommand_args.to_vec();
        for a in &query_args {
            args.push(a);
        }
        let stdout = self.exec(&args)?;
        serde_json::from_str(&stdout)
            .map_err(|e| eyre!("failed to parse query JSON: {}: stdout={}", e, stdout))
    }

    pub fn create_policy(&self, yaml: &str) -> Result<String> {
        // Write policy YAML to temp file
        let tmp = self.home_dir.join("tmp_policy.yaml");
        std::fs::write(&tmp, yaml)?;

        // Snapshot policy IDs before
        let before = self.list_policy_ids()?;

        self.exec_tx(&[
            "tx",
            "acp",
            "create-policy",
            tmp.to_str().ok_or_else(|| eyre!("invalid path"))?,
        ])?;
        // `exec_tx` already waited for the transaction to be committed, so the
        // policy is normally queryable at once; poll briefly for the query
        // node to catch up rather than sleeping a fixed interval first, which
        // would put a floor under every measurement of this call.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let new_id = loop {
            let after = self.list_policy_ids()?;
            if let Some(id) = after.into_iter().find(|id| !before.contains(id)) {
                break id;
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre!(
                    "policy creation succeeded but no new policy ID found"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        let _ = std::fs::remove_file(&tmp);
        Ok(new_id)
    }

    /// Number of policies registered on the chain.
    ///
    /// Chain state grows per tenant, so this is the per-tenant chain cost a
    /// scale test reports.
    pub fn list_policy_count(&self) -> Result<usize> {
        Ok(self.list_policy_ids()?.len())
    }

    fn list_policy_ids(&self) -> Result<Vec<String>> {
        let result = self.exec_query(&["query", "acp", "policy-ids"])?;
        // Response has {"ids": ["abc...", "def..."]} or {"policy_ids": [...]}
        let ids = result
            .pointer("/ids")
            .or_else(|| result.pointer("/policy_ids"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(ids
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect())
    }

    /// Register `object_id` under `resource` in `policy_id`.
    ///
    /// Argument order matches the `verad` command and the rest of this client:
    /// policy, resource, object.
    pub fn register_object(&self, policy_id: &str, resource: &str, object_id: &str) -> Result<()> {
        self.exec_tx(&[
            "tx",
            "acp",
            "direct-policy-cmd",
            "register-object",
            policy_id,
            resource,
            object_id,
        ])?;
        Ok(())
    }

    pub fn set_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor_did: &str,
    ) -> Result<()> {
        self.exec_tx(&[
            "tx",
            "acp",
            "direct-policy-cmd",
            "set-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor_did,
        ])?;
        Ok(())
    }

    pub fn delete_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor_did: &str,
    ) -> Result<()> {
        self.exec_tx(&[
            "tx",
            "acp",
            "direct-policy-cmd",
            "delete-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor_did,
        ])?;
        Ok(())
    }

    /// Ask Vera directly whether `actor_did` holds `permission` on
    /// `resource:object_id` under `policy_id`, bypassing every client cache.
    ///
    /// This is the authoritative answer both DefraDB's query gate and the
    /// Orbis signing gate converge on; tests use it as the reference clock.
    pub fn verify_access(
        &self,
        policy_id: &str,
        actor_did: &str,
        resource: &str,
        object_id: &str,
        permission: &str,
    ) -> Result<bool> {
        let operation = format!("{}:{}#{}", resource, object_id, permission);
        let result = self.exec_query(&[
            "query",
            "acp",
            "verify-access-request",
            policy_id,
            actor_did,
            &operation,
        ])?;
        result
            .get("valid")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| eyre!("verify-access-request response has no `valid`: {}", result))
    }

    /// Owner DID of a registered object, or `None` when it is unregistered.
    pub fn object_owner(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<Option<String>> {
        let result = self.exec_query(&[
            "query",
            "acp",
            "object-owner",
            policy_id,
            resource,
            object_id,
        ])?;
        let registered = result
            .get("is_registered")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !registered {
            return Ok(None);
        }
        // QueryObjectOwnerResponse carries the owner as the subject of the
        // `owner` RelationshipRecord (`proto/vera/acp/record.proto`).
        Ok(result
            .pointer("/record/relationship/subject/actor/id")
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    pub fn register_namespace(&self, namespace: &str) -> Result<()> {
        self.exec_tx(&["tx", "bulletin", "register-namespace", namespace])?;
        Ok(())
    }

    pub fn add_collaborator(&self, namespace: &str, address: &str) -> Result<()> {
        self.exec_tx(&["tx", "bulletin", "add-collaborator", namespace, address])?;
        Ok(())
    }

    pub fn create_post(
        &self,
        namespace: &str,
        payload_hex: &str,
        proof_hex: &str,
    ) -> Result<String> {
        let result = self.exec_tx(&[
            "tx",
            "bulletin",
            "create-post",
            namespace,
            payload_hex,
            proof_hex,
        ])?;
        // Extract post_id from tx events
        extract_event_attr(&result, "bulletin_post", "post_id")
            .ok_or_else(|| eyre!("no post_id in create-post response"))
    }

    pub fn read_post(&self, namespace: &str, id: &str) -> Result<Vec<u8>> {
        let result = self.exec_query(&["query", "bulletin", "post", namespace, id])?;
        let payload_str = result
            .pointer("/post/payload")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre!("no payload in post response"))?;
        // Payload is base64-encoded in the query response
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload_str)
            .map_err(|e| eyre!("failed to decode post payload: {}", e))
    }

    pub fn get_account_sequence(&self, address: &str) -> Result<u64> {
        let result = self.exec_query(&["query", "auth", "account", address])?;
        let seq = result
            .pointer("/account/sequence")
            .or_else(|| result.pointer("/account/base_account/sequence"))
            .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|_| "").or(None)))
            .unwrap_or("0");
        seq.parse::<u64>()
            .or_else(|_| {
                result
                    .pointer("/account/sequence")
                    .or_else(|| result.pointer("/account/base_account/sequence"))
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| eyre!("invalid sequence"))
            })
            .map_err(|e| eyre!("failed to parse account sequence: {}", e))
    }

    /// Spendable `uopen` balance of `address`, or 0 when the account does not
    /// exist yet.
    pub fn balance(&self, address: &str) -> Result<u128> {
        let result = self.exec_query(&["query", "bank", "balances", address])?;
        let Some(balances) = result.get("balances").and_then(|v| v.as_array()) else {
            return Ok(0);
        };
        let total = balances
            .iter()
            .filter(|coin| coin.get("denom").and_then(|d| d.as_str()) == Some("uopen"))
            .filter_map(|coin| coin.get("amount").and_then(|a| a.as_str()))
            .filter_map(|amount| amount.parse::<u128>().ok())
            .sum();
        Ok(total)
    }

    /// Send `uopen` from the validator account to `address` and wait until the
    /// balance is actually visible on chain.
    ///
    /// Waiting matters: a Cosmos client caches the account number it reads at
    /// startup, and an account that does not exist yet reads as number 0. A
    /// process funded after it connected keeps signing with the stale number
    /// and every transaction fails signature verification, so callers must be
    /// able to rely on "funded" meaning the account exists.
    pub fn fund(&self, address: &str) -> Result<()> {
        self.fund_amount(address, DEFAULT_FUND_UOPEN)
    }

    /// Send `amount_uopen` from the validator account to `address` and wait
    /// until the balance is visible on chain.
    ///
    /// An Orbis node refuses to finish starting while its balance is below its
    /// own minimum, and it pays fees out of that balance as it works, so a node
    /// funded with exactly the minimum starves after its first transactions and
    /// blocks on the next restart. Fund with headroom.
    pub fn fund_amount(&self, address: &str, amount_uopen: u128) -> Result<()> {
        let amount = format!("{}uopen", amount_uopen);
        let amount = amount.as_str();
        let before = self.balance(address).unwrap_or(0);
        for attempt in 0..5 {
            let args_owned = vec![
                "tx".to_string(),
                "bank".to_string(),
                "send".to_string(),
                "validator".to_string(),
                address.to_string(),
                amount.to_string(),
                "--home".to_string(),
                self.home_dir.display().to_string(),
                "--node".to_string(),
                self.node_url.clone(),
                "--chain-id".to_string(),
                self.chain_id.clone(),
                "--from".to_string(),
                "validator".to_string(),
                "--keyring-backend".to_string(),
                "test".to_string(),
                "-y".to_string(),
                "-o".to_string(),
                "json".to_string(),
                "--gas".to_string(),
                "200000".to_string(),
                "--fees".to_string(),
                "10000uopen".to_string(),
            ];
            let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
            let broadcast = match self.exec(&args) {
                Ok(stdout) => Self::classify_tx_output(&stdout),
                Err(e) => {
                    if format!("{}", e).contains("account sequence mismatch") {
                        TxOutcome::SequenceMismatch
                    } else {
                        TxOutcome::Failed(format!("{}", e))
                    }
                }
            };

            match broadcast {
                TxOutcome::Accepted => {
                    return self.wait_for_balance(address, before + amount_uopen);
                }
                TxOutcome::SequenceMismatch if attempt < 4 => {
                    tracing::warn!(attempt, "fund: sequence mismatch, retrying");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                TxOutcome::SequenceMismatch => {
                    return Err(eyre!(
                        "fund {}: account sequence mismatch after 5 attempts",
                        address
                    ))
                }
                TxOutcome::Failed(err) => return Err(eyre!("fund {} failed: {}", address, err)),
            }
        }
        Err(eyre!("fund: exhausted retries for {}", address))
    }

    /// Poll until `address` holds at least `target` uopen.
    fn wait_for_balance(&self, address: &str, target: u128) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let balance = self.balance(address).unwrap_or(0);
            if balance >= target {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre!(
                    "fund {}: balance {} did not reach {} within 30s",
                    address,
                    balance,
                    target
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Classify a `verad tx` JSON result: CheckTx accepted, a sequence race, or
    /// a real failure. Output that carries no JSON object is a failure, never a
    /// silent success.
    fn classify_tx_output(stdout: &str) -> TxOutcome {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            let code = v.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
            if code == 0 {
                return TxOutcome::Accepted;
            }
            let raw_log = v.get("raw_log").and_then(|rl| rl.as_str()).unwrap_or("");
            if raw_log.contains("account sequence mismatch") {
                return TxOutcome::SequenceMismatch;
            }
            return TxOutcome::Failed(format!("code {}: {}", code, raw_log));
        }
        TxOutcome::Failed(format!("no tx result in output: {}", stdout.trim()))
    }

    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }
}

fn extract_event_attr(
    tx_result: &serde_json::Value,
    event_type: &str,
    attr_key: &str,
) -> Option<String> {
    let events = tx_result
        .pointer("/events")
        .or_else(|| tx_result.pointer("/tx_result/events"))
        .and_then(|v| v.as_array())?;

    for event in events {
        let etype = event.get("type").and_then(|v| v.as_str())?;
        if etype == event_type {
            let attrs = event.get("attributes").and_then(|v| v.as_array())?;
            for attr in attrs {
                let key = attr.get("key").and_then(|v| v.as_str())?;
                if key == attr_key {
                    return attr
                        .get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }
    None
}
