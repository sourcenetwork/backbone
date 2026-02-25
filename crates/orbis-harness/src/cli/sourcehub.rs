use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{eyre, Result};
use sourcehub_harness::SourceHubNode;

pub struct SourceHubCliClient {
    binary_path: PathBuf,
    home_dir: PathBuf,
    node_url: String,
    chain_id: String,
}

impl SourceHubCliClient {
    pub fn from_node(node: &SourceHubNode) -> Result<Self> {
        let resolved = test_infra::BinaryResolver::new("SOURCEHUBD", "sourcehubd").resolve()?;
        Ok(Self {
            binary_path: resolved.path,
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
            "auto".to_string(),
            "--gas-adjustment".to_string(),
            "1.3".to_string(),
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
                "sourcehubd failed (exit {}): stderr={}, stdout={}",
                output.status,
                stderr.trim(),
                stdout.trim(),
            ))
        }
    }

    fn exec_tx(&self, subcommand_args: &[&str]) -> Result<serde_json::Value> {
        let tx_args = self.tx_args();
        let mut args: Vec<&str> = subcommand_args.to_vec();
        for a in &tx_args {
            args.push(a);
        }
        let stdout = self.exec(&args)?;
        // tx output may include non-JSON lines; find the JSON object
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    return Ok(v);
                }
            }
        }
        // Try parsing the whole output
        serde_json::from_str(&stdout)
            .map_err(|e| eyre!("failed to parse tx JSON: {}: stdout={}", e, stdout))
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
            "SHORT_YAML",
            tmp.to_str().ok_or_else(|| eyre!("invalid path"))?,
        ])?;

        // Wait for tx to be included
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Find new policy ID
        let after = self.list_policy_ids()?;
        let new_id = after
            .into_iter()
            .find(|id| !before.contains(id))
            .ok_or_else(|| eyre!("policy creation succeeded but no new policy ID found"))?;

        let _ = std::fs::remove_file(&tmp);
        Ok(new_id)
    }

    fn list_policy_ids(&self) -> Result<Vec<String>> {
        let result = self.exec_query(&["query", "acp", "policies"])?;
        // Extract policy IDs from response
        let policies = result
            .pointer("/policies")
            .or_else(|| result.pointer("/policy"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(policies
            .iter()
            .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect())
    }

    pub fn register_object(&self, policy_id: &str, object_id: &str, resource: &str) -> Result<()> {
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

    pub fn fund(&self, address: &str) -> Result<()> {
        let amount = "1000000uopen";
        self.exec_tx(&["tx", "bank", "send", "validator", address, amount])?;
        Ok(())
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
