use std::path::PathBuf;
use std::process::Command;

use eyre::{eyre, Result};

use super::types::*;

pub struct OrbisCliClient {
    binary_path: PathBuf,
}

impl OrbisCliClient {
    pub fn new() -> Result<Self> {
        let mut resolver =
            test_infra::BinaryResolver::new("ORBIS_CLI", "cli-tool").cargo_package("cli-tool");
        if let Some(root) = test_infra::find_project_root() {
            resolver = resolver.sibling_symlink("backbone", root);
        }
        let resolved = resolver.resolve()?;
        Ok(Self {
            binary_path: resolved.path,
        })
    }

    pub fn from_binary(path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: path.into(),
        }
    }

    /// Run a cli-tool command and return stdout.
    fn exec(&self, args: &[&str]) -> Result<String> {
        self.exec_inner(args, false)
    }

    /// Run a cli-tool command with `--output json` and return stdout.
    fn exec_json(&self, args: &[&str]) -> Result<String> {
        self.exec_inner(args, true)
    }

    fn exec_inner(&self, args: &[&str], json_output: bool) -> Result<String> {
        let mut cmd = Command::new(&self.binary_path);
        if json_output {
            cmd.arg("--output").arg("json");
        }
        cmd.args(args);

        let output = cmd.output().map_err(|e| {
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
                "cli-tool failed (exit {}): stderr={}, stdout={}",
                output.status,
                stderr.trim(),
                stdout.trim(),
            ))
        }
    }

    /// Run a command with `--output json` and deserialize the result.
    fn parse<T: serde::de::DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let stdout = self.exec_json(args)?;
        serde_json::from_str(&stdout).map_err(|e| {
            eyre!(
                "failed to parse cli-tool JSON output: {}: stdout={}",
                e,
                stdout
            )
        })
    }

    pub fn query_node_info(&self, endpoint: &str) -> Result<NodeInfoResult> {
        // The cli-tool's `info` command doesn't support `--output json`,
        // so we parse the text output directly.
        let output = Command::new(&self.binary_path)
            .args(["info", "--endpoint", endpoint])
            .output()
            .map_err(|e| eyre!("failed to exec cli-tool info: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(eyre!("cli-tool info failed (exit {}): {}", output.status, stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut public_address = String::new();
        let mut peer_id = String::new();
        let mut p2p_address = String::new();

        for line in stdout.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("Public Address:") {
                public_address = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Peer ID:") {
                peer_id = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("P2P Address:") {
                p2p_address = val.trim().to_string();
            }
        }

        if peer_id.is_empty() {
            return Err(eyre!("cli-tool info: could not parse peer_id from output: {}", stdout));
        }

        Ok(NodeInfoResult {
            public_address,
            peer_id,
            p2p_address,
        })
    }

    /// Check if a node is responsive (exit code 0 from `info`).
    ///
    /// Unlike `query_node_info`, this doesn't try to parse JSON output.
    /// The cli-tool's `info` command doesn't support `--output json`,
    /// so we just check if the command succeeds.
    pub fn is_healthy(&self, endpoint: &str) -> bool {
        let output = std::process::Command::new(&self.binary_path)
            .args(["info", "--endpoint", endpoint])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        matches!(output, Ok(status) if status.success())
    }

    pub fn do_dkg(&self, endpoint: &str, threshold: u32, peer_ids: &[String]) -> Result<DkgResult> {
        let threshold_str = threshold.to_string();
        let mut args = vec!["dkg", "--endpoint", endpoint, "--threshold", &threshold_str];
        for pid in peer_ids {
            args.push("--peer-ids");
            args.push(pid);
        }
        // DKG command doesn't support --output json, parse text output.
        let stdout = self.exec(&args)?;
        let mut session_id = String::new();
        let mut status = String::new();
        let mut message = String::new();

        for line in stdout.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("Session ID:") {
                session_id = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Status:") {
                status = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Message:") {
                message = val.trim().to_string();
            }
        }

        if session_id.is_empty() {
            return Err(eyre!("cli-tool dkg: could not parse session_id from output: {}", stdout));
        }

        Ok(DkgResult {
            session_id,
            status,
            message,
        })
    }

    pub fn derive_public_key(
        &self,
        endpoint: &str,
        ring_id: &str,
        derivation_hex: &str,
    ) -> Result<DerivePublicKeyResult> {
        self.parse(&[
            "derive-public-key",
            "--endpoint",
            endpoint,
            "--ring-id",
            ring_id,
            "--derivation",
            derivation_hex,
        ])
    }

    pub fn do_sign(
        &self,
        endpoint: &str,
        ring_id: &str,
        message_hex: &str,
        derivation_hex: Option<&str>,
        signer_did_pk: Option<&str>,
        acp: Option<&SignAcpFields>,
    ) -> Result<SignResult> {
        let mut args = vec![
            "sign",
            "--endpoint",
            endpoint,
            "--ring-id",
            ring_id,
            "--message",
            message_hex,
        ];
        if let Some(d) = derivation_hex {
            args.push("--derivation");
            args.push(d);
        }
        if let Some(pk) = signer_did_pk {
            args.push("--signer-did-pk");
            args.push(pk);
        }
        if let Some(acp) = acp {
            args.push("--acp-policy-id");
            args.push(&acp.policy_id);
            args.push("--acp-resource");
            args.push(&acp.resource);
            args.push("--acp-object-id");
            args.push(&acp.object_id);
            args.push("--acp-permission");
            args.push(&acp.permission);
        }
        self.parse(&args)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_secret(
        &self,
        secret: &[u8],
        ring_pk_hex: &str,
        derivation_hex: Option<&str>,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<PreparedSecret> {
        let secret_str = String::from_utf8_lossy(secret);
        let mut args = vec![
            "prepare-secret",
            "--secret",
            &secret_str,
            "--ring-pk-hex",
            ring_pk_hex,
            "--policy-id",
            policy_id,
            "--resource",
            resource,
            "--permission",
            permission,
        ];
        if let Some(d) = derivation_hex {
            args.push("--derivation");
            args.push(d);
        }
        self.parse(&args)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store_prepared_secret(
        &self,
        endpoint: &str,
        prepared: &PreparedSecret,
        ring_id: &str,
        namespace: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        reader_did_pk: Option<&str>,
        derived_pk_hex: Option<&str>,
        with_proof: bool,
    ) -> Result<StoreSecretResult> {
        let prepared_json =
            serde_json::to_string(prepared).map_err(|e| eyre!("serialize prepared: {}", e))?;
        let mut args = vec![
            "store-prepared-secret",
            "--endpoint",
            endpoint,
            "--prepared-json",
            &prepared_json,
            "--ring-id",
            ring_id,
            "--namespace",
            namespace,
            "--policy-id",
            policy_id,
            "--resource",
            resource,
            "--permission",
            permission,
        ];
        if let Some(pk) = reader_did_pk {
            args.push("--reader-did-pk");
            args.push(pk);
        }
        if let Some(dpk) = derived_pk_hex {
            args.push("--derived-pk");
            args.push(dpk);
        }
        if with_proof {
            args.push("--with-proof");
        }
        self.parse(&args)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn do_pre(
        &self,
        endpoint: &str,
        ring_pk_hex: &str,
        reader_pk_hex: &str,
        reader_sk_hex: &str,
        object_id: &str,
        reader_did_pk: Option<&str>,
        namespace: &str,
        derivation_hex: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut args = vec![
            "pre",
            "--endpoint",
            endpoint,
            "--ring-pk",
            ring_pk_hex,
            "--reader-pk",
            reader_pk_hex,
            "--reader-sk",
            reader_sk_hex,
            "--object-id",
            object_id,
            "--namespace",
            namespace,
        ];
        if let Some(pk) = reader_did_pk {
            args.push("--reader-did-pk");
            args.push(pk);
        }
        if let Some(d) = derivation_hex {
            args.push("--derivation");
            args.push(d);
        }
        let result: PreResult = self.parse(&args)?;
        hex::decode(&result.decrypted_hex)
            .map_err(|e| eyre!("failed to decode PRE result hex: {}", e))
    }

    pub fn generate_reader_key(&self) -> Result<(String, String)> {
        let result: ReaderKeyResult = self.parse(&["generate-reader-key"])?;
        Ok((result.secret_key, result.public_key))
    }
}
