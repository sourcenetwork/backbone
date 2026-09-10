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
    ///
    /// Some subcommands print a human-readable heading before the JSON body,
    /// so parsing starts at the first `{` or `[`.
    fn parse<T: serde::de::DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let stdout = self.exec_json(args)?;
        let json = json_body(&stdout)
            .ok_or_else(|| eyre!("no JSON body in cli-tool output: stdout={}", stdout))?;
        serde_json::from_str(json).map_err(|e| {
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
            return Err(eyre!(
                "cli-tool info failed (exit {}): {}",
                output.status,
                stderr.trim()
            ));
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
            return Err(eyre!(
                "cli-tool info: could not parse peer_id from output: {}",
                stdout
            ));
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
            return Err(eyre!(
                "cli-tool dkg: could not parse session_id from output: {}",
                stdout
            ));
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
        // `utility-sign` is the UtilityService pathway that takes a ring id and
        // an optional ACP tuple directly. The `sign` subcommand is the separate
        // KeyDerivation pathway and takes a derivation id instead.
        let mut args = vec![
            "utility-sign",
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
            args.push("--policy-id");
            args.push(&acp.policy_id);
            args.push("--resource");
            args.push(&acp.resource);
            args.push("--object-id");
            args.push(&acp.object_id);
            args.push("--permission");
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
        let stdout = self.exec(&args)?;
        parse_store_secret_result(&stdout)
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

    /// Generate a PRE reader keypair, returning `(secret_key_hex, public_key_hex)`.
    ///
    /// `generate-reader-key` prints a labelled text block and ignores
    /// `--output json`, so the hex values are read from the lines following
    /// their labels rather than parsed as JSON.
    pub fn generate_reader_key(&self) -> Result<(String, String)> {
        let stdout = self.exec(&["generate-reader-key"])?;
        let secret_key = value_after_label(&stdout, "Reader Secret Key")
            .ok_or_else(|| eyre!("no reader secret key in output: {}", stdout))?;
        let public_key = value_after_label(&stdout, "Reader Public Key")
            .ok_or_else(|| eyre!("no reader public key in output: {}", stdout))?;
        Ok((secret_key, public_key))
    }
}

/// Parse the labelled report `store-prepared-secret` prints.
///
/// The command reports `Status`, `Message`, `Object ID`, `Ring ID` and
/// `signature` as `  Label: value` lines under a heading, and ignores
/// `--output json`.
fn parse_store_secret_result(output: &str) -> Result<StoreSecretResult> {
    let field = |label: &str| -> Option<String> {
        output.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == label).then(|| value.trim().to_string())
        })
    };
    let missing = |label: &str| eyre!("no `{}` in store-secret output: {}", label, output);
    Ok(StoreSecretResult {
        status: field("Status").ok_or_else(|| missing("Status"))?,
        message: field("Message").ok_or_else(|| missing("Message"))?,
        object_id: field("Object ID").ok_or_else(|| missing("Object ID"))?,
        ring_id: field("Ring ID").ok_or_else(|| missing("Ring ID"))?,
        signature: field("signature").ok_or_else(|| missing("signature"))?,
    })
}

/// The JSON body of a cli-tool response, skipping any human-readable heading.
fn json_body(output: &str) -> Option<&str> {
    let start = output.find(['{', '['])?;
    Some(output[start..].trim())
}

/// First non-empty line after the line containing `label`.
fn value_after_label(output: &str, label: &str) -> Option<String> {
    let mut lines = output.lines().skip_while(|line| !line.contains(label));
    lines.next()?;
    lines
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::value_after_label;

    #[test]
    fn reads_the_hex_under_a_label() {
        let output = "Generated Reader Keypair:\n====\nReader Secret Key (--reader-sk):\nabc123\n\nReader Public Key (--reader-pk):\ndef456";
        assert_eq!(
            value_after_label(output, "Reader Secret Key").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            value_after_label(output, "Reader Public Key").as_deref(),
            Some("def456")
        );
    }

    #[test]
    fn parses_the_store_secret_report() {
        let output = "StoreSecret Result:\n====\n  Status: success\n  Message: Secret stored successfully\n  Object ID: abc\n  Ring ID: ring1\n  signature: sig1\n  enc_cmt: cmt";
        let result = super::parse_store_secret_result(output).expect("parse");
        assert_eq!(result.status, "success");
        assert_eq!(result.object_id, "abc");
        assert_eq!(result.ring_id, "ring1");
        assert_eq!(result.signature, "sig1");
    }

    #[test]
    fn store_secret_report_missing_a_field_is_an_error() {
        assert!(super::parse_store_secret_result("Status: success").is_err());
    }

    #[test]
    fn json_body_skips_a_heading() {
        let output = "Prepared Secret (save this):\n====\n{\n  \"a\": 1\n}";
        assert_eq!(super::json_body(output), Some("{\n  \"a\": 1\n}"));
    }

    #[test]
    fn json_body_is_none_without_json() {
        assert!(super::json_body("no json here").is_none());
    }

    #[test]
    fn returns_none_when_the_label_is_absent() {
        assert!(value_after_label("nothing here", "Reader Secret Key").is_none());
    }
}
