use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Result, WrapErr};

use super::{DefraNode, KeyringBackend, NodeConfig};
use crate::divergences::{self, NodeKind};
use crate::workspace_root;

type Parts = (PathBuf, Vec<String>, Vec<(String, String)>);

/// A Rust DefraDB node backed by the `defra` binary.
pub struct RustNode {
    binary_path: PathBuf,
}

impl RustNode {
    /// Point to the debug binary in the workspace target dir.
    pub fn from_workspace() -> Self {
        Self {
            binary_path: Self::workspace_binary_path(),
        }
    }

    /// Use a pre-existing binary at the given path.
    pub fn from_binary(path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: path.into(),
        }
    }

    /// The default workspace binary path (`target/debug/defra`).
    pub fn workspace_binary_path() -> PathBuf {
        workspace_root().join("target/debug/defra")
    }

    /// Build the Rust binary via cargo (debug mode for fast iteration).
    pub fn build() -> Result<()> {
        let status = Command::new("cargo")
            .args(["build", "-p", "cli"])
            .current_dir(workspace_root())
            .status()
            .wrap_err("failed to run cargo build")?;

        eyre::ensure!(status.success(), "cargo build failed with {}", status);
        Ok(())
    }

    /// Build the Rust binary with additional cargo features enabled.
    pub fn build_with_features(features: &[&str]) -> Result<()> {
        let features_str = features.join(",");
        let status = Command::new("cargo")
            .args(["build", "-p", "cli", "--features", &features_str])
            .current_dir(workspace_root())
            .status()
            .wrap_err("failed to run cargo build with features")?;

        eyre::ensure!(status.success(), "cargo build failed with {}", status);
        Ok(())
    }

    /// Verify the Rust binary is built and returns parseable version info.
    pub fn check_available() -> Result<()> {
        let binary = workspace_root().join("target/debug/defra");

        let output = Command::new(&binary)
            .args(["version", "--format", "json"])
            .output()
            .wrap_err("defra binary not found — run `cargo build -p cli` first")?;

        eyre::ensure!(
            output.status.success(),
            "defra version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let _json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .wrap_err("failed to parse defra version JSON")?;

        Ok(())
    }
}

impl DefraNode for RustNode {
    fn kind(&self) -> NodeKind {
        NodeKind::Rust
    }

    fn command_parts(&self, config: &NodeConfig) -> Parts {
        let mut args = vec![
            "--rootdir".to_string(),
            config.rootdir.display().to_string(),
            "--url".to_string(),
            config.http_addr.clone(),
            "--no-log-color".to_string(),
            "--log-output".to_string(),
            "stdout".to_string(),
        ];

        let mut envs: Vec<(String, String)> = Vec::new();

        match &config.keyring {
            KeyringBackend::None => args.push("--no-keyring".to_string()),
            KeyringBackend::Env { secret } => {
                envs.push(("DEFRA_KEYRING_SECRET".to_string(), secret.clone()));
            }
            KeyringBackend::File { path, secret } => {
                args.extend([
                    "--keyring-backend".into(),
                    "file".into(),
                    "--keyring-path".into(),
                    path.display().to_string(),
                ]);
                envs.push(("DEFRA_KEYRING_SECRET".to_string(), secret.clone()));
            }
        }

        args.push("start".to_string());
        args.push("--store".to_string());
        args.push(config.store.as_deref().unwrap_or("memory").to_string());
        args.push("--no-telemetry".to_string());

        if !config.encryption_enabled {
            args.push("--no-encryption".to_string());
            args.push("--no-searchable-encryption".to_string());
        }
        if let Some(ref signer) = config.orbis_signer {
            args.extend([
                "--signer-type".into(),
                "orbis".into(),
                "--signer-orbis-endpoint".into(),
                signer.endpoint.clone(),
                "--signer-orbis-ring-id".into(),
                signer.ring_id.clone(),
                "--signer-orbis-derivation".into(),
                signer.derivation.clone(),
            ]);
        } else if !config.signing_enabled {
            args.push("--no-signing".to_string());
        }

        if config.p2p_enabled {
            if let Some(ref addr) = config.p2p_addr {
                args.push("--p2paddr".to_string());
                args.push(addr.clone());
            }
            for peer in &config.peers {
                args.push("--peers".to_string());
                args.push(peer.clone());
            }
        } else {
            args.push("--no-p2p".to_string());
        }

        if let Some(ref identity) = config.identity {
            args.push("--identity".to_string());
            args.push(identity.clone());
        }

        if let Some(ref acp_type) = config.acp_document_type {
            args.push("--document-acp-type".to_string());
            args.push(acp_type.clone());
        }

        if config.nac_enabled {
            args.push("--node-acp-enable".to_string());
        }

        // DIVERGENCE: Only Rust supports --source-hub-* flags
        if divergences::supports_source_hub_flags(NodeKind::Rust) {
            if let Some(ref sh) = config.source_hub {
                args.extend([
                    "--source-hub-address".into(),
                    sh.lcd_url.clone(),
                    "--source-hub-comet-address".into(),
                    sh.comet_rpc_url.clone(),
                    "--source-hub-chain-id".into(),
                    sh.chain_id.clone(),
                ]);
            }
        }

        if let Some(ref hub_rs) = config.hub_rs_address {
            args.extend(["--hub-rs-address".into(), hub_rs.clone()]);
        }

        if let Some(ref transport) = config.p2p_transport {
            args.push("--p2p-transport".to_string());
            args.push(transport.clone());
        }

        if config.development {
            args.push("--development".to_string());
        }

        if let Some(timeout) = config.query_timeout {
            args.push("--query-timeout".to_string());
            args.push(timeout.to_string());
        }

        (self.binary_path.clone(), args, envs)
    }

    fn binary_path(&self) -> &Path {
        &self.binary_path
    }
}
