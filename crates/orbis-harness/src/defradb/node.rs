use std::path::{Path, PathBuf};
use std::time::Duration;

use super::DefraDbPorts;

/// A running DefraDB node.
///
/// Spawns `defra start` with in-memory storage and minimal overhead
/// for fast test cycles. Killed on drop via ManagedProcess.
pub struct DefraDbNode {
    #[allow(dead_code)]
    process: test_infra::ManagedProcess,
    /// HTTP API URL (e.g. "http://127.0.0.1:9181").
    pub http_url: String,
    /// P2P multiaddr (e.g. "/ip4/127.0.0.1/tcp/9171").
    pub p2p_addr: String,
    #[allow(dead_code)]
    pub root_dir: PathBuf,
}

impl DefraDbNode {
    /// Start a DefraDB node.
    ///
    /// Uses in-memory store, disables encryption/signing/telemetry for speed.
    /// Optionally connects to a SourceHub instance for ACP.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        root_dir: PathBuf,
        log_dir: PathBuf,
        ports: &DefraDbPorts,
        binary: &Path,
        sourcehub: Option<&SourceHubConfig>,
        identity_key: Option<&str>,
        orbis_signer: Option<&OrbisSignerConfig>,
        ready_timeout: Duration,
    ) -> eyre::Result<Self> {
        let http_addr = format!("127.0.0.1:{}", ports.http);
        let p2p_addr = format!("/ip4/127.0.0.1/tcp/{}", ports.p2p);

        let mut args_owned: Vec<String> = vec![
            "--rootdir".to_string(),
            root_dir.display().to_string(),
            "--url".to_string(),
            http_addr.clone(),
            "--no-log-color".to_string(),
        ];

        let mut envs_owned: Vec<(String, String)> = Vec::new();

        if let Some(key_hex) = identity_key {
            let keyring_path = root_dir.join("keys");
            std::fs::create_dir_all(&keyring_path)?;
            args_owned.extend([
                "--keyring-backend".to_string(),
                "file".to_string(),
                "--keyring-path".to_string(),
                keyring_path.to_str().unwrap_or("keys").to_string(),
            ]);
            envs_owned.push((
                "DEFRA_KEYRING_SECRET".to_string(),
                "e2e-test-password".to_string(),
            ));
            args_owned.extend(["start".to_string(), "-i".to_string(), key_hex.to_string()]);
        } else {
            args_owned.extend(["start".to_string(), "--no-keyring".to_string()]);
        }

        args_owned.extend([
            "--store".to_string(),
            "memory".to_string(),
            "--no-telemetry".to_string(),
            "--no-encryption".to_string(),
        ]);

        if let Some(signer) = orbis_signer {
            args_owned.extend([
                "--signer-type".to_string(),
                "orbis".to_string(),
                "--signer-orbis-endpoint".to_string(),
                signer.endpoint.clone(),
                "--signer-orbis-ring-id".to_string(),
                signer.ring_id.clone(),
                "--signer-orbis-derivation".to_string(),
                signer.derivation.clone(),
            ]);
        } else {
            args_owned.push("--no-signing".to_string());
        }

        args_owned.extend(["--p2paddr".to_string(), p2p_addr.clone()]);

        if let Some(sh) = sourcehub {
            args_owned.extend([
                "--source-hub-address".to_string(),
                sh.lcd_url.clone(),
                "--source-hub-comet-address".to_string(),
                sh.comet_rpc_url.clone(),
                "--source-hub-chain-id".to_string(),
                sh.chain_id.clone(),
                "--acp-document-type".to_string(),
                "source-hub".to_string(),
            ]);
        }

        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
        let envs: Vec<(&str, &str)> = envs_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let process = test_infra::ManagedProcess::spawn("defra", binary, &args, &envs, &log_dir)
            .map_err(|e| eyre::eyre!("{:#}", e))?;

        let http_url = format!("http://{}", http_addr);

        let client = reqwest::Client::new();
        let health_url = format!("{}/health-check", http_url);
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => break,
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "defra health check timed out at {}",
                    health_url
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tracing::info!(
            http = %http_url,
            p2p = %p2p_addr,
            identity = identity_key.is_some(),
            "DefraDB node ready"
        );

        Ok(Self {
            process,
            http_url,
            p2p_addr,
            root_dir,
        })
    }

    pub fn http_url(&self) -> &str {
        &self.http_url
    }

    pub fn p2p_addr(&self) -> &str {
        &self.p2p_addr
    }
}

/// Minimal SourceHub connection info for DefraDB's ACP integration.
pub struct SourceHubConfig {
    pub lcd_url: String,
    pub comet_rpc_url: String,
    pub chain_id: String,
}

/// Configuration for DefraDB's Orbis signer integration.
///
/// When provided, DefraDB delegates document signing to an Orbis ring
/// via gRPC threshold signing instead of using a local key.
pub struct OrbisSignerConfig {
    /// gRPC endpoint of an Orbis node (e.g. "http://127.0.0.1:8081").
    pub endpoint: String,
    /// Ring ID to sign with (from DKG bulletin post).
    pub ring_id: String,
    /// Derivation label (e.g. "x-archive") for derived key signing.
    pub derivation: String,
}
