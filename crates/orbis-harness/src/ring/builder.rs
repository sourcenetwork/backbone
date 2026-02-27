use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::health::{self, HealthCheckConfig};
use super::node::OrbisNode;
use sourcehub_harness::SourceHubConfig;

/// Configuration for connecting orbis nodes to a hub.rs cluster.
pub struct HubRsNodeConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub chain_id: u64,
}

/// A running Orbis ring with managed node processes.
///
/// Does not own infrastructure (SourceHub, DefraDB, TestRunDir).
/// The caller is responsible for managing those lifetimes and ensuring
/// correct drop order (ring before infrastructure before run dir).
pub struct OrbisRing {
    nodes: Vec<OrbisNode>,
    threshold: u32,
}

impl fmt::Debug for OrbisRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRing")
            .field("node_count", &self.nodes.len())
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl OrbisRing {
    pub fn builder() -> OrbisRingBuilder {
        OrbisRingBuilder::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn node(&self, index: usize) -> &OrbisNode {
        &self.nodes[index]
    }

    pub fn nodes(&self) -> &[OrbisNode] {
        &self.nodes
    }

    pub fn grpc_addrs(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.grpc_addr()).collect()
    }

    /// Wait for all nodes' gRPC endpoints to become responsive.
    pub async fn wait_ready(&self, timeout: Duration) -> eyre::Result<()> {
        let config = HealthCheckConfig {
            poll_interval: Duration::from_millis(100),
            timeout,
        };
        health::wait_all_healthy(&self.grpc_addrs(), &config).await
    }
}

/// Builder for `OrbisRing`.
///
/// Requires `base_dir` and `identity_keys` to be set.
pub struct OrbisRingBuilder {
    node_count: usize,
    threshold: u32,
    log_level: String,
    base_dir: Option<PathBuf>,
    identity_keys: Option<Vec<String>>,
    sourcehub_config: Option<SourceHubConfig>,
    hub_rs_config: Option<HubRsNodeConfig>,
}

impl fmt::Debug for OrbisRingBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRingBuilder")
            .field("node_count", &self.node_count)
            .field("threshold", &self.threshold)
            .field("log_level", &self.log_level)
            .field("has_base_dir", &self.base_dir.is_some())
            .field("has_identity_keys", &self.identity_keys.is_some())
            .field("has_sourcehub_config", &self.sourcehub_config.is_some())
            .field("has_hub_rs_config", &self.hub_rs_config.is_some())
            .finish()
    }
}

impl Default for OrbisRingBuilder {
    fn default() -> Self {
        Self {
            node_count: 3,
            threshold: 2,
            log_level: "info".to_string(),
            base_dir: None,
            identity_keys: None,
            sourcehub_config: None,
            hub_rs_config: None,
        }
    }
}

impl OrbisRingBuilder {
    #[must_use]
    pub fn nodes(mut self, n: usize) -> Self {
        self.node_count = n;
        self
    }

    #[must_use]
    pub fn threshold(mut self, t: u32) -> Self {
        self.threshold = t;
        self
    }

    #[must_use]
    pub fn log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    #[must_use]
    pub fn base_dir(mut self, path: &Path) -> Self {
        self.base_dir = Some(path.to_path_buf());
        self
    }

    #[must_use]
    pub fn identity_keys(mut self, keys: Vec<String>) -> Self {
        self.identity_keys = Some(keys);
        self
    }

    #[must_use]
    pub fn sourcehub_config(mut self, config: SourceHubConfig) -> Self {
        self.sourcehub_config = Some(config);
        self
    }

    #[must_use]
    pub fn hub_rs_config(mut self, config: HubRsNodeConfig) -> Self {
        self.hub_rs_config = Some(config);
        self
    }

    /// Build and start the ring.
    ///
    /// Resolves the orbis-node binary via `BinaryResolver` (set `ORBIS_BINARY`
    /// to override), allocates gRPC ports, and spawns node processes.
    pub async fn build(self) -> eyre::Result<OrbisRing> {
        let n = self.node_count;

        let resolver = if self.hub_rs_config.is_some() {
            test_infra::BinaryResolver::new("ORBIS", "orbis-node")
                .cargo_package("orbis-node")
                .cargo_features(&[
                    "bls12-381",
                    "redb",
                    "bulletin-hubrs",
                    "iroh",
                    "authz-sourcehub",
                ])
        } else {
            test_infra::BinaryResolver::new("ORBIS", "orbis-node").cargo_package("orbis-node")
        };
        let binary = resolver.resolve()?;

        let base_dir = self
            .base_dir
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: base_dir is required"))?;

        let identity_keys = self
            .identity_keys
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: identity_keys is required"))?;

        if identity_keys.len() != n {
            return Err(eyre::eyre!(
                "OrbisRingBuilder: expected {} identity keys, got {}",
                n,
                identity_keys.len()
            ));
        }

        let grpc_ports = test_infra::allocate_ports(n)?;
        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = base_dir.join(format!("node{}", i));
            std::fs::create_dir_all(&node_dir)?;
            let log_dir = node_dir.join("logs");
            let data_dir = node_dir.join("data");
            std::fs::create_dir_all(&data_dir)?;

            let secret_hex = &identity_keys[i];
            let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| self.log_level.clone());

            let mut args_owned = vec![
                "--addr".to_string(),
                format!("127.0.0.1:{}", grpc_ports[i]),
                "--log-level".to_string(),
                self.log_level.clone(),
                "--data-dir".to_string(),
                data_dir.to_str().unwrap_or("data").to_string(),
            ];

            if let Some(ref hub) = self.hub_rs_config {
                // Hub.rs mode: bulletin via EVM precompiles, ACP via light client
                args_owned.extend([
                    "--hub-rpc".to_string(),
                    hub.rpc_url.clone(),
                    "--hub-ws".to_string(),
                    hub.ws_url.clone(),
                    "--hub-chain-id".to_string(),
                    hub.chain_id.to_string(),
                ]);
                // Only pass authz-grpc from SourceHub (read-only queries)
                if let Some(ref sh) = self.sourcehub_config {
                    args_owned.extend(["--authz-grpc".to_string(), sh.grpc_url.clone()]);
                }
            } else if let Some(ref sh) = self.sourcehub_config {
                // Legacy SourceHub mode: all services via SourceHub
                args_owned.extend([
                    "--authz-grpc".to_string(),
                    sh.grpc_url.clone(),
                    "--bulletin-grpc".to_string(),
                    sh.grpc_url.clone(),
                    "--chain-rpc".to_string(),
                    sh.comet_rpc_url.clone(),
                    "--chain-rest".to_string(),
                    sh.lcd_url.clone(),
                ]);
            }

            let envs_owned = [
                (
                    "ORBIS_PASSWORD".to_string(),
                    "e2e-test-password".to_string(),
                ),
                ("ORBIS_SECRET_KEY".to_string(), secret_hex.clone()),
                ("NO_COLOR".to_string(), "1".to_string()),
                ("RUST_LOG".to_string(), rust_log),
            ];

            let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
            let envs: Vec<(&str, &str)> = envs_owned
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let name = format!("node{}", i);
            let process =
                test_infra::ManagedProcess::spawn(&name, &binary.path, &args, &envs, &log_dir)?;

            nodes.push(OrbisNode {
                index: i,
                grpc_port: grpc_ports[i],
                data_dir: node_dir,
                log_dir,
                process,
            });
        }

        Ok(OrbisRing {
            nodes,
            threshold: self.threshold,
        })
    }
}
