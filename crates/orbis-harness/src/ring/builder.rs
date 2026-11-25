use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::health::{self, HealthCheckConfig};
use super::node::OrbisNode;
use crate::vera::OrbisVeraConfig;

/// A running Orbis ring with managed node processes.
///
/// Does not own infrastructure (Vera, DefraDB, TestRunDir).
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

    /// Wait until every node reports itself ready and return what each reports.
    pub async fn wait_ready(
        &self,
        timeout: Duration,
    ) -> eyre::Result<Vec<cli_tool::NodeInfoResult>> {
        let config = HealthCheckConfig {
            poll_interval: Duration::from_millis(100),
            timeout,
        };
        health::wait_all_ready(&self.grpc_addrs(), &config).await
    }
}

/// Builder for `OrbisRing`.
///
/// Requires `base_dir`, `identity_keys`, `vera` and `controller_key` to be set.
pub struct OrbisRingBuilder {
    node_count: usize,
    threshold: u32,
    log_level: String,
    base_dir: Option<PathBuf>,
    identity_keys: Option<Vec<String>>,
    vera: Option<OrbisVeraConfig>,
    controller_key: Option<String>,
}

impl fmt::Debug for OrbisRingBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrbisRingBuilder")
            .field("node_count", &self.node_count)
            .field("threshold", &self.threshold)
            .field("log_level", &self.log_level)
            .field("has_base_dir", &self.base_dir.is_some())
            .field("has_identity_keys", &self.identity_keys.is_some())
            .field("vera", &self.vera)
            .field("controller_key", &self.controller_key)
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
            vera: None,
            controller_key: None,
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

    /// The Vera deployment every node authorizes against and posts to.
    #[must_use]
    pub fn vera(mut self, config: OrbisVeraConfig) -> Self {
        self.vera = Some(config);
        self
    }

    /// The compressed secp256k1 key that manages every node's registration.
    #[must_use]
    pub fn controller_key(mut self, key: impl Into<String>) -> Self {
        self.controller_key = Some(key.into());
        self
    }

    /// Build and start the ring.
    ///
    /// Resolves the orbis-node binary via `BinaryResolver` (set `ORBIS_BINARY`
    /// to override), allocates gRPC ports, and spawns node processes.
    pub async fn build(self) -> eyre::Result<OrbisRing> {
        let n = self.node_count;

        let mut resolver =
            test_infra::BinaryResolver::new("ORBIS", "orbis-node").cargo_package("orbis-node");
        // orbis-rs has `path = "../backbone/..."` deps — symlink backbone
        // into the temp build dir so cargo can resolve them.
        if let Some(root) = test_infra::find_project_root() {
            resolver = resolver.sibling_symlink("backbone", root);
        }
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

        let vera = self
            .vera
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: vera is required"))?;
        let controller_key = self
            .controller_key
            .ok_or_else(|| eyre::eyre!("OrbisRingBuilder: controller_key is required"))?;
        let services_config = serde_json::to_vec(&vera.services_config())?;

        let ports = test_infra::allocate_ports(2 * n)?;
        let (grpc_ports, p2p_ports) = ports.split_at(n);
        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = base_dir.join(format!("node{}", i));
            std::fs::create_dir_all(&node_dir)?;
            let log_dir = node_dir.join("logs");
            let data_dir = node_dir.join("data");
            std::fs::create_dir_all(&data_dir)?;

            let secret_hex = &identity_keys[i];
            let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| self.log_level.clone());

            let services_path = node_dir.join("services.json");
            std::fs::write(&services_path, &services_config)?;
            let args_owned = vec![
                "--services-config".to_string(),
                services_path.display().to_string(),
                "--addr".to_string(),
                format!("127.0.0.1:{}", grpc_ports[i]),
                "--log-level".to_string(),
                self.log_level.clone(),
                "--runtime-base-path".to_string(),
                data_dir.display().to_string(),
                "--node-controller-key".to_string(),
                controller_key.clone(),
                // Every peer is a local process: routes are the bound loopback
                // addresses, without relays or discovery.
                "--network-private-routes-only".to_string(),
                "--network-bind-addr".to_string(),
                format!("127.0.0.1:{}", p2p_ports[i]),
                // Refresh only when a test asks for it.
                "--reshare-interval-secs".to_string(),
                "0".to_string(),
            ];

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
