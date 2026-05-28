use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use eyre::{Result, WrapErr};
use reqwest::Client;

use crate::divergences::NodeKind;
use crate::node::{start_node, BinarySource, GoNode, KeyringBackend, NodeConfig, RustNode};
use crate::ports::allocate_node_ports;
use sourcehub_harness::{allocate_source_hub_ports, SourceHubConfig, SourceHubNode};

use super::health::health_check_all;
use super::runtime::TestCluster;

static RUST_BUILD_DONE: OnceLock<()> = OnceLock::new();
static IROH_BUILD_DONE: OnceLock<()> = OnceLock::new();

/// Reads the `DEFRA_MULTIPLIERS` env var and returns true if `signed-docs`
/// is present in its comma-separated value.
// `#[allow(dead_code)]` is removed in Task 3 when build() consumes this.
#[allow(dead_code)]
fn signed_docs_multiplier_active() -> bool {
    signed_docs_in(std::env::var("DEFRA_MULTIPLIERS").ok().as_deref())
}

/// Returns true if `value` is a comma-separated multiplier list that
/// contains `signed-docs` (case-sensitive, whitespace-trimmed per entry).
///
/// `DEFRA_MULTIPLIERS` is forward-compatible — unknown entries are
/// ignored, so e.g. `"signed-docs,foo"` matches.
///
/// Pulled out from `signed_docs_multiplier_active` so the parsing logic
/// can be unit-tested without mutating process env vars.
fn signed_docs_in(value: Option<&str>) -> bool {
    value
        .map(|v| v.split(',').any(|s| s.trim() == "signed-docs"))
        .unwrap_or(false)
}

pub struct TestClusterBuilder {
    rust_nodes: usize,
    go_nodes: usize,
    p2p_enabled: bool,
    health_timeout: Duration,
    rust_binary: Option<BinarySource>,
    go_binary: Option<BinarySource>,
    acp_document_type: Option<String>,
    node_identity: Option<String>,
    node_identities: Vec<Option<String>>,
    encryption_enabled: bool,
    signing_enabled: bool,
    nac_enabled: bool,
    source_hub_enabled: bool,
    development: bool,
    store: Option<String>,
    query_timeout: Option<u64>,
    p2p_transport: Option<String>,
    keyring: KeyringBackend,
    acp_cache_ttl: Option<u64>,
    acp_circuit_breaker_threshold: Option<u32>,
    acp_circuit_breaker_reset_timeout: Option<u64>,
    acp_request_timeout: Option<u64>,
    acp_receipt_timeout: Option<u64>,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self {
            rust_nodes: 0,
            go_nodes: 0,
            p2p_enabled: false,
            health_timeout: Duration::from_secs(30),
            rust_binary: None,
            go_binary: None,
            acp_document_type: None,
            node_identity: None,
            node_identities: Vec::new(),
            encryption_enabled: false,
            signing_enabled: false,
            nac_enabled: false,
            source_hub_enabled: false,
            development: false,
            store: None,
            query_timeout: None,
            p2p_transport: None,
            keyring: KeyringBackend::None,
            acp_cache_ttl: None,
            acp_circuit_breaker_threshold: None,
            acp_circuit_breaker_reset_timeout: None,
            acp_request_timeout: None,
            acp_receipt_timeout: None,
        }
    }

    pub fn rust_nodes(mut self, n: usize) -> Self {
        self.rust_nodes = n;
        self
    }

    pub fn go_nodes(mut self, n: usize) -> Self {
        self.go_nodes = n;
        self
    }

    pub fn with_p2p(mut self) -> Self {
        self.p2p_enabled = true;
        self
    }

    pub fn health_timeout(mut self, d: Duration) -> Self {
        self.health_timeout = d;
        self
    }

    /// Set the binary source for Rust nodes.
    ///
    /// Defaults to `BinarySource::Workspace` (builds from workspace via cargo).
    pub fn with_rust_binary(mut self, source: BinarySource) -> Self {
        self.rust_binary = Some(source);
        self
    }

    /// Set the binary source for Go nodes.
    ///
    /// Defaults to `BinarySource::Path("defradb")` (found via PATH).
    pub fn with_go_binary(mut self, source: BinarySource) -> Self {
        self.go_binary = Some(source);
        self
    }

    /// Skip the cargo build step for Rust nodes.
    /// Equivalent to `.with_rust_binary(BinarySource::Path(workspace_binary_path()))`.
    pub fn skip_build(mut self) -> Self {
        self.rust_binary = Some(BinarySource::Path(RustNode::workspace_binary_path()));
        self
    }

    pub fn with_acp_local(mut self) -> Self {
        self.acp_document_type = Some("local".to_string());
        self
    }

    pub fn with_identity(mut self, key: impl Into<String>) -> Self {
        self.node_identity = Some(key.into());
        self
    }

    /// Set identity for a specific node (by index). Overrides cluster-wide identity.
    pub fn with_node_identity(mut self, index: usize, key: impl Into<String>) -> Self {
        while self.node_identities.len() <= index {
            self.node_identities.push(None);
        }
        self.node_identities[index] = Some(key.into());
        self
    }

    pub fn with_encryption(mut self) -> Self {
        self.encryption_enabled = true;
        self
    }

    pub fn with_signing(mut self) -> Self {
        self.signing_enabled = true;
        self
    }

    pub fn with_nac(mut self) -> Self {
        self.nac_enabled = true;
        self
    }

    pub fn with_source_hub(mut self) -> Self {
        self.source_hub_enabled = true;
        self.acp_document_type = Some("source-hub".to_string());
        self
    }

    pub fn with_development(mut self) -> Self {
        self.development = true;
        self
    }

    pub fn with_store(mut self, store: impl Into<String>) -> Self {
        self.store = Some(store.into());
        self
    }

    pub fn with_query_timeout(mut self, secs: u64) -> Self {
        self.query_timeout = Some(secs);
        self
    }

    pub fn with_iroh_transport(mut self) -> Self {
        self.p2p_transport = Some("iroh".to_string());
        self.p2p_enabled = true;
        self
    }

    pub fn with_acp_cache_ttl(mut self, secs: u64) -> Self {
        self.acp_cache_ttl = Some(secs);
        self
    }

    pub fn with_acp_circuit_breaker_threshold(mut self, threshold: u32) -> Self {
        self.acp_circuit_breaker_threshold = Some(threshold);
        self
    }

    pub fn with_acp_circuit_breaker_reset_timeout(mut self, secs: u64) -> Self {
        self.acp_circuit_breaker_reset_timeout = Some(secs);
        self
    }

    pub fn with_acp_request_timeout(mut self, secs: u64) -> Self {
        self.acp_request_timeout = Some(secs);
        self
    }

    pub fn with_acp_receipt_timeout(mut self, secs: u64) -> Self {
        self.acp_receipt_timeout = Some(secs);
        self
    }

    pub fn with_keyring(mut self) -> Self {
        self.keyring = KeyringBackend::Env {
            secret: "integration-test-secret".to_string(),
        };
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
        let total = self.rust_nodes + self.go_nodes;
        eyre::ensure!(total > 0, "must have at least one node");

        let is_iroh = self.p2p_transport.as_deref() == Some("iroh");

        // Resolve Rust binary source
        let rust_binary_path = if self.rust_nodes > 0 {
            let source = self.rust_binary.clone().unwrap_or_else(|| {
                if is_iroh {
                    std::env::var("DEFRA_IROH_BINARY")
                        .ok()
                        .map(|p| BinarySource::Path(PathBuf::from(p)))
                        .unwrap_or_else(|| {
                            BinarySource::WorkspaceWithFeatures(vec!["iroh".to_string()])
                        })
                } else {
                    std::env::var("DEFRA_RUST_BINARY")
                        .ok()
                        .map(|p| BinarySource::Path(PathBuf::from(p)))
                        .unwrap_or(BinarySource::Workspace)
                }
            });
            // Use OnceLock for workspace builds to avoid parallel rebuilds
            let path = match &source {
                BinarySource::Workspace => {
                    RUST_BUILD_DONE.get_or_init(|| {
                        RustNode::build().expect("failed to build Rust binary");
                    });
                    RustNode::workspace_binary_path()
                }
                BinarySource::WorkspaceWithFeatures(features) => {
                    let features_clone = features.clone();
                    IROH_BUILD_DONE.get_or_init(|| {
                        let refs: Vec<&str> = features_clone.iter().map(|s| s.as_str()).collect();
                        RustNode::build_with_features(&refs)
                            .expect("failed to build Rust binary with features");
                    });
                    RustNode::workspace_binary_path()
                }
                _ => source.resolve(NodeKind::Rust)?,
            };
            Some(path)
        } else {
            None
        };

        // Resolve Go binary source
        let go_binary_path = if self.go_nodes > 0 {
            let source = self.go_binary.clone().unwrap_or(BinarySource::Workspace);
            let path = match &source {
                BinarySource::Workspace => {
                    // Default Go behavior: PATH lookup + version check
                    GoNode::check_available().wrap_err("Go defradb binary not available")?;
                    GoNode::path_binary()
                }
                _ => source.resolve(NodeKind::Go)?,
            };
            Some(path)
        } else {
            None
        };

        // Source Hub or NAC requires an identity at startup.
        if (self.nac_enabled || self.source_hub_enabled) && self.node_identity.is_none() {
            let binary = if let Some(ref p) = go_binary_path {
                p.clone()
            } else if let Some(ref p) = rust_binary_path {
                p.clone()
            } else {
                eyre::bail!("no binary available for identity generation");
            };
            let id = crate::identity::generate_identity(&binary)
                .wrap_err("auto-generating identity for NAC/SourceHub")?;
            self.node_identity = Some(id.private_key_hex);
        }

        // Allocate ports for all nodes
        let mut all_ports = allocate_node_ports(total)?;

        // Create run directory
        let run_dir = test_infra::TestRunDir::new(
            &crate::workspace_root().join("target/e2e"),
            "DEFRA_E2E_KEEP",
        )?;

        // Start Source Hub if enabled
        let source_hub = if self.source_hub_enabled {
            let sh_ports = allocate_source_hub_ports().wrap_err("allocating source hub ports")?;

            let sh_home = run_dir.node_dir("sourcehub")?;
            let sh_log_dir = sh_home.join("logs");
            std::fs::create_dir_all(&sh_log_dir)?;

            let identity_keys: Vec<String> = self.node_identity.iter().cloned().collect();

            let sh_node = SourceHubNode::start(
                sh_home,
                sh_log_dir,
                &sh_ports,
                &identity_keys,
                Duration::from_secs(60),
            )
            .await
            .wrap_err("failed to start source hub node")?;

            Some(sh_node)
        } else {
            None
        };

        let sh_config: Option<SourceHubConfig> = source_hub.as_ref().map(SourceHubConfig::from);

        let mut nodes = Vec::with_capacity(total);

        // Spawn Rust nodes
        for (i, ports) in all_ports.iter_mut().enumerate().take(self.rust_nodes) {
            let name = format!("rust-{}", i);
            let node = RustNode::from_binary(rust_binary_path.as_ref().unwrap());
            let identity = self
                .node_identities
                .get(i)
                .cloned()
                .flatten()
                .or_else(|| self.node_identity.clone());

            let node_dir = run_dir.node_dir(&name)?;
            let log_dir = node_dir.join("logs");
            let rootdir = node_dir.join("data");

            let p2p_addr = if self.p2p_enabled && !is_iroh {
                Some(format!("/ip4/127.0.0.1/tcp/{}", ports.p2p))
            } else {
                None
            };

            let config = NodeConfig {
                name: name.clone(),
                rootdir,
                log_dir,
                http_addr: format!("127.0.0.1:{}", ports.http),
                p2p_enabled: self.p2p_enabled,
                p2p_addr,
                peers: vec![],
                identity,
                acp_document_type: self.acp_document_type.clone(),
                encryption_enabled: self.encryption_enabled,
                signing_enabled: self.signing_enabled,
                nac_enabled: self.nac_enabled,
                source_hub: sh_config.clone(),
                hub_rs_address: None,
                orbis_signer: None,
                keyring: self.keyring.clone(),
                development: self.development,
                store: self.store.clone(),
                query_timeout: self.query_timeout,
                p2p_transport: self.p2p_transport.clone(),
                acp_cache_ttl: self.acp_cache_ttl,
                acp_circuit_breaker_threshold: self.acp_circuit_breaker_threshold,
                acp_circuit_breaker_reset_timeout: self.acp_circuit_breaker_reset_timeout,
                acp_request_timeout: self.acp_request_timeout,
                acp_receipt_timeout: self.acp_receipt_timeout,
            };

            // Release port guards right before spawn so the child process can bind
            ports.release();
            let running = start_node(&node, config, self.health_timeout)
                .await
                .wrap_err_with(|| format!("failed to start {}", name))?;
            nodes.push(running);
        }

        // Spawn Go nodes
        for (i, ports) in all_ports.iter_mut().skip(self.rust_nodes).enumerate() {
            let name = format!("go-{}", i);
            let node = GoNode::from_binary(go_binary_path.as_ref().unwrap());
            let go_index = self.rust_nodes + i;
            let identity = self
                .node_identities
                .get(go_index)
                .cloned()
                .flatten()
                .or_else(|| self.node_identity.clone());

            let node_dir = run_dir.node_dir(&name)?;
            let log_dir = node_dir.join("logs");
            let rootdir = node_dir.join("data");

            let p2p_addr = if self.p2p_enabled {
                Some(format!("/ip4/127.0.0.1/tcp/{}", ports.p2p))
            } else {
                None
            };

            let config = NodeConfig {
                name: name.clone(),
                rootdir,
                log_dir,
                http_addr: format!("127.0.0.1:{}", ports.http),
                p2p_enabled: self.p2p_enabled,
                p2p_addr,
                peers: vec![],
                identity,
                acp_document_type: self.acp_document_type.clone(),
                encryption_enabled: self.encryption_enabled,
                signing_enabled: self.signing_enabled,
                nac_enabled: self.nac_enabled,
                source_hub: sh_config.clone(),
                hub_rs_address: None,
                orbis_signer: None,
                keyring: KeyringBackend::None,
                development: self.development,
                store: self.store.clone(),
                query_timeout: self.query_timeout,
                p2p_transport: None,
                acp_cache_ttl: self.acp_cache_ttl,
                acp_circuit_breaker_threshold: self.acp_circuit_breaker_threshold,
                acp_circuit_breaker_reset_timeout: self.acp_circuit_breaker_reset_timeout,
                acp_request_timeout: self.acp_request_timeout,
                acp_receipt_timeout: self.acp_receipt_timeout,
            };

            // Release port guards right before spawn so the child process can bind
            ports.release();
            let running = start_node(&node, config, self.health_timeout)
                .await
                .wrap_err_with(|| format!("failed to start {}", name))?;
            nodes.push(running);
        }

        // Confirm all nodes are healthy via HTTP
        let client = Client::new();
        let urls: Vec<String> = nodes.iter().map(|n| n.api_url.clone()).collect();
        health_check_all(&client, &urls, self.health_timeout)
            .await
            .wrap_err("health check failed")?;

        // Collect effective per-node identities for test assertions
        let effective_identities: Vec<Option<String>> = (0..total)
            .map(|i| {
                self.node_identities
                    .get(i)
                    .cloned()
                    .flatten()
                    .or_else(|| self.node_identity.clone())
            })
            .collect();

        Ok(TestCluster::new(
            nodes,
            run_dir,
            self.node_identity,
            effective_identities,
            source_hub,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_docs_in_handles_all_cases() {
        assert!(!signed_docs_in(None), "unset → false");
        assert!(!signed_docs_in(Some("")), "empty → false");
        assert!(signed_docs_in(Some("signed-docs")), "exact → true");
        assert!(signed_docs_in(Some(" signed-docs ")), "padded → true");
        assert!(
            signed_docs_in(Some("signed-docs,foo")),
            "first of list → true"
        );
        assert!(
            signed_docs_in(Some("foo,signed-docs")),
            "second of list → true"
        );
        assert!(
            signed_docs_in(Some("foo, signed-docs ,bar")),
            "padded middle → true"
        );
        assert!(!signed_docs_in(Some("foo")), "other only → false");
        assert!(!signed_docs_in(Some("foo,bar")), "no match → false");
        assert!(
            !signed_docs_in(Some("SIGNED-DOCS")),
            "case-sensitive → false"
        );
    }
}
