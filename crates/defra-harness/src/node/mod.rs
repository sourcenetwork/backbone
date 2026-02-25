mod go_node;
mod rust_node;

pub use go_node::GoNode;
pub use rust_node::RustNode;

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::divergences::NodeKind;

/// Where to obtain a DefraDB binary.
#[derive(Debug, Clone)]
pub enum BinarySource {
    /// Build from the local workspace via `cargo build -p cli`.
    /// This is the default for Rust nodes.
    Workspace,

    /// Build from the local workspace with extra cargo features (e.g. `["iroh"]`).
    WorkspaceWithFeatures(Vec<String>),

    /// Use a pre-existing binary at this absolute path. No build step.
    Path(PathBuf),

    /// Download a release binary by version tag (e.g. `"v0.20.0"`).
    /// The binary is cached in `~/.cache/defra-harness/<version>/`.
    Release(String),
}

impl BinarySource {
    /// Resolve the binary source to an absolute path, building or downloading as needed.
    pub fn resolve(&self, kind: NodeKind) -> anyhow::Result<PathBuf> {
        match self {
            BinarySource::Workspace => match kind {
                NodeKind::Rust => {
                    RustNode::build()?;
                    Ok(RustNode::workspace_binary_path())
                }
                NodeKind::Go => Ok(GoNode::path_binary()),
            },
            BinarySource::WorkspaceWithFeatures(features) => {
                let refs: Vec<&str> = features.iter().map(|s| s.as_str()).collect();
                RustNode::build_with_features(&refs)?;
                Ok(RustNode::workspace_binary_path())
            }
            BinarySource::Path(p) => {
                anyhow::ensure!(p.exists(), "binary not found at {}", p.display());
                Ok(p.clone())
            }
            BinarySource::Release(version) => resolve_release(version, kind),
        }
    }
}

/// Download (or return cached) a release binary for the given version and node kind.
fn resolve_release(version: &str, kind: NodeKind) -> anyhow::Result<PathBuf> {
    let cache_dir = dirs_cache().join("defra-harness").join(version);
    let binary_name = match kind {
        NodeKind::Rust => "defra",
        NodeKind::Go => "defradb",
    };
    let cached = cache_dir.join(binary_name);
    if cached.exists() {
        return Ok(cached);
    }

    let asset_name = release_asset_name(version, kind)?;
    let repo = match kind {
        NodeKind::Rust => "sourcenetwork/defradb.rs",
        NodeKind::Go => "sourcenetwork/defradb",
    };
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, version, asset_name
    );

    std::fs::create_dir_all(&cache_dir)?;

    tracing::info!(%version, %url, "downloading release binary");

    let output = Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(&cached)
        .arg(&url)
        .output()
        .with_context(|| format!("failed to download {}", url))?;

    anyhow::ensure!(
        output.status.success(),
        "download failed ({}): {}",
        url,
        String::from_utf8_lossy(&output.stderr)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cached, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(cached)
}

fn release_asset_name(version: &str, kind: NodeKind) -> anyhow::Result<String> {
    let (os, arch) = current_platform()?;
    let ver_num = version.strip_prefix('v').unwrap_or(version);
    let name = match kind {
        NodeKind::Go => format!("defradb_{}_{}", ver_num, os_arch_suffix(os, arch)),
        NodeKind::Rust => format!("defra_{}_{}", ver_num, os_arch_suffix(os, arch)),
    };
    Ok(name)
}

fn os_arch_suffix(os: &str, arch: &str) -> String {
    match (os, arch) {
        ("macos", "aarch64") => "darwin_arm64".to_string(),
        ("macos", "x86_64") => "darwin_x86_64".to_string(),
        ("linux", "x86_64") => "linux_x86_64".to_string(),
        ("linux", "aarch64") => "linux_arm64".to_string(),
        ("windows", "x86_64") => "windows_x86_64.exe".to_string(),
        _ => format!("{}_{}", os, arch),
    }
}

fn current_platform() -> anyhow::Result<(&'static str, &'static str)> {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        anyhow::bail!("unsupported OS for release download")
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        anyhow::bail!("unsupported architecture for release download")
    };

    Ok((os, arch))
}

fn dirs_cache() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache");
    }
    PathBuf::from("/tmp")
}

use anyhow::Context;

/// Configuration for a single DefraDB node.
#[derive(Clone)]
pub struct NodeConfig {
    pub name: String,
    pub rootdir: PathBuf,
    pub log_dir: PathBuf,
    pub http_addr: String,
    pub p2p_enabled: bool,
    pub p2p_addr: Option<String>,
    pub peers: Vec<String>,
    pub identity: Option<String>,
    pub acp_document_type: Option<String>,
    pub encryption_enabled: bool,
    pub signing_enabled: bool,
    pub nac_enabled: bool,
    pub source_hub_address: Option<String>,
    pub source_hub_comet_address: Option<String>,
    pub source_hub_chain_id: Option<String>,
    pub development: bool,
    pub store: Option<String>,
    pub query_timeout: Option<u64>,
    pub p2p_transport: Option<String>,
    pub keyring_enabled: bool,
}

/// Trait for building a DefraDB command from config.
pub trait DefraNode {
    fn kind(&self) -> NodeKind;
    fn command(&self, config: &NodeConfig) -> Command;
    fn api_url(host: &str, port: u16) -> String
    where
        Self: Sized,
    {
        format!("http://{}:{}", host, port)
    }
    fn prepare(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn binary_path(&self) -> &Path;
}
