mod go_node;
mod running;
mod rust_node;

pub use go_node::GoNode;
pub use running::{start_node, RunningNode};
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
    pub fn resolve(&self, kind: NodeKind) -> eyre::Result<PathBuf> {
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
                eyre::ensure!(p.exists(), "binary not found at {}", p.display());
                Ok(p.clone())
            }
            BinarySource::Release(version) => resolve_release(version, kind),
        }
    }
}

/// Download (or return cached) a release binary for the given version and node kind.
fn resolve_release(version: &str, kind: NodeKind) -> eyre::Result<PathBuf> {
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
        .wrap_err_with(|| format!("failed to download {}", url))?;

    eyre::ensure!(
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

fn release_asset_name(version: &str, kind: NodeKind) -> eyre::Result<String> {
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

fn current_platform() -> eyre::Result<(&'static str, &'static str)> {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        eyre::bail!("unsupported OS for release download")
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        eyre::bail!("unsupported architecture for release download")
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

use eyre::WrapErr;

/// How the DefraDB keyring is configured.
#[derive(Clone, Debug)]
pub enum KeyringBackend {
    /// No keyring (`--no-keyring` flag).
    None,
    /// Environment-based keyring (`DEFRA_KEYRING_SECRET` env var).
    Env { secret: String },
    /// File-based keyring (`--keyring-backend file --keyring-path <path>`).
    File { path: PathBuf, secret: String },
}

/// Configuration for DefraDB's Orbis signer integration.
///
/// When provided, DefraDB delegates document signing to an Orbis ring
/// via gRPC threshold signing instead of using a local key.
#[derive(Clone, Debug)]
pub struct OrbisSignerConfig {
    /// gRPC endpoint of an Orbis node (e.g. `"http://127.0.0.1:8081"`).
    pub endpoint: String,
    /// Ring ID to sign with (from DKG bulletin post).
    pub ring_id: String,
    /// Derivation label (e.g. `"x-archive"`) for derived key signing.
    pub derivation: String,
}

/// Configuration for a single DefraDB node.
#[derive(Clone, Debug)]
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
    pub source_hub: Option<sourcehub_harness::SourceHubConfig>,
    pub orbis_signer: Option<OrbisSignerConfig>,
    pub keyring: KeyringBackend,
    pub development: bool,
    pub store: Option<String>,
    pub query_timeout: Option<u64>,
    pub p2p_transport: Option<String>,
}

impl NodeConfig {
    pub fn new(
        name: impl Into<String>,
        rootdir: PathBuf,
        log_dir: PathBuf,
        http_addr: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            rootdir,
            log_dir,
            http_addr: http_addr.into(),
            p2p_enabled: false,
            p2p_addr: None,
            peers: vec![],
            identity: None,
            acp_document_type: None,
            encryption_enabled: false,
            signing_enabled: false,
            nac_enabled: false,
            source_hub: None,
            orbis_signer: None,
            keyring: KeyringBackend::None,
            development: false,
            store: None,
            query_timeout: None,
            p2p_transport: None,
        }
    }
}

/// Trait for building a DefraDB command from config.
pub trait DefraNode {
    fn kind(&self) -> NodeKind;
    /// Return (program, args, envs) for spawning via ManagedProcess.
    fn command_parts(&self, config: &NodeConfig) -> (PathBuf, Vec<String>, Vec<(String, String)>);
    fn api_url(host: &str, port: u16) -> String
    where
        Self: Sized,
    {
        format!("http://{}:{}", host, port)
    }
    fn prepare(&self) -> eyre::Result<()> {
        Ok(())
    }
    fn binary_path(&self) -> &Path;
}
