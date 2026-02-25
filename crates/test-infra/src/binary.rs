//! Version-aware binary resolution for integration test dependencies.
//!
//! Each component in the stack (defra, hubd, orbis-node, sourcehubd) needs to be
//! resolved at test time. The resolution order supports both local development
//! (dirty working tree) and CI (pinned versions):
//!
//! 1. **Env var override** — explicit path, skips all checks
//! 2. **Local workspace build** — `cargo build` in a workspace directory
//! 3. **PATH lookup** — find binary on PATH, optionally version-check
//! 4. **Manifest lookup** — read `backbone.toml` for repo/ref, build from source
//! 5. **Env var git build** — `{PREFIX}_GIT_REPO` + `{PREFIX}_GIT_REF`
//!
//! When a version pin is set (via env var), the resolver verifies the binary's
//! reported version matches. This keeps the stack in sync across repos.

use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{ContextCompat, Result, WrapErr};

use crate::manifest::Manifest;

/// How a binary was resolved.
#[derive(Debug, Clone)]
pub enum BinarySource {
    /// Explicit path from env var (no version check).
    EnvOverride,
    /// Built from a local workspace via `cargo build`.
    LocalBuild { workspace: PathBuf },
    /// Found on PATH (version-checked if pin was set).
    Path,
    /// Built from source at a specific git ref.
    BuiltFromSource { repo: String, git_ref: String },
}

/// A resolved binary ready for use in tests.
#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    pub path: PathBuf,
    pub version: Option<String>,
    pub source: BinarySource,
}

/// Resolves a component binary using the standard resolution order.
///
/// Configuration is env-var-driven so each consuming repo controls resolution:
///
/// | Env Var | Example | Effect |
/// |---------|---------|--------|
/// | `{PREFIX}_BINARY` | `DEFRA_BINARY=/path/to/defra` | Use this path directly |
/// | `{PREFIX}_WORKSPACE` | `DEFRA_WORKSPACE=/path/to/defradb.rs` | Build from this workspace |
/// | `{PREFIX}_CARGO_PACKAGE` | `DEFRA_CARGO_PACKAGE=cli` | Package name for `cargo build -p` |
/// | `{PREFIX}_VERSION_PIN` | `DEFRA_VERSION_PIN=4b8993f8` | Expected version/commit prefix |
/// | `{PREFIX}_SKIP_VERSION_CHECK` | `DEFRA_SKIP_VERSION_CHECK=1` | Skip version verification |
/// | `{PREFIX}_GIT_REPO` | `DEFRA_GIT_REPO=https://...` | Clone and build from source |
/// | `{PREFIX}_GIT_REF` | `DEFRA_GIT_REF=v0.5.0` | Git ref to checkout |
pub struct BinaryResolver {
    /// Env var prefix (e.g., "DEFRA", "HUBD", "ORBIS").
    prefix: String,
    /// Binary name on PATH (e.g., "defra", "hubd", "orbis-node").
    binary_name: String,
    /// Default cargo package name for workspace builds.
    default_cargo_package: Option<String>,
    /// Command to extract version from the binary (e.g., ["version", "--format", "json"]).
    version_args: Vec<String>,
    /// Function to extract a version string from command output.
    version_extractor: fn(&str) -> Option<String>,
}

impl BinaryResolver {
    pub fn new(prefix: &str, binary_name: &str) -> Self {
        Self {
            prefix: prefix.to_uppercase(),
            binary_name: binary_name.to_string(),
            default_cargo_package: None,
            version_args: vec!["version".to_string()],
            version_extractor: |output| Some(output.trim().to_string()),
        }
    }

    /// Set the default cargo package name for workspace builds.
    pub fn cargo_package(mut self, pkg: &str) -> Self {
        self.default_cargo_package = Some(pkg.to_string());
        self
    }

    /// Set the command args to extract version info from the binary.
    pub fn version_args(mut self, args: &[&str]) -> Self {
        self.version_args = args.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the function that extracts a version string from command output.
    pub fn version_extractor(mut self, f: fn(&str) -> Option<String>) -> Self {
        self.version_extractor = f;
        self
    }

    fn env(&self, suffix: &str) -> Option<String> {
        std::env::var(format!("{}_{}", self.prefix, suffix)).ok()
    }

    /// Resolve the binary using the standard resolution order.
    pub fn resolve(&self) -> Result<ResolvedBinary> {
        // 1. Explicit path override
        if let Some(path) = self.env("BINARY") {
            let path = PathBuf::from(&path);
            eyre::ensure!(
                path.exists(),
                "{} does not exist: {}",
                self.prefix,
                path.display()
            );
            return Ok(ResolvedBinary {
                path,
                version: None,
                source: BinarySource::EnvOverride,
            });
        }

        // 2. Local workspace build
        if let Some(workspace) = self.env("WORKSPACE") {
            let workspace = PathBuf::from(&workspace);
            let pkg = self
                .env("CARGO_PACKAGE")
                .or_else(|| self.default_cargo_package.clone())
                .wrap_err(format!(
                    "{}_CARGO_PACKAGE not set and no default configured",
                    self.prefix
                ))?;

            return self.build_from_workspace(&workspace, &pkg);
        }

        // 3. PATH lookup with optional version check
        if let Ok(resolved) = self.resolve_from_path() {
            return Ok(resolved);
        }

        // 4. Manifest lookup (backbone.toml)
        if let Some(resolved) = self.resolve_from_manifest()? {
            return Ok(resolved);
        }

        // 5. Build from source via env vars (git clone + cargo build)
        if let (Some(repo), Some(git_ref)) = (self.env("GIT_REPO"), self.env("GIT_REF")) {
            return self.build_from_git(&repo, &git_ref, None);
        }

        eyre::bail!(
            "Cannot resolve binary '{}'. Set {}_BINARY, {}_WORKSPACE, or ensure '{}' is on PATH.",
            self.binary_name,
            self.prefix,
            self.prefix,
            self.binary_name
        )
    }

    fn build_from_workspace(&self, workspace: &Path, package: &str) -> Result<ResolvedBinary> {
        tracing::info!(
            workspace = %workspace.display(),
            package = package,
            "Building {} from local workspace",
            self.binary_name
        );

        let status = Command::new("cargo")
            .args(["build", "-p", package])
            .current_dir(workspace)
            .status()
            .wrap_err(format!(
                "failed to run cargo build in {}",
                workspace.display()
            ))?;

        eyre::ensure!(status.success(), "cargo build -p {} failed", package);

        let binary_path = workspace.join("target/debug").join(&self.binary_name);
        eyre::ensure!(
            binary_path.exists(),
            "Built binary not found at {}",
            binary_path.display()
        );

        let version = self.extract_version(&binary_path);

        Ok(ResolvedBinary {
            path: binary_path,
            version,
            source: BinarySource::LocalBuild {
                workspace: workspace.to_path_buf(),
            },
        })
    }

    fn resolve_from_path(&self) -> Result<ResolvedBinary> {
        let output = Command::new("which")
            .arg(&self.binary_name)
            .output()
            .wrap_err(format!("'{}' not found on PATH", self.binary_name))?;

        eyre::ensure!(
            output.status.success(),
            "'{}' not found on PATH",
            self.binary_name
        );

        let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        let version = self.extract_version(&path);

        // Version pin check
        if let Some(pin) = self.env("VERSION_PIN") {
            let skip = self.env("SKIP_VERSION_CHECK").as_deref() == Some("1");
            if let Some(ref ver) = version {
                if !ver.starts_with(&pin) {
                    if skip {
                        tracing::warn!(
                            expected = %pin,
                            actual = %ver,
                            "Version mismatch for {} (skipped via {}_SKIP_VERSION_CHECK)",
                            self.binary_name, self.prefix
                        );
                    } else {
                        eyre::bail!(
                            "Version mismatch for {}: expected prefix '{}', got '{}'. \
                             Set {}_SKIP_VERSION_CHECK=1 to bypass.",
                            self.binary_name,
                            pin,
                            ver,
                            self.prefix
                        );
                    }
                }
            }
        }

        Ok(ResolvedBinary {
            path,
            version,
            source: BinarySource::Path,
        })
    }

    fn resolve_from_manifest(&self) -> Result<Option<ResolvedBinary>> {
        let manifest = match Manifest::discover() {
            Some(m) => m,
            None => return Ok(None),
        };

        let pin = match manifest.find_by_prefix(&self.prefix) {
            Some(p) => p,
            None => return Ok(None),
        };

        let (repo, git_ref) = match (&pin.repo, &pin.git_ref) {
            (Some(r), Some(g)) => (r.as_str(), g.as_str()),
            _ => return Ok(None),
        };

        let pkg = pin
            .cargo_package
            .as_deref()
            .or(self.default_cargo_package.as_deref());

        tracing::info!(
            prefix = %self.prefix,
            repo = repo,
            git_ref = git_ref,
            "Resolving {} from backbone.toml manifest",
            self.binary_name
        );

        self.build_from_git(repo, git_ref, pkg).map(Some)
    }

    fn build_from_git(
        &self,
        repo: &str,
        git_ref: &str,
        cargo_package: Option<&str>,
    ) -> Result<ResolvedBinary> {
        let build_dir = std::env::temp_dir()
            .join("backbone-builds")
            .join(&self.binary_name)
            .join(git_ref.replace('/', "_"));

        if !build_dir.exists() {
            tracing::info!(
                repo = repo,
                git_ref = git_ref,
                "Cloning and building from source"
            );

            let status = Command::new("git")
                .args(["clone", "--depth", "1", "--branch", git_ref, repo])
                .arg(&build_dir)
                .status()
                .wrap_err("git clone failed")?;

            eyre::ensure!(
                status.success(),
                "git clone failed for {} @ {}",
                repo,
                git_ref
            );
        }

        let pkg = cargo_package
            .map(|s| s.to_string())
            .or_else(|| self.env("CARGO_PACKAGE"))
            .or_else(|| self.default_cargo_package.clone())
            .wrap_err(format!(
                "{}_CARGO_PACKAGE not set for source build",
                self.prefix
            ))?;

        let status = Command::new("cargo")
            .args(["build", "-p", &pkg])
            .current_dir(&build_dir)
            .status()
            .wrap_err("cargo build from source failed")?;

        eyre::ensure!(status.success(), "cargo build from source failed");

        let binary_path = build_dir.join("target/debug").join(&self.binary_name);
        eyre::ensure!(binary_path.exists(), "Binary not found after source build");

        let version = self.extract_version(&binary_path);

        Ok(ResolvedBinary {
            path: binary_path,
            version,
            source: BinarySource::BuiltFromSource {
                repo: repo.to_string(),
                git_ref: git_ref.to_string(),
            },
        })
    }

    fn extract_version(&self, binary: &Path) -> Option<String> {
        let output = Command::new(binary)
            .args(&self.version_args)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        (self.version_extractor)(&stdout)
    }
}
