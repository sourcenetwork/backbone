//! Reads and parses the `backbone.toml` component version manifest.
//!
//! The manifest declares which git repo and ref each binary dependency should
//! be built from. [`BinaryResolver`](crate::BinaryResolver) consults it as a
//! fallback when the binary isn't found via env var, workspace build, or PATH.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Parsed contents of `backbone.toml`.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub components: HashMap<String, ComponentPin>,
}

/// A single component entry in the manifest.
#[derive(Debug, Deserialize)]
pub struct ComponentPin {
    pub prefix: String,
    pub repo: Option<String>,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub cargo_package: Option<String>,
}

const MANIFEST_FILENAME: &str = "backbone.toml";

impl Manifest {
    /// Walk up from `start` to find `backbone.toml`, then parse it.
    ///
    /// Returns `None` if no manifest is found in any ancestor directory.
    pub fn discover_from(start: &Path) -> Option<Self> {
        let path = find_manifest(start)?;
        let contents = std::fs::read_to_string(&path).ok()?;
        match toml::from_str(&contents) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to parse backbone.toml");
                None
            }
        }
    }

    /// Walk up from the current working directory to find and parse `backbone.toml`.
    pub fn discover() -> Option<Self> {
        let cwd = std::env::current_dir().ok()?;
        Self::discover_from(&cwd)
    }

    /// Find the component whose `prefix` matches the given value.
    pub fn find_by_prefix(&self, prefix: &str) -> Option<&ComponentPin> {
        self.components.values().find(|c| c.prefix == prefix)
    }
}

/// Find the backbone project root (directory containing `backbone.toml`).
pub fn find_project_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    find_manifest(&cwd).map(|p| p.parent().unwrap().to_path_buf())
}

/// Walk up from `start` looking for `backbone.toml`.
fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(MANIFEST_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}
