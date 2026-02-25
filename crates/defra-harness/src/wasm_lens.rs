//! WASM lens module build and caching.
//!
//! Builds a WASM lens module for schema migration tests.
//! The module is compiled once per process and cached.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use eyre::{Result, WrapErr};

static BUILD_DONE: OnceLock<()> = OnceLock::new();

pub struct WasmLens {
    source_dir: PathBuf,
}

impl WasmLens {
    pub fn new(source_dir: PathBuf) -> Self {
        Self { source_dir }
    }

    /// Build the WASM lens module (once per process).
    pub fn build(&self) -> Result<()> {
        BUILD_DONE.get_or_init(|| {
            self.do_build().expect("failed to build WASM lens");
        });
        Ok(())
    }

    fn do_build(&self) -> Result<()> {
        let wasm_path = self.wasm_file_path();
        if self.wasm_is_current(&wasm_path) {
            return Ok(());
        }

        // Verify wasm32-unknown-unknown target is installed
        let target_check = Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()
            .wrap_err("failed to run rustup")?;
        let installed = String::from_utf8_lossy(&target_check.stdout);
        eyre::ensure!(
            installed.contains("wasm32-unknown-unknown"),
            "wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown"
        );

        eprintln!("Building WASM lens module from {:?}...", self.source_dir);
        let status = Command::new("cargo")
            .args([
                "build",
                "--target",
                "wasm32-unknown-unknown",
                "--manifest-path",
            ])
            .arg(self.source_dir.join("Cargo.toml"))
            .status()
            .wrap_err("failed to run cargo build for WASM lens")?;

        eyre::ensure!(status.success(), "cargo build failed for WASM lens");

        eyre::ensure!(
            wasm_path.exists(),
            "WASM file not found after build at {}",
            wasm_path.display()
        );

        Ok(())
    }

    /// Check if the .wasm file exists and is newer than source files.
    fn wasm_is_current(&self, wasm_path: &PathBuf) -> bool {
        let wasm_mtime = match std::fs::metadata(wasm_path) {
            Ok(m) => match m.modified() {
                Ok(t) => t,
                Err(_) => return false,
            },
            Err(_) => return false,
        };

        let sources = [
            self.source_dir.join("Cargo.toml"),
            self.source_dir.join("src/lib.rs"),
        ];

        for src in &sources {
            if let Ok(meta) = std::fs::metadata(src) {
                if let Ok(mtime) = meta.modified() {
                    if mtime > wasm_mtime {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Return the file:// prefixed path to the compiled WASM module.
    pub fn module_path(&self) -> String {
        format!("file://{}", self.wasm_file_path().display())
    }

    /// Read the raw compiled WASM bytes.
    pub fn module_bytes(&self) -> Vec<u8> {
        std::fs::read(self.wasm_file_path()).expect("read WASM file")
    }

    /// Derive the crate name from the source directory name.
    fn crate_name(&self) -> String {
        self.source_dir
            .file_name()
            .expect("source_dir has no file name")
            .to_string_lossy()
            .replace('-', "_")
    }

    /// Path to the compiled .wasm file.
    fn wasm_file_path(&self) -> PathBuf {
        let wasm_name = format!("{}_lens.wasm", self.crate_name());
        self.source_dir
            .join("target/wasm32-unknown-unknown/debug")
            .join(wasm_name)
    }
}
