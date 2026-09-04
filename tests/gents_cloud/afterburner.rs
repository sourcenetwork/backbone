//! The Afterburner half of the architecture, checked at the artifact level.
//!
//! gents-cloud states that a sealed package's permission surface is its
//! `manifold.json`, that an absent field stays sealed, that package identity is
//! the digest of its bytes (H4), and that `child_process` never appears in a
//! cloud manifold (§26). Those are properties of the artifact, so they can be
//! asserted without running anything: this scenario reads the packages the
//! defraburner proof of concept ships and checks them.
//!
//! What it deliberately does not do is re-test Afterburner's runtime. Fuel
//! exhaustion, the policy clamp, gateway admission, and the lifecycle of the
//! wasm DefraDB each cell owns are covered by defraburner's own suite, against
//! its own binary, which is where those mechanisms live.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::fixture::Stack;
use crate::{banner, passed, Scenario};

const SEALED_PACKAGES: Scenario = Scenario {
    id: "afterburner_sealed_packages",
    spec: "gents-cloud §1.1 (the manifold is the whole permission surface), H4, H11, §26 ban list, I-3",
    claim: "every sealed package the proof of concept ships declares a fully sealed manifold, grants no child process, and is identified by the digest of its bytes",
};

/// Where the defraburner checkout lives. It is the proof of concept for the
/// cell, mesh, gateway and policy half of the architecture.
fn defraburner_dir() -> Option<PathBuf> {
    let dir = std::env::var("DEFRABURNER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("projects/defraburner")
        });
    dir.join("packages").is_dir().then_some(dir)
}

pub async fn run(stack: &mut Stack) {
    let t = banner(&SEALED_PACKAGES);

    let Some(dir) = defraburner_dir() else {
        // Not evaluated is recorded, never passed over in silence.
        stack.record(
            "afterburner_sealed_packages",
            "not evaluated: no defraburner checkout (set DEFRABURNER_DIR)",
        );
        passed(&SEALED_PACKAGES, t);
        return;
    };

    let packages = dir.join("packages");
    let mut checked = Vec::new();
    for entry in std::fs::read_dir(&packages).expect("read packages directory") {
        let package = entry.expect("package entry").path();
        if !package.is_dir() {
            continue;
        }
        let name = package
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        let manifold_path = package.join("manifold.json");
        if !manifold_path.is_file() {
            continue;
        }
        let manifold: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifold_path).expect("read manifold"))
                .unwrap_or_else(|e| panic!("{}: parse manifold.json: {}", name, e));

        // The ban list is absolute: no cloud manifold grants a child process.
        assert_eq!(
            manifold.get("child_process").and_then(|v| v.as_bool()),
            Some(false),
            "{}: child_process must be false; the WASM backend refuses it and the \
             cloud build bans it outright",
            name
        );
        // Sealed by default means every capability is off unless the package
        // states otherwise. These four are the ones a database or a policy
        // package has no business holding.
        for (field, expected) in [
            ("fs", "None"),
            ("net", "None"),
            ("env", "None"),
            ("listen", "None"),
        ] {
            assert_eq!(
                manifold.get(field).and_then(|v| v.as_str()),
                Some(expected),
                "{}: {} must be {}",
                name,
                field,
                expected
            );
        }
        assert_eq!(
            manifold.get("allow_exit").and_then(|v| v.as_bool()),
            Some(false),
            "{}: allow_exit must be false",
            name
        );

        // Package identity is the digest of the bytes, not the file name.
        let archive = newest_afb(&package)
            .unwrap_or_else(|| panic!("{}: no .afb archive beside the manifold", name));
        let bytes = std::fs::read(&archive).expect("read archive");
        assert!(
            bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]),
            "{}: the archive must be zstd, which is what makes the format byte-reproducible",
            name
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        checked.push(format!(
            "{} {} ({} bytes)",
            name,
            &digest[..16],
            bytes.len()
        ));
    }

    assert!(
        !checked.is_empty(),
        "a defraburner checkout must ship at least one sealed package"
    );
    for line in &checked {
        eprintln!("[gents-cloud]   sealed package {}", line);
    }
    stack.record(
        "afterburner_sealed_packages",
        format!(
            "{} packages, all sealed: {}",
            checked.len(),
            checked.join("; ")
        ),
    );

    passed(&SEALED_PACKAGES, t);
}

/// The most recently built `.afb` archive in a package directory.
fn newest_afb(package: &Path) -> Option<PathBuf> {
    let mut archives: Vec<PathBuf> = std::fs::read_dir(package)
        .ok()?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("afb"))
        .collect();
    archives.sort();
    archives.pop()
}
