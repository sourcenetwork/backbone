//! Orbis rings on a native Vera deployment for integration tests.
//!
//! - `OrbisRingBuilder` starts orbis-node processes configured for a
//!   `VeraDeployment`
//! - `RingAdmin` registers nodes, creates rings and stores documents through
//!   native Vera requests
//! - `DkgFixture` runs a deployment, a ring and its key generation

pub mod admin;
pub mod defradb;
mod did;
pub mod fixture;
pub mod ring;
pub mod vera;

pub use admin::{RingAdmin, RING_POLICY_YAML};
pub use defra_harness::node::RustNode;
pub use defra_harness::{start_node, KeyringBackend, NodeConfig, OrbisSignerConfig, RunningNode};
pub use defradb::identity::DefraHttpClient;
pub use did::{derived_public_key, ed25519_identity_hex, signer_did_for_pk};
pub use fixture::DkgFixture;
pub use ring::{OrbisNode, OrbisRing, OrbisRingBuilder};
pub use vera::OrbisVeraConfig;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use rand::Rng;

/// Generate a unique run ID based on timestamp + random suffix.
pub fn generate_run_id() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let suffix: u32 = rand::thread_rng().gen_range(1000..9999);
    format!("{ts}-{suffix}")
}

/// Generate a deterministic 256-bit value from run_id and node index.
pub fn u256_from_seed(run_id: &str, node_index: usize) -> u128 {
    let mut hasher = DefaultHasher::new();
    run_id.hash(&mut hasher);
    node_index.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    node_index.hash(&mut hasher2);
    let h2 = hasher2.finish();

    ((h1 as u128) << 64) | (h2 as u128)
}

/// Generate deterministic identity keys for N nodes.
///
/// Returns hex-encoded 256-bit secret keys derived from the run_id.
pub fn generate_identity_keys(run_id: &str, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("{:0>64x}", u256_from_seed(run_id, i)))
        .collect()
}

/// Base directory for orbis e2e test artifacts.
pub fn e2e_base_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."))
        .join("target")
        .join("e2e")
        .join("orbis")
}
