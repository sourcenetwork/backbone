use std::path::PathBuf;

use defra_harness::node::RustNode;

#[path = "vera/compartments.rs"]
mod compartments;
#[path = "vera/p2p_acp.rs"]
mod p2p_acp;
#[path = "vera/policy_lifecycle.rs"]
mod policy_lifecycle;
#[path = "vera/resilience.rs"]
mod resilience;
#[path = "vera/smoke.rs"]
mod smoke;

/// The DefraDB binary these tests run: `DEFRA_RUST_BINARY`, or the workspace
/// build with the `vera` feature that the native Vera provider needs.
fn vera_binary() -> PathBuf {
    if let Ok(path) = std::env::var("DEFRA_RUST_BINARY") {
        return path.into();
    }
    RustNode::build_with_features(&["vera"]).expect("build rust binary with vera");
    RustNode::workspace_binary_path()
}
