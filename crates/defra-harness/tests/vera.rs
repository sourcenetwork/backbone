use std::path::PathBuf;

use defra_harness::node::RustNode;
use defra_harness::VeraNodeConfig;
use vera_support::VeraDeployment;

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

/// Validator key seed and deployment identifier of the deployment these tests start.
const VERA_SEED: u64 = 42;
const VERA_DEPLOYMENT_ID: u64 = 9003;

/// Start the deployment a test's nodes attach to. Declared before the
/// cluster, it outlives the nodes and stops when the test drops it.
async fn start_vera() -> VeraDeployment {
    VeraDeployment::start(VERA_SEED, VERA_DEPLOYMENT_ID)
        .await
        .expect("failed to start Vera deployment")
}

/// How a DefraDB node reaches `deployment`.
fn node_config(deployment: &VeraDeployment) -> VeraNodeConfig {
    VeraNodeConfig {
        address: deployment.rpc_url(),
        consensus_key: deployment.consensus_key_hex(),
        genesis_id: deployment.genesis_id_hex(),
        deployment_id: deployment.deployment_id(),
    }
}
