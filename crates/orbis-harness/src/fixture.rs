//! DKG fixture for e2e tests.
//!
//! Running DKG is expensive (~30-40s). This module provides a helper that
//! starts a Vera deployment and a 3-node ring, runs DKG, and returns the
//! results.
//!
//! The returned `DkgFixture` owns the ring, the deployment and the run
//! directory. Drop order is: ring -> vera -> run_dir (by field order).

use std::time::Duration;

use cli_tool::NodeInfoResult;
use vera_support::VeraDeployment;

use crate::admin::{RingAdmin, RING_POLICY_YAML};
use crate::ring::OrbisRing;
use crate::vera::OrbisVeraConfig;
use crate::{generate_identity_keys, generate_run_id};

const VERA_SEED: u64 = 42;
const VERA_DEPLOYMENT_ID: u64 = 9003;
const READY_TIMEOUT: Duration = Duration::from_secs(90);
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(240);

/// Results of a completed DKG ceremony, ready for use by tests.
///
/// Field drop order: ring (orbis nodes killed first) -> vera -> run_dir (cleaned last).
pub struct DkgFixture {
    pub ring: OrbisRing,
    pub admin: RingAdmin,
    pub vera: VeraDeployment,
    pub ring_pk_hex: String,
    pub ring_id: String,
    /// The policy the ring was created under, which also governs its documents.
    pub policy_id: String,
    pub node_infos: Vec<NodeInfoResult>,
    _run_dir: test_infra::TestRunDir,
}

impl DkgFixture {
    pub fn endpoint(&self) -> String {
        self.ring.node(0).grpc_addr()
    }
}

/// Start a Vera deployment and a 3-node ring, run DKG, and return the fixture.
///
/// The returned fixture owns all processes — they are killed when the
/// fixture is dropped.
pub async fn setup_dkg() -> DkgFixture {
    eprintln!("[fixture] Starting DKG fixture (3 nodes + Vera)...");

    let run_id = generate_run_id();
    let base_dir = crate::e2e_base_dir();
    let run_dir =
        test_infra::TestRunDir::new(&base_dir, "ORBIS_E2E_KEEP").expect("fixture: create run dir");
    let identity_keys = generate_identity_keys(&run_id, 3);

    let vera = VeraDeployment::start(VERA_SEED, VERA_DEPLOYMENT_ID)
        .await
        .expect("fixture: Vera should start");
    let admin = RingAdmin::new(&vera)
        .await
        .expect("fixture: connect the ring administrator");

    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(identity_keys)
        .vera(OrbisVeraConfig::from(&vera))
        .controller_key(admin.controller_key_hex())
        .build()
        .await
        .expect("fixture: ring should start");

    let node_infos = ring
        .wait_ready(READY_TIMEOUT)
        .await
        .expect("fixture: all nodes should be ready");

    let policy_id = admin
        .account()
        .create_policy(RING_POLICY_YAML)
        .await
        .expect("fixture: create ring policy");
    for info in &node_infos {
        admin
            .authorize_node(&info.node_key, &info.p2p_address, &policy_id, READY_TIMEOUT)
            .await
            .expect("fixture: authorize node");
    }
    let node_keys: Vec<String> = node_infos
        .iter()
        .map(|info| info.node_key.clone())
        .collect();
    let ring_id = admin
        .create_ring(&policy_id, &node_keys, ring.threshold())
        .await
        .expect("fixture: create ring");

    eprintln!("[fixture] Running DKG...");
    cli_tool::do_dkg(ring.node(0).grpc_addr(), ring_id.clone())
        .await
        .expect("fixture: DKG should start");
    let ring_pk_hex = admin
        .wait_for_ring_key(&ring_id, FINALIZE_TIMEOUT)
        .await
        .expect("fixture: DKG should finalize");

    eprintln!(
        "[fixture] DKG complete. Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    DkgFixture {
        ring,
        admin,
        vera,
        ring_pk_hex,
        ring_id,
        policy_id,
        node_infos,
        _run_dir: run_dir,
    }
}
