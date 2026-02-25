//! DKG fixture for e2e tests.
//!
//! Running DKG is expensive (~30-40s). This module provides a helper that
//! starts a 3-node ring, runs DKG, and returns the results.
//!
//! The returned `DkgFixture` owns the ring, SourceHub, and run directory
//! independently. Drop order is: ring -> sourcehub -> run_dir (by field order).

use sourcehub_harness::SourceHubNode;
use std::time::Duration;

use crate::cli::types::{NodeInfoResult, RingPayload};
use crate::cli::{BulletinEventSubscription, OrbisCliClient, SourceHubCliClient};
use crate::ring::OrbisRing;
use crate::{allocate_source_hub_ports, generate_identity_keys, generate_run_id};
use sourcehub_harness::SourceHubConfig;

/// The bulletin namespace used for ring payloads (must match orbis-node constant).
const BULLETIN_RING_NAMESPACE: &str = "orbis";

/// Results of a completed DKG ceremony, ready for use by tests.
///
/// Field drop order: ring (orbis nodes killed first) -> sourcehub -> run_dir (cleaned last).
pub struct DkgFixture {
    pub ring: OrbisRing,
    pub sourcehub: SourceHubNode,
    pub ring_pk_hex: String,
    pub ring_id: String,
    pub node_infos: Vec<NodeInfoResult>,
    pub orbis_cli: OrbisCliClient,
    pub sourcehub_cli: SourceHubCliClient,
    _run_dir: test_infra::TestRunDir,
}

impl DkgFixture {
    pub fn endpoint(&self) -> String {
        self.ring.node(0).grpc_addr()
    }
}

/// Start a 3-node ring with SourceHub, run DKG, and return the fixture.
///
/// This takes ~30-40s. The returned fixture owns all processes — they are
/// killed when the fixture is dropped.
pub async fn setup_dkg() -> DkgFixture {
    eprintln!("[fixture] Starting DKG fixture (3 nodes + SourceHub)...");

    let run_id = generate_run_id();
    let base_dir = crate::e2e_base_dir();
    let run_dir =
        test_infra::TestRunDir::new(&base_dir, "ORBIS_E2E_KEEP").expect("fixture: create run dir");
    let identity_keys = generate_identity_keys(&run_id, 3);

    // Start SourceHub
    let sh_ports = allocate_source_hub_ports().expect("fixture: allocate sourcehub ports");
    let sh_home = run_dir
        .node_dir("sourcehub")
        .expect("fixture: create sourcehub dir");
    let sh_log_dir = sh_home.join("logs");
    std::fs::create_dir_all(&sh_log_dir).expect("fixture: create sourcehub log dir");

    let sourcehub = SourceHubNode::start(
        sh_home,
        sh_log_dir,
        &sh_ports,
        &identity_keys,
        Duration::from_secs(60),
    )
    .await
    .expect("fixture: sourcehub should start");

    // Build the ring
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(identity_keys)
        .sourcehub_config(SourceHubConfig::from(&sourcehub))
        .build()
        .await
        .expect("fixture: ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("fixture: all nodes should be healthy");

    let orbis_cli = OrbisCliClient::new().expect("fixture: resolve cli-tool binary");
    let sourcehub_cli =
        SourceHubCliClient::from_node(&sourcehub).expect("fixture: resolve sourcehubd binary");

    // Query node info
    let mut node_infos = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let info = orbis_cli
            .query_node_info(&ring.node(i).grpc_addr())
            .unwrap_or_else(|e| panic!("fixture: query node{} info: {}", i, e));
        node_infos.push(info);
    }

    // Register ring namespace + add all nodes as collaborators
    sourcehub_cli
        .register_namespace(BULLETIN_RING_NAMESPACE)
        .expect("fixture: register ring namespace");

    for info in &node_infos {
        sourcehub_cli
            .add_collaborator(BULLETIN_RING_NAMESPACE, &info.public_address)
            .expect("fixture: add collaborator");
    }

    // Subscribe to events BEFORE starting DKG
    let event_subscription = BulletinEventSubscription::connect(&sourcehub.comet_rpc_url)
        .await
        .expect("fixture: event subscription");

    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();

    // Run DKG
    eprintln!("[fixture] Running DKG...");
    let dkg_result = orbis_cli
        .do_dkg(&ring.node(0).grpc_addr(), ring.threshold(), &peer_ids)
        .expect("fixture: DKG should succeed");

    let session_id = dkg_result.session_id;
    let post_event = event_subscription
        .wait_for_artifact(&session_id, Duration::from_secs(120))
        .await
        .expect("fixture: DKG completion event");

    // Read ring payload
    let post_payload = sourcehub_cli
        .read_post(BULLETIN_RING_NAMESPACE, &post_event.post_id)
        .expect("fixture: read ring post");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("fixture: parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;
    let ring_id = post_event.post_id;

    eprintln!(
        "[fixture] DKG complete. Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    DkgFixture {
        ring,
        sourcehub,
        ring_pk_hex,
        ring_id,
        node_infos,
        orbis_cli,
        sourcehub_cli,
        _run_dir: run_dir,
    }
}
