//! Three-component smoke test: SourceHub + DefraDB + Orbis.

use std::time::Duration;

use common::blockchain::events::BulletinEventSubscription;
use orbis_harness::defradb::{self, DefraDbNode};
use orbis_harness::ring::{OrbisRing, SourceHubUrls};
use orbis_harness::sourcehub::{self, SourceHubNode};
use orbis_harness::{generate_identity_keys, generate_run_id};

const BULLETIN_RING_NAMESPACE: &str = "orbis";
const SIMPLE_SCHEMA: &str = "type Note { title: String  body: String }";

#[tokio::test]
#[ignore = "requires sourcehubd and defra on PATH, ~2 min runtime"]
async fn three_component_smoke() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    // ================================================================
    // Setup: generate identities and shared run directory
    // ================================================================
    let run_id = generate_run_id();
    let base_dir = orbis_harness::e2e_base_dir();
    let run_dir = test_infra::TestRunDir::new(&base_dir, "ORBIS_E2E_KEEP").expect("create run dir");

    let all_keys = generate_identity_keys(&run_id, 4);
    let orbis_keys: Vec<String> = all_keys[..3].to_vec();
    let defra_key = &all_keys[3];

    eprintln!("[smoke] Run ID: {}", run_id);

    // ================================================================
    // 1. Start SourceHub
    // ================================================================
    eprintln!("[smoke] Starting SourceHub...");
    let sh_ports = sourcehub::allocate_source_hub_ports().expect("allocate sourcehub ports");
    let sh_home = run_dir.node_dir("sourcehub").expect("create sourcehub dir");
    let sh_log_dir = sh_home.join("logs");
    std::fs::create_dir_all(&sh_log_dir).expect("create sourcehub log dir");

    let sourcehub = SourceHubNode::start(
        sh_home,
        sh_log_dir,
        &sh_ports,
        &all_keys,
        Duration::from_secs(60),
    )
    .await
    .expect("sourcehub should start");

    eprintln!(
        "[smoke] SourceHub ready: LCD={}, gRPC={}, RPC={}",
        sourcehub.lcd_url, sourcehub.grpc_url, sourcehub.comet_rpc_url
    );

    // ================================================================
    // 2. Start DefraDB with identity + file keyring + SourceHub ACP
    // ================================================================
    eprintln!("[smoke] Starting DefraDB with identity...");
    let defra_binary = defradb::resolve_binary().expect("find defra binary");
    let defra_ports = defradb::allocate_defra_ports().expect("allocate defra ports");
    let defra_dir = run_dir.node_dir("defra0").expect("create defra dir");
    let defra_log_dir = defra_dir.join("logs");
    let defra_root = defra_dir.join("data");
    std::fs::create_dir_all(&defra_root).expect("create defra data dir");

    let sh_config = sourcehub.defra_config();
    let defra = DefraDbNode::start(
        defra_root,
        defra_log_dir,
        &defra_ports,
        &defra_binary,
        Some(&sh_config),
        Some(defra_key),
        None,
        Duration::from_secs(30),
    )
    .await
    .expect("defra should start with identity + SourceHub ACP");

    eprintln!(
        "[smoke] DefraDB ready: HTTP={}, P2P={}",
        defra.http_url, defra.p2p_addr
    );

    // ================================================================
    // 3. Start 3-node Orbis ring + DKG
    // ================================================================
    eprintln!("[smoke] Starting Orbis ring (3 nodes)...");
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(orbis_keys)
        .sourcehub_urls(SourceHubUrls::from(&sourcehub))
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("all orbis nodes should be healthy");

    eprintln!("[smoke] Orbis ring ready ({} nodes)", ring.node_count());

    let chain_config = sourcehub.chain_config();

    let mut node_infos = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let info = cli_tool::query_node_info(ring.node(i).grpc_addr())
            .await
            .unwrap_or_else(|e| panic!("query node{} info: {}", i, e));
        node_infos.push(info);
    }

    cli_tool::register_bulletin_namespace(
        BULLETIN_RING_NAMESPACE.to_string(),
        chain_config.clone(),
    )
    .await
    .expect("register ring namespace");

    for info in &node_infos {
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            info.public_address.clone(),
            chain_config.clone(),
        )
        .await
        .expect("add collaborator");
    }

    let event_subscription = BulletinEventSubscription::connect(&sourcehub.comet_rpc_url)
        .await
        .expect("event subscription");

    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();

    eprintln!("[smoke] Running DKG...");
    let dkg_result = cli_tool::do_dkg(ring.node(0).grpc_addr(), ring.threshold(), peer_ids)
        .await
        .expect("DKG should succeed");

    let session_id = dkg_result.session_id;
    let post_event = event_subscription
        .wait_for_artifact(&session_id, Duration::from_secs(120))
        .await
        .expect("DKG completion event");

    let post_payload = cli_tool::read_bulletin_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        post_event.post_id.clone(),
        chain_config.clone(),
    )
    .await
    .expect("read ring post");

    let ring_payload: bulletin::r#trait::RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;
    let ring_id = post_event.post_id;

    eprintln!(
        "[smoke] DKG complete. Ring PK: {}..., Ring ID: {}",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // ================================================================
    // 4. DefraDB: add schema, create document, query it back
    // ================================================================
    eprintln!("[smoke] Testing DefraDB operations...");
    let http = reqwest::Client::new();

    let schema_resp = http
        .post(format!("{}/api/v0/schema", defra.http_url))
        .header("Content-Type", "text/plain")
        .body(SIMPLE_SCHEMA)
        .send()
        .await
        .expect("schema add request");
    assert!(
        schema_resp.status().is_success(),
        "schema add failed: {}",
        schema_resp.text().await.unwrap_or_default()
    );
    eprintln!("[smoke] Schema added: Note {{ title, body }}");

    let create_mutation = r#"mutation { create_Note(input: {title: "Hello from smoke test", body: "All three components are running!"}) { _docID title body } }"#;
    let create_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": create_mutation}))
        .send()
        .await
        .expect("create document request");
    assert!(
        create_resp.status().is_success(),
        "create document failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let create_body: serde_json::Value = create_resp.json().await.expect("parse create response");
    eprintln!("[smoke] Document created: {}", create_body);

    let query = r#"query { Note { _docID title body } }"#;
    let query_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": query}))
        .send()
        .await
        .expect("query request");
    assert!(
        query_resp.status().is_success(),
        "query failed: {}",
        query_resp.text().await.unwrap_or_default()
    );
    let query_body: serde_json::Value = query_resp.json().await.expect("parse query response");

    let notes = query_body
        .pointer("/data/Note")
        .and_then(|v| v.as_array())
        .expect("Note array in query response");
    assert_eq!(notes.len(), 1, "should have 1 Note document");
    assert_eq!(
        notes[0]["title"].as_str().unwrap_or(""),
        "Hello from smoke test"
    );
    eprintln!("[smoke] DefraDB query verified: {} doc(s)", notes.len());

    // ================================================================
    // 5. Orbis: store a secret with the ring
    // ================================================================
    eprintln!("[smoke] Testing Orbis secret storage...");

    let policy_id = cli_tool::add_policy_to_chain(chain_config.clone())
        .await
        .expect("add policy");

    let resource = "document".to_string();
    let permission = "read".to_string();
    let namespace = "smoke_test_ns".to_string();

    cli_tool::register_bulletin_namespace(namespace.clone(), chain_config.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(
        namespace.clone(),
        node_infos[0].public_address.clone(),
        chain_config.clone(),
    )
    .await
    .expect("add node as collaborator");

    let secret = b"Three components working together!";
    let prepared = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
    )
    .expect("prepare_secret");

    let store_result = cli_tool::store_prepared_secret(
        ring.node(0).grpc_addr(),
        &prepared,
        ring_id.clone(),
        namespace.clone(),
        policy_id,
        resource,
        permission,
        Some("smoke_test_did".to_string()),
        None,
        true,
    )
    .await
    .expect("store secret");

    eprintln!(
        "[smoke] Secret stored. Object ID: {}",
        &store_result.object_id[..16.min(store_result.object_id.len())]
    );

    // ================================================================
    // All three components verified!
    // ================================================================
    eprintln!("[smoke] === Three-component smoke test passed ===");
    eprintln!("[smoke] SourceHub: LCD={}", sourcehub.lcd_url);
    eprintln!("[smoke] DefraDB: HTTP={}", defra.http_url);
    eprintln!(
        "[smoke] Orbis: {} nodes, ring_pk={}...",
        ring.node_count(),
        &ring_pk_hex[..20.min(ring_pk_hex.len())]
    );

    drop(ring);
    drop(defra);
    drop(sourcehub);
}
