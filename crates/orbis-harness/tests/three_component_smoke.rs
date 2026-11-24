//! Three-component smoke test: Vera + DefraDB + Orbis.

use std::time::Duration;

use defra_harness::node::RustNode;
use defra_harness::{VeraNodeConfig, VERA_ACP_DOCUMENT_TYPE};
use orbis_harness::fixture::setup_dkg;
use orbis_harness::{
    generate_identity_keys, generate_run_id, start_node, KeyringBackend, NodeConfig,
};

const SIMPLE_SCHEMA: &str = "type Note { title: String  body: String }";

const DEFAULT_ACP_POLICY_YAML: &str = r#"
name: default-e2e-policy
resources:
  - name: document
    relations:
      - name: reader
        types:
          - actor
      - name: writer
        types:
          - actor
    permissions:
      - name: read
        expr: writer + reader
      - name: write
        expr: writer
"#;

#[tokio::test]
#[ignore = "requires verad, orbis-node and defradb (VERAD_BINARY, ORBIS_BINARY, DEFRA_BINARY), ~2 min runtime"]
async fn three_component_smoke() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    // ================================================================
    // 1. Start Vera and a 3-node Orbis ring, then run DKG
    // ================================================================
    eprintln!("[smoke] Starting Vera and the Orbis ring...");
    let fixture = setup_dkg().await;
    eprintln!(
        "[smoke] DKG complete. Ring PK: {}..., Ring ID: {}",
        &fixture.ring_pk_hex[..40.min(fixture.ring_pk_hex.len())],
        &fixture.ring_id[..16.min(fixture.ring_id.len())],
    );

    // ================================================================
    // 2. Start DefraDB with identity + file keyring + Vera ACP
    // ================================================================
    let run_id = generate_run_id();
    let base_dir = orbis_harness::e2e_base_dir();
    let run_dir = test_infra::TestRunDir::new(&base_dir, "ORBIS_E2E_KEEP").expect("create run dir");
    let defra_key = generate_identity_keys(&run_id, 1).remove(0);

    eprintln!("[smoke] Starting DefraDB with identity...");
    let defra_binary = test_infra::BinaryResolver::new("DEFRA", "defradb")
        .cargo_package("cli")
        .resolve()
        .expect("find defradb binary");
    let ports = test_infra::allocate_ports(2).expect("allocate defra ports");
    let defra_dir = run_dir.node_dir("defra0").expect("create defra dir");
    let defra_log_dir = defra_dir.join("logs");
    let defra_root = defra_dir.join("data");
    let keyring_path = defra_root.join("keys");

    let node = RustNode::from_binary(&defra_binary.path);
    let mut config = NodeConfig::new(
        "defra0",
        defra_root,
        defra_log_dir,
        format!("127.0.0.1:{}", ports[0]),
    );
    config.p2p_enabled = true;
    config.p2p_addr = Some(format!("/ip4/127.0.0.1/tcp/{}", ports[1]));
    config.vera = Some(VeraNodeConfig::from(&fixture.vera));
    config.acp_document_type = Some(VERA_ACP_DOCUMENT_TYPE.to_string());
    config.identity = Some(defra_key);
    config.keyring = KeyringBackend::File {
        path: keyring_path,
        secret: "e2e-test-password".to_string(),
    };

    let defra = start_node(&node, config, Duration::from_secs(30))
        .await
        .expect("defra should start with identity + Vera ACP");

    eprintln!("[smoke] DefraDB ready: {}", defra.api_url);

    // ================================================================
    // 3. DefraDB: add schema, create document, query it back
    // ================================================================
    eprintln!("[smoke] Testing DefraDB operations...");
    let http = reqwest::Client::new();

    let schema_resp = http
        .post(format!("{}/api/v0/schema", defra.api_url))
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

    let add_mutation = r#"mutation { add_Note(input: {title: "Hello from smoke test", body: "All three components are running!"}) { _docID title body } }"#;
    let add_resp = http
        .post(format!("{}/api/v0/graphql", defra.api_url))
        .json(&serde_json::json!({"query": add_mutation}))
        .send()
        .await
        .expect("add document request");
    assert!(
        add_resp.status().is_success(),
        "add document failed: {}",
        add_resp.text().await.unwrap_or_default()
    );
    let add_body: serde_json::Value = add_resp.json().await.expect("parse add response");
    eprintln!("[smoke] Document added: {}", add_body);

    let query = r#"query { Note { _docID title body } }"#;
    let query_resp = http
        .post(format!("{}/api/v0/graphql", defra.api_url))
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
        .unwrap_or_else(|| panic!("Note array in query response: {query_body}"));
    assert_eq!(notes.len(), 1, "should have 1 Note document");
    assert_eq!(
        notes[0]["title"].as_str().unwrap_or(""),
        "Hello from smoke test"
    );
    eprintln!("[smoke] DefraDB query verified: {} doc(s)", notes.len());

    // ================================================================
    // 4. Orbis: store a secret with the ring
    // ================================================================
    eprintln!("[smoke] Testing Orbis secret storage...");

    let policy_id = fixture
        .admin
        .account()
        .create_policy(DEFAULT_ACP_POLICY_YAML)
        .await
        .expect("add policy");

    let secret = b"Three components working together!";
    let prepared = cli_tool::prepare_secret(
        secret,
        &fixture.ring_pk_hex,
        None,
        policy_id,
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = cli_tool::store_prepared_secret(
        fixture.endpoint(),
        &prepared,
        fixture.ring_id.clone(),
        Some("smoke_test_did".to_string()),
        true,
        None,
    )
    .await
    .expect("store secret");
    let stored = fixture
        .admin
        .read_document(&store_result.object_id)
        .await
        .expect("read stored document");
    assert!(stored.is_some(), "the stored secret should be on Vera");

    eprintln!(
        "[smoke] Secret stored. Object ID: {}",
        &store_result.object_id[..16.min(store_result.object_id.len())]
    );

    // ================================================================
    // All three components verified!
    // ================================================================
    eprintln!("[smoke] === Three-component smoke test passed ===");
    eprintln!("[smoke] Vera: RPC={}", fixture.vera.rpc_url());
    eprintln!("[smoke] DefraDB: HTTP={}", defra.api_url);
    eprintln!(
        "[smoke] Orbis: {} nodes, ring_pk={}...",
        fixture.ring.node_count(),
        &fixture.ring_pk_hex[..20.min(fixture.ring_pk_hex.len())]
    );

    drop(defra);
    drop(fixture);
}
