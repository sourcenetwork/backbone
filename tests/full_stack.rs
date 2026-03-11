//! Secure Training Data Compartments end-to-end test.
//!
//! Two compartments (acme, globex), one Orbis ring (T=2, N=3), multiple service
//! identities with scoped permissions. Full Rust stack: hub.rs + Orbis + DefraDB.
//!
//! See `memory/full_stack_test.md` for the step-by-step breakdown.

mod support;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use defra_harness::node::RustNode;
use defra_harness::sse::{open_acp_events_sse, wait_for_acp_invalidation};
use defra_harness::{DefraClient, NodeKind};
use orbis_harness::cli::signer_did_for_pk;
use orbis_harness::cli::types::RingPayload;
use orbis_harness::defradb::identity::{did_key_from_secp256k1, DefraHttpClient};
use orbis_harness::ring::OrbisRing;
use orbis_harness::{
    generate_identity_keys, generate_run_id, start_node, HubRsNodeConfig, KeyringBackend,
    NodeConfig, OrbisCliClient, OrbisSignerConfig,
};

use hub_harness::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_harness::observe::ClusterAssertions;
use support::full_stack::{
    assert_doc_ids_match, bls_did_key_from_hex, configure_replication_link, extract_doc_ids,
    graphql_string_literal, is_acp_denied, is_write_acp_denied, poll_query_count,
    poll_query_denied, poll_replicated_doc_ids, poll_write_denied, wait_for_block_finality,
    wait_for_dkg_post, wait_for_orbis_health, wait_for_orbis_node_identities,
    wait_for_orbis_node_infos, wait_for_tx_receipt,
};
use support::hubd::{
    evm_address_from_private_key, submit_acp_relationship_txs, AcpRelationshipTx,
    AcpRelationshipTxKind, HubdCli, HARDHAT_KEY_0,
};

const ACME_POLICY_YAML: &str = r#"
name: acme-training-policy
resources:
  - name: transcript
    relations:
      - name: owner
        types:
          - actor
      - name: reader
        types:
          - actor
      - name: writer
        types:
          - actor
    permissions:
      - name: read
        expr: owner + writer + reader
      - name: update
        expr: owner + writer
      - name: delete
        expr: owner
"#;

const GLOBEX_POLICY_YAML: &str = r#"
name: globex-support-policy
resources:
  - name: ticket
    relations:
      - name: owner
        types:
          - actor
      - name: reader
        types:
          - actor
      - name: writer
        types:
          - actor
    permissions:
      - name: read
        expr: owner + writer + reader
      - name: update
        expr: owner + writer
      - name: delete
        expr: owner
"#;

const RING_SIGNING_POLICY_YAML: &str = r#"
name: ring-signing-policy
resources:
  - name: ring
    relations:
      - name: signer
        types:
          - actor
    permissions:
      - name: sign
        expr: signer
"#;

struct ServiceIdentity {
    label: String,
    private_key_hex: String,
    did_key: String,
    _keyring_dir: PathBuf,
}

impl ServiceIdentity {
    fn new_file_keyring(label: &str, base_dir: &std::path::Path) -> Self {
        let keyring_dir = base_dir.join(label).join("keys");
        std::fs::create_dir_all(&keyring_dir)
            .unwrap_or_else(|e| panic!("create keyring dir for {}: {}", label, e));

        // Deterministic key derivation: SHA-256(fixed_seed || label).
        // Same label always produces the same private key across runs.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"backbone-e2e-test-seed-v1:");
        hasher.update(label.as_bytes());
        let result = hasher.finalize();
        let private_key_hex = hex::encode(result);

        let (did_key, _pub_bytes) = did_key_from_secp256k1(&private_key_hex)
            .unwrap_or_else(|e| panic!("derive did_key for {}: {}", label, e));

        Self {
            label: label.to_string(),
            private_key_hex,
            did_key,
            _keyring_dir: keyring_dir,
        }
    }
}

const BULLETIN_RING_NAMESPACE: &str = "orbis";

#[tokio::test]
#[ignore = "spec test: requires hubd, defra-iroh, and orbis-node on PATH"]
async fn secure_training_data_compartments() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let run_id = generate_run_id();
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("e2e")
        .join("full-stack");
    let run_dir =
        test_infra::TestRunDir::new(&base_dir, "BACKBONE_E2E_KEEP").expect("create run dir");

    let test_start = Instant::now();
    let orbis_operator_keys = generate_identity_keys(&run_id, 3);

    // Step 1a. Start hub.rs single node (bulletin + ACP)
    let t = Instant::now();
    eprintln!("[backbone] Step 1a: Starting hub.rs node...");
    let hubd_binary = hub_harness::resolve_binary().expect("resolve hubd binary");
    let hub_chain_id: u64 = 9003;
    let hub_genesis = GenesisBuilder::devnet().funded_accounts(2, "1000000000000000000000000");
    let hub_cluster = TestCluster::builder()
        .nodes(1)
        .chain_id(hub_chain_id)
        .genesis(hub_genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("hub.rs node should start");

    let hub_rpc_url = hub_cluster.node(0).rpc_url();
    let hub_ws_url = hub_cluster.node(0).ws_url();
    let hub_cli = HubdCli::new(hubd_binary, &hub_rpc_url, hub_chain_id, HARDHAT_KEY_0);

    // Step 2. Start Orbis ring (T=2, N=3) with hub.rs for bulletin + ACP
    let ring_spawn_start = Instant::now();
    eprintln!("[backbone] Step 2: Starting Orbis ring (3 nodes, threshold 2)...");
    let hub_ready = async {
        hub_cluster
            .wait_ready(Duration::from_secs(30))
            .await
            .expect("hub.rs node should become healthy");

        let hub_state = hub_cluster.observe(Duration::from_millis(200));
        hub_state
            .wait_for_height(3, Duration::from_secs(30))
            .await
            .expect("hub.rs should reach height 3");
        t.elapsed().as_secs_f64()
    };
    let ring_start = async {
        let ring = OrbisRing::builder()
            .nodes(3)
            .threshold(2)
            .log_level("info")
            .base_dir(run_dir.path())
            .identity_keys(orbis_operator_keys.clone())
            .hub_rs_config(HubRsNodeConfig {
                rpc_url: hub_rpc_url.clone(),
                ws_url: hub_ws_url.clone(),
                chain_id: hub_chain_id,
            })
            .build()
            .await;
        (ring_spawn_start.elapsed().as_secs_f64(), ring)
    };
    let (hub_ready_secs, (ring_spawn_secs, ring)) = tokio::join!(hub_ready, ring_start);
    let ring = ring.expect("ring should start");
    eprintln!("[backbone] Hub.rs node ready in {:.2}s", hub_ready_secs);
    eprintln!(
        "[backbone]   Orbis ring processes spawned in {:.2}s",
        ring_spawn_secs
    );
    let hub_state = hub_cluster.observe(Duration::from_millis(200));

    let ring_health_task = tokio::spawn(wait_for_orbis_health(
        ring.grpc_addrs(),
        Duration::from_secs(60),
    ));
    let node_identities = wait_for_orbis_node_identities(&ring, Duration::from_secs(15))
        .await
        .expect("orbis nodes should write EVM addresses + signer pubkeys");

    // Step 2a. Fund orbis nodes on hub.rs
    let mut evm_addresses = Vec::with_capacity(ring.node_count());
    let mut node_signer_dids = Vec::with_capacity(ring.node_count());
    for (i, identity) in node_identities.iter().enumerate() {
        eprintln!(
            "[backbone]   Funding orbis node{} on hub.rs: {} (DID: {}...)",
            i,
            identity.address,
            &identity.signer_did[..40.min(identity.signer_did.len())]
        );
        hub_cli
            .fund_evm_address(&identity.address, "1000000000000000000")
            .unwrap_or_else(|e| panic!("fund node{} on hub.rs: {}", i, e));
        evm_addresses.push(identity.address.clone());
        node_signer_dids.push(identity.signer_did.clone());
    }

    // Step 2b. Wait for basic node health that can overlap funding.
    ring_health_task
        .await
        .expect("orbis ring health task should join")
        .expect("all nodes should become healthy");

    let node_infos = wait_for_orbis_node_infos(ring.grpc_addrs(), Duration::from_secs(60))
        .await
        .expect("all nodes should report info");

    eprintln!(
        "[backbone]   Orbis nodes funded + healthy in {:.2}s",
        ring_spawn_start.elapsed().as_secs_f64()
    );

    // Step 3. Register bulletin namespace + add collaborators
    let orbis_cli = OrbisCliClient::new().expect("resolve cli-tool binary");
    eprintln!("[backbone] Step 3: Registering bulletin namespace on hub.rs...");
    hub_cli
        .register_namespace(BULLETIN_RING_NAMESPACE)
        .expect("register ring namespace on hub.rs");

    for (i, did) in node_signer_dids.iter().enumerate() {
        eprintln!(
            "[backbone]   Adding collaborator for node{}: {}...",
            i,
            &did[..40.min(did.len())]
        );
        hub_cli
            .add_collaborator(BULLETIN_RING_NAMESPACE, did)
            .unwrap_or_else(|e| panic!("add collaborator for node{}: {}", i, e));
    }

    // Step 3a. Run DKG ceremony
    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();

    eprintln!("[backbone] Step 3a: Running DKG...");
    let _dkg_result = orbis_cli
        .do_dkg(&ring.node(0).grpc_addr(), ring.threshold(), &peer_ids)
        .expect("DKG should succeed");

    // Step 3b. Poll for DKG post on hub.rs
    eprintln!("[backbone] Step 3b: Polling for DKG post on hub.rs...");
    let (ring_id, post_payload) =
        wait_for_dkg_post(&hub_cli, BULLETIN_RING_NAMESPACE, Duration::from_secs(120))
            .await
            .expect("DKG post on hub.rs");

    // Step 3c. Read RingPayload from hub.rs bulletin
    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;

    eprintln!(
        "[backbone] Ring ready in {:.2}s. PK: {}..., ID: {}...",
        t.elapsed().as_secs_f64(),
        &ring_pk_hex[..32.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // Step 4. Create ring signing policy + register ring object
    let t = Instant::now();
    eprintln!("[backbone] Step 4: Creating ring signing ACP policy...");
    let ring_policy_id = hub_cli
        .create_policy(RING_SIGNING_POLICY_YAML)
        .expect("create ring signing ACP policy");
    eprintln!("[backbone]   ring_policy_id = {}", ring_policy_id);

    hub_cli
        .register_object(&ring_policy_id, "ring", &ring_id)
        .expect("register ring object");

    // Step 5. Derive PLATFORM_DID from ring
    let platform_derived = orbis_cli
        .derive_public_key(
            &ring.node(0).grpc_addr(),
            &ring_id,
            &hex::encode(b"platform"),
        )
        .expect("derive platform public key");
    let platform_did = bls_did_key_from_hex(&platform_derived.derived_public_key);
    eprintln!("[backbone] Step 5: PLATFORM_DID: {}", platform_did);

    // Step 6. Derive ACME_DID from ring
    let acme_derived = orbis_cli
        .derive_public_key(
            &ring.node(0).grpc_addr(),
            &ring_id,
            &hex::encode(b"acme-corp"),
        )
        .expect("derive acme-corp public key");
    let acme_did = bls_did_key_from_hex(&acme_derived.derived_public_key);
    eprintln!("[backbone] Step 6: ACME_DID: {}", acme_did);

    // Step 7. Derive GLOBEX_DID from ring
    let globex_derived = orbis_cli
        .derive_public_key(
            &ring.node(0).grpc_addr(),
            &ring_id,
            &hex::encode(b"globex-inc"),
        )
        .expect("derive globex-inc public key");
    let globex_did = bls_did_key_from_hex(&globex_derived.derived_public_key);
    eprintln!("[backbone] Step 7: GLOBEX_DID: {}", globex_did);

    // Step 8. Verify all 3 derived keys are distinct
    assert_ne!(
        platform_derived.derived_public_key, acme_derived.derived_public_key,
        "platform and acme keys must differ"
    );
    assert_ne!(
        acme_derived.derived_public_key, globex_derived.derived_public_key,
        "acme and globex keys must differ"
    );
    assert_ne!(
        platform_derived.derived_public_key, globex_derived.derived_public_key,
        "platform and globex keys must differ"
    );
    eprintln!("[backbone] Step 8: Verified 3 unique BLS did:key identities from same ring");

    // Step 9. Create service identities
    let training_svc = ServiceIdentity::new_file_keyring("training-svc", run_dir.path());
    let inference_svc = ServiceIdentity::new_file_keyring("inference-svc", run_dir.path());
    let audit_svc = ServiceIdentity::new_file_keyring("audit-svc", run_dir.path());
    let globex_svc = ServiceIdentity::new_file_keyring("globex-svc", run_dir.path());
    let acme_defra_svc = ServiceIdentity::new_file_keyring("acme-defra-svc", run_dir.path());
    let globex_defra_svc = ServiceIdentity::new_file_keyring("globex-defra-svc", run_dir.path());
    let platform_defra_svc =
        ServiceIdentity::new_file_keyring("platform-defra-svc", run_dir.path());
    eprintln!(
        "[backbone] Step 9: Service identities created: {}, {}, {}, {}, {}, {}, {}",
        training_svc.label,
        inference_svc.label,
        audit_svc.label,
        globex_svc.label,
        acme_defra_svc.label,
        globex_defra_svc.label,
        platform_defra_svc.label,
    );

    // Step 10. Authorize DefraDB service accounts as ring signers
    let acme_defra_signer_did = signer_did_for_pk(&acme_defra_svc.private_key_hex);
    hub_cli
        .set_relationship(
            &ring_policy_id,
            "ring",
            &ring_id,
            "signer",
            &acme_defra_signer_did,
        )
        .expect("grant acme_defra_svc signer on ring");

    let globex_defra_signer_did = signer_did_for_pk(&globex_defra_svc.private_key_hex);
    hub_cli
        .set_relationship(
            &ring_policy_id,
            "ring",
            &ring_id,
            "signer",
            &globex_defra_signer_did,
        )
        .expect("grant globex_defra_svc signer on ring");

    let platform_defra_signer_did = signer_did_for_pk(&platform_defra_svc.private_key_hex);
    hub_cli
        .set_relationship(
            &ring_policy_id,
            "ring",
            &ring_id,
            "signer",
            &platform_defra_signer_did,
        )
        .expect("grant platform_defra_svc signer on ring");
    eprintln!(
        "[backbone] Steps 4-10: Policy + identities setup in {:.2}s",
        t.elapsed().as_secs_f64()
    );

    // Step 11. Create acme ACP policy
    let t = Instant::now();
    eprintln!("[backbone] Step 11: Creating acme ACP policy...");
    let acme_policy_id = hub_cli
        .create_policy(ACME_POLICY_YAML)
        .expect("create acme ACP policy");

    let transcript_object = "transcript";
    hub_cli
        .register_object(&acme_policy_id, "transcript", transcript_object)
        .expect("register transcript collection object");
    eprintln!("[backbone] Acme policy: {}", acme_policy_id);

    // Step 12. Grant TRAINING_SVC writer on transcript collection
    hub_cli
        .set_relationship(
            &acme_policy_id,
            "transcript",
            transcript_object,
            "writer",
            &training_svc.did_key,
        )
        .expect("grant training_svc writer on transcript collection");
    eprintln!("[backbone] Step 12: TRAINING_SVC granted writer on transcript collection");

    // Step 13. Fund DefraDB service accounts on hub.rs
    let acme_defra_evm_addr = evm_address_from_private_key(&acme_defra_svc.private_key_hex);
    let globex_defra_evm_addr = evm_address_from_private_key(&globex_defra_svc.private_key_hex);
    let platform_defra_evm_addr = evm_address_from_private_key(&platform_defra_svc.private_key_hex);
    for (label, addr) in &[
        ("acme-defra", &acme_defra_evm_addr),
        ("globex-defra", &globex_defra_evm_addr),
        ("platform-defra", &platform_defra_evm_addr),
    ] {
        hub_cli
            .fund_evm_address(addr, "1000000000000000000")
            .unwrap_or_else(|e| panic!("fund {} on hub.rs: {}", label, e));
        eprintln!("[backbone] Step 13: Funded {} on hub.rs: {}", label, addr);
    }

    // Step 14. Start acme DefraDB with Orbis signer (derivation="acme-corp")
    let defra_binary = test_infra::BinaryResolver::new("DEFRA", "defra-iroh")
        .cargo_package("cli")
        .resolve()
        .expect("find defra binary");
    let acme_defra_ports = test_infra::allocate_ports(2).expect("acme defra ports");
    let acme_defra_dir = run_dir.node_dir("defra-acme").expect("acme defra dir");
    let acme_defra_log_dir = acme_defra_dir.join("logs");
    let acme_defra_root = acme_defra_dir.join("data");
    let acme_keyring_path = acme_defra_root.join("keys");

    let acme_defra_node = RustNode::from_binary(&defra_binary.path);
    let mut acme_defra_config = NodeConfig::new(
        "defra-acme",
        acme_defra_root,
        acme_defra_log_dir,
        format!("127.0.0.1:{}", acme_defra_ports[0]),
    );
    acme_defra_config.p2p_enabled = true;
    acme_defra_config.p2p_addr = Some(format!("/ip4/127.0.0.1/tcp/{}", acme_defra_ports[1]));
    acme_defra_config.hub_rs_address = Some(hub_cluster.node(0).rpc_url());
    acme_defra_config.acp_document_type = Some("hub-rs".to_string());
    acme_defra_config.identity = Some(acme_defra_svc.private_key_hex.clone());
    acme_defra_config.keyring = KeyringBackend::File {
        path: acme_keyring_path,
        secret: "e2e-test-password".to_string(),
    };
    acme_defra_config.orbis_signer = Some(OrbisSignerConfig {
        endpoint: ring.node(0).grpc_addr(),
        ring_id: ring_id.clone(),
        derivation: "acme-corp".to_string(),
    });

    let acme_defra = start_node(&acme_defra_node, acme_defra_config, Duration::from_secs(30))
        .await
        .expect("acme defra should start with Orbis signer");
    eprintln!(
        "[backbone] Step 14: Acme DefraDB ready: {}",
        acme_defra.api_url
    );

    // Step 14a. Start PlatformCo DefraDB with Orbis signer (derivation="platform")
    let platform_defra_ports = test_infra::allocate_ports(2).expect("platform defra ports");
    let platform_defra_dir = run_dir
        .node_dir("defra-platform")
        .expect("platform defra dir");
    let platform_defra_log_dir = platform_defra_dir.join("logs");
    let platform_defra_root = platform_defra_dir.join("data");
    let platform_keyring_path = platform_defra_root.join("keys");

    let platform_defra_node = RustNode::from_binary(&defra_binary.path);
    let mut platform_defra_config = NodeConfig::new(
        "defra-platform",
        platform_defra_root,
        platform_defra_log_dir,
        format!("127.0.0.1:{}", platform_defra_ports[0]),
    );
    platform_defra_config.p2p_enabled = true;
    platform_defra_config.p2p_addr =
        Some(format!("/ip4/127.0.0.1/tcp/{}", platform_defra_ports[1]));
    platform_defra_config.hub_rs_address = Some(hub_cluster.node(0).rpc_url());
    platform_defra_config.acp_document_type = Some("hub-rs".to_string());
    platform_defra_config.identity = Some(platform_defra_svc.private_key_hex.clone());
    platform_defra_config.keyring = KeyringBackend::File {
        path: platform_keyring_path,
        secret: "e2e-test-password".to_string(),
    };
    platform_defra_config.orbis_signer = Some(OrbisSignerConfig {
        endpoint: ring.node(0).grpc_addr(),
        ring_id: ring_id.clone(),
        derivation: "platform".to_string(),
    });

    let platform_defra = start_node(
        &platform_defra_node,
        platform_defra_config,
        Duration::from_secs(30),
    )
    .await
    .expect("platform defra should start");
    eprintln!(
        "[backbone] Step 14a: PlatformCo DefraDB ready: {}",
        platform_defra.api_url
    );

    // Step 15. Deploy Transcript schema with @policy on Acme + PlatformCo
    let acme_client = DefraHttpClient::new(&acme_defra.api_url);
    let platform_client = DefraHttpClient::new(&platform_defra.api_url);
    let (_acme_acp_sse, acme_acp_events) = open_acp_events_sse(&acme_defra.api_url).await;
    let acme_defra_cli =
        DefraClient::new(&defra_binary.path, &acme_defra.http_addr, NodeKind::Rust);
    let platform_defra_cli = DefraClient::new(
        &defra_binary.path,
        &platform_defra.http_addr,
        NodeKind::Rust,
    );

    let transcript_schema = format!(
        r#"type Transcript @policy(id: "{}", resource: "transcript") {{ call_id: String  content: String  customer: String }}"#,
        acme_policy_id,
    );
    acme_client
        .schema_add(&transcript_schema)
        .await
        .expect("add transcript schema");
    platform_client
        .schema_add(&transcript_schema)
        .await
        .expect("add transcript schema on platform");
    configure_replication_link(
        &acme_defra_cli,
        &acme_defra.api_url,
        &platform_defra_cli,
        &["Transcript"],
        "acme -> platform transcript replication",
    )
    .await;
    eprintln!("[backbone] Step 15a: PlatformCo subscribed to Acme Transcript replication");
    eprintln!(
        "[backbone] Steps 11-15: ACP policies + DefraDB setup in {:.2}s",
        t.elapsed().as_secs_f64()
    );

    // Step 16. TRAINING_SVC writes training transcripts
    let transcripts = vec![
        (
            "call-001",
            "Customer asked about billing cycle",
            "acme-cust-42",
        ),
        ("call-002", "Password reset request handled", "acme-cust-17"),
        (
            "call-003",
            "Product return initiated for order 9981",
            "acme-cust-42",
        ),
    ];

    let batch_start = Instant::now();
    let transcript_inputs = transcripts
        .iter()
        .map(|(call_id, content, customer)| {
            format!(
                "{{ call_id: {}, content: {}, customer: {} }}",
                graphql_string_literal(call_id),
                graphql_string_literal(content),
                graphql_string_literal(customer)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mutation = format!(
        "mutation {{ add_Transcript(input: [{}]) {{ _docID call_id }} }}",
        transcript_inputs
    );
    let write_start = Instant::now();
    let result = acme_client
        .graphql(&mutation, Some(&training_svc.private_key_hex))
        .await
        .unwrap_or_else(|e| panic!("batch write transcripts: {}", e));
    let write_dur = write_start.elapsed();
    let acme_doc_ids = extract_doc_ids(&result, "/data/add_Transcript", "Step 16");
    let created_transcripts = result
        .pointer("/data/add_Transcript")
        .and_then(|value| value.as_array())
        .expect("Step 16 add_Transcript array");
    for (index, entry) in created_transcripts.iter().enumerate() {
        let call_id = entry
            .get("call_id")
            .and_then(|value| value.as_str())
            .unwrap_or("<missing call_id>");
        let doc_id = entry
            .get("_docID")
            .and_then(|value| value.as_str())
            .unwrap_or("<missing _docID>");
        eprintln!(
            "[backbone]   batch write transcript[{}]: call_id={} docID={}",
            index, call_id, doc_id
        );
    }
    assert_eq!(
        acme_doc_ids.len(),
        transcripts.len(),
        "should have captured all transcript doc IDs"
    );
    eprintln!(
        "[backbone] Step 16: TRAINING_SVC wrote {} transcripts in {:.2}s (single batch, mutation {:.2}s)",
        acme_doc_ids.len(),
        batch_start.elapsed().as_secs_f64(),
        write_dur.as_secs_f64()
    );
    let replicated_transcripts = poll_replicated_doc_ids(
        &platform_client,
        &platform_defra_cli,
        "Transcript",
        &training_svc.private_key_hex,
        "/data/Transcript",
        &acme_doc_ids,
        "Step 16a",
        Duration::from_secs(60),
    )
    .await;
    let replicated_transcript_docs = replicated_transcripts
        .pointer("/data/Transcript")
        .and_then(|v| v.as_array())
        .expect("PlatformCo Transcript array");
    assert_doc_ids_match(
        &replicated_transcripts,
        "/data/Transcript",
        &acme_doc_ids,
        "Step 16a",
    );
    eprintln!(
        "[backbone] Step 16a: PlatformCo replicated {} acme transcripts",
        replicated_transcript_docs.len()
    );

    // Step 16b. INFERENCE_SVC reads BEFORE being granted reader — denied.
    let pre_grant_query = acme_client
        .graphql(
            r#"query { Transcript { _docID call_id } }"#,
            Some(&inference_svc.private_key_hex),
        )
        .await;
    assert!(
        is_acp_denied(&pre_grant_query, "/data/Transcript"),
        "INFERENCE_SVC should be denied BEFORE reader grant"
    );
    eprintln!("[backbone] Step 16b: INFERENCE_SVC denied before reader grant (sad path)");

    // Step 16c. Grant INFERENCE_SVC reader on each transcript document
    let acme_height_before_grants = acme_client
        .acp_status()
        .await
        .map(|s| s.height)
        .unwrap_or(0);
    let grant_start = Instant::now();
    let grant_txs = acme_doc_ids
        .iter()
        .map(|doc_id| AcpRelationshipTx {
            kind: AcpRelationshipTxKind::Set,
            policy_id: &acme_policy_id,
            resource: "transcript",
            object_id: doc_id.as_str(),
            relation: "reader",
            actor: &inference_svc.did_key,
        })
        .collect::<Vec<_>>();
    let submit_start = Instant::now();
    let grant_tx_hash = submit_acp_relationship_txs(&hub_cli, &grant_txs)
        .unwrap_or_else(|e| panic!("submit Step 16c grant tx batch: {}", e));
    eprintln!(
        "[backbone]   Step 16c submitted {} grant ops in one tx in {:.2}s",
        grant_txs.len(),
        submit_start.elapsed().as_secs_f64()
    );
    eprintln!("[backbone]   Step 16c batch tx={}", grant_tx_hash);
    for doc_id in &acme_doc_ids {
        eprintln!("[backbone]   grant reader on {}", doc_id);
    }
    wait_for_tx_receipt(&hub_cli, &grant_tx_hash, "Step 16c")
        .unwrap_or_else(|e| panic!("wait for Step 16c grant receipt: {}", e));
    eprintln!(
        "[backbone] Step 16c: INFERENCE_SVC granted reader on {} documents in {:.2}s",
        acme_doc_ids.len(),
        grant_start.elapsed().as_secs_f64()
    );

    // Step 17. INFERENCE_SVC reads back — sees transcripts (reader grant)
    // Wait for DefraDB's ACP light client to invalidate cache after the grants.
    wait_for_acp_invalidation(
        &acme_acp_events,
        acme_height_before_grants,
        Duration::from_secs(30),
    )
    .await;
    let query = r#"query { Transcript { _docID call_id content customer } }"#;
    let query_body = poll_query_count(
        &acme_client,
        query,
        &inference_svc.private_key_hex,
        "/data/Transcript",
        3,
        "Step 17",
    )
    .await;
    let docs = query_body
        .pointer("/data/Transcript")
        .and_then(|v| v.as_array())
        .expect("Transcript array");
    assert_doc_ids_match(&query_body, "/data/Transcript", &acme_doc_ids, "Step 17");
    eprintln!(
        "[backbone] Step 17: INFERENCE_SVC reads {} transcripts",
        docs.len()
    );

    // Step 18. INFERENCE_SVC attempts UPDATE — denied (reader only)
    let inference_write = format!(
        r#"mutation {{ update_Transcript(docID: "{}", input: {{ content: "hacked" }}) {{ _docID }} }}"#,
        acme_doc_ids[0]
    );
    let inference_write_result = acme_client
        .graphql(&inference_write, Some(&inference_svc.private_key_hex))
        .await;

    assert!(
        is_write_acp_denied(&inference_write_result, "/data/update_Transcript"),
        "INFERENCE_SVC update should be denied (reader only)"
    );
    eprintln!("[backbone] Step 18: INFERENCE_SVC update denied (reader only)");

    // Step 19. Create globex ACP policy + grant GLOBEX_SVC writer
    eprintln!("[backbone] Step 19: Creating globex ACP policy...");
    let globex_policy_id = hub_cli
        .create_policy(GLOBEX_POLICY_YAML)
        .expect("create globex ACP policy");

    let ticket_object = "ticket";
    hub_cli
        .register_object(&globex_policy_id, "ticket", ticket_object)
        .expect("register ticket collection object");

    hub_cli
        .set_relationship(
            &globex_policy_id,
            "ticket",
            ticket_object,
            "writer",
            &globex_svc.did_key,
        )
        .expect("grant globex_svc writer on ticket collection");
    eprintln!(
        "[backbone] Step 19: Globex policy: {}, GLOBEX_SVC granted writer on collection",
        globex_policy_id
    );

    // Step 20. Start globex DefraDB with Orbis signer (derivation="globex-inc")
    let globex_defra_ports = test_infra::allocate_ports(2).expect("globex defra ports");
    let globex_defra_dir = run_dir.node_dir("defra-globex").expect("globex defra dir");
    let globex_defra_log_dir = globex_defra_dir.join("logs");
    let globex_defra_root = globex_defra_dir.join("data");
    let globex_keyring_path = globex_defra_root.join("keys");

    let globex_defra_node = RustNode::from_binary(&defra_binary.path);
    let mut globex_defra_config = NodeConfig::new(
        "defra-globex",
        globex_defra_root,
        globex_defra_log_dir,
        format!("127.0.0.1:{}", globex_defra_ports[0]),
    );
    globex_defra_config.p2p_enabled = true;
    globex_defra_config.p2p_addr = Some(format!("/ip4/127.0.0.1/tcp/{}", globex_defra_ports[1]));
    globex_defra_config.hub_rs_address = Some(hub_cluster.node(0).rpc_url());
    globex_defra_config.acp_document_type = Some("hub-rs".to_string());
    globex_defra_config.identity = Some(globex_defra_svc.private_key_hex.clone());
    globex_defra_config.keyring = KeyringBackend::File {
        path: globex_keyring_path,
        secret: "e2e-test-password".to_string(),
    };
    globex_defra_config.orbis_signer = Some(OrbisSignerConfig {
        endpoint: ring.node(0).grpc_addr(),
        ring_id: ring_id.clone(),
        derivation: "globex-inc".to_string(),
    });

    let globex_defra = start_node(
        &globex_defra_node,
        globex_defra_config,
        Duration::from_secs(30),
    )
    .await
    .expect("globex defra should start");
    eprintln!(
        "[backbone] Step 20: Globex DefraDB ready: {}",
        globex_defra.api_url
    );

    // Step 21. Deploy SupportTicket schema with @policy on Globex + PlatformCo
    let globex_defra_cli =
        DefraClient::new(&defra_binary.path, &globex_defra.http_addr, NodeKind::Rust);
    let globex_client = DefraHttpClient::new(&globex_defra.api_url);
    let (_globex_acp_sse, globex_acp_events) = open_acp_events_sse(&globex_defra.api_url).await;

    let ticket_schema = format!(
        r#"type SupportTicket @policy(id: "{}", resource: "ticket") {{ ticket_id: String  subject: String  body: String  priority: String }}"#,
        globex_policy_id,
    );
    globex_client
        .schema_add(&ticket_schema)
        .await
        .expect("add ticket schema");
    platform_client
        .schema_add(&ticket_schema)
        .await
        .expect("add ticket schema on platform");
    configure_replication_link(
        &globex_defra_cli,
        &globex_defra.api_url,
        &platform_defra_cli,
        &["SupportTicket"],
        "globex -> platform support ticket replication",
    )
    .await;
    eprintln!("[backbone] Step 21: Schema added: SupportTicket @policy, PlatformCo subscribed");

    // Step 22. GLOBEX_SVC writes + reads tickets
    let tickets = vec![
        (
            "GLOB-001",
            "Login timeout",
            "User reports 30s timeout on SSO",
            "high",
        ),
        (
            "GLOB-002",
            "Export CSV broken",
            "CSV export produces empty file",
            "medium",
        ),
    ];

    let batch_start = Instant::now();
    let ticket_inputs = tickets
        .iter()
        .map(|(ticket_id, subject, body, priority)| {
            format!(
                "{{ ticket_id: {}, subject: {}, body: {}, priority: {} }}",
                graphql_string_literal(ticket_id),
                graphql_string_literal(subject),
                graphql_string_literal(body),
                graphql_string_literal(priority)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mutation = format!(
        "mutation {{ add_SupportTicket(input: [{}]) {{ _docID ticket_id }} }}",
        ticket_inputs
    );
    let write_start = Instant::now();
    let result = globex_client
        .graphql(&mutation, Some(&globex_svc.private_key_hex))
        .await
        .unwrap_or_else(|e| panic!("batch write tickets: {}", e));
    let write_dur = write_start.elapsed();
    let globex_doc_ids = extract_doc_ids(&result, "/data/add_SupportTicket", "Step 22");
    let created_tickets = result
        .pointer("/data/add_SupportTicket")
        .and_then(|value| value.as_array())
        .expect("Step 22 add_SupportTicket array");
    for (index, entry) in created_tickets.iter().enumerate() {
        let ticket_id = entry
            .get("ticket_id")
            .and_then(|value| value.as_str())
            .unwrap_or("<missing ticket_id>");
        let doc_id = entry
            .get("_docID")
            .and_then(|value| value.as_str())
            .unwrap_or("<missing _docID>");
        eprintln!(
            "[backbone]   batch write ticket[{}]: ticket_id={} docID={}",
            index, ticket_id, doc_id
        );
    }
    assert_eq!(
        globex_doc_ids.len(),
        tickets.len(),
        "should have captured all ticket doc IDs"
    );

    let ticket_query = r#"query { SupportTicket { _docID ticket_id subject priority } }"#;
    let ticket_body = globex_client
        .graphql(ticket_query, Some(&globex_svc.private_key_hex))
        .await
        .expect("globex_svc query tickets");
    let ticket_docs = ticket_body
        .pointer("/data/SupportTicket")
        .and_then(|v| v.as_array())
        .expect("SupportTicket array");
    assert_doc_ids_match(
        &ticket_body,
        "/data/SupportTicket",
        &globex_doc_ids,
        "Step 22",
    );
    assert_eq!(
        ticket_docs.len(),
        2,
        "globex_svc should see exactly 2 tickets (owner has read access)"
    );
    eprintln!(
        "[backbone] Step 22: GLOBEX_SVC wrote {} tickets in {:.2}s (single batch, mutation {:.2}s), reads back {}",
        tickets.len(),
        batch_start.elapsed().as_secs_f64(),
        write_dur.as_secs_f64(),
        ticket_docs.len()
    );
    let replicated_tickets = poll_replicated_doc_ids(
        &platform_client,
        &platform_defra_cli,
        "SupportTicket",
        &globex_svc.private_key_hex,
        "/data/SupportTicket",
        &globex_doc_ids,
        "Step 22a",
        Duration::from_secs(60),
    )
    .await;
    let replicated_ticket_docs = replicated_tickets
        .pointer("/data/SupportTicket")
        .and_then(|v| v.as_array())
        .expect("PlatformCo SupportTicket array");
    assert_doc_ids_match(
        &replicated_tickets,
        "/data/SupportTicket",
        &globex_doc_ids,
        "Step 22a",
    );
    eprintln!(
        "[backbone] Step 22a: PlatformCo replicated {} globex tickets",
        replicated_ticket_docs.len()
    );

    // Step 23. Cross-compartment isolation: globex -> acme (denied)
    eprintln!("[backbone] Step 23: Testing cross-compartment isolation: globex -> acme...");
    let cross_acme = acme_client
        .graphql(
            r#"query { Transcript { _docID content } }"#,
            Some(&globex_svc.private_key_hex),
        )
        .await;

    assert!(
        is_acp_denied(&cross_acme, "/data/Transcript"),
        "GLOBEX_SVC should be denied on acme transcripts (cross-compartment)"
    );
    eprintln!("[backbone] PASSED: GLOBEX_SVC denied on acme transcripts");

    // Step 24. Cross-compartment isolation: acme -> globex (denied)
    eprintln!("[backbone] Step 24: Testing cross-compartment isolation: acme -> globex...");
    let cross_globex = globex_client
        .graphql(
            r#"query { SupportTicket { _docID subject } }"#,
            Some(&training_svc.private_key_hex),
        )
        .await;

    assert!(
        is_acp_denied(&cross_globex, "/data/SupportTicket"),
        "TRAINING_SVC should be denied on globex tickets (cross-compartment)"
    );
    eprintln!("[backbone] PASSED: TRAINING_SVC denied on globex tickets");

    // Step 25. Grant AUDIT_SVC reader on all docs in both compartments
    let acme_height_before_audit = acme_client
        .acp_status()
        .await
        .map(|s| s.height)
        .unwrap_or(0);
    let globex_height_before_audit = globex_client
        .acp_status()
        .await
        .map(|s| s.height)
        .unwrap_or(0);
    let t = Instant::now();
    let mut audit_grant_txs = acme_doc_ids
        .iter()
        .map(|doc_id| AcpRelationshipTx {
            kind: AcpRelationshipTxKind::Set,
            policy_id: &acme_policy_id,
            resource: "transcript",
            object_id: doc_id.as_str(),
            relation: "reader",
            actor: &audit_svc.did_key,
        })
        .collect::<Vec<_>>();
    audit_grant_txs.extend(globex_doc_ids.iter().map(|doc_id| AcpRelationshipTx {
        kind: AcpRelationshipTxKind::Set,
        policy_id: &globex_policy_id,
        resource: "ticket",
        object_id: doc_id.as_str(),
        relation: "reader",
        actor: &audit_svc.did_key,
    }));
    let submit_start = Instant::now();
    let audit_grant_hash = submit_acp_relationship_txs(&hub_cli, &audit_grant_txs)
        .unwrap_or_else(|e| panic!("submit Step 25 audit grant tx batch: {}", e));
    eprintln!(
        "[backbone]   Step 25 submitted {} audit grant ops in one tx in {:.2}s",
        audit_grant_txs.len(),
        submit_start.elapsed().as_secs_f64()
    );
    eprintln!("[backbone]   Step 25 batch tx={}", audit_grant_hash);
    wait_for_tx_receipt(&hub_cli, &audit_grant_hash, "Step 25")
        .unwrap_or_else(|e| panic!("wait for Step 25 audit grant receipt: {}", e));
    eprintln!(
        "[backbone] Step 25: AUDIT_SVC granted reader on {} acme docs + {} globex docs in {:.2}s",
        acme_doc_ids.len(),
        globex_doc_ids.len(),
        t.elapsed().as_secs_f64()
    );

    // Wait for both DefraDB nodes to invalidate ACP caches after the grants.
    wait_for_acp_invalidation(
        &acme_acp_events,
        acme_height_before_audit,
        Duration::from_secs(30),
    )
    .await;
    wait_for_acp_invalidation(
        &globex_acp_events,
        globex_height_before_audit,
        Duration::from_secs(30),
    )
    .await;

    // Step 26. AUDIT_SVC reads acme transcripts — succeeds
    let audit_acme = poll_query_count(
        &acme_client,
        r#"query { Transcript { _docID call_id content } }"#,
        &audit_svc.private_key_hex,
        "/data/Transcript",
        3,
        "Step 26",
    )
    .await;
    let audit_acme_docs = audit_acme
        .pointer("/data/Transcript")
        .and_then(|v| v.as_array())
        .expect("Transcript array for audit");
    assert_doc_ids_match(&audit_acme, "/data/Transcript", &acme_doc_ids, "Step 26");
    eprintln!(
        "[backbone] Step 26: AUDIT_SVC reads {} acme transcripts",
        audit_acme_docs.len()
    );

    // Step 27. AUDIT_SVC reads globex tickets — succeeds
    let audit_globex = poll_query_count(
        &globex_client,
        r#"query { SupportTicket { _docID ticket_id subject } }"#,
        &audit_svc.private_key_hex,
        "/data/SupportTicket",
        2,
        "Step 27",
    )
    .await;
    let audit_globex_docs = audit_globex
        .pointer("/data/SupportTicket")
        .and_then(|v| v.as_array())
        .expect("SupportTicket array for audit");
    assert_doc_ids_match(
        &audit_globex,
        "/data/SupportTicket",
        &globex_doc_ids,
        "Step 27",
    );
    eprintln!(
        "[backbone] Step 27: AUDIT_SVC reads {} globex tickets",
        audit_globex_docs.len()
    );

    // Step 28. AUDIT_SVC attempts UPDATE — denied (reader only)
    let audit_update_acme = acme_client
        .graphql(
            &format!(
                r#"mutation {{ update_Transcript(docID: "{}", input: {{ content: "audit-hack" }}) {{ _docID }} }}"#,
                acme_doc_ids[0]
            ),
            Some(&audit_svc.private_key_hex),
        )
        .await;

    assert!(
        is_write_acp_denied(&audit_update_acme, "/data/update_Transcript"),
        "AUDIT_SVC update should be denied on acme (reader only)"
    );
    eprintln!("[backbone] Step 28a: AUDIT_SVC update denied on acme");

    let audit_update_globex = globex_client
        .graphql(
            &format!(
                r#"mutation {{ update_SupportTicket(docID: "{}", input: {{ subject: "audit-hack" }}) {{ _docID }} }}"#,
                globex_doc_ids[0]
            ),
            Some(&audit_svc.private_key_hex),
        )
        .await;

    assert!(
        is_write_acp_denied(&audit_update_globex, "/data/update_SupportTicket"),
        "AUDIT_SVC update should be denied on globex (reader only)"
    );
    eprintln!("[backbone] Step 28b: AUDIT_SVC update denied on globex");

    // Step 29. Revoke AUDIT_SVC from acme, verify still reads globex
    let acme_height_before_revoke = acme_client
        .acp_status()
        .await
        .map(|s| s.height)
        .unwrap_or(0);
    let t = Instant::now();
    eprintln!("[backbone] Step 29: Revoking AUDIT_SVC from acme...");
    let revoke_txs = acme_doc_ids
        .iter()
        .map(|doc_id| AcpRelationshipTx {
            kind: AcpRelationshipTxKind::Delete,
            policy_id: &acme_policy_id,
            resource: "transcript",
            object_id: doc_id.as_str(),
            relation: "reader",
            actor: &audit_svc.did_key,
        })
        .collect::<Vec<_>>();
    let submit_start = Instant::now();
    let revoke_tx_hash = submit_acp_relationship_txs(&hub_cli, &revoke_txs)
        .unwrap_or_else(|e| panic!("submit Step 29 revoke tx batch: {}", e));
    eprintln!(
        "[backbone]   Step 29 submitted {} revoke ops in one tx in {:.2}s",
        revoke_txs.len(),
        submit_start.elapsed().as_secs_f64()
    );
    eprintln!("[backbone]   Step 29 batch tx={}", revoke_tx_hash);
    wait_for_tx_receipt(&hub_cli, &revoke_tx_hash, "Step 29")
        .unwrap_or_else(|e| panic!("wait for Step 29 revoke receipt: {}", e));
    eprintln!(
        "[backbone]   Step 29 revocation txs: {:.2}s",
        t.elapsed().as_secs_f64()
    );

    // Wait for cache invalidation, then verify revocation took effect
    wait_for_acp_invalidation(
        &acme_acp_events,
        acme_height_before_revoke,
        Duration::from_secs(30),
    )
    .await;
    poll_query_denied(
        &acme_client,
        r#"query { Transcript { _docID call_id } }"#,
        &audit_svc.private_key_hex,
        "/data/Transcript",
        "Step 29",
    )
    .await;
    eprintln!("[backbone] PASSED: Revoked AUDIT_SVC can no longer read acme transcripts");

    let still_globex = globex_client
        .graphql(
            r#"query { SupportTicket { _docID ticket_id } }"#,
            Some(&audit_svc.private_key_hex),
        )
        .await
        .expect("audit_svc should still read globex");
    let still_globex_docs = still_globex
        .pointer("/data/SupportTicket")
        .and_then(|v| v.as_array())
        .expect("SupportTicket array post-revocation");
    assert_doc_ids_match(
        &still_globex,
        "/data/SupportTicket",
        &globex_doc_ids,
        "Step 29-globex",
    );
    assert_eq!(
        still_globex_docs.len(),
        2,
        "audit_svc should still see exactly 2 globex tickets after acme revocation"
    );
    eprintln!(
        "[backbone] PASSED: AUDIT_SVC still reads {} globex tickets after acme revocation",
        still_globex_docs.len()
    );

    // Step 30. Key rotation: new key works, old key denied
    let step30_start = Instant::now();
    eprintln!("[backbone] Step 30: Rotating TRAINING_SVC key...");
    let new_training_svc = ServiceIdentity::new_file_keyring("training-svc-v2", run_dir.path());

    hub_cli
        .set_relationship(
            &acme_policy_id,
            "transcript",
            transcript_object,
            "writer",
            &new_training_svc.did_key,
        )
        .expect("grant new_training_svc writer on transcript collection");

    // Wait for block finality before writing (Orbis nodes check ACP directly)
    wait_for_block_finality(&hub_state, "Step 30-grant").await;

    let new_key_write = r#"mutation {
        create_Transcript(input: {
            call_id: "call-004",
            content: "Written by rotated training key",
            customer: "acme-cust-99"
        }) {
            _docID
        }
    }"#;
    let t = Instant::now();
    let _new_key_result = acme_client
        .graphql(new_key_write, Some(&new_training_svc.private_key_hex))
        .await
        .expect("new training_svc write");
    eprintln!(
        "[backbone]   new key write: {:.2}s",
        t.elapsed().as_secs_f64()
    );
    eprintln!("[backbone] PASSED: New TRAINING_SVC writes successfully");

    let acme_height_before_key_revoke = acme_client
        .acp_status()
        .await
        .map(|s| s.height)
        .unwrap_or(0);
    hub_cli
        .delete_relationship(
            &acme_policy_id,
            "transcript",
            transcript_object,
            "writer",
            &training_svc.did_key,
        )
        .expect("revoke old training_svc writer on transcript collection");

    // DefraDB's query gate invalidation is not enough here: create authorization is
    // enforced on the Orbis signing path, which checks ACP against finalized hub state.
    wait_for_block_finality(&hub_state, "Step 30-revoke").await;
    wait_for_acp_invalidation(
        &acme_acp_events,
        acme_height_before_key_revoke,
        Duration::from_secs(30),
    )
    .await;
    let old_key_write = r#"mutation {
        create_Transcript(input: {
            call_id: "call-old-key-after-revoke",
            content: "Old training key should not create after revocation",
            customer: "acme-cust-404"
        }) {
            _docID
        }
    }"#;
    poll_write_denied(
        &acme_client,
        old_key_write,
        &training_svc.private_key_hex,
        "/data/add_Transcript",
        "Step 30-revoke",
    )
    .await;
    eprintln!("[backbone] PASSED: Old TRAINING_SVC cannot create after revocation");

    let rotated_verify = acme_client
        .graphql(
            r#"mutation { create_Transcript(input: { call_id: "call-005", content: "Rotated key still works", customer: "acme-cust-1" }) { _docID } }"#,
            Some(&new_training_svc.private_key_hex),
        )
        .await
        .expect("rotated training_svc should still work");

    let has_doc = rotated_verify
        .pointer("/data/add_Transcript/0/_docID")
        .is_some();
    if !has_doc {
        let verify = acme_client
            .graphql(
                r#"query { Transcript(filter: {call_id: {_eq: "call-005"}}) { _docID } }"#,
                Some(&new_training_svc.private_key_hex),
            )
            .await
            .expect("verify rotated key write 2");
        let found = verify
            .pointer("/data/Transcript")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        assert!(found, "rotated training_svc transcript 2 should exist");
    }
    eprintln!(
        "[backbone] Step 30: Key rotation complete in {:.2}s",
        step30_start.elapsed().as_secs_f64()
    );

    // Final: hub.rs cluster health check
    hub_state
        .assert_no_errors()
        .expect("hub.rs cluster should have no unexpected errors");
    eprintln!("[backbone] Hub.rs cluster health: no unexpected errors");

    drop(hub_cluster);
    drop(platform_defra);
    drop(globex_defra);
    drop(acme_defra);

    eprintln!(
        "[backbone] End-to-end product flow passed in {:.2}s",
        test_start.elapsed().as_secs_f64()
    );
}
