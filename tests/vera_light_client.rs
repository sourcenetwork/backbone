//! Vera ACP light client integration test.
//!
//! Tests the ACP light client crate against a live Vera cluster. ACP
//! operations are native BLS requests submitted through `vera-client`; the
//! ACP light client verifies the resulting proofs.

use std::time::Duration;

mod support;

use acp_light_client::{AcpLightClient, ObjectRegistration};
use commonware_codec::Encode as _;
use vera_harness::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_support::{VeraAccount, ADMIN_KEY};

const POLICY_YAML: &str = "\
name: light-client-test-policy
resources:
  - name: transcript
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
        expr: writer";

// ============================================================================
// The test
// ============================================================================

#[tokio::test]
#[ignore = "requires verad binary (set VERAD_BINARY)"]
async fn vera_acp_light_client() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    // Step 1. Start Vera cluster
    eprintln!("[vera-lc] Step 1: Starting Vera cluster (4 validators)...");
    let vera_chain_id = 9003;
    let vera_cluster = TestCluster::builder()
        .nodes(4)
        .seed(42)
        .chain_id(vera_chain_id)
        .genesis(GenesisBuilder::devnet())
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .expect("Vera cluster should start");

    vera_cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("Vera cluster should become healthy");

    let vera_state = vera_cluster.observe(Duration::from_millis(200));
    vera_state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("Vera should reach height 3");
    eprintln!(
        "[vera-lc] Vera cluster ready: {} nodes",
        vera_cluster.node_count()
    );

    let account = VeraAccount::connect(&vera_cluster.node(0).rpc_url(), vera_chain_id, &ADMIN_KEY)
        .await
        .expect("connect the administering account");

    // Step 2. Create ACP policy on Vera
    eprintln!("[vera-lc] Step 2: Creating ACP policy on Vera...");
    let policy_id = account
        .create_policy(POLICY_YAML)
        .await
        .expect("create_policy");
    let policy_id_str = policy_id.as_str();
    eprintln!("[vera-lc] Policy ID: {}", policy_id_str);
    let listed = account.list_policies().await.expect("list_policies");
    assert_eq!(listed, vec![policy_id.clone()], "the one created policy");

    let register = account
        .register_object(policy_id_str, "transcript", "test-transcripts")
        .await
        .expect("register_object");
    eprintln!(
        "[vera-lc] register_object at height {}",
        register.block_number
    );

    // Step 3. Grant writer relationship
    eprintln!("[vera-lc] Step 3: Granting writer relationship...");
    let set_rel = account
        .set_relationship(
            policy_id_str,
            "transcript",
            "test-transcripts",
            "writer",
            "did:key:zQ3shtest1234",
        )
        .await
        .expect("set_relationship writer");
    eprintln!(
        "[vera-lc] set_relationship writer at height {}",
        set_rel.block_number
    );

    // Wait for finalization
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 4. Start AcpLightClient
    eprintln!("[vera-lc] Step 4: Starting ACP light client...");
    let vera_rpc = vera_cluster.node(0).rpc_url();
    let vera_ws = vera_cluster.node(0).ws_url();
    let keys = KeySet::builder()
        .nodes(4)
        .seed(42)
        .build()
        .expect("bootstrap keys");
    let trusted_key = hex::encode(keys.epoch_info().output.public().public().encode());
    let light_client = AcpLightClient::new(&vera_rpc, &vera_ws, &trusted_key, 10)
        .await
        .expect("ACP light client should connect");

    // Step 5. Verify light client receives headers and syncs height
    eprintln!("[vera-lc] Step 5: Waiting for light client to sync...");
    let sync = light_client
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("light client should sync to height 3");
    eprintln!(
        "[vera-lc] Light client synced: height={}, module_state_root={}",
        sync.height, sync.module_state_root
    );

    // Step 6. read_policy → allowed (existence proof)
    eprintln!("[vera-lc] Step 6: Checking policy existence...");
    let policy_check = light_client
        .read_policy(policy_id_str)
        .await
        .expect("read_policy should succeed");
    assert!(policy_check.value.is_some(), "policy should exist on Vera");
    assert!(policy_check.proof.is_some(), "proof should be returned");
    eprintln!(
        "[vera-lc] PASSED: Policy exists, verified at height {}",
        policy_check.verified_at_height
    );

    // Step 7. Verify non-existence proof for absent policy
    eprintln!("[vera-lc] Step 7: Checking non-existent policy...");
    let absent_check = light_client
        .read_policy("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .await
        .expect("check absent policy should succeed");
    assert!(
        absent_check.value.is_none(),
        "absent policy should not exist"
    );
    assert!(
        absent_check.proof.is_some(),
        "non-existence proof should be returned"
    );
    eprintln!("[vera-lc] PASSED: Non-existent policy denied with proof");

    // Record the current module_state_root
    let root_before = light_client
        .header_chain()
        .latest_module_state_root()
        .expect("should have module_state_root");

    // Step 8. Mutate ACP state (add reader relationship)
    eprintln!("[vera-lc] Step 8: Mutating ACP state...");
    let mutate = account
        .set_relationship(
            policy_id_str,
            "transcript",
            "test-transcripts",
            "reader",
            "did:key:zQ3shtest5678",
        )
        .await
        .expect("set_relationship reader");
    eprintln!(
        "[vera-lc] set_relationship reader at height {}",
        mutate.block_number
    );

    // Step 9. Wait for module_state_root change
    eprintln!("[vera-lc] Step 9: Waiting for module_state_root change...");
    let new_sync = light_client
        .wait_for_root_change(root_before, Duration::from_secs(30))
        .await
        .expect("module_state_root should change after mutation");
    eprintln!(
        "[vera-lc] PASSED: module_state_root changed at height {}",
        new_sync.height
    );
    assert_ne!(
        root_before, new_sync.module_state_root,
        "module_state_root should differ after ACP mutation"
    );

    // Step 10. Re-check policy (cache invalidated, re-verified with new root)
    eprintln!("[vera-lc] Step 10: Re-checking policy after state change...");
    let recheck = light_client
        .read_policy(policy_id_str)
        .await
        .expect("re-check policy should succeed");
    assert!(recheck.value.is_some(), "policy should still exist");
    assert!(
        recheck.proof.is_some(),
        "new proof should be returned (cache was invalidated)"
    );
    eprintln!(
        "[vera-lc] PASSED: Policy re-verified at height {} after cache invalidation",
        recheck.verified_at_height
    );

    // Step 11. Evaluate permissions from the node's evidence
    eprintln!("[vera-lc] Step 11: Verifying permissions from certified evidence...");
    let access = |actor: &str, permission: &str| acp_light_client::AccessRequest {
        actor: acp_light_client::Actor(actor.parse().expect("actor DID")),
        operations: vec![acp_light_client::Operation {
            object: acp_light_client::Object {
                resource: "transcript".into(),
                id: "test-transcripts".into(),
            },
            permission: permission.into(),
        }],
    };
    for (actor, permission, expected) in [
        ("did:key:zQ3shtest1234", "write", true),
        ("did:key:zQ3shtest5678", "read", true),
        ("did:key:zQ3shtest5678", "write", false),
    ] {
        let allowed = light_client
            .verify_access(policy_id_str, &access(actor, permission))
            .await
            .expect("permission evidence should verify");
        assert_eq!(allowed, expected, "{actor} {permission}");
    }
    eprintln!("[vera-lc] PASSED: Permissions evaluated from certified evidence");

    // Step 12. Verify the reader grant's receipt against its revision's commitment
    eprintln!("[vera-lc] Step 12: Verifying a committed receipt...");
    let submission = mutate.transaction_hash;
    let verified = light_client
        .proof_client()
        .fetch_and_verify_receipt(submission)
        .await
        .expect("receipt evidence should verify")
        .expect("node should hold the receipt");
    assert!(verified.receipt.success());
    assert!(verified.receipt.refusal.is_none());
    eprintln!(
        "[vera-lc] PASSED: Receipt verified at height {}",
        verified.revision.height
    );

    // Step 13. Tell a live, an archived and a never-registered object apart
    eprintln!("[vera-lc] Step 13: Reading object registrations...");
    let transcript = |id: &str| acp_light_client::Object {
        resource: "transcript".into(),
        id: id.into(),
    };
    account
        .register_object(policy_id_str, "transcript", "archived-transcripts")
        .await
        .expect("register the object to archive");
    let archive = account
        .archive_object(policy_id_str, "transcript", "archived-transcripts")
        .await
        .expect("archive_object");
    light_client
        .wait_for_height(archive.block_number, Duration::from_secs(30))
        .await
        .expect("light client should reach the archiving revision");
    let owner = acp_light_client::Actor(account.did().parse().expect("account DID"));
    for (id, expected) in [
        ("test-transcripts", ObjectRegistration::Live(owner)),
        ("archived-transcripts", ObjectRegistration::Archived),
        ("never-registered", ObjectRegistration::Absent),
    ] {
        let registration = light_client
            .read_object_registration(policy_id_str, &transcript(id))
            .await
            .expect("registration evidence should verify");
        assert_eq!(registration, expected, "{id}");
    }
    assert_eq!(
        light_client
            .read_object_owner(policy_id_str, &transcript("archived-transcripts"))
            .await
            .expect("ownership evidence should verify"),
        None,
        "an archived object has no owner"
    );
    eprintln!("[vera-lc] PASSED: Live, archived and absent objects read apart");

    drop(vera_cluster);
    eprintln!("[vera-lc] === All steps passed ===");
}
