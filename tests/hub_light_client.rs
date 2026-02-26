//! Hub.rs ACP Light Client integration test.
//!
//! Tests the ACP light client crate against a live hub.rs cluster.
//! Uses the `hubd client` CLI for ACP operations (handles nonce management,
//! tx signing, and receipt polling) and the ACP light client for proof
//! verification.

use std::process::Command;
use std::time::Duration;

use acp_light_client::AcpLightClient;
use hub_harness::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

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
// CLI helper
// ============================================================================

struct HubdCli {
    binary: std::path::PathBuf,
    rpc_url: String,
    chain_id: u64,
    key: String,
}

impl HubdCli {
    fn new(binary: std::path::PathBuf, rpc_url: &str, chain_id: u64, key: &str) -> Self {
        Self {
            binary,
            rpc_url: rpc_url.to_string(),
            chain_id,
            key: key.to_string(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.args([
            "client",
            "--url",
            &self.rpc_url,
            "--key",
            &self.key,
            "--client-chain-id",
            &self.chain_id.to_string(),
            "--compact",
        ]);
        cmd
    }

    fn exec(&self, args: &[&str]) -> eyre::Result<String> {
        let output = self.cmd().args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(eyre::eyre!(
                "hubd client {} failed ({}): stderr={}, stdout={}",
                args.join(" "),
                output.status,
                stderr.trim(),
                stdout.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn create_policy(&self, yaml: &str) -> eyre::Result<String> {
        self.exec(&["acp", "create-policy", yaml])
    }

    fn list_policies(&self) -> eyre::Result<String> {
        self.exec(&["acp", "list-policies"])
    }

    fn register_object(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> eyre::Result<String> {
        self.exec(&["acp", "register-object", policy_id, resource, object_id])
    }

    fn set_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<String> {
        self.exec(&[
            "acp",
            "set-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor,
        ])
    }
}

// ============================================================================
// The test
// ============================================================================

#[tokio::test]
#[ignore = "requires hubd binary (set HUBD_BINARY)"]
async fn hub_acp_light_client() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let hubd_binary = hub_harness::resolve_binary().expect("resolve hubd binary");

    // Step 1. Start hub.rs cluster
    eprintln!("[hub-lc] Step 1: Starting hub.rs cluster (4 validators)...");
    let hub_chain_id = 9003;
    let hub_genesis = GenesisBuilder::devnet().funded_accounts(1, "1000000000000000000000000");
    let hub_cluster = TestCluster::builder()
        .nodes(4)
        .chain_id(hub_chain_id)
        .genesis(hub_genesis)
        .preset(ConsensusPreset::Fast)
        .build()
        .await
        .expect("hub.rs cluster should start");

    hub_cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("hub.rs cluster should become healthy");

    let hub_state = hub_cluster.observe(Duration::from_millis(200));
    hub_state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("hub.rs should reach height 3");
    eprintln!(
        "[hub-lc] Hub.rs cluster ready: {} nodes",
        hub_cluster.node_count()
    );

    let cli = HubdCli::new(
        hubd_binary,
        &hub_cluster.node(0).rpc_url(),
        hub_chain_id,
        HARDHAT_KEY_0,
    );

    // Step 2. Create ACP policy on hub.rs
    eprintln!("[hub-lc] Step 2: Creating ACP policy on hub.rs...");
    let create_output = cli.create_policy(POLICY_YAML).expect("create_policy");
    eprintln!("[hub-lc] create_policy output: {}", create_output);

    // Query policy IDs
    let list_output = cli.list_policies().expect("list_policies");
    eprintln!("[hub-lc] list_policies output: {}", list_output);

    // Parse policy ID from the list output (JSON array of hex strings)
    let policy_ids: serde_json::Value =
        serde_json::from_str(&list_output).expect("list_policies should return JSON");
    let policy_id_str = policy_ids
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .expect("should have at least one policy ID");
    eprintln!("[hub-lc] Policy ID: {}", policy_id_str);

    // Register object — wait for consensus between txs to avoid nonce race
    tokio::time::sleep(Duration::from_secs(1)).await;
    let register_output = cli
        .register_object(policy_id_str, "transcript", "test-transcripts")
        .expect("register_object");
    eprintln!("[hub-lc] register_object output: {}", register_output);

    // Step 3. Grant writer relationship
    eprintln!("[hub-lc] Step 3: Granting writer relationship...");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let set_rel_output = cli
        .set_relationship(
            policy_id_str,
            "transcript",
            "test-transcripts",
            "writer",
            "did:key:zQ3shtest1234",
        )
        .expect("set_relationship writer");
    eprintln!("[hub-lc] set_relationship output: {}", set_rel_output);

    // Wait for finalization
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 4. Start AcpLightClient
    eprintln!("[hub-lc] Step 4: Starting ACP light client...");
    let hub_rpc = hub_cluster.node(0).rpc_url();
    let hub_ws = hub_cluster.node(0).ws_url();
    let light_client = AcpLightClient::new(&hub_rpc, &hub_ws, 10)
        .await
        .expect("ACP light client should connect");

    // Step 5. Verify light client receives headers and syncs height
    eprintln!("[hub-lc] Step 5: Waiting for light client to sync...");
    let sync = light_client
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("light client should sync to height 3");
    eprintln!(
        "[hub-lc] Light client synced: height={}, module_state_root={}",
        sync.height, sync.module_state_root
    );

    // Step 6. check_policy → allowed (existence proof)
    eprintln!("[hub-lc] Step 6: Checking policy existence...");
    let policy_check = light_client
        .check_policy(policy_id_str)
        .await
        .expect("check_policy should succeed");
    assert!(policy_check.allowed, "policy should exist on hub.rs");
    assert!(policy_check.proof.is_some(), "proof should be returned");
    eprintln!(
        "[hub-lc] PASSED: Policy exists, verified at height {}",
        policy_check.verified_at_height
    );

    // Step 7. Verify non-existence proof for absent policy
    eprintln!("[hub-lc] Step 7: Checking non-existent policy...");
    let absent_check = light_client
        .check_policy("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .await
        .expect("check absent policy should succeed");
    assert!(!absent_check.allowed, "absent policy should not exist");
    assert!(
        absent_check.proof.is_some(),
        "non-existence proof should be returned"
    );
    eprintln!("[hub-lc] PASSED: Non-existent policy denied with proof");

    // Record the current module_state_root
    let root_before = light_client
        .header_chain()
        .latest_module_state_root()
        .expect("should have module_state_root");

    // Step 8. Mutate ACP state (add reader relationship)
    eprintln!("[hub-lc] Step 8: Mutating ACP state...");
    let mutate_output = cli
        .set_relationship(
            policy_id_str,
            "transcript",
            "test-transcripts",
            "reader",
            "did:key:zQ3shtest5678",
        )
        .expect("set_relationship reader");
    eprintln!("[hub-lc] set_relationship reader output: {}", mutate_output);

    // Step 9. Wait for module_state_root change
    eprintln!("[hub-lc] Step 9: Waiting for module_state_root change...");
    let new_sync = light_client
        .wait_for_root_change(root_before, Duration::from_secs(30))
        .await
        .expect("module_state_root should change after mutation");
    eprintln!(
        "[hub-lc] PASSED: module_state_root changed at height {}",
        new_sync.height
    );
    assert_ne!(
        root_before, new_sync.module_state_root,
        "module_state_root should differ after ACP mutation"
    );

    // Step 10. Re-check policy (cache invalidated, re-verified with new root)
    eprintln!("[hub-lc] Step 10: Re-checking policy after state change...");
    let recheck = light_client
        .check_policy(policy_id_str)
        .await
        .expect("re-check policy should succeed");
    assert!(recheck.allowed, "policy should still exist");
    assert!(
        recheck.proof.is_some(),
        "new proof should be returned (cache was invalidated)"
    );
    eprintln!(
        "[hub-lc] PASSED: Policy re-verified at height {} after cache invalidation",
        recheck.verified_at_height
    );

    // Step 11. Measure revocation SLA
    let revocation_blocks = new_sync.height.saturating_sub(sync.height);
    eprintln!(
        "[hub-lc] Step 11: Revocation SLA: {} blocks from tx to cache invalidation",
        revocation_blocks
    );

    drop(hub_cluster);
    eprintln!("[hub-lc] === All steps passed ===");
}
