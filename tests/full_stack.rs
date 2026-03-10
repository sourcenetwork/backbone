//! Secure Training Data Compartments — 41-step e2e test.
//!
//! Two compartments (acme, globex), one Orbis ring (T=2, N=3), multiple service
//! identities with scoped permissions. Full Rust stack: hub.rs + Orbis + DefraDB.
//!
//! See `memory/full_stack_test.md` for the step-by-step breakdown.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use defra_harness::node::RustNode;
use orbis_harness::cli::signer_did_for_pk;
use orbis_harness::cli::types::RingPayload;
use orbis_harness::defradb::identity::{did_key_from_secp256k1, DefraHttpClient};
use orbis_harness::ring::OrbisRing;
use orbis_harness::{
    generate_identity_keys, generate_run_id, start_node, HubRsNodeConfig, KeyringBackend,
    NodeConfig, OrbisCliClient, OrbisSignerConfig,
};

use acp_light_client::AcpLightClient;
use hub_harness::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};
use hub_harness::observe::ClusterAssertions;

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

const HARDHAT_KEY_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HARDHAT_KEY_1: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

struct HubdCli {
    binary: PathBuf,
    rpc_url: String,
    chain_id: u64,
    key: String,
}

impl HubdCli {
    fn new(binary: PathBuf, rpc_url: &str, chain_id: u64, key: &str) -> Self {
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
        let before: Vec<String> =
            serde_json::from_str(&self.exec(&["acp", "list-policies"])?).unwrap_or_default();

        self.exec(&["acp", "create-policy", yaml])?;

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let after_output = self.exec(&["acp", "list-policies"])?;
            let after: Vec<String> = serde_json::from_str(&after_output)
                .map_err(|e| eyre::eyre!("parse list-policies '{}': {}", after_output, e))?;
            let new_ids: Vec<&String> = after.iter().filter(|id| !before.contains(id)).collect();
            match new_ids.len() {
                1 => return Ok(new_ids[0].clone()),
                n if n > 1 => {
                    return Err(eyre::eyre!(
                        "expected 1 new policy ID, got {}: {:?}",
                        n,
                        new_ids
                    ))
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre::eyre!("no new policy ID found after 30s polling"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
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

    fn delete_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<String> {
        self.exec(&[
            "acp",
            "delete-relationship",
            policy_id,
            resource,
            object_id,
            relation,
            actor,
        ])
    }

    fn register_namespace(&self, namespace: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "register-namespace", namespace])
    }

    fn add_collaborator(&self, namespace: &str, did: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "add-collaborator", namespace, did])
    }

    fn list_posts(&self, namespace: &str) -> eyre::Result<String> {
        self.exec(&["bulletin", "list-posts", "--namespace", namespace])
    }

    fn fund_evm_address(&self, to_address: &str, value_wei: &str) -> eyre::Result<String> {
        let nonce = self.get_evm_nonce(HARDHAT_KEY_1)?;
        let raw_tx = sign_eth_transfer(HARDHAT_KEY_1, to_address, value_wei, nonce, self.chain_id);
        let result = self.exec(&["tx", "send-raw", &hex::encode(raw_tx)])?;
        let json: serde_json::Value = serde_json::from_str(result.trim())
            .map_err(|e| eyre::eyre!("parse send-raw response: {}", e))?;
        let tx_hash = json
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("no tx_hash in send-raw response: {}", result))?;
        self.wait_for_tx_receipt(tx_hash)?;
        Ok(result)
    }

    fn wait_for_tx_receipt(&self, tx_hash: &str) -> eyre::Result<()> {
        for _attempt in 0..50 {
            let body = format!(
                r#"{{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["{}"],"id":1}}"#,
                tx_hash
            );
            let output = Command::new("curl")
                .args([
                    "-s",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &body,
                    &self.rpc_url,
                ])
                .output()
                .map_err(|e| eyre::eyre!("curl eth_getTransactionReceipt: {}", e))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                if json.get("result").is_some_and(|v| !v.is_null()) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        eyre::bail!("receipt not available after 50 attempts for {}", tx_hash)
    }

    fn get_evm_nonce(&self, key_hex: &str) -> eyre::Result<u64> {
        let key_bytes = hex::decode(key_hex).map_err(|e| eyre::eyre!("invalid key hex: {}", e))?;
        let signer = PrivateKeySigner::from_slice(&key_bytes)
            .map_err(|e| eyre::eyre!("invalid signing key: {}", e))?;
        let address = format!("{:?}", signer.address());
        self.get_evm_nonce_for_address(&address)
    }

    fn get_evm_nonce_for_address(&self, address: &str) -> eyre::Result<u64> {
        let body = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["{}","latest"],"id":1}}"#,
            address
        );
        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &body,
                &self.rpc_url,
            ])
            .output()
            .map_err(|e| eyre::eyre!("curl eth_getTransactionCount: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|e| eyre::eyre!("parse nonce response '{}': {}", stdout.trim(), e))?;
        let hex_nonce = json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("no result in nonce response: {}", stdout.trim()))?;
        let nonce = u64::from_str_radix(hex_nonce.trim_start_matches("0x"), 16)
            .map_err(|e| eyre::eyre!("parse hex nonce '{}': {}", hex_nonce, e))?;
        Ok(nonce)
    }
}

fn sign_eth_transfer(
    from_key_hex: &str,
    to: &str,
    value_wei: &str,
    nonce: u64,
    chain_id: u64,
) -> Vec<u8> {
    let key_bytes = hex::decode(from_key_hex).expect("valid hex key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("valid signing key");

    let to_addr: alloy_primitives::Address = to.parse().expect("valid to address");
    let value = value_wei.parse::<U256>().expect("valid wei value");

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 0,
        gas_limit: 21_000,
        to: TxKind::Call(to_addr),
        value,
        input: Default::default(),
    };

    let sig_hash = tx.signature_hash();
    let sig = signer.sign_hash_sync(&sig_hash).expect("sign transfer");
    let signed = tx.into_signed(sig);
    signed.encoded_2718()
}

fn evm_address_from_private_key(key_hex: &str) -> String {
    let key_bytes = hex::decode(key_hex).expect("valid hex key");
    let signer = PrivateKeySigner::from_slice(&key_bytes).expect("valid signing key");
    format!("{:#x}", signer.address())
}

fn secp256k1_did_from_compressed_pubkey_hex(pubkey_hex: &str) -> String {
    let pubkey_bytes = hex::decode(pubkey_hex).expect("decode pubkey hex");
    assert_eq!(
        pubkey_bytes.len(),
        33,
        "expected 33-byte compressed secp256k1 pubkey"
    );
    let mut codec_bytes = Vec::with_capacity(2 + 33);
    codec_bytes.extend_from_slice(&[0xe7, 0x01]);
    codec_bytes.extend_from_slice(&pubkey_bytes);
    let encoded = bs58::encode(&codec_bytes).into_string();
    format!("did:key:z{}", encoded)
}

async fn wait_for_dkg_post(
    hub_cli: &HubdCli,
    namespace: &str,
    timeout: Duration,
) -> eyre::Result<(String, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(output) = hub_cli.list_posts(namespace) {
            if let Ok(posts) = serde_json::from_str::<serde_json::Value>(&output) {
                if let Some(arr) = posts.as_array() {
                    for post in arr {
                        let payload_bytes = match post.get("payload") {
                            // Byte array: [123, 34, ...]
                            Some(serde_json::Value::Array(byte_arr)) => {
                                let bytes: Vec<u8> = byte_arr
                                    .iter()
                                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                                    .collect();
                                if bytes.is_empty() {
                                    continue;
                                }
                                bytes
                            }
                            // Hex string
                            Some(serde_json::Value::String(s)) if !s.is_empty() => {
                                hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec())
                            }
                            _ => continue,
                        };

                        let post_id = post
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        return Ok((post_id, payload_bytes));
                    }
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            // One last attempt with full debug output
            if let Ok(output) = hub_cli.list_posts(namespace) {
                eprintln!("[backbone]   FINAL list-posts output: {}", output);
            }
            return Err(eyre::eyre!(
                "timeout waiting for DKG post in namespace '{}'",
                namespace
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn bls_did_key(public_key_bytes: &[u8]) -> String {
    let mut buf = vec![0xea, 0x01];
    buf.extend_from_slice(public_key_bytes);
    let encoded = bs58::encode(&buf).into_string();
    format!("did:key:z{}", encoded)
}

fn bls_did_key_from_hex(public_key_hex: &str) -> String {
    let bytes =
        hex::decode(public_key_hex).unwrap_or_else(|e| panic!("invalid BLS public key hex: {}", e));
    bls_did_key(&bytes)
}

fn is_acp_denied(result: &Result<serde_json::Value, eyre::Report>, data_path: &str) -> bool {
    let body = result
        .as_ref()
        .expect("GraphQL request failed (network error, not ACP denial)");
    body.get("errors").is_some()
        || body
            .pointer(data_path)
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
}

fn is_write_acp_denied(
    result: &Result<serde_json::Value, eyre::Report>,
    create_path: &str,
) -> bool {
    let body = result
        .as_ref()
        .expect("GraphQL request failed (network error, not ACP denial)");
    if body.get("errors").is_some() {
        return true;
    }
    match body.pointer(create_path) {
        None => true,
        Some(v) => v.as_array().is_some_and(|a| a.is_empty()),
    }
}

#[tokio::test]
#[ignore = "spec test: requires hubd, defra, and orbis-node on PATH"]
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

    let orbis_operator_keys = generate_identity_keys(&run_id, 3);

    // Step 1a. Start hub.rs single node (bulletin + ACP)
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

    hub_cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("hub.rs node should become healthy");

    let hub_state = hub_cluster.observe(Duration::from_millis(200));
    hub_state
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("hub.rs should reach height 3");
    eprintln!("[backbone] Hub.rs node ready");

    let hub_cli = HubdCli::new(
        hubd_binary,
        &hub_cluster.node(0).rpc_url(),
        hub_chain_id,
        HARDHAT_KEY_0,
    );

    // Step 2. Start Orbis ring (T=2, N=3) with hub.rs for bulletin + ACP
    eprintln!("[backbone] Step 2: Starting Orbis ring (3 nodes, threshold 2)...");
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(orbis_operator_keys.clone())
        .hub_rs_config(HubRsNodeConfig {
            rpc_url: hub_cluster.node(0).rpc_url(),
            ws_url: hub_cluster.node(0).ws_url(),
            chain_id: hub_chain_id,
        })
        .build()
        .await
        .expect("ring should start");

    // Step 2a. Fund orbis nodes on hub.rs
    let mut evm_addresses = Vec::with_capacity(ring.node_count());
    let mut node_signer_dids = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let data_dir = ring.node(i).data_dir().join("data");
        let pk_path = data_dir.join("public_key.txt");
        let signer_pk_path = data_dir.join("signer_pubkey.txt");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let (address, signer_did) = loop {
            let addr_ok = std::fs::read_to_string(&pk_path)
                .ok()
                .filter(|s| !s.trim().is_empty() && s.trim().starts_with("0x"));
            let pubkey_ok = std::fs::read_to_string(&signer_pk_path)
                .ok()
                .filter(|s| !s.trim().is_empty());
            if let (Some(addr), Some(pubkey_hex)) = (addr_ok, pubkey_ok) {
                let did = secp256k1_did_from_compressed_pubkey_hex(pubkey_hex.trim());
                break (addr.trim().to_string(), did);
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "node{} did not write public_key.txt + signer_pubkey.txt within 15s",
                    i
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        eprintln!(
            "[backbone]   Funding orbis node{} on hub.rs: {} (DID: {}...)",
            i,
            address,
            &signer_did[..40.min(signer_did.len())]
        );
        hub_cli
            .fund_evm_address(&address, "1000000000000000000")
            .unwrap_or_else(|e| panic!("fund node{} on hub.rs: {}", i, e));
        evm_addresses.push(address);
        node_signer_dids.push(signer_did);
    }

    // Step 2b. Wait for ring to be ready
    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("all nodes should be healthy");

    let orbis_cli = OrbisCliClient::new().expect("resolve cli-tool binary");

    let mut node_infos = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let info = orbis_cli
            .query_node_info(&ring.node(i).grpc_addr())
            .unwrap_or_else(|e| panic!("query node{} info: {}", i, e));
        node_infos.push(info);
    }

    // Step 3. Register bulletin namespace + add collaborators
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
        "[backbone] Ring ready. PK: {}..., ID: {}...",
        &ring_pk_hex[..32.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // Step 4. Create ring signing policy + register ring object
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
    eprintln!(
        "[backbone] Step 9: Service identities created: {}, {}, {}, {}, {}, {}",
        training_svc.label,
        inference_svc.label,
        audit_svc.label,
        globex_svc.label,
        acme_defra_svc.label,
        globex_defra_svc.label,
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
    eprintln!("[backbone] Step 10: DefraDB service accounts authorized as ring signers");

    // Step 11. Create acme ACP policy
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
    for (label, addr) in &[
        ("acme-defra", &acme_defra_evm_addr),
        ("globex-defra", &globex_defra_evm_addr),
    ] {
        hub_cli
            .fund_evm_address(addr, "1000000000000000000")
            .unwrap_or_else(|e| panic!("fund {} on hub.rs: {}", label, e));
        eprintln!("[backbone] Step 13: Funded {} on hub.rs: {}", label, addr);
    }

    // Step 14. Start acme DefraDB with Orbis signer (derivation="acme-corp")
    let defra_binary = test_infra::BinaryResolver::new("DEFRA", "defra")
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

    // Step 15. Deploy Transcript schema with @policy
    let acme_client = DefraHttpClient::new(&acme_defra.api_url);

    let transcript_schema = format!(
        r#"type Transcript @policy(id: "{}", resource: "transcript") {{ call_id: String  content: String  customer: String }}"#,
        acme_policy_id,
    );
    acme_client
        .schema_add(&transcript_schema)
        .await
        .expect("add transcript schema");
    eprintln!("[backbone] Step 15: Schema added: Transcript @policy");

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

    let mut acme_doc_ids: Vec<String> = Vec::new();
    for (call_id, content, customer) in &transcripts {
        let mutation = format!(
            r#"mutation {{ create_Transcript(input: {{ call_id: "{}", content: "{}", customer: "{}" }}) {{ _docID }} }}"#,
            call_id, content, customer
        );
        let result = acme_client
            .graphql(&mutation, Some(&training_svc.private_key_hex))
            .await
            .unwrap_or_else(|e| panic!("write transcript {}: {}", call_id, e));
        if let Some(doc_id) = result
            .pointer("/data/create_Transcript/0/_docID")
            .and_then(|v| v.as_str())
        {
            acme_doc_ids.push(doc_id.to_string());
        }
    }
    assert_eq!(
        acme_doc_ids.len(),
        transcripts.len(),
        "should have captured all transcript doc IDs"
    );
    eprintln!(
        "[backbone] Step 16: TRAINING_SVC wrote {} transcripts",
        acme_doc_ids.len()
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
    for doc_id in &acme_doc_ids {
        hub_cli
            .set_relationship(
                &acme_policy_id,
                "transcript",
                doc_id,
                "reader",
                &inference_svc.did_key,
            )
            .unwrap_or_else(|e| {
                panic!("grant inference_svc reader on transcript {}: {}", doc_id, e)
            });
    }
    eprintln!(
        "[backbone] Step 16c: INFERENCE_SVC granted reader on {} transcript documents",
        acme_doc_ids.len()
    );

    // Step 17. INFERENCE_SVC reads back — sees transcripts (reader grant)
    let query = r#"query { Transcript { _docID call_id content customer } }"#;
    let query_body = acme_client
        .graphql(query, Some(&inference_svc.private_key_hex))
        .await
        .expect("inference_svc query transcripts");
    let docs = query_body
        .pointer("/data/Transcript")
        .and_then(|v| v.as_array())
        .expect("Transcript array");
    assert_eq!(
        docs.len(),
        3,
        "inference_svc should see exactly 3 transcripts (has reader grant)"
    );
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

    // Step 21. Deploy SupportTicket schema with @policy
    let globex_client = DefraHttpClient::new(&globex_defra.api_url);

    let ticket_schema = format!(
        r#"type SupportTicket @policy(id: "{}", resource: "ticket") {{ ticket_id: String  subject: String  body: String  priority: String }}"#,
        globex_policy_id,
    );
    globex_client
        .schema_add(&ticket_schema)
        .await
        .expect("add ticket schema");
    eprintln!("[backbone] Step 21: Schema added: SupportTicket @policy");

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

    let mut globex_doc_ids: Vec<String> = Vec::new();
    for (tid, subject, body, priority) in &tickets {
        let mutation = format!(
            r#"mutation {{ create_SupportTicket(input: {{ ticket_id: "{}", subject: "{}", body: "{}", priority: "{}" }}) {{ _docID }} }}"#,
            tid, subject, body, priority
        );
        let result = globex_client
            .graphql(&mutation, Some(&globex_svc.private_key_hex))
            .await
            .unwrap_or_else(|e| panic!("write ticket {}: {}", tid, e));
        if let Some(doc_id) = result
            .pointer("/data/create_SupportTicket/0/_docID")
            .and_then(|v| v.as_str())
        {
            globex_doc_ids.push(doc_id.to_string());
        }
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
    assert_eq!(
        ticket_docs.len(),
        2,
        "globex_svc should see exactly 2 tickets (owner has read access)"
    );
    eprintln!(
        "[backbone] Step 22: GLOBEX_SVC wrote {} tickets, reads back {}",
        tickets.len(),
        ticket_docs.len()
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
    for doc_id in &acme_doc_ids {
        hub_cli
            .set_relationship(
                &acme_policy_id,
                "transcript",
                doc_id,
                "reader",
                &audit_svc.did_key,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "grant audit_svc reader on acme transcript {}: {}",
                    doc_id, e
                )
            });
    }
    for doc_id in &globex_doc_ids {
        hub_cli
            .set_relationship(
                &globex_policy_id,
                "ticket",
                doc_id,
                "reader",
                &audit_svc.did_key,
            )
            .unwrap_or_else(|e| {
                panic!("grant audit_svc reader on globex ticket {}: {}", doc_id, e)
            });
    }
    eprintln!(
        "[backbone] Step 25: AUDIT_SVC granted reader on {} acme docs + {} globex docs",
        acme_doc_ids.len(),
        globex_doc_ids.len()
    );

    // Step 26. AUDIT_SVC reads acme transcripts — succeeds
    let audit_acme = acme_client
        .graphql(
            r#"query { Transcript { _docID call_id content } }"#,
            Some(&audit_svc.private_key_hex),
        )
        .await
        .expect("audit_svc query acme transcripts");
    let audit_acme_docs = audit_acme
        .pointer("/data/Transcript")
        .and_then(|v| v.as_array())
        .expect("Transcript array for audit");
    assert_eq!(
        audit_acme_docs.len(),
        3,
        "audit_svc should see exactly 3 acme transcripts"
    );
    eprintln!(
        "[backbone] Step 26: AUDIT_SVC reads {} acme transcripts",
        audit_acme_docs.len()
    );

    // Step 27. AUDIT_SVC reads globex tickets — succeeds
    let audit_globex = globex_client
        .graphql(
            r#"query { SupportTicket { _docID ticket_id subject } }"#,
            Some(&audit_svc.private_key_hex),
        )
        .await
        .expect("audit_svc query globex tickets");
    let audit_globex_docs = audit_globex
        .pointer("/data/SupportTicket")
        .and_then(|v| v.as_array())
        .expect("SupportTicket array for audit");
    assert_eq!(
        audit_globex_docs.len(),
        2,
        "audit_svc should see exactly 2 globex tickets"
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
    eprintln!("[backbone] Step 29: Revoking AUDIT_SVC from acme...");
    for doc_id in &acme_doc_ids {
        hub_cli
            .delete_relationship(
                &acme_policy_id,
                "transcript",
                doc_id,
                "reader",
                &audit_svc.did_key,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "revoke audit_svc reader on acme transcript {}: {}",
                    doc_id, e
                )
            });
    }

    let revoked_acme = acme_client
        .graphql(
            r#"query { Transcript { _docID call_id } }"#,
            Some(&audit_svc.private_key_hex),
        )
        .await;

    assert!(
        is_acp_denied(&revoked_acme, "/data/Transcript"),
        "Revoked AUDIT_SVC should not read acme transcripts"
    );
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

    let new_key_write = r#"mutation {
        create_Transcript(input: {
            call_id: "call-004",
            content: "Written by rotated training key",
            customer: "acme-cust-99"
        }) {
            _docID
        }
    }"#;
    let new_key_result = acme_client
        .graphql(new_key_write, Some(&new_training_svc.private_key_hex))
        .await
        .expect("new training_svc write");

    // Extract the new document's ID so we can test old-key denial against it.
    // The old key doesn't own this document, so after writer revocation it has no access.
    let new_doc_id = new_key_result
        .pointer("/data/create_Transcript/0/_docID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let new_doc_id = match new_doc_id {
        Some(id) => id,
        None => {
            let verify = acme_client
                .graphql(
                    r#"query { Transcript(filter: {call_id: {_eq: "call-004"}}) { _docID } }"#,
                    Some(&new_training_svc.private_key_hex),
                )
                .await
                .expect("verify rotated key write");
            verify
                .pointer("/data/Transcript/0/_docID")
                .and_then(|v| v.as_str())
                .expect("rotated training_svc transcript should exist")
                .to_string()
        }
    };
    eprintln!("[backbone] PASSED: New TRAINING_SVC writes successfully");

    hub_cli
        .delete_relationship(
            &acme_policy_id,
            "transcript",
            transcript_object,
            "writer",
            &training_svc.did_key,
        )
        .expect("revoke old training_svc writer on transcript collection");

    // Wait for the light client to sync the new state root after deletion.
    // The websocket header subscription needs time to deliver the new block.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Old training_svc tries to UPDATE the new document — should be denied.
    // The old key doesn't own this doc (new_training_svc does) and its writer
    // relationship was revoked, so no relation grants update access.
    let old_key_write = format!(
        r#"mutation {{ update_Transcript(docID: "{}", input: {{ content: "old-key-hack" }}) {{ _docID }} }}"#,
        new_doc_id
    );
    let old_key_result = acme_client
        .graphql(&old_key_write, Some(&training_svc.private_key_hex))
        .await;

    assert!(
        is_write_acp_denied(&old_key_result, "/data/update_Transcript"),
        "Old TRAINING_SVC should be denied after revocation"
    );
    eprintln!("[backbone] PASSED: Old TRAINING_SVC denied after revocation");

    let rotated_verify = acme_client
        .graphql(
            r#"mutation { create_Transcript(input: { call_id: "call-005", content: "Rotated key still works", customer: "acme-cust-1" }) { _docID } }"#,
            Some(&new_training_svc.private_key_hex),
        )
        .await
        .expect("rotated training_svc should still work");

    let has_doc = rotated_verify
        .pointer("/data/create_Transcript/0/_docID")
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
    eprintln!("[backbone] PASSED: Rotated TRAINING_SVC still works after old key revoked");

    // Step 34. Start AcpLightClient
    eprintln!("[backbone] Step 34: Starting ACP light client...");
    let hub_rpc = hub_cluster.node(0).rpc_url();
    let hub_ws = hub_cluster.node(0).ws_url();
    let light_client = AcpLightClient::new(&hub_rpc, &hub_ws, 10)
        .await
        .expect("ACP light client should connect");

    // Step 35. Verify light client receives headers and syncs height
    eprintln!("[backbone] Step 35: Waiting for light client to sync...");
    let sync = light_client
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("light client should sync to height 3");
    eprintln!(
        "[backbone] Light client synced: height={}, module_state_root={}",
        sync.height, sync.module_state_root
    );

    // Step 36. Verify policy existence with Merkle proof
    eprintln!("[backbone] Step 36: Checking policy existence...");
    let policy_check = light_client
        .check_policy(&acme_policy_id)
        .await
        .expect("check_policy should succeed");
    assert!(policy_check.allowed, "policy should exist on hub.rs");
    assert!(policy_check.proof.is_some(), "proof should be returned");
    eprintln!(
        "[backbone] PASSED: Policy exists, verified at height {}",
        policy_check.verified_at_height
    );

    // Step 37. Non-existence proof for absent policy
    eprintln!("[backbone] Step 37: Checking non-existent policy...");
    let absent_check = light_client
        .check_policy("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .await
        .expect("check absent policy should succeed");
    assert!(!absent_check.allowed, "absent policy should not exist");
    assert!(
        absent_check.proof.is_some(),
        "non-existence proof should be returned"
    );
    eprintln!("[backbone] PASSED: Non-existent policy denied with proof");

    let root_before = light_client
        .header_chain()
        .latest_module_state_root()
        .expect("should have module_state_root");

    // Step 38. Re-grant audit_svc reader (revoked in Step 29) to mutate state
    eprintln!("[backbone] Step 38: Mutating ACP state on hub.rs...");
    hub_cli
        .set_relationship(
            &acme_policy_id,
            "transcript",
            &acme_doc_ids[0],
            "reader",
            &audit_svc.did_key,
        )
        .expect("re-grant audit_svc reader on first acme transcript");

    // Step 39. Wait for module_state_root change
    eprintln!("[backbone] Step 39: Waiting for module_state_root change...");
    let new_sync = light_client
        .wait_for_root_change(root_before, Duration::from_secs(30))
        .await
        .expect("module_state_root should change after mutation");
    eprintln!(
        "[backbone] PASSED: module_state_root changed at height {}",
        new_sync.height
    );
    assert_ne!(
        root_before, new_sync.module_state_root,
        "module_state_root should differ after ACP mutation"
    );

    // Step 40. Re-check policy after state change (cache invalidation)
    eprintln!("[backbone] Step 40: Re-checking policy after state change...");
    let recheck = light_client
        .check_policy(&acme_policy_id)
        .await
        .expect("re-check policy should succeed");
    assert!(recheck.allowed, "policy should still exist");
    assert!(
        recheck.proof.is_some(),
        "new proof should be returned (cache was invalidated)"
    );
    eprintln!(
        "[backbone] PASSED: Policy re-verified at height {} after cache invalidation",
        recheck.verified_at_height
    );

    // Step 41. Revocation SLA <= 5 blocks
    let revocation_blocks = new_sync.height.saturating_sub(sync.height);
    eprintln!(
        "[backbone] Step 41: Revocation SLA: {} blocks from tx to cache invalidation",
        revocation_blocks
    );
    assert!(
        revocation_blocks <= 5,
        "revocation SLA violated: {} blocks (max 5)",
        revocation_blocks
    );

    // Final: hub.rs cluster health check
    hub_state
        .assert_no_errors()
        .expect("hub.rs cluster should have no unexpected errors");
    eprintln!("[backbone] Hub.rs cluster health: no unexpected errors");

    drop(hub_cluster);
    drop(globex_defra);
    drop(acme_defra);

    eprintln!("[backbone] All 41 steps passed.");
}
