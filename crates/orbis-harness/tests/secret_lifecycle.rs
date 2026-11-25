//! Secret lifecycle test: DKG -> StoreSecret -> PRE -> Decrypt, on native Vera.

use std::time::Duration;

use bulletin::r#trait::BulletinPost;
use crypto::r#trait::{CryptoDeserialize, EncryptionProof, ThresholdSigner};
use crypto::{GroupAffine, SignImpl};
use orbis_harness::fixture::setup_dkg;
use orbis_harness::DkgFixture;
use vera_client::threshold_objects::EncryptedDocument;

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

const RESOURCE: &str = "document";
const RELATION: &str = "reader";
const PERMISSION: &str = "read";
const READER_SEED: &str = "test_did_secret";
const SECRET: &[u8] = b"Hello from StoreSecret!";
const MANUAL_SECRET: &[u8] = b"Hello from manual path!";
const DERIVATION: &[u8] = b"test_derivation";
const RETRY_DEADLINE: Duration = Duration::from_secs(90);
/// How long a submission still in flight after a store gets to reach Vera.
const SETTLE: Duration = Duration::from_secs(5);
/// Blocks that must finalize after the pause before a sequence is read.
const SETTLE_BLOCKS: u64 = 2;

fn prepare(
    plaintext: &[u8],
    fixture: &DkgFixture,
    policy_id: &str,
    derivation: Option<Vec<u8>>,
) -> cli_tool::PreparedSecret {
    cli_tool::prepare_secret(
        plaintext,
        &fixture.ring_pk_hex,
        derivation,
        policy_id.to_string(),
        RESOURCE.to_string(),
        PERMISSION.to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare secret")
}

/// Store through the ring, retrying while the nodes catch up on the ring's state.
async fn store(
    fixture: &DkgFixture,
    prepared: &cli_tool::PreparedSecret,
    with_proof: bool,
) -> cli_tool::StoreSecretResult {
    let deadline = tokio::time::Instant::now() + RETRY_DEADLINE;
    loop {
        match cli_tool::store_prepared_secret(
            fixture.endpoint(),
            prepared,
            fixture.ring_id.clone(),
            Some(READER_SEED.to_string()),
            with_proof,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "StoreSecret did not succeed in time: {error:#}"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Re-encrypt to the reader, retrying while the grant reaches the nodes.
async fn pre(fixture: &DkgFixture, object_id: &str, derivation: Option<Vec<u8>>) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + RETRY_DEADLINE;
    loop {
        match cli_tool::do_pre(
            fixture.endpoint(),
            fixture.admin.chain_id(),
            fixture.ring_pk_hex.clone(),
            object_id.to_string(),
            Some(READER_SEED.to_string()),
            derivation.clone(),
            None,
            None,
            None,
        )
        .await
        {
            Ok(plaintext) => return plaintext,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "PRE did not succeed in time: {error:#}"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// The committed native sequence of the node's Vera submitter.
async fn sequence(fixture: &DkgFixture, submitter: &str) -> u64 {
    fixture
        .vera
        .client()
        .get_native_nonce(submitter)
        .await
        .expect("read the node's native sequence")
}

/// The submitter's sequence after a pause and a few more finalized blocks,
/// so a submission still in flight from a store is counted.
async fn settled_sequence(fixture: &DkgFixture, submitter: &str) -> u64 {
    tokio::time::sleep(SETTLE).await;
    let client = fixture.vera.client();
    let target = client.block_number().await.expect("Vera height") + SETTLE_BLOCKS;
    let deadline = tokio::time::Instant::now() + RETRY_DEADLINE;
    while client.block_number().await.expect("Vera height") < target {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Vera did not finalize {SETTLE_BLOCKS} more blocks in time"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    sequence(fixture, submitter).await
}

async fn stored_document(fixture: &DkgFixture, object_id: &str) -> EncryptedDocument {
    fixture
        .admin
        .read_document(object_id)
        .await
        .expect("read document from Vera")
        .unwrap_or_else(|| panic!("document {object_id} should be on Vera"))
}

#[tokio::test]
#[ignore = "requires verad and orbis-node (VERAD_BINARY, ORBIS_BINARY) and ~2 min runtime"]
async fn dkg_store_pre_decrypt_full_pipeline() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let fixture = setup_dkg().await;
    let admin = &fixture.admin;
    let ring_id = &fixture.ring_id;

    println!("Ring ready: pk={}...", &fixture.ring_pk_hex[..40]);

    // ================================================================
    // Setup: ACP policy
    // ================================================================
    let policy_id = admin
        .account()
        .create_policy(DEFAULT_ACP_POLICY_YAML)
        .await
        .expect("add policy");

    // ================================================================
    // Store secrets: manual + service paths
    // ================================================================

    // Manual path: encrypt locally and store the document on Vera directly.
    let manual = prepare(MANUAL_SECRET, &fixture, &policy_id, None);
    let manual_document = EncryptedDocument {
        ring_id: ring_id.clone(),
        document: String::from_utf8(manual.encrypted_document).expect("encrypted JSON is UTF-8"),
        proof: EncryptionProof {
            challenge: manual.challenge,
            response: manual.response,
        }
        .try_into()
        .expect("serialize encryption proof"),
        policy_id: policy_id.clone(),
        resource: RESOURCE.to_string(),
        permission: PERMISSION.to_string(),
        tier: None,
        timestamp: None,
        pet_tag: None,
        pet_tag_proof: None,
    };
    let object_id_manual = admin
        .register_document(manual_document.clone())
        .await
        .expect("store manual document");
    assert_eq!(
        stored_document(&fixture, &object_id_manual).await,
        manual_document,
        "the manual document must round-trip through Vera"
    );

    // Service path: prepare + StoreSecret through the ring.
    let prepared = prepare(SECRET, &fixture, &policy_id, None);
    let prepared_derived = prepare(SECRET, &fixture, &policy_id, Some(DERIVATION.to_vec()));

    // The node that serves the requests submits each document to Vera with
    // its own native signer.
    let submitter = admin
        .node_submitter_did(&fixture.node_infos[0].node_key)
        .await
        .expect("find node0's Vera submitter");
    let sequence_before = sequence(&fixture, &submitter).await;
    let stored = store(&fixture, &prepared, true).await;
    let sequence_after = settled_sequence(&fixture, &submitter).await;
    assert!(
        sequence_after > sequence_before,
        "Sequence should increment after store ({sequence_before} -> {sequence_after})"
    );
    let object_id_service = stored.object_id.clone();
    assert!(
        !object_id_service.is_empty(),
        "StoreSecret returns an object id"
    );
    let derived = store(&fixture, &prepared_derived, false).await;
    let object_id_derived = derived.object_id.clone();

    // The ring's node submitted each document to Vera.
    let service_document = stored_document(&fixture, &object_id_service).await;
    stored_document(&fixture, &object_id_derived).await;
    assert_eq!(manual_document.ring_id, service_document.ring_id);
    assert_eq!(manual_document.policy_id, service_document.policy_id);

    // ================================================================
    // Verify the ring's BLS signature over the stored document
    // ================================================================
    let post = BulletinPost {
        id: object_id_service.clone(),
        payload: serde_json::to_vec(&service_document).expect("serialize stored document"),
    };
    let message: Vec<u8> = post.try_into().expect("serialize BulletinPost");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(
        &hex::decode(&stored.signature).expect("decode signature hex"),
    )
    .expect("deserialize signature");
    let ring_pk =
        GroupAffine::from_bytes(&hex::decode(&fixture.ring_pk_hex).expect("decode ring_pk"))
            .expect("deserialize ring pk");
    SignImpl::new()
        .verify(&ring_pk, &message, &signature)
        .expect("BLS signature should verify");
    println!("BLS signature verified!");

    // ================================================================
    // ACP: register objects + set relationships
    // ================================================================
    let reader_did = cli_tool::reader_did_from_seed(READER_SEED);
    for object_id in [&object_id_manual, &object_id_service, &object_id_derived] {
        admin
            .account()
            .register_object(&policy_id, RESOURCE, object_id)
            .await
            .expect("register object");
        admin
            .account()
            .set_relationship(&policy_id, RESOURCE, object_id, RELATION, &reader_did)
            .await
            .expect("grant reader");
    }

    // ================================================================
    // PRE + decrypt
    // ================================================================
    assert_eq!(
        pre(&fixture, &object_id_service, None).await,
        SECRET,
        "Decrypted should match original"
    );
    println!("PRE decryption verified!");

    assert_eq!(
        pre(&fixture, &object_id_derived, Some(DERIVATION.to_vec())).await,
        SECRET,
        "Derived decrypted should match"
    );
    println!("Derived-key PRE verified!");

    assert_eq!(
        pre(&fixture, &object_id_manual, None).await,
        MANUAL_SECRET,
        "Manually stored document should decrypt"
    );
    println!("Manual-path PRE verified!");

    // ================================================================
    // Idempotent store
    // ================================================================
    let seq_before = sequence(&fixture, &submitter).await;
    let duplicate = store(&fixture, &prepared, true).await;
    let seq_after = settled_sequence(&fixture, &submitter).await;
    assert_eq!(object_id_service, duplicate.object_id, "Same object_id");
    assert_eq!(seq_before, seq_after, "No submission for duplicate store");
    assert_eq!(
        stored_document(&fixture, &object_id_service).await,
        service_document,
        "a duplicate store leaves the document unchanged"
    );
    println!("Idempotency verified!");
    println!("=== Full pipeline test passed ===");
}
