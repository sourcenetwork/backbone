//! Secret lifecycle test: DKG -> StoreSecret -> PRE -> Decrypt.

use std::time::Duration;

use crypto::helpers::generate_keypair;
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, SignImpl};
use orbis_harness::cli::types::{BulletinPost, DocumentPayload};
use orbis_harness::fixture::setup_dkg;

const BULLETIN_PLACEHOLDER_PROOF: &[u8] = &[0x01];

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
#[ignore = "requires sourcehubd on PATH and ~2 min runtime"]
async fn dkg_store_pre_decrypt_full_pipeline() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    let fixture = setup_dkg().await;
    let orbis_cli = &fixture.orbis_cli;
    let sourcehub_cli = &fixture.sourcehub_cli;
    let endpoint = fixture.endpoint();
    let ring_pk_hex = &fixture.ring_pk_hex;
    let ring_id = &fixture.ring_id;
    let node1_address = &fixture.node_infos[0].public_address;

    println!("Ring ready: pk={}...", &ring_pk_hex[..40]);

    // ================================================================
    // Setup: ACP policy + user namespace
    // ================================================================
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));

    let resource = "document";
    let relation = "reader";
    let permission = "read";
    let did_pk_string = "test_did_secret";
    let namespace = "e2e_pipeline_ns";
    let full_namespace = format!("bulletin/{}", namespace);

    let policy_id = sourcehub_cli
        .create_policy(DEFAULT_ACP_POLICY_YAML)
        .expect("add policy");

    sourcehub_cli
        .register_namespace(namespace)
        .expect("register user namespace");

    sourcehub_cli
        .add_collaborator(namespace, &fixture.node_infos[0].public_address)
        .expect("add node as collaborator");

    // ================================================================
    // Store secrets: manual + service paths
    // ================================================================
    let ring_pk_bytes = hex::decode(ring_pk_hex).expect("decode ring_pk hex");
    let ring_pk_point = GroupAffine::from_bytes(&ring_pk_bytes).expect("deserialize ring_pk");
    let proof = vec![0x01];

    // Manual path: encrypt + post directly to bulletin
    let object_id_manual = {
        let metadata = PreImpl::encode_metadata(&policy_id, resource, permission, None, None, None);
        let (_enc_cmt, encrypted_secret, enc_proof) = PreImpl::encrypt_secret(
            &ring_pk_point,
            b"Hello from manual path!",
            None,
            Some(&metadata),
        )
        .expect("encrypt secret");
        let payload = DocumentPayload {
            ring_id: ring_id.clone(),
            document: serde_json::to_string(&encrypted_secret).expect("serialize"),
            proof: String::try_from(enc_proof).expect("serialize proof"),
            policy_id: policy_id.clone(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            tier: None,
            date: None,
        };
        let serialized: Vec<u8> = serde_json::to_vec(&payload).expect("serialize payload");
        sourcehub_cli
            .create_post(namespace, &hex::encode(&serialized), &hex::encode(&proof))
            .expect("create_bulletin_post")
    };

    // Service path: prepare + store
    let secret = b"Hello from StoreSecret!";
    let prepared_secret = orbis_cli
        .prepare_secret(secret, ring_pk_hex, None, &policy_id, resource, permission)
        .expect("prepare_secret");

    let derivation = b"test_derivation";
    let derivation_hex = hex::encode(derivation);
    let prepared_secret_derived = orbis_cli
        .prepare_secret(
            secret,
            ring_pk_hex,
            Some(&derivation_hex),
            &policy_id,
            resource,
            permission,
        )
        .expect("prepare_secret derived");

    let sequence_before = sourcehub_cli
        .get_account_sequence(node1_address)
        .expect("get sequence before store");

    let object_response = orbis_cli
        .store_prepared_secret(
            &endpoint,
            &prepared_secret,
            ring_id,
            namespace,
            &policy_id,
            resource,
            permission,
            Some(did_pk_string),
            None,
            true,
        )
        .expect("store_prepared_secret");

    let object_id_service = object_response.object_id.clone();
    let signature_hex = object_response.signature.clone();

    let derived_pk_hex = prepared_secret_derived.derived_pk.as_ref().map(hex::encode);

    let object_response_derived = orbis_cli
        .store_prepared_secret(
            &endpoint,
            &prepared_secret_derived,
            ring_id,
            namespace,
            &policy_id,
            resource,
            permission,
            Some(did_pk_string),
            derived_pk_hex.as_deref(),
            false,
        )
        .expect("store_prepared_secret_derived");
    let object_id_derived = object_response_derived.object_id.clone();

    // Verify tx was broadcast
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sequence_after = sourcehub_cli
        .get_account_sequence(node1_address)
        .expect("get sequence after store");
    assert!(
        sequence_after > sequence_before,
        "Sequence should increment after store"
    );

    // ================================================================
    // Verify bulletin posts + BLS signature
    // ================================================================
    let manual_bytes = sourcehub_cli
        .read_post(&full_namespace, &object_id_manual)
        .expect("read manual post");
    let service_bytes = sourcehub_cli
        .read_post(&full_namespace, &object_id_service)
        .expect("read service post");

    let manual: DocumentPayload = serde_json::from_slice(&manual_bytes).expect("parse manual");
    let service: DocumentPayload = serde_json::from_slice(&service_bytes).expect("parse service");
    assert_eq!(manual.ring_id, service.ring_id);
    assert_eq!(manual.policy_id, service.policy_id);

    // Verify BLS threshold signature
    let bulletin_post = BulletinPost {
        id: object_id_service.clone(),
        namespace: namespace.to_string(),
        payload: service_bytes.clone(),
        proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
    };
    let message_bytes: Vec<u8> = bulletin_post.try_into().expect("serialize BulletinPost");
    let signature_bytes = hex::decode(&signature_hex).expect("decode signature hex");
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
        .expect("deserialize signature");
    let ring_pk = GroupAffine::from_bytes(&hex::decode(ring_pk_hex).expect("decode ring_pk"))
        .expect("deserialize ring pk");
    SignImpl::new()
        .verify(&ring_pk, &message_bytes, &signature)
        .expect("BLS signature should verify");
    println!("BLS signature verified!");

    // ================================================================
    // ACP: register objects + set relationships
    // ================================================================
    for obj_id in [&object_id_manual, &object_id_derived] {
        sourcehub_cli
            .register_object(&policy_id, obj_id, resource)
            .expect("register_object_to_chain");

        sourcehub_cli
            .set_relationship(&policy_id, resource, obj_id, relation, did_pk_string)
            .expect("set_relationship_on_chain");
    }

    // ================================================================
    // PRE + decrypt
    // ================================================================
    let decrypted = orbis_cli
        .do_pre(
            &endpoint,
            ring_pk_hex,
            &reader_pk_hex,
            &reader_sk_hex,
            &object_id_service,
            Some(did_pk_string),
            &full_namespace,
            None,
        )
        .expect("PRE should succeed");
    assert_eq!(decrypted, secret, "Decrypted should match original");
    println!("PRE decryption verified!");

    // Derived-key PRE
    let decrypted_derived = orbis_cli
        .do_pre(
            &endpoint,
            ring_pk_hex,
            &reader_pk_hex,
            &reader_sk_hex,
            &object_id_derived,
            Some(did_pk_string),
            &full_namespace,
            Some(&derivation_hex),
        )
        .expect("derived PRE should succeed");
    assert_eq!(decrypted_derived, secret, "Derived decrypted should match");
    println!("Derived-key PRE verified!");

    // ================================================================
    // Idempotent store
    // ================================================================
    let seq_before = sourcehub_cli
        .get_account_sequence(node1_address)
        .expect("seq before idempotent store");

    let response_2 = orbis_cli
        .store_prepared_secret(
            &endpoint,
            &prepared_secret,
            ring_id,
            namespace,
            &policy_id,
            resource,
            permission,
            Some(did_pk_string),
            None,
            true,
        )
        .expect("idempotent store");

    tokio::time::sleep(Duration::from_secs(2)).await;
    let seq_after = sourcehub_cli
        .get_account_sequence(node1_address)
        .expect("seq after idempotent store");

    assert_eq!(object_id_service, response_2.object_id, "Same object_id");
    assert_eq!(seq_before, seq_after, "No tx for duplicate store");
    println!("Idempotency verified!");
    println!("=== Full pipeline test passed ===");
}
