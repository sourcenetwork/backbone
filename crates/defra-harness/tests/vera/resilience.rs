use std::time::Duration;

use defra_harness::{
    generate_identity, users_schema_with_policy, BinarySource, TestCluster, USER_ACP_POLICY,
};

/// How long a verified state stands without a newer one
/// (`vera_light_client::FreshnessPolicy::default().max_age`).
const FRESHNESS_LIMIT: Duration = Duration::from_secs(30);

/// Circuit breaker fail-closed: when Vera becomes unreachable after
/// initial setup, ACP-protected queries deny ALL access (including owner).
///
/// Sequence:
/// 1. Start cluster with Vera, create policy + protected doc
/// 2. Verify Jack (owner) can read during normal operation
/// 3. Stop the Vera deployment (simulates network partition)
/// 4. Once the node's newest verified state is older than the light
///    client's freshness limit, verify Jack is DENIED (fail-closed)
/// 5. Verify anonymous is also denied
#[tokio::test]
async fn rust_circuit_breaker_trip_recovery() {
    let binary = super::vera_binary();
    let jack = generate_identity(&binary).expect("Jack identity");

    let vera = super::start_vera().await;
    let cluster = TestCluster::builder()
        .rust_nodes(1)
        .with_rust_binary(BinarySource::Path(binary.clone()))
        .with_vera(super::node_config(&vera))
        .with_identity(&jack.private_key_hex)
        .build()
        .await
        .expect("build cluster");

    let node = cluster.client(0);

    // Phase 1: Normal operation — create policy and document
    let policy_result = node
        .acp_policy_add(USER_ACP_POLICY, &jack.private_key_hex)
        .expect("add policy");
    let policy_id = policy_result["PolicyID"]
        .as_str()
        .or_else(|| policy_result["policyID"].as_str())
        .expect("PolicyID");

    let schema = users_schema_with_policy(policy_id);
    node.schema_add_with_identity(&schema, &jack.private_key_hex)
        .expect("add schema");

    node.query_with_identity(
        r#"mutation { add_User(input: {name: "Jack", age: 30}) { _docID } }"#,
        &jack.private_key_hex,
    )
    .expect("create doc");

    // Jack reads successfully
    let jack_read = node
        .query_with_identity("query { User { _docID name } }", &jack.private_key_hex)
        .expect("Jack read");
    assert_eq!(
        jack_read["User"].as_array().unwrap().len(),
        1,
        "Jack should see 1 doc during normal operation"
    );

    // Phase 2: Stop Vera — kill every validator
    drop(vera);

    // Decisions stand while the newest verified state is fresh; wait until
    // the state the node holds is older than the freshness limit.
    tokio::time::sleep(FRESHNESS_LIMIT + Duration::from_secs(5)).await;

    // Phase 3: Fail-closed — even the owner is denied when Vera is unreachable.
    // The node cannot verify ACP permissions without fresh evidence, so it
    // denies all access.
    let jack_after_stop = node
        .query_with_identity("query { User { _docID name } }", &jack.private_key_hex)
        .expect("Jack read after Vera stop");
    assert_eq!(
        jack_after_stop["User"].as_array().unwrap().len(),
        0,
        "Jack should be denied when Vera is down (fail-closed)"
    );

    // Anonymous is also denied
    let anon_after_stop = node
        .query("query { User { _docID name } }")
        .expect("anon read after stop");
    assert_eq!(
        anon_after_stop["User"].as_array().unwrap().len(),
        0,
        "anonymous must be denied with Vera down (fail-closed)"
    );
}

/// Policy cache verification: after creating a policy on Vera,
/// subsequent ACP operations use the cached policy without hitting
/// the chain for every request.
///
/// This tests the positive path — policy is cached and operations are
/// fast. The 5-minute TTL makes expiry impractical to test at integration
/// level (unit tests cover expiry in policy_cache.rs).
#[tokio::test]
async fn rust_policy_cache_ttl_expiry() {
    let binary = super::vera_binary();
    let alice = generate_identity(&binary).expect("Alice identity");
    let bob = generate_identity(&binary).expect("Bob identity");

    let vera = super::start_vera().await;
    let cluster = TestCluster::builder()
        .rust_nodes(1)
        .with_rust_binary(BinarySource::Path(binary.clone()))
        .with_vera(super::node_config(&vera))
        .with_identity(&alice.private_key_hex)
        .build()
        .await
        .expect("build cluster");

    let node = cluster.client(0);

    // Create policy — triggers on-chain tx + cache insert
    let policy_result = node
        .acp_policy_add(USER_ACP_POLICY, &alice.private_key_hex)
        .expect("add policy");
    let policy_id = policy_result["PolicyID"]
        .as_str()
        .or_else(|| policy_result["policyID"].as_str())
        .expect("PolicyID");

    let schema = users_schema_with_policy(policy_id);
    node.schema_add_with_identity(&schema, &alice.private_key_hex)
        .expect("add schema");

    // Create a doc — registers on-chain, caches locally
    let data = node
        .query_with_identity(
            r#"mutation { add_User(input: {name: "Alice", age: 25}) { _docID } }"#,
            &alice.private_key_hex,
        )
        .expect("create doc");
    let doc_id = data["add_User"][0]["_docID"].as_str().expect("_docID");

    // Multiple rapid ACP operations — all should use cached policy
    for i in 0..5 {
        let result = node
            .query_with_identity("query { User { _docID name } }", &alice.private_key_hex)
            .unwrap_or_else(|_| panic!("Alice query iteration {}", i));
        assert_eq!(
            result["User"].as_array().unwrap().len(),
            1,
            "Alice should see 1 doc on iteration {}",
            i
        );
    }

    // Grant Bob reader (on-chain tx) — policy is already cached
    node.acp_relationship_add("User", doc_id, "reader", &bob.did, &alice.private_key_hex)
        .expect("grant Bob reader");

    // Bob reads — triggers verify_access which uses cached policy
    let bob_read = node
        .query_with_identity("query { User { _docID name } }", &bob.private_key_hex)
        .expect("Bob read");
    assert_eq!(
        bob_read["User"].as_array().unwrap().len(),
        1,
        "Bob should see 1 doc after grant"
    );

    // Revoke and verify — all using cached policy
    node.acp_relationship_delete("User", doc_id, "reader", &bob.did, &alice.private_key_hex)
        .expect("revoke Bob");

    let bob_revoked = node
        .query_with_identity("query { User { _docID name } }", &bob.private_key_hex)
        .expect("Bob read after revoke");
    assert_eq!(
        bob_revoked["User"].as_array().unwrap().len(),
        0,
        "Bob should see 0 docs after revoke"
    );
}
