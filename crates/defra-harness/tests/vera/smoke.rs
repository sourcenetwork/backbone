use defra_harness::{
    generate_identity, users_schema_with_policy, BinarySource, TestCluster, USER_ACP_POLICY,
};

/// Smoke test proving DefraDB -> Vera ACP pipeline works end-to-end.
///
/// 1. Starts a vera.rs deployment + 1 Rust DefraDB node connected to it
/// 2. Creates an ACP policy (a native request the node's worker submits)
/// 3. Creates a protected document as Jack (owner)
/// 4. Jack sees the document, anonymous sees nothing
///
/// The node must be started with Jack's identity so its Vera provider
/// can create bearer tokens for Jack's DID.
#[tokio::test]
async fn rust_vera_smoke() {
    let binary = super::vera_binary();
    let jack = generate_identity(&binary).expect("failed to generate Jack identity");

    let cluster = TestCluster::builder()
        .rust_nodes(1)
        .with_rust_binary(BinarySource::Path(binary.clone()))
        .with_vera()
        .with_identity(&jack.private_key_hex)
        .build()
        .await
        .expect("failed to build Vera cluster");

    let node = cluster.client(0);

    // Add ACP policy — the node submits its creation to Vera
    let policy_result = node
        .acp_policy_add(USER_ACP_POLICY, &jack.private_key_hex)
        .expect("failed to add ACP policy via Vera");

    let policy_id = policy_result["PolicyID"]
        .as_str()
        .or_else(|| policy_result["policyID"].as_str())
        .expect("missing PolicyID in policy add result");

    // Deploy schema with @policy directive
    let schema = users_schema_with_policy(policy_id);
    node.schema_add_with_identity(&schema, &jack.private_key_hex)
        .expect("failed to add schema with policy");

    // Create a protected document as Jack
    let data = node
        .query_with_identity(
            r#"mutation { add_User(input: {name: "Jack", age: 30}) { _docID name age } }"#,
            &jack.private_key_hex,
        )
        .expect("failed to create document");

    let _doc_id = data["add_User"][0]["_docID"]
        .as_str()
        .unwrap_or_else(|| panic!("missing _docID in create result: {data}"));

    // Jack queries -> sees 1 document
    let jack_result = node
        .query_with_identity("query { User { _docID name age } }", &jack.private_key_hex)
        .expect("Jack query failed");

    let jack_users = jack_result["User"]
        .as_array()
        .expect("Jack result not array");
    assert_eq!(jack_users.len(), 1, "Jack should see 1 document");
    assert_eq!(jack_users[0]["name"], "Jack");

    // Anonymous query -> sees 0 documents (ACP enforced via Vera)
    let anon_result = node
        .query("query { User { _docID name age } }")
        .expect("anonymous query failed");

    let anon_users = anon_result["User"]
        .as_array()
        .expect("anon result not array");
    assert_eq!(
        anon_users.len(),
        0,
        "anonymous should see 0 documents (Vera ACP)"
    );
}
