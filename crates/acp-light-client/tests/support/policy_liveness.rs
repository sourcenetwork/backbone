use super::*;
use vera_modules::{
    acp::{
        keys,
        types::{Object, PolicyCmd, PolicyMarshalingType},
        AcpModule,
    },
    kv_store::ModuleKvStore,
};

#[tokio::test]
async fn retained_relationships_do_not_restore_retired_policy_ownership() {
    let mut module = AcpModule::new();
    let owner = "did:key:owner".parse().unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: documents\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    let record = module
        .query_object_owner(&policy, &object)
        .unwrap()
        .1
        .unwrap();
    let storage_key = keys::relationship_storage_key(&record.relationship);
    let key =
        acp_light_client::cache::keys::relationship_key(&policy, record.generations, &storage_key);
    assert_eq!(key, keys::relationship_key(&policy, &storage_key));
    assert!(key.starts_with(b"relationship/v4/"));
    let prefix = vera_permission::object_owner_prefix(&policy, &object).unwrap();
    let live = fixture_records(42, module.store().prefix_scan(b""));
    let live_policy = live.policy_prefixes[&prefix].policy.clone();
    let timestamp = live.light.timestamp;
    let server = Server::start(live).await;
    let client = server.client();
    assert_eq!(
        client
            .read_current_object_owner(&policy, &object, HEIGHT)
            .await
            .unwrap()
            .1,
        Some(vera_permission::Actor(owner.clone()))
    );
    assert!(client
        .read_current_relationship(&policy, &key, HEIGHT)
        .await
        .unwrap()
        .1
        .value
        .is_some());
    assert!(client
        .read_current_object_owner(&policy, &object, HEIGHT + 1)
        .await
        .is_err());
    assert!(client
        .read_current_relationship(&policy, &keys::relationship_policy_prefix(&policy), HEIGHT)
        .await
        .is_err());

    module.delete_policy(&owner, &policy).unwrap();
    let retired = fixture_records_at(
        42,
        module.store().prefix_scan(b""),
        timestamp + 1,
        HEIGHT + 1,
    );
    assert!(retired.points[&key].value.is_some());
    *server.fixture.write() = retired;
    assert!(client
        .read_current_object_owner(&policy, &object, HEIGHT)
        .await
        .unwrap()
        .1
        .is_none());
    assert!(client
        .read_current_relationship(&policy, &key, HEIGHT)
        .await
        .unwrap()
        .1
        .value
        .is_none());
    assert!(client
        .fetch_and_verify_record(ModuleId::Acp, &key, HEIGHT)
        .await
        .unwrap()
        .record
        .value
        .is_some());

    let (connected, headers) = connect_current(&server).await;
    let raw = client
        .fetch_and_verify_record(ModuleId::Acp, &key, HEIGHT + 1)
        .await
        .unwrap();
    let root = raw.revision.module_state_root.parse().unwrap();
    let key_hex = acp_light_client::cache::keys::hex_encode_key(&key);
    connected.cache().insert(
        &key_hex,
        raw.record
            .value
            .map(|value| Arc::<[u8]>::from(value.as_ref())),
        HEIGHT + 1,
        root,
    );
    assert!(connected
        .cache()
        .get(&key_hex, HEIGHT + 1, root)
        .unwrap()
        .value
        .is_some());
    assert!(connected
        .read_relationship(&policy, record.generations, &storage_key)
        .await
        .unwrap()
        .value
        .is_none());
    headers.abort();
    drop(connected);

    for selected in [&prefix, &key] {
        let valid = server.fixture.read().policy_prefixes[selected].clone();
        server
            .fixture
            .write()
            .policy_prefixes
            .get_mut(selected)
            .unwrap()
            .prefix
            .proof = Default::default();
        assert!(client
            .read_current_relationship(&policy, selected, HEIGHT)
            .await
            .is_err());
        server
            .fixture
            .write()
            .policy_prefixes
            .insert(selected.clone(), valid);
    }
    server
        .fixture
        .write()
        .policy_prefixes
        .get_mut(&prefix)
        .unwrap()
        .policy = live_policy;
    assert!(client
        .read_current_object_owner(&policy, &object, HEIGHT)
        .await
        .is_err());
}

#[tokio::test]
async fn recreated_target_and_userset_relations_require_fresh_grants() {
    const SCHEMA: &str = "\
name: generations
resources:
  - name: document
    relations:
      - name: reader
  - name: group
    relations:
      - name: member
";
    for removed in ["reader", "member"] {
        let mut module = AcpModule::new();
        let owner = "did:key:owner".parse().unwrap();
        let policy = module
            .create_policy(&owner, SCHEMA, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let id = &policy.policy.id;
        let object = Object {
            resource: "document".into(),
            id: "report".into(),
        };
        module
            .direct_policy_cmd(&owner, id, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
        let mut relationship = module
            .query_object_owner(id, &object)
            .unwrap()
            .1
            .unwrap()
            .relationship;
        relationship.relation = "reader".into();
        relationship.subject = serde_json::from_value(serde_json::json!({
            "EntitySet": {"resource": "group", "object_id": "staff", "relation": "member"}
        }))
        .unwrap();
        module
            .direct_policy_cmd(&owner, id, PolicyCmd::SetRelationship(relationship.clone()))
            .unwrap();
        let old_pair = policy.relations.pair(&relationship).unwrap();
        assert!(old_pair.target > 0 && old_pair.subject > 0);
        let suffix = keys::relationship_storage_key(&relationship);
        let old_key = acp_light_client::cache::keys::relationship_key(id, old_pair, &suffix);
        assert_eq!(
            old_key,
            keys::relationship_generation_key(id, old_pair, &suffix)
        );
        let live = fixture_records(42, module.store().prefix_scan(b""));
        let original_policy = live.policy_prefixes[&old_key].policy.clone();
        let timestamp = live.light.timestamp;
        let server = Server::start(live).await;
        let client = server.client();
        assert!(client
            .read_current_relationship(id, &old_key, HEIGHT)
            .await
            .unwrap()
            .1
            .value
            .is_some());
        let old_namespace = format!("relationship/v3/{id}/{suffix}");
        assert!(client
            .read_current_relationship(id, old_namespace.as_bytes(), HEIGHT)
            .await
            .is_err());

        let stripped = SCHEMA.replace(&format!("    relations:\n      - name: {removed}\n"), "");
        assert_eq!(
            module
                .edit_policy(&owner, id, &stripped, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .0,
            1
        );
        *server.fixture.write() = fixture_records_at(
            42,
            module.store().prefix_scan(b""),
            timestamp + 1,
            HEIGHT + 1,
        );
        assert!(client
            .fetch_and_verify_record(ModuleId::Acp, &old_key, HEIGHT + 1)
            .await
            .unwrap()
            .record
            .value
            .is_some());
        assert!(client
            .read_current_relationship(id, &old_key, HEIGHT + 1)
            .await
            .is_err());
        assert_eq!(
            client
                .read_current_object_owner(id, &object, HEIGHT + 1)
                .await
                .unwrap()
                .1,
            Some(vera_permission::Actor(owner.clone()))
        );

        let (_, recreated) = module
            .edit_policy(&owner, id, SCHEMA, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let fresh_pair = recreated.relations.pair(&relationship).unwrap();
        if removed == "reader" {
            assert_ne!(fresh_pair.target, old_pair.target);
            assert_eq!(fresh_pair.subject, old_pair.subject);
        } else {
            assert_eq!(fresh_pair.target, old_pair.target);
            assert_ne!(fresh_pair.subject, old_pair.subject);
        }
        let fresh_key = acp_light_client::cache::keys::relationship_key(id, fresh_pair, &suffix);
        assert_ne!(fresh_key, old_key);
        *server.fixture.write() = fixture_records_at(
            42,
            module.store().prefix_scan(b""),
            timestamp + 2,
            HEIGHT + 2,
        );
        let (connected, headers) = connect_current(&server).await;
        let raw = client
            .fetch_and_verify_record(ModuleId::Acp, &old_key, HEIGHT + 2)
            .await
            .unwrap();
        let root = raw.revision.module_state_root.parse().unwrap();
        for key in [&old_key, &fresh_key] {
            let key_hex = acp_light_client::cache::keys::hex_encode_key(key);
            connected.cache().insert(
                &key_hex,
                raw.record
                    .value
                    .as_ref()
                    .map(|value| Arc::<[u8]>::from(value.as_ref())),
                HEIGHT + 2,
                root,
            );
            assert!(connected
                .cache()
                .get(&key_hex, HEIGHT + 2, root)
                .unwrap()
                .value
                .is_some());
        }
        assert!(connected
            .read_relationship(id, old_pair, &suffix)
            .await
            .is_err());
        let absent = connected
            .read_relationship(id, fresh_pair, &suffix)
            .await
            .unwrap();
        assert!(absent.value.is_none());
        assert!(absent.proof.is_none());

        let current_policy = server.fixture.read().policy_prefixes[&fresh_key]
            .policy
            .clone();
        server
            .fixture
            .write()
            .policy_prefixes
            .get_mut(&fresh_key)
            .unwrap()
            .policy = original_policy;
        assert!(connected
            .read_relationship(id, fresh_pair, &suffix)
            .await
            .is_err());
        server
            .fixture
            .write()
            .policy_prefixes
            .get_mut(&fresh_key)
            .unwrap()
            .policy = current_policy;

        module
            .direct_policy_cmd(&owner, id, PolicyCmd::SetRelationship(relationship.clone()))
            .unwrap();
        *server.fixture.write() = fixture_records_at(
            42,
            module.store().prefix_scan(b""),
            timestamp + 3,
            HEIGHT + 3,
        );
        let fresh = connected
            .read_relationship(id, fresh_pair, &suffix)
            .await
            .unwrap();
        let record: vera_modules::acp::types::RelationshipRecord =
            serde_json::from_slice(fresh.value.as_deref().unwrap()).unwrap();
        assert_eq!(record.relationship, relationship);
        assert_eq!(record.generations, fresh_pair);
        assert!(fresh.proof.is_none());
        assert!(connected
            .read_relationship(id, old_pair, &suffix)
            .await
            .is_err());
        headers.abort();
    }
}

async fn connect_current(server: &Server) -> (AcpLightClient, tokio::task::JoinHandle<()>) {
    let light = server.fixture.read().light.clone();
    let height = light.height;
    let trusted = server.fixture.read().key.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        let request = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["method"], "vera_subscribeHeaders");
        ws.send(Message::Text(
            serde_json::json!({"jsonrpc":"2.0", "id":1, "result":"1"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let header = GossipHeader {
            chain_id: 9001,
            height,
            block_hash: light.block_hash.parse().unwrap(),
            parent_hash: light.parent_hash.parse().unwrap(),
            timestamp: light.timestamp,
            state_root: light.state_root.parse().unwrap(),
            module_state_root: light.module_state_root.parse().unwrap(),
            tx_count: 0,
            publisher_index: 0,
            signature: vec![],
        };
        ws.send(Message::Text(
            serde_json::json!({"jsonrpc":"2.0", "method":"vera_header",
            "params":{"subscription":"1", "result":header}})
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        while ws.next().await.is_some() {}
    });
    let client = AcpLightClient::new(&server.url, &ws_url, &trusted, 10)
        .await
        .unwrap();
    client
        .wait_for_height(height, Duration::from_secs(3))
        .await
        .unwrap();
    (client, task)
}
