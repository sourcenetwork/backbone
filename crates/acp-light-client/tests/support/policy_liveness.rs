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
    let key = acp_light_client::cache::keys::relationship_key(&policy, &storage_key);
    assert_eq!(key, keys::relationship_key(&policy, &storage_key));
    assert!(key.starts_with(b"relationship/v3/"));
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
        .read_relationship(&policy, &storage_key)
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
