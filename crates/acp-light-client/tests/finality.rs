use std::{sync::Arc, time::Duration};

use acp_light_client::{
    AcpCache, AcpLightClient, GossipHeader, LightBlock, ModuleId, ModuleStateProof, ProofClient,
};
use alloy_primitives::{keccak256, B256};
use axum::{extract::State, routing::post, Json, Router};
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Finalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, Digestible as _, Signer as _,
};
use commonware_parallel::Sequential;
use commonware_utils::{non_empty, ordered::Set, N3f1, TestRng};
use futures::{SinkExt as _, StreamExt as _};
use hub_domain::{
    Block, BlockId, ConsensusContext, ConsensusDigest, DbTargets, EpochMaterial,
    LightConsensusScheme, StateRoot, LIGHT_BLOCK_NAMESPACE,
};
use jmt::{mock::MockTreeStore, JellyfishMerkleTree, KeyHash};
use parking_lot::RwLock;
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const HEIGHT: u64 = 10;
const KEY: &[u8] = b"policy/objs/policy-1";

struct Fixture {
    light: LightBlock,
    proof: ModuleStateProof,
    key: String,
    root: B256,
    points: std::collections::BTreeMap<Vec<u8>, ModuleStateProof>,
    permission: Option<hub_permission::PermissionProof>,
    delay: Duration,
}

fn fixture(seed: u64) -> Fixture {
    fixture_records(seed, vec![(KEY.to_vec(), b"allowed".to_vec())])
}

fn fixture_records(seed: u64, records: Vec<(Vec<u8>, Vec<u8>)>) -> Fixture {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fixture_records_at(seed, records, timestamp, HEIGHT)
}

fn fixture_records_at(
    seed: u64,
    records: Vec<(Vec<u8>, Vec<u8>)>,
    timestamp: u64,
    height: u64,
) -> Fixture {
    let store = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&store);
    let key_hash = KeyHash::with::<Sha256>(KEY);
    let (root, batch) = tree
        .put_value_set(
            records
                .iter()
                .map(|(key, value)| (KeyHash::with::<Sha256>(key), Some(value.clone()))),
            height,
        )
        .unwrap();
    store.write_tree_update_batch(batch).unwrap();
    let (value, proof) = tree.get_with_proof(key_hash, height).unwrap();
    let roots = [root.0; 4];
    let root = keccak256([b"_HUB_MODULE_ROOT".as_slice(), roots.as_flattened()].concat());
    let proof = ModuleStateProof::new(
        ModuleId::Acp,
        height,
        KEY,
        value.as_deref(),
        &proof,
        roots[0],
        roots,
    );

    let points = records
        .iter()
        .map(|(key, _)| {
            let (value, proof) = tree
                .get_with_proof(KeyHash::with::<Sha256>(key), height)
                .unwrap();
            (
                key.clone(),
                ModuleStateProof::new(
                    ModuleId::Acp,
                    height,
                    key,
                    value.as_deref(),
                    &proof,
                    roots[0],
                    roots,
                ),
            )
        })
        .collect();

    let identity = ed25519::PrivateKey::from_seed(seed).public_key();
    let players = Set::from_iter_dedup([identity.clone()]);
    let (output, shares) =
        deal::<MinSig, _, N3f1>(TestRng::new(seed), Mode::NonZeroCounter, players.clone()).unwrap();
    let key = hex::encode(output.public().public().encode());
    let signer = LightConsensusScheme::signer(
        LIGHT_BLOCK_NAMESPACE,
        players.clone(),
        output.public().clone(),
        shares.get_value(&identity).unwrap().clone(),
    )
    .unwrap();
    let material = EpochMaterial::new(players, output.public().clone());
    let round = Round::new(Epoch::zero(), View::new(height));
    let block = Block {
        context: ConsensusContext {
            round,
            leader: identity,
            parent: (View::new(height - 1), ConsensusDigest::from([3; 32])),
        },
        parent: BlockId(B256::repeat_byte(3)),
        height,
        timestamp,
        prevrandao: B256::ZERO,
        state_root: StateRoot(B256::repeat_byte(1)),
        module_state_root: root,
        txs: vec![],
        payload: None,
        db_targets: DbTargets::default(),
    };
    let vote = Finalize::sign(
        &signer,
        Proposal::new(round, View::new(height - 1), block.digest()),
    )
    .unwrap();
    let votes = [vote];
    let finalization =
        Finalization::from_finalizes(&signer, non_empty![@votes.iter()], &Sequential).unwrap();
    Fixture {
        light: LightBlock::from_parts(&block, &finalization.encode(), &material.encode()),
        proof,
        key,
        root,
        points,
        permission: None,
        delay: Duration::ZERO,
    }
}

struct Server {
    url: String,
    fixture: Arc<RwLock<Fixture>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(fixture: Fixture) -> Self {
        let fixture = Arc::new(RwLock::new(fixture));
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(f): State<Arc<RwLock<Fixture>>>,
                     Json(request): Json<serde_json::Value>| async move {
                        let (result, delay) = {
                            let f = f.read();
                            let result = match request["method"].as_str().unwrap() {
                                "hub_getLightBlock" => serde_json::to_value(&f.light).unwrap(),
                                "hub_getStateProof" => {
                                    let key = request["params"][1].as_str().unwrap();
                                    let key = hex::decode(key.trim_start_matches("0x")).unwrap();
                                    let proof = if key == KEY {
                                        &f.proof
                                    } else {
                                        f.points.get(&key).unwrap_or(&f.proof)
                                    };
                                    serde_json::to_value(proof).unwrap()
                                }
                                "hub_getPermissionProof" => {
                                    serde_json::to_value(f.permission.as_ref().unwrap()).unwrap()
                                }
                                method => panic!("unexpected RPC: {method}"),
                            };
                            (result, f.delay)
                        };
                        tokio::time::sleep(delay).await;
                        Json(serde_json::json!({"jsonrpc":"2.0", "id":1, "result":result}))
                    },
                ),
            )
            .with_state(fixture.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, fixture, task }
    }

    fn client(&self) -> ProofClient {
        ProofClient::new(&self.url, &self.fixture.read().key).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn proof_is_bound_to_requested_revision_module_and_key() {
    let server = Server::start(fixture(42)).await;
    let client = server.client();
    let key = hex::encode(KEY);
    let fetch = || client.fetch_and_verify_proof("acp", &key, HEIGHT);
    assert!(fetch().await.unwrap().0.value.is_some());
    assert!(client
        .fetch_and_verify_proof("acp", &key, HEIGHT + 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("light block height"));
    server.fixture.write().proof.height += 1;
    assert!(fetch()
        .await
        .unwrap_err()
        .to_string()
        .contains("proof height"));
    server.fixture.write().proof.height = HEIGHT;
    assert!(client
        .fetch_and_verify_proof("bulletin", &key, HEIGHT)
        .await
        .unwrap_err()
        .to_string()
        .contains("proof module"));
    assert!(client
        .fetch_and_verify_proof("acp", "0x00", HEIGHT)
        .await
        .unwrap_err()
        .to_string()
        .contains("proof key"));
    server.fixture.write().proof.value = Some("0x00".into());
    assert!(fetch().await.is_err());
}

#[tokio::test]
async fn endpoint_cannot_supply_its_own_trust_key() {
    let server = Server::start(fixture(42)).await;
    let client = server.client();
    *server.fixture.write() = fixture(99);
    assert!(client.verified_state(HEIGHT).await.is_err());
    for key in ["", "xyz", "00", &"00".repeat(96)] {
        assert!(ProofClient::new(&server.url, key).is_err());
    }
}

#[tokio::test]
async fn forged_header_cannot_publish_a_root_or_seed_the_cache() {
    let server = Server::start(fixture(42)).await;
    let light = server.fixture.read().light.clone();
    let header = GossipHeader {
        chain_id: 9001,
        height: HEIGHT,
        block_hash: light.block_hash.parse().unwrap(),
        parent_hash: light.parent_hash.parse().unwrap(),
        timestamp: light.timestamp,
        state_root: light.state_root.parse().unwrap(),
        module_state_root: B256::repeat_byte(99),
        tx_count: 0,
        publisher_index: 0,
        signature: vec![],
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_url = format!("ws://{}", listener.local_addr().unwrap());
    let (send, mut receive) = tokio::sync::mpsc::channel::<GossipHeader>(4);
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        ws.next().await.unwrap().unwrap();
        while let Some(header) = receive.recv().await {
            let msg = serde_json::json!({"jsonrpc":"2.0", "method":"eth_subscription", "params":{"subscription":"1", "result":header}});
            ws.send(Message::Text(msg.to_string().into()))
                .await
                .unwrap();
        }
    });
    let key = server.fixture.read().key.clone();
    let client = AcpLightClient::new(&server.url, &ws_url, &key, 10)
        .await
        .unwrap();
    send.send(header.clone()).await.unwrap();
    assert!(client
        .wait_for_height(HEIGHT, Duration::from_millis(300))
        .await
        .is_err());
    assert!(client.header_chain().state().is_none());
    assert!(client.read_policy("policy-1").await.is_err());
    assert!(client.cache().is_empty());
    let root = server.fixture.read().root;
    for timestamp in [light.timestamp - 60, light.timestamp + 60] {
        *server.fixture.write() = fixture_records_at(
            42,
            vec![(KEY.to_vec(), b"allowed".to_vec())],
            timestamp,
            HEIGHT,
        );
        let bad_time = server.fixture.read().light.clone();
        send.send(GossipHeader {
            module_state_root: root,
            block_hash: bad_time.block_hash.parse().unwrap(),
            // An unauthenticated notification cannot repair a signed stale timestamp.
            timestamp: light.timestamp,
            ..header.clone()
        })
        .await
        .unwrap();
        assert!(client
            .wait_for_height(HEIGHT, Duration::from_millis(100))
            .await
            .is_err());
        assert!(client.header_chain().state().is_none());
    }
    *server.fixture.write() = fixture_records_at(
        42,
        vec![(KEY.to_vec(), b"allowed".to_vec())],
        light.timestamp,
        HEIGHT,
    );
    send.send(GossipHeader {
        module_state_root: root,
        ..header.clone()
    })
    .await
    .unwrap();
    let sync = client
        .wait_for_height(HEIGHT, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(sync.module_state_root, server.fixture.read().root);
    let record = client.read_policy("policy-1").await.unwrap();
    assert_eq!(record.value.as_deref(), Some(b"allowed".as_slice()));
    assert_eq!(record.module_state_root, root);
    assert!(record.proof.is_some());
    let cached = client.read_policy("policy-1").await.unwrap();
    assert_eq!(cached.value, record.value);
    assert_eq!(cached.module_state_root, root);
    assert!(cached.proof.is_none());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    // Replaying the same valid certificate must not renew a cached grant.
    send.send(GossipHeader {
        module_state_root: root,
        ..header.clone()
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(client
        .read_policy("policy-1")
        .await
        .unwrap_err()
        .to_string()
        .contains("stale"));
    assert!(client
        .wait_for_height(HEIGHT, Duration::from_millis(100))
        .await
        .is_err());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    *server.fixture.write() = fixture_records_at(
        42,
        vec![(KEY.to_vec(), b"allowed".to_vec())],
        timestamp,
        HEIGHT + 1,
    );
    let renewed = server.fixture.read().light.clone();
    send.send(GossipHeader {
        height: HEIGHT + 1,
        block_hash: renewed.block_hash.parse().unwrap(),
        timestamp,
        module_state_root: renewed.module_state_root.parse().unwrap(),
        ..header
    })
    .await
    .unwrap();
    client
        .wait_for_height(HEIGHT + 1, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(
        client
            .read_policy("policy-1")
            .await
            .unwrap()
            .value
            .as_deref(),
        Some(b"allowed".as_slice())
    );
    task.abort();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    assert!(client.read_policy("policy-1").await.is_err());
}

#[test]
fn delayed_proof_cannot_restore_a_revoked_cache_entry() {
    let cache = AcpCache::new(10);
    let old_root = B256::repeat_byte(1);
    let new_root = B256::repeat_byte(2);
    cache.insert("key", Some(Arc::from([1])), HEIGHT, old_root);
    assert_eq!(cache.invalidate_stale(new_root), 1);
    cache.insert("key", Some(Arc::from([1])), HEIGHT, old_root);
    assert!(cache.get("key", HEIGHT + 1, new_root).is_none());
    assert!(cache.get("key", HEIGHT - 1, old_root).is_none());
    assert!(cache.get("key", HEIGHT + 11, old_root).is_none());
    cache.insert("key", None, HEIGHT + 1, new_root);
    assert!(cache
        .get("key", HEIGHT + 1, new_root)
        .unwrap()
        .value
        .is_none());
}

#[tokio::test]
async fn permission_requests_replay_verified_records_and_reject_removed_coverage() {
    use hub_modules::{
        acp::{
            types::{PolicyCmd, PolicyMarshalingType},
            AcpModule,
        },
        kv_store::ModuleKvStore,
    };
    use hub_permission::{
        AccessRequest, Actor, Object, Operation, PermissionProof, PermissionRead, RecordRead,
        PERMISSION_LIMITS,
    };
    let mut module = AcpModule::new();
    let owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        .parse()
        .unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: documents\nresources:\n  - name: file\n    permissions:\n      - name: read\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::RegisterObject(Object {
                resource: "file".into(),
                id: "report".into(),
            }),
        )
        .unwrap();
    let request = AccessRequest {
        actor: Actor(owner),
        operations: vec![Operation {
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
            permission: "read".into(),
        }],
    };
    let block = hub_modules::types::BlockExecCtx {
        deployment_id: 9001,
        timestamp: hub_modules::types::Timestamp {
            seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            block_height: HEIGHT,
        },
        ..Default::default()
    };
    let tx = hub_modules::types::TxExecCtx {
        sequence: 7,
        signer: request.actor.0.to_string(),
        tx_hash: vec![1; 32],
    };
    let decision = module
        .check_access(&request.actor.0, &policy, &request, &block, &tx)
        .unwrap();
    let expected_decision = acp_light_client::DecisionRequest {
        deployment_id: 9001,
        policy_id: policy.clone(),
        creator: tx.signer,
        creator_sequence: tx.sequence,
        request: request.clone(),
    };
    let reads =
        hub_permission::capture_reads(module.store().clone(), &policy, &request, PERMISSION_LIMITS)
            .unwrap();
    let mut data = fixture_records(42, module.store().prefix_scan(b""));
    let proof = PermissionProof {
        reads: reads
            .into_iter()
            .map(|read| {
                let RecordRead::Key(key) = read else {
                    panic!("owner requires only point evidence")
                };
                PermissionRead::Point {
                    proof: data.points[&key].clone(),
                }
            })
            .collect(),
    };
    data.permission = Some(proof.clone());
    let light = data.light.clone();
    let trusted = data.key.clone();
    let server = Server::start(data).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        ws.next().await.unwrap().unwrap();
        let header = GossipHeader {
            chain_id: 9001,
            height: HEIGHT,
            block_hash: light.block_hash.parse().unwrap(),
            parent_hash: light.parent_hash.parse().unwrap(),
            timestamp: light.timestamp,
            state_root: light.state_root.parse().unwrap(),
            module_state_root: light.module_state_root.parse().unwrap(),
            tx_count: 0,
            publisher_index: 0,
            signature: vec![],
        };
        ws.send(Message::Text(serde_json::json!({"jsonrpc":"2.0", "method":"eth_subscription", "params":{"subscription":"1", "result":header}}).to_string().into())).await.unwrap();
        while ws.next().await.is_some() {}
    });
    let client = AcpLightClient::new(&server.url, &ws_url, &trusted, 10)
        .await
        .unwrap();
    client
        .wait_for_height(HEIGHT, Duration::from_secs(3))
        .await
        .unwrap();
    assert!(client.verify_access(&policy, &request).await.unwrap());
    assert_eq!(
        client
            .verify_access_decision(&expected_decision)
            .await
            .unwrap(),
        decision
    );
    let mut wrong_submission = expected_decision.clone();
    wrong_submission.creator_sequence += 1;
    assert!(client
        .verify_access_decision(&wrong_submission)
        .await
        .is_err());
    for index in 0..proof.reads.len() {
        let mut incomplete = proof.clone();
        incomplete.reads.remove(index);
        server.fixture.write().permission = Some(incomplete);
        assert!(client.verify_access(&policy, &request).await.is_err());
    }
    server.fixture.write().permission = Some(proof);
    let mut wrong = request.clone();
    wrong.actor = Actor(
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            .parse()
            .unwrap(),
    );
    assert!(client.verify_access(&policy, &wrong).await.is_err());
    assert!(client.verify_access(&policy, &request).await.unwrap());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(28)).await;
    tokio::time::resume();
    assert!(client.header_chain().fresh_state().is_ok());
    server.fixture.write().delay = Duration::from_secs(3);
    let error = client.verify_access(&policy, &request).await.unwrap_err();
    assert!(error.to_string().contains("stale"), "{error:?}");
    task.abort();
}
