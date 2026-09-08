use std::{sync::Arc, time::Duration};

use acp_light_client::{
    AcpCache, AcpLightClient, GossipHeader, LightBlock, ModuleId, ProofClient, RecordProof,
};
use alloy_primitives::B256;
use axum::{extract::State, routing::post, Json, Router};
use commonware_codec::{Decode as _, Encode as _};
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
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const HEIGHT: u64 = 10;
const KEY: &[u8] = b"policy/objs/policy-1";

struct Fixture {
    light: LightBlock,
    proof: RecordProof,
    key: String,
    root: B256,
    points: std::collections::BTreeMap<Vec<u8>, RecordProof>,
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
    let (root, points, proof) = std::thread::spawn(move || {
        use commonware_glue::stateful::db::DatabaseSet;
        use commonware_runtime::{buffer::paged::CacheRef, tokio, Runner as _, Supervisor as _};
        use commonware_utils::{NZUsize, NZU16};
        use hub_backend::native::{self, NativeStateSet};

        let directory = tempfile::tempdir().unwrap();
        tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
            |context| async move {
                let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
                let set = NativeStateSet::init(
                    context.child("proof"),
                    native::state_config("proof", cache),
                )
                .await;
                let mut changes: Vec<_> = records
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect();
                changes.sort_by(|a, b| a.0.cmp(&b.0));
                set.apply(
                    native::prepare(set.new_batches().await, [changes, vec![], vec![], vec![]])
                        .await
                        .unwrap(),
                )
                .await;
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let roots = [a.root().0, b.root().0, h.root().0, n.root().0];
                let root = hub_modules::module_state::combine_module_roots(&roots);
                let mut points = std::collections::BTreeMap::new();
                for (key, _) in records {
                    let proof =
                        native::record_proof_at([&a, &b, &h, &n], root, ModuleId::Acp, &key)
                            .await
                            .unwrap();
                    points.insert(key, proof);
                }
                let proof = native::record_proof_at([&a, &b, &h, &n], root, ModuleId::Acp, KEY)
                    .await
                    .unwrap();
                (root, points, proof)
            },
        )
    })
    .join()
    .unwrap();

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
        native_targets: Some(Default::default()),
        receipt_commitment: Some(B256::ZERO),
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
                                "hub_getCurrentRecordProof" => {
                                    let key = request["params"][1].as_str().unwrap();
                                    let key = hex::decode(key.trim_start_matches("0x")).unwrap();
                                    let proof = if key == KEY {
                                        &f.proof
                                    } else {
                                        f.points.get(&key).unwrap_or(&f.proof)
                                    };
                                    serde_json::to_value(hub_permission::RecordResponse {
                                        revision: f.light.clone(),
                                        record: proof.clone(),
                                    })
                                    .unwrap()
                                }
                                "hub_getCurrentPermissionProof" => {
                                    serde_json::to_value(hub_permission::PermissionResponse {
                                        revision: f.light.clone(),
                                        proof: f.permission.as_ref().unwrap().clone(),
                                    })
                                    .unwrap()
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
    let fetch = || client.fetch_and_verify_record(ModuleId::Acp, KEY, HEIGHT);
    assert!(fetch().await.unwrap().record.value.is_some());
    assert!(client
        .fetch_and_verify_record(ModuleId::Acp, KEY, HEIGHT + 1)
        .await
        .is_err());
    server.fixture.write().light.height += 1;
    assert!(fetch().await.is_err());
    server.fixture.write().light.height = HEIGHT;
    assert!(client
        .fetch_and_verify_record(ModuleId::Bulletin, KEY, HEIGHT)
        .await
        .is_err());
    assert!(client
        .fetch_and_verify_record(ModuleId::Acp, b"other", HEIGHT)
        .await
        .is_err());
    server.fixture.write().proof.value = Some(vec![0].into());
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
    client.cache().clear();
    *server.fixture.write() = fixture_records_at(
        42,
        vec![(KEY.to_vec(), b"changed".to_vec())],
        timestamp,
        HEIGHT + 2,
    );
    let current = client.read_policy("policy-1").await.unwrap();
    assert_eq!(current.value.as_deref(), Some(b"changed".as_slice()));
    assert_eq!(current.verified_at_height, HEIGHT + 2);
    assert_eq!(client.header_chain().latest_height(), HEIGHT + 2);
    assert_eq!(
        client.read_policy("policy-1").await.unwrap().value,
        current.value
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
    verify_permission_records("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").await;
}

#[tokio::test]
async fn provider_actor_permissions_reject_missing_evidence_and_stale_state() {
    verify_permission_records(&format!("did:opk:{}", "ab".repeat(32))).await;
}

async fn verify_permission_records(owner: &str) {
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
    let owner = owner.parse().unwrap();
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
        roots: Some(data.proof.roots),
        reads: reads
            .into_iter()
            .map(|read| {
                let RecordRead::Key(key) = read else {
                    panic!("owner requires only point evidence")
                };
                let point = &data.points[&key];
                PermissionRead::CurrentPoint {
                    key: point.key.clone(),
                    value: point.value.clone(),
                    proof: point.proof.clone(),
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
    let age = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .saturating_sub(Duration::from_secs(server.fixture.read().light.timestamp));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(29).saturating_sub(age)).await;
    tokio::time::resume();
    assert!(client.header_chain().fresh_state().is_ok());
    server.fixture.write().delay = Duration::from_secs(3);
    let error = client.verify_access(&policy, &request).await.unwrap_err();
    assert!(error.to_string().contains("stale"), "{error:?}");
    task.abort();
}

#[tokio::test]
async fn oversized_header_frames_and_fragmented_messages_close_without_publishing() {
    use tokio_tungstenite::tungstenite::protocol::frame::{
        coding::{Data, OpCode},
        Frame,
    };
    for fragmented in [false, true] {
        let data = fixture(42);
        let trusted = data.key.clone();
        let header = GossipHeader {
            chain_id: 9001,
            height: HEIGHT,
            block_hash: data.light.block_hash.parse().unwrap(),
            parent_hash: data.light.parent_hash.parse().unwrap(),
            timestamp: data.light.timestamp,
            state_root: data.light.state_root.parse().unwrap(),
            module_state_root: data.root,
            tx_count: 0,
            publisher_index: 0,
            signature: vec![],
        };
        let mut message = vec![b' '; acp_light_client::header_sync::HEADER_MESSAGE_BYTES + 1];
        message.extend(serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0", "method":"eth_subscription", "params":{"subscription":"1", "result":header}})).unwrap());
        let server = Server::start(data).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_url = format!("ws://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            ws.next().await.unwrap().unwrap();
            if fragmented {
                let second = message.split_off(message.len() / 2);
                assert!(message.len() < acp_light_client::header_sync::HEADER_MESSAGE_BYTES);
                assert!(second.len() < acp_light_client::header_sync::HEADER_MESSAGE_BYTES);
                let _ = ws
                    .send(Message::Frame(Frame::message(
                        message,
                        OpCode::Data(Data::Text),
                        false,
                    )))
                    .await;
                let _ = ws
                    .send(Message::Frame(Frame::message(
                        second,
                        OpCode::Data(Data::Continue),
                        true,
                    )))
                    .await;
            } else {
                let _ = ws
                    .send(Message::Text(String::from_utf8(message).unwrap().into()))
                    .await;
            }
            let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap();
            assert!(
                matches!(response, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
                "{response:?}"
            );
        });
        let client = AcpLightClient::new(&server.url, &ws_url, &trusted, 10)
            .await
            .unwrap();
        task.await.unwrap();
        assert!(client.header_chain().state().is_none());
        assert!(client.cache().is_empty());
    }
}

#[tokio::test]
async fn epoch_end_reproposal_preserves_requested_state_and_timestamp() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut f = fixture_records_at(
        42,
        vec![(KEY.to_vec(), b"allowed".to_vec())],
        now - 60,
        HEIGHT,
    );
    let target_time = f.light.timestamp;
    let parent = Block::decode_cfg(
        hex::decode(f.light.block.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
        &hub_domain::BlockCfg {
            max_txs: 64,
            tx: hub_domain::TxCfg {
                max_tx_bytes: 65_536,
            },
        },
    )
    .unwrap();
    let mut child = parent.clone();
    child.parent = parent.id();
    child.height += 1;
    child.timestamp += 60;
    child.module_state_root = B256::repeat_byte(99);
    child.context.parent = (parent.context.round.view(), parent.digest());
    child.context.round = Round::new(Epoch::new(1), View::new(1));
    let identity = ed25519::PrivateKey::from_seed(42).public_key();
    let players = Set::from_iter_dedup([identity.clone()]);
    let (output, shares) =
        deal::<MinSig, _, N3f1>(TestRng::new(42), Mode::NonZeroCounter, players.clone()).unwrap();
    child.payload = Some(hub_domain::DkgPayload::EpochInfo(
        commonware_glue::dkg::types::EpochInfo {
            outcome: commonware_glue::dkg::types::EpochOutcome::Success,
            epoch: Epoch::new(2),
            output: output.clone(),
            players: players.clone(),
            next_players: players.clone(),
            directory: commonware_utils::sequence::Unit,
        },
    ));
    let signer = LightConsensusScheme::signer(
        LIGHT_BLOCK_NAMESPACE,
        players,
        output.public().clone(),
        shares.get_value(&identity).unwrap().clone(),
    )
    .unwrap();
    let vote = Finalize::sign(
        &signer,
        Proposal::new(
            Round::new(Epoch::new(1), View::new(3)),
            View::new(2),
            child.digest(),
        ),
    )
    .unwrap();
    let finalization =
        Finalization::from_finalizes(&signer, non_empty![&vote], &Sequential).unwrap();
    f.light.finalization = format!("0x{}", hex::encode(finalization.encode()));
    f.light.descendants = vec![format!("0x{}", hex::encode(child.encode()))];
    let root = f.root;
    let server = Server::start(f).await;
    let client = server.client();
    let state = client.verified_state(HEIGHT).await.unwrap();
    assert_eq!(state.height, HEIGHT);
    assert_eq!(state.timestamp, target_time);
    assert_eq!(state.module_state_root, root);
    let record = client
        .fetch_and_verify_record(ModuleId::Acp, KEY, HEIGHT)
        .await
        .unwrap();
    assert_eq!(
        record.revision.module_state_root.parse::<B256>().unwrap(),
        root
    );
    server.fixture.write().light.descendants.clear();
    assert!(client.verified_state(HEIGHT).await.is_err());
}
