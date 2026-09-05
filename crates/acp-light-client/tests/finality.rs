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
}

fn fixture(seed: u64) -> Fixture {
    let store = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&store);
    let key_hash = KeyHash::with::<Sha256>(KEY);
    let (root, batch) = tree
        .put_value_set([(key_hash, Some(b"allowed".to_vec()))], HEIGHT)
        .unwrap();
    store.write_tree_update_batch(batch).unwrap();
    let (value, proof) = tree.get_with_proof(key_hash, HEIGHT).unwrap();
    let roots = [root.0; 4];
    let root = keccak256([b"_HUB_MODULE_ROOT".as_slice(), roots.as_flattened()].concat());
    let proof = ModuleStateProof::new(
        ModuleId::Acp,
        HEIGHT,
        KEY,
        value.as_deref(),
        &proof,
        roots[0],
        roots,
    );

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
    let round = Round::new(Epoch::zero(), View::new(HEIGHT));
    let block = Block {
        context: ConsensusContext {
            round,
            leader: identity,
            parent: (View::new(HEIGHT - 1), ConsensusDigest::from([3; 32])),
        },
        parent: BlockId(B256::repeat_byte(3)),
        height: HEIGHT,
        timestamp: 1_700_000_000,
        prevrandao: B256::ZERO,
        state_root: StateRoot(B256::repeat_byte(1)),
        module_state_root: root,
        txs: vec![],
        payload: None,
        db_targets: DbTargets::default(),
    };
    let vote = Finalize::sign(
        &signer,
        Proposal::new(round, View::new(HEIGHT - 1), block.digest()),
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
                        let f = f.read();
                        let result = match request["method"].as_str().unwrap() {
                            "hub_getLightBlock" => serde_json::to_value(&f.light).unwrap(),
                            "hub_getStateProof" => serde_json::to_value(&f.proof).unwrap(),
                            method => panic!("unexpected RPC: {method}"),
                        };
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
    assert!(client.check_policy("policy-1").await.is_err());
    assert!(client.cache().is_empty());
    let root = server.fixture.read().root;
    send.send(GossipHeader {
        module_state_root: root,
        ..header
    })
    .await
    .unwrap();
    let sync = client
        .wait_for_height(HEIGHT, Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(sync.module_state_root, server.fixture.read().root);
    assert!(client.check_policy("policy-1").await.unwrap().allowed);
    assert!(client
        .check_policy("policy-1")
        .await
        .unwrap()
        .proof
        .is_none());
    task.abort();
}

#[test]
fn delayed_proof_cannot_restore_a_revoked_cache_entry() {
    let cache = AcpCache::new(10);
    let old_root = B256::repeat_byte(1);
    let new_root = B256::repeat_byte(2);
    cache.insert("key", Some(vec![1]), HEIGHT, old_root);
    assert_eq!(cache.invalidate_stale(new_root), 1);
    cache.insert("key", Some(vec![1]), HEIGHT, old_root);
    assert!(cache.get("key", HEIGHT + 1, new_root).is_none());
    assert!(cache.get("key", HEIGHT - 1, old_root).is_none());
    assert!(cache.get("key", HEIGHT + 11, old_root).is_none());
    cache.insert("key", None, HEIGHT + 1, new_root);
    assert!(!cache.get("key", HEIGHT + 1, new_root).unwrap().allowed);
}
