use std::collections::BTreeMap;

use super::*;
use acp_light_client::Voided;
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use vera_domain::{TermApproval, TermCertificate, TermChange, TermCut};
use vera_modules::vera::administration::{AdministrationState, OperatorPolicy, STATE_KEY};

const SEED: u64 = 42;
const GENESIS: B256 = B256::repeat_byte(7);
const POLICY: &str = "policy-1";

fn operator(byte: u8) -> SigningKey {
    SigningKey::from_bytes((&[byte; 32]).into()).unwrap()
}

fn certificate(term: u64, cut: &LightBlock, signer: &SigningKey) -> TermCertificate {
    let change = TermChange {
        genesis_id: GENESIS,
        term,
        holder: B256::repeat_byte(2),
        cut: TermCut {
            height: cut.height,
            block: cut.block_hash.parse().unwrap(),
        },
    };
    let signature: Signature = signer.sign_prehash(&change.signing_digest()).unwrap();
    TermCertificate {
        change,
        approvals: vec![TermApproval {
            signer: 0,
            signature: alloy_primitives::FixedBytes::from_slice(&signature.to_bytes()),
            webauthn: None,
        }],
    }
}

/// Native state holding an operator policy of `operator` alone, with the
/// proofs of that record and of the absence of `POLICY`.
fn administered_state(operator: &SigningKey) -> (B256, RecordProof, RecordProof) {
    let state = AdministrationState {
        policy: OperatorPolicy {
            threshold: 1,
            keys: vec![hex::encode(operator.verifying_key().to_sec1_bytes())],
        },
        sequence: 0,
        membership_policy: None,
    };
    let record = borsh::to_vec(&state).unwrap();
    std::thread::spawn(move || {
        use commonware_glue::stateful::db::DatabaseSet;
        use commonware_runtime::{buffer::paged::CacheRef, tokio, Runner as _, Supervisor as _};
        use commonware_utils::{NZUsize, NZU16};
        use vera_backend::native::{self, NativeStateSet};

        let directory = tempfile::tempdir().unwrap();
        tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
            |context| async move {
                let cache = CacheRef::new(NZU16!(4084), NZUsize!(64));
                let set = NativeStateSet::init(
                    context.child("proof"),
                    native::state_config("proof", cache),
                    None,
                )
                .await;
                let administration = vec![(STATE_KEY.to_vec(), Some(record))];
                set.apply(
                    native::prepare(
                        set.new_batches().await,
                        [vec![], vec![], administration, vec![]],
                    )
                    .await
                    .unwrap(),
                )
                .await;
                let (a, b, h, n) =
                    futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
                let roots = [a.root().0, b.root().0, h.root().0, n.root().0];
                let root = vera_modules::module_state::combine_module_roots(&roots);
                let administration =
                    native::record_proof_at([&a, &b, &h, &n], root, ModuleId::Vera, STATE_KEY)
                        .await
                        .unwrap();
                let policy = native::record_proof_at(
                    [&a, &b, &h, &n],
                    root,
                    ModuleId::Acp,
                    &vera_modules::acp::keys::policy_key(POLICY),
                )
                .await
                .unwrap();
                (root, administration, policy)
            },
        )
    })
    .join()
    .unwrap()
}

fn block(root: B256, height: u64, term: u64, history: u8) -> LightBlock {
    certified(root, height, term, history).0
}

/// A certified block of the deployment and the deployment's consensus key;
/// `history` tells apart blocks at one height.
fn certified(root: B256, height: u64, term: u64, history: u8) -> (LightBlock, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let block = Block {
        context: ConsensusContext {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: ed25519::PrivateKey::from_seed(SEED).public_key(),
            parent: (View::new(height - 1), ConsensusDigest::from([history; 32])),
        },
        parent: BlockId(B256::repeat_byte(history)),
        height,
        ancestry: ancestry(height),
        timestamp,
        term,
        module_state_root: root,
        txs: vec![],
        payload: None,
        native_targets: Default::default(),
        receipt_commitment: B256::ZERO,
    };
    certify(SEED, &block)
}

fn header(light: &LightBlock, term: u64) -> GossipHeader {
    GossipHeader {
        chain_id: 9001,
        height: light.height,
        block_hash: light.block_hash.parse().unwrap(),
        parent_hash: light.parent_hash.parse().unwrap(),
        timestamp: light.timestamp,
        term,
        module_state_root: light.module_state_root.parse().unwrap(),
        tx_count: 0,
        publisher_index: 0,
        signature: vec![],
    }
}

/// What one device serves: its blocks by height, its newest block and its certificate.
struct Device {
    blocks: BTreeMap<u64, LightBlock>,
    certificate: Option<TermCertificate>,
    administration: RecordProof,
    policy: RecordProof,
}

impl Device {
    fn hold(&mut self, light: &LightBlock) {
        self.blocks.insert(light.height, light.clone());
    }
}

struct DeviceTransport {
    device: Arc<RwLock<Device>>,
    headers: parking_lot::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<GossipHeader>>>,
}

impl AcpTransport for DeviceTransport {
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
        _: usize,
    ) -> futures::future::BoxFuture<'_, Result<serde_json::Value, TransportError>> {
        let device = self.device.read();
        let newest = || device.blocks.values().next_back().unwrap().clone();
        let result = match method {
            "vera_getLightBlock" => device
                .blocks
                .get(&params[0].as_u64().unwrap())
                .map(|light| serde_json::to_value(light).unwrap())
                .ok_or(TransportError::Rpc {
                    method,
                    code: -32001,
                    message: "revision not found".into(),
                }),
            "vera_getTermCertificate" => Ok(serde_json::to_value(&device.certificate).unwrap()),
            "vera_getCurrentRecordProof" => {
                let record = if params[0] == serde_json::to_value(ModuleId::Vera).unwrap() {
                    device.administration.clone()
                } else {
                    device.policy.clone()
                };
                Ok(serde_json::to_value(vera_permission::RecordResponse {
                    revision: newest(),
                    record,
                })
                .unwrap())
            }
            method => panic!("unexpected RPC: {method}"),
        };
        Box::pin(async move { result })
    }

    fn subscribe_headers(
        &self,
    ) -> futures::future::BoxFuture<'_, Result<HeaderStream, TransportError>> {
        let headers = self.headers.lock().take();
        Box::pin(async move {
            let headers =
                headers.ok_or_else(|| TransportError::other("headers already subscribed"))?;
            Ok(futures::stream::unfold(headers, |mut headers| async move {
                headers.recv().await.map(|header| (Ok(header), headers))
            })
            .boxed())
        })
    }
}

struct Deployment {
    root: B256,
    operator: SigningKey,
    device: Arc<RwLock<Device>>,
    headers: tokio::sync::mpsc::UnboundedSender<GossipHeader>,
    transport: Arc<DeviceTransport>,
    key: String,
}

impl Deployment {
    fn new() -> Self {
        let operator = operator(11);
        let (root, administration, policy) = administered_state(&operator);
        let device = Arc::new(RwLock::new(Device {
            blocks: BTreeMap::new(),
            certificate: None,
            administration,
            policy,
        }));
        let (headers, receive) = tokio::sync::mpsc::unbounded_channel();
        let transport = Arc::new(DeviceTransport {
            device: device.clone(),
            headers: parking_lot::Mutex::new(Some(receive)),
        });
        let (_, key) = certified(root, 1, 0, 3);
        Self {
            root,
            operator,
            device,
            headers,
            transport,
            key,
        }
    }

    fn client(&self) -> AcpLightClient {
        AcpLightClient::for_deployment(
            self.transport.clone(),
            &self.key,
            GENESIS,
            10,
            FreshnessPolicy::default(),
        )
        .unwrap()
    }

    /// The device finalizes a block and announces it.
    fn finalize(&self, height: u64, term: u64, history: u8) -> LightBlock {
        let light = block(self.root, height, term, history);
        self.device.write().hold(&light);
        self.headers.send(header(&light, term)).unwrap();
        light
    }
}

async fn reaches(client: &AcpLightClient, light: &LightBlock, term: u64) {
    let wanted: B256 = light.block_hash.parse().unwrap();
    for _ in 0..200 {
        if client
            .header_chain()
            .state()
            .is_some_and(|state| state.block_hash == wanted)
        {
            assert_eq!(client.header_chain().state().unwrap().term, term);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "client stayed at {:?} instead of reaching height {}",
        client.header_chain().state(),
        light.height
    );
}

async fn stays(client: &AcpLightClient, light: &LightBlock) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        client.header_chain().state().unwrap().block_hash,
        light.block_hash.parse::<B256>().unwrap()
    );
}

#[tokio::test]
async fn a_takeover_moves_the_client_below_the_height_it_had_reached() {
    let deployment = Deployment::new();
    let client = deployment.client();
    let cut = deployment.finalize(10, 0, 3);
    deployment.finalize(11, 0, 3);
    let replaced = deployment.finalize(12, 0, 3);
    reaches(&client, &replaced, 0).await;

    // Another device takes over at block 10. The client now reaches that device.
    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    let first = deployment.finalize(11, 1, 4);
    reaches(&client, &first, 1).await;
    assert_eq!(
        client.header_chain().voided(),
        Some(Voided {
            revision: acp_light_client::SyncState {
                height: 12,
                timestamp: replaced.timestamp,
                term: 0,
                module_state_root: deployment.root,
                block_hash: replaced.block_hash.parse().unwrap(),
            },
            term: 1,
        })
    );
    assert_eq!(
        client
            .header_chain()
            .term_certificate()
            .unwrap()
            .change
            .term,
        1
    );

    // The replaced device still finalizes, and its blocks still verify.
    deployment.finalize(13, 0, 3);
    stays(&client, &first).await;
    let next = deployment.finalize(12, 1, 4);
    reaches(&client, &next, 1).await;
}

#[tokio::test]
async fn a_term_is_followed_only_under_a_certificate_of_the_operators() {
    let deployment = Deployment::new();
    let client = deployment.client();
    let cut = deployment.finalize(10, 0, 3);
    reaches(&client, &cut, 0).await;

    // No certificate, one a stranger signed, one of another deployment, one of another term.
    deployment.finalize(11, 1, 4);
    stays(&client, &cut).await;

    deployment.device.write().certificate = Some(certificate(1, &cut, &operator(12)));
    deployment.finalize(12, 1, 4);
    stays(&client, &cut).await;

    let mut foreign = certificate(1, &cut, &deployment.operator);
    foreign.change.genesis_id = B256::repeat_byte(8);
    deployment.device.write().certificate = Some(foreign);
    deployment.finalize(13, 1, 4);
    stays(&client, &cut).await;

    deployment.device.write().certificate = Some(certificate(2, &cut, &deployment.operator));
    deployment.finalize(14, 1, 4);
    stays(&client, &cut).await;
    assert!(client.header_chain().term_certificate().is_none());

    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    let followed = deployment.finalize(15, 1, 4);
    reaches(&client, &followed, 1).await;
    assert_eq!(client.header_chain().voided(), None);
}

#[tokio::test]
async fn a_client_without_the_deployment_identifier_follows_no_later_term() {
    let deployment = Deployment::new();
    let client = AcpLightClient::with_transport(
        deployment.transport.clone(),
        &deployment.key,
        10,
        FreshnessPolicy::default(),
    )
    .unwrap();
    let cut = deployment.finalize(10, 0, 3);
    reaches(&client, &cut, 0).await;

    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    deployment.finalize(11, 1, 4);
    stays(&client, &cut).await;
}

#[tokio::test]
async fn a_read_served_in_a_later_term_is_accepted_under_its_certificate() {
    let deployment = Deployment::new();
    let client = deployment.client();
    let cut = deployment.finalize(10, 0, 3);
    reaches(&client, &cut, 0).await;

    // A handover: the successor builds on the block the client holds. No header arrives.
    let successor = block(deployment.root, 11, 1, 4);
    deployment.device.write().hold(&successor);
    let error = client.read_policy(POLICY).await.unwrap_err();
    assert_eq!(error.to_string(), "node holds no certificate of term 1");
    stays(&client, &cut).await;

    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    assert!(client.read_policy(POLICY).await.unwrap().value.is_none());
    let state = client.header_chain().state().unwrap();
    assert_eq!((state.height, state.term), (11, 1));
    assert_eq!(client.header_chain().voided(), None);
}

#[tokio::test]
async fn a_client_whose_history_left_the_holders_below_the_cut_is_told() {
    // The device that keeps the deployment holds another block at the client's
    // height, or none it can show: it took its state from a snapshot above it.
    for holds_another in [true, false] {
        let deployment = Deployment::new();
        let client = deployment.client();
        let alone = deployment.finalize(9, 0, 5);
        reaches(&client, &alone, 0).await;

        let cut = block(deployment.root, 10, 0, 3);
        {
            let mut device = deployment.device.write();
            device.blocks.clear();
            if holds_another {
                device.hold(&block(deployment.root, 9, 0, 3));
            }
            device.hold(&cut);
            device.certificate = Some(certificate(1, &cut, &deployment.operator));
        }
        let first = deployment.finalize(11, 1, 3);
        reaches(&client, &first, 1).await;
        let voided = client.header_chain().voided().unwrap();
        assert_eq!(
            (voided.revision.block_hash, voided.term),
            (alone.block_hash.parse().unwrap(), 1)
        );
    }
}

#[tokio::test]
async fn a_client_on_the_holders_history_below_the_cut_keeps_its_revision() {
    let deployment = Deployment::new();
    let client = deployment.client();
    let shared = deployment.finalize(9, 0, 3);
    reaches(&client, &shared, 0).await;

    let cut = block(deployment.root, 10, 0, 3);
    deployment.device.write().hold(&cut);
    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    let first = deployment.finalize(11, 1, 3);
    reaches(&client, &first, 1).await;
    assert_eq!(client.header_chain().voided(), None);
}

#[tokio::test]
async fn a_header_must_carry_the_term_of_its_certified_block() {
    let deployment = Deployment::new();
    let client = deployment.client();
    let cut = deployment.finalize(10, 0, 3);
    reaches(&client, &cut, 0).await;

    deployment.device.write().certificate = Some(certificate(1, &cut, &deployment.operator));
    let successor = block(deployment.root, 11, 1, 4);
    deployment.device.write().hold(&successor);
    for claimed in [0, 2] {
        deployment
            .headers
            .send(header(&successor, claimed))
            .unwrap();
    }
    stays(&client, &cut).await;
    assert!(client.header_chain().term_certificate().is_none());

    deployment.headers.send(header(&successor, 1)).unwrap();
    reaches(&client, &successor, 1).await;
}
