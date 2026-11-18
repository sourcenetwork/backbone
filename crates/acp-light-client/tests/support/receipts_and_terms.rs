use super::*;
use acp_light_client::{ExecutionReceipt, Refusal, RefusalKind, RefusingModule};
use commonware_codec::DecodeExt as _;

const GAS_LIMIT: u64 = 30_000_000;
const TERM: u64 = 3;

fn submission(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn receipts() -> Vec<ExecutionReceipt> {
    vec![
        ExecutionReceipt::new(submission(1), true, 21_000, 21_000, vec![], None),
        ExecutionReceipt::new(submission(2), false, 50_000, 71_000, vec![], None).with_refusal(
            Some(Refusal::new(
                RefusingModule::Acp,
                RefusalKind::Unauthorized,
                "actor may not edit the policy",
            )),
        ),
    ]
}

/// A fixture whose block carries `TERM` and commits `committed` under the v2 receipt encoding,
/// while the node serves `served`.
fn receipt_fixture(committed: &[ExecutionReceipt], served: Vec<ExecutionReceipt>) -> Fixture {
    let mut fixture = fixture(42);
    let mut block = vera_domain::verify_finalized_block(
        &fixture.light,
        &ConsensusPublicKey::decode(commonware_codec::Copying(
            &hex::decode(&fixture.key).unwrap(),
        ))
        .unwrap(),
    )
    .unwrap();
    block.term = TERM;
    block.txs = committed
        .iter()
        .map(|receipt| vera_domain::Tx::new(receipt.tx_hash.to_vec().into()))
        .collect();
    block.receipt_commitment = Some(vera_domain::receipt_commitment(GAS_LIMIT, committed));
    let (light, _) = certify(42, &block);
    fixture.receipts = Some(ReceiptResponse {
        revision: light.clone(),
        gas_limit: GAS_LIMIT,
        receipts: served,
    });
    fixture.light = light;
    fixture
}

#[tokio::test]
async fn a_refused_receipt_is_verified_against_the_v2_commitment() {
    let server = Server::start(receipt_fixture(&receipts(), receipts())).await;
    let client = server.client();

    let verified = client
        .fetch_and_verify_receipt(submission(2))
        .await
        .unwrap()
        .unwrap();
    assert!(!verified.receipt.success());
    let refusal = verified.receipt.refusal.unwrap();
    assert_eq!(
        (refusal.module, refusal.kind),
        (RefusingModule::Acp, RefusalKind::Unauthorized)
    );
    assert_eq!(verified.revision.height, HEIGHT);
    assert_eq!(verified.revision.term, TERM);

    let accepted = client
        .fetch_and_verify_receipt(submission(1))
        .await
        .unwrap()
        .unwrap();
    assert!(accepted.receipt.success() && accepted.receipt.refusal.is_none());

    let error = client
        .fetch_and_verify_receipt(submission(3))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid receipt evidence: requested submission missing"
    );

    server.fixture.write().receipts = None;
    assert!(client
        .fetch_and_verify_receipt(submission(2))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_refusal_message_is_the_nodes_text_but_its_kind_is_committed() {
    let mut reworded = receipts();
    reworded[1] = reworded[1].clone().with_refusal(Some(Refusal::new(
        RefusingModule::Acp,
        RefusalKind::Unauthorized,
        "different wording",
    )));
    let server = Server::start(receipt_fixture(&receipts(), reworded)).await;
    let verified = server
        .client()
        .fetch_and_verify_receipt(submission(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        verified.receipt.refusal.unwrap().message(),
        "different wording"
    );

    let mut changed_kind = receipts();
    changed_kind[1] = changed_kind[1].clone().with_refusal(Some(Refusal::new(
        RefusingModule::Acp,
        RefusalKind::WorkLimitExceeded,
        "actor may not edit the policy",
    )));
    let mut unrefused = receipts();
    unrefused[1] = unrefused[1].clone().with_refusal(None);
    for served in [changed_kind, unrefused] {
        let server = Server::start(receipt_fixture(&receipts(), served)).await;
        let error = server
            .client()
            .fetch_and_verify_receipt(submission(2))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid receipt evidence: receipt commitment"
        );
    }

    let mut refused_success = receipts();
    refused_success[0] = refused_success[0].clone().with_refusal(Some(Refusal::new(
        RefusingModule::Acp,
        RefusalKind::Unauthorized,
        "",
    )));
    let server = Server::start(receipt_fixture(&refused_success, refused_success.clone())).await;
    let error = server
        .client()
        .fetch_and_verify_receipt(submission(1))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid receipt evidence: refusal on a successful receipt"
    );
}

#[tokio::test]
async fn a_header_must_carry_the_term_of_its_certified_block() {
    let fixture = Arc::new(RwLock::new(receipt_fixture(&receipts(), receipts())));
    let (light, key) = {
        let fixture = fixture.read();
        (fixture.light.clone(), fixture.key.clone())
    };
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let transport = Arc::new(FixtureTransport {
        fixture,
        headers: parking_lot::Mutex::new(Some(receive)),
        failure: parking_lot::Mutex::new(None),
    });
    let client =
        AcpLightClient::with_transport(transport, &key, 10, FreshnessPolicy::default()).unwrap();
    let genuine = GossipHeader {
        chain_id: 9001,
        height: HEIGHT,
        block_hash: light.block_hash.parse().unwrap(),
        parent_hash: light.parent_hash.parse().unwrap(),
        timestamp: light.timestamp,
        term: TERM,
        state_root: light.state_root.parse().unwrap(),
        module_state_root: light.module_state_root.parse().unwrap(),
        tx_count: 2,
        publisher_index: 0,
        signature: vec![],
    };
    send.send(GossipHeader {
        term: TERM - 1,
        ..genuine.clone()
    })
    .unwrap();
    assert!(client
        .wait_for_height(HEIGHT, Duration::from_millis(300))
        .await
        .is_err());
    assert!(client.header_chain().state().is_none());

    send.send(genuine).unwrap();
    let state = client
        .wait_for_height(HEIGHT, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(state.term, TERM);
}
