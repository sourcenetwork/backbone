//! Identity persisted before use (I-7): a cell killed with SIGKILL comes back
//! with the same node DID, the same peer identity, its documents, and its ring
//! signer, the shape gents-cloud §17.6 calls a volume restore.

use std::time::{Duration, Instant};

use crate::fixture::{create_transcripts, visible_doc_ids, Stack, WriteOutcome};
use crate::{banner, passed, Scenario};

const I7_KILL9: Scenario = Scenario {
    id: "i7_kill9_identity",
    spec: "gents-cloud I-7, §5.3 'golden kill -9', §17.6 VolumeRestore, §1.2 peerstore row",
    claim: "after SIGKILL and re-ignition on the same data directory the node DID, peer id, and documents are identical and ring-signed writes resume",
};

pub async fn run(stack: &mut Stack) {
    kill9_identity(stack).await;
}

async fn kill9_identity(stack: &mut Stack) {
    let t = banner(&I7_KILL9);
    let identity_before = stack.acme.cli.node_identity().expect("node identity");
    let p2p_before = stack.acme.cli.p2p_info().expect("p2p info");
    let docs_before = visible_doc_ids(&stack.acme, &stack.training_svc, "Transcript").await;
    assert!(
        !docs_before.is_empty(),
        "acme must hold documents before the kill"
    );

    stack.acme.node.process.kill();
    let restart = Instant::now();
    stack
        .acme
        .node
        .process
        .respawn()
        .expect("respawn acme on the same rootdir");
    stack
        .acme
        .node
        .log_tracker
        .wait_for_ready(Duration::from_secs(60))
        .await
        .expect("acme should become ready again");
    let ready_ms = restart.elapsed().as_millis();
    stack.record("i7_kill9_to_ready_ms", format!("{}", ready_ms));

    let identity_after = stack.acme.cli.node_identity().expect("node identity after");
    assert_eq!(
        identity_before, identity_after,
        "node identity must survive SIGKILL"
    );
    let p2p_after = stack.acme.cli.p2p_info().expect("p2p info after");
    assert_eq!(
        p2p_before, p2p_after,
        "peer identity and address must survive SIGKILL"
    );
    let docs_after = visible_doc_ids(&stack.acme, &stack.training_svc, "Transcript").await;
    assert_eq!(
        sorted(&docs_before),
        sorted(&docs_after),
        "documents must survive SIGKILL"
    );

    let outcome = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[("call-i7", "Written after re-ignition", "acme-cust-7")],
    )
    .await;
    match outcome {
        WriteOutcome::Created(ids) => stack.transcript_doc_ids.extend(ids),
        other => panic!("ring-signed create after re-ignition: {}", other.detail()),
    }

    passed(&I7_KILL9, t);
}

fn sorted(ids: &[String]) -> Vec<String> {
    let mut v = ids.to_vec();
    v.sort();
    v
}
