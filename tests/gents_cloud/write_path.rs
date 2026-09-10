//! The write path: the ring's ACP gate as a mechanism (H3), the ring below
//! threshold (degradation rung L8), the cost of a threshold signature (spike
//! S7), and the account-funding failure mode gents-cloud §1.6 names.

use std::time::{Duration, Instant};

use orbis_harness::cli::signer_did_for_pk;
use orbis_harness::cli::types::SignAcpFields;

use crate::fixture::{
    create_transcripts, grant_document_relation, transcript_schema, visible_doc_ids,
    wait_for_vera_access, AccessCheck, CellSpec, Invalidation, Stack, WriteOutcome,
    TRANSCRIPT_RESOURCE,
};
use crate::{banner, passed, Scenario};

const H3_RING_GATE: Scenario = Scenario {
    id: "h3_ring_gate_mechanism",
    spec: "gents-cloud §12.2 (H3), §1.6 row 2, spike S7 [?] on what the ring checks",
    claim: "given an ACP tuple, the ring refuses to sign for a DID Vera does not authorise and signs for one it does; DefraDB never supplies that tuple under Vera",
};

const L8_BELOW_THRESHOLD: Scenario = Scenario {
    id: "l8_ring_below_threshold",
    spec: "gents-cloud §24 rung L8, §22.4, decision 43",
    claim: "with fewer than T ring members alive a write is refused and no document appears; the ring recovers and the write succeeds",
};

const S7_SIGNED_COST: Scenario = Scenario {
    id: "s7_signed_write_cost",
    spec: "gents-cloud §12.3 cost, spike S7, §19.1 'ring round trip: to be measured'",
    claim: "the ring round trip per create, measured against an unsigned cell on the same Vera",
};

const DRY_ACCOUNT: Scenario = Scenario {
    id: "dry_account",
    spec: "gents-cloud §1.6 (a cell that cannot write because its account is dry), §1.2 (unregistered means public), §24",
    claim: "a cell whose Vera account holds no funds fails the create at registration, leaves the document locally committed and therefore public, and works once funded",
};

pub async fn run(stack: &mut Stack) {
    ring_gate_mechanism(stack).await;
    below_threshold(stack).await;
    signed_write_cost(stack).await;
    dry_account(stack).await;
}

async fn ring_gate_mechanism(stack: &mut Stack) {
    let t = banner(&H3_RING_GATE);
    let endpoint = stack.ring.node(0).grpc_addr();
    let doc_id = stack.transcript_doc_ids[0].clone();
    let message_hex = hex::encode(b"gents-cloud write");

    let granted_pk = "3d".repeat(32);
    let granted_did = signer_did_for_pk(&granted_pk);
    let stranger_pk = "4c".repeat(32);
    let acp = SignAcpFields {
        policy_id: stack.acme_policy_id.clone(),
        resource: TRANSCRIPT_RESOURCE.to_string(),
        object_id: doc_id.clone(),
        permission: "read".to_string(),
    };

    let refused = stack.orbis_cli.do_sign(
        &endpoint,
        &stack.ring_id,
        &message_hex,
        Some(&hex::encode(b"acme-corp")),
        Some(&stranger_pk),
        Some(&acp),
    );
    assert!(
        refused.is_err(),
        "the ring must refuse to sign for a DID without the relation"
    );

    grant_document_relation(
        &stack.acme,
        &stack.training_svc,
        "Transcript",
        &doc_id,
        "reader",
        &granted_did,
    )
    .await;
    wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.acme_policy_id,
            actor_did: &granted_did,
            resource: TRANSCRIPT_RESOURCE,
            object_id: &doc_id,
            permission: "read",
        },
        true,
        Duration::from_secs(30),
    );
    let sign_start = Instant::now();
    let signed = stack
        .orbis_cli
        .do_sign(
            &endpoint,
            &stack.ring_id,
            &message_hex,
            Some(&hex::encode(b"acme-corp")),
            Some(&granted_pk),
            Some(&acp),
        )
        .expect("the ring must sign for an authorised DID");
    stack.record(
        "ring_sign_with_vera_acp_check_ms",
        format!("{}", sign_start.elapsed().as_millis()),
    );
    assert!(!signed.signature.is_empty(), "signature must be present");

    // Without any tuple the ring signs for any authenticated caller. This is
    // the request shape DefraDB sends under Vera (see h5_two_clocks).
    let unchecked = stack
        .orbis_cli
        .do_sign(
            &endpoint,
            &stack.ring_id,
            &message_hex,
            Some(&hex::encode(b"acme-corp")),
            Some(&stranger_pk),
            None,
        )
        .expect("the ring signs without an ACP tuple");
    assert!(!unchecked.signature.is_empty());
    stack.record(
        "ring_signs_without_acp_tuple",
        "yes (DefraDB's Vera write path sends none)",
    );

    passed(&H3_RING_GATE, t);
}

async fn below_threshold(stack: &mut Stack) {
    let t = banner(&L8_BELOW_THRESHOLD);
    let before = visible_doc_ids(&stack.acme, &stack.training_svc, "Transcript").await;

    // T=2 of N=3: with two members down the coordinator cannot reach threshold.
    stack.ring.node_mut(1).kill();
    stack.ring.node_mut(2).kill();
    let refuse_start = Instant::now();
    let outcome = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[(
            "call-l8",
            "Written while the ring is below threshold",
            "acme-cust-1",
        )],
    )
    .await;
    let refusal_ms = refuse_start.elapsed().as_millis();
    assert!(
        outcome.is_refused_or_failed(),
        "a create must not succeed below threshold: {}",
        outcome.detail()
    );
    eprintln!(
        "[gents-cloud]   refused in {}ms: {}",
        refusal_ms,
        outcome.detail()
    );
    stack.record("l8_refusal_latency_ms", format!("{}", refusal_ms));
    let after = visible_doc_ids(&stack.acme, &stack.training_svc, "Transcript").await;
    assert_eq!(
        after.len(),
        before.len(),
        "no document may exist for a write refused below threshold"
    );

    stack
        .ring
        .node_mut(1)
        .restart()
        .expect("restart ring node 1");
    stack
        .ring
        .node_mut(2)
        .restart()
        .expect("restart ring node 2");
    let recover_start = Instant::now();
    stack
        .ring
        .wait_ready(Duration::from_secs(60))
        .await
        .expect("ring members should come back");
    let recovered = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[(
            "call-l8-after",
            "Written after the ring recovered",
            "acme-cust-1",
        )],
    )
    .await;
    let ids = match recovered {
        WriteOutcome::Created(ids) => ids,
        other => panic!("create after ring recovery: {}", other.detail()),
    };
    stack.record(
        "l8_ring_recovery_to_first_signed_write_ms",
        format!("{}", recover_start.elapsed().as_millis()),
    );
    stack.transcript_doc_ids.extend(ids);

    passed(&L8_BELOW_THRESHOLD, t);
}

async fn signed_write_cost(stack: &mut Stack) {
    let t = banner(&S7_SIGNED_COST);
    let unsigned_key = stack.unsigned_node_key.clone();
    let unsigned = stack
        .start_cell(CellSpec {
            name: "unsigned",
            identity: &unsigned_key,
            derivation: "unsigned",
            invalidation: Invalidation::Eager,
            ring_signed: false,
        })
        .await;
    unsigned
        .http
        .schema_add(&transcript_schema(&stack.acme_policy_id))
        .await
        .expect("unsigned cell transcript schema");

    const SAMPLES: usize = 8;
    let mut signed_ms = Vec::with_capacity(SAMPLES);
    let mut unsigned_ms = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let call_id = format!("call-s7-{}", i);
        let start = Instant::now();
        let outcome =
            create_transcripts(&stack.acme, &stack.training_svc, &[(&call_id, "s7", "c")]).await;
        signed_ms.push(start.elapsed().as_millis());
        match outcome {
            WriteOutcome::Created(ids) => stack.transcript_doc_ids.extend(ids),
            other => panic!("signed create {}: {}", i, other.detail()),
        }

        let start = Instant::now();
        let outcome =
            create_transcripts(&unsigned, &stack.training_svc, &[(&call_id, "s7", "c")]).await;
        unsigned_ms.push(start.elapsed().as_millis());
        assert!(
            matches!(outcome, WriteOutcome::Created(_)),
            "unsigned create {}: {}",
            i,
            outcome.detail()
        );
    }
    let signed_p50 = median(&signed_ms);
    let unsigned_p50 = median(&unsigned_ms);
    stack.record("s7_create_p50_ring_signed_ms", format!("{}", signed_p50));
    stack.record("s7_create_p50_unsigned_ms", format!("{}", unsigned_p50));
    stack.record(
        "s7_ring_round_trip_p50_ms",
        format!(
            "{} (signed minus unsigned over {} samples; both are dominated by the Vera \
             registration transaction, so a value at or below zero means the ring round trip \
             is not separable at this sample size, not that it is free)",
            signed_p50 as i128 - unsigned_p50 as i128,
            SAMPLES
        ),
    );
    drop(unsigned);

    passed(&S7_SIGNED_COST, t);
}

async fn dry_account(stack: &mut Stack) {
    let t = banner(&DRY_ACCOUNT);
    let dry_key = stack.dry_node_key.clone();
    let dry = stack
        .start_cell(CellSpec {
            name: "dry",
            identity: &dry_key,
            derivation: "dry",
            invalidation: Invalidation::Eager,
            ring_signed: true,
        })
        .await;
    dry.http
        .schema_add(&transcript_schema(&stack.acme_policy_id))
        .await
        .expect("dry cell transcript schema");

    let outcome = create_transcripts(
        &dry,
        &stack.training_svc,
        &[(
            "call-dry",
            "Written on a cell with an unfunded account",
            "c",
        )],
    )
    .await;
    assert!(
        outcome.is_refused_or_failed(),
        "a cell that cannot pay for the registration transaction must not report success: {}",
        outcome.detail()
    );
    let detail = outcome.detail();
    eprintln!("[gents-cloud]   dry cell refused: {}", detail);
    let lower = detail.to_ascii_lowercase();
    assert!(
        !lower.contains("permission denied") && !lower.contains("not authorized"),
        "the dry-account failure must be distinguishable from an ACP denial"
    );
    stack.record("dry_account_error", first_line(&detail));

    // The write failed at the registration transaction, but the document was
    // already committed locally. DefraDB treats a document with no ACP
    // registration as public (gents-cloud §1.2), so the failed create leaves a
    // document any identity can read on that cell: a partial write that is
    // also an exposure, not merely a lost one.
    let unrelated = visible_doc_ids(&dry, &stack.globex_svc, "Transcript").await;
    assert!(
        !unrelated.is_empty(),
        "expected the locally committed document to remain readable; if this now \
         fails, the create became atomic and this finding is closed"
    );
    stack.record(
        "dry_account_leaves_public_document",
        format!(
            "yes: {} document(s) readable by an unrelated DID after the failed registration",
            unrelated.len()
        ),
    );

    stack
        .vera_cli
        .fund(&dry_key.vera_address)
        .expect("fund the dry cell's account");
    let funded = create_transcripts(
        &dry,
        &stack.training_svc,
        &[("call-dry-funded", "Written after funding", "c")],
    )
    .await;
    assert!(
        matches!(funded, WriteOutcome::Created(_)),
        "create after funding: {}",
        funded.detail()
    );
    drop(dry);

    passed(&DRY_ACCOUNT, t);
}

/// First line of a multi-line error, for a one-line measurement value.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

fn median(samples: &[u128]) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}
