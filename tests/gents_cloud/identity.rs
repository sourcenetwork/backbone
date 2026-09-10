//! Identity and access scenarios: the node-identity shortcut H1 exists to
//! remove, absence-versus-denial (I-26), and the grant granularity asymmetry
//! recorded in gents-cloud §1.6.

use std::time::{Duration, Instant};

use crate::fixture::{
    create_transcripts, grant_document_relation, visible_doc_ids, wait_for_vera_access, wait_until,
    AccessCheck, Stack, WriteOutcome, TRANSCRIPT_RESOURCE,
};
use crate::support::full_stack::{is_acp_denied, poll_replicated_doc_ids};
use crate::{banner, passed, Scenario};

const H1_SHORTCUT: Scenario = Scenario {
    id: "h1_node_identity_no_privileged_read",
    spec: "gents-cloud §1.2 row 2 [V], H1 §10.2, I-2, spike S6, readiness C4",
    claim: "on a cell whose document ACP is Vera, the cell's own node identity reads nothing it holds no relation on, so the DAC full-access shortcut H1 exists to remove is not reachable here; the document owner reads its own documents",
};

const I26_PAIRING: Scenario = Scenario {
    id: "i26_absence_denial_indistinguishable",
    spec: "gents-cloud §11.6, I-26, Phase 2 gate",
    claim: "reading a forbidden document and reading a non-existent document return the same status and the same body",
};

const GRANT_ASYMMETRY: Scenario = Scenario {
    id: "grant_asymmetry",
    spec: "gents-cloud §1.6 (asymmetric grant granularity), §11.4 revocation cost",
    claim: "a reader relation on the collection-level object grants nothing on documents; read grants are per document",
};

pub async fn run(stack: &mut Stack) {
    node_identity_shortcut(stack).await;
    absence_denial_pairing(stack).await;
    grant_asymmetry(stack).await;
}

async fn node_identity_shortcut(stack: &mut Stack) {
    let t = banner(&H1_SHORTCUT);

    // training_svc holds writer on the collection object and creates three
    // transcripts; the acme cell registers each with training_svc as owner.
    let write_start = Instant::now();
    let outcome = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[
            (
                "call-001",
                "Customer asked about billing cycle",
                "acme-cust-42",
            ),
            ("call-002", "Password reset request handled", "acme-cust-17"),
            (
                "call-003",
                "Product return initiated for order 9981",
                "acme-cust-42",
            ),
        ],
    )
    .await;
    let doc_ids = match outcome {
        WriteOutcome::Created(ids) => ids,
        other => panic!(
            "training_svc batch create on acme should succeed: {}",
            other.detail()
        ),
    };
    assert_eq!(doc_ids.len(), 3, "three transcripts expected");
    stack.record(
        "ring_signed_batch_create_3_docs_ms",
        format!("{}", write_start.elapsed().as_millis()),
    );
    let owner = stack
        .vera_cli
        .object_owner(&stack.acme_policy_id, TRANSCRIPT_RESOURCE, &doc_ids[0])
        .expect("object-owner query");
    assert_eq!(
        owner.as_deref(),
        Some(stack.training_svc.did_key.as_str()),
        "the creating DID must be registered on Vera as the document owner"
    );
    stack.transcript_doc_ids = doc_ids.clone();

    // The replica holds the same documents; it evaluates the same Vera state.
    poll_replicated_doc_ids(
        &stack.platform.http,
        "Transcript",
        &stack.training_svc.private_key_hex,
        "/data/Transcript",
        &doc_ids,
        "platform replica",
        Duration::from_secs(60),
    )
    .await;

    // (1) The document owner reads its own documents. Vera's ACP transformer
    // adds the `owner` relation to the creator at registration, which is what
    // makes this hold with no explicit grant.
    let owned = visible_doc_ids(&stack.acme, &stack.training_svc, "Transcript").await;
    assert_eq!(
        sorted(&owned),
        sorted(&doc_ids),
        "the creating identity must read the documents it owns"
    );

    // (2) The cell's own node identity reads nothing. Upstream DefraDB grants
    // full DAC access when the request identity equals the configured node
    // identity, which is the hazard H1 is built to remove. With document ACP
    // on Vera that context carries no node identity, so the shortcut is not
    // reachable from a request path on this deployment and the node DID is an
    // ordinary actor: it holds no relation, so it reads nothing.
    let seen = visible_doc_ids(&stack.acme, &stack.acme_node_key, "Transcript").await;
    assert!(
        seen.is_empty(),
        "the node identity must hold no privileged read on its own cell, saw {:?}",
        seen
    );
    let vera_says = stack
        .vera_cli
        .verify_access(
            &stack.acme_policy_id,
            &stack.acme_node_key.did_key,
            TRANSCRIPT_RESOURCE,
            &doc_ids[0],
            "read",
        )
        .expect("verify-access-request");
    assert!(
        !vera_says,
        "Vera must hold no read relation for the node DID"
    );

    // (3) The same key on another cell is equally powerless.
    let cross = stack
        .platform
        .http
        .graphql(
            "query { Transcript { _docID } }",
            Some(&stack.acme_node_key.private_key_hex),
        )
        .await;
    assert!(
        is_acp_denied(&cross, "/data/Transcript"),
        "acme's node DID must hold no access on the platform cell"
    );

    // (4) No token: anonymous, denied on a protected collection (readiness C4).
    let anon = stack
        .acme
        .http
        .graphql("query { Transcript { _docID } }", None)
        .await;
    assert!(
        is_acp_denied(&anon, "/data/Transcript"),
        "an anonymous request must see no protected documents"
    );

    passed(&H1_SHORTCUT, t);
}

async fn absence_denial_pairing(stack: &mut Stack) {
    let t = banner(&I26_PAIRING);
    let forbidden = stack.transcript_doc_ids[0].clone();
    let absent = "bae-00000000-0000-0000-0000-000000000000";

    // globex_svc holds no relation under the acme policy.
    let mut responses = Vec::new();
    for (label, doc_id) in [("forbidden", forbidden.as_str()), ("absent", absent)] {
        let query = format!(
            r#"query {{ Transcript(docID: "{}") {{ _docID call_id content }} }}"#,
            doc_id
        );
        let start = Instant::now();
        let raw = stack
            .acme
            .http
            .graphql_raw(&query, Some(&stack.globex_svc.private_key_hex))
            .await
            .expect("raw graphql");
        let elapsed = start.elapsed();
        eprintln!(
            "[gents-cloud]   {:<9} status={} {:>4}ms body={}",
            label,
            raw.status,
            elapsed.as_millis(),
            raw.body
        );
        stack.record(
            &format!("i26_{}_read_ms", label),
            format!("{}", elapsed.as_millis()),
        );
        responses.push(raw);
    }
    assert_eq!(
        responses[0].status, responses[1].status,
        "forbidden and absent reads must share one status"
    );
    assert_eq!(
        responses[0].body, responses[1].body,
        "forbidden and absent reads must share one body"
    );
    assert!(
        !responses[0].body.contains(&forbidden),
        "the forbidden document id must not be echoed"
    );

    passed(&I26_PAIRING, t);
}

async fn grant_asymmetry(stack: &mut Stack) {
    let t = banner(&GRANT_ASYMMETRY);
    let doc_ids = stack.transcript_doc_ids.clone();

    let before = stack
        .acme
        .http
        .graphql(
            "query { Transcript { _docID } }",
            Some(&stack.inference_svc.private_key_hex),
        )
        .await;
    assert!(
        is_acp_denied(&before, "/data/Transcript"),
        "inference_svc must be denied before any grant"
    );

    // A reader relation on the collection-level object.
    stack
        .vera_cli
        .set_relationship(
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            TRANSCRIPT_RESOURCE,
            "reader",
            &stack.inference_svc.did_key,
        )
        .expect("grant reader on the collection object");
    wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.acme_policy_id,
            actor_did: &stack.inference_svc.did_key,
            resource: TRANSCRIPT_RESOURCE,
            object_id: TRANSCRIPT_RESOURCE,
            permission: "read",
        },
        true,
        Duration::from_secs(30),
    );
    for doc_id in &doc_ids {
        let on_doc = stack
            .vera_cli
            .verify_access(
                &stack.acme_policy_id,
                &stack.inference_svc.did_key,
                TRANSCRIPT_RESOURCE,
                doc_id,
                "read",
            )
            .expect("verify-access-request");
        assert!(
            !on_doc,
            "Vera: a relation on the collection object must not grant read on document {}",
            doc_id
        );
    }
    // Give the eager cell a full invalidation cycle, then confirm it agrees.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after_collection_grant = stack
        .acme
        .http
        .graphql(
            "query { Transcript { _docID } }",
            Some(&stack.inference_svc.private_key_hex),
        )
        .await;
    assert!(
        is_acp_denied(&after_collection_grant, "/data/Transcript"),
        "the cell must still deny: collection-level reader is not a document grant"
    );

    // Per-document grants: one Vera transaction each, the cost §11.4 names.
    let grant_start = Instant::now();
    for doc_id in &doc_ids {
        grant_document_relation(
            &stack.acme,
            &stack.training_svc,
            "Transcript",
            doc_id,
            "reader",
            &stack.inference_svc.did_key,
        )
        .await;
    }
    let vera_lag = wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.acme_policy_id,
            actor_did: &stack.inference_svc.did_key,
            resource: TRANSCRIPT_RESOURCE,
            object_id: &doc_ids[doc_ids.len() - 1],
            permission: "read",
        },
        true,
        Duration::from_secs(30),
    );
    stack.record(
        "per_document_grant_3_docs_to_vera_visible_ms",
        format!("{}", (grant_start.elapsed()).as_millis()),
    );
    let expected = sorted(&doc_ids);
    let acme = &stack.acme;
    let inference = stack.inference_svc.clone();
    let read_lag = wait_until("inference_svc reads on acme", Duration::from_secs(30), || {
        let expected = expected.clone();
        let inference = inference.clone();
        async move { sorted(&visible_doc_ids(acme, &inference, "Transcript").await) == expected }
    })
    .await;
    stack.record(
        "grant_read_gate_eager_cell_lag_after_vera_ms",
        format!(
            "{}",
            read_lag.as_millis().saturating_sub(vera_lag.as_millis())
        ),
    );

    passed(&GRANT_ASYMMETRY, t);
}

fn sorted(ids: &[String]) -> Vec<String> {
    let mut v = ids.to_vec();
    v.sort();
    v
}
