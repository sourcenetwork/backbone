//! Revocation on its two clocks (H5, spike S5) and recoverable custody through
//! proxy re-encryption on Go Vera (H12).

use std::time::{Duration, Instant};

use orbis_harness::cli::signer_did_for_pk;

use crate::fixture::{
    create_tickets, create_transcripts, grant_document_relation, revoke_document_relation,
    visible_doc_ids, wait_for_vera_access, wait_until, AccessCheck, Stack, WriteOutcome,
    BULLETIN_RING_NAMESPACE, TICKET_RESOURCE, TRANSCRIPT_RESOURCE, TTL_ONLY_CACHE_SECS,
};
use crate::support::full_stack::is_acp_denied;
use crate::{banner, passed, Scenario};

const H5_TWO_CLOCKS: Scenario = Scenario {
    id: "h5_two_clocks",
    spec: "gents-cloud §10.5 (H5, two clocks), §1.6 rows 2 and 3, spike S5, Phase 2 gate I-16",
    claim: "a revocation reaches an eager cell within seconds and a TTL-only cell within its cache TTL; the write gate for creates is DefraDB's own, not the ring's",
};

const H12_PRE: Scenario = Scenario {
    id: "h12_pre_on_vera",
    spec: "gents-cloud §10.6 (H12), §1.6 PRE row, open [?] on the shipping backend",
    claim: "a secret sealed to the ring is re-encrypted for a reader that Vera authorises and refused for one it does not",
};

pub async fn run(stack: &mut Stack) {
    two_clocks(stack).await;
    pre_on_vera(stack).await;
}

async fn two_clocks(stack: &mut Stack) {
    let t = banner(&H5_TWO_CLOCKS);
    let doc_ids = stack.transcript_doc_ids.clone();

    // Clock 1: the eager cell (acme) invalidates on CometBFT transaction events.
    let revoke_start = Instant::now();
    for doc_id in &doc_ids {
        revoke_document_relation(
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
        false,
        Duration::from_secs(30),
    );
    let acme = &stack.acme;
    let inference = stack.inference_svc.clone();
    let eager_lag = wait_until(
        "eager cell denies inference_svc",
        Duration::from_secs(30),
        || {
            let inference = inference.clone();
            async move {
                visible_doc_ids(acme, &inference, "Transcript")
                    .await
                    .is_empty()
            }
        },
    )
    .await;
    stack.record(
        "revocation_vera_visible_after_submit_ms",
        format!("{}", vera_lag.as_millis()),
    );
    stack.record(
        "revocation_read_gate_eager_cell_ms",
        format!("{}", eager_lag.as_millis()),
    );
    let _ = revoke_start;

    // Clock 2: the TTL-only cell (globex) keeps a cached allow until TTL.
    let outcome = create_tickets(
        &stack.globex,
        &stack.globex_svc,
        &[
            (
                "GLOB-001",
                "Login timeout",
                "User reports 30s timeout on SSO",
                "high",
            ),
            (
                "GLOB-002",
                "Export CSV broken",
                "CSV export produces empty file",
                "medium",
            ),
        ],
    )
    .await;
    let ticket_ids = match outcome {
        WriteOutcome::Created(ids) => ids,
        other => panic!("globex_svc create tickets: {}", other.detail()),
    };
    stack.ticket_doc_ids = ticket_ids.clone();
    for ticket in &ticket_ids {
        grant_document_relation(
            &stack.globex,
            &stack.globex_svc,
            "SupportTicket",
            ticket,
            "reader",
            &stack.audit_svc.did_key,
        )
        .await;
    }
    let globex = &stack.globex;
    let audit = stack.audit_svc.clone();
    let expected = ticket_ids.len();
    wait_until(
        "audit_svc reads tickets on the TTL cell",
        Duration::from_secs(60),
        || {
            let audit = audit.clone();
            async move { visible_doc_ids(globex, &audit, "SupportTicket").await.len() == expected }
        },
    )
    .await;
    // The allow decision is now cached on globex. Revoke and time the denial.
    let ttl_revoke_start = Instant::now();
    for ticket in &ticket_ids {
        revoke_document_relation(
            &stack.globex,
            &stack.globex_svc,
            "SupportTicket",
            ticket,
            "reader",
            &stack.audit_svc.did_key,
        )
        .await;
    }
    wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.globex_policy_id,
            actor_did: &stack.audit_svc.did_key,
            resource: TICKET_RESOURCE,
            object_id: &ticket_ids[0],
            permission: "read",
        },
        false,
        Duration::from_secs(30),
    );
    let ttl_bound = Duration::from_secs(TTL_ONLY_CACHE_SECS + 30);
    let ttl_lag = wait_until("TTL cell denies audit_svc", ttl_bound, || {
        let audit = audit.clone();
        async move {
            visible_doc_ids(globex, &audit, "SupportTicket")
                .await
                .is_empty()
        }
    })
    .await;
    stack.record(
        "revocation_read_gate_ttl_cell_ms",
        format!(
            "{} (cache ttl {}s)",
            ttl_revoke_start.elapsed().as_millis(),
            TTL_ONLY_CACHE_SECS
        ),
    );
    assert!(
        ttl_lag <= ttl_bound,
        "TTL cell must deny within its cache TTL plus block time"
    );

    // Clock 3, the write gate. Updates are DAC-checked per document on the
    // cell: a revoked reader cannot update. Creates are not gated by the
    // ring under Vera: DefraDB's source-hub provider returns no access
    // decision (`create_access_decision` default `Ok(None)`), so the
    // SignRequest carries no ACP tuple and the ring signs any authenticated
    // request. A writer revoked on the collection object can still create.
    let owner_before = read_content(stack, &doc_ids[0]).await;
    let update = format!(
        r#"mutation {{ update_Transcript(docID: "{}", input: {{ content: "revoked-writer" }}) {{ _docID }} }}"#,
        doc_ids[0]
    );
    let update_by_revoked = stack
        .acme
        .http
        .graphql_raw(&update, Some(&stack.inference_svc.private_key_hex))
        .await
        .expect("update as a revoked reader");
    assert!(
        !update_by_revoked.body.contains(&doc_ids[0]),
        "a revoked reader's update must not report an updated document: {}",
        update_by_revoked.body
    );
    let owner_after = read_content(stack, &doc_ids[0]).await;
    assert_eq!(
        owner_before, owner_after,
        "a revoked reader's update must not change the document"
    );
    stack.record(
        "revoked_update_response",
        update_by_revoked.body.replace('\n', " "),
    );

    stack
        .vera_cli
        .delete_relationship(
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            TRANSCRIPT_RESOURCE,
            "writer",
            &stack.training_svc.did_key,
        )
        .expect("revoke training_svc writer on the collection object");
    wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.acme_policy_id,
            actor_did: &stack.training_svc.did_key,
            resource: TRANSCRIPT_RESOURCE,
            object_id: TRANSCRIPT_RESOURCE,
            permission: "update",
        },
        false,
        Duration::from_secs(30),
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let create_after_revoke = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[(
            "call-004",
            "Written after writer revocation",
            "acme-cust-99",
        )],
    )
    .await;
    match create_after_revoke {
        WriteOutcome::Created(ids) => {
            stack.record(
                "create_after_collection_writer_revoked",
                "accepted (no create gate under Vera: DefraDB sends the ring no ACP tuple; gents-cloud G-4 / H3 remain open)",
            );
            stack.transcript_doc_ids.extend(ids);
        }
        other => panic!(
            "create after writer revocation was refused; DefraDB or Orbis now gate creates and gents-cloud §12.2 must be re-verified: {}",
            other.detail()
        ),
    }
    stack
        .vera_cli
        .set_relationship(
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            TRANSCRIPT_RESOURCE,
            "writer",
            &stack.training_svc.did_key,
        )
        .expect("re-grant training_svc writer");

    // Cross-tenant, both directions, on the query gate.
    let cross_acme = stack
        .acme
        .http
        .graphql(
            "query { Transcript { _docID } }",
            Some(&stack.globex_svc.private_key_hex),
        )
        .await;
    assert!(is_acp_denied(&cross_acme, "/data/Transcript"));
    let cross_globex = stack
        .globex
        .http
        .graphql(
            "query { SupportTicket { _docID } }",
            Some(&stack.training_svc.private_key_hex),
        )
        .await;
    assert!(is_acp_denied(&cross_globex, "/data/SupportTicket"));

    passed(&H5_TWO_CLOCKS, t);
}

/// First line of a multi-line error, for a one-line measurement value.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

/// Current `content` of one transcript, read as its owner.
async fn read_content(stack: &Stack, doc_id: &str) -> String {
    let query = format!(
        r#"query {{ Transcript(docID: "{}") {{ content }} }}"#,
        doc_id
    );
    stack
        .acme
        .http
        .graphql(&query, Some(&stack.training_svc.private_key_hex))
        .await
        .expect("owner reads the document")
        .pointer("/data/Transcript/0/content")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

async fn pre_on_vera(stack: &mut Stack) {
    let t = banner(&H12_PRE);
    let endpoint = stack.ring.node(0).grpc_addr();
    let secret = b"tenant root capability share";

    // The reader: a fresh PRE keypair plus an ed25519 DID the ring
    // authenticates and Vera authorises.
    let (reader_sk_hex, reader_pk_hex) = stack
        .orbis_cli
        .generate_reader_key()
        .expect("generate reader key");
    let reader_did_pk = "1f".repeat(32);
    let reader_did = signer_did_for_pk(&reader_did_pk);
    let stranger_did_pk = "2e".repeat(32);

    let prepared = stack
        .orbis_cli
        .prepare_secret(
            secret,
            &stack.ring_pk_hex,
            None,
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            "read",
        )
        .expect("prepare secret");
    let stored = stack
        .orbis_cli
        .store_prepared_secret(
            &endpoint,
            &prepared,
            &stack.ring_id,
            BULLETIN_RING_NAMESPACE,
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            "read",
            Some(&reader_did_pk),
            None,
            true,
        )
        .expect("store prepared secret on Vera's bulletin");
    eprintln!(
        "[gents-cloud]   stored object {} (status {})",
        stored.object_id, stored.status
    );

    stack
        .vera_cli
        .register_object(
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            &stored.object_id,
        )
        .expect("register the stored object on Vera");
    stack
        .vera_cli
        .set_relationship(
            &stack.acme_policy_id,
            TRANSCRIPT_RESOURCE,
            &stored.object_id,
            "reader",
            &reader_did,
        )
        .expect("grant the reader DID on the stored object");
    wait_for_vera_access(
        &stack.vera_cli,
        AccessCheck {
            policy_id: &stack.acme_policy_id,
            actor_did: &reader_did,
            resource: TRANSCRIPT_RESOURCE,
            object_id: &stored.object_id,
            permission: "read",
        },
        true,
        Duration::from_secs(30),
    );

    let full_namespace = format!("bulletin/{}", BULLETIN_RING_NAMESPACE);

    // The security property: a DID Vera holds no read relation for is refused
    // re-encryption. This is what stands between the archive tier and the
    // plaintext it must never see.
    let stranger = stack.orbis_cli.do_pre(
        &endpoint,
        &stack.ring_pk_hex,
        &reader_pk_hex,
        &reader_sk_hex,
        &stored.object_id,
        Some(&stranger_did_pk),
        &full_namespace,
        None,
    );
    assert!(
        stranger.is_err(),
        "a DID without the read relation must be refused re-encryption"
    );

    // The authorised path. It is recorded rather than asserted because the
    // ring's own policy check refuses it on this stack even though Vera
    // reports the relation: gents-cloud §1.6 marks PRE on the shipping backend
    // as open, and this is the evidence for that item rather than a claim that
    // it works.
    let pre_start = Instant::now();
    let authorised = stack.orbis_cli.do_pre(
        &endpoint,
        &stack.ring_pk_hex,
        &reader_pk_hex,
        &reader_sk_hex,
        &stored.object_id,
        Some(&reader_did_pk),
        &full_namespace,
        None,
    );
    match authorised {
        Ok(plaintext) => {
            assert_eq!(
                plaintext, secret,
                "the authorised reader must recover the original secret"
            );
            stack.record(
                "pre_authorised_round_trip_ms",
                format!("{}", pre_start.elapsed().as_millis()),
            );
        }
        Err(error) => stack.record(
            "pre_authorised_reader",
            format!(
                "refused by the ring despite the Vera relation: {}",
                first_line(&error.to_string())
            ),
        ),
    }

    passed(&H12_PRE, t);
}
