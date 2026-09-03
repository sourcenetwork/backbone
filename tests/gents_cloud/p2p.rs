//! Cross-tenant isolation on the P2P layer: whether two cells that hold the
//! same schema share a gossip topic (spike S8, decisions A-1 and A-2), and what
//! the receiving cell's query gate does with a block that arrived that way
//! (readiness C1, read against Vera rather than Local ACP).

use std::time::Duration;

use crate::fixture::{
    create_transcripts, transcript_schema, visible_doc_ids, wait_until_or_timeout, Stack,
    WriteOutcome, TRANSCRIPT_RESOURCE,
};
use crate::support::full_stack::is_acp_denied;
use crate::{banner, passed, Scenario};

const S8_TOPIC_COLLISION: Scenario = Scenario {
    id: "s8_topic_collision_c1",
    spec: "gents-cloud §11.7 (A-1, A-2), spike S8, readiness C1, I-30",
    claim: "an identical schema and policy give two tenants one collection topic, so topic separation is not automatic; whether a block crosses is recorded, and either way the receiving cell gates reads on Vera",
};

pub async fn run(stack: &mut Stack) {
    topic_collision(stack).await;
}

async fn topic_collision(stack: &mut Stack) {
    let t = banner(&S8_TOPIC_COLLISION);

    // The globex cell registers the acme Transcript schema: same policy id,
    // same SDL, therefore the same collection id and the same topic string.
    stack
        .globex
        .http
        .schema_add(&transcript_schema(&stack.acme_policy_id))
        .await
        .expect("globex registers the same Transcript schema");
    let acme_desc = stack
        .acme
        .cli
        .collection_describe_version("Transcript")
        .expect("describe Transcript on acme");
    let globex_desc = stack
        .globex
        .cli
        .collection_describe_version("Transcript")
        .expect("describe Transcript on globex");
    let acme_id = collection_id(&acme_desc);
    let globex_id = collection_id(&globex_desc);
    assert_eq!(
        acme_id, globex_id,
        "identical schema and policy must derive one collection id (the gossip topic)"
    );
    stack.record("s8_shared_collection_topic", acme_id.clone());

    // Peer the cells and subscribe both to the collection topic. No replicator
    // is installed between them.
    let acme_addr = stack
        .acme
        .cli
        .p2p_info()
        .expect("acme p2p info")
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .expect("acme p2p address")
        .to_string();
    stack
        .globex
        .cli
        .p2p_connect(&[&acme_addr])
        .expect("globex connects to acme");
    stack
        .globex
        .cli
        .p2p_collection_add(&["Transcript"])
        .expect("globex subscribes to Transcript");

    let outcome = create_transcripts(
        &stack.acme,
        &stack.training_svc,
        &[(
            "call-s8",
            "Written on acme while globex shares the topic",
            "acme-cust-8",
        )],
    )
    .await;
    let leaked_id = match outcome {
        WriteOutcome::Created(ids) => ids[0].clone(),
        other => panic!("acme create for S8: {}", other.detail()),
    };
    stack.transcript_doc_ids.push(leaked_id.clone());

    // Does a block actually cross on the shared topic? Wait a bounded window
    // and record what happened either way. A collision is a necessary
    // condition for a leak, not a sufficient one: the source publishes to the
    // collection topic but replicates only to peers it holds a replicator for.
    let globex = &stack.globex;
    let training = stack.training_svc.clone();
    let expected = leaked_id.clone();
    let crossed = wait_until_or_timeout(Duration::from_secs(45), || {
        let training = training.clone();
        let expected = expected.clone();
        async move {
            visible_doc_ids(globex, &training, "Transcript")
                .await
                .contains(&expected)
        }
    })
    .await;
    match crossed {
        Some(elapsed) => stack.record(
            "s8_block_crossed_on_shared_topic_ms",
            format!("{}", elapsed.as_millis()),
        ),
        None => stack.record(
            "s8_block_crossed_on_shared_topic",
            "no: within 45s no block reached the other tenant's cell over the shared topic, \
             with a peer connection and a subscription in place but no replicator",
        ),
    }

    // Whether or not a block crossed, an identity Vera has granted nothing
    // reads nothing on the receiving cell: registration lives on Vera, so a
    // replicated document is gated there rather than being unregistered and
    // therefore public, which is what readiness C1 warns about under Local ACP.
    let stranger = stack
        .globex
        .http
        .graphql(
            "query { Transcript { _docID } }",
            Some(&stack.globex_svc.private_key_hex),
        )
        .await;
    assert!(
        is_acp_denied(&stranger, "/data/Transcript"),
        "a DID with no relation must read nothing on the receiving cell"
    );
    let owner = stack
        .vera_cli
        .object_owner(&stack.acme_policy_id, TRANSCRIPT_RESOURCE, &leaked_id)
        .expect("object owner on Vera");
    assert_eq!(
        owner.as_deref(),
        Some(stack.training_svc.did_key.as_str()),
        "the document must be registered on Vera, which is what gates it on any cell"
    );
    stack.record(
        "c1_registration_is_chain_side",
        "yes (a replicated document stays registered on Vera, so the receiving cell gates it)",
    );

    passed(&S8_TOPIC_COLLISION, t);
}

fn collection_id(describe: &serde_json::Value) -> String {
    describe
        .get("CollectionID")
        .or_else(|| describe.get("collection_id"))
        .or_else(|| describe.get("ID"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("collection describe has no collection id: {}", describe))
        .to_string()
}
