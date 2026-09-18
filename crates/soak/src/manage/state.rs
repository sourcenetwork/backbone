//! State cases: what a mutate leaves in the target's lists, and on the
//! data plane behind them.

use eyre::Result;
use serde_json::{json, Value};

use super::actors::Actor;
use super::cases::{
    expect_status, fail, managed_state, replicator_add, replicator_delete, replicators_for,
    Channel, Verb, COLLECTION,
};
use super::data::{converge, update_user, write_docs};

/// A reply later than this is the correlator's 30 s, not the node's answer.
const CLEAN_MS: u64 = 5_000;

/// A well-formed peer no node in the mesh has.
const ABSENT_PEER: &str =
    "/ip4/127.0.0.1/tcp/1/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo";

pub(super) fn replicator_add_filtered(addr: &str, filters: &Value) -> Value {
    json!({ "Kind": "ReplicatorAdd", "addresses": [addr], "collection_ids": [COLLECTION], "filters": filters })
}

pub(super) fn document_add(id: &str) -> Value {
    json!({ "Kind": "DocumentAdd", "docs": [{ "collection": COLLECTION, "doc_id": id }] })
}

pub(super) fn document_remove(id: &str) -> Value {
    json!({ "Kind": "DocumentRemove", "docs": [{ "collection": COLLECTION, "doc_id": id }] })
}

/// The `filters` of the `Replicators` entry for `peer_id`.
fn filters_for(body: &Value, peer_id: &str) -> Value {
    body["replicators"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"] == peer_id)
        .map_or(Value::Null, |r| r["filters"].clone())
}

/// Every replicator from `source`, dropped (`add` false) or restored.
async fn mesh_from(ch: &mut dyn Channel, relay: usize, source: usize, add: bool) -> Result<()> {
    for j in (0..ch.len()).filter(|j| *j != source) {
        let addr = ch.addr(j);
        let (op, name) = if add {
            (replicator_add(&addr), "ReplicatorAdd")
        } else {
            (replicator_delete(&addr), "ReplicatorDelete")
        };
        let r = ch.send(relay, source, Actor::Admin, op).await?;
        expect_status(&r, 200, &format!("{name} on {source} for {j}"))?;
    }
    Ok(())
}

/// S2: `ReplicatorDelete` for a peer the target has no replicator to. The
/// node may say no (400) or nothing (200); either is fine when it comes
/// quickly and the lists are unchanged; which one is recorded.
pub(super) async fn s2(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let before = managed_state(ch, relay, target).await?;
    let r = ch
        .send(relay, target, Actor::Admin, replicator_delete(ABSENT_PEER))
        .await?;
    let after = managed_state(ch, relay, target).await?;
    if !matches!(r.status, 200 | 400) || r.latency_ms > CLEAN_MS {
        return Err(fail(
            format!("200 no-op or 400 error within {CLEAN_MS} ms for ReplicatorDelete of an absent peer"),
            format!("{} after {} ms: {}", r.status, r.latency_ms, r.body),
        ));
    }
    if before != after {
        return Err(fail(
            format!("target state unchanged: {before}"),
            after.to_string(),
        ));
    }
    ch.note(match r.status {
        200 => "ReplicatorDelete of an absent peer: 200 no-op".to_string(),
        _ => format!("ReplicatorDelete of an absent peer: 400 {}", r.body),
    });
    Ok(())
}

/// S3: the source's replicators are dropped and one to the sink comes back
/// through the channel with an `age` filter; documents of both ages are
/// written at the source and only the matching ones reach the sink. The
/// filter the list shows is then compared with one added on the source
/// itself. The mesh is restored either way.
pub(super) async fn s3(ch: &mut dyn Channel) -> Result<()> {
    let (relay, source) = (0, 1);
    let sink = relay;
    let filters = json!({ COLLECTION: { "Field": "age", "Value": 1 } });
    let sink_addr = ch.addr(sink);
    let sink_peer = ch.peer_id(sink);
    let list = json!({ "Kind": "ReplicatorList" });
    mesh_from(ch, relay, source, false).await?;
    let r = ch
        .send(
            relay,
            source,
            Actor::Admin,
            replicator_add_filtered(&sink_addr, &filters),
        )
        .await?;
    expect_status(&r, 200, "ReplicatorAdd with a filter")?;
    let remote = filters_for(
        &ch.send(relay, source, Actor::Admin, list.clone())
            .await?
            .body,
        &sink_peer,
    );
    let hit = write_docs(ch, source, 2, 1).await?;
    let miss = write_docs(ch, source, 2, 2).await?;
    let have = converge(ch, sink, &hit).await?;
    let r = ch
        .send(relay, source, Actor::Admin, replicator_delete(&sink_addr))
        .await?;
    expect_status(&r, 200, "ReplicatorDelete of the filtered replicator")?;
    ch.control(Verb::LocalReplicatorAdd {
        node: source,
        peer: sink,
        filters: filters.clone(),
    })
    .await?;
    let local = filters_for(
        &ch.send(relay, source, Actor::Admin, list).await?.body,
        &sink_peer,
    );
    let r = ch
        .send(relay, source, Actor::Admin, replicator_delete(&sink_addr))
        .await?;
    expect_status(&r, 200, "ReplicatorDelete of the local twin")?;
    mesh_from(ch, relay, source, true).await?;
    if !hit.iter().all(|id| have.contains(id)) {
        return Err(fail(
            format!("the sink to have the age-1 documents {hit:?}"),
            format!("{have:?}"),
        ));
    }
    if miss.iter().any(|id| have.contains(id)) {
        return Err(fail(
            format!("the sink without the age-2 documents {miss:?}"),
            format!("{have:?}"),
        ));
    }
    if remote != local {
        return Err(fail(
            format!("the relayed filter equal to the local one {local}"),
            remote.to_string(),
        ));
    }
    Ok(())
}

/// S4: with the source's replicators dropped, a document written at the
/// source stays there; `DocumentAdd` for it on the target (relayed by the
/// source, the only other node), then an update at the source, and the
/// target has it. Restores the target's document list and the mesh.
pub(super) async fn s4(ch: &mut dyn Channel) -> Result<()> {
    let (relay, source) = (0, 1);
    let target = relay;
    mesh_from(ch, relay, source, false).await?;
    let ids = write_docs(ch, source, 1, 1).await?;
    let Some(id) = ids.first().cloned() else {
        return Err(fail("one document id from the source", format!("{ids:?}")));
    };
    let r = ch
        .send(source, target, Actor::Admin, document_add(&id))
        .await?;
    expect_status(&r, 200, "DocumentAdd on the target")?;
    ch.gql(source, update_user(&id, "touched")).await?;
    let have = converge(ch, target, std::slice::from_ref(&id)).await?;
    let r = ch
        .send(source, target, Actor::Admin, document_remove(&id))
        .await?;
    expect_status(&r, 200, "DocumentRemove (restore)")?;
    mesh_from(ch, relay, source, true).await?;
    if !have.contains(&id) {
        return Err(fail(
            format!("the target to have {id} after DocumentAdd and an update at the source"),
            format!("{} documents, not it", have.len()),
        ));
    }
    Ok(())
}

/// S1: `ReplicatorAdd` twice for the same peer leaves one entry. The mesh
/// replicator from the target to the relay is dropped first so the first
/// add is a real add; the second add restores the mesh.
pub(super) async fn s1(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let relay_addr = ch.addr(relay);
    let r = ch
        .send(relay, target, Actor::Admin, replicator_delete(&relay_addr))
        .await?;
    expect_status(&r, 200, "ReplicatorDelete before the double add")?;
    for n in 1..=2 {
        let r = ch
            .send(relay, target, Actor::Admin, replicator_add(&relay_addr))
            .await?;
        expect_status(&r, 200, &format!("ReplicatorAdd #{n}"))?;
    }
    let list = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "ReplicatorList" }),
        )
        .await?;
    expect_status(&list, 200, "ReplicatorList")?;
    let entries = replicators_for(&list.body, &ch.peer_id(relay));
    if entries != 1 {
        return Err(fail(
            "one replicator entry for the relay after two adds",
            format!("{entries} in {}", list.body),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::super::client::Reply;
    use super::super::data::fake::store;
    use super::*;

    #[tokio::test]
    async fn s1_adds_twice_and_wants_one_entry() {
        let mut adds = 0;
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("S1", move |_, _, _, _, op| {
            if op["Kind"] == "ReplicatorAdd" {
                adds += 1;
                tx.send(adds).unwrap();
            }
            admin_view(op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(rx.try_iter().last(), Some(2));

        let doubled = run_one("S1", |_, _, _, _, op| {
            if op["Kind"] == "ReplicatorList" {
                ok(json!({"Kind": "Replicators", "replicators": [{"id": "peer0"}, {"id": "peer0"}]}))
            } else {
                admin_view(op)
            }
        })
        .await;
        assert!(
            matches!(&doubled, Outcome::Fail { got, .. } if got.contains('2')),
            "{doubled:?}"
        );
    }

    fn replied(status: u16, ms: u64, body: Value) -> Result<Reply> {
        Ok(Reply {
            status,
            body,
            latency_ms: ms,
        })
    }

    #[tokio::test]
    async fn s2_takes_a_quick_no_op_or_error_and_records_it() {
        for (status, want) in [(200, "200 no-op"), (400, "400 {\"error\":\"not found\"}")] {
            let fake = Fake::new(move |_, _, _, _, op| {
                if op["Kind"] == "ReplicatorDelete" {
                    assert_eq!(op["addresses"][0], ABSENT_PEER);
                    replied(status, 12, json!({"error": "not found"}))
                } else {
                    admin_view(op)
                }
            });
            let (outcome, notes) = run_noted("S2", fake).await;
            assert_eq!(outcome, Outcome::Pass, "{status}");
            assert_eq!(
                notes,
                [format!("ReplicatorDelete of an absent peer: {want}")]
            );
        }
    }

    #[tokio::test]
    async fn s2_fails_on_a_5xx_a_late_reply_or_a_changed_list() {
        let server_error = run_one("S2", |_, _, _, _, op| match op["Kind"].as_str() {
            Some("ReplicatorDelete") => replied(500, 12, Value::Null),
            _ => admin_view(op),
        })
        .await;
        assert!(
            matches!(&server_error, Outcome::Fail { got, .. } if got.starts_with("500")),
            "{server_error:?}"
        );
        let late = run_one("S2", |_, _, _, _, op| match op["Kind"].as_str() {
            Some("ReplicatorDelete") => replied(400, 30_100, json!({"error": "response timeout"})),
            _ => admin_view(op),
        })
        .await;
        assert!(
            matches!(&late, Outcome::Fail { got, .. } if got.contains("30100 ms")),
            "{late:?}"
        );
        let lists = RefCell::new(0);
        let changed = run_one("S2", move |_, _, _, _, op| match op["Kind"].as_str() {
            Some("ReplicatorDelete") => status(200),
            Some("ReplicatorList") => {
                *lists.borrow_mut() += 1;
                if *lists.borrow() > 1 {
                    ok(json!({"Kind": "Replicators", "replicators": []}))
                } else {
                    admin_view(op)
                }
            }
            _ => admin_view(op),
        })
        .await;
        assert!(
            matches!(&changed, Outcome::Fail { expected, .. } if expected.contains("unchanged")),
            "{changed:?}"
        );
    }

    /// The source (node 1) keeps its replicator list, with filters, as
    /// the ops shape it; `local_filters` is what the local add stores.
    fn source_lists(local_filters: Value) -> Fake {
        let entries: std::rc::Rc<RefCell<Vec<Value>>> = Default::default();
        let seen = entries.clone();
        let verbs: std::rc::Rc<RefCell<Vec<Verb>>> = Default::default();
        let by_verb = verbs.clone();
        let applied = std::cell::Cell::new(0);
        let mut fake = Fake::new(move |_, target, _, _, op| {
            let peer = op["addresses"][0]
                .as_str()
                .and_then(|a| a.rsplit("/p2p/").next())
                .unwrap_or_default()
                .to_string();
            for verb in by_verb.borrow().iter().skip(applied.get()) {
                if let Verb::LocalReplicatorAdd { peer, .. } = verb {
                    seen.borrow_mut()
                        .push(json!({"id": format!("peer{peer}"), "filters": local_filters}));
                }
            }
            applied.set(by_verb.borrow().len());
            match op["Kind"].as_str().unwrap() {
                "ReplicatorDelete" if target == 1 => {
                    seen.borrow_mut().retain(|r| r["id"] != peer);
                    status(200)
                }
                "ReplicatorAdd" if target == 1 => {
                    seen.borrow_mut()
                        .push(json!({"id": peer, "filters": op["filters"]}));
                    status(200)
                }
                "ReplicatorList" if target == 1 => {
                    ok(json!({"Kind": "Replicators", "replicators": *seen.borrow()}))
                }
                _ => admin_view(op),
            }
        });
        fake.verbs = verbs;
        fake
    }

    #[tokio::test]
    async fn s3_wants_only_matching_docs_at_the_sink_and_the_same_filter_both_ways() {
        let filters = json!({"User": {"Field": "age", "Value": 1}});
        let mut fake = source_lists(filters.clone());
        fake.gql = RefCell::new(Box::new(store(|age| age == 1)));
        let (outcome, verbs) = run_fake("S3", fake).await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(
            verbs,
            [Verb::LocalReplicatorAdd {
                node: 1,
                peer: 0,
                filters
            }]
        );

        let mut leaky = source_lists(json!({"User": {"Field": "age", "Value": 1}}));
        leaky.gql = RefCell::new(Box::new(store(|_| true)));
        let (outcome, _) = run_fake("S3", leaky).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("without the age-2")),
            "{outcome:?}"
        );

        let mut mangled = source_lists(json!({"User": {"Field": "age", "Value": "1"}}));
        mangled.gql = RefCell::new(Box::new(store(|age| age == 1)));
        let (outcome, _) = run_fake("S3", mangled).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("equal to the local")),
            "{outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn s3_fails_when_the_sink_never_converges_and_still_restores_the_mesh() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut fake = source_lists(json!({"User": {"Field": "age", "Value": 1}}));
        let inner = fake.rule.replace(Box::new(|_, _, _, _, _| status(200)));
        let inner = RefCell::new(inner);
        fake.rule = RefCell::new(Box::new(move |r, t, a, actor, op| {
            tx.send((t, op["Kind"].as_str().unwrap().to_string()))
                .unwrap();
            (inner.borrow_mut())(r, t, a, actor, op)
        }));
        fake.gql = RefCell::new(Box::new(store(|_| false)));
        let (outcome, _) = run_fake("S3", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("to have the age-1")),
            "{outcome:?}"
        );
        let ops: Vec<_> = rx.try_iter().collect();
        let adds = ops
            .iter()
            .filter(|(t, k)| *t == 1 && k == "ReplicatorAdd")
            .count();
        assert_eq!(adds, 3, "one filtered add, two restoring the mesh: {ops:?}");
    }

    #[tokio::test]
    async fn s4_adds_the_doc_on_the_target_via_the_source_then_updates_and_wants_it_there() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut fake = Fake::new(move |relay, target, _, _, op| {
            tx.send((
                relay,
                target,
                op["Kind"].as_str().unwrap().to_string(),
                op["docs"][0]["doc_id"].clone(),
            ))
            .unwrap();
            admin_view(op)
        });
        fake.gql = RefCell::new(Box::new(store(|_| true)));
        let (outcome, _) = run_fake("S4", fake).await;
        assert_eq!(outcome, Outcome::Pass);
        let ops: Vec<_> = rx.try_iter().collect();
        assert!(
            ops.contains(&(1, 0, "DocumentAdd".into(), json!("bae-0"))),
            "{ops:?}"
        );
        assert!(
            ops.contains(&(1, 0, "DocumentRemove".into(), json!("bae-0"))),
            "{ops:?}"
        );
        assert_eq!(ops.last().unwrap().2, "ReplicatorAdd", "{ops:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn s4_fails_when_the_target_never_gets_the_doc() {
        let mut fake = Fake::new(|_, _, _, _, op| admin_view(op));
        fake.gql = RefCell::new(Box::new(store(|_| false)));
        let (outcome, _) = run_fake("S4", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("bae-0") && got == "0 documents, not it"),
            "{outcome:?}"
        );
    }
}
