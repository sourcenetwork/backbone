//! Partition and concurrency cases: an op into a cut-off target, and ops
//! beside a write burst.

use eyre::Result;
use serde_json::json;
use tokio::time::Instant;

use super::actors::Actor;
use super::cases::{
    collection_add, collection_remove, expect_status, fail, managed_state, skip, Channel, Verb,
    COLLECTION,
};
use super::data::{converge, create_users, doc_ids, ids_in};
use super::state::{document_add, document_remove};

/// Documents the C1 burst writes at the source.
const BURST: usize = 50;

/// A well-formed id no document has; C1 tracks and untracks it.
const SYNTH_DOC: &str = "bae-00000000-0000-0000-0000-0000000000c1";

/// P1: `CollectionAdd` while the target is cut off, then healed. The
/// outcome is recorded, not judged: the relay must answer, whatever it
/// says, and after the rejoin the op is on the target or it is not.
pub(super) async fn p1(ch: &mut dyn Channel) -> Result<()> {
    if !ch.can_partition() {
        return Err(skip(
            "this backend cannot partition a node (process nodes; manage has no --docker yet)",
        ));
    }
    let (relay, target) = (0, 1);
    ch.control(Verb::Partition(target)).await?;
    let probe = ch.send(relay, target, Actor::Admin, collection_add()).await;
    ch.control(Verb::Rejoin(target)).await?;
    let probe = probe.map_err(|e| {
        fail(
            "a reply while the target is partitioned",
            format!("no reply: {e:#}"),
        )
    })?;
    let list = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "CollectionList" }),
        )
        .await?;
    expect_status(&list, 200, "CollectionList after the rejoin")?;
    let landed = list.body["values"]
        .as_array()
        .is_some_and(|v| v.iter().any(|c| c == COLLECTION));
    if landed {
        let r = ch
            .send(relay, target, Actor::Admin, collection_remove())
            .await?;
        expect_status(&r, 200, "CollectionRemove (restore)")?;
    }
    ch.note(format!(
        "CollectionAdd while partitioned: {} after {} ms: {}; after rejoin: {}",
        probe.status,
        probe.latency_ms,
        probe.body,
        if landed { "landed" } else { "lost" }
    ));
    Ok(())
}

/// C1: a fixed op sequence on the source while a burst of documents is
/// written there: every op lands, at least one is answered before the
/// burst's own reply comes back (the timestamps are noted), the source's
/// managed state is back where it started, and the sink has as many
/// documents as the source.
pub(super) async fn c1(ch: &mut dyn Channel) -> Result<()> {
    let (relay, source) = (0, 1);
    let sink = relay;
    let before = managed_state(ch, relay, source).await?;
    let started = Instant::now();
    let write = ch.gql(source, create_users(BURST, 1));
    let burst = tokio::spawn(async move { (write.await, Instant::now()) });
    let ops = [
        collection_add(),
        document_add(SYNTH_DOC),
        collection_remove(),
        document_remove(SYNTH_DOC),
    ];
    let mut spans = Vec::new();
    for op in ops {
        let kind = op["Kind"].as_str().unwrap_or_default().to_string();
        let sent = started.elapsed();
        let r = ch.send(relay, source, Actor::Admin, op).await?;
        spans.push((kind.clone(), sent, started.elapsed()));
        expect_status(&r, 200, &format!("{kind} during the burst"))?;
    }
    let (data, ended) = burst.await?;
    let ended = ended - started;
    let written = ids_in(&data?, &format!("add_{COLLECTION}"));
    let inside = spans
        .iter()
        .filter(|(_, _, replied)| *replied < ended)
        .count();
    ch.note(format!(
        "burst 0..{} ms; {}; {inside} of {} ops inside",
        ended.as_millis(),
        spans
            .iter()
            .map(|(kind, sent, replied)| format!(
                "{kind} {}..{} ms",
                sent.as_millis(),
                replied.as_millis()
            ))
            .collect::<Vec<_>>()
            .join(", "),
        spans.len()
    ));
    if inside == 0 {
        return Err(fail(
            "an op answered while the burst was in flight",
            format!(
                "sequential, not concurrent: the burst ended at {} ms, the first op was answered at {} ms",
                ended.as_millis(),
                spans[0].2.as_millis()
            ),
        ));
    }
    if written.len() != BURST {
        return Err(fail(
            format!("{BURST} documents from the burst"),
            format!("{}", written.len()),
        ));
    }
    let have = converge(ch, sink, &written).await?;
    let after = managed_state(ch, relay, source).await?;
    if after != before {
        return Err(fail(
            format!("source state back where it started: {before}"),
            after.to_string(),
        ));
    }
    let at_source = doc_ids(ch, source).await?.len();
    if have.len() != at_source {
        return Err(fail(
            format!("the sink with the source's {at_source} documents after the burst"),
            format!("{}", have.len()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::super::client::Reply;
    use super::super::data::fake::store;
    use super::*;

    fn replied(status: u16, ms: u64, body: &str) -> Result<Reply> {
        Ok(Reply {
            status,
            body: json!({ "error": body }),
            latency_ms: ms,
        })
    }

    /// Node 1 answers `cut` while partitioned; after the rejoin its
    /// collection list has the collection iff `landed`.
    fn partitioned(cut: Result<Reply>, landed: bool) -> Fake {
        let verbs: Rc<RefCell<Vec<Verb>>> = Default::default();
        let seen = verbs.clone();
        let cut = std::cell::Cell::new(Some(cut));
        let mut fake = Fake::new(move |_, target, _, _, op| {
            if target == 1 && seen.borrow().last() == Some(&Verb::Partition(1)) {
                return cut.take().expect("one op while partitioned");
            }
            if op["Kind"] == "CollectionList" {
                let values: Vec<&str> = if landed { vec![COLLECTION] } else { vec![] };
                return ok(json!({"Kind": "Strings", "values": values}));
            }
            admin_view(op)
        });
        fake.verbs = verbs;
        fake
    }

    #[tokio::test]
    async fn p1_records_lost_or_landed_and_never_fails_a_recorded_outcome() {
        let (outcome, notes) = run_noted(
            "P1",
            partitioned(replied(400, 10_000, "dial timeout"), false),
        )
        .await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(
            notes,
            ["CollectionAdd while partitioned: 400 after 10000 ms: {\"error\":\"dial timeout\"}; after rejoin: lost"]
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let mut fake = partitioned(replied(200, 15, "ok"), true);
        let inner = RefCell::new(fake.rule.replace(Box::new(|_, _, _, _, _| status(200))));
        fake.rule = RefCell::new(Box::new(move |r, t, a, actor, op| {
            tx.send(op["Kind"].as_str().unwrap().to_string()).unwrap();
            (inner.borrow_mut())(r, t, a, actor, op)
        }));
        let (outcome, notes) = run_noted("P1", fake).await;
        assert_eq!(outcome, Outcome::Pass);
        assert!(notes[0].ends_with("after rejoin: landed"), "{notes:?}");
        assert!(
            rx.try_iter().any(|k| k == "CollectionRemove"),
            "a landed op is restored"
        );
    }

    #[tokio::test]
    async fn p1_fails_only_on_a_hang_and_still_rejoins() {
        let (outcome, verbs) = run_fake(
            "P1",
            partitioned(Err(eyre::eyre!("operation timed out")), false),
        )
        .await;
        assert!(
            matches!(&outcome, Outcome::Fail { got, .. } if got.contains("timed out")),
            "{outcome:?}"
        );
        assert_eq!(verbs, [Verb::Partition(1), Verb::Rejoin(1)]);
    }

    #[tokio::test]
    async fn p1_skips_where_nothing_can_partition() {
        let mut fake = Fake::new(|_, _, _, _, op| admin_view(op));
        fake.partition = false;
        let (outcome, verbs) = run_fake("P1", fake).await;
        assert!(
            matches!(&outcome, Outcome::Skip { reason } if reason.contains("cannot partition")),
            "{outcome:?}"
        );
        assert!(verbs.is_empty());
    }

    /// `fake` with a data plane whose sink sees `sink_sees`, answering
    /// 100 ms later, so a burst is in flight while the ops go out.
    fn bursting(mut fake: Fake, sink_sees: impl Fn(i64) -> bool + 'static) -> Fake {
        fake.gql = RefCell::new(Box::new(store(sink_sees)));
        fake.gql_ms = 100;
        fake
    }

    #[tokio::test(start_paused = true)]
    async fn c1_lands_every_op_inside_the_burst_and_wants_the_sink_to_catch_up() {
        let (tx, rx) = std::sync::mpsc::channel();
        let fake = Fake::new(move |_, target, _, _, op| {
            tx.send((target, op["Kind"].as_str().unwrap().to_string()))
                .unwrap();
            admin_view(op)
        });
        let (outcome, notes) = run_noted("C1", bursting(fake, |_| true)).await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(
            notes,
            ["burst 0..100 ms; CollectionAdd 0..0 ms, DocumentAdd 0..0 ms, CollectionRemove 0..0 ms, DocumentRemove 0..0 ms; 4 of 4 ops inside"]
        );
        let kinds: Vec<String> = rx
            .try_iter()
            .filter(|(t, k)| *t == 1 && !k.ends_with("List"))
            .map(|(_, k)| k)
            .collect();
        assert_eq!(
            kinds,
            [
                "CollectionAdd",
                "DocumentAdd",
                "CollectionRemove",
                "DocumentRemove"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn c1_fails_when_no_op_is_answered_while_the_burst_is_in_flight() {
        let mut fake = Fake::new(|_, _, _, _, op| admin_view(op));
        fake.gql = RefCell::new(Box::new(store(|_| true)));
        // The burst answers at once, so it is over before the first op replies.
        let (outcome, notes) = run_noted("C1", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("in flight") && got.starts_with("sequential, not concurrent")),
            "{outcome:?}"
        );
        assert_eq!(
            notes,
            ["burst 0..0 ms; CollectionAdd 0..0 ms, DocumentAdd 0..0 ms, CollectionRemove 0..0 ms, DocumentRemove 0..0 ms; 0 of 4 ops inside"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn c1_fails_when_the_count_diverges_after_settle() {
        let fake = Fake::new(|_, _, _, _, op| admin_view(op));
        let (outcome, _) = run_fake("C1", bursting(fake, |_| false)).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("50 documents") && got == "0"),
            "{outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn c1_fails_on_a_refused_op_or_drifted_state() {
        let refused = Fake::new(|_, _, _, _, op| {
            if op["Kind"] == "DocumentAdd" {
                status(400)
            } else {
                admin_view(op)
            }
        });
        let (outcome, _) = run_fake("C1", bursting(refused, |_| true)).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("DocumentAdd during the burst")),
            "{outcome:?}"
        );

        let lists = RefCell::new(0);
        let drifted = Fake::new(move |_, _, _, _, op| {
            if op["Kind"] == "CollectionList" {
                *lists.borrow_mut() += 1;
                if *lists.borrow() > 1 {
                    return ok(json!({"Kind": "Strings", "values": []}));
                }
            }
            admin_view(op)
        });
        let (outcome, _) = run_fake("C1", bursting(drifted, |_| true)).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("back where it started")),
            "{outcome:?}"
        );
    }
}
