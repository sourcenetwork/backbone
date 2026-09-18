//! Bounds cases: the request size the channel carries, and a target that
//! never answers. Big requests are `DocumentAdd` with many well-formed
//! doc ids, the only op whose payload scales.

use eyre::Result;
use serde_json::{json, Value};

use super::actors::Actor;
use super::cases::{expect_status, fail, Channel, Verb, COLLECTION};
use crate::Transport;

/// Wire bytes of one doc ref: a CBOR map of `Collection` "User" and a
/// 40-character `DocID`. A request of `n` refs is `n * DOC_REF_BYTES`
/// plus an 855-byte envelope (token, signature), well under `MARGIN`.
const DOC_REF_BYTES: usize = 65;

/// What the bounds cases size against, per transport.
pub struct Bounds {
    /// The request size bound, in wire bytes.
    pub max_request: usize,
    /// B4's request: big enough that the target is still applying it
    /// `pause_after_ms` in, small enough that the target's document list
    /// still fits a reply.
    pub silent_request: usize,
    pub pause_after_ms: u64,
}

/// libp2p is what B3 located on 2026-09-17: 258048 refs (16773977 B) land,
/// 258112 (16778137 B) are refused with "failed to write manage request:
/// connection is closed" in 2 s, the target's `max_msg_size`. B3 measured
/// 12.5 MiB at 3.2 s round trip, so B4 pauses 1.5 s into 12 MiB.
pub const LIBP2P: Bounds = Bounds {
    max_request: 16 * 1024 * 1024,
    silent_request: 12 * 1024 * 1024,
    pause_after_ms: 1_500,
};

/// Iroh is `MAX_MANAGE_MSG_SIZE` (crates/p2p/src/iroh/protocols.rs:98),
/// which B2 confirmed from above on 2026-09-18: 65536 refs are refused in
/// 212 ms with "codec error: failed to write payload: sending stopped by
/// peer: error 0". B3 could not bracket it from below: a `DocumentAdd` of
/// 1024 refs (~65 KiB) gets "response timeout" after 30 s, the target
/// stops accepting after its 165th document-topic join, and every later
/// dial of it is "dial error: timed out". B4's request wedges the target
/// the same way, so its pause has not been calibrated.
pub const IROH: Bounds = Bounds {
    max_request: 4 * 1024 * 1024,
    silent_request: 3 * 1024 * 1024,
    pause_after_ms: 400,
};

const _: () = assert!(LIBP2P.silent_request < LIBP2P.max_request);
const _: () = assert!(IROH.silent_request < IROH.max_request);

pub fn for_transport(t: Transport) -> &'static Bounds {
    match t {
        Transport::Libp2p => &LIBP2P,
        Transport::Iroh => &IROH,
    }
}

/// How far under and over the bound B1 and B2 sit.
const MARGIN: usize = 64 * 1024;

/// B3 stops when the landed and refused sizes are this close, in refs.
const RESOLUTION: usize = 64;

/// B3 gives up looking for a refusal past this many refs.
const CAP: usize = 1 << 20;

fn docs_for(bytes: usize) -> usize {
    bytes / DOC_REF_BYTES
}

fn document_op(kind: &str, n: usize) -> Value {
    let docs: Vec<Value> = (0..n)
        .map(|i| json!({ "collection": COLLECTION, "doc_id": format!("bae-00000000-0000-0000-0000-{i:012x}") }))
        .collect();
    json!({ "Kind": kind, "docs": docs })
}

/// B1: a `DocumentAdd` just under the bound lands; the same refs are
/// removed again.
pub(super) async fn b1(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let n = docs_for(for_transport(ch.transport()).max_request - MARGIN);
    let r = ch
        .send(relay, target, Actor::Admin, document_op("DocumentAdd", n))
        .await?;
    expect_status(&r, 200, &format!("DocumentAdd of {n} refs under the bound"))?;
    let r = ch
        .send(
            relay,
            target,
            Actor::Admin,
            document_op("DocumentRemove", n),
        )
        .await?;
    expect_status(&r, 200, "DocumentRemove (restore)")
}

/// B2: a `DocumentAdd` just over the bound is refused, not served and not
/// a 5xx; the status is recorded. The target then serves a request and
/// so does the relay, for a third node.
pub(super) async fn b2(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target, other) = (0, 1, 2);
    let n = docs_for(for_transport(ch.transport()).max_request + MARGIN);
    let r = ch
        .send(relay, target, Actor::Admin, document_op("DocumentAdd", n))
        .await?;
    if r.status == 200 || r.status >= 500 {
        return Err(fail(
            format!("a clean refusal of {n} refs over the bound"),
            format!("{} after {} ms: {}", r.status, r.latency_ms, r.body),
        ));
    }
    ch.note(format!(
        "{n} refs over the bound: {} after {} ms: {}",
        r.status, r.latency_ms, r.body
    ));
    let list = json!({ "Kind": "CollectionList" });
    let r = ch.send(relay, target, Actor::Admin, list.clone()).await?;
    expect_status(
        &r,
        200,
        "CollectionList on the target after the oversized request",
    )?;
    let r = ch.send(relay, other, Actor::Admin, list).await?;
    expect_status(&r, 200, "CollectionList through the relay to a third node")
}

/// B3: the transport's bound, by doubling then bisecting the ref count of a
/// `DocumentAdd`; each probe and the located interval are recorded, not
/// asserted. Landed probes are removed again; a refused probe leaves the
/// target as it was, so this runs alone under `--locate-size-bound`.
pub(super) async fn b3(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let mut lo = 0;
    let mut hi: Option<(usize, String)> = None;
    let mut n = 1024;
    while n <= CAP {
        let r = ch
            .send(relay, target, Actor::Admin, document_op("DocumentAdd", n))
            .await?;
        ch.note(format!(
            "{n} refs (~{} KiB): {} after {} ms {}",
            n * DOC_REF_BYTES / 1024,
            r.status,
            r.latency_ms,
            if r.status == 200 {
                String::new()
            } else {
                r.body.to_string()
            }
        ));
        if r.status == 200 {
            lo = n;
            let r = ch
                .send(
                    relay,
                    target,
                    Actor::Admin,
                    document_op("DocumentRemove", n),
                )
                .await?;
            expect_status(&r, 200, &format!("DocumentRemove of {n} refs (restore)"))?;
        } else {
            hi = Some((n, format!("{} {}", r.status, r.body)));
        }
        n = match &hi {
            None => n * 2,
            Some((h, _)) if h - lo <= RESOLUTION => break,
            Some((h, _)) => (lo + h) / 2,
        };
    }
    let Some((h, refusal)) = hi else {
        return Err(fail(
            format!("a refused DocumentAdd within {CAP} refs"),
            format!("{lo} refs landed"),
        ));
    };
    ch.note(format!(
        "{} bound: between {lo} and {h} refs, {} and {} bytes; at {h}: {refusal}",
        ch.transport().label(),
        lo * DOC_REF_BYTES,
        h * DOC_REF_BYTES
    ));
    Ok(())
}

/// After the resume, the target finishes applying before the restore.
const APPLY_GRACE_MS: u64 = 10_000;

/// B4: the target is frozen mid-request (SIGSTOP, while it is still
/// reading or applying a big `DocumentAdd`), so the request is on its way
/// and no reply ever comes: the relay must give up with its correlator's
/// "response timeout", not a dial or stream error, and serve a healthy
/// target meanwhile. The target is resumed and its list restored either
/// way.
pub(super) async fn b4(ch: &mut dyn Channel) -> Result<()> {
    let (relay, silent, healthy) = (0, 1, 2);
    let bounds = for_transport(ch.transport());
    let n = docs_for(bounds.silent_request);
    let list = json!({ "Kind": "CollectionList" });
    let r = ch.send(relay, silent, Actor::Admin, list.clone()).await?;
    expect_status(&r, 200, "CollectionList before the pause")?;
    ch.control(Verb::PauseAfter {
        node: silent,
        delay_ms: bounds.pause_after_ms,
    })
    .await?;
    let probe = ch
        .send(relay, silent, Actor::Admin, document_op("DocumentAdd", n))
        .await;
    let next = ch.send(relay, healthy, Actor::Admin, list).await;
    ch.control(Verb::Resume(silent)).await?;
    tokio::time::sleep(std::time::Duration::from_millis(APPLY_GRACE_MS)).await;
    let r = ch
        .send(
            relay,
            silent,
            Actor::Admin,
            document_op("DocumentRemove", n),
        )
        .await?;
    expect_status(&r, 200, "DocumentRemove (restore)")?;
    let r = ch
        .send(
            relay,
            silent,
            Actor::Admin,
            json!({ "Kind": "DocumentList" }),
        )
        .await?;
    expect_status(&r, 200, "DocumentList after the restore")?;
    let tracked = r.body["documents"].as_array().map_or(0, Vec::len);
    if tracked != 0 {
        return Err(fail(
            "the target's document list empty after the restore",
            format!("{tracked} tracked"),
        ));
    }
    let probe = probe.map_err(|e| {
        fail(
            "a reply while the target is silent",
            format!("no reply: {e:#}"),
        )
    })?;
    let body = probe.body.to_string();
    if probe.status != 400 || !body.contains("response timeout") {
        return Err(fail(
            "400 response timeout from the relay's correlator",
            format!("{} after {} ms: {body}", probe.status, probe.latency_ms),
        ));
    }
    expect_status(
        &next?,
        200,
        "CollectionList to a healthy target while the silent one hangs",
    )
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::super::client::Reply;
    use super::*;

    fn replied(status: u16, ms: u64, body: &str) -> Result<Reply> {
        Ok(Reply {
            status,
            body: json!({ "error": body }),
            latency_ms: ms,
        })
    }

    fn refs(op: &Value) -> usize {
        op["docs"].as_array().map_or(0, Vec::len)
    }

    /// A target that lands `DocumentAdd` up to `max` refs and answers
    /// `refusal` past it.
    fn bounded(max: usize, refusal: Result<Reply>) -> Fake {
        let refusal = Cell::new(Some(refusal));
        Fake::new(move |_, _, _, _, op| match op["Kind"].as_str() {
            Some("DocumentAdd" | "DocumentRemove") if refs(op) > max => refusal
                .take()
                .unwrap_or_else(|| replied(400, 30_000, "response timeout")),
            _ => admin_view(op),
        })
    }

    #[test]
    fn bounds_follow_the_transport() {
        assert_eq!(
            for_transport(Transport::Libp2p).max_request,
            16 * 1024 * 1024
        );
        assert_eq!(for_transport(Transport::Iroh).max_request, 4 * 1024 * 1024);
    }

    #[test]
    fn document_op_refs_are_well_formed_and_sized() {
        let op = document_op("DocumentAdd", 3);
        assert_eq!(
            op["docs"][2]["doc_id"],
            "bae-00000000-0000-0000-0000-000000000002"
        );
        assert!(docs_for(LIBP2P.max_request) * DOC_REF_BYTES <= LIBP2P.max_request);
        assert!(docs_for(MARGIN) > 0);
    }

    #[tokio::test]
    async fn b1_lands_under_the_bound_and_removes_again() {
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("B1", move |_, _, _, _, op| {
            tx.send((op["Kind"].as_str().unwrap().to_string(), refs(op)))
                .unwrap();
            admin_view(op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        let n = docs_for(LIBP2P.max_request - MARGIN);
        let seen: Vec<_> = rx.try_iter().collect();
        assert_eq!(seen[0], ("DocumentAdd".to_string(), n));
        assert!(seen.contains(&("DocumentRemove".to_string(), n)));

        let (tx, rx) = std::sync::mpsc::channel();
        let mut fake = Fake::new(move |_, _, _, _, op| {
            tx.send(refs(op)).unwrap();
            admin_view(op)
        });
        fake.transport = Transport::Iroh;
        assert_eq!(run_fake("B1", fake).await.0, Outcome::Pass);
        assert_eq!(
            rx.try_iter().next(),
            Some(docs_for(IROH.max_request - MARGIN))
        );

        let (outcome, _) = run_fake(
            "B1",
            bounded(n - 1, replied(400, 30_000, "response timeout")),
        )
        .await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("under the bound") && got.starts_with("400")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn b2_needs_a_refusal_then_the_target_then_the_relay() {
        let n = docs_for(LIBP2P.max_request + MARGIN);
        let (outcome, notes) = run_noted(
            "B2",
            bounded(n - 1, replied(400, 30_000, "response timeout")),
        )
        .await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("400 after 30000 ms"), "{notes:?}");

        let served = run_fake("B2", bounded(n + 1, status(200))).await.0;
        assert!(
            matches!(&served, Outcome::Fail { expected, .. } if expected.contains("clean refusal")),
            "{served:?}"
        );
        let crashed = run_fake("B2", bounded(n - 1, status(502))).await.0;
        assert!(
            matches!(&crashed, Outcome::Fail { got, .. } if got.starts_with("502")),
            "{crashed:?}"
        );

        for (down, what) in [(1, "on the target"), (2, "to a third node")] {
            let outcome = run_one("B2", move |_, target, _, _, op| {
                if op["Kind"] == "DocumentAdd" {
                    replied(400, 30_000, "response timeout")
                } else if target == down {
                    replied(400, 10_000, "dial timeout")
                } else {
                    admin_view(op)
                }
            })
            .await;
            assert!(
                matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains(what)),
                "{what}: {outcome:?}"
            );
        }
    }

    #[tokio::test]
    async fn b3_brackets_the_bound_and_restores_what_landed() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut fake = bounded(100_000, replied(400, 30_000, "response timeout"));
        let inner = RefCell::new(std::mem::replace(
            &mut fake.rule,
            Box::new(|_, _, _, _, _| status(200)),
        ));
        fake.rule = Box::new(move |r, t, a, actor, op| {
            tx.send((op["Kind"].as_str().unwrap().to_string(), refs(op)))
                .unwrap();
            (inner.borrow_mut())(r, t, a, actor, op)
        });
        let (outcome, notes) = run_noted("B3", fake).await;
        assert_eq!(outcome, Outcome::Pass);
        let last = notes.last().unwrap();
        assert!(last.starts_with("libp2p bound: between "), "{last}");
        let words: Vec<&str> = last.split(' ').collect();
        let (lo, hi): (usize, usize) = (words[3].parse().unwrap(), words[5].parse().unwrap());
        assert!(
            lo <= 100_000 && 100_000 < hi && hi - lo <= RESOLUTION,
            "{last}"
        );
        assert!(
            last.ends_with("400 {\"error\":\"response timeout\"}"),
            "{last}"
        );
        let ops: Vec<_> = rx.try_iter().collect();
        for (kind, n) in &ops {
            if kind == "DocumentAdd" && *n <= 100_000 {
                assert!(
                    ops.contains(&("DocumentRemove".into(), *n)),
                    "{n} not removed"
                );
            }
        }
        assert!(
            !ops.contains(&("DocumentRemove".into(), 131072)),
            "refused probe removed"
        );
    }

    #[tokio::test]
    async fn b3_fails_when_nothing_is_refused_under_the_cap() {
        let (outcome, _) = run_fake("B3", bounded(usize::MAX, status(200))).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("refused")),
            "{outcome:?}"
        );
    }

    const PAUSE: Verb = Verb::PauseAfter {
        node: 1,
        delay_ms: LIBP2P.pause_after_ms,
    };

    /// Frozen: node 1 answers `reply` to the one request in flight while
    /// its pause is pending; everyone else is healthy.
    fn paused_target(reply: Result<Reply>) -> Fake {
        let verbs: Rc<RefCell<Vec<Verb>>> = Default::default();
        let seen = verbs.clone();
        let reply = Cell::new(Some(reply));
        let mut fake = Fake::new(move |_, target, _, _, op| {
            if target == 1 && seen.borrow().last() == Some(&PAUSE) {
                return reply.take().expect("one probe while paused");
            }
            admin_view(op)
        });
        fake.verbs = verbs;
        fake
    }

    #[tokio::test(start_paused = true)]
    async fn b4_wants_the_correlator_timeout_not_a_dial_error_and_resumes() {
        let (outcome, verbs) = run_fake(
            "B4",
            paused_target(replied(400, 30_050, "response timeout")),
        )
        .await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(verbs, [PAUSE, Verb::Resume(1)]);

        let dial = run_fake("B4", paused_target(replied(400, 10_000, "dial timeout"))).await;
        assert!(
            matches!(&dial.0, Outcome::Fail { expected, got } if expected.contains("response timeout") && got.contains("dial timeout")),
            "{:?}",
            dial.0
        );
        assert_eq!(dial.1, [PAUSE, Verb::Resume(1)]);

        let hung = run_fake("B4", paused_target(Err(eyre::eyre!("operation timed out")))).await;
        assert!(
            matches!(&hung.0, Outcome::Fail { got, .. } if got.contains("timed out")),
            "{:?}",
            hung.0
        );
        assert_eq!(hung.1, [PAUSE, Verb::Resume(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn b4_fails_when_the_healthy_target_is_not_served_or_the_restore_leaves_docs() {
        let verbs: Rc<RefCell<Vec<Verb>>> = Default::default();
        let seen = verbs.clone();
        let mut fake = Fake::new(
            move |_, target, _, _, op| match (target, seen.borrow().last()) {
                (1 | 2, Some(&PAUSE)) => replied(400, 30_050, "response timeout"),
                _ => admin_view(op),
            },
        );
        fake.verbs = verbs;
        let (outcome, verbs) = run_fake("B4", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("healthy target")),
            "{outcome:?}"
        );
        assert_eq!(verbs, [PAUSE, Verb::Resume(1)]);

        let mut fake = paused_target(replied(400, 30_050, "response timeout"));
        let inner = RefCell::new(std::mem::replace(
            &mut fake.rule,
            Box::new(|_, _, _, _, _| status(200)),
        ));
        fake.rule = Box::new(move |r, t, a, actor, op| {
            if op["Kind"] == "DocumentList" {
                return ok(json!({"Kind": "Documents", "documents": [{"doc_id": "bae-1"}]}));
            }
            (inner.borrow_mut())(r, t, a, actor, op)
        });
        let (outcome, _) = run_fake("B4", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("empty after the restore") && got == "1 tracked"),
            "{outcome:?}"
        );
    }
}
