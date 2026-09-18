//! Routing cases: the relay reaches the target whatever their relationship.

use eyre::Result;
use serde_json::json;

use super::actors::Actor;
use super::cases::{
    expect_status, fail, replicator_add, replicator_delete, replicators_for, Channel, Verb,
    COLLECTION,
};
use super::client::Reply;
use crate::Transport;

/// The relay gives a libp2p dial 10 s; a clean error later than this is a
/// hang.
const LIBP2P_DIAL_BUDGET_MS: u64 = 15_000;

/// Iroh gives up on a dead peer only after ~30 s (defradb.rs
/// `endpoint_commands.rs:761-766`), so its budget admits that.
const IROH_DIAL_BUDGET_MS: u64 = 35_000;

fn dial_budget_ms(t: Transport) -> u64 {
    match t {
        Transport::Libp2p => LIBP2P_DIAL_BUDGET_MS,
        Transport::Iroh => IROH_DIAL_BUDGET_MS,
    }
}

/// R1: for every ordered (relay, target, source) of distinct nodes, admin
/// drops and restores the target's replicator to the source through the
/// relay, and the target's list follows each op.
pub(super) async fn r1(ch: &mut dyn Channel) -> Result<()> {
    let n = ch.len();
    for relay in 0..n {
        for target in (0..n).filter(|t| *t != relay) {
            for source in (0..n).filter(|s| *s != relay && *s != target) {
                let addr = ch.addr(source);
                let peer = ch.peer_id(source);
                let steps = [
                    (replicator_delete(&addr), 0, "ReplicatorDelete"),
                    (replicator_add(&addr), 1, "ReplicatorAdd"),
                ];
                for (op, want, name) in steps {
                    let what = format!("{name} via {relay} on {target} for {source}");
                    let r = ch.send(relay, target, Actor::Admin, op).await?;
                    expect_status(&r, 200, &what)?;
                    let list = ch
                        .send(
                            relay,
                            target,
                            Actor::Admin,
                            json!({ "Kind": "ReplicatorList" }),
                        )
                        .await?;
                    let got = replicators_for(&list.body, &peer);
                    if got != want {
                        return Err(fail(
                            format!("{want} replicator entry for node {source} after {what}"),
                            format!("{got} in {}", list.body),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// R3, two halves, each noted: the target (node 1) is stopped before the
/// call and the relay answers a clean 400 within the transport's dial
/// budget; then the relay serves the target again once it is back. A
/// missing reply is the hang the first half exists to catch, not a
/// harness fault. The outcome is the first half that fails. The grants
/// are re-applied after the check: a node that comes back without them
/// is reported here and must not poison the rest.
pub(super) async fn r3(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let list = json!({ "Kind": "CollectionList" });
    ch.control(Verb::Stop(target)).await?;
    let probe = ch.send(relay, target, Actor::Admin, list.clone()).await;
    ch.control(Verb::Start(target)).await?;
    let next = ch.send(relay, target, Actor::Admin, list).await;
    ch.control(Verb::Regrant(target)).await?;
    let stopped = dial_check(probe, dial_budget_ms(ch.transport()));
    let restarted = next.and_then(|r| {
        expect_status(
            &r,
            200,
            "admin CollectionList via the relay after the target restarted",
        )
        .map(|()| "200 on admin CollectionList via the relay".to_string())
    });
    for (half, verdict) in [
        ("stopped target", &stopped),
        ("restarted target", &restarted),
    ] {
        ch.note(match verdict {
            Ok(text) => format!("{half}: {text}"),
            Err(e) => format!("{half}: FAIL {e:#}"),
        });
    }
    stopped?;
    restarted.map(drop)
}

/// The stopped-target half: a clean 400 within `budget_ms`.
fn dial_check(probe: Result<Reply>, budget_ms: u64) -> Result<String> {
    let probe = probe.map_err(|e| {
        fail(
            "a reply while the target is stopped",
            format!("no reply: {e:#}"),
        )
    })?;
    expect_status(&probe, 400, "CollectionList to a stopped target")?;
    if probe.latency_ms > budget_ms {
        return Err(fail(
            format!("a clean error within the {budget_ms} ms dial budget"),
            format!("400 after {} ms: {}", probe.latency_ms, probe.body),
        ));
    }
    Ok(format!(
        "400 after {} ms, within the {budget_ms} ms dial budget",
        probe.latency_ms
    ))
}

/// R2: the relay (node 0) has no replicator to the target (node 1); an admin
/// op still dials and lands. The relay's replicator is dropped and restored
/// through the channel in the other direction.
pub(super) async fn r2(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let target_addr = ch.addr(target);
    let r = ch
        .send(target, relay, Actor::Admin, replicator_delete(&target_addr))
        .await?;
    expect_status(&r, 200, "ReplicatorDelete on the relay")?;
    let list = ch
        .send(
            target,
            relay,
            Actor::Admin,
            json!({ "Kind": "ReplicatorList" }),
        )
        .await?;
    let left = replicators_for(&list.body, &ch.peer_id(target));
    if left != 0 {
        return Err(fail(
            "no replicator from the relay to the target",
            format!("{left} in {}", list.body),
        ));
    }
    let r = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "CollectionAdd", "collection_ids": [COLLECTION] }),
        )
        .await?;
    expect_status(&r, 200, "CollectionAdd via a relay without a replicator")?;
    let list = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "CollectionList" }),
        )
        .await?;
    if !list.body["values"]
        .as_array()
        .is_some_and(|v| v.iter().any(|c| c == COLLECTION))
    {
        return Err(fail(
            format!("{COLLECTION} in the target's CollectionList"),
            list.body.to_string(),
        ));
    }
    let r = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "CollectionRemove", "collection_ids": [COLLECTION] }),
        )
        .await?;
    expect_status(&r, 200, "CollectionRemove (restore)")?;
    let r = ch
        .send(target, relay, Actor::Admin, replicator_add(&target_addr))
        .await?;
    expect_status(&r, 200, "ReplicatorAdd on the relay (restore)")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::*;
    use serde_json::Value;

    /// A three-node mesh whose replicator lists follow the adds and deletes.
    fn following_mesh() -> impl FnMut(usize, usize, usize, Actor, &Value) -> Result<Reply> {
        let mut mesh: HashMap<usize, BTreeSet<String>> = (0..3)
            .map(|t| {
                (
                    t,
                    (0..3)
                        .filter(|s| *s != t)
                        .map(|s| format!("peer{s}"))
                        .collect(),
                )
            })
            .collect();
        move |_, target, _, _, op| {
            let peer = op["addresses"][0]
                .as_str()
                .and_then(|a| a.rsplit("/p2p/").next())
                .unwrap_or_default()
                .to_string();
            match op["Kind"].as_str().unwrap() {
                "ReplicatorDelete" => {
                    mesh.get_mut(&target).unwrap().remove(&peer);
                    status(200)
                }
                "ReplicatorAdd" => {
                    mesh.get_mut(&target).unwrap().insert(peer);
                    status(200)
                }
                "ReplicatorList" => ok(json!({"Kind": "Replicators", "replicators":
                    mesh[&target].iter().map(|p| json!({"id": p, "collections": ["bafy-user"]})).collect::<Vec<_>>()
                })),
                _ => admin_view(op),
            }
        }
    }

    #[tokio::test]
    async fn r1_drops_and_restores_every_target_source_pair_through_every_third_node() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut mesh = following_mesh();
        let outcome = run_one("R1", move |relay, target, _, actor, op| {
            if op["Kind"] == "ReplicatorAdd" {
                let src = op["addresses"][0]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_string();
                tx.send((relay, target, src)).unwrap();
            }
            assert_eq!(actor, Actor::Admin);
            mesh(relay, target, target, actor, op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        let mut triples: Vec<_> = rx.try_iter().collect();
        triples.sort();
        assert_eq!(
            triples,
            [
                (0, 1, "peer2".into()),
                (0, 2, "peer1".into()),
                (1, 0, "peer2".into()),
                (1, 2, "peer0".into()),
                (2, 0, "peer1".into()),
                (2, 1, "peer0".into()),
            ]
        );
    }

    #[tokio::test]
    async fn r1_fails_when_a_list_does_not_follow_the_op() {
        let stuck = run_one("R1", |_, _, _, _, op| {
            if op["Kind"] == "ReplicatorList" {
                ok(json!({"Kind": "Replicators", "replicators": [
                    {"id": "peer0"}, {"id": "peer1"}, {"id": "peer2"}
                ]}))
            } else {
                status(200)
            }
        })
        .await;
        assert!(
            matches!(&stuck, Outcome::Fail { expected, got } if expected.contains("0 replicator") && expected.contains("ReplicatorDelete") && got.starts_with("1 in")),
            "{stuck:?}"
        );
    }

    /// While node 1 is stopped the relay answers `status` after `ms`.
    fn stopped_target(
        verbs: std::rc::Rc<std::cell::RefCell<Vec<Verb>>>,
        reply: Result<Reply>,
    ) -> Fake {
        let reply = std::cell::Cell::new(Some(reply));
        let seen = verbs.clone();
        let mut fake = Fake::new(move |_, target, _, _, op| {
            let down = seen.borrow().last() == Some(&Verb::Stop(1));
            if target == 1 && down {
                return reply.take().expect("one probe while stopped");
            }
            admin_view(op)
        });
        fake.verbs = verbs;
        fake
    }

    fn after(status: u16, ms: u64) -> Result<Reply> {
        Ok(Reply {
            status,
            body: json!({"error": "dial timeout"}),
            latency_ms: ms,
        })
    }

    #[tokio::test]
    async fn r3_wants_a_clean_400_within_the_dial_budget_then_a_restart() {
        let verbs = std::rc::Rc::default();
        let (outcome, seen) = run_fake("R3", stopped_target(verbs, after(400, 9_800))).await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(seen, [Verb::Stop(1), Verb::Start(1), Verb::Regrant(1)]);
    }

    #[tokio::test]
    async fn r3_fails_on_a_slow_error_a_hang_or_a_200_and_still_restarts() {
        let slow = run_fake("R3", stopped_target(Default::default(), after(400, 31_000))).await;
        assert!(
            matches!(&slow.0, Outcome::Fail { expected, got } if expected.contains("dial budget") && got.contains("31000 ms")),
            "{:?}",
            slow.0
        );
        assert_eq!(slow.1, [Verb::Stop(1), Verb::Start(1), Verb::Regrant(1)]);

        let hung = run_fake(
            "R3",
            stopped_target(Default::default(), Err(eyre::eyre!("operation timed out"))),
        )
        .await;
        assert!(
            matches!(&hung.0, Outcome::Fail { got, .. } if got.contains("timed out")),
            "{:?}",
            hung.0
        );
        assert_eq!(hung.1, [Verb::Stop(1), Verb::Start(1), Verb::Regrant(1)]);

        let served = run_fake("R3", stopped_target(Default::default(), after(200, 5))).await;
        assert!(
            matches!(&served.0, Outcome::Fail { expected, .. } if expected.starts_with("400")),
            "{:?}",
            served.0
        );
    }

    #[tokio::test]
    async fn r3_fails_when_the_restarted_target_refuses_admin_and_still_regrants() {
        let verbs: std::rc::Rc<std::cell::RefCell<Vec<Verb>>> = Default::default();
        let seen = verbs.clone();
        let mut fake = Fake::new(move |_, target, _, _, op| match seen.borrow().last() {
            Some(Verb::Stop(1)) if target == 1 => after(400, 9_800),
            Some(Verb::Start(1)) if target == 1 => status(403),
            _ => admin_view(op),
        });
        fake.verbs = verbs.clone();
        let (outcome, notes) = run_noted("R3", fake).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("restarted") && got.starts_with("403")),
            "{outcome:?}"
        );
        assert_eq!(
            notes,
            [
                "stopped target: 400 after 9800 ms, within the 15000 ms dial budget",
                "restarted target: FAIL expected 200 on admin CollectionList via the relay after the target restarted, got 403 null"
            ]
        );
        assert_eq!(
            *verbs.borrow(),
            [Verb::Stop(1), Verb::Start(1), Verb::Regrant(1)]
        );
    }

    #[tokio::test]
    async fn r3_notes_both_halves_and_gives_iroh_its_slow_dead_peer_dial() {
        let (outcome, notes) =
            run_noted("R3", stopped_target(Default::default(), after(400, 9_800))).await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(
            notes,
            [
                "stopped target: 400 after 9800 ms, within the 15000 ms dial budget",
                "restarted target: 200 on admin CollectionList via the relay"
            ]
        );

        let mut iroh = stopped_target(Default::default(), after(400, 31_000));
        iroh.transport = Transport::Iroh;
        let (outcome, notes) = run_noted("R3", iroh).await;
        assert_eq!(outcome, Outcome::Pass, "{notes:?}");
        assert_eq!(
            notes[0],
            "stopped target: 400 after 31000 ms, within the 35000 ms dial budget"
        );

        let mut iroh = stopped_target(Default::default(), after(400, 36_000));
        iroh.transport = Transport::Iroh;
        let (outcome, _) = run_noted("R3", iroh).await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, got } if expected.contains("35000 ms dial budget") && got.contains("36000 ms")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn r2_drops_the_relay_replicator_before_the_probe_and_restores_it() {
        let mut seen = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("R2", move |relay, target, _, actor, op| {
            tx.send((
                relay,
                target,
                actor,
                op["Kind"].as_str().unwrap().to_string(),
            ))
            .unwrap();
            admin_view(op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        seen.extend(rx.try_iter().skip_while(|s| s.3 == "CollectionList"));
        // The relay's own replicator is managed through the target as relay.
        assert_eq!(seen[0], (1, 0, Actor::Admin, "ReplicatorDelete".into()));
        assert_eq!(seen[1], (1, 0, Actor::Admin, "ReplicatorList".into()));
        assert!(seen
            .iter()
            .any(|s| s == &(0, 1, Actor::Admin, "CollectionAdd".into())));
        assert_eq!(
            seen.last().unwrap(),
            &(1, 0, Actor::Admin, "ReplicatorAdd".into())
        );
    }

    #[tokio::test]
    async fn r2_fails_when_the_relay_still_replicates_to_the_target() {
        let outcome = run_one("R2", |_, target, _, _, op| {
            if op["Kind"] == "ReplicatorList" && target == 0 {
                ok(json!({"Kind": "Replicators", "replicators": [{"id": "peer1", "collections": ["bafy-user"]}]}))
            } else {
                admin_view(op)
            }
        })
        .await;
        assert!(
            matches!(&outcome, Outcome::Fail { expected, .. } if expected.contains("no replicator")),
            "{outcome:?}"
        );
    }
}
