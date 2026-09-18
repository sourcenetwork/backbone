//! The case table and its runner. A case is one function with one
//! expectation; it speaks to the cluster only through [`Channel`], so the
//! runner and every case run against a scripted fake in the unit tests.
//! Each case restores what it changed.

use std::fmt;

use eyre::{ensure, Result};
use futures::future::LocalBoxFuture;
use serde::Serialize;
use serde_json::{json, Value};

use super::actors::Actor;
use super::client::Reply;

pub const COLLECTION: &str = "User";

/// One relayed request as the report records it.
#[derive(Clone, Debug, Serialize)]
pub struct OpRecord {
    pub relay: usize,
    pub target: usize,
    pub actor: Actor,
    pub kind: String,
    pub status: u16,
    pub latency_ms: u64,
    /// The target's list for the op's family after a mutate, as admin.
    pub target_state: Option<Value>,
}

/// Relay `op` through node `relay` to node `target` as `actor`.
pub trait Channel {
    fn addr(&self, node: usize) -> String;
    fn peer_id(&self, node: usize) -> String;
    fn send<'a>(
        &'a mut self,
        relay: usize,
        target: usize,
        actor: Actor,
        op: Value,
    ) -> LocalBoxFuture<'a, Result<Reply>>;
    /// The requests since the last call, for the report.
    fn take_records(&mut self) -> Vec<OpRecord> {
        Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome")]
pub enum Outcome {
    Pass,
    Fail { expected: String, got: String },
    Skip { reason: String },
    Infra { error: String },
}

/// An expectation miss, distinct from a harness fault: the runner turns it
/// into [`Outcome::Fail`] and any other error into [`Outcome::Infra`].
#[derive(Debug)]
pub struct Failed {
    pub expected: String,
    pub got: String,
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}, got {}", self.expected, self.got)
    }
}

impl std::error::Error for Failed {}

fn fail(expected: impl Into<String>, got: impl Into<String>) -> eyre::Report {
    Failed {
        expected: expected.into(),
        got: got.into(),
    }
    .into()
}

fn expect_status(r: &Reply, want: u16, what: &str) -> Result<()> {
    if r.status == want {
        Ok(())
    } else {
        Err(fail(
            format!("{want} on {what}"),
            format!("{} {}", r.status, r.body),
        ))
    }
}

/// Minimum Rust node count a case needs.
#[derive(Clone, Copy, Debug)]
pub struct Topo {
    pub min_rust: usize,
}

pub struct Case {
    pub name: &'static str,
    pub requires: Topo,
    pub run: for<'a> fn(&'a mut dyn Channel) -> LocalBoxFuture<'a, Result<()>>,
}

#[derive(Serialize)]
pub struct CaseReport {
    pub name: &'static str,
    pub outcome: Outcome,
    pub ops: Vec<OpRecord>,
}

pub fn all() -> Vec<Case> {
    let two = Topo { min_rust: 2 };
    vec![
        Case {
            name: "R2",
            requires: two,
            run: |ch| Box::pin(r2(ch)),
        },
        Case {
            name: "A2",
            requires: two,
            run: |ch| Box::pin(a2(ch)),
        },
        Case {
            name: "S1",
            requires: two,
            run: |ch| Box::pin(s1(ch)),
        },
    ]
}

/// `--cases R2,S1` in table order; `None` is every case.
pub fn select<'a>(all: &'a [Case], filter: Option<&str>) -> Result<Vec<&'a Case>> {
    let Some(filter) = filter else {
        return Ok(all.iter().collect());
    };
    let wanted: Vec<&str> = filter.split(',').map(str::trim).collect();
    for w in &wanted {
        ensure!(
            all.iter().any(|c| c.name == *w),
            "--cases: unknown case {w}"
        );
    }
    Ok(all.iter().filter(|c| wanted.contains(&c.name)).collect())
}

pub async fn run_all(ch: &mut dyn Channel, cases: &[&Case], rust_nodes: usize) -> Vec<CaseReport> {
    let mut reports = Vec::new();
    for case in cases {
        let outcome = if rust_nodes < case.requires.min_rust {
            Outcome::Skip {
                reason: format!(
                    "needs {} Rust nodes, topology has {rust_nodes}",
                    case.requires.min_rust
                ),
            }
        } else {
            match (case.run)(ch).await {
                Ok(()) => Outcome::Pass,
                Err(e) => match e.downcast_ref::<Failed>() {
                    Some(f) => Outcome::Fail {
                        expected: f.expected.clone(),
                        got: f.got.clone(),
                    },
                    None => Outcome::Infra {
                        error: format!("{e:#}"),
                    },
                },
            }
        };
        println!("case {}: {outcome:?}", case.name);
        reports.push(CaseReport {
            name: case.name,
            outcome,
            ops: ch.take_records(),
        });
    }
    reports
}

fn replicator_add(addr: &str) -> Value {
    json!({ "Kind": "ReplicatorAdd", "addresses": [addr], "collection_ids": [COLLECTION] })
}

fn replicator_delete(addr: &str) -> Value {
    json!({ "Kind": "ReplicatorDelete", "addresses": [addr], "collection_ids": [COLLECTION] })
}

/// Entries of a `Replicators` reply whose peer is `peer_id`. The relayed
/// body is the http crate's snake_case `ReplicatorInfo` (`id`, `address`,
/// `collections` as collection ids), not the p2p wire type.
fn replicators_for(body: &Value, peer_id: &str) -> usize {
    body["replicators"]
        .as_array()
        .map_or(0, |a| a.iter().filter(|r| r["id"] == peer_id).count())
}

/// R2: the relay (node 0) has no replicator to the target (node 1); an admin
/// op still dials and lands. The relay's replicator is dropped and restored
/// through the channel in the other direction.
async fn r2(ch: &mut dyn Channel) -> Result<()> {
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

/// Every mutate and query op, with a payload that deserializes at the relay.
fn every_op(relay_addr: &str) -> Vec<Value> {
    let doc =
        json!({ "collection": COLLECTION, "doc_id": "bae-00000000-0000-0000-0000-000000000000" });
    vec![
        replicator_add(relay_addr),
        replicator_delete(relay_addr),
        json!({ "Kind": "CollectionAdd", "collection_ids": [COLLECTION] }),
        json!({ "Kind": "CollectionRemove", "collection_ids": [COLLECTION] }),
        json!({ "Kind": "DocumentAdd", "docs": [doc] }),
        json!({ "Kind": "DocumentRemove", "docs": [doc] }),
        json!({ "Kind": "PeerConnect", "address": relay_addr }),
        json!({ "Kind": "PeerDisconnect", "address": relay_addr }),
        json!({ "Kind": "ReplicatorList" }),
        json!({ "Kind": "CollectionList" }),
        json!({ "Kind": "DocumentList" }),
    ]
}

/// The target's managed state as admin: replicators as (peer, collections),
/// subscriptions, tracked documents. Connection health fields are left out
/// so an idle status flip does not read as a change.
async fn managed_state(ch: &mut dyn Channel, relay: usize, target: usize) -> Result<Value> {
    let mut out = Vec::new();
    for kind in ["ReplicatorList", "CollectionList", "DocumentList"] {
        let r = ch
            .send(relay, target, Actor::Admin, json!({ "Kind": kind }))
            .await?;
        expect_status(&r, 200, &format!("{kind} as admin"))?;
        out.push(r.body);
    }
    let mut replicators: Vec<Value> = out[0]["replicators"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| json!([r["id"], r["collections"]]))
        .collect();
    replicators.sort_by_key(|v| v.to_string());
    Ok(json!({
        "replicators": replicators,
        "collections": out[1]["values"],
        "documents": out[2]["documents"],
    }))
}

/// A2: the outsider is refused on every op with 403 at the relay, and the
/// target's three lists are the same before and after.
async fn a2(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let before = managed_state(ch, relay, target).await?;
    for op in every_op(&ch.addr(relay)) {
        let kind = op["Kind"].as_str().unwrap_or_default().to_string();
        let r = ch.send(relay, target, Actor::Outsider, op).await?;
        expect_status(&r, 403, &format!("outsider {kind}"))?;
    }
    let after = managed_state(ch, relay, target).await?;
    if before != after {
        return Err(fail(
            format!("target state unchanged: {before}"),
            after.to_string(),
        ));
    }
    Ok(())
}

/// S1: `ReplicatorAdd` twice for the same peer leaves one entry. The mesh
/// replicator from the target to the relay is dropped first so the first
/// add is a real add; the second add restores the mesh.
async fn s1(ch: &mut dyn Channel) -> Result<()> {
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
    use super::*;

    type Rule = dyn FnMut(usize, usize, Actor, &Value) -> Result<Reply>;

    /// A channel that answers from a rule; `Err` from the rule is a
    /// transport fault.
    struct Fake(Box<Rule>);

    impl Channel for Fake {
        fn addr(&self, node: usize) -> String {
            format!("/ip4/127.0.0.1/tcp/{node}/p2p/peer{node}")
        }
        fn peer_id(&self, node: usize) -> String {
            format!("peer{node}")
        }
        fn send<'a>(
            &'a mut self,
            relay: usize,
            target: usize,
            actor: Actor,
            op: Value,
        ) -> LocalBoxFuture<'a, Result<Reply>> {
            let r = (self.0)(relay, target, actor, &op);
            Box::pin(async move { r })
        }
    }

    fn ok(body: Value) -> Result<Reply> {
        Ok(Reply {
            status: 200,
            body,
            latency_ms: 1,
        })
    }

    fn status(code: u16) -> Result<Reply> {
        Ok(Reply {
            status: code,
            body: Value::Null,
            latency_ms: 1,
        })
    }

    /// Admin sees a healthy mesh: node 1 replicates to node 0, subscribes to
    /// the collection, tracks no documents.
    fn admin_view(op: &Value) -> Result<Reply> {
        match op["Kind"].as_str().unwrap() {
            "ReplicatorList" => ok(json!({"Kind": "Replicators", "replicators": [
                {"id": "peer0", "address": "/ip4/127.0.0.1/tcp/0/p2p/peer0", "collections": ["bafy-user"]}
            ]})),
            "CollectionList" => ok(json!({"Kind": "Strings", "values": [COLLECTION]})),
            "DocumentList" => ok(json!({"Kind": "Documents", "documents": []})),
            _ => status(200),
        }
    }

    fn by_name(name: &str) -> Case {
        all().into_iter().find(|c| c.name == name).unwrap()
    }

    async fn run_one(
        name: &str,
        rule: impl FnMut(usize, usize, Actor, &Value) -> Result<Reply> + 'static,
    ) -> Outcome {
        let mut fake = Fake(Box::new(rule));
        let case = by_name(name);
        run_all(&mut fake, &[&case], 2).await.remove(0).outcome
    }

    #[tokio::test]
    async fn runner_classifies_pass_fail_infra_and_skip() {
        assert_eq!(
            run_one("R2", |_, _, _, op| admin_view(op)).await,
            Outcome::Pass
        );
        let failed = run_one("R2", |_, _, _, op| {
            if op["Kind"] == "CollectionAdd" {
                status(400)
            } else {
                admin_view(op)
            }
        })
        .await;
        assert!(
            matches!(&failed, Outcome::Fail { expected, got } if expected.starts_with("200") && got.starts_with("400")),
            "{failed:?}"
        );
        let infra = run_one("R2", |_, _, _, _| eyre::bail!("connection refused")).await;
        assert!(
            matches!(&infra, Outcome::Infra { error } if error.contains("refused")),
            "{infra:?}"
        );

        let mut fake = Fake(Box::new(|_, _, _, op| admin_view(op)));
        let three = Case {
            name: "X",
            requires: Topo { min_rust: 3 },
            run: |ch| Box::pin(r2(ch)),
        };
        let r = run_all(&mut fake, &[&three], 2).await.remove(0);
        assert!(matches!(r.outcome, Outcome::Skip { .. }), "{:?}", r.outcome);
    }

    #[tokio::test]
    async fn r2_drops_the_relay_replicator_before_the_probe_and_restores_it() {
        let mut seen = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("R2", move |relay, target, actor, op| {
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
        seen.extend(rx.try_iter());
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
        let outcome = run_one("R2", |_, target, _, op| {
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

    #[tokio::test]
    async fn a2_needs_403_on_every_op_and_unchanged_state() {
        let mut kinds = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("A2", move |_, _, actor, op| {
            if actor == Actor::Outsider {
                tx.send(op["Kind"].as_str().unwrap().to_string()).unwrap();
                status(403)
            } else {
                admin_view(op)
            }
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        kinds.extend(rx.try_iter());
        kinds.sort();
        assert_eq!(kinds.len(), 11, "{kinds:?}");
        assert!(
            kinds.contains(&"PeerDisconnect".to_string())
                && kinds.contains(&"DocumentList".to_string())
        );

        let leaked = run_one("A2", |_, _, actor, op| {
            if actor == Actor::Outsider && op["Kind"] == "CollectionAdd" {
                status(200)
            } else if actor == Actor::Outsider {
                status(403)
            } else {
                admin_view(op)
            }
        })
        .await;
        assert!(
            matches!(&leaked, Outcome::Fail { expected, got } if expected.contains("CollectionAdd") && got.starts_with("200")),
            "{leaked:?}"
        );

        let mut calls = 0;
        let drifted = run_one("A2", move |_, _, actor, op| {
            if actor == Actor::Outsider {
                return status(403);
            }
            if op["Kind"] == "CollectionList" {
                calls += 1;
                if calls > 1 {
                    return ok(json!({"Kind": "Strings", "values": []}));
                }
            }
            admin_view(op)
        })
        .await;
        assert!(
            matches!(&drifted, Outcome::Fail { expected, .. } if expected.contains("unchanged")),
            "{drifted:?}"
        );
    }

    #[tokio::test]
    async fn s1_adds_twice_and_wants_one_entry() {
        let mut adds = 0;
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("S1", move |_, _, _, op| {
            if op["Kind"] == "ReplicatorAdd" {
                adds += 1;
                tx.send(adds).unwrap();
            }
            admin_view(op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(rx.try_iter().last(), Some(2));

        let doubled = run_one("S1", |_, _, _, op| {
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

    #[test]
    fn select_keeps_table_order_and_rejects_unknown_names() {
        let table = all();
        let names = |v: Vec<&Case>| v.iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(names(select(&table, None).unwrap()), ["R2", "A2", "S1"]);
        assert_eq!(names(select(&table, Some("S1, R2")).unwrap()), ["R2", "S1"]);
        assert!(select(&table, Some("R2,Z9")).is_err());
    }
}
