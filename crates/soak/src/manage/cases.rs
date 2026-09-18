//! The case table and its runner. A case is one function with one
//! expectation; it speaks to the cluster only through [`Channel`], so the
//! runner and every case run against a scripted fake in the unit tests.
//! Each case restores what it changed. The cases live by group in
//! `routing.rs`, `authz.rs`, `state.rs`, `bounds.rs` and `partition.rs`.

use std::fmt;

use eyre::{eyre, Result};
use futures::future::{BoxFuture, LocalBoxFuture};
use serde::Serialize;
use serde_json::{json, Value};

use super::actors::Actor;
use super::client::Reply;
use super::data::list_users;
use super::{authz, bounds, partition, routing, state};
use crate::Transport;

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

/// A cluster verb a case needs beyond sending; the live channel maps each
/// to the harness, the fake records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verb {
    Stop(usize),
    Start(usize),
    /// The actors' grants on one node again, after a restart.
    Regrant(usize),
    Grant {
        node: usize,
        actor: Actor,
        relation: &'static str,
    },
    Revoke {
        node: usize,
        actor: Actor,
        relation: &'static str,
    },
    /// NAC on or off on one node, as the owner.
    Nac {
        node: usize,
        on: bool,
    },
    Partition(usize),
    Rejoin(usize),
    /// Freeze the node's process `delay_ms` from now, without waiting: its
    /// connections stay up, it reads nothing until `Resume`.
    PauseAfter {
        node: usize,
        delay_ms: u64,
    },
    Resume(usize),
    /// A replicator from `node` to `peer` through `node`'s own HTTP API as
    /// the owner, with the suite's collection and these filters.
    LocalReplicatorAdd {
        node: usize,
        peer: usize,
        filters: Value,
    },
}

/// Relay `op` through node `relay` to node `target` as `actor`. Sends
/// borrow the channel shared, so a case can hold two in flight at once.
pub trait Channel {
    fn len(&self) -> usize;
    fn transport(&self) -> Transport;
    fn addr(&self, node: usize) -> String;
    fn peer_id(&self, node: usize) -> String;
    /// `send` with the token minted for `audience` instead of the target.
    fn send_for<'a>(
        &'a self,
        relay: usize,
        target: usize,
        audience: usize,
        actor: Actor,
        op: Value,
    ) -> LocalBoxFuture<'a, Result<Reply>>;
    fn send<'a>(
        &'a self,
        relay: usize,
        target: usize,
        actor: Actor,
        op: Value,
    ) -> LocalBoxFuture<'a, Result<Reply>> {
        self.send_for(relay, target, target, actor, op)
    }
    fn control<'a>(&'a mut self, verb: Verb) -> LocalBoxFuture<'a, Result<()>>;
    /// GraphQL on `node`'s own HTTP API as the owner; the `data` object.
    /// Owned so a case can spawn it beside its ops.
    fn gql(&self, node: usize, query: String) -> BoxFuture<'static, Result<Value>>;
    fn can_partition(&self) -> bool;
    /// Something the report keeps beside the outcome: a mode the case
    /// observed and did not assert.
    fn note(&mut self, text: String);
    /// The requests since the last call, for the report.
    fn take_records(&mut self) -> Vec<OpRecord> {
        Vec::new()
    }
    fn take_notes(&mut self) -> Vec<String> {
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

pub(super) fn fail(expected: impl Into<String>, got: impl Into<String>) -> eyre::Report {
    Failed {
        expected: expected.into(),
        got: got.into(),
    }
    .into()
}

/// A case that cannot run here; the runner turns it into [`Outcome::Skip`].
#[derive(Debug)]
pub struct Skipped(pub String);

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "skipped: {}", self.0)
    }
}

impl std::error::Error for Skipped {}

pub(super) fn skip(reason: impl Into<String>) -> eyre::Report {
    Skipped(reason.into()).into()
}

pub(super) fn expect_status(r: &Reply, want: u16, what: &str) -> Result<()> {
    if r.status == want {
        Ok(())
    } else {
        Err(fail(
            format!("{want} on {what}"),
            format!("{} {}", r.status, r.body),
        ))
    }
}

/// Minimum Rust node count a case needs; the case uses nodes `0..min_rust`.
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
    pub notes: Vec<String>,
}

/// Cases a default selection leaves out; `--locate-size-bound` adds B3.
pub const OPT_IN: &[&str] = &["B3"];

/// The table, in the default order: the bounds group last, so a target
/// it wedges cannot poison the state, partition or concurrency cases.
pub fn all() -> Vec<Case> {
    let two = Topo { min_rust: 2 };
    let three = Topo { min_rust: 3 };
    vec![
        Case {
            name: "R1",
            requires: three,
            run: |ch| Box::pin(routing::r1(ch)),
        },
        Case {
            name: "R2",
            requires: two,
            run: |ch| Box::pin(routing::r2(ch)),
        },
        Case {
            name: "R3",
            requires: two,
            run: |ch| Box::pin(routing::r3(ch)),
        },
        Case {
            name: "A1",
            requires: two,
            run: |ch| Box::pin(authz::a1(ch)),
        },
        Case {
            name: "A2",
            requires: two,
            run: |ch| Box::pin(authz::a2(ch)),
        },
        Case {
            name: "A3",
            requires: two,
            run: |ch| Box::pin(authz::a3(ch)),
        },
        Case {
            name: "A4",
            requires: two,
            run: |ch| Box::pin(authz::a4(ch)),
        },
        Case {
            name: "A5",
            requires: three,
            run: |ch| Box::pin(authz::a5(ch)),
        },
        Case {
            name: "A6",
            requires: two,
            run: |ch| Box::pin(authz::a6(ch)),
        },
        Case {
            name: "S1",
            requires: two,
            run: |ch| Box::pin(state::s1(ch)),
        },
        Case {
            name: "S2",
            requires: two,
            run: |ch| Box::pin(state::s2(ch)),
        },
        Case {
            name: "S3",
            requires: two,
            run: |ch| Box::pin(state::s3(ch)),
        },
        Case {
            name: "S4",
            requires: two,
            run: |ch| Box::pin(state::s4(ch)),
        },
        Case {
            name: "P1",
            requires: two,
            run: |ch| Box::pin(partition::p1(ch)),
        },
        Case {
            name: "C1",
            requires: two,
            run: |ch| Box::pin(partition::c1(ch)),
        },
        Case {
            name: "B1",
            requires: two,
            run: |ch| Box::pin(bounds::b1(ch)),
        },
        Case {
            name: "B2",
            requires: three,
            run: |ch| Box::pin(bounds::b2(ch)),
        },
        Case {
            name: "B3",
            requires: two,
            run: |ch| Box::pin(bounds::b3(ch)),
        },
        Case {
            name: "B4",
            requires: three,
            run: |ch| Box::pin(bounds::b4(ch)),
        },
    ]
}

/// `--cases S1,R2` in the order given; `None` is every case but [`OPT_IN`]
/// in table order.
pub fn select<'a>(all: &'a [Case], filter: Option<&str>) -> Result<Vec<&'a Case>> {
    let Some(filter) = filter else {
        return Ok(all.iter().filter(|c| !OPT_IN.contains(&c.name)).collect());
    };
    filter
        .split(',')
        .map(str::trim)
        .map(|w| {
            all.iter()
                .find(|c| c.name == w)
                .ok_or_else(|| eyre!("--cases: unknown case {w}"))
        })
        .collect()
}

/// Before a case, the cheapest admin query to every node it uses: node 0
/// over its own HTTP as the owner, the rest through node 0 as relay. A
/// node that does not answer is named with the last case that used it,
/// so a wedge left behind reads as `Infra`, not as this case's `Fail`.
async fn unreachable(
    ch: &mut dyn Channel,
    case: &Case,
    last_touch: &[Option<&str>],
) -> Option<String> {
    for (node, touched) in last_touch.iter().enumerate().take(case.requires.min_rust) {
        let answered = if node == 0 {
            ch.gql(0, list_users())
                .await
                .map(drop)
                .map_err(|e| format!("{e:#}"))
        } else {
            match ch
                .send(0, node, Actor::Admin, json!({ "Kind": "CollectionList" }))
                .await
            {
                Ok(r) if r.status == 200 => Ok(()),
                Ok(r) => Err(format!(
                    "{} after {} ms: {}",
                    r.status, r.latency_ms, r.body
                )),
                Err(e) => Err(format!("{e:#}")),
            }
        };
        if let Err(why) = answered {
            ch.take_records();
            return Some(format!(
                "node {node} unreachable before {}; last case to touch it: {} ({why})",
                case.name,
                touched.unwrap_or("none")
            ));
        }
    }
    ch.take_records();
    None
}

pub async fn run_all(ch: &mut dyn Channel, cases: &[&Case], rust_nodes: usize) -> Vec<CaseReport> {
    let mut reports = Vec::new();
    let mut last_touch: Vec<Option<&str>> = vec![None; ch.len()];
    for case in cases {
        let outcome = if rust_nodes < case.requires.min_rust {
            Outcome::Skip {
                reason: format!(
                    "needs {} Rust nodes, topology has {rust_nodes}",
                    case.requires.min_rust
                ),
            }
        } else if let Some(error) = unreachable(ch, case, &last_touch).await {
            Outcome::Infra { error }
        } else {
            for touched in &mut last_touch[..case.requires.min_rust] {
                *touched = Some(case.name);
            }
            match (case.run)(ch).await {
                Ok(()) => Outcome::Pass,
                Err(e) => match (e.downcast_ref::<Failed>(), e.downcast_ref::<Skipped>()) {
                    (Some(f), _) => Outcome::Fail {
                        expected: f.expected.clone(),
                        got: f.got.clone(),
                    },
                    (_, Some(s)) => Outcome::Skip {
                        reason: s.0.clone(),
                    },
                    _ => Outcome::Infra {
                        error: format!("{e:#}"),
                    },
                },
            }
        };
        let notes = ch.take_notes();
        println!("case {}: {outcome:?} {}", case.name, notes.join("; "));
        reports.push(CaseReport {
            name: case.name,
            outcome,
            ops: ch.take_records(),
            notes,
        });
    }
    reports
}

pub(super) fn replicator_add(addr: &str) -> Value {
    json!({ "Kind": "ReplicatorAdd", "addresses": [addr], "collection_ids": [COLLECTION] })
}

pub(super) fn replicator_delete(addr: &str) -> Value {
    json!({ "Kind": "ReplicatorDelete", "addresses": [addr], "collection_ids": [COLLECTION] })
}

pub(super) fn collection_add() -> Value {
    json!({ "Kind": "CollectionAdd", "collection_ids": [COLLECTION] })
}

pub(super) fn collection_remove() -> Value {
    json!({ "Kind": "CollectionRemove", "collection_ids": [COLLECTION] })
}

/// Entries of a `Replicators` reply whose peer is `peer_id`. The relayed
/// body is the http crate's snake_case `ReplicatorInfo` (`id`, `address`,
/// `collections` as collection ids), not the p2p wire type.
pub(super) fn replicators_for(body: &Value, peer_id: &str) -> usize {
    body["replicators"]
        .as_array()
        .map_or(0, |a| a.iter().filter(|r| r["id"] == peer_id).count())
}

/// Every mutate and query op, with a payload that deserializes at the relay.
pub(super) fn every_op(relay_addr: &str) -> Vec<Value> {
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

/// The target's managed state as admin: replicators as (peer, collections,
/// filters), subscriptions, tracked documents. Connection health fields
/// are left out so an idle status flip does not read as a change.
pub(super) async fn managed_state(
    ch: &mut dyn Channel,
    relay: usize,
    target: usize,
) -> Result<Value> {
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
        .map(|r| json!([r["id"], r["collections"], r["filters"]]))
        .collect();
    replicators.sort_by_key(|v| v.to_string());
    Ok(json!({
        "replicators": replicators,
        "collections": out[1]["values"],
        "documents": out[2]["documents"],
    }))
}

/// A scripted channel for the case tests in every group.
#[cfg(test)]
pub(super) mod fake {
    use super::*;

    use std::cell::RefCell;
    use std::rc::Rc;

    /// `(relay, target, audience, actor, op)`.
    pub type Rule = dyn FnMut(usize, usize, usize, Actor, &Value) -> Result<Reply>;

    /// `(node, query)`.
    pub type GqlRule = dyn FnMut(usize, &str) -> Result<Value>;

    /// A channel that answers from a rule and records every verb; `Err`
    /// from the rule is a transport fault. Share `verbs` with the rule
    /// when a reply depends on a verb (a stopped node, a revoked grant).
    /// With `timed`, a reply arrives its `latency_ms` later in tokio time.
    /// `gql` answers the data plane `gql_ms` later, in tokio time; the
    /// default is an empty node answering at once.
    pub struct Fake {
        pub rule: RefCell<Box<Rule>>,
        pub timed: bool,
        pub gql: RefCell<Box<GqlRule>>,
        pub gql_ms: u64,
        pub verbs: Rc<RefCell<Vec<Verb>>>,
        pub notes: Vec<String>,
        pub partition: bool,
        pub transport: Transport,
    }

    impl Fake {
        pub fn new(
            rule: impl FnMut(usize, usize, usize, Actor, &Value) -> Result<Reply> + 'static,
        ) -> Self {
            Self {
                rule: RefCell::new(Box::new(rule)),
                timed: false,
                gql: RefCell::new(Box::new(|_, _| Ok(json!({ "User": [] })))),
                gql_ms: 0,
                verbs: Rc::default(),
                notes: Vec::new(),
                partition: true,
                transport: Transport::Libp2p,
            }
        }
    }

    impl Channel for Fake {
        fn len(&self) -> usize {
            3
        }
        fn transport(&self) -> Transport {
            self.transport
        }
        fn addr(&self, node: usize) -> String {
            format!("/ip4/127.0.0.1/tcp/{node}/p2p/peer{node}")
        }
        fn peer_id(&self, node: usize) -> String {
            format!("peer{node}")
        }
        fn send_for<'a>(
            &'a self,
            relay: usize,
            target: usize,
            audience: usize,
            actor: Actor,
            op: Value,
        ) -> LocalBoxFuture<'a, Result<Reply>> {
            let r = (self.rule.borrow_mut())(relay, target, audience, actor, &op);
            let delay = r
                .as_ref()
                .ok()
                .filter(|_| self.timed)
                .map(|r| std::time::Duration::from_millis(r.latency_ms));
            Box::pin(async move {
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                r
            })
        }
        fn control<'a>(&'a mut self, verb: Verb) -> LocalBoxFuture<'a, Result<()>> {
            self.verbs.borrow_mut().push(verb);
            Box::pin(async { Ok(()) })
        }
        fn gql(&self, node: usize, query: String) -> BoxFuture<'static, Result<Value>> {
            let r = (self.gql.borrow_mut())(node, &query);
            let delay = std::time::Duration::from_millis(self.gql_ms);
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                r
            })
        }
        fn can_partition(&self) -> bool {
            self.partition
        }
        fn note(&mut self, text: String) {
            self.notes.push(text);
        }
        fn take_notes(&mut self) -> Vec<String> {
            std::mem::take(&mut self.notes)
        }
    }

    pub fn ok(body: Value) -> Result<Reply> {
        Ok(Reply {
            status: 200,
            body,
            latency_ms: 1,
        })
    }

    pub fn status(code: u16) -> Result<Reply> {
        Ok(Reply {
            status: code,
            body: Value::Null,
            latency_ms: 1,
        })
    }

    /// Admin sees a healthy mesh: node 1 replicates to node 0, subscribes to
    /// the collection, tracks no documents.
    pub fn admin_view(op: &Value) -> Result<Reply> {
        match op["Kind"].as_str().unwrap() {
            "ReplicatorList" => ok(json!({"Kind": "Replicators", "replicators": [
                {"id": "peer0", "address": "/ip4/127.0.0.1/tcp/0/p2p/peer0", "collections": ["bafy-user"]}
            ]})),
            "CollectionList" => ok(json!({"Kind": "Strings", "values": [COLLECTION]})),
            "DocumentList" => ok(json!({"Kind": "Documents", "documents": []})),
            _ => status(200),
        }
    }

    pub fn by_name(name: &str) -> Case {
        all().into_iter().find(|c| c.name == name).unwrap()
    }

    /// Run `name` on a three-node fake; the outcome and the verbs it used.
    pub async fn run_fake(name: &str, mut fake: Fake) -> (Outcome, Vec<Verb>) {
        let case = by_name(name);
        let outcome = run_all(&mut fake, &[&case], 3).await.remove(0).outcome;
        let verbs = fake.verbs.borrow().clone();
        (outcome, verbs)
    }

    /// `run_fake`, with the notes the case recorded.
    pub async fn run_noted(name: &str, mut fake: Fake) -> (Outcome, Vec<String>) {
        let case = by_name(name);
        let report = run_all(&mut fake, &[&case], 3).await.remove(0);
        (report.outcome, report.notes)
    }

    pub async fn run_one(
        name: &str,
        rule: impl FnMut(usize, usize, usize, Actor, &Value) -> Result<Reply> + 'static,
    ) -> Outcome {
        run_fake(name, Fake::new(rule)).await.0
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    #[tokio::test]
    async fn runner_classifies_pass_fail_infra_and_skip() {
        assert_eq!(
            run_one("R2", |_, _, _, _, op| admin_view(op)).await,
            Outcome::Pass
        );
        let failed = run_one("R2", |_, _, _, _, op| {
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
        let infra = run_one("R2", |_, _, _, _, _| eyre::bail!("connection refused")).await;
        assert!(
            matches!(&infra, Outcome::Infra { error } if error.contains("refused")),
            "{infra:?}"
        );

        let mut fake = Fake::new(|_, _, _, _, op| admin_view(op));
        let three = Case {
            name: "X",
            requires: Topo { min_rust: 3 },
            run: |ch| Box::pin(routing::r2(ch)),
        };
        let r = run_all(&mut fake, &[&three], 2).await.remove(0);
        assert!(matches!(r.outcome, Outcome::Skip { .. }), "{:?}", r.outcome);

        let bowed_out = Case {
            name: "Y",
            requires: Topo { min_rust: 2 },
            run: |_| Box::pin(async { Err(skip("no partition here")) }),
        };
        let r = run_all(&mut fake, &[&bowed_out], 3).await.remove(0);
        assert_eq!(
            r.outcome,
            Outcome::Skip {
                reason: "no partition here".into()
            }
        );
    }

    #[tokio::test]
    async fn runner_reports_an_unreachable_node_as_infra_naming_the_last_case_to_touch_it() {
        // Node 1 stops answering once R2's restoring CollectionRemove has landed.
        let wedged = std::cell::Cell::new(false);
        let mut fake = Fake::new(move |_, target, _, _, op| {
            if target == 1 && wedged.get() {
                return Ok(Reply {
                    status: 400,
                    body: json!({"error": "dial error: timed out"}),
                    latency_ms: 30_012,
                });
            }
            wedged.set(wedged.get() || op["Kind"] == "CollectionRemove");
            admin_view(op)
        });
        let cases = [by_name("R2"), by_name("S1")];
        let reports = run_all(&mut fake, &[&cases[0], &cases[1]], 3).await;
        assert_eq!(reports[0].outcome, Outcome::Pass);
        assert_eq!(
            reports[1].outcome,
            Outcome::Infra {
                error: "node 1 unreachable before S1; last case to touch it: R2 (400 after 30012 ms: {\"error\":\"dial error: timed out\"})".into()
            }
        );

        let untouched = run_one("S1", |_, _, _, _, _| eyre::bail!("connection refused")).await;
        assert_eq!(
            untouched,
            Outcome::Infra {
                error:
                    "node 1 unreachable before S1; last case to touch it: none (connection refused)"
                        .into()
            }
        );
    }

    #[test]
    fn select_runs_bounds_last_by_default_keeps_the_given_order_and_rejects_unknown_names() {
        let table = all();
        let names = |v: Vec<&Case>| v.iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(
            names(select(&table, None).unwrap()),
            [
                "R1", "R2", "R3", "A1", "A2", "A3", "A4", "A5", "A6", "S1", "S2", "S3", "S4", "P1",
                "C1", "B1", "B2", "B4"
            ]
        );
        assert_eq!(names(select(&table, Some("S1, R2")).unwrap()), ["S1", "R2"]);
        assert_eq!(names(select(&table, Some("B3")).unwrap()), ["B3"]);
        assert!(select(&table, Some("R2,Z9")).is_err());
    }
}
