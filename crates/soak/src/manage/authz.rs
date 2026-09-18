//! Authorization cases: who the target lets do what, and when.

use eyre::Result;
use serde_json::json;

use super::actors::{Actor, OPERATOR_GRANTS};
use super::cases::{
    collection_add, collection_remove, every_op, expect_status, fail, managed_state, Channel, Verb,
    COLLECTION,
};

/// The NAC relation an op's permission is (`ManageMutateOp::permission`,
/// `ManageQueryOp::permission` and `NodePermission::as_str` in defradb.rs).
fn permission(kind: &str) -> &'static str {
    match kind {
        "ReplicatorAdd" => "add-p2p-replicator",
        "ReplicatorDelete" => "delete-p2p-replicator",
        "ReplicatorList" => "list-p2p-replicator",
        "CollectionAdd" => "add-p2p-collection",
        "CollectionRemove" => "delete-p2p-collection",
        "CollectionList" => "list-p2p-collection",
        "DocumentAdd" => "add-p2p-document",
        "DocumentRemove" => "delete-p2p-document",
        "DocumentList" => "list-p2p-document",
        "PeerConnect" => "connect-p2p-peer",
        "PeerDisconnect" => "disconnect-p2p-peer",
        other => unreachable!("{other} is not a manage op"),
    }
}

/// A1: `operator` tries every op; the ones its grants cover land, the rest
/// are refused. One row per op, every miss named with the grant it had.
pub(super) async fn a1(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let mut misses = Vec::new();
    let mut subscribed = false;
    for op in every_op(&ch.addr(relay)) {
        let kind = op["Kind"].as_str().unwrap_or_default().to_string();
        let relation = permission(&kind);
        let granted = OPERATOR_GRANTS.contains(&relation);
        let r = ch.send(relay, target, Actor::Operator, op).await?;
        if r.status != if granted { 200 } else { 403 } {
            misses.push(format!(
                "{kind}: {} {} with {relation} {}",
                r.status,
                r.body,
                if granted { "granted" } else { "not granted" }
            ));
        }
        subscribed |= kind == "CollectionAdd" && r.status == 200;
    }
    if subscribed {
        let r = ch
            .send(relay, target, Actor::Admin, collection_remove())
            .await?;
        expect_status(&r, 200, "CollectionRemove (restore)")?;
    }
    if misses.is_empty() {
        return Ok(());
    }
    Err(fail(
        format!(
            "200 on the ops {} cover, 403 on the rest",
            OPERATOR_GRANTS.join(" and ")
        ),
        misses.join("; "),
    ))
}

/// A2: the outsider is refused on every op with 403 at the relay, and the
/// target's three lists are the same before and after.
pub(super) async fn a2(ch: &mut dyn Channel) -> Result<()> {
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

/// A3: `operator` lands `CollectionAdd`, its grant is revoked on the
/// target, the same op is refused. The post-revoke op goes out even when
/// the first was refused, so the verdict says whether the revoke was
/// enforced, not enforced, or untested because the grant was inert. The
/// grant comes back either way.
pub(super) async fn a3(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let relation = permission("CollectionAdd");
    let actor = Actor::Operator;
    let node = target;
    let first = ch.send(relay, target, actor, collection_add()).await?;
    ch.control(Verb::Revoke {
        node,
        actor,
        relation,
    })
    .await?;
    let second = ch.send(relay, target, actor, collection_add()).await;
    ch.control(Verb::Grant {
        node,
        actor,
        relation,
    })
    .await?;
    let second = second?;
    if first.status == 200 || second.status == 200 {
        let r = ch
            .send(relay, target, Actor::Admin, collection_remove())
            .await?;
        expect_status(&r, 200, "CollectionRemove (restore)")?;
    }
    match (first.status, second.status) {
        (200, 403) => {
            ch.note("revoke enforced: 200 before, 403 after".into());
            Ok(())
        }
        (200, after) => Err(fail(
            format!("403 on operator CollectionAdd after revoking {relation}"),
            format!("{after} {}: revoke not enforced", second.body),
        )),
        (before, after) => Err(fail(
            format!("200 on operator CollectionAdd with {relation} granted, before the revoke"),
            format!(
                "{before} {} before, {after} after; revoke untested: pre-revoke op refused (grant inert, defect 1)",
                first.body
            ),
        )),
    }
}

/// A4: `outsider` is refused `CollectionAdd`, is granted its permission on
/// the target, the same op lands. The grant is revoked either way.
pub(super) async fn a4(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    let relation = permission("CollectionAdd");
    let first = ch
        .send(relay, target, Actor::Outsider, collection_add())
        .await?;
    expect_status(&first, 403, "outsider CollectionAdd before the grant")?;
    let actor = Actor::Outsider;
    let node = target;
    ch.control(Verb::Grant {
        node,
        actor,
        relation,
    })
    .await?;
    let second = ch
        .send(relay, target, Actor::Outsider, collection_add())
        .await;
    ch.control(Verb::Revoke {
        node,
        actor,
        relation,
    })
    .await?;
    let second = second?;
    if second.status == 200 {
        let r = ch
            .send(relay, target, Actor::Admin, collection_remove())
            .await?;
        expect_status(&r, 200, "CollectionRemove (restore)")?;
    }
    expect_status(
        &second,
        200,
        &format!("outsider CollectionAdd with {relation} granted"),
    )
}

/// A5: a token minted for node 1 is relayed by node 0 to node 2: refused
/// on audience (400, the token is malformed for node 2) and nothing lands.
pub(super) async fn a5(ch: &mut dyn Channel) -> Result<()> {
    let (relay, minted_for, target) = (0, 1, 2);
    let r = ch
        .send_for(relay, target, minted_for, Actor::Admin, collection_add())
        .await?;
    if r.status == 200 {
        let rm = ch
            .send(relay, target, Actor::Admin, collection_remove())
            .await?;
        expect_status(&rm, 200, "CollectionRemove (restore)")?;
    }
    if r.status != 400 || !r.body.to_string().contains("token") {
        return Err(fail(
            "400 with a token error on CollectionAdd carrying node 1's audience to node 2",
            format!("{} {}", r.status, r.body),
        ));
    }
    let list = ch
        .send(
            relay,
            target,
            Actor::Admin,
            json!({ "Kind": "CollectionList" }),
        )
        .await?;
    expect_status(&list, 200, "CollectionList as admin")?;
    if list.body["values"]
        .as_array()
        .is_some_and(|v| v.iter().any(|c| c == COLLECTION))
    {
        return Err(fail(
            format!("{COLLECTION} absent from node 2's CollectionList after the refused add"),
            list.body.to_string(),
        ));
    }
    Ok(())
}

/// A6: with NAC disabled on the target (its own `acp node disable`, as the
/// owner) the outsider's ops land; NAC comes back either way.
pub(super) async fn a6(ch: &mut dyn Channel) -> Result<()> {
    let (relay, target) = (0, 1);
    ch.control(Verb::Nac {
        node: target,
        on: false,
    })
    .await?;
    let ops = async {
        let r = ch
            .send(relay, target, Actor::Outsider, collection_add())
            .await?;
        expect_status(
            &r,
            200,
            "outsider CollectionAdd with NAC disabled on the target",
        )?;
        let r = ch
            .send(relay, target, Actor::Outsider, collection_remove())
            .await?;
        expect_status(
            &r,
            200,
            "outsider CollectionRemove with NAC disabled on the target",
        )
    }
    .await;
    ch.control(Verb::Nac {
        node: target,
        on: true,
    })
    .await?;
    ops
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use serde_json::Value;

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::super::client::Reply;
    use super::*;

    const ADD: &str = "add-p2p-collection";

    /// The target honours per-permission grants: `granted` decides the
    /// operator's ops, the outsider is always refused.
    fn by_grants(
        granted: &'static [&'static str],
    ) -> impl FnMut(usize, usize, usize, Actor, &Value) -> Result<Reply> {
        move |_, _, _, actor, op| {
            let kind = op["Kind"].as_str().unwrap();
            match actor {
                Actor::Admin => admin_view(op),
                Actor::Operator if granted.contains(&permission(kind)) => admin_view(op),
                _ => status(403),
            }
        }
    }

    #[tokio::test]
    async fn a1_sends_every_op_as_operator_and_wants_the_grants_honoured() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut grants = by_grants(OPERATOR_GRANTS);
        let outcome = run_one("A1", move |relay, target, aud, actor, op| {
            if actor == Actor::Operator {
                tx.send(op["Kind"].as_str().unwrap().to_string()).unwrap();
            }
            if actor == Actor::Admin && op["Kind"] == "CollectionRemove" {
                tx.send("restore".into()).unwrap();
            }
            grants(relay, target, aud, actor, op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        let rows: Vec<String> = rx.try_iter().collect();
        assert_eq!(rows.len(), 12, "{rows:?}");
        assert_eq!(rows.iter().filter(|r| *r == "restore").count(), 1);
        assert_eq!(rows.iter().filter(|r| *r == "CollectionAdd").count(), 1);
    }

    #[tokio::test]
    async fn a1_names_the_granted_permission_when_a_granted_op_is_refused() {
        let defect = run_one("A1", by_grants(&[])).await;
        let Outcome::Fail { expected, got } = &defect else {
            panic!("{defect:?}");
        };
        assert!(
            expected.contains(ADD) && expected.contains("403"),
            "{expected}"
        );
        assert!(
            got.contains("CollectionAdd: 403") && got.contains(&format!("{ADD} granted")),
            "{got}"
        );
        assert!(got.contains("ReplicatorList: 403"), "{got}");
        assert!(!got.contains("ReplicatorAdd"), "{got}");

        let leak = run_one("A1", |_, _, _, _, op| admin_view(op)).await;
        assert!(
            matches!(&leak, Outcome::Fail { got, .. } if got.contains("ReplicatorAdd: 200") && got.contains("add-p2p-replicator not granted")),
            "{leak:?}"
        );
    }

    /// A target that consults the live grants: the last verb decides. With
    /// `defect`, per-permission grants have no effect (the product today).
    fn live_grants(verbs: Rc<RefCell<Vec<Verb>>>, defect: bool) -> Fake {
        let seen = verbs.clone();
        let mut fake = Fake::new(move |_, _, _, actor, op| {
            if actor == Actor::Admin {
                return admin_view(op);
            }
            let last = seen.borrow().last().cloned();
            let granted = match (actor, last) {
                (Actor::Operator, Some(Verb::Revoke { .. })) => false,
                (Actor::Operator, _) => true,
                (Actor::Outsider, Some(Verb::Grant { .. })) => true,
                (Actor::Outsider, Some(Verb::Nac { on: false, .. })) => return admin_view(op),
                _ => false,
            };
            if granted && !defect {
                admin_view(op)
            } else {
                status(403)
            }
        });
        fake.verbs = verbs;
        fake
    }

    #[tokio::test]
    async fn a3_revokes_then_wants_a_403_and_restores_the_grant() {
        let verbs: Rc<RefCell<Vec<Verb>>> = Rc::default();
        let (outcome, notes) = run_noted("A3", live_grants(verbs.clone(), false)).await;
        assert_eq!(outcome, Outcome::Pass);
        assert_eq!(notes, ["revoke enforced: 200 before, 403 after"]);
        let revoke = Verb::Revoke {
            node: 1,
            actor: Actor::Operator,
            relation: ADD,
        };
        let grant = Verb::Grant {
            node: 1,
            actor: Actor::Operator,
            relation: ADD,
        };
        assert_eq!(*verbs.borrow(), [revoke.clone(), grant.clone()]);

        let (defect, verbs) = run_fake("A3", live_grants(Rc::default(), true)).await;
        assert!(
            matches!(&defect, Outcome::Fail { expected, got } if expected.contains(ADD) && expected.contains("before") && got.starts_with("403") && got.ends_with("revoke untested: pre-revoke op refused (grant inert, defect 1)")),
            "{defect:?}"
        );
        assert_eq!(verbs, [revoke, grant]);

        let (stale, verbs) = run_fake(
            "A3",
            Fake::new(|_, _, _, actor, op| {
                if actor == Actor::Admin {
                    admin_view(op)
                } else {
                    status(200)
                }
            }),
        )
        .await;
        assert!(
            matches!(&stale, Outcome::Fail { expected, got } if expected.contains("403") && expected.contains("revok") && got.ends_with("revoke not enforced")),
            "{stale:?}"
        );
        assert_eq!(verbs.len(), 2, "{verbs:?}");
    }

    #[tokio::test]
    async fn a4_grants_then_wants_a_200_and_revokes() {
        let (outcome, verbs) = run_fake("A4", live_grants(Rc::default(), false)).await;
        assert_eq!(outcome, Outcome::Pass);
        let grant = Verb::Grant {
            node: 1,
            actor: Actor::Outsider,
            relation: ADD,
        };
        let revoke = Verb::Revoke {
            node: 1,
            actor: Actor::Outsider,
            relation: ADD,
        };
        assert_eq!(verbs, [grant.clone(), revoke.clone()]);

        let (defect, verbs) = run_fake("A4", live_grants(Rc::default(), true)).await;
        assert!(
            matches!(&defect, Outcome::Fail { expected, got } if expected.contains(&format!("{ADD} granted")) && got.starts_with("403")),
            "{defect:?}"
        );
        assert_eq!(verbs, [grant, revoke]);
    }

    #[tokio::test]
    async fn a5_relays_node_1s_token_to_node_2_and_wants_a_token_error() {
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("A5", move |relay, target, aud, actor, op| {
            tx.send((
                relay,
                target,
                aud,
                actor,
                op["Kind"].as_str().unwrap().to_string(),
            ))
            .unwrap();
            if aud != target {
                return Ok(Reply {
                    status: 400,
                    body: json!({"error": "transport: actor token rejected: audience"}),
                    latency_ms: 1,
                });
            }
            if op["Kind"] == "CollectionList" {
                return ok(json!({"Kind": "Strings", "values": []}));
            }
            admin_view(op)
        })
        .await;
        assert_eq!(outcome, Outcome::Pass);
        let sent: Vec<_> = rx.try_iter().collect();
        assert_eq!(sent[0], (0, 2, 1, Actor::Admin, "CollectionAdd".into()));
        assert!(sent.iter().all(|s| s.0 == 0 && s.1 == 2), "{sent:?}");

        let leak = run_one("A5", |_, _, _, _, op| {
            if op["Kind"] == "CollectionList" {
                ok(json!({"Kind": "Strings", "values": [COLLECTION]}))
            } else {
                admin_view(op)
            }
        })
        .await;
        assert!(
            matches!(&leak, Outcome::Fail { expected, got } if expected.contains("400") && got.starts_with("200")),
            "{leak:?}"
        );
    }

    #[tokio::test]
    async fn a6_disables_nac_on_the_target_wants_outsider_ops_to_land_and_re_enables() {
        let (outcome, verbs) = run_fake("A6", live_grants(Rc::default(), false)).await;
        assert_eq!(outcome, Outcome::Pass);
        let off = Verb::Nac { node: 1, on: false };
        let on = Verb::Nac { node: 1, on: true };
        assert_eq!(verbs, [off.clone(), on.clone()]);

        let (refused, verbs) = run_fake(
            "A6",
            Fake::new(|_, _, _, actor, op| {
                if actor == Actor::Admin {
                    admin_view(op)
                } else {
                    status(403)
                }
            }),
        )
        .await;
        assert!(
            matches!(&refused, Outcome::Fail { expected, .. } if expected.contains("NAC disabled")),
            "{refused:?}"
        );
        assert_eq!(verbs, [off, on]);
    }

    #[tokio::test]
    async fn a2_needs_403_on_every_op_and_unchanged_state() {
        let mut kinds = Vec::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let outcome = run_one("A2", move |_, _, _, actor, op| {
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

        let leaked = run_one("A2", |_, _, _, actor, op| {
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
        let drifted = run_one("A2", move |_, _, _, actor, op| {
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
}
