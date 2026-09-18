//! State cases: what a mutate leaves in the target's lists.

use eyre::Result;
use serde_json::json;

use super::actors::Actor;
use super::cases::{
    expect_status, fail, replicator_add, replicator_delete, replicators_for, Channel,
};

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
    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::*;

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
}
