//! Routing cases: the relay reaches the target whatever their relationship.

use eyre::Result;
use serde_json::json;

use super::actors::Actor;
use super::cases::{
    expect_status, fail, replicator_add, replicator_delete, replicators_for, Channel, COLLECTION,
};

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
    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::*;

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
}
