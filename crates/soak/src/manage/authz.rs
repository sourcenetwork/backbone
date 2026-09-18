//! Authorization cases: who the target lets do what, and when.

use eyre::Result;

use super::actors::Actor;
use super::cases::{every_op, expect_status, fail, managed_state, Channel};

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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::cases::fake::*;
    use super::super::cases::Outcome;
    use super::*;

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
