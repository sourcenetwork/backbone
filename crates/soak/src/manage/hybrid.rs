//! H1: Go nodes present as replication peers, never as manage targets (Go
//! has no manage protocol). The cases two Rust nodes can host run with the
//! Go nodes in the mesh, each its own row; H1's own row is about the Go
//! nodes: they converge on the source's documents after every writing
//! case, and their replicator sets are what the mesh gave them.

use eyre::Result;
use serde_json::{json, Value};

use super::cases::{self, fail, skip, Channel};
use super::data::{converge, doc_ids};

/// The rows H1 runs, in table order; `WRITERS` write at [`SOURCE`].
const EMBEDDED: &str = "R2,A1,A2,S1,S3,S4";
const WRITERS: &[&str] = &["S3", "S4"];
const SOURCE: usize = 1;

pub(super) async fn h1(ch: &mut dyn Channel) -> Result<()> {
    let go = ch.go_nodes();
    if go.is_empty() {
        return Err(skip("no Go nodes in the topology"));
    }
    let rust = ch.len();
    let peers = rust + go.len() - 1;
    let before = go_replicator_sets(ch, &go, peers)?;
    let table = cases::all();
    // Embedded rows drain the channel's notes; H1's own wait until the end.
    let mut notes = Vec::new();
    let mut verdict = Ok(());
    for case in cases::select(&table, Some(EMBEDDED))? {
        let rows = cases::run_all(ch, &[case], rust).await;
        ch.embed(rows);
        if WRITERS.contains(&case.name) {
            verdict = verdict.and(converged(ch, &go, case.name, &mut notes).await);
        }
    }
    for note in notes {
        ch.note(note);
    }
    verdict?;
    let after = go_replicator_sets(ch, &go, peers)?;
    if before != after {
        return Err(fail(
            format!("the Go nodes' replicator sets untouched: {before}"),
            after.to_string(),
        ));
    }
    Ok(())
}

/// Every Go node has exactly the source's documents within the settle
/// window; the counts are noted either way.
async fn converged(
    ch: &dyn Channel,
    go: &[usize],
    after: &str,
    notes: &mut Vec<String>,
) -> Result<()> {
    let want = doc_ids(ch, SOURCE).await?;
    let mut counts = Vec::new();
    let mut lagging = Vec::new();
    for &g in go {
        let have = converge(ch, g, &want).await?;
        counts.push(format!("go node {g} {}/{}", have.len(), want.len()));
        if have.len() != want.len() || !want.iter().all(|w| have.contains(w)) {
            lagging.push(counts.last().unwrap().clone());
        }
    }
    notes.push(format!("after {after}: {}", counts.join(", ")));
    if lagging.is_empty() {
        Ok(())
    } else {
        Err(fail(
            format!(
                "every Go node with the source's {} documents after {after}",
                want.len()
            ),
            lagging.join(", "),
        ))
    }
}

/// Each Go node's replicators as (peer id, collection ids), the fields a
/// manage op could change; the status fields flip on their own. The list
/// is the Go CLI's `client.Replicator` shape. The mesh gave every Go node
/// one replicator per peer; another count is a finding in its own right.
fn go_replicator_sets(ch: &dyn Channel, go: &[usize], peers: usize) -> Result<Value> {
    let mut sets = Vec::new();
    for &g in go {
        let list = ch.replicators(g)?;
        let mut set: Vec<Value> = list
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let mut cols = r["CollectionIDs"].as_array().cloned().unwrap_or_default();
                cols.sort_by_key(|v| v.to_string());
                json!([r["ID"], cols])
            })
            .collect();
        set.sort_by_key(|v| v.to_string());
        if set.len() != peers {
            return Err(fail(
                format!("go node {g} with the mesh's {peers} replicators"),
                format!("{} in {list}", set.len()),
            ));
        }
        sets.push(json!({ "node": g, "replicators": set }));
    }
    Ok(Value::Array(sets))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::super::cases::fake::*;
    use super::super::cases::{run_all, CaseReport, Outcome};
    use super::super::data::fake::store;
    use super::*;

    /// A Go node's list on the three-Rust, two-Go fake: one per peer.
    fn go_mesh() -> Value {
        json!([{"ID": "peer0", "CollectionIDs": ["bafy-user"], "Status": 1},
               {"ID": "peer1", "CollectionIDs": ["bafy-user"], "Status": 0},
               {"ID": "peer2", "CollectionIDs": ["bafy-user"], "Status": 0},
               {"ID": "peer9", "CollectionIDs": ["bafy-user"], "Status": 0}])
    }

    fn hybrid(sees: impl Fn(usize) -> bool + 'static) -> Fake {
        let mut fake = Fake::new(|_, _, _, _, op| admin_view(op));
        fake.go = vec![3, 4];
        fake.own = RefCell::new(Box::new(|_| Ok(go_mesh())));
        let mut inner = store(|age| age == 1);
        fake.gql = RefCell::new(Box::new(move |node, q| {
            if !sees(node) && !q.starts_with("mutation") {
                return Ok(json!({ "User": [] }));
            }
            inner(node, q)
        }));
        fake
    }

    /// H1's rows: the embedded ones, then its own.
    async fn run_h1(mut fake: Fake) -> Vec<CaseReport> {
        run_all(&mut fake, &[&by_name("H1")], 3).await
    }

    #[tokio::test]
    async fn h1_skips_without_go_nodes() {
        let rows = run_h1(Fake::new(|_, _, _, _, op| admin_view(op))).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].outcome,
            Outcome::Skip {
                reason: "no Go nodes in the topology".into()
            }
        );
    }

    #[tokio::test]
    async fn h1_embeds_the_two_node_cases_and_notes_the_go_counts_after_each_writer() {
        let rows = run_h1(hybrid(|_| true)).await;
        let names: Vec<_> = rows.iter().map(|r| r.name).collect();
        assert_eq!(names, ["R2", "A1", "A2", "S1", "S3", "S4", "H1"]);
        let h1 = rows.last().unwrap();
        assert_eq!(h1.outcome, Outcome::Pass, "{:?}", h1.notes);
        assert_eq!(
            h1.notes,
            [
                "after S3: go node 3 4/4, go node 4 4/4",
                "after S4: go node 3 5/5, go node 4 5/5"
            ]
        );
        assert!(
            rows[5].notes.is_empty(),
            "S4 kept H1's note: {:?}",
            rows[5].notes
        );
    }

    #[tokio::test(start_paused = true)]
    async fn h1_fails_when_a_go_node_lags_after_the_settle_window() {
        let rows = run_h1(hybrid(|node| node != 4)).await;
        assert_eq!(rows.len(), 7, "every row still runs");
        let h1 = rows.last().unwrap();
        assert!(
            matches!(&h1.outcome, Outcome::Fail { expected, got } if expected == "every Go node with the source's 4 documents after S3" && got == "go node 4 0/4"),
            "{:?}",
            h1.outcome
        );
        assert_eq!(
            h1.notes,
            [
                "after S3: go node 3 4/4, go node 4 0/4",
                "after S4: go node 3 5/5, go node 4 0/5"
            ]
        );
    }

    #[tokio::test]
    async fn h1_fails_when_a_go_replicator_set_changed_and_ignores_status_flips() {
        let mut fake = hybrid(|_| true);
        let reads = std::cell::Cell::new(0);
        fake.own = RefCell::new(Box::new(move |node| {
            reads.set(reads.get() + 1);
            let mut list = go_mesh();
            list[0]["Status"] = json!(reads.get());
            if node == 4 && reads.get() > 2 {
                list[0]["CollectionIDs"] = json!(["bafy-other"]);
            }
            Ok(list)
        }));
        let rows = run_h1(fake).await;
        let outcome = &rows.last().unwrap().outcome;
        assert!(
            matches!(outcome, Outcome::Fail { expected, got } if expected.starts_with("the Go nodes' replicator sets untouched") && got.contains(r#"{"node":4,"replicators":[["peer0",["bafy-other"]],["peer1",["bafy-user"]]"#)),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn h1_fails_when_a_go_node_does_not_show_the_mesh() {
        let mut fake = hybrid(|_| true);
        fake.own = RefCell::new(Box::new(|node| {
            Ok(if node == 3 { json!([]) } else { go_mesh() })
        }));
        let rows = run_h1(fake).await;
        assert_eq!(
            rows.last().unwrap().outcome,
            Outcome::Fail {
                expected: "go node 3 with the mesh's 4 replicators".into(),
                got: "0 in []".into()
            }
        );
    }
}
