//! The data plane the state, bounds and concurrency cases lean on:
//! documents in the suite's collection, written and listed over a node's
//! own HTTP API as the owner, and a wait for them to reach another node.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use eyre::Result;
use serde_json::Value;

use super::cases::{Channel, COLLECTION};

/// Polls of `converge`, half a second apart.
const SETTLE_POLLS: usize = 40;

/// Ids are content-derived, so every document gets a name of its own.
static NEXT_NAME: AtomicUsize = AtomicUsize::new(0);

pub(super) fn create_users(n: usize, age: i64) -> String {
    let first = NEXT_NAME.fetch_add(n, Ordering::Relaxed);
    let inputs: Vec<String> = (first..first + n)
        .map(|i| format!("{{name: \"u{i}\", age: {age}}}"))
        .collect();
    format!(
        "mutation {{ add_{COLLECTION}(input: [{}]) {{ _docID }} }}",
        inputs.join(", ")
    )
}

/// `age` is immutable (a filter field); an update touches `name`.
pub(super) fn update_user(id: &str, name: &str) -> String {
    format!(
        "mutation {{ update_{COLLECTION}(docID: \"{id}\", input: {{name: \"{name}\"}}) {{ _docID }} }}"
    )
}

pub(super) fn list_users() -> String {
    format!("{{ {COLLECTION} {{ _docID name }} }}")
}

/// The `_docID`s under `key` of a `data` object.
pub(super) fn ids_in(data: &Value, key: &str) -> Vec<String> {
    data[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["_docID"].as_str())
        .map(str::to_string)
        .collect()
}

/// The `name` of document `id` in a `list_users` reply; `None` when the
/// node does not have it.
pub(super) fn name_of(data: &Value, id: &str) -> Option<String> {
    data[COLLECTION]
        .as_array()?
        .iter()
        .find(|d| d["_docID"] == id)
        .map(|d| d["name"].as_str().unwrap_or_default().to_string())
}

/// Create `n` documents with `age` at `node`; their ids.
pub(super) async fn write_docs(
    ch: &dyn Channel,
    node: usize,
    n: usize,
    age: i64,
) -> Result<Vec<String>> {
    let data = ch.gql(node, create_users(n, age)).await?;
    Ok(ids_in(&data, &format!("add_{COLLECTION}")))
}

pub(super) async fn doc_ids(ch: &dyn Channel, node: usize) -> Result<Vec<String>> {
    Ok(ids_in(&ch.gql(node, list_users()).await?, COLLECTION))
}

/// Poll `node` with `query` until `done` holds of the data or the settle
/// window passes; the data at the end.
pub(super) async fn settle(
    ch: &dyn Channel,
    node: usize,
    query: &str,
    done: impl Fn(&Value) -> bool,
) -> Result<Value> {
    for poll in 0..SETTLE_POLLS {
        let data = ch.gql(node, query.to_string()).await?;
        if done(&data) || poll + 1 == SETTLE_POLLS {
            return Ok(data);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    unreachable!("SETTLE_POLLS is positive")
}

/// Poll `node` until it has every id in `want` or the settle window
/// passes; the ids it had at the end.
pub(super) async fn converge(
    ch: &dyn Channel,
    node: usize,
    want: &[String],
) -> Result<Vec<String>> {
    let data = settle(ch, node, &list_users(), |data| {
        let have = ids_in(data, COLLECTION);
        want.iter().all(|w| have.contains(w))
    })
    .await?;
    Ok(ids_in(&data, COLLECTION))
}

#[cfg(test)]
pub(super) mod fake {
    use serde_json::json;

    use super::*;

    /// A data plane where a write at any node is on every node at once,
    /// except node 0, which sees a document only if `sink_sees(age)`.
    /// `add_` mints ids, `update_` renames, a query lists.
    pub fn store(
        sink_sees: impl Fn(i64) -> bool + 'static,
    ) -> impl FnMut(usize, &str) -> Result<Value> {
        let quoted = |rest: &str| rest.split('"').next().unwrap_or_default().to_string();
        let mut docs: Vec<(String, String, i64)> = Vec::new();
        move |node, q| {
            if q.starts_with("mutation { add_") {
                let ids: Vec<Value> = q
                    .split("name: \"")
                    .skip(1)
                    .map(|rest| {
                        let age = rest
                            .split("age: ")
                            .nth(1)
                            .unwrap()
                            .chars()
                            .take_while(char::is_ascii_digit)
                            .collect::<String>()
                            .parse()
                            .unwrap();
                        let id = format!("bae-{}", docs.len());
                        docs.push((id.clone(), quoted(rest), age));
                        json!({ "_docID": id })
                    })
                    .collect();
                return Ok(json!({ format!("add_{COLLECTION}"): ids }));
            }
            if q.starts_with("mutation { update_") {
                let id = quoted(q.split("docID: \"").nth(1).unwrap());
                let name = quoted(q.split("name: \"").nth(1).unwrap());
                if let Some(doc) = docs.iter_mut().find(|d| d.0 == id) {
                    doc.1 = name;
                }
                return Ok(json!({}));
            }
            let seen: Vec<Value> = docs
                .iter()
                .filter(|(_, _, age)| node != 0 || sink_sees(*age))
                .map(|(id, name, _)| json!({ "_docID": id, "name": name }))
                .collect();
            Ok(json!({ COLLECTION: seen }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::store;
    use super::*;

    #[test]
    fn mutations_and_ids() {
        let (a, b) = (create_users(2, 1), create_users(1, 1));
        assert!(
            a.starts_with("mutation { add_User(input: [{name: \"u"),
            "{a}"
        );
        assert!(a.ends_with(", age: 1}]) { _docID } }"), "{a}");
        let name = |m: &str| {
            m.split("name: ")
                .nth(1)
                .unwrap()
                .split('"')
                .nth(1)
                .unwrap()
                .to_string()
        };
        assert_ne!(name(&a), name(&b), "names never repeat: {a} / {b}");
        assert_eq!(
            update_user("bae-1", "x"),
            "mutation { update_User(docID: \"bae-1\", input: {name: \"x\"}) { _docID } }"
        );
        let mut s = store(|age| age == 1);
        let made = s(1, &create_users(2, 1)).unwrap();
        assert_eq!(ids_in(&made, "add_User"), ["bae-0", "bae-1"]);
        s(1, &create_users(1, 2)).unwrap();
        assert_eq!(
            ids_in(&s(1, &list_users()).unwrap(), COLLECTION),
            ["bae-0", "bae-1", "bae-2"]
        );
        assert_eq!(
            ids_in(&s(0, &list_users()).unwrap(), COLLECTION),
            ["bae-0", "bae-1"]
        );
        s(1, &update_user("bae-1", "x")).unwrap();
        let listed = s(0, &list_users()).unwrap();
        assert_eq!(name_of(&listed, "bae-1").as_deref(), Some("x"));
        assert!(name_of(&listed, "bae-0").unwrap().starts_with('u'));
        assert_eq!(name_of(&listed, "bae-2"), None);
    }
}
