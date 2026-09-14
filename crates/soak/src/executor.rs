//! Executes planned ops over HTTP GraphQL and appends one JSONL record each.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eyre::{Result, WrapErr};
use serde::Serialize;
use serde_json::{json, Value};

use crate::generator::{OpKind, PlannedOp};

/// One executed op. `wall_ts_ms`, `latency_ms` and `error` (runtime text,
/// e.g. Go's "did you mean" list is unordered) are the only fields a replay
/// may differ in.
#[derive(Debug, Serialize)]
pub struct OpRecord {
    pub op_index: u64,
    pub virtual_ts_ms: u64,
    pub wall_ts_ms: u64,
    pub node: String,
    pub kind: OpKind,
    pub collection: String,
    pub doc_id: Option<String>,
    pub ok: bool,
    /// The victim's create failed (its node was down), so there was nothing
    /// to update or delete; not an error of this op.
    pub skipped: bool,
    pub error: Option<String>,
    pub latency_ms: u64,
}

pub struct Executor {
    http: reqwest::Client,
    /// (name, api_url) per node index.
    nodes: Vec<(String, String)>,
    collection: String,
    /// Slot -> docID learned from the create response.
    slots: Vec<Option<String>>,
    log: BufWriter<File>,
}

impl Executor {
    pub fn new(nodes: Vec<(String, String)>, collection: &str, log_path: &Path) -> Result<Self> {
        let log =
            File::create(log_path).wrap_err_with(|| format!("creating {}", log_path.display()))?;
        Ok(Self {
            http: reqwest::Client::new(),
            nodes,
            collection: collection.to_string(),
            slots: Vec::new(),
            log: BufWriter::new(log),
        })
    }

    /// Run one op against its node and log the record. `Err` only for log I/O.
    pub async fn execute(&mut self, op: &PlannedOp) -> Result<OpRecord> {
        let (name, url) = &self.nodes[op.node];
        let col = &self.collection;
        let payload = op.payload.as_deref().unwrap_or("{}");
        let victim = op.slot.and_then(|s| self.slots.get(s).cloned().flatten());
        let query = match op.kind {
            OpKind::Create => Some(format!(
                "mutation {{ add_{col}(input: [{payload}]) {{ _docID }} }}"
            )),
            OpKind::Update => victim.as_ref().map(|id| {
                format!(
                    "mutation {{ update_{col}(docID: \"{id}\", input: {payload}) {{ _docID }} }}"
                )
            }),
            OpKind::Delete => victim
                .as_ref()
                .map(|id| format!("mutation {{ delete_{col}(docID: \"{id}\") {{ _docID }} }}")),
            OpKind::Query => Some(format!("{{ {payload} }}")),
        };

        let wall_ts_ms = now_ms();
        let started = Instant::now();
        let skipped = query.is_none();
        let outcome = match query {
            Some(q) => gql(&self.http, url, &q).await,
            None => Err("orphan: this slot's create failed".to_string()),
        };
        let latency_ms = started.elapsed().as_millis() as u64;

        let mut doc_id = victim;
        let (ok, error) = match outcome {
            Ok(data) if op.kind == OpKind::Create => {
                // Both runtimes answer `add_X` with a list; tolerate an object.
                let added = &data[format!("add_{col}")];
                let first = added.as_array().and_then(|a| a.first()).unwrap_or(added);
                doc_id = first["_docID"].as_str().map(String::from);
                match (&doc_id, op.slot) {
                    (Some(id), Some(slot)) => {
                        if self.slots.len() <= slot {
                            self.slots.resize(slot + 1, None);
                        }
                        self.slots[slot] = Some(id.clone());
                        (true, None)
                    }
                    _ => (false, Some("create returned no _docID".to_string())),
                }
            }
            Ok(_) => (true, None),
            Err(e) => (false, Some(e)),
        };

        let record = OpRecord {
            op_index: op.index,
            virtual_ts_ms: op.virtual_ts_ms,
            wall_ts_ms,
            node: name.clone(),
            kind: op.kind,
            collection: col.clone(),
            doc_id,
            ok,
            skipped,
            error,
            latency_ms,
        };
        serde_json::to_writer(&mut self.log, &record)?;
        self.log.write_all(b"\n")?;
        self.log.flush()?;
        Ok(record)
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// POST a GraphQL document to a node; transport and GraphQL errors become
/// a message so the caller can record them instead of failing the run.
pub async fn gql(http: &reqwest::Client, url: &str, query: &str) -> Result<Value, String> {
    let body: Value = http
        .post(format!("{url}/api/v0/graphql"))
        .json(&json!({ "query": query }))
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?
        .json()
        .await
        .map_err(|e| format!("bad json: {e}"))?;
    if let Some(errors) = body
        .get("errors")
        .and_then(Value::as_array)
        .filter(|e| !e.is_empty())
    {
        let msgs: Vec<&str> = errors
            .iter()
            .map(|e| e["message"].as_str().unwrap_or("?"))
            .collect();
        return Err(format!("graphql: {}", msgs.join("; ")));
    }
    Ok(body["data"].clone())
}
