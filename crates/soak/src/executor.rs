//! Executes planned ops over HTTP GraphQL and appends one JSONL record each.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eyre::{Result, WrapErr};
use serde::Serialize;
use serde_json::{json, Value};

use crate::auth::{host_port, Identities, TokenCache};
use crate::generator::{Actor, OpKind, PlannedOp, Profile};

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
    /// Identity the request was sent as (`None` = anonymous / pre-ACP record).
    pub actor: Option<Actor>,
    /// `"http"` (GraphQL) or `"cli"` (grants go through the node binary).
    pub path: &'static str,
    /// Bytes of the GraphQL input this op sent; 0 for ops that send none
    /// (queries, grants, deletes).
    /// `#[serde(default)]` is a no-op today -- `OpRecord` only derives `Serialize` -- kept in case it gains `Deserialize`.
    #[serde(default)]
    pub payload_bytes: usize,
}

pub struct Executor {
    http: reqwest::Client,
    /// (name, api_url) per node index.
    nodes: Vec<(String, String)>,
    collection: String,
    encrypt_fields: Vec<String>,
    se_field: Option<String>,
    /// Slot -> docID learned from the create response.
    slots: Vec<Option<String>>,
    /// Bearer tokens per actor; `None` when the profile has no identities.
    tokens: Option<TokenCache>,
    /// Node binary per node index, for CLI-only ops (grants).
    binaries: Vec<PathBuf>,
    acp: bool,
    log: BufWriter<File>,
}

impl Executor {
    pub fn new(
        nodes: Vec<(String, String)>,
        profile: &Profile,
        identities: Option<Identities>,
        binaries: Vec<PathBuf>,
        log_path: &Path,
    ) -> Result<Self> {
        let log =
            File::create(log_path).wrap_err_with(|| format!("creating {}", log_path.display()))?;
        Ok(Self {
            http: http_client(Duration::from_secs(30)),
            nodes,
            collection: profile.collection.clone(),
            encrypt_fields: profile.encrypt_fields.clone(),
            se_field: profile.se_field.clone(),
            slots: Vec::new(),
            tokens: identities.map(TokenCache::new),
            binaries,
            acp: profile.is_acp(),
            log: BufWriter::new(log),
        })
    }

    /// Run one op against its node and log the record. `Err` only for log I/O.
    pub async fn execute(&mut self, op: &PlannedOp) -> Result<OpRecord> {
        if self.acp && op.kind == OpKind::Query {
            return self.viewer_query(op).await;
        }
        if op.kind == OpKind::Grant {
            return self.grant(op).await;
        }
        let (name, url) = &self.nodes[op.node];
        let col = &self.collection;
        let payload = op.payload.as_deref().unwrap_or("{}");
        let victim = op.slot.and_then(|s| self.slots.get(s).cloned().flatten());
        let expected: Vec<String> = op
            .expect_slots
            .iter()
            .filter_map(|s| self.slots.get(*s).cloned().flatten())
            .collect();
        let query = match op.kind {
            OpKind::Create => Some(create_mutation(col, payload, &self.encrypt_fields)),
            OpKind::Update => victim.as_ref().map(|id| {
                format!(
                    "mutation {{ update_{col}(docID: \"{id}\", input: {payload}) {{ _docID }} }}"
                )
            }),
            OpKind::Delete => victim
                .as_ref()
                .map(|id| format!("mutation {{ delete_{col}(docID: \"{id}\") {{ _docID }} }}")),
            OpKind::Query => Some(match &self.se_field {
                Some(field) => se_query(col, field, payload),
                None => format!("{{ {payload} }}"),
            }),
            OpKind::Grant => unreachable!("grants return early"),
        };
        let bearer = match (op.actor, self.tokens.as_mut()) {
            (Some(a), Some(t)) => t.bearer(a, url).map_err(|e| e.to_string()),
            _ => Ok(None),
        };

        let wall_ts_ms = now_ms();
        let started = Instant::now();
        let skipped = query.is_none();
        let outcome = match (query, bearer) {
            (Some(q), Ok(b)) => gql_as(&self.http, url, &q, b.as_deref()).await,
            (Some(_), Err(e)) => Err(e),
            (None, _) => Err("orphan: this slot's create failed".to_string()),
        };
        let latency_ms = started.elapsed().as_millis() as u64;

        let mut doc_id = victim;
        let (ok, error) = match outcome {
            Ok(data) => match op.kind {
                OpKind::Create => {
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
                // A docID the node does not hold yet (replication lag) is
                // not an error to either runtime: the reply is just empty.
                OpKind::Update | OpKind::Delete => {
                    let verb = if op.kind == OpKind::Update {
                        "update"
                    } else {
                        "delete"
                    };
                    let matched = match &data[format!("{verb}_{col}")] {
                        Value::Array(a) => a.len(),
                        Value::Object(_) => 1,
                        _ => 0,
                    };
                    if matched > 0 {
                        (true, None)
                    } else {
                        (
                            false,
                            Some("no doc matched on this node (not replicated yet?)".to_string()),
                        )
                    }
                }
                OpKind::Query => match &self.se_field {
                    Some(_) => se_verdict(&data, col, &expected),
                    None => (true, None),
                },
                OpKind::Grant => unreachable!("grants return early"),
            },
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
            actor: op.actor,
            path: "http",
            // Create/update send `payload` as the mutation's input object;
            // delete and plain query send no document payload.
            payload_bytes: match op.kind {
                OpKind::Create | OpKind::Update => payload.len(),
                _ => 0,
            },
        };
        self.write(&record)?;
        Ok(record)
    }

    /// Read the victim as owner, reader and anonymous on `op.node`; ok iff every
    /// read answered (the visibility itself is the checker's judgement). On
    /// success `error` carries the observed views so `ops.jsonl` records them.
    async fn viewer_query(&mut self, op: &PlannedOp) -> Result<OpRecord> {
        let (name, url) = self.nodes[op.node].clone();
        let wall_ts_ms = now_ms();
        let started = Instant::now();
        let victim = op.slot.and_then(|s| self.slots.get(s).cloned().flatten());
        let (ok, skipped, error) = match (&victim, self.tokens.as_mut()) {
            (None, _) => (
                false,
                true,
                Some("orphan: this slot's create failed".to_string()),
            ),
            (_, None) => (
                false,
                false,
                Some("viewer query without identities".to_string()),
            ),
            (Some(id), Some(tokens)) => {
                let q = format!(
                    "{{ {}(filter: {{_docID: {{_eq: \"{id}\"}}}}) {{ _docID }} }}",
                    self.collection
                );
                let mut seen = Vec::new();
                let mut err = None;
                for actor in [Actor::Owner, Actor::Reader, Actor::Anon] {
                    match tokens.bearer(actor, &url).map_err(|e| e.to_string()) {
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                        Ok(b) => match gql_as(&self.http, &url, &q, b.as_deref()).await {
                            Ok(data) => {
                                seen.push(data[&self.collection].as_array().map_or(0, Vec::len) > 0)
                            }
                            Err(e) => {
                                err = Some(format!("{actor:?}: {e}"));
                                break;
                            }
                        },
                    }
                }
                match err {
                    Some(e) => (false, false, Some(e)),
                    None => (true, false, Some(views_line(&seen))),
                }
            }
        };
        let record = OpRecord {
            op_index: op.index,
            virtual_ts_ms: op.virtual_ts_ms,
            wall_ts_ms,
            node: name,
            kind: op.kind,
            collection: self.collection.clone(),
            doc_id: victim,
            ok,
            skipped,
            error,
            latency_ms: started.elapsed().as_millis() as u64,
            actor: None,
            path: "http",
            // Viewer query reads the victim by docID; it sends no document payload.
            payload_bytes: 0,
        };
        self.write(&record)?;
        Ok(record)
    }

    /// `acp document relationship add` through the node's CLI (no HTTP route in the harness).
    async fn grant(&mut self, op: &PlannedOp) -> Result<OpRecord> {
        let (name, url) = self.nodes[op.node].clone();
        let wall_ts_ms = now_ms();
        let started = Instant::now();
        let victim = op.slot.and_then(|s| self.slots.get(s).cloned().flatten());
        let ids = self.tokens.as_ref().map(|t| t.identities().clone());
        let (ok, skipped, error) = match (&victim, ids) {
            (None, _) => (
                false,
                true,
                Some("orphan: this slot's create failed".to_string()),
            ),
            (_, None) => (false, false, Some("grant without identities".to_string())),
            (Some(id), Some(ids)) => {
                let out = tokio::process::Command::new(&self.binaries[op.node])
                    .args([
                        "--url",
                        host_port(&url),
                        "client",
                        "-i",
                        &ids.owner.key_hex,
                        "acp",
                        "document",
                        "relationship",
                        "add",
                        "-c",
                        &self.collection,
                        "--docID",
                        id,
                        "-r",
                        "reader",
                        "-a",
                        &ids.reader.did,
                    ])
                    .output()
                    .await;
                match out {
                    Ok(o) if o.status.success() => (true, false, None),
                    Ok(o) => (
                        false,
                        false,
                        Some(format!(
                            "cli: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        )),
                    ),
                    Err(e) => (false, false, Some(format!("cli spawn: {e}"))),
                }
            }
        };
        let record = OpRecord {
            op_index: op.index,
            virtual_ts_ms: op.virtual_ts_ms,
            wall_ts_ms,
            node: name,
            kind: op.kind,
            collection: self.collection.clone(),
            doc_id: victim,
            ok,
            skipped,
            error,
            latency_ms: started.elapsed().as_millis() as u64,
            actor: Some(Actor::Owner),
            path: "cli",
            // Grant sends a relationship add via the CLI, not a document payload.
            payload_bytes: 0,
        };
        self.write(&record)?;
        Ok(record)
    }

    fn write(&mut self, record: &OpRecord) -> Result<()> {
        serde_json::to_writer(&mut self.log, record)?;
        self.log.write_all(b"\n")?;
        self.log.flush()?;
        Ok(())
    }
}

/// The `error` text of a successful viewer query: `[owner, reader, anon]` saw the doc.
pub fn views_line(seen: &[bool]) -> String {
    format!(
        "views owner={} reader={} anon={}",
        seen[0], seen[1], seen[2]
    )
}

/// `add_<col>` with the profile's `encryptFields:` list (unquoted names).
pub fn create_mutation(col: &str, payload: &str, encrypt_fields: &[String]) -> String {
    if encrypt_fields.is_empty() {
        format!("mutation {{ add_{col}(input: [{payload}]) {{ _docID }} }}")
    } else {
        format!(
            "mutation {{ add_{col}(input: [{payload}], encryptFields: [{}]) {{ _docID }} }}",
            encrypt_fields.join(", ")
        )
    }
}

/// Searchable-encryption equality query; the owner fans it to its replicators.
pub fn se_query(col: &str, field: &str, value: &str) -> String {
    format!("{{ encrypted_{col}(filter: {{{field}: {{_eq: \"{value}\"}}}}) {{ docIDs }} }}")
}

/// ok iff every expected docID is in the flattened `docIDs` of the reply.
pub fn se_verdict(data: &Value, col: &str, expected: &[String]) -> (bool, Option<String>) {
    let got: std::collections::HashSet<&str> = data[format!("encrypted_{col}")]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|row| row["docIDs"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .collect();
    let missing: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|id| !got.contains(id))
        .collect();
    if missing.is_empty() {
        return (true, None);
    }
    let mut shown: Vec<&str> = missing.iter().copied().take(5).collect();
    if missing.len() > 5 {
        shown.push("...");
    }
    (
        false,
        Some(format!(
            "se query missing {} of {} expected docIDs: {}",
            missing.len(),
            expected.len(),
            shown.join(", ")
        )),
    )
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A client whose requests fail after `timeout`; without one a request that
/// never completes stalls the workload loop for the rest of the run.
pub(crate) fn http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("reqwest client")
}

/// POST a GraphQL document to a node; transport and GraphQL errors become
/// a message so the caller can record them instead of failing the run.
pub async fn gql(http: &reqwest::Client, url: &str, query: &str) -> Result<Value, String> {
    gql_as(http, url, query, None).await
}

/// `gql` with an optional bearer token (identity-scoped request).
pub async fn gql_as(
    http: &reqwest::Client,
    url: &str,
    query: &str,
    bearer: Option<&str>,
) -> Result<Value, String> {
    let mut req = http
        .post(format!("{url}/api/v0/graphql"))
        .json(&json!({ "query": query }));
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.map_err(|e| format!("http: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("http body: {e}"))?;
    if !status.is_success() {
        let snippet: String = text.chars().take(200).collect();
        return Err(format!("http {status}: {snippet}"));
    }
    let body: Value = serde_json::from_str(&text).map_err(|e| format!("bad json: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gql_times_out_against_silent_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let http = http_client(Duration::from_secs(1));
        let started = Instant::now();
        let out =
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(gql(&http, &url, "{ __typename }"));
        let err = out.expect_err("a request nobody answers must fail");
        assert!(err.starts_with("http:"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn gql_as_reports_non_success_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let body = r#"{"error":"nope"}"#;
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
        });
        let http = http_client(Duration::from_secs(5));
        let out = tokio::runtime::Runtime::new().unwrap().block_on(gql_as(
            &http,
            &url,
            "{ __typename }",
            Some("bad"),
        ));
        let err = out.expect_err("a 403 must not parse as Ok");
        assert!(err.starts_with("http 403"), "{err}");
        assert!(err.contains("nope"), "{err}");
    }

    #[test]
    fn op_record_carries_payload_bytes() {
        let json = serde_json::to_value(OpRecord {
            op_index: 0,
            virtual_ts_ms: 0,
            wall_ts_ms: 0,
            node: "rust-0".into(),
            kind: OpKind::Create,
            collection: "Users".into(),
            doc_id: None,
            ok: true,
            skipped: false,
            error: None,
            latency_ms: 0,
            actor: None,
            path: "http",
            payload_bytes: 1234,
        })
        .unwrap();
        assert_eq!(json["payload_bytes"], 1234);
    }

    #[test]
    fn views_line_format() {
        assert_eq!(
            views_line(&[true, false, false]),
            "views owner=true reader=false anon=false"
        );
    }

    #[test]
    fn create_mutation_plain_and_encrypted() {
        assert_eq!(
            create_mutation("Users", "{a: 1}", &[]),
            "mutation { add_Users(input: [{a: 1}]) { _docID } }"
        );
        assert_eq!(
            create_mutation(
                "Vault",
                "{a: 1}",
                &["secret".to_string(), "pin".to_string()]
            ),
            "mutation { add_Vault(input: [{a: 1}], encryptFields: [secret, pin]) { _docID } }"
        );
    }

    #[test]
    fn se_query_string() {
        assert_eq!(
            se_query("Vault", "name", "name-07"),
            "{ encrypted_Vault(filter: {name: {_eq: \"name-07\"}}) { docIDs } }"
        );
    }

    #[test]
    fn se_verdict_subset_ok_missing_fails() {
        let data = json!({ "encrypted_Vault": [ { "docIDs": ["bae-a", "bae-b"] }, { "docIDs": ["bae-c"] } ] });
        let want = ["bae-a".to_string(), "bae-c".to_string()];
        assert_eq!(se_verdict(&data, "Vault", &want), (true, None));
        let want2 = ["bae-a".to_string(), "bae-z".to_string()];
        let (ok, err) = se_verdict(&data, "Vault", &want2);
        assert!(!ok);
        assert_eq!(
            err.as_deref(),
            Some("se query missing 1 of 2 expected docIDs: bae-z")
        );
        assert_eq!(
            se_verdict(&json!({ "encrypted_Vault": [] }), "Vault", &[]),
            (true, None)
        );
        let many: Vec<String> = (0..7).map(|i| format!("bae-m{i}")).collect();
        let (ok, err) = se_verdict(&json!({ "encrypted_Vault": [] }), "Vault", &many);
        assert!(!ok);
        assert_eq!(
            err.as_deref(),
            Some("se query missing 7 of 7 expected docIDs: bae-m0, bae-m1, bae-m2, bae-m3, bae-m4, ...")
        );
    }
}
