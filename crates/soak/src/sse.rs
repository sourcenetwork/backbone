//! GraphQL subscriptions over server-sent events, one per node.
//!
//! Both runtimes answer `POST /api/v0/graphql` with `Accept:
//! text/event-stream` for a `subscription { ... }` document. Each event's
//! `data:` payload is a GraphQL response carrying the docs that changed on
//! that node, including remote merges. The checker uses the arrivals for
//! lag samples with sub-second resolution and as its quiescence trigger.

use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::executor::now_ms;

/// A doc changed on `node`, per its subscription stream.
#[derive(Debug)]
pub struct Arrival {
    pub node: usize,
    pub doc_id: String,
    pub wall_ts_ms: u64,
}

/// Incremental server-sent-events parser: feed body chunks, get back the
/// `data` payload of every completed event. Multi-line `data:` fields are
/// joined with newlines; comment lines and other fields are ignored.
#[derive(Default)]
pub struct SseParser {
    buffer: String,
    data: Vec<String>,
}

impl SseParser {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        let mut out = Vec::new();
        while let Some(pos) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=pos).collect();
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                if !self.data.is_empty() {
                    out.push(std::mem::take(&mut self.data).join("\n"));
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.data
                    .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
        }
        out
    }
}

/// Every `_docID` string anywhere in a GraphQL payload.
fn doc_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            if let Some(id) = o.get("_docID").and_then(Value::as_str) {
                out.push(id.to_string());
            }
            o.values().for_each(|x| doc_ids(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| doc_ids(x, out)),
        _ => {}
    }
}

/// Keep a subscription open on `url`, reconnecting after any error or end
/// of stream (a restarted node), forwarding every changed doc as an
/// [`Arrival`]. Runs until the receiver is dropped.
pub async fn subscribe(
    node: usize,
    url: String,
    query: String,
    tx: mpsc::UnboundedSender<Arrival>,
) {
    let http = reqwest::Client::new();
    loop {
        let stream = http
            .post(format!("{url}/api/v0/graphql"))
            .header("Accept", "text/event-stream")
            .json(&json!({ "query": query }))
            .send()
            .await;
        if let Ok(resp) = stream {
            let mut parser = SseParser::default();
            let mut body = resp.bytes_stream();
            while let Some(Ok(chunk)) = body.next().await {
                for payload in parser.push(&chunk) {
                    let Ok(v) = serde_json::from_str::<Value>(&payload) else {
                        continue;
                    };
                    let mut ids = Vec::new();
                    doc_ids(&v, &mut ids);
                    let wall_ts_ms = now_ms();
                    for doc_id in ids {
                        if tx
                            .send(Arrival {
                                node,
                                doc_id,
                                wall_ts_ms,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        }
        if tx.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_event() {
        let mut p = SseParser::default();
        assert_eq!(p.push(b"data: {\"a\":1}\n\n"), vec!["{\"a\":1}"]);
    }

    #[test]
    fn two_events_in_one_chunk_and_comments_ignored() {
        let mut p = SseParser::default();
        let out = p.push(b": keepalive\ndata: x\n\nevent: next\ndata: y\n\n");
        assert_eq!(out, vec!["x", "y"]);
    }

    #[test]
    fn event_split_across_chunks() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: {\"a\":").is_empty());
        assert!(p.push(b"1}\n").is_empty());
        assert_eq!(p.push(b"\n"), vec!["{\"a\":1}"]);
    }

    #[test]
    fn multi_line_data_joined() {
        let mut p = SseParser::default();
        assert_eq!(p.push(b"data: a\ndata: b\n\n"), vec!["a\nb"]);
    }

    #[test]
    fn crlf_and_leading_space_variants() {
        let mut p = SseParser::default();
        assert_eq!(p.push(b"data:x\r\n\r\ndata: y\r\n\r\n"), vec!["x", "y"]);
    }

    #[test]
    fn doc_ids_found_anywhere() {
        let v =
            json!({"data": {"Users": [{"_docID": "a"}, {"_docID": "b", "x": {"_docID": "c"}}]}});
        let mut out = Vec::new();
        doc_ids(&v, &mut out);
        assert_eq!(out, vec!["a", "b", "c"]);
    }
}
