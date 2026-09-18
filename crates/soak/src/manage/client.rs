//! One raw request on the P2P management channel: POST to a relay node's
//! `/api/v0/p2p/manage` (or `/manage/query` for the `*List` kinds) with
//! `{Target, AuthToken, Op}`. No retries, no interpretation (copy of the
//! integration tests' `post_manage`, tools/integration-test/tests/manage_relay_common.rs).

use std::time::Instant;

use eyre::{Result, WrapErr};
use serde::Serialize;
use serde_json::{json, Value};

use crate::auth::auth_token;

#[derive(Clone, Debug, Serialize)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub latency_ms: u64,
}

/// The `*List` kinds go to `/manage/query`; everything else mutates.
pub fn is_query(op: &Value) -> bool {
    op["Kind"].as_str().is_some_and(|k| k.ends_with("List"))
}

/// `courier_key` is the HTTP caller at the relay (needs `connect-p2p-peer`
/// there); `actor_token` is the relayed identity the target authorizes.
pub async fn post(
    http: &reqwest::Client,
    relay_url: &str,
    courier_key: &str,
    target_addr: &str,
    actor_token: &str,
    op: &Value,
) -> Result<Reply> {
    let route = if is_query(op) {
        "/api/v0/p2p/manage/query"
    } else {
        "/api/v0/p2p/manage"
    };
    let body = json!({ "Target": target_addr, "AuthToken": actor_token, "Op": op });
    let started = Instant::now();
    let resp = http
        .post(format!("{relay_url}{route}"))
        .bearer_auth(auth_token(courier_key, relay_url)?)
        .json(&body)
        .send()
        .await
        .wrap_err_with(|| format!("POST {route} at {relay_url}"))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    Ok(Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::String(text)),
        latency_ms: started.elapsed().as_millis() as u64,
    })
}
