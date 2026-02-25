use std::time::Duration;

use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use super::types::BulletinPostEvent;

pub struct BulletinEventSubscription {
    ws_url: String,
}

impl BulletinEventSubscription {
    pub async fn connect(rpc_url: &str) -> Result<Self> {
        // Parse the RPC URL to extract host:port, then construct ws:// URL
        let url = rpc_url
            .strip_prefix("http://")
            .or_else(|| rpc_url.strip_prefix("https://"))
            .unwrap_or(rpc_url);

        let ws_url = format!("ws://{}/websocket", url);

        // Test connectivity by doing a quick connect/disconnect
        let (ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .map_err(|e| eyre!("failed to connect to WebSocket {}: {}", ws_url, e))?;
        drop(ws);

        Ok(Self { ws_url })
    }

    pub async fn wait_for_artifact(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<BulletinPostEvent> {
        let (mut ws, _) = tokio_tungstenite::connect_async(&self.ws_url)
            .await
            .map_err(|e| eyre!("failed to connect to WebSocket: {}", e))?;

        // Subscribe to Tx events
        let subscribe_msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "subscribe",
            "params": {"query": "tm.event='Tx'"},
            "id": 1
        });

        ws.send(Message::Text(subscribe_msg.to_string().into()))
            .await
            .map_err(|e| eyre!("failed to send subscribe: {}", e))?;

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(eyre!(
                    "timeout ({:?}) waiting for bulletin post event (session_id={})",
                    timeout,
                    session_id,
                ));
            }

            let msg = tokio::time::timeout(remaining, ws.next()).await;
            let msg = match msg {
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(e))) => return Err(eyre!("websocket error: {}", e)),
                Ok(None) => return Err(eyre!("websocket closed")),
                Err(_) => {
                    return Err(eyre!(
                        "timeout ({:?}) waiting for bulletin post event",
                        timeout
                    ))
                }
            };

            if let Message::Text(text) = &msg {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                    if let Some(event) = extract_bulletin_post_event(&json, session_id) {
                        return Ok(event);
                    }
                }
            }
        }
    }
}

fn extract_bulletin_post_event(
    msg: &serde_json::Value,
    _session_id: &str,
) -> Option<BulletinPostEvent> {
    // CometBFT event structure:
    // { "result": { "events": { "bulletin_post.post_id": ["..."], ... } } }
    let events = msg.pointer("/result/events")?;

    // Check for bulletin post events
    let post_ids = events
        .get("bulletin_post.post_id")
        .or_else(|| events.get("sourcehub.bulletin.v1beta1.EventBulletinPost.post_id"))
        .and_then(|v| v.as_array())?;

    let namespaces = events
        .get("bulletin_post.namespace")
        .or_else(|| events.get("sourcehub.bulletin.v1beta1.EventBulletinPost.namespace"))
        .and_then(|v| v.as_array());

    let post_id = post_ids.first()?.as_str()?;
    let namespace = namespaces
        .and_then(|ns| ns.first())
        .and_then(|v| v.as_str())
        .unwrap_or("orbis")
        .to_string();

    Some(BulletinPostEvent {
        post_id: post_id.to_string(),
        namespace,
    })
}
