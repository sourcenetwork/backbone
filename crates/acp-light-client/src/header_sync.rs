//! WebSocket header subscription and tracking.
//!
//! Subscribes to `eth_subscribe("headers")` and maintains a view of the
//! latest finalized block height and module state root. Validates header
//! chain continuity (sequential heights, parent_hash linkage).

use alloy_primitives::B256;
use eyre::WrapErr;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use crate::types::GossipHeader;

/// Snapshot of the latest finalized state tracked by header sync.
#[derive(Debug, Clone)]
pub struct SyncState {
    pub height: u64,
    pub module_state_root: B256,
    pub block_hash: B256,
}

/// Tracks the latest finalized header state from WebSocket subscription.
///
/// Spawns a background task that subscribes to `eth_subscribe("headers")`,
/// validates header chain continuity, and updates the latest finalized
/// `(height, module_state_root)`.
pub struct HeaderChain {
    state: Arc<RwLock<Option<SyncState>>>,
    notify: Arc<tokio::sync::Notify>,
    _handle: tokio::task::JoinHandle<()>,
}

impl HeaderChain {
    /// Connect to a hub.rs node's WebSocket endpoint and start syncing headers.
    pub async fn connect(ws_url: &str) -> eyre::Result<Self> {
        let state: Arc<RwLock<Option<SyncState>>> = Arc::new(RwLock::new(None));
        let notify = Arc::new(tokio::sync::Notify::new());

        let state_clone = state.clone();
        let notify_clone = notify.clone();
        let ws_url = ws_url.to_string();

        let handle = tokio::spawn(async move {
            if let Err(e) = run_header_loop(&ws_url, state_clone, notify_clone).await {
                warn!("header sync loop exited: {e}");
            }
        });

        Ok(Self {
            state,
            notify,
            _handle: handle,
        })
    }

    /// Current sync state, or `None` if no header has been received yet.
    pub fn state(&self) -> Option<SyncState> {
        self.state.read().clone()
    }

    /// Latest finalized height, or 0 if not yet synced.
    pub fn latest_height(&self) -> u64 {
        self.state.read().as_ref().map_or(0, |s| s.height)
    }

    /// Latest finalized module state root.
    pub fn latest_module_state_root(&self) -> Option<B256> {
        self.state.read().as_ref().map(|s| s.module_state_root)
    }

    /// Wait until the finalized height reaches at least `target`.
    pub async fn wait_for_height(
        &self,
        target: u64,
        timeout: std::time::Duration,
    ) -> eyre::Result<SyncState> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(state) = self.state() {
                if state.height >= target {
                    return Ok(state);
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(eyre::eyre!(
                    "timeout waiting for height {target} (current: {})",
                    self.latest_height()
                ));
            }
            tokio::time::timeout(remaining, self.notify.notified())
                .await
                .ok();
        }
    }

    /// Wait until the module state root changes from `previous`.
    pub async fn wait_for_root_change(
        &self,
        previous: B256,
        timeout: std::time::Duration,
    ) -> eyre::Result<SyncState> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(state) = self.state() {
                if state.module_state_root != previous {
                    return Ok(state);
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(eyre::eyre!("timeout waiting for module_state_root change"));
            }
            tokio::time::timeout(remaining, self.notify.notified())
                .await
                .ok();
        }
    }
}

impl Drop for HeaderChain {
    fn drop(&mut self) {
        self._handle.abort();
    }
}

async fn run_header_loop(
    ws_url: &str,
    state: Arc<RwLock<Option<SyncState>>>,
    notify: Arc<tokio::sync::Notify>,
) -> eyre::Result<()> {
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .wrap_err("connecting to hub.rs WebSocket")?;

    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_subscribe",
        "params": ["headers"],
        "id": 1,
    });
    ws.send(Message::Text(subscribe_msg.to_string().into()))
        .await
        .wrap_err("sending eth_subscribe")?;

    loop {
        let msg = ws.next().await;
        let msg = match msg {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => return Err(eyre::eyre!("websocket error: {e}")),
            None => return Err(eyre::eyre!("websocket closed")),
        };

        if let Message::Text(ref text) = msg {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                if let Some(header) = extract_header(&json) {
                    let prev = state.read().clone();

                    if let Some(ref prev) = prev {
                        if header.height <= prev.height {
                            continue;
                        }
                        if header.height != prev.height + 1 {
                            warn!(
                                "header gap: expected {} got {}",
                                prev.height + 1,
                                header.height
                            );
                        }
                        if header.parent_hash != prev.block_hash {
                            warn!(
                                "parent_hash mismatch at height {}: expected {}, got {}",
                                header.height, prev.block_hash, header.parent_hash
                            );
                        }
                    }

                    debug!(
                        height = header.height,
                        module_state_root = %header.module_state_root,
                        "new finalized header"
                    );

                    *state.write() = Some(SyncState {
                        height: header.height,
                        module_state_root: header.module_state_root,
                        block_hash: header.block_hash,
                    });
                    notify.notify_waiters();
                }
            }
        }
    }
}

fn extract_header(msg: &serde_json::Value) -> Option<GossipHeader> {
    // eth_subscription notification format:
    // {"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"...","result":{...}}}
    let result = msg.pointer("/params/result")?;
    serde_json::from_value(result.clone()).ok()
}
