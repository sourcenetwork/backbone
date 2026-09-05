//! WebSocket header subscription and tracking.
//!
//! Subscribes to `eth_subscribe("headers")` and maintains a view of the
//! latest finalized revision after checking its certificate against a configured key.

use alloy_primitives::B256;
use eyre::WrapErr;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use crate::{proof_client::ProofClient, types::GossipHeader};

/// Snapshot of the latest finalized state tracked by header sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub height: u64,
    pub module_state_root: B256,
    pub block_hash: B256,
}

/// Tracks the latest finalized header state from WebSocket subscription.
///
/// Spawns a background task that subscribes to `eth_subscribe("headers")`,
/// authenticates the requested light blocks, and updates the latest finalized
/// `(height, module_state_root)`.
pub struct HeaderChain {
    state: Arc<RwLock<Option<SyncState>>>,
    notify: Arc<tokio::sync::Notify>,
    _handle: tokio::task::JoinHandle<()>,
}

impl HeaderChain {
    /// Connect to a hub.rs node's WebSocket endpoint and start syncing headers.
    pub async fn connect(ws_url: &str, proof_client: ProofClient) -> eyre::Result<Self> {
        let state: Arc<RwLock<Option<SyncState>>> = Arc::new(RwLock::new(None));
        let notify = Arc::new(tokio::sync::Notify::new());

        let state_clone = state.clone();
        let notify_clone = notify.clone();
        let ws_url = ws_url.to_string();

        let handle = tokio::spawn(async move {
            loop {
                if let Err(e) =
                    run_header_loop(&ws_url, &proof_client, &state_clone, &notify_clone).await
                {
                    warn!("header sync disconnected: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
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
            tokio::time::timeout(remaining, notified).await.ok();
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
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(state) = self.state() {
                if state.module_state_root != previous {
                    return Ok(state);
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(eyre::eyre!("timeout waiting for module_state_root change"));
            }
            tokio::time::timeout(remaining, notified).await.ok();
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
    proof_client: &ProofClient,
    state: &RwLock<Option<SyncState>>,
    notify: &tokio::sync::Notify,
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
                    if state
                        .read()
                        .as_ref()
                        .is_some_and(|prev| header.height <= prev.height)
                    {
                        continue;
                    }
                    match authenticate_header(proof_client, &header).await {
                        Ok(verified) => {
                            debug!(height = verified.height, "verified finalized revision");
                            *state.write() = Some(verified);
                            notify.notify_waiters();
                        }
                        Err(error) => {
                            warn!(height = header.height, %error, "rejecting unverified header")
                        }
                    }
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

async fn authenticate_header(
    client: &ProofClient,
    header: &GossipHeader,
) -> eyre::Result<SyncState> {
    let verified = client.verified_state(header.height).await?;
    eyre::ensure!(
        verified.block_hash == header.block_hash,
        "header block hash differs from verified block"
    );
    eyre::ensure!(
        verified.module_state_root == header.module_state_root,
        "header root differs from verified block"
    );
    Ok(verified)
}
