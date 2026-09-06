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

use crate::{
    freshness::ObservedState, proof_client::ProofClient, types::GossipHeader, FreshnessPolicy,
};

/// Snapshot of the latest finalized state tracked by header sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub height: u64,
    /// Timestamp authenticated by the finalized revision certificate, in Unix seconds.
    pub timestamp: u64,
    pub module_state_root: B256,
    pub block_hash: B256,
}

/// Tracks the latest finalized header state from WebSocket subscription.
///
/// Spawns a background task that subscribes to `eth_subscribe("headers")`,
/// authenticates the requested light blocks, and updates the latest finalized
/// `(height, module_state_root)`.
pub struct HeaderChain {
    state: Arc<RwLock<Option<ObservedState>>>,
    freshness: FreshnessPolicy,
    notify: Arc<tokio::sync::Notify>,
    _handle: tokio::task::JoinHandle<()>,
}

impl HeaderChain {
    /// Connect to a hub.rs node's WebSocket endpoint and start syncing headers.
    pub async fn connect(ws_url: &str, proof_client: ProofClient) -> eyre::Result<Self> {
        Self::connect_with_freshness(ws_url, proof_client, FreshnessPolicy::default()).await
    }

    /// Connect with explicit local age and clock-skew bounds.
    pub async fn connect_with_freshness(
        ws_url: &str,
        proof_client: ProofClient,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        eyre::ensure!(
            !freshness.max_age.is_zero(),
            "maximum revision age must be positive"
        );
        let state = Arc::new(RwLock::new(None));
        let notify = Arc::new(tokio::sync::Notify::new());

        let state_clone = state.clone();
        let notify_clone = notify.clone();
        let ws_url = ws_url.to_string();

        let handle = tokio::spawn(async move {
            loop {
                if let Err(e) = run_header_loop(
                    &ws_url,
                    &proof_client,
                    &state_clone,
                    &notify_clone,
                    freshness,
                )
                .await
                {
                    warn!("header sync disconnected: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        Ok(Self {
            state,
            freshness,
            notify,
            _handle: handle,
        })
    }

    /// Last authenticated state for diagnostics; it may be stale.
    pub fn state(&self) -> Option<SyncState> {
        self.state.read().as_ref().map(|s| s.revision.clone())
    }

    /// Current authenticated state within the configured age and clock-skew bounds.
    pub fn fresh_state(&self) -> eyre::Result<SyncState> {
        let guard = self.state.read();
        let state = guard
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no verified finalized state available"))?;
        state.check(self.freshness)?;
        Ok(state.revision.clone())
    }

    /// Latest authenticated height for diagnostics, or 0 if not yet synced.
    pub fn latest_height(&self) -> u64 {
        self.state.read().as_ref().map_or(0, |s| s.revision.height)
    }

    /// Latest finalized module state root.
    pub fn latest_module_state_root(&self) -> Option<B256> {
        self.state
            .read()
            .as_ref()
            .map(|s| s.revision.module_state_root)
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
            if let Ok(state) = self.fresh_state() {
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
            if let Ok(state) = self.fresh_state() {
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
    state: &RwLock<Option<ObservedState>>,
    notify: &tokio::sync::Notify,
    freshness: FreshnessPolicy,
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
                        .is_some_and(|prev| header.height <= prev.revision.height)
                    {
                        continue;
                    }
                    match authenticate_header(proof_client, &header)
                        .await
                        .and_then(|verified| {
                            let observed = ObservedState::new(verified)?;
                            observed.check(freshness)?;
                            Ok(observed)
                        }) {
                        Ok(verified) => {
                            debug!(
                                height = verified.revision.height,
                                "verified finalized revision"
                            );
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
