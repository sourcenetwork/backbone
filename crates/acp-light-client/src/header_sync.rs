//! WebSocket header subscription and tracking.
//!
//! Subscribes to `hub_subscribeHeaders` and maintains a view of the
//! latest finalized revision after checking its certificate against a configured key.

use alloy_primitives::B256;
use eyre::WrapErr;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use tracing::{debug, warn};

use crate::{
    freshness::ObservedState, proof_client::ProofClient, types::GossipHeader, FreshnessPolicy,
};

/// Maximum frame and assembled-message bytes accepted from the header stream.
pub const HEADER_MESSAGE_BYTES: usize = 64 << 10;

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
/// Spawns a background task that subscribes to `hub_subscribeHeaders`,
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

    /// Publish an independently verified response revision without regressing header state.
    pub(crate) fn accept_response(&self, revision: SyncState) -> eyre::Result<SyncState> {
        let root = revision.module_state_root;
        let current = observe_revision(&self.state, &self.notify, self.freshness, revision)?;
        eyre::ensure!(
            current.module_state_root == root,
            "ACP state changed during verification; retry the request"
        );
        Ok(current)
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
    let config = WebSocketConfig::default()
        .max_message_size(Some(HEADER_MESSAGE_BYTES))
        .max_frame_size(Some(HEADER_MESSAGE_BYTES))
        .max_write_buffer_size(256 << 10);
    let (mut ws, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio_tungstenite::connect_async_with_config(ws_url, Some(config), false),
    )
    .await
    .wrap_err("header WebSocket connection timeout")?
    .wrap_err("connecting to hub.rs WebSocket")?;

    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "hub_subscribeHeaders",
        "params": [],
        "id": 1,
    });
    ws.send(Message::Text(subscribe_msg.to_string().into()))
        .await
        .wrap_err("sending hub_subscribeHeaders")?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut subscription = None;
    loop {
        let msg = if subscription.is_none() {
            tokio::time::timeout_at(deadline, ws.next())
                .await
                .wrap_err("header subscription acknowledgement timeout")?
        } else {
            ws.next().await
        };
        let msg = match msg {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => return Err(eyre::eyre!("websocket error: {e}")),
            None => return Err(eyre::eyre!("websocket closed")),
        };

        if let Message::Text(ref text) = msg {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                let Some(subscription_id) = subscription.as_ref() else {
                    subscription = Some(subscription_id(&json)?);
                    continue;
                };
                if let Some(header) = extract_header(&json, subscription_id) {
                    if state
                        .read()
                        .as_ref()
                        .is_some_and(|prev| header.height <= prev.revision.height)
                    {
                        continue;
                    }
                    match authenticate_header(proof_client, &header)
                        .await
                        .and_then(|verified| observe_revision(state, notify, freshness, verified))
                    {
                        Ok(verified) => {
                            debug!(height = verified.height, "verified finalized revision");
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

fn observe_revision(
    state: &RwLock<Option<ObservedState>>,
    notify: &tokio::sync::Notify,
    freshness: FreshnessPolicy,
    revision: SyncState,
) -> eyre::Result<SyncState> {
    let observed = ObservedState::new(revision)?;
    observed.check(freshness)?;
    let mut state = state.write();
    if let Some(previous) = state.as_ref() {
        if observed.revision.height <= previous.revision.height {
            if observed.revision.height == previous.revision.height {
                eyre::ensure!(
                    observed.revision == previous.revision,
                    "conflicting finalized revision at the same height"
                );
            }
            // Repeated certificates cannot reset the monotonic age of a cached revision.
            previous.check(freshness)?;
            return Ok(previous.revision.clone());
        }
    }
    let current = observed.revision.clone();
    *state = Some(observed);
    notify.notify_waiters();
    Ok(current)
}

fn subscription_id(msg: &serde_json::Value) -> eyre::Result<serde_json::Value> {
    eyre::ensure!(
        msg["jsonrpc"] == "2.0" && msg["id"] == 1,
        "invalid header subscription acknowledgement"
    );
    eyre::ensure!(
        msg.get("error").is_none(),
        "header subscription rejected: {}",
        msg["error"]
    );
    let id = &msg["result"];
    eyre::ensure!(
        id.is_string() || id.as_u64().is_some(),
        "invalid header subscription ID"
    );
    Ok(id.clone())
}

fn extract_header(
    msg: &serde_json::Value,
    subscription_id: &serde_json::Value,
) -> Option<GossipHeader> {
    if msg["jsonrpc"] != "2.0"
        || msg["method"] != "hub_header"
        || msg.pointer("/params/subscription") != Some(subscription_id)
    {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::{extract_header, subscription_id};
    use serde_json::json;

    #[test]
    fn header_subscription_acknowledgement_requires_matching_request_and_typed_id() {
        for id in [json!("stream"), json!(7)] {
            assert_eq!(
                subscription_id(&json!({"jsonrpc":"2.0", "id":1, "result":id})).unwrap(),
                id
            );
        }
        for message in [
            json!({"jsonrpc":"2.0", "id":2, "result":"stream"}),
            json!({"jsonrpc":"1.0", "id":1, "result":"stream"}),
            json!({"jsonrpc":"2.0", "id":1, "result":null}),
            json!({"jsonrpc":"2.0", "id":1, "result":-1}),
            json!({"jsonrpc":"2.0", "id":1, "result":{}, "error":{"code":-1}}),
            json!({"jsonrpc":"2.0", "method":"hub_header", "params":{}}),
        ] {
            assert!(subscription_id(&message).is_err(), "{message}");
        }
    }

    #[test]
    fn header_subscription_notifications_match_method_and_exact_id() {
        let header = super::GossipHeader {
            chain_id: 1,
            height: 1,
            block_hash: Default::default(),
            parent_hash: Default::default(),
            timestamp: 1,
            state_root: Default::default(),
            module_state_root: Default::default(),
            tx_count: 0,
            publisher_index: 0,
            signature: vec![],
        };
        let mut message = json!({"jsonrpc":"2.0", "method":"hub_header", "params":{"subscription":"7", "result":header}});
        assert!(extract_header(&message, &json!("7")).is_some());
        for id in [json!(7), json!("other"), json!(null)] {
            assert!(extract_header(&message, &id).is_none());
        }
        message["method"] = json!("eth_subscription");
        assert!(extract_header(&message, &json!("7")).is_none());
    }

    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn responses_and_delayed_headers_cannot_regress_or_renew_state() {
        let chain = HeaderChain {
            state: Arc::new(RwLock::new(None)),
            freshness: FreshnessPolicy::default(),
            notify: Arc::new(tokio::sync::Notify::new()),
            _handle: tokio::spawn(std::future::pending()),
        };
        let first = SyncState {
            height: 10,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            module_state_root: B256::repeat_byte(1),
            block_hash: B256::repeat_byte(2),
        };
        chain.accept_response(first.clone()).unwrap();
        let second = SyncState {
            height: 11,
            module_state_root: B256::repeat_byte(3),
            block_hash: B256::repeat_byte(4),
            ..first.clone()
        };
        chain.accept_response(second.clone()).unwrap();
        let delayed =
            observe_revision(&chain.state, &chain.notify, chain.freshness, first.clone()).unwrap();
        assert_eq!(delayed, second);
        assert!(chain.accept_response(first).is_err());
        let conflicting = SyncState {
            block_hash: B256::repeat_byte(9),
            ..second.clone()
        };
        assert!(chain.accept_response(conflicting).is_err());
        let stale = SyncState {
            height: 12,
            timestamp: second.timestamp - 60,
            ..second.clone()
        };
        assert!(chain.accept_response(stale).is_err());
        assert_eq!(chain.fresh_state().unwrap(), second);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(chain.accept_response(second.clone()).is_err());
        assert!(chain.fresh_state().is_err());
        assert_eq!(chain.state().unwrap(), second);
    }
}
