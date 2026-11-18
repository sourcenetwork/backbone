//! WebSocket header subscription and tracking.
//!
//! Subscribes to `vera_subscribeHeaders` and maintains a view of the
//! latest finalized revision after checking its certificate against a configured key.

use alloy_primitives::B256;
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use tracing::{debug, warn};

use vera_domain::TermCertificate;

use crate::{
    proof_client::ProofClient,
    term::{self, observe_revision, Tracked, Voided},
    transport::{AcpTransport, HeaderStream, HttpWsTransport, TransportError},
    types::GossipHeader,
    FreshnessPolicy,
};

/// Maximum frame and assembled-message bytes accepted from the header stream.
pub const HEADER_MESSAGE_BYTES: usize = 64 << 10;

/// Snapshot of the latest finalized state tracked by header sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub height: u64,
    /// Timestamp authenticated by the finalized revision certificate, in Unix seconds.
    pub timestamp: u64,
    /// Term of the device that proposed the revision; it never decreases along the chain.
    pub term: u64,
    pub module_state_root: B256,
    pub block_hash: B256,
}

/// Tracks the latest finalized header state from WebSocket subscription.
///
/// Spawns a background task that subscribes to `vera_subscribeHeaders`,
/// authenticates the requested light blocks, and updates the latest finalized
/// `(height, module_state_root)`.
pub struct HeaderChain {
    state: Arc<RwLock<Tracked>>,
    proof_client: ProofClient,
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
        Self::start(
            Arc::new(HttpWsTransport::headers_only(ws_url)),
            proof_client,
            freshness,
        )
    }

    /// Follow the headers `transport` delivers, resubscribing when its stream ends.
    pub fn start(
        transport: Arc<dyn AcpTransport>,
        proof_client: ProofClient,
        freshness: FreshnessPolicy,
    ) -> eyre::Result<Self> {
        eyre::ensure!(
            !freshness.max_age.is_zero(),
            "maximum revision age must be positive"
        );
        let state = Arc::new(RwLock::new(Tracked::default()));
        let notify = Arc::new(tokio::sync::Notify::new());

        let state_clone = state.clone();
        let notify_clone = notify.clone();
        let header_client = proof_client.clone();

        let handle = tokio::spawn(async move {
            loop {
                if let Err(e) = run_header_loop(
                    transport.as_ref(),
                    &header_client,
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
            proof_client,
            freshness,
            notify,
            _handle: handle,
        })
    }

    /// Last authenticated state for diagnostics; it may be stale.
    pub fn state(&self) -> Option<SyncState> {
        self.state.read().head.as_ref().map(|s| s.revision.clone())
    }

    /// Certificate of the newest term this client verified, or `None` while
    /// every accepted revision is in term 0.
    pub fn term_certificate(&self) -> Option<Arc<TermCertificate>> {
        self.state.read().certificate.clone()
    }

    /// The last accepted revision that a later term voided, if any.
    ///
    /// Each term voids at most one tracked revision, so a caller that
    /// remembers the term it last handled sees every report once.
    pub fn voided(&self) -> Option<Voided> {
        self.state.read().voided.clone()
    }

    /// Current authenticated state within the configured age and clock-skew bounds.
    pub fn fresh_state(&self) -> eyre::Result<SyncState> {
        let guard = self.state.read();
        let state = guard
            .head
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no verified finalized state available"))?;
        state.check(self.freshness)?;
        Ok(state.revision.clone())
    }

    /// Publish an independently verified response revision without regressing header state.
    ///
    /// A revision of a term above the one held is accepted only once that
    /// term's certificate verifies; see [`crate::term`].
    pub(crate) async fn accept_response(&self, revision: SyncState) -> eyre::Result<SyncState> {
        let root = revision.module_state_root;
        term::certify(&self.proof_client, &self.state, &revision).await?;
        let current = observe_revision(&self.state, &self.notify, self.freshness, revision)?;
        eyre::ensure!(
            current.module_state_root == root,
            "ACP state changed during verification; retry the request"
        );
        Ok(current)
    }

    /// Latest authenticated height for diagnostics, or 0 if not yet synced.
    pub fn latest_height(&self) -> u64 {
        self.state
            .read()
            .head
            .as_ref()
            .map_or(0, |s| s.revision.height)
    }

    /// Latest finalized module state root.
    pub fn latest_module_state_root(&self) -> Option<B256> {
        self.state
            .read()
            .head
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
    transport: &dyn AcpTransport,
    proof_client: &ProofClient,
    state: &RwLock<Tracked>,
    notify: &tokio::sync::Notify,
    freshness: FreshnessPolicy,
) -> eyre::Result<()> {
    let mut headers = transport.subscribe_headers().await?;
    while let Some(header) = headers.next().await {
        let header = header?;
        // A header of a later term is read even below the head: the term may void the head.
        let known = {
            let tracked = state.read();
            header.term <= tracked.certified_term()
                && tracked
                    .head
                    .as_ref()
                    .is_some_and(|prev| header.height <= prev.revision.height)
        };
        if known {
            continue;
        }
        let accepted = async {
            let verified = authenticate_header(proof_client, &header).await?;
            term::certify(proof_client, state, &verified).await?;
            observe_revision(state, notify, freshness, verified)
        };
        match accepted.await {
            Ok(verified) => {
                debug!(height = verified.height, "verified finalized revision");
            }
            Err(error) => {
                warn!(height = header.height, %error, "rejecting unverified header")
            }
        }
    }
    Err(eyre::eyre!("header stream ended"))
}

/// Subscribe over a WebSocket and yield each `vera_header` notification.
pub(crate) async fn websocket_headers(ws_url: &str) -> Result<HeaderStream, TransportError> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(HEADER_MESSAGE_BYTES))
        .max_frame_size(Some(HEADER_MESSAGE_BYTES))
        .max_write_buffer_size(256 << 10);
    let (mut ws, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio_tungstenite::connect_async_with_config(ws_url, Some(config), false),
    )
    .await
    .map_err(|elapsed| TransportError::context("header WebSocket connection timeout", elapsed))?
    .map_err(|error| TransportError::context("connecting to hub.rs WebSocket", error))?;

    let subscribe_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "vera_subscribeHeaders",
        "params": [],
        "id": 1,
    });
    ws.send(Message::Text(subscribe_msg.to_string().into()))
        .await
        .map_err(|error| TransportError::context("sending vera_subscribeHeaders", error))?;

    let acknowledgement = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                        return subscription_id(&json);
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(websocket_error(e)),
                None => return Err(TransportError::other("websocket closed")),
            }
        }
    })
    .await
    .map_err(|elapsed| {
        TransportError::context("header subscription acknowledgement timeout", elapsed)
    })??;

    Ok(
        futures::stream::unfold((ws, acknowledgement), |(mut ws, subscription)| async move {
            loop {
                let header = match ws.next().await {
                    Some(Ok(Message::Text(text))) => {
                        serde_json::from_str::<serde_json::Value>(text.as_ref())
                            .ok()
                            .and_then(|json| extract_header(&json, &subscription))
                    }
                    Some(Ok(_)) => None,
                    Some(Err(e)) => return Some((Err(websocket_error(e)), (ws, subscription))),
                    None => return None,
                };
                if let Some(header) = header {
                    return Some((Ok(header), (ws, subscription)));
                }
            }
        })
        .boxed(),
    )
}

fn websocket_error(error: tokio_tungstenite::tungstenite::Error) -> TransportError {
    TransportError::other(format!("websocket error: {error}"))
}

fn subscription_id(msg: &serde_json::Value) -> Result<serde_json::Value, TransportError> {
    if msg["jsonrpc"] != "2.0" || msg["id"] != 1 {
        return Err(TransportError::other(
            "invalid header subscription acknowledgement",
        ));
    }
    if let Some(error) = msg.get("error") {
        return Err(TransportError::other(format!(
            "header subscription rejected: {error}"
        )));
    }
    let id = &msg["result"];
    if !id.is_string() && id.as_u64().is_none() {
        return Err(TransportError::other("invalid header subscription ID"));
    }
    Ok(id.clone())
}

fn extract_header(
    msg: &serde_json::Value,
    subscription_id: &serde_json::Value,
) -> Option<GossipHeader> {
    if msg["jsonrpc"] != "2.0"
        || msg["method"] != "vera_header"
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
    eyre::ensure!(
        verified.term == header.term,
        "header term differs from verified block"
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
            json!({"jsonrpc":"2.0", "method":"vera_header", "params":{}}),
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
            term: 0,
            state_root: Default::default(),
            module_state_root: Default::default(),
            tx_count: 0,
            publisher_index: 0,
            signature: vec![],
        };
        let mut message = json!({"jsonrpc":"2.0", "method":"vera_header", "params":{"subscription":"7", "result":header}});
        assert!(extract_header(&message, &json!("7")).is_some());
        for id in [json!(7), json!("other"), json!(null)] {
            assert!(extract_header(&message, &id).is_none());
        }
        message["method"] = json!("eth_subscription");
        assert!(extract_header(&message, &json!("7")).is_none());
    }

    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// A client of a node nothing answers for, under a well-formed consensus key.
    fn proof_client() -> ProofClient {
        use commonware_codec::Encode as _;
        use commonware_cryptography::{
            bls12381::{
                dkg::feldman_desmedt::deal,
                primitives::{sharing::Mode, variant::MinSig},
            },
            ed25519, Signer as _,
        };
        use commonware_utils::{ordered::Set, N3f1, TestRng};

        let players = Set::from_iter_dedup([ed25519::PrivateKey::from_seed(1).public_key()]);
        let (output, _) =
            deal::<MinSig, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, players).unwrap();
        let key = hex::encode(output.public().public().encode());
        ProofClient::new("http://127.0.0.1:1", &key).unwrap()
    }

    fn chain() -> HeaderChain {
        HeaderChain {
            state: Arc::new(RwLock::new(Tracked::default())),
            proof_client: proof_client(),
            freshness: FreshnessPolicy::default(),
            notify: Arc::new(tokio::sync::Notify::new()),
            _handle: tokio::spawn(std::future::pending()),
        }
    }

    fn revision(height: u64, term: u64) -> SyncState {
        SyncState {
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            term,
            module_state_root: B256::repeat_byte(1),
            block_hash: B256::repeat_byte(2),
        }
    }

    #[tokio::test]
    async fn responses_and_delayed_headers_cannot_regress_or_renew_state() {
        let chain = chain();
        let first = revision(10, 0);
        chain.accept_response(first.clone()).await.unwrap();
        let second = SyncState {
            height: 11,
            module_state_root: B256::repeat_byte(3),
            block_hash: B256::repeat_byte(4),
            ..first.clone()
        };
        chain.accept_response(second.clone()).await.unwrap();
        let delayed =
            observe_revision(&chain.state, &chain.notify, chain.freshness, first.clone()).unwrap();
        assert_eq!(delayed, second);
        assert!(chain.accept_response(first).await.is_err());
        let conflicting = SyncState {
            block_hash: B256::repeat_byte(9),
            ..second.clone()
        };
        assert!(chain.accept_response(conflicting).await.is_err());
        let stale = SyncState {
            height: 12,
            timestamp: second.timestamp - 60,
            ..second.clone()
        };
        assert!(chain.accept_response(stale).await.is_err());
        assert_eq!(chain.fresh_state().unwrap(), second);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(chain.accept_response(second.clone()).await.is_err());
        assert!(chain.fresh_state().is_err());
        assert_eq!(chain.state().unwrap(), second);
    }

    #[tokio::test]
    async fn a_term_cannot_be_checked_without_the_deployment_identifier() {
        let chain = chain();
        chain.accept_response(revision(10, 0)).await.unwrap();
        let error = chain.accept_response(revision(11, 1)).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "term 1 cannot be checked: no deployment identifier is configured"
        );
        assert_eq!(chain.state().unwrap().height, 10);
        assert!(chain.term_certificate().is_none() && chain.voided().is_none());
    }
}
