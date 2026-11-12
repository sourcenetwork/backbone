//! How the light client reaches a Vera node.
//!
//! The transport only moves bytes. Every response and header it delivers is
//! verified against the configured consensus key before use.

use std::time::Duration;

use futures::{future::BoxFuture, stream::BoxStream, FutureExt as _};

use crate::types::GossipHeader;

/// Finalized-header notifications. The stream ends when the connection does.
pub type HeaderStream = BoxStream<'static, eyre::Result<GossipHeader>>;

/// A JSON-RPC channel to a Vera node.
pub trait AcpTransport: Send + Sync + 'static {
    /// Call `method` with positional `params` and return its `result` value.
    ///
    /// Implementations reject a response larger than `max_bytes`.
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
        max_bytes: usize,
    ) -> BoxFuture<'_, eyre::Result<serde_json::Value>>;

    /// Subscribe to finalized headers (`vera_subscribeHeaders`).
    fn subscribe_headers(&self) -> BoxFuture<'_, eyre::Result<HeaderStream>>;
}

/// HTTP JSON-RPC for calls and a WebSocket for headers.
#[derive(Clone)]
pub struct HttpWsTransport {
    client: reqwest::Client,
    rpc_url: String,
    ws_url: Option<String>,
}

impl HttpWsTransport {
    /// Connect calls to `rpc_url` and headers to `ws_url`.
    pub fn new(rpc_url: &str, ws_url: &str) -> eyre::Result<Self> {
        Ok(Self {
            ws_url: Some(ws_url.to_string()),
            ..Self::calls_only(rpc_url)?
        })
    }

    /// A transport for calls alone; subscribing to headers fails.
    pub fn calls_only(rpc_url: &str) -> eyre::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self::from_client(client, rpc_url))
    }

    pub(crate) fn from_client(client: reqwest::Client, rpc_url: &str) -> Self {
        Self {
            client,
            rpc_url: rpc_url.to_string(),
            ws_url: None,
        }
    }

    pub(crate) fn headers_only(ws_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            rpc_url: String::new(),
            ws_url: Some(ws_url.to_string()),
        }
    }
}

impl AcpTransport for HttpWsTransport {
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
        max_bytes: usize,
    ) -> BoxFuture<'_, eyre::Result<serde_json::Value>> {
        crate::rpc::http_call(&self.client, &self.rpc_url, method, params, max_bytes).boxed()
    }

    fn subscribe_headers(&self) -> BoxFuture<'_, eyre::Result<HeaderStream>> {
        async move {
            let ws_url = self
                .ws_url
                .as_deref()
                .ok_or_else(|| eyre::eyre!("transport has no header endpoint"))?;
            crate::header_sync::websocket_headers(ws_url).await
        }
        .boxed()
    }
}
