//! How the light client reaches a Vera node.
//!
//! The transport only moves bytes. Every response and header it delivers is
//! verified against the configured consensus key before use.

use std::time::Duration;

use futures::{future::BoxFuture, stream::BoxStream, FutureExt as _};

use crate::types::GossipHeader;

/// Why a transport could not deliver a response or a header.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The node answered `method` with a JSON-RPC error.
    #[error("{method} RPC error ({code}): {message}")]
    Rpc {
        method: &'static str,
        code: i64,
        message: String,
    },

    /// The response to `method` is larger than the caller allows.
    #[error("{method} response exceeds byte limit")]
    ResponseTooLarge { method: &'static str },

    /// Any other failure, reported in the words of its cause.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl TransportError {
    /// A failure described by a message or by another error.
    pub fn other(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Other(error.into())
    }

    pub(crate) fn context<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::other(Context {
            message: message.into(),
            source,
        })
    }

    /// Reports an HTTP or JSON failure as that error itself, with any message
    /// as context, because callers downcast reports to those types.
    pub(crate) fn into_report(self) -> eyre::Report {
        let Self::Other(source) = self else {
            return self.into();
        };
        let source = match source.downcast::<reqwest::Error>() {
            Ok(error) => return eyre::Report::new(*error),
            Err(source) => source,
        };
        let source = match source.downcast::<serde_json::Error>() {
            Ok(error) => return eyre::Report::new(*error),
            Err(source) => source,
        };
        match source.downcast::<Context<reqwest::Error>>() {
            Ok(context) => eyre::Report::new(context.source).wrap_err(context.message),
            Err(source) => Self::Other(source).into(),
        }
    }
}

/// A cause with a message that says what was being attempted.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct Context<E> {
    message: String,
    source: E,
}

/// Finalized-header notifications. The stream ends when the connection does.
pub type HeaderStream = BoxStream<'static, Result<GossipHeader, TransportError>>;

/// A JSON-RPC channel to a Vera node.
pub trait AcpTransport: Send + Sync + 'static {
    /// Call `method` with positional `params` and return its `result` value.
    ///
    /// A JSON-RPC error from the node is [`TransportError::Rpc`]. Implementations
    /// reject a response larger than `max_bytes` with
    /// [`TransportError::ResponseTooLarge`].
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
        max_bytes: usize,
    ) -> BoxFuture<'_, Result<serde_json::Value, TransportError>>;

    /// Subscribe to finalized headers (`vera_subscribeHeaders`).
    fn subscribe_headers(&self) -> BoxFuture<'_, Result<HeaderStream, TransportError>>;
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
    ) -> BoxFuture<'_, Result<serde_json::Value, TransportError>> {
        crate::rpc::http_call(&self.client, &self.rpc_url, method, params, max_bytes).boxed()
    }

    fn subscribe_headers(&self) -> BoxFuture<'_, Result<HeaderStream, TransportError>> {
        async move {
            let ws_url = self
                .ws_url
                .as_deref()
                .ok_or_else(|| TransportError::other("transport has no header endpoint"))?;
            crate::header_sync::websocket_headers(ws_url).await
        }
        .boxed()
    }
}
