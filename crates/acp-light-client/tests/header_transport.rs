//! The header subscription's failures, with the text the header task logs.

use std::time::Duration;

use acp_light_client::{header_sync::HEADER_MESSAGE_BYTES, AcpTransport, HttpWsTransport};
use futures::{future::BoxFuture, FutureExt as _, SinkExt as _, StreamExt as _};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

type Socket = WebSocketStream<TcpStream>;

/// The message alone, then the message with its causes.
fn text(error: impl Into<eyre::Report>) -> (String, String) {
    let error = error.into();
    (error.to_string(), format!("{error:#}"))
}

fn both(message: &str) -> (String, String) {
    (message.to_string(), message.to_string())
}

fn transport(ws_url: &str) -> HttpWsTransport {
    HttpWsTransport::new("http://127.0.0.1:1", ws_url).unwrap()
}

/// Accept one subscription request, then let `script` drive the socket.
async fn node<F>(script: F) -> (String, tokio::task::JoinHandle<()>)
where
    F: FnOnce(Socket) -> BoxFuture<'static, ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        let request = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["method"], "vera_subscribeHeaders");
        script(ws).await;
    });
    (url, task)
}

async fn say(ws: &mut Socket, message: serde_json::Value) {
    ws.send(Message::Text(message.to_string().into()))
        .await
        .unwrap();
}

async fn subscription_error<F>(script: F) -> (String, String)
where
    F: FnOnce(Socket) -> BoxFuture<'static, ()> + Send + 'static,
{
    let (url, task) = node(script).await;
    let error = transport(&url)
        .subscribe_headers()
        .await
        .map(|_| ())
        .unwrap_err();
    task.abort();
    text(error)
}

#[tokio::test]
async fn a_transport_without_a_header_endpoint_says_so() {
    let error = HttpWsTransport::calls_only("http://127.0.0.1:1")
        .unwrap()
        .subscribe_headers()
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(text(error), both("transport has no header endpoint"));
}

#[tokio::test]
async fn connection_failures_keep_their_text() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", closed.local_addr().unwrap());
    drop(closed);
    let error = transport(&url)
        .subscribe_headers()
        .await
        .map(|_| ())
        .unwrap_err();
    let (message, chain) = text(error);
    assert_eq!(message, "connecting to hub.rs WebSocket");
    assert!(
        chain.starts_with("connecting to hub.rs WebSocket: IO error: "),
        "{chain}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let refusing = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let error = transport(&url)
        .subscribe_headers()
        .await
        .map(|_| ())
        .unwrap_err();
    refusing.await.unwrap();
    assert_eq!(
        text(error),
        (
            "connecting to hub.rs WebSocket".to_string(),
            "connecting to hub.rs WebSocket: HTTP error: 404 Not Found".to_string()
        )
    );
}

#[tokio::test]
async fn rejected_acknowledgements_keep_their_text() {
    for (acknowledgement, expected) in [
        (
            json!({"jsonrpc":"2.0", "id":2, "result":"1"}),
            "invalid header subscription acknowledgement",
        ),
        (
            json!({"jsonrpc":"2.0", "id":1, "error":{"code":-32601, "message":"Method not found"}}),
            r#"header subscription rejected: {"code":-32601,"message":"Method not found"}"#,
        ),
        (
            json!({"jsonrpc":"2.0", "id":1, "result":null}),
            "invalid header subscription ID",
        ),
    ] {
        let error = subscription_error(move |mut ws| {
            async move {
                say(&mut ws, acknowledgement).await;
                std::future::pending::<()>().await;
            }
            .boxed()
        })
        .await;
        assert_eq!(error, both(expected));
    }
}

#[tokio::test]
async fn a_connection_lost_before_the_acknowledgement_keeps_its_text() {
    let closed = subscription_error(|mut ws| {
        async move {
            ws.close(None).await.unwrap();
            while ws.next().await.is_some() {}
        }
        .boxed()
    })
    .await;
    assert_eq!(closed, both("websocket closed"));

    let reset = subscription_error(|ws| async move { drop(ws) }.boxed()).await;
    assert_eq!(
        reset,
        both(
            "websocket error: WebSocket protocol error: Connection reset without closing handshake"
        )
    );
}

#[tokio::test]
async fn stalled_connections_and_acknowledgements_time_out_with_their_text() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let silent = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let connecting = async {
        let error =
            tokio::time::timeout(Duration::from_secs(12), transport(&url).subscribe_headers())
                .await
                .unwrap()
                .map(|_| ())
                .unwrap_err();
        text(error)
    };
    let acknowledging = async {
        tokio::time::timeout(
            Duration::from_secs(12),
            subscription_error(|mut ws| {
                async move {
                    // Text that is not JSON is skipped, not taken as the acknowledgement.
                    ws.send(Message::Text("later".into())).await.unwrap();
                    std::future::pending::<()>().await;
                }
                .boxed()
            }),
        )
        .await
        .unwrap()
    };
    let (connecting, acknowledging) = tokio::join!(connecting, acknowledging);
    silent.abort();
    assert_eq!(
        connecting,
        (
            "header WebSocket connection timeout".to_string(),
            "header WebSocket connection timeout: deadline has elapsed".to_string()
        )
    );
    assert_eq!(
        acknowledging,
        (
            "header subscription acknowledgement timeout".to_string(),
            "header subscription acknowledgement timeout: deadline has elapsed".to_string()
        )
    );
}

#[tokio::test]
async fn a_subscribed_stream_reports_a_lost_connection_and_ends_on_a_clean_close() {
    let acknowledged = json!({"jsonrpc":"2.0", "id":1, "result":"1"});

    let acknowledgement = acknowledged.clone();
    let (url, _task) = node(move |mut ws| {
        async move {
            say(&mut ws, acknowledgement).await;
            drop(ws);
        }
        .boxed()
    })
    .await;
    let mut headers = transport(&url).subscribe_headers().await.unwrap();
    let error = headers.next().await.unwrap().map(|_| ()).unwrap_err();
    assert_eq!(
        text(error),
        both(
            "websocket error: WebSocket protocol error: Connection reset without closing handshake"
        )
    );

    let acknowledgement = acknowledged.clone();
    let (url, _task) = node(move |mut ws| {
        async move {
            say(&mut ws, acknowledgement).await;
            let _ = ws
                .send(Message::Text(" ".repeat(HEADER_MESSAGE_BYTES + 1).into()))
                .await;
            while ws.next().await.is_some() {}
        }
        .boxed()
    })
    .await;
    let mut headers = transport(&url).subscribe_headers().await.unwrap();
    let error = headers.next().await.unwrap().map(|_| ()).unwrap_err();
    assert_eq!(
        text(error),
        both("websocket error: Space limit exceeded: Message too long: 65537 > 65536")
    );

    let (url, _task) = node(move |mut ws| {
        async move {
            say(&mut ws, acknowledged).await;
            ws.close(None).await.unwrap();
            while ws.next().await.is_some() {}
        }
        .boxed()
    })
    .await;
    let mut headers = transport(&url).subscribe_headers().await.unwrap();
    assert!(headers.next().await.is_none());
}
