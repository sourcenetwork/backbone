use std::{convert::Infallible, time::Duration};

use acp_light_client::{rpc, AccessRequest, Actor};
use axum::{
    body::{Body, Bytes},
    http::{Response, StatusCode},
    routing::post,
    Router,
};
use tokio::net::TcpListener;

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum Endpoint {
    State,
    Light,
    Permission,
}

impl Endpoint {
    fn maximum(self) -> usize {
        match self {
            Self::State => rpc::STATE_PROOF_RESPONSE_BYTES,
            Self::Light => rpc::LIGHT_BLOCK_RESPONSE_BYTES,
            Self::Permission => rpc::PERMISSION_RESPONSE_BYTES,
        }
    }

    async fn fetch(self, url: &str) -> eyre::Result<()> {
        let client = reqwest::Client::new();
        match self {
            Self::State => rpc::get_state_proof(&client, url, "acp", "0x00", 1)
                .await
                .map(|_| ()),
            Self::Light => rpc::get_light_block(&client, url, 1).await.map(|_| ()),
            Self::Permission => rpc::get_permission_proof(
                &client,
                url,
                "policy",
                &AccessRequest {
                    actor: Actor("did:key:actor".parse().unwrap()),
                    operations: vec![],
                },
                1,
            )
            .await
            .map(|_| ()),
        }
    }
}

#[tokio::test]
async fn every_proof_endpoint_rejects_declared_and_streamed_oversize_bodies() {
    for endpoint in [Endpoint::State, Endpoint::Light, Endpoint::Permission] {
        for declared in [true, false] {
            let maximum = endpoint.maximum();
            let app = Router::new().route(
                "/",
                post(move || async move {
                    if declared {
                        Response::builder()
                            .header("content-length", maximum + 1)
                            .body(Body::from_stream(futures::stream::pending::<
                                Result<Bytes, Infallible>,
                            >()))
                            .unwrap()
                    } else {
                        let chunks = std::iter::repeat_n(
                            Ok::<_, Infallible>(Bytes::from_static(&[b' '; 8192])),
                            maximum / 8192 + 1,
                        );
                        Response::new(Body::from_stream(futures::stream::iter(chunks)))
                    }
                }),
            );
            let server = Server::start(app).await;
            let error = tokio::time::timeout(Duration::from_secs(3), endpoint.fetch(&server.url))
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                error.to_string().contains("exceeds byte limit"),
                "{endpoint:?}, declared={declared}: {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn every_proof_endpoint_checks_http_and_rpc_envelopes() {
    for endpoint in [Endpoint::State, Endpoint::Light, Endpoint::Permission] {
        for (status, body, expected) in [
            (
                StatusCode::BAD_GATEWAY,
                r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
                "502",
            ),
            (
                StatusCode::OK,
                r#"{"jsonrpc":"2.0","id":2,"result":null}"#,
                "metadata mismatch",
            ),
            (
                StatusCode::OK,
                r#"{"jsonrpc":"1.0","id":1,"result":null}"#,
                "metadata mismatch",
            ),
            (
                StatusCode::OK,
                r#"{"jsonrpc":"2.0","id":1,"result":null,"error":{}}"#,
                "both result and error",
            ),
            (StatusCode::OK, r#"{"jsonrpc":"2.0","id":1}"#, "no result"),
            (
                StatusCode::OK,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unavailable"}}"#,
                "unavailable",
            ),
        ] {
            let server = Server::start(
                Router::new().route("/", post(move || async move { (status, body) })),
            )
            .await;
            let error = endpoint.fetch(&server.url).await.unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{endpoint:?}: {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn exact_response_limit_is_accepted_and_stalled_bodies_time_out() {
    let mut body = r#"{"jsonrpc":"2.0","id":1,"result":{"reads":[]}}"#.to_string();
    body.extend(std::iter::repeat_n(
        ' ',
        rpc::PERMISSION_RESPONSE_BYTES - body.len(),
    ));
    let server = Server::start(Router::new().route(
        "/",
        post(move || {
            let body = body.clone();
            async move { body }
        }),
    ))
    .await;
    Endpoint::Permission.fetch(&server.url).await.unwrap();

    let server = Server::start(Router::new().route(
        "/",
        post(|| async {
            Response::new(Body::from_stream(futures::stream::pending::<
                Result<Bytes, Infallible>,
            >()))
        }),
    ))
    .await;
    let error = tokio::time::timeout(Duration::from_secs(12), Endpoint::State.fetch(&server.url))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout),
        "{error:?}"
    );
}
