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
    Prefix,
    PolicyPrefix,
    Light,
    Permission,
}

impl Endpoint {
    fn maximum(self) -> usize {
        match self {
            Self::State | Self::Prefix | Self::PolicyPrefix => rpc::RECORD_RESPONSE_BYTES,
            Self::Light => rpc::LIGHT_BLOCK_RESPONSE_BYTES,
            Self::Permission => rpc::PERMISSION_RESPONSE_BYTES,
        }
    }

    async fn fetch(self, url: &str) -> eyre::Result<()> {
        let client = reqwest::Client::new();
        match self {
            Self::State => rpc::get_current_record_proof(
                &client,
                url,
                acp_light_client::ModuleId::Acp,
                &[0],
                1,
            )
            .await
            .map(|_| ()),
            Self::Prefix => rpc::get_current_prefix_proof(
                &client,
                url,
                acp_light_client::ModuleId::Acp,
                &[0],
                1,
            )
            .await
            .map(|_| ()),
            Self::PolicyPrefix => {
                let policy = "ab".repeat(32);
                let prefix = vera_modules::acp::keys::relationship_policy_prefix(&policy);
                rpc::get_current_policy_prefix_proof(&client, url, &policy, &prefix, 1)
                    .await
                    .map(|_| ())
            }
            Self::Light => rpc::get_light_block(&client, url, 1).await.map(|_| ()),
            Self::Permission => rpc::get_current_permission_proof(
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

impl Endpoint {
    const ALL: [Self; 5] = [
        Self::State,
        Self::Prefix,
        Self::PolicyPrefix,
        Self::Light,
        Self::Permission,
    ];

    fn method(self) -> &'static str {
        match self {
            Self::State => "vera_getCurrentRecordProof",
            Self::Prefix => "vera_getCurrentPrefixProof",
            Self::PolicyPrefix => "vera_getCurrentPolicyPrefixProof",
            Self::Light => "vera_getLightBlock",
            Self::Permission => "vera_getCurrentPermissionProof",
        }
    }
}

/// The message alone, then the message with its causes.
fn text(error: &eyre::Report) -> (String, String) {
    (error.to_string(), format!("{error:#}"))
}

async fn serve(status: StatusCode, body: &'static str) -> Server {
    Server::start(Router::new().route("/", post(move || async move { (status, body) }))).await
}

#[tokio::test]
async fn envelope_failures_reach_callers_with_exact_text() {
    for endpoint in Endpoint::ALL {
        let method = endpoint.method();
        for (body, expected) in [
            (
                r#"{"jsonrpc":"2.0","id":2,"result":null}"#,
                "RPC response metadata mismatch",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":null,"error":{}}"#,
                "RPC response has both result and error",
            ),
            (r#"{"jsonrpc":"2.0","id":1}"#, "RPC response has no result"),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"busy"}}"#,
                "RPC error (-32002): busy",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"error":{}}"#,
                "RPC error (0): unknown",
            ),
        ] {
            let server = serve(StatusCode::OK, body).await;
            let error = endpoint.fetch(&server.url).await.unwrap_err();
            let expected = format!("{method} {expected}");
            assert_eq!(text(&error), (expected.clone(), expected), "{body}");
        }
    }
}

#[tokio::test]
async fn http_and_json_failures_keep_their_text_and_underlying_error() {
    for endpoint in Endpoint::ALL {
        let method = endpoint.method();

        let server = serve(StatusCode::BAD_GATEWAY, "").await;
        let error = endpoint.fetch(&server.url).await.unwrap_err();
        let expected = format!(
            "HTTP status server error (502 Bad Gateway) for url ({}/)",
            server.url
        );
        assert_eq!(text(&error), (expected.clone(), expected));
        assert_eq!(
            error.downcast_ref::<reqwest::Error>().unwrap().status(),
            Some(StatusCode::BAD_GATEWAY)
        );

        let server = serve(StatusCode::OK, "nope").await;
        let error = endpoint.fetch(&server.url).await.unwrap_err();
        let expected = "expected ident at line 1 column 2".to_string();
        assert_eq!(text(&error), (expected.clone(), expected));
        assert!(error
            .downcast_ref::<serde_json::Error>()
            .unwrap()
            .is_syntax());

        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let error = endpoint.fetch(&url).await.unwrap_err();
        let (message, chain) = text(&error);
        assert_eq!(message, format!("{method} request"));
        let cause = error.downcast_ref::<reqwest::Error>().unwrap();
        assert!(cause.is_connect(), "{error:?}");
        assert!(
            chain.starts_with(&format!("{method} request: {cause}: ")),
            "{chain}"
        );
    }
}

#[tokio::test]
async fn a_result_of_the_wrong_shape_names_the_method() {
    let server = serve(StatusCode::OK, r#"{"jsonrpc":"2.0","id":1,"result":null}"#).await;
    let error = Endpoint::Light.fetch(&server.url).await.unwrap_err();
    assert_eq!(
        text(&error),
        (
            "deserializing vera_getLightBlock result".to_string(),
            "deserializing vera_getLightBlock result: invalid type: null, expected struct LightBlock"
                .to_string()
        )
    );
}

#[tokio::test]
async fn oversize_and_stalled_bodies_keep_their_text() {
    for endpoint in Endpoint::ALL {
        let maximum = endpoint.maximum();
        let expected = format!("{} response exceeds byte limit", endpoint.method());
        for declared in [true, false] {
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
            let error = endpoint.fetch(&server.url).await.unwrap_err();
            assert_eq!(text(&error), (expected.clone(), expected.clone()));
        }
    }

    let server = Server::start(Router::new().route(
        "/",
        post(|| async {
            Response::new(Body::from_stream(futures::stream::pending::<
                Result<Bytes, Infallible>,
            >()))
        }),
    ))
    .await;
    let error = Endpoint::Light.fetch(&server.url).await.unwrap_err();
    assert_eq!(
        text(&error),
        (
            "error decoding response body".to_string(),
            "error decoding response body: request or response body error: operation timed out"
                .to_string()
        )
    );
}

#[tokio::test]
async fn every_proof_endpoint_rejects_declared_and_streamed_oversize_bodies() {
    for endpoint in [
        Endpoint::State,
        Endpoint::Prefix,
        Endpoint::PolicyPrefix,
        Endpoint::Light,
        Endpoint::Permission,
    ] {
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
    for endpoint in [
        Endpoint::State,
        Endpoint::Prefix,
        Endpoint::PolicyPrefix,
        Endpoint::Light,
        Endpoint::Permission,
    ] {
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
    let mut body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "revision": {
                "block_hash": "", "parent_hash": "", "height": 1, "timestamp": 0,
                "state_root": "", "module_state_root": "", "epoch": 0, "view": 1,
                "parent_view": 0, "block": "", "finalization": "", "epoch_material": ""
            },
            "proof": { "reads": [] }
        }
    })
    .to_string();
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
