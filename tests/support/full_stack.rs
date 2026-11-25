#![allow(dead_code)]

use std::collections::HashSet;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use defra_harness::DefraClient;
use orbis_harness::defradb::identity::DefraHttpClient;
use vera_harness::observe::ClusterState;
use vera_support::VeraAccount;

pub fn bls_did_key_from_hex(public_key_hex: &str) -> String {
    let bytes =
        hex::decode(public_key_hex).unwrap_or_else(|e| panic!("invalid BLS public key hex: {}", e));
    bls_did_key(&bytes)
}

pub async fn wait_for_block_finality(vera_state: &ClusterState, label: &str) {
    let current = vera_state.node(0).effective_height();
    let target = current + 2;
    let t = Instant::now();
    vera_state
        .wait_for_height(target, Duration::from_secs(30))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}: chain didn't advance 2 blocks (current={}, target={}): {}",
                label, current, target, e
            )
        });
    eprintln!(
        "[backbone]   {} block finality: {:.2}s (height {}→{})",
        label,
        t.elapsed().as_secs_f64(),
        current,
        target
    );
}

pub async fn configure_replication_link(
    source: &DefraClient,
    dest: &DefraClient,
    collections: &[&str],
    label: &str,
) {
    let dest_addr = p2p_addr(dest, label);
    source
        .p2p_connect(&[&dest_addr])
        .unwrap_or_else(|e| panic!("{}: p2p connect: {}", label, e));
    wait_for_active_peer_count(source, 1, label).await;
    source
        .p2p_collection_add(collections)
        .unwrap_or_else(|e| panic!("{}: source p2p collection add: {}", label, e));
    dest.p2p_collection_add(collections)
        .unwrap_or_else(|e| panic!("{}: destination p2p collection add: {}", label, e));
    source
        .p2p_replicator_set(collections, &dest_addr)
        .unwrap_or_else(|e| panic!("{}: set replicator: {}", label, e));
    wait_for_replicator(source, &dest_addr, Duration::from_secs(15), label).await;
}

/// Wait until `source` lists a replicator to the peer of `dest_addr`.
async fn wait_for_replicator(
    source: &DefraClient,
    dest_addr: &str,
    timeout: Duration,
    label: &str,
) {
    let peer_id = dest_addr.rsplit('/').next().unwrap_or(dest_addr);
    let t = Instant::now();
    loop {
        let listed = source.p2p_replicator_list();
        if let Ok(ref replicators) = listed {
            if replicators.to_string().contains(peer_id) {
                eprintln!(
                    "[backbone]   {} replication setup ready in {:.2}s",
                    label,
                    t.elapsed().as_secs_f64()
                );
                return;
            }
        }
        if t.elapsed() > timeout {
            panic!(
                "{}: no replicator to {} within {}s (replicators: {:?})",
                label,
                peer_id,
                timeout.as_secs(),
                listed
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn graphql_string_literal(value: &str) -> String {
    serde_json::to_string(value).expect("serialize GraphQL string literal")
}

pub fn extract_doc_ids(body: &serde_json::Value, pointer: &str, label: &str) -> Vec<String> {
    body.pointer(pointer)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("{}: expected array at {}: {}", label, pointer, body))
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .get("_docID")
                .and_then(|doc_id| doc_id.as_str())
                .unwrap_or_else(|| panic!("{}: missing _docID at {}[{}]", label, pointer, index))
                .to_string()
        })
        .collect()
}

pub fn assert_doc_ids_match(
    body: &serde_json::Value,
    pointer: &str,
    expected: &[String],
    label: &str,
) {
    let mut actual_doc_ids = extract_doc_ids(body, pointer, label);
    let mut expected_doc_ids = expected.to_vec();
    actual_doc_ids.sort();
    expected_doc_ids.sort();
    assert_eq!(
        actual_doc_ids, expected_doc_ids,
        "{}: unexpected doc IDs at {}",
        label, pointer
    );
}

pub async fn poll_replicated_doc_ids(
    client: &DefraHttpClient,
    collection_name: &str,
    identity: &str,
    pointer: &str,
    expected_doc_ids: &[String],
    label: &str,
    timeout: Duration,
) -> serde_json::Value {
    let t = Instant::now();
    let expected_set = expected_doc_ids.iter().cloned().collect::<HashSet<_>>();
    let mut last_response = None;
    let mut last_sync_attempt: Option<Instant> = None;

    loop {
        if let Ok(response_body) = client
            .graphql(
                &format!("query {{ {} {{ _docID }} }}", collection_name),
                Some(identity),
            )
            .await
        {
            let actual_doc_ids = response_body
                .pointer(pointer)
                .and_then(|value| value.as_array())
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|value| {
                            value
                                .get("_docID")
                                .and_then(|doc_id| doc_id.as_str())
                                .map(ToOwned::to_owned)
                        })
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default();

            last_response = Some(response_body.clone());

            if actual_doc_ids == expected_set {
                eprintln!(
                    "[backbone]   {} replicated in {:.2}s ({} docs)",
                    label,
                    t.elapsed().as_secs_f64(),
                    actual_doc_ids.len()
                );
                return response_body;
            }

            let missing = expected_doc_ids
                .iter()
                .filter(|doc_id| !actual_doc_ids.contains(*doc_id))
                .cloned()
                .collect::<Vec<_>>();

            let should_sync = !missing.is_empty()
                && last_sync_attempt
                    .map(|last| last.elapsed() >= Duration::from_secs(3))
                    .unwrap_or_else(|| t.elapsed() >= Duration::from_secs(3));

            if should_sync {
                let sync_start = Instant::now();
                client
                    .p2p_document_sync(collection_name, &missing)
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "{}: p2p document sync for missing docs {:?}: {}",
                            label, missing, error
                        )
                    });
                eprintln!(
                    "[backbone]   {} targeted doc sync for {} missing docs in {:.2}s",
                    label,
                    missing.len(),
                    sync_start.elapsed().as_secs_f64()
                );
                last_sync_attempt = Some(Instant::now());
            }
        }

        if t.elapsed() > timeout {
            panic!(
                "{}: expected doc IDs {:?} at {} but didn't get them within {}s. Last response: {}",
                label,
                expected_doc_ids,
                pointer,
                timeout.as_secs(),
                last_response
                    .map(|body| body.to_string())
                    .unwrap_or_else(|| "<no successful response>".to_string())
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_for_tx_receipt(
    vera_account: &VeraAccount,
    tx_hash: B256,
    label: &str,
) -> eyre::Result<()> {
    let t = Instant::now();
    vera_account.wait_for_success(tx_hash).await?;
    eprintln!(
        "[backbone]   {} receipt confirmed in {:.2}s",
        label,
        t.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn poll_query_count(
    client: &DefraHttpClient,
    query: &str,
    identity: &str,
    pointer: &str,
    expected: usize,
    label: &str,
) -> serde_json::Value {
    poll_query_count_with_timeout(
        client,
        query,
        identity,
        pointer,
        expected,
        label,
        Duration::from_secs(30),
    )
    .await
}

pub async fn poll_query_count_with_timeout(
    client: &DefraHttpClient,
    query: &str,
    identity: &str,
    pointer: &str,
    expected: usize,
    label: &str,
    timeout: Duration,
) -> serde_json::Value {
    let t = Instant::now();
    let mut last_response = None;
    loop {
        if let Ok(response_body) = client.graphql(query, Some(identity)).await {
            let count = response_body
                .pointer(pointer)
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());
            last_response = Some(response_body.clone());
            if count == expected {
                eprintln!(
                    "[backbone]   {} ACP synced in {:.2}s ({} docs)",
                    label,
                    t.elapsed().as_secs_f64(),
                    count
                );
                return response_body;
            }
        }
        if t.elapsed() > timeout {
            panic!(
                "{}: expected {} docs at {} but didn't get them within {}s. Last response: {}",
                label,
                expected,
                pointer,
                timeout.as_secs(),
                last_response
                    .map(|body| body.to_string())
                    .unwrap_or_else(|| "<no successful response>".to_string())
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn poll_query_denied(
    client: &DefraHttpClient,
    query: &str,
    identity: &str,
    data_path: &str,
    label: &str,
) {
    let t = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        let result = client.graphql(query, Some(identity)).await;
        if is_acp_denied(&result, data_path) {
            eprintln!(
                "[backbone]   {} ACP revocation synced in {:.2}s",
                label,
                t.elapsed().as_secs_f64()
            );
            return;
        }
        if t.elapsed() > timeout {
            panic!(
                "{}: ACP revocation didn't propagate within {}s",
                label,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn poll_write_denied(
    client: &DefraHttpClient,
    mutation: &str,
    identity: &str,
    data_path: &str,
    label: &str,
) {
    let t = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        let result = client.graphql(mutation, Some(identity)).await;
        if is_write_acp_denied(&result, data_path) {
            eprintln!(
                "[backbone]   {} write revocation synced in {:.2}s",
                label,
                t.elapsed().as_secs_f64()
            );
            return;
        }
        if t.elapsed() > timeout {
            panic!(
                "{}: write ACP revocation didn't propagate within {}s. Last result: {}",
                label,
                timeout.as_secs(),
                match &result {
                    Ok(body) => format!("ok: {}", body),
                    Err(err) => format!("err: {}", err),
                }
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub fn is_acp_denied(result: &Result<serde_json::Value, eyre::Report>, data_path: &str) -> bool {
    let body = result
        .as_ref()
        .expect("GraphQL request failed (network error, not ACP denial)");
    has_permission_denied_error(body)
        || body
            .pointer(data_path)
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
}

pub fn is_write_acp_denied(
    result: &Result<serde_json::Value, eyre::Report>,
    create_path: &str,
) -> bool {
    let body = result
        .as_ref()
        .expect("GraphQL request failed (network error, not ACP denial)");
    has_permission_denied_error(body)
        && match body.pointer(create_path) {
            None => true,
            Some(v) => v.as_array().is_some_and(|a| a.is_empty()) || v.is_null(),
        }
}

fn has_permission_denied_error(body: &serde_json::Value) -> bool {
    const DENIAL_SUBSTRINGS: &[&str] = &[
        "permission denied",
        "access denied",
        "not authorized",
        "unauthorized",
    ];

    body.get("errors")
        .and_then(|value| value.as_array())
        .is_some_and(|errors| {
            errors.iter().any(|error| {
                let message = error
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                DENIAL_SUBSTRINGS
                    .iter()
                    .any(|needle| message.contains(needle))
            })
        })
}

fn bls_did_key(public_key_bytes: &[u8]) -> String {
    let mut buf = vec![0xea, 0x01];
    buf.extend_from_slice(public_key_bytes);
    let encoded = bs58::encode(&buf).into_string();
    format!("did:key:z{}", encoded)
}

fn p2p_addr(client: &DefraClient, label: &str) -> String {
    client
        .p2p_info()
        .unwrap_or_else(|e| panic!("{}: fetch p2p info: {}", label, e))
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{}: node has no P2P address", label))
        .to_string()
}

async fn wait_for_active_peer_count(client: &DefraClient, expected: usize, label: &str) {
    let t = Instant::now();
    let timeout = Duration::from_secs(15);
    loop {
        let count = client
            .p2p_active_peers()
            .ok()
            .and_then(|v| v.as_array().map(|arr| arr.len()))
            .unwrap_or(0);
        if count >= expected {
            eprintln!(
                "[backbone]   {} active peers ready in {:.2}s ({} peers)",
                label,
                t.elapsed().as_secs_f64(),
                count
            );
            return;
        }
        if t.elapsed() > timeout {
            panic!(
                "{}: expected at least {} active peers within {}s",
                label,
                expected,
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_event_count(
    events: &std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    expected: usize,
    timeout: Duration,
    label: &str,
) {
    let t = Instant::now();
    loop {
        let count = events.lock().unwrap().len();
        if count >= expected {
            eprintln!(
                "[backbone]   {} replication setup ready in {:.2}s ({} events)",
                label,
                t.elapsed().as_secs_f64(),
                count
            );
            return;
        }

        if t.elapsed() > timeout {
            let current = events.lock().unwrap().clone();
            panic!(
                "{}: expected {} readiness events within {}s (events: {:?})",
                label,
                expected,
                timeout.as_secs(),
                current
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
