//! HTTP-based RPC poller for monitoring node state.

use std::{sync::Arc, time::Duration};

use tokio::sync::broadcast;

use super::{rpc_events::RpcEvent, rpc_snapshot::NodeSnapshot};

/// Polls node RPC endpoints at a regular interval and emits events.
#[derive(Debug)]
pub struct RpcPoller {
    tx: broadcast::Sender<RpcEvent>,
    snapshots: Arc<parking_lot::RwLock<Vec<NodeSnapshot>>>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl RpcPoller {
    /// Create a new poller for the given node RPC URLs.
    pub fn new(rpc_urls: Vec<String>, poll_interval: Duration) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let n = rpc_urls.len();
        let snapshots = Arc::new(parking_lot::RwLock::new(
            (0..n)
                .map(|i| NodeSnapshot {
                    node_index: i,
                    ..Default::default()
                })
                .collect(),
        ));

        let mut handles = Vec::with_capacity(n);

        for (i, url) in rpc_urls.into_iter().enumerate() {
            let tx = tx.clone();
            let snapshots = snapshots.clone();

            let handle = tokio::spawn(async move {
                Self::poll_loop(i, url, poll_interval, tx, snapshots).await;
            });
            handles.push(handle);
        }

        Self {
            tx,
            snapshots,
            _handles: handles,
        }
    }

    /// Subscribe to RPC events.
    pub fn subscribe(&self) -> broadcast::Receiver<RpcEvent> {
        self.tx.subscribe()
    }

    /// Get the latest snapshot for a specific node.
    pub fn snapshot(&self, node_index: usize) -> NodeSnapshot {
        self.snapshots.read()[node_index].clone()
    }

    /// Get snapshots for all nodes.
    pub fn all_snapshots(&self) -> Vec<NodeSnapshot> {
        self.snapshots.read().clone()
    }

    async fn poll_loop(
        node_index: usize,
        rpc_url: String,
        interval: Duration,
        tx: broadcast::Sender<RpcEvent>,
        snapshots: Arc<parking_lot::RwLock<Vec<NodeSnapshot>>>,
    ) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("http client");

        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            // Poll hub_nodeStatus.
            let status = Self::call_node_status(&client, &rpc_url).await;
            let block_height = Self::call_latest_block(&client, &rpc_url).await;

            let mut snaps = snapshots.write();
            let snap = &mut snaps[node_index];
            let prev_view = snap.current_view;
            let prev_finalized = snap.finalized_count;
            let prev_peers = snap.peer_count;
            let prev_leader = snap.is_leader;
            let prev_height = snap.latest_block_height;

            if let Some(ref s) = status {
                snap.chain_id = s.chain_id;
                snap.validator_index = s.validator_index;
                snap.validator_count = s.validator_count;
                snap.uptime_secs = s.uptime_secs;
                snap.current_view = s.current_view;
                snap.finalized_count = s.finalized_count;
                snap.proposed_count = s.proposed_count;
                snap.nullified_count = s.nullified_count;
                snap.peer_count = s.peer_count;
                snap.is_leader = s.is_leader;
                snap.backfilling = s.backfilling;
                snap.is_healthy = true;
            }

            if let Some(height) = block_height {
                snap.latest_block_height = height;
            }

            // Emit events for state changes.
            if let Some(ref s) = status {
                if s.current_view != prev_view {
                    let _ = tx.send(RpcEvent::ViewAdvanced {
                        node: node_index,
                        view: s.current_view,
                    });
                }
                if s.finalized_count != prev_finalized {
                    let _ = tx.send(RpcEvent::Finalized {
                        node: node_index,
                        count: s.finalized_count,
                    });
                }
                if s.peer_count != prev_peers {
                    let _ = tx.send(RpcEvent::PeerCountChanged {
                        node: node_index,
                        peers: s.peer_count,
                    });
                }
                if s.is_leader != prev_leader {
                    let _ = tx.send(RpcEvent::LeaderChanged {
                        node: node_index,
                        is_leader: s.is_leader,
                    });
                }
            }

            if let Some(height) = block_height {
                if height != prev_height {
                    let _ = tx.send(RpcEvent::NewBlock {
                        node: node_index,
                        height,
                    });
                }
            }

            if status.is_none() {
                snaps[node_index].is_healthy = false;
            }
        }
    }

    async fn call_node_status(client: &reqwest::Client, url: &str) -> Option<NodeStatusResponse> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "hub_nodeStatus",
            "params": [],
            "id": 1
        });

        let resp = client.post(url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let result = json.get("result")?;
        serde_json::from_value(result.clone()).ok()
    }

    async fn call_latest_block(client: &reqwest::Client, url: &str) -> Option<u64> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 2
        });

        let resp = client.post(url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let result = json.get("result")?;
        let number_hex = result.get("number")?.as_str()?;
        u64::from_str_radix(number_hex.trim_start_matches("0x"), 16).ok()
    }
}

impl Drop for RpcPoller {
    fn drop(&mut self) {
        for handle in &self._handles {
            handle.abort();
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeStatusResponse {
    chain_id: u64,
    validator_index: u32,
    #[serde(default)]
    validator_count: u32,
    uptime_secs: u64,
    current_view: u64,
    finalized_count: u64,
    proposed_count: u64,
    nullified_count: u64,
    peer_count: u64,
    is_leader: bool,
    #[serde(default)]
    backfilling: bool,
}
