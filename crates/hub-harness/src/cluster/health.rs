//! Fast health check for cluster startup.
//!
//! Polls eth_chainId with 50ms intervals and no initial wait,
//! targeting sub-5-second cold start for 4-node clusters.

use std::time::Duration;

/// Fast health check configuration.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    /// Poll interval between health check attempts.
    pub poll_interval: Duration,
    /// Maximum time to wait for all nodes.
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Check if a single node is healthy by calling eth_chainId.
async fn check_node_health(client: &reqwest::Client, url: &str) -> bool {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_chainId",
        "params": [],
        "id": 1
    });

    client
        .post(url)
        .json(&body)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Wait for all nodes to become healthy.
pub async fn wait_all_healthy(rpc_urls: &[String], config: &HealthCheckConfig) -> eyre::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    let deadline = tokio::time::Instant::now() + config.timeout;

    loop {
        let mut handles = Vec::with_capacity(rpc_urls.len());
        for url in rpc_urls {
            let client = client.clone();
            let url = url.clone();
            handles.push(tokio::spawn(async move {
                check_node_health(&client, &url).await
            }));
        }

        let mut all_healthy = true;
        for handle in handles {
            if !handle.await.unwrap_or(false) {
                all_healthy = false;
            }
        }

        if all_healthy {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timeout ({:?}) waiting for {} nodes to become healthy",
                config.timeout,
                rpc_urls.len()
            ));
        }

        tokio::time::sleep(config.poll_interval).await;
    }
}
