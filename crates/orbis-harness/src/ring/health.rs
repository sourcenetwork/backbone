//! Readiness polling for orbis-node gRPC endpoints.

use std::time::Duration;

use cli_tool::NodeInfoResult;
use proto::info_service::NodeStatus;

/// Health check configuration.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    /// Poll interval between health check attempts.
    pub poll_interval: Duration,
    /// Maximum time to wait for all nodes to become ready.
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            timeout: Duration::from_secs(10),
        }
    }
}

/// What a node reports once it is ready, or `None` until then.
async fn ready_info(addr: &str) -> Option<NodeInfoResult> {
    cli_tool::query_node_info(addr.to_string())
        .await
        .ok()
        .filter(|info| info.status == NodeStatus::Ready)
}

/// Wait until every node reports itself ready, in order, and return what
/// each reports.
pub async fn wait_all_ready(
    grpc_addrs: &[String],
    config: &HealthCheckConfig,
) -> eyre::Result<Vec<NodeInfoResult>> {
    let deadline = tokio::time::Instant::now() + config.timeout;
    let mut infos = Vec::with_capacity(grpc_addrs.len());
    for (index, addr) in grpc_addrs.iter().enumerate() {
        loop {
            if let Some(info) = ready_info(addr).await {
                infos.push(info);
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "timeout ({:?}) waiting for node{} at {} to become ready",
                    config.timeout,
                    index,
                    addr,
                ));
            }
            tokio::time::sleep(config.poll_interval).await;
        }
    }
    Ok(infos)
}
