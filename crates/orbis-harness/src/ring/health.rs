//! Health check polling for orbis-node gRPC endpoints.
//!
//! Uses the cli-tool's info command to determine if a node is responsive.

use std::time::Duration;

use crate::cli::OrbisCliClient;

/// Health check configuration.
#[derive(Clone, Debug)]
pub struct HealthCheckConfig {
    /// Poll interval between health check attempts.
    pub poll_interval: Duration,
    /// Maximum time to wait for all nodes to become healthy.
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

fn check_node_health(cli: &OrbisCliClient, addr: &str) -> bool {
    cli.query_node_info(addr).is_ok()
}

/// Wait for all nodes to become healthy.
///
/// Polls each node at the configured interval until all respond
/// successfully or the timeout is reached.
pub async fn wait_all_healthy(
    grpc_addrs: &[String],
    config: &HealthCheckConfig,
) -> eyre::Result<()> {
    let cli = OrbisCliClient::new()?;
    let deadline = tokio::time::Instant::now() + config.timeout;

    loop {
        let mut all_healthy = true;
        for addr in grpc_addrs {
            if !check_node_health(&cli, addr) {
                all_healthy = false;
                break;
            }
        }

        if all_healthy {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            let mut unhealthy = Vec::new();
            for (i, addr) in grpc_addrs.iter().enumerate() {
                if !check_node_health(&cli, addr) {
                    unhealthy.push(i);
                }
            }
            return Err(eyre::eyre!(
                "timeout ({:?}) waiting for {} nodes to become healthy. \
                 Unhealthy nodes: {:?}",
                config.timeout,
                grpc_addrs.len(),
                unhealthy,
            ));
        }

        tokio::time::sleep(config.poll_interval).await;
    }
}
