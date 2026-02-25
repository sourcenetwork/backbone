//! Assertion helpers for cluster state validation.

use super::{cluster_state::ClusterState, events::LogEvent};

/// Known hub errors that are expected and should not fail tests.
///
/// hub binds both jsonrpsee and a status HTTP server to the same port —
/// the second binding always fails with "Address already in use".
const KNOWN_ERRORS: &[&str] = &["HTTP status server not started"];

/// Extension trait for cluster-level assertions.
pub trait ClusterAssertions {
    /// Assert no unexpected errors have been logged by any node.
    fn assert_no_errors(&self) -> eyre::Result<()>;

    /// Assert all healthy nodes have the same latest block height (within tolerance).
    fn assert_heights_converged(&self, tolerance: u64) -> eyre::Result<()>;
}

impl ClusterAssertions for ClusterState {
    fn assert_no_errors(&self) -> eyre::Result<()> {
        let errors = self.all_errors();
        let unexpected: Vec<_> = errors
            .iter()
            .filter(|(_, e)| {
                let msg = match e {
                    LogEvent::Error { message, .. } => message.as_str(),
                    _ => return true,
                };
                !KNOWN_ERRORS.iter().any(|known| msg.contains(known))
            })
            .collect();

        if unexpected.is_empty() {
            Ok(())
        } else {
            let msgs: Vec<String> = unexpected
                .iter()
                .map(|(node, e)| format!("node{}: {:?}", node, e))
                .collect();
            Err(eyre::eyre!(
                "cluster has {} unexpected errors:\n{}",
                unexpected.len(),
                msgs.join("\n")
            ))
        }
    }

    fn assert_heights_converged(&self, tolerance: u64) -> eyre::Result<()> {
        let snaps = self.all_nodes();
        let healthy: Vec<_> = snaps.iter().filter(|s| s.is_healthy).collect();
        if healthy.is_empty() {
            return Err(eyre::eyre!("no healthy nodes"));
        }

        let min = healthy
            .iter()
            .map(|s| s.effective_height())
            .min()
            .unwrap_or(0);
        let max = healthy
            .iter()
            .map(|s| s.effective_height())
            .max()
            .unwrap_or(0);

        if max - min > tolerance {
            return Err(eyre::eyre!(
                "block heights not converged: min={}, max={}, tolerance={}",
                min,
                max,
                tolerance
            ));
        }
        Ok(())
    }
}
