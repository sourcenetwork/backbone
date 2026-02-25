//! Shared integration test primitives for Source Network components.
//!
//! Provides the foundational building blocks that all component harnesses use:
//! - [`ManagedProcess`] — child process lifecycle (SIGTERM → wait → SIGKILL)
//! - [`TestRunDir`] — isolated test artifact directories with RAII cleanup
//! - [`LogTracker`] — async log file tailing with pattern matching
//! - [`BinaryResolver`] — version-aware binary resolution (local build → PATH → source)
//! - Port allocation — ephemeral OS-assigned ports for parallel test execution
//! - Health check polling — configurable readiness detection

pub mod binary;
pub mod log_tracker;
pub mod manifest;
pub mod poll;
pub mod ports;
pub mod process;
pub mod run;

pub use binary::{BinaryResolver, BinarySource, ResolvedBinary};
pub use log_tracker::{LogEvent, LogTracker, NamedPattern};
pub use manifest::{ComponentPin, Manifest};
pub use poll::poll_until;
pub use ports::allocate_ports;
pub use process::ManagedProcess;
pub use run::TestRunDir;
