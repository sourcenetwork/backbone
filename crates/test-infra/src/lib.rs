//! Shared integration test primitives for Source Network components.
//!
//! Provides the foundational building blocks that all component harnesses use:
//! - `ManagedProcess` — child process lifecycle (SIGTERM → wait → SIGKILL)
//! - `TestRunDir` — isolated test artifact directories with RAII cleanup
//! - `LogTracker` — async log file tailing with pattern matching and event broadcasting
//! - Port allocation — ephemeral OS-assigned ports for parallel test execution
//! - Health check polling — configurable readiness detection
