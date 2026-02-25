use std::path::PathBuf;

use test_infra::ManagedProcess;

/// A single managed node in the Orbis ring.
///
/// Each node has a gRPC endpoint and a data directory with logs.
pub struct OrbisNode {
    pub(crate) index: usize,
    pub(crate) grpc_port: u16,
    pub(crate) data_dir: PathBuf,
    pub(crate) log_dir: PathBuf,
    pub(crate) process: ManagedProcess,
}

impl OrbisNode {
    /// Node index within the ring.
    pub fn index(&self) -> usize {
        self.index
    }

    /// gRPC address for this node (e.g. "http://127.0.0.1:50051").
    pub fn grpc_addr(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    /// gRPC port.
    pub fn grpc_port(&self) -> u16 {
        self.grpc_port
    }

    /// Path to this node's data directory.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// Path to this node's log directory.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.log_dir
    }

    /// Path to stdout.log for this node.
    pub fn stdout_log(&self) -> PathBuf {
        self.log_dir.join("stdout.log")
    }

    /// Path to stderr.log for this node.
    pub fn stderr_log(&self) -> PathBuf {
        self.log_dir.join("stderr.log")
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        self.process.is_running()
    }

    /// Kill the process.
    pub fn kill(&mut self) {
        self.process.kill();
    }
}
