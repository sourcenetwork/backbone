//! Log event types emitted by the LogTracker.

/// Events parsed from validator process stdout.
#[derive(Clone, Debug)]
pub enum LogEvent {
    /// A block was built by this node.
    BlockBuilt {
        /// Block height.
        height: u64,
        /// Number of transactions in the block.
        txs: u64,
        /// Time to build the block in milliseconds.
        total_ms: u64,
    },
    /// A block was verified by this node.
    BlockVerified {
        /// Block height.
        height: u64,
        /// Number of transactions in the block.
        txs: u64,
        /// Time to verify the block in milliseconds.
        total_ms: u64,
    },
    /// An error log line.
    Error {
        /// Log level (ERROR).
        level: String,
        /// The log message.
        message: String,
    },
}
