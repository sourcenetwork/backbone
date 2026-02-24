/// Which DefraDB implementation a node is running.
///
/// Threading this through the test harness makes every Go/Rust behavioral
/// difference explicit at the call site rather than hidden behind `or_else()`
/// fallback chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Rust,
    Go,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::Rust => write!(f, "Rust"),
            NodeKind::Go => write!(f, "Go"),
        }
    }
}

// ---- Divergence catalog ----
//
// Every known behavioral difference between Go and Rust DefraDB is listed
// here, grouped by category. When a divergence is resolved (Go and Rust
// converge), the function is collapsed to return a single shared value.
//
// Remaining divergences are an at-a-glance measure of how far apart the
// implementations are.

// -- Start command flags (CONVERGED) --

/// ACP document type flag name. Both use `--document-acp-type`.
pub fn acp_document_type_flag(_kind: NodeKind) -> &'static str {
    "--document-acp-type"
}

/// NAC enable flag name. Both use `--node-acp-enable`.
pub fn nac_enable_flag(_kind: NodeKind) -> &'static str {
    "--node-acp-enable"
}

// -- CLI subcommand syntax (CONVERGED) --

/// Collection doc-ids subcommand name. Both use `docIDs`.
pub fn doc_ids_subcommand(_kind: NodeKind) -> &'static str {
    "docIDs"
}

/// Both Go and Rust now use `--collection`/`--name` flags for index commands.
pub fn index_uses_positional_args(_kind: NodeKind) -> bool {
    false
}

/// Both Go and Rust now use `--collection`/`--field` flags for encrypted-index commands.
pub fn encrypted_index_uses_positional_args(_kind: NodeKind) -> bool {
    false
}

// -- Output format (DIVERGENT) --

/// Whether the query command wraps output in `{"data": ...}`.
/// Go: yes (also prefixes with "Request Results" header)
/// Rust: no (returns data directly)
pub fn query_wraps_in_data(kind: NodeKind) -> bool {
    match kind {
        NodeKind::Rust => false,
        NodeKind::Go => true,
    }
}

/// Doc ID output format.
/// Rust: `{"doc_ids": ["id1", ...]}`
/// Go: line-separated `{"DocID": "id1"}\n{"DocID": "id2"}\n...`
#[derive(Debug, Clone, Copy)]
pub enum DocIdFormat {
    /// `{"doc_ids": ["id1", ...]}`
    RustArray,
    /// Line-separated `{"DocID": "..."}`
    GoLineObjects,
}

pub fn doc_id_format(kind: NodeKind) -> DocIdFormat {
    match kind {
        NodeKind::Rust => DocIdFormat::RustArray,
        NodeKind::Go => DocIdFormat::GoLineObjects,
    }
}

// -- Log patterns --

/// The log line substring that indicates the HTTP server is ready.
/// Both use the same pattern currently.
pub fn ready_log_pattern(_kind: NodeKind) -> &'static str {
    "Providing HTTP API at"
}

/// Peer-connected log pattern regex.
/// Rust: `"Peer connected: "`, Go: `"Peer connected|PeerConnect"`
pub fn peer_connected_pattern(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Rust => r"Peer connected: ",
        NodeKind::Go => r"Peer connected|PeerConnect",
    }
}

/// P2P listening log pattern regex.
/// Rust: `"Now listening on: "`, Go: `"Created LibP2P host"`
pub fn p2p_listening_pattern(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Rust => r"Now listening on: ",
        NodeKind::Go => r"Created LibP2P host",
    }
}

// -- SourceHub support --

/// Whether the node supports `--source-hub-*` start flags.
/// Rust: yes, Go: not yet
pub fn supports_source_hub_flags(kind: NodeKind) -> bool {
    match kind {
        NodeKind::Rust => true,
        NodeKind::Go => false,
    }
}
