//! DefraDB node manager, CLI client, and test fixtures.
//!
//! Provides everything needed to start, configure, and interact with DefraDB
//! nodes in integration tests:
//! - `DefraNode` trait — abstraction over Rust and Go binaries
//! - `TestClusterBuilder` — fluent API for multi-node cluster setup
//! - `DefraClient` — CLI-based client wrapping all DefraDB operations
//! - Test macros — `for_each_runtime!`, `for_each_p2p_topology!`
//! - Fixtures — ACP policies, schemas, identity generators
