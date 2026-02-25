//! Hub.rs node manager, cluster builder, and observability.
//!
//! Provides everything needed to start, configure, and observe Hub.rs
//! validator clusters in integration tests:
//! - `TestClusterBuilder` — BFT-aware cluster setup with key generation
//! - `KeySet` — deterministic ed25519 + BLS threshold scheme generation
//! - `ClusterState` — unified observability (log tracking + RPC polling)
//! - `GenesisBuilder` — EVM-compatible genesis configuration
//! - `FaultInjector` — BFT fault injection patterns
//! - Consensus presets — Fast/Normal/Stress timing profiles

pub mod cluster;
pub mod contracts;
pub mod fault;
pub mod observe;
