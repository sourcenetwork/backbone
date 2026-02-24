//! Orbis ring builder, DKG fixtures, and event subscriptions.
//!
//! Provides everything needed to start, configure, and orchestrate Orbis
//! DKG rings in integration tests:
//! - `OrbisRingBuilder` — multi-node ring setup with threshold configuration
//! - `DkgFixture` — complete SourceHub + Orbis ring setup with DKG ceremony
//! - Event-based synchronization — WebSocket subscriptions for DKG completion
//! - CLI tool integration — direct Rust function calls for DKG, PRE, encryption
