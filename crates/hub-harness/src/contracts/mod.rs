//! Contract deployment and interaction utilities for e2e tests.
//!
//! Provides transaction signing with funded Hardhat test accounts,
//! contract deployment, storage reads, and state-changing calls.

pub mod caller;
pub mod deployer;
pub mod rpc;
pub mod signer;

pub use caller::send;
pub use deployer::{deploy, DeployReceipt};
pub use rpc::{get_balance, get_storage_at};
pub use signer::{test_address, test_signer};
