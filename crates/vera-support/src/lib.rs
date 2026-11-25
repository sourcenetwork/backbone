//! Native Vera deployments and administration for Backbone's integration tests.
//!
//! A [`VeraDeployment`] runs a vera.rs cluster and names the trust material
//! that DefraDB and Orbis are configured with; a [`VeraAccount`] submits
//! native requests to it.

mod account;
mod deployment;

pub use account::{AcpRelationshipTx, AcpRelationshipTxKind, VeraAccount, ADMIN_KEY};
pub use deployment::VeraDeployment;
