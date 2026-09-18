//! The three identities the cases speak as, and their NAC grants on every
//! target. Grants go through `acp node relationship add` as the cluster's
//! startup identity (the NAC owner), live, no restart.

use std::collections::HashMap;
use std::path::Path;

use eyre::{Result, WrapErr};
use serde::Serialize;

use crate::auth::{manage_token, Identity};
use crate::nodes::Nodes;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Actor {
    /// The `admin` relation: every node permission.
    Admin,
    /// `add-p2p-collection` and `list-p2p-replicator` only, so `CollectionAdd`
    /// lands and `ReplicatorAdd` is refused from the same actor. Granted on
    /// every run; the first case to speak as it is A1.
    #[allow(dead_code)]
    Operator,
    /// No grants.
    Outsider,
}

pub const OPERATOR_GRANTS: &[&str] = &["add-p2p-collection", "list-p2p-replicator"];

#[derive(Serialize)]
pub struct Actors {
    pub admin: Identity,
    pub operator: Identity,
    pub outsider: Identity,
    /// Manage tokens per (actor, target peer id); they outlive a run.
    #[serde(skip)]
    tokens: HashMap<(Actor, String), String>,
}

impl Actors {
    pub fn generate(bin: &Path) -> Result<Self> {
        Ok(Self {
            admin: crate::generate_identity(bin, "admin")?,
            operator: crate::generate_identity(bin, "operator")?,
            outsider: crate::generate_identity(bin, "outsider")?,
            tokens: HashMap::new(),
        })
    }

    /// Apply the grants on node `i` as `owner_key`.
    pub fn grant_on(&self, nodes: &Nodes, i: usize, owner_key: &str) -> Result<()> {
        let client = nodes.client(i);
        let name = nodes.name(i);
        client
            .acp_node_relationship_add("admin", &self.admin.did, owner_key)
            .wrap_err_with(|| format!("granting admin on {name}"))?;
        for relation in OPERATOR_GRANTS {
            client
                .acp_node_relationship_add(relation, &self.operator.did, owner_key)
                .wrap_err_with(|| format!("granting {relation} on {name}"))?;
        }
        Ok(())
    }

    pub fn token(&mut self, actor: Actor, target_peer_id: &str) -> Result<String> {
        let key = match actor {
            Actor::Admin => &self.admin.key_hex,
            Actor::Operator => &self.operator.key_hex,
            Actor::Outsider => &self.outsider.key_hex,
        };
        let k = (actor, target_peer_id.to_string());
        if let Some(tok) = self.tokens.get(&k) {
            return Ok(tok.clone());
        }
        let tok = manage_token(key, target_peer_id)?;
        self.tokens.insert(k, tok.clone());
        Ok(tok)
    }
}
