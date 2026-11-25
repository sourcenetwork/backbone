//! How an Orbis node reaches its Vera deployment.

use vera_support::VeraDeployment;

/// The trust material and endpoint an Orbis node's `--services-config`
/// names for its authorization and bulletin backends.
#[derive(Clone, Debug)]
pub struct OrbisVeraConfig {
    pub endpoint: String,
    pub deployment_id: u64,
    pub deployment_root: String,
    pub consensus_key: String,
}

impl From<&VeraDeployment> for OrbisVeraConfig {
    fn from(deployment: &VeraDeployment) -> Self {
        Self {
            endpoint: deployment.rpc_url(),
            deployment_id: deployment.deployment_id(),
            deployment_root: deployment.genesis_id_hex(),
            consensus_key: deployment.consensus_key_hex(),
        }
    }
}

impl OrbisVeraConfig {
    /// The `--services-config` document: authorization reads only, the
    /// bulletin also signs submissions for the deployment.
    pub fn services_config(&self) -> serde_json::Value {
        serde_json::json!({
            "authz": {
                "endpoint": self.endpoint,
                "deployment_root": self.deployment_root,
                "consensus_key": self.consensus_key,
            },
            "bulletin": {
                "endpoint": self.endpoint,
                "deployment_id": self.deployment_id,
                "deployment_root": self.deployment_root,
                "consensus_key": self.consensus_key,
            },
        })
    }
}
