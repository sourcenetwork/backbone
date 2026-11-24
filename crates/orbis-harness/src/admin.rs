//! Native Vera administration of Orbis nodes, rings and documents.
//!
//! The ring controller signs node requests and delegates ring and document
//! commands to the deployment's administering account, which submits them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::{eyre, Result, WrapErr};
use vera_client::nodes::{
    encode_node_request, sign_node_request, NodeCommand, NodeRequest, NodeTarget,
};
use vera_client::rings::{
    encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState,
};
use vera_client::threshold_objects::{
    encode_threshold_object, EncryptedDocument, KeyDerivation, ObjectKind, ThresholdObject,
};
use vera_client::{
    create_scoped_bearer_token, DelegationScope, Secp256k1SigningKey, VeraClient, VERA_ADDRESS,
};
use vera_domain::ConsensusPublicKey;
use vera_support::{VeraAccount, VeraDeployment};

/// The secret of the controller that manages every node of a test ring.
const CONTROLLER_SECRET: [u8; 32] = [34; 32];
/// How long a delegation or a node request stays valid.
const VALIDITY: u64 = 300;
/// The shortest refresh interval a live ring may name.
const PSS_INTERVAL: u64 = 86_400;
const POLL: Duration = Duration::from_millis(100);

/// A policy for a ring and the documents it encrypts: the controller
/// creates rings under it, nodes sign under `key`, readers read `document`.
pub const RING_POLICY_YAML: &str = r#"
name: orbis-harness-ring-policy
resources:
  - name: ring_policy
    relations:
      - name: creator
        types:
          - actor
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
        types:
          - actor
    permissions:
      - name: update_ring
        expr: operator
  - name: key
    relations:
      - name: signer
        types:
          - actor
    permissions:
      - name: sign
        expr: signer
  - name: document
    relations:
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: reader
"#;

/// Administers Orbis on one Vera deployment.
pub struct RingAdmin {
    account: VeraAccount,
    client: VeraClient,
    trusted: ConsensusPublicKey,
    deployment_root: [u8; 32],
    deployment_id: u64,
    controller: Secp256k1SigningKey,
}

impl RingAdmin {
    pub async fn new(vera: &VeraDeployment) -> Result<Self> {
        Ok(Self {
            account: vera.admin().await?,
            client: vera.client(),
            trusted: *vera.consensus_key(),
            deployment_root: vera.genesis_id().0,
            deployment_id: vera.deployment_id(),
            controller: Secp256k1SigningKey::from_slice(&CONTROLLER_SECRET)?,
        })
    }

    /// The account that creates policies, grants relations and submits.
    pub fn account(&self) -> &VeraAccount {
        &self.account
    }

    /// The deployment label Orbis clients bind their requests to.
    pub fn chain_id(&self) -> String {
        vera_client::rings::ring_deployment_label(self.deployment_root, self.deployment_id)
    }

    /// The controller's compressed public key, as `--node-controller-key` takes it.
    pub fn controller_key_hex(&self) -> String {
        hex::encode(self.controller.verifying_key().to_sec1_bytes())
    }

    /// The controller's actor DID.
    pub fn controller_did(&self) -> Result<String> {
        Ok(vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            self.controller.verifying_key().to_sec1_bytes().as_ref(),
        )?)
    }

    /// Route a registered node at `p2p_address` and allow it rings of `policy_id`.
    pub async fn authorize_node(
        &self,
        node_key: &str,
        p2p_address: &str,
        policy_id: &str,
        timeout: Duration,
    ) -> Result<()> {
        for command in [
            NodeCommand::SetPeer(p2p_address.to_string()),
            NodeCommand::Allow(NodeTarget::Policy(policy_id.to_string())),
        ] {
            let sequence = self.registered_sequence(node_key, timeout).await?;
            let signed = sign_node_request(
                NodeRequest {
                    deployment_root: self.deployment_root,
                    deployment_id: self.deployment_id,
                    node_key: node_key.to_string(),
                    sequence,
                    expires_at: now() + VALIDITY,
                    command,
                },
                &self.controller,
            )?;
            self.account
                .submit(VERA_ADDRESS, encode_node_request(&signed)?)
                .await
                .wrap_err("node request")?;
        }
        Ok(())
    }

    /// The next sequence of a node, once the node has registered itself.
    async fn registered_sequence(&self, node_key: &str, timeout: Duration) -> Result<u64> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let read = self
                .client
                .read_threshold_node(node_key, 1, &self.trusted)
                .await?;
            if let Some(record) = read.record {
                return Ok(record.sequence);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre!("node {node_key} did not register within {timeout:?}"));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Let the controller create rings under `policy_id`, then create one
    /// over `node_keys` and return its id.
    pub async fn create_ring(
        &self,
        policy_id: &str,
        node_keys: &[String],
        threshold: u32,
    ) -> Result<String> {
        self.account
            .register_object(policy_id, "ring_policy", policy_id)
            .await?;
        self.account
            .set_relationship(
                policy_id,
                "ring_policy",
                policy_id,
                "creator",
                &self.controller_did()?,
            )
            .await?;
        let mut peer_node_keys = node_keys.to_vec();
        peer_node_keys.sort();
        let config = RingConfig {
            policy_id: policy_id.to_string(),
            peer_node_keys,
            threshold,
            pss_interval: PSS_INTERVAL,
            current_version: 0,
            requires_pet: false,
            nonce: rand::random(),
            trusted_auth_relay_dids: None,
            pre_share_endpoints: Vec::new(),
            reporting: ReportingConfig::default(),
        };
        let ring_id = config.id()?;
        let token = self.delegation(DelegationScope::ManageRings)?;
        self.account
            .submit(
                VERA_ADDRESS,
                encode_ring_command(&RingCommand::Create(config), &token)?,
            )
            .await
            .wrap_err("create ring")?;
        Ok(ring_id)
    }

    /// Wait until the ring's key generation finalizes and return its public key.
    pub async fn wait_for_ring_key(&self, ring_id: &str, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let read = self
                .client
                .read_threshold_ring(ring_id, 1, &self.trusted)
                .await;
            if let Ok(read) = read {
                if let Some(RingState::Active { keys }) = read.record.map(|record| record.state) {
                    return Ok(keys.public_key);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre!("ring {ring_id} did not finalize within {timeout:?}"));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Store an encrypted document directly, as a client that holds the
    /// controller's delegation does, and return its id.
    pub async fn register_document(&self, document: EncryptedDocument) -> Result<String> {
        let object = ThresholdObject::Document(document);
        let id = object.id()?;
        let token = self.delegation(DelegationScope::StoreThresholdObject)?;
        self.account
            .submit(VERA_ADDRESS, encode_threshold_object(&object, &token)?)
            .await
            .wrap_err("store document")?;
        Ok(id)
    }

    /// Register a signing key derived from `ring_id` under `derivation`,
    /// usable by actors holding `permission` on it, and return its id.
    pub async fn register_key_derivation(
        &self,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<String> {
        let object = ThresholdObject::KeyDerivation(KeyDerivation {
            ring_id: ring_id.to_string(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        });
        let id = object.id()?;
        let token = self.delegation(DelegationScope::StoreThresholdObject)?;
        self.account
            .submit(VERA_ADDRESS, encode_threshold_object(&object, &token)?)
            .await
            .wrap_err("store key derivation")?;
        Ok(id)
    }

    /// The certified document stored under `id`, if any.
    pub async fn read_document(&self, id: &str) -> Result<Option<EncryptedDocument>> {
        let read = self
            .client
            .read_threshold_object(ObjectKind::Document, id, 1, &self.trusted)
            .await?;
        Ok(read.record.map(|record| match record.object {
            ThresholdObject::Document(document) => Ok(document),
            ThresholdObject::KeyDerivation(_) => Err(eyre!("{id} names a key derivation")),
        }))
        .and_then(|document| document.transpose())
    }

    fn delegation(&self, scope: DelegationScope) -> Result<String> {
        let issued = now();
        Ok(create_scoped_bearer_token(
            &self.controller,
            self.account.did(),
            self.deployment_id,
            issued,
            issued + VALIDITY,
            scope,
        )?)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the Unix epoch")
        .as_secs()
}
