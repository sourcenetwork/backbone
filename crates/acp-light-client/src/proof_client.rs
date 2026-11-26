//! Fetch state proofs against finality authenticated by a configured consensus key.

mod assignments;
pub use assignments::AssignmentReadError;

use std::sync::Arc;

use alloy_primitives::B256;
use commonware_codec::DecodeExt as _;
use eyre::{ensure, WrapErr};
use vera_domain::TermCertificate;
use vera_modules::vera::administration;
use vera_permission::ObjectRegistration;

use crate::header_sync::SyncState;
use crate::rpc;
use crate::transport::{AcpTransport, HttpWsTransport};
use crate::types::{ConsensusPublicKey, LightBlock, ModuleId, VerifiedReceipt, VerifiedRecord};
use crate::verify;

/// JSON-RPC client with an independently configured consensus trust anchor.
#[derive(Clone)]
pub struct ProofClient {
    transport: Arc<dyn AcpTransport>,
    trusted_key: ConsensusPublicKey,
    genesis: Option<B256>,
}

impl ProofClient {
    /// `trusted_key_hex` must come from operator configuration, not the RPC endpoint.
    pub fn new(rpc_url: &str, trusted_key_hex: &str) -> eyre::Result<Self> {
        let trusted_key = decode_trusted_key(trusted_key_hex)?;
        Ok(Self {
            transport: Arc::new(HttpWsTransport::calls_only(rpc_url)?),
            trusted_key,
            genesis: None,
        })
    }

    /// Fetch through `transport`. The trust anchor is still configured here, not by the node.
    pub fn with_transport(
        transport: Arc<dyn AcpTransport>,
        trusted_key_hex: &str,
    ) -> eyre::Result<Self> {
        Ok(Self {
            transport,
            trusted_key: decode_trusted_key(trusted_key_hex)?,
            genesis: None,
        })
    }

    /// Name the deployment whose term certificates this client accepts.
    ///
    /// `genesis_id` is the identifier of the deployment's genesis block and,
    /// like the consensus key, must not come from the node. Without it a
    /// revision of any term above 0 is refused.
    #[must_use]
    pub fn for_deployment(mut self, genesis_id: B256) -> Self {
        self.genesis = Some(genesis_id);
        self
    }

    /// Fetch the node's term certificate and verify that it starts `term`
    /// under the operator policy in certified state at `minimum_height` or later.
    ///
    /// The certificate names the device that proposes from `term` on and the
    /// last block of the term before. The policy is read from the state of the
    /// node that serves the certificate, so this does not protect against a
    /// device that holds the deployment's consensus key and forges that state;
    /// nothing a client verifies does.
    pub async fn verified_term(
        &self,
        term: u64,
        minimum_height: u64,
    ) -> eyre::Result<TermCertificate> {
        let genesis = self.genesis.ok_or_else(|| {
            eyre::eyre!("term {term} cannot be checked: no deployment identifier is configured")
        })?;
        let certificate = rpc::term_certificate(self.transport.as_ref())
            .await?
            .ok_or_else(|| eyre::eyre!("node holds no certificate of term {term}"))?;
        ensure!(
            certificate.change.term == term,
            "node holds the certificate of term {}, not of term {term}",
            certificate.change.term
        );
        let response = self
            .fetch_and_verify_record(ModuleId::Vera, administration::STATE_KEY, minimum_height)
            .await?;
        let record = response
            .record
            .value
            .as_ref()
            .ok_or_else(|| eyre::eyre!("operator authority is not configured"))?;
        let state = administration::AdministrationState::decode(record.as_ref())
            .map_err(|error| eyre::eyre!("invalid administration record: {error}"))?;
        vera_permission::verify_term_certificate(&certificate, &genesis, &state.policy)?;
        Ok(certificate)
    }

    /// Fetch a light block without verifying it.
    pub async fn get_light_block(&self, height: u64) -> eyre::Result<LightBlock> {
        rpc::light_block(self.transport.as_ref(), height).await
    }

    /// Authenticate the requested revision using the configured consensus key.
    pub async fn verified_state(&self, height: u64) -> eyre::Result<SyncState> {
        let light = self
            .get_light_block(height)
            .await
            .wrap_err("fetching light block")?;
        ensure!(
            light.height == height,
            "light block height differs from request"
        );
        let block = verify::verify_finalized_block(&light, &self.trusted_key)?;
        Ok(SyncState {
            height,
            timestamp: block.timestamp,
            term: block.term,
            module_state_root: block.module_state_root,
            block_hash: light.block_hash.parse()?,
        })
    }

    /// Verify a current permission response against independently configured trust.
    pub async fn verify_current_permission(
        &self,
        policy: &str,
        request: &vera_permission::AccessRequest,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, bool)> {
        vera_permission::validate_request(policy, request, vera_permission::PERMISSION_LIMITS)?;
        let response =
            rpc::permission_proof(self.transport.as_ref(), policy, request, minimum_height).await?;
        let allowed = response.verify(
            policy,
            request,
            minimum_height,
            &self.trusted_key,
            vera_permission::PERMISSION_LIMITS,
        )?;
        Ok((revision_state(&response.revision)?, allowed))
    }

    /// Verify complete ownership evidence and policy liveness at one certified revision.
    pub async fn read_current_object_owner(
        &self,
        policy: &str,
        object: &vera_permission::Object,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, Option<vera_permission::Actor>)> {
        let (revision, registration) = self
            .read_current_object_registration(policy, object, minimum_height)
            .await?;
        let owner = match registration {
            ObjectRegistration::Live(owner) => Some(owner),
            ObjectRegistration::Archived | ObjectRegistration::Absent => None,
        };
        Ok((revision, owner))
    }

    /// Classify an object as live, archived or absent from complete owner evidence
    /// and policy liveness at one certified revision.
    ///
    /// An absent policy reads as `Absent`. An archived object has no owner and
    /// authorizes nothing; it differs from an absent one in that it cannot be
    /// registered again unless its previous owner unarchives it.
    pub async fn read_current_object_registration(
        &self,
        policy: &str,
        object: &vera_permission::Object,
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, ObjectRegistration)> {
        let prefix = vera_permission::object_owner_prefix(policy, object)?;
        let response =
            rpc::policy_prefix_proof(self.transport.as_ref(), policy, &prefix, minimum_height)
                .await?;
        let registration = response.verify_object_registration(
            policy,
            object,
            minimum_height,
            &self.trusted_key,
        )?;
        Ok((revision_state(&response.revision)?, registration))
    }

    /// Read an exact v5 relationship key only while its policy, relation generations
    /// and target object incarnation are current at the same certified revision.
    pub async fn read_current_relationship(
        &self,
        policy: &str,
        key: &[u8],
        minimum_height: u64,
    ) -> eyre::Result<(SyncState, VerifiedRecord)> {
        let response =
            rpc::policy_prefix_proof(self.transport.as_ref(), policy, key, minimum_height).await?;
        let evidence = response.verify(
            policy,
            key,
            minimum_height,
            &self.trusted_key,
            vera_permission::RECORD_PROOF_BYTES,
        )?;
        let value = match evidence {
            None => None,
            Some(evidence) => {
                ensure!(
                    evidence.entries.len() <= 1,
                    "relationship selection is not an exact key"
                );
                evidence
                    .entries
                    .first()
                    .map(|entry| {
                        ensure!(entry.key == key, "relationship differs from requested key");
                        Ok::<_, eyre::Report>(Arc::<[u8]>::from(entry.value.as_ref()))
                    })
                    .transpose()?
            }
        };
        let revision = revision_state(&response.revision)?;
        let record = VerifiedRecord {
            value,
            module_state_root: revision.module_state_root,
            verified_at_height: revision.height,
            // A raw point proof does not authenticate policy, generation or incarnation liveness.
            proof: None,
        };
        Ok((revision, record))
    }

    /// Fetch the committed receipt of an exact submission and verify it against
    /// the revision's receipt commitment and configured trust.
    ///
    /// `None` means the node returned no evidence; it does not show that the
    /// submission was refused or never accepted. A refusal's module and kind are
    /// committed; its message is the serving node's text.
    pub async fn fetch_and_verify_receipt(
        &self,
        submission: B256,
    ) -> eyre::Result<Option<VerifiedReceipt>> {
        let Some(response) = rpc::receipt_proof(self.transport.as_ref(), submission).await? else {
            return Ok(None);
        };
        let receipt = response.verify(submission, &self.trusted_key)?.clone();
        Ok(Some(VerifiedReceipt {
            receipt,
            revision: revision_state(&response.revision)?,
        }))
    }

    /// Fetch and verify a native record and its finalized revision in one response.
    pub async fn fetch_and_verify_record(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
    ) -> eyre::Result<vera_permission::RecordResponse> {
        eyre::ensure!(
            key.len() <= vera_permission::current::MAX_KEY_BYTES,
            "record key exceeds limit"
        );
        let response =
            rpc::record_proof(self.transport.as_ref(), module, key, minimum_height).await?;
        response.verify(
            module,
            key,
            minimum_height,
            &self.trusted_key,
            vera_permission::RECORD_PROOF_BYTES,
        )?;
        Ok(response)
    }
}

/// The state of a revision whose finality the caller has already verified.
pub(crate) fn revision_state(light: &LightBlock) -> eyre::Result<SyncState> {
    let block = verify::decode_block(light)?;
    Ok(SyncState {
        height: block.height,
        timestamp: block.timestamp,
        term: block.term,
        module_state_root: block.module_state_root,
        block_hash: light.block_hash.parse()?,
    })
}

fn decode_trusted_key(trusted_key_hex: &str) -> eyre::Result<ConsensusPublicKey> {
    let bytes = decode_hex(trusted_key_hex).wrap_err("invalid trusted consensus key hex")?;
    ConsensusPublicKey::decode(bytes).wrap_err("invalid trusted consensus key")
}

fn decode_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}
