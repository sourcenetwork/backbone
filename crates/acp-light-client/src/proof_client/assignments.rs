use vera_modules::acp::{keys, types::PolicyRecord};
use vera_permission::{
    AssignmentSelector, ModuleId, PolicyPrefixResponse, RecordResponse, RECORD_PROOF_BYTES,
    RECORD_RESPONSE_BYTES,
};

use super::ProofClient;
use crate::transport::TransportError;

/// Failure to obtain complete certified assignment evidence.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentReadError {
    /// The proof service could not answer the request.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The response did not contain valid JSON.
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
    /// The evidence failed verification or exceeded its budget.
    #[error(transparent)]
    Proof(#[from] vera_permission::PermissionError),
    /// The policy is absent or does not contain the requested relation.
    #[error("{0}")]
    Invalid(&'static str),
    /// The policy or active revision changed during the read.
    #[error("assignment revision changed; retry")]
    Overtaken,
    /// The light client cannot establish a fresh active revision.
    #[error("assignment revision unavailable: {0}")]
    Revision(String),
}

impl ProofClient {
    async fn assignment_generation(
        &self,
        policy: &str,
        selector: &AssignmentSelector<'_>,
        minimum: u64,
    ) -> Result<(u64, u64), AssignmentReadError> {
        let policy_prefix = keys::relationship_policy_prefix(policy);
        vera_permission::validate_policy_prefix(policy, &policy_prefix)?;
        let key = keys::policy_key(policy);
        let value = self
            .transport
            .call(
                "vera_getCurrentRecordProof",
                serde_json::json!([ModuleId::Acp, format!("0x{}", hex::encode(&key)), minimum]),
                RECORD_RESPONSE_BYTES,
            )
            .await?;
        let policy_response: RecordResponse = serde_json::from_value(value)?;
        policy_response.verify(
            ModuleId::Acp,
            &key,
            minimum,
            &self.trusted_key,
            RECORD_PROOF_BYTES,
        )?;
        let bytes = policy_response
            .record
            .value
            .as_ref()
            .ok_or(AssignmentReadError::Invalid("policy is absent"))?;
        let record: PolicyRecord = serde_json::from_slice(bytes)?;
        if record.policy.id != policy
            || record.derived_id() != policy
            || record.relations.validate(&record.policy).is_err()
        {
            return Err(AssignmentReadError::Invalid("invalid authenticated policy"));
        }
        let generation = record
            .relations
            .generation(selector.resource, selector.relation)
            .ok_or(AssignmentReadError::Invalid("relation is absent"))?;
        if generation == 0 {
            return Err(AssignmentReadError::Invalid(
                "owner relation requires object-scoped evidence",
            ));
        }
        Ok((generation, policy_response.revision.height))
    }

    pub(crate) async fn assignment_evidence(
        &self,
        policy: &str,
        selector: &AssignmentSelector<'_>,
        minimum: u64,
    ) -> Result<PolicyPrefixResponse, AssignmentReadError> {
        let (generation, selected_height) = self
            .assignment_generation(policy, selector, minimum)
            .await?;
        let prefix = keys::relationship_target_prefix(policy, generation);
        let minimum = minimum.max(selected_height);
        let result = self
            .transport
            .call(
                "vera_getCurrentPolicyPrefixProof",
                serde_json::json!([policy, format!("0x{}", hex::encode(&prefix)), minimum]),
                RECORD_RESPONSE_BYTES,
            )
            .await;
        let value = match result {
            Ok(value) => value,
            Err(error) => match self.assignment_generation(policy, selector, minimum).await {
                Ok((current, _)) if current != generation => {
                    return Err(AssignmentReadError::Overtaken)
                }
                Err(AssignmentReadError::Invalid("policy is absent" | "relation is absent")) => {
                    return Err(AssignmentReadError::Overtaken)
                }
                _ => return Err(error.into()),
            },
        };
        let evidence: PolicyPrefixResponse = serde_json::from_value(value)?;
        let block = vera_domain::verify_finalized_block(&evidence.revision, &self.trusted_key)
            .map_err(|error| AssignmentReadError::Revision(error.to_string()))?;
        if block.height < minimum {
            return Err(AssignmentReadError::Overtaken);
        }
        evidence.proof.policy.verify(
            block.module_state_root,
            ModuleId::Acp,
            &keys::policy_key(policy),
            RECORD_PROOF_BYTES,
        )?;
        let current: PolicyRecord = serde_json::from_slice(
            evidence
                .proof
                .policy
                .value
                .as_ref()
                .ok_or(AssignmentReadError::Overtaken)?,
        )?;
        if current.policy.id != policy
            || current.derived_id() != policy
            || current.relations.validate(&current.policy).is_err()
        {
            return Err(AssignmentReadError::Invalid("invalid authenticated policy"));
        }
        if current
            .relations
            .generation(selector.resource, selector.relation)
            != Some(generation)
        {
            return Err(AssignmentReadError::Overtaken);
        }
        evidence.verify(
            policy,
            &prefix,
            minimum,
            &self.trusted_key,
            RECORD_PROOF_BYTES,
        )?;
        evidence.verify_assignments(
            policy,
            selector,
            minimum,
            &self.trusted_key,
            RECORD_PROOF_BYTES,
        )?;
        Ok(evidence)
    }
}
