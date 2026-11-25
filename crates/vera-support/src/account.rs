use std::time::Duration;

use alloy_primitives::{Address, Bytes, B256};
use std::time::{SystemTime, UNIX_EPOCH};

use vera_client::{
    create_operation_token, parse_policy_id, predict_policy_id, random_policy_nonce, BlsSigner,
    PolicyMarshalingType, PolicyNonce, PolicyOperation, Secp256k1SigningKey, TransactionReceipt,
    VeraClient, ACP_ADDRESS,
};
use vera_crypto::operation::OperationId;
use vera_modules::acp::types::PolicyCmd;

/// The secret scalar of the account the tests administer Vera with.
pub const ADMIN_KEY: [u8; 32] = [7; 32];

/// YAML, as `PolicyMarshalingType::ShortYaml` numbers it on the wire.
const YAML: u8 = 1;
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(300);
const RECEIPT_POLL_ATTEMPTS: u32 = 400;
/// How long an owner's signed operation stays valid.
const OPERATION_LIFETIME_SECS: u64 = 300;

#[derive(Clone, Copy)]
pub enum AcpRelationshipTxKind {
    Set,
    Delete,
}

#[derive(Clone, Copy)]
pub struct AcpRelationshipTx<'a> {
    pub kind: AcpRelationshipTxKind,
    pub policy_id: &'a str,
    pub resource: &'a str,
    pub object_id: &'a str,
    pub relation: &'a str,
    pub actor: &'a str,
}

/// A BLS account that submits native requests to one Vera node.
pub struct VeraAccount {
    client: VeraClient,
    signer: BlsSigner,
}

impl VeraAccount {
    /// Sign as `secret` for `chain_id`, continuing from the account's
    /// committed native sequence.
    pub async fn connect(rpc_url: &str, chain_id: u64, secret: &[u8; 32]) -> eyre::Result<Self> {
        let client = VeraClient::new(rpc_url);
        let signer = BlsSigner::from_secret_bytes(secret, chain_id, 0)?;
        signer.set_next_sequence(client.get_native_nonce(signer.did()).await?);
        Ok(Self { client, signer })
    }

    pub fn did(&self) -> &str {
        self.signer.did()
    }

    pub fn client(&self) -> &VeraClient {
        &self.client
    }

    /// Create a policy under a random nonce, so creating one definition
    /// again yields another policy rather than `PolicyAlreadyExists`.
    pub async fn create_policy(&self, yaml: &str) -> eyre::Result<String> {
        self.create_policy_with_nonce(yaml, random_policy_nonce())
            .await
    }

    /// Create a policy under `nonce`; the policy id binds the definition,
    /// the signer and the nonce.
    pub async fn create_policy_with_nonce(
        &self,
        yaml: &str,
        nonce: PolicyNonce,
    ) -> eyre::Result<String> {
        let policy_id =
            predict_policy_id(yaml, &PolicyMarshalingType::ShortYaml, &nonce, self.did())?;
        self.client
            .native_create_policy(&self.signer, yaml.as_bytes(), YAML, nonce)
            .await?;
        let listed = self.client.get_policy_ids().await?;
        eyre::ensure!(
            listed.contains(&policy_id),
            "created policy {policy_id} is not among {listed:?}"
        );
        Ok(policy_id)
    }

    pub async fn list_policies(&self) -> eyre::Result<Vec<String>> {
        Ok(self.client.get_policy_ids().await?)
    }

    pub async fn register_object(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> eyre::Result<TransactionReceipt> {
        Ok(self
            .client
            .native_register_object(
                &self.signer,
                parse_policy_id(policy_id)?,
                object_id,
                resource,
            )
            .await?)
    }

    pub async fn set_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<TransactionReceipt> {
        Ok(self
            .client
            .native_set_relationship(
                &self.signer,
                parse_policy_id(policy_id)?,
                resource,
                object_id,
                relation,
                actor,
            )
            .await?)
    }

    pub async fn delete_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> eyre::Result<TransactionReceipt> {
        Ok(self
            .client
            .native_delete_relationship(
                &self.signer,
                parse_policy_id(policy_id)?,
                resource,
                object_id,
                relation,
                actor,
            )
            .await?)
    }

    pub async fn register_namespace(&self, namespace: &str) -> eyre::Result<TransactionReceipt> {
        Ok(self
            .client
            .native_register_namespace(&self.signer, namespace)
            .await?)
    }

    pub async fn add_collaborator(
        &self,
        namespace: &str,
        did: &str,
    ) -> eyre::Result<TransactionReceipt> {
        Ok(self
            .client
            .native_add_collaborator(&self.signer, namespace, did)
            .await?)
    }

    /// The namespace's posts as the module's JSON records.
    pub async fn list_posts(&self, namespace: &str) -> eyre::Result<serde_json::Value> {
        let posts = self.client.get_namespace_posts(namespace).await?;
        Ok(serde_json::from_slice(&posts)?)
    }

    /// Submit `txs` as one ordered command list that `owner` signs once,
    /// applied all or none under the owner's authority, without waiting for
    /// its receipt. `genesis_id` names the deployment the operation binds to.
    pub async fn submit_relationship_batch(
        &self,
        owner: &Secp256k1SigningKey,
        genesis_id: B256,
        txs: &[AcpRelationshipTx<'_>],
    ) -> eyre::Result<B256> {
        let commands = txs
            .iter()
            .map(|tx| {
                let relationship = serde_json::json!({
                    "resource": tx.resource,
                    "object_id": tx.object_id,
                    "relation": tx.relation,
                    "subject": { "Entity": tx.actor },
                });
                let command = match tx.kind {
                    AcpRelationshipTxKind::Set => {
                        serde_json::json!({ "SetRelationship": relationship })
                    }
                    AcpRelationshipTxKind::Delete => {
                        serde_json::json!({ "DeleteRelationship": relationship })
                    }
                };
                Ok((
                    tx.policy_id.to_string(),
                    serde_json::from_value::<PolicyCmd>(command)?,
                ))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let operation = PolicyOperation::list(commands)?;
        let issued_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let identity = OperationId::new(issued_at + OPERATION_LIFETIME_SECS, rand::random());
        let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            owner.verifying_key().to_sec1_bytes().as_ref(),
        )?;
        let claims = operation.claims(
            &issuer,
            self.did(),
            self.signer.chain_id(),
            genesis_id.0,
            identity,
            issued_at,
        )?;
        let token = create_operation_token(owner, &claims)?;
        self.send(ACP_ADDRESS, operation.calldata(&token)?.into())
            .await
    }

    /// Sign `calldata` to the module at `target`, submit it and wait for a
    /// successful receipt.
    pub async fn submit(
        &self,
        target: Address,
        calldata: Bytes,
    ) -> eyre::Result<TransactionReceipt> {
        let submission = self.send(target, calldata).await?;
        self.wait_for_success(submission).await
    }

    /// Sign `calldata` at the account's next sequence and submit it; the
    /// sequence advances once the node admits the request.
    async fn send(&self, target: Address, calldata: Bytes) -> eyre::Result<B256> {
        let sequence = self.signer.nonce();
        let wire = self
            .signer
            .sign_native_tx_with_sequence(target, calldata, sequence)?;
        let submission = self.client.send_native_tx(&wire).await?;
        self.signer.set_next_sequence(sequence + 1);
        Ok(submission)
    }

    /// Wait for the receipt of `submission` and require that it succeeded.
    pub async fn wait_for_success(&self, submission: B256) -> eyre::Result<TransactionReceipt> {
        let receipt = self
            .client
            .wait_for_receipt(submission, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
            .await?;
        eyre::ensure!(
            receipt.success,
            "request {submission} was refused: {:?}",
            receipt.refusal
        );
        Ok(receipt)
    }
}
