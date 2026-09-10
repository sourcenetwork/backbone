//! DefraDB identity helpers: did:key derivation, ES256K JWT, and authenticated HTTP.
//!
//! DefraDB uses secp256k1-based `did:key` identities for ACP. Each request
//! carries a Bearer JWT signed with the identity's private key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use eyre::{eyre, Result};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
/// Derive a `did:key:z...` from a secp256k1 private key hex string.
///
/// Uses the multicodec prefix `0xe7 0x01` for secp256k1-pub and
/// base58btc encoding with the `z` multibase prefix.
///
/// DefraDB uses the **uncompressed** (65-byte) public key for did:key
/// derivation (matching Go's SerializeUncompressed).
///
/// Returns `(did_key_string, compressed_public_key_bytes)`.
pub fn did_key_from_secp256k1(private_key_hex: &str) -> Result<(String, Vec<u8>)> {
    let key_bytes = hex::decode(private_key_hex).map_err(|e| eyre!("invalid hex key: {}", e))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| eyre!("invalid secp256k1 key: {}", e))?;
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_sec1_bytes();

    let uncompressed = verifying_key.to_encoded_point(false);

    // multicodec: varint(0xe7) = [0xe7, 0x01] for secp256k1-pub
    let mut multicodec = vec![0xe7, 0x01];
    multicodec.extend_from_slice(uncompressed.as_bytes());

    let encoded = bs58::encode(&multicodec).into_string();
    let did = format!("did:key:z{}", encoded);

    Ok((did, compressed.to_vec()))
}

/// Generate an ES256K JWT compatible with DefraDB's identity extractor.
pub fn generate_defra_jwt(private_key_hex: &str, audience: &str) -> Result<String> {
    generate_defra_jwt_with_account(private_key_hex, audience, None)
}

/// Generate an ES256K JWT that DefraDB accepts and that Vera also accepts as
/// the bearer token behind `MsgBearerPolicyCmd`.
///
/// DefraDB stores the request JWT keyed by DID and passes it through to Vera
/// when it registers a document object (`resolve_cosmos_bearer_token`). Vera
/// then requires an `authorized_account` claim equal to the transaction
/// creator, which is the DefraDB node's own `vera1...` address. Without the
/// claim the registration transaction is rejected and the create fails.
pub fn generate_defra_jwt_with_account(
    private_key_hex: &str,
    audience: &str,
    authorized_account: Option<&str>,
) -> Result<String> {
    let key_bytes = hex::decode(private_key_hex).map_err(|e| eyre!("invalid hex key: {}", e))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| eyre!("invalid secp256k1 key: {}", e))?;

    let (did_key, compressed_pub) = did_key_from_secp256k1(private_key_hex)?;
    let sub = hex::encode(&compressed_pub);

    let aud = audience
        .strip_prefix("http://")
        .or_else(|| audience.strip_prefix("https://"))
        .unwrap_or(audience);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| eyre!("system time error: {}", e))?
        .as_secs();

    let header = serde_json::json!({"alg": "ES256K", "typ": "JWT"});
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

    let mut claims = serde_json::json!({
        "sub": sub,
        "iss": did_key,
        "exp": now + 900,
        "nbf": now,
        "iat": now,
        "aud": [aud],
        "key_type": "secp256k1",
    });
    if let Some(account) = authorized_account {
        claims["authorized_account"] = serde_json::Value::String(account.to_string());
    }
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());

    let message = format!("{}.{}", header_b64, claims_b64);

    let signature: Signature = signing_key
        .try_sign(message.as_bytes())
        .map_err(|e| eyre!("signing failed: {}", e))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}", message, sig_b64))
}

/// HTTP client that adds Bearer JWT for identity-authenticated DefraDB requests.
pub struct DefraHttpClient {
    http: reqwest::Client,
    base_url: String,
    /// Vera address stamped into every identity JWT as `authorized_account`,
    /// so DefraDB's bearer passthrough satisfies Vera's creator check.
    authorized_account: Option<String>,
}

/// Direction of a document ACP relationship change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationshipChange {
    Add,
    Delete,
}

/// A GraphQL response before any success or shape interpretation.
///
/// Used where a test must compare two responses byte for byte, such as the
/// absence-versus-denial pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawGraphqlResponse {
    pub status: u16,
    pub body: String,
}

impl DefraHttpClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.to_string(),
            authorized_account: None,
        }
    }

    /// Stamp `account` into every identity JWT this client issues.
    #[must_use]
    pub fn with_authorized_account(mut self, account: &str) -> Self {
        self.authorized_account = Some(account.to_string());
        self
    }

    fn identity_header(&self, identity_hex: Option<&str>) -> Result<Option<String>> {
        let Some(key_hex) = identity_hex else {
            return Ok(None);
        };
        let jwt = generate_defra_jwt_with_account(
            key_hex,
            &self.base_url,
            self.authorized_account.as_deref(),
        )?;
        Ok(Some(format!("Bearer {}", jwt)))
    }

    /// Execute a GraphQL query/mutation, optionally with identity authentication.
    pub async fn graphql(
        &self,
        query: &str,
        identity_hex: Option<&str>,
    ) -> Result<serde_json::Value> {
        let raw = self.graphql_raw(query, identity_hex).await?;
        if !(200..300).contains(&raw.status) {
            return Err(eyre!("graphql HTTP {}: {}", raw.status, raw.body));
        }
        serde_json::from_str(&raw.body)
            .map_err(|e| eyre!("failed to parse graphql response: {}", e))
    }

    /// Execute a GraphQL request and return the status and body verbatim.
    pub async fn graphql_raw(
        &self,
        query: &str,
        identity_hex: Option<&str>,
    ) -> Result<RawGraphqlResponse> {
        let url = format!("{}/api/v0/graphql", self.base_url);
        let body = serde_json::json!({"query": query});

        let mut request = self.http.post(&url).json(&body);
        if let Some(header) = self.identity_header(identity_hex)? {
            request = request.header("Authorization", header);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| eyre!("graphql request failed: {}", e))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .await
            .map_err(|e| eyre!("failed to read graphql response: {}", e))?;
        Ok(RawGraphqlResponse { status, body })
    }

    /// Add or remove a document ACP relationship, authenticated as
    /// `identity_hex`.
    ///
    /// The node forwards this to Vera as a bearer policy command on the
    /// caller's behalf, so the caller must be the document's manager (its
    /// owner) and the JWT must carry the `authorized_account` claim naming the
    /// node's own chain address, which is what Vera checks the transaction
    /// creator against.
    pub async fn acp_relationship(
        &self,
        method: RelationshipChange,
        collection: &str,
        doc_id: &str,
        relation: &str,
        actor_did: &str,
        identity_hex: &str,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/api/v0/acp/document/relationship", self.base_url);
        let body = serde_json::json!({
            "collection": collection,
            "docID": doc_id,
            "relation": relation,
            "actor": actor_did,
        });
        let request = match method {
            RelationshipChange::Add => self.http.post(&url),
            RelationshipChange::Delete => self.http.delete(&url),
        };
        let mut request = request.json(&body);
        if let Some(header) = self.identity_header(Some(identity_hex))? {
            request = request.header("Authorization", header);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| eyre!("acp relationship request failed: {}", e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("acp relationship HTTP {}: {}", status, body));
        }
        resp.json()
            .await
            .map_err(|e| eyre!("failed to parse acp relationship response: {}", e))
    }

    /// Add a schema (SDL string) to DefraDB.
    pub async fn schema_add(&self, sdl: &str) -> Result<()> {
        let url = format!("{}/api/v0/schema", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(sdl.to_string())
            .send()
            .await
            .map_err(|e| eyre!("schema add request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("schema add HTTP {}: {}", status, body));
        }

        Ok(())
    }

    /// Fetch ACP light client status from DefraDB.
    ///
    /// GET /api/v0/acp/status — returns height, module_state_root,
    /// cache_entries, last_invalidation_height, connected.
    pub async fn acp_status(&self) -> Result<AcpLightClientStatus> {
        let url = format!("{}/api/v0/acp/status", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| eyre!("acp status request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("acp status HTTP {}: {}", status, body));
        }

        resp.json()
            .await
            .map_err(|e| eyre!("failed to parse acp status response: {}", e))
    }

    /// Trigger targeted P2P document sync for specific document IDs.
    pub async fn p2p_document_sync(&self, collection_name: &str, doc_ids: &[String]) -> Result<()> {
        let url = format!("{}/api/v0/p2p/documents/sync", self.base_url);
        let body = serde_json::json!({
            "collectionName": collection_name,
            "docIDs": doc_ids,
        });

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| eyre!("p2p document sync request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(eyre!("p2p document sync HTTP {}: {}", status, body));
        }

        Ok(())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// ACP light client status from DefraDB's `/api/v0/acp/status` endpoint.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AcpLightClientStatus {
    pub height: u64,
    pub module_state_root: String,
    pub cache_entries: usize,
    pub last_invalidation_height: u64,
    pub connected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (did, pub_bytes) = did_key_from_secp256k1(key_hex).unwrap();
        assert!(did.starts_with("did:key:z"), "got: {}", did);
        assert_eq!(
            pub_bytes.len(),
            33,
            "compressed secp256k1 pubkey is 33 bytes"
        );
    }

    #[test]
    fn jwt_has_three_parts() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let jwt = generate_defra_jwt(key_hex, "http://127.0.0.1:9181").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts: {}", jwt);

        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "ES256K");

        let claims_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["key_type"], "secp256k1");
        assert_eq!(claims["aud"][0], "127.0.0.1:9181");
        assert!(claims["iss"].as_str().unwrap().starts_with("did:key:z"));
    }
}
