use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfoResult {
    pub public_address: String,
    pub peer_id: String,
    pub p2p_address: String,
}

#[derive(Debug, Deserialize)]
pub struct DkgResult {
    pub session_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct StoreSecretResult {
    pub status: String,
    pub message: String,
    pub created_at: i64,
    pub object_id: String,
    pub ring_id: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct DerivePublicKeyResult {
    pub derived_public_key: String,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct SignAcpFields {
    pub policy_id: String,
    pub resource: String,
    pub object_id: String,
    pub permission: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedSecret {
    pub encrypted_document: Vec<u8>,
    pub enc_cmt: Vec<u8>,
    pub shared_point: Vec<u8>,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
    pub metadata: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_pk: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct ReaderKeyResult {
    pub secret_key: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PreResult {
    pub decrypted_hex: String,
    pub decrypted_utf8: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RingPayload {
    pub ring_pk: String,
    pub peer_ids: Vec<String>,
    pub threshold: u32,
    pub public_polynomial: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DocumentPayload {
    pub ring_id: String,
    pub document: String,
    pub proof: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulletinPost {
    pub id: String,
    pub namespace: String,
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
}

impl TryFrom<BulletinPost> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(post: BulletinPost) -> Result<Self, Self::Error> {
        serde_json::to_vec(&post)
    }
}

impl TryFrom<DocumentPayload> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(payload: DocumentPayload) -> Result<Self, Self::Error> {
        serde_json::to_vec(&payload)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BulletinPostEvent {
    pub post_id: String,
    pub namespace: String,
}
