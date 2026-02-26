//! Standalone verification functions — no network access required.
//!
//! Reimplements hub-domain's verification logic using the same underlying
//! crates (`jmt`, `commonware-cryptography`, `commonware-consensus`) but
//! with no compile-time coupling to hub.rs.

use alloy_primitives::{keccak256, B256};
use borsh::BorshDeserialize;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{ed25519, Hasher as _, Verifier as _};
use jmt::{proof::SparseMerkleProof, KeyHash, RootHash};
use sha2::Sha256;

use crate::types::{LightBlock, ModuleStateProof};

const MODULE_ROOT_NAMESPACE: &[u8] = b"_HUB_MODULE_ROOT";
const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Consensus digest type — same alias hub.rs uses.
type ConsensusDigest = commonware_cryptography::sha256::Digest;

// ── Proof verification errors ──────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("failed to decode jmt_proof from hex: {0}")]
    JmtProofHex(String),
    #[error("failed to deserialize jmt_proof: {0}")]
    JmtProofDeserialize(String),
    #[error("failed to decode module_root from hex: {0}")]
    ModuleRootHex(String),
    #[error("failed to decode all_module_roots[{0}] from hex: {1}")]
    AllModuleRootsHex(usize, String),
    #[error("failed to decode key from hex: {0}")]
    KeyHex(String),
    #[error("failed to decode value from hex: {0}")]
    ValueHex(String),
    #[error("module_root does not match all_module_roots[{0}]")]
    ModuleRootMismatch(usize),
    #[error("recomputed module_state_root does not match expected")]
    StateRootMismatch,
    #[error("JMT proof verification failed: {0}")]
    JmtVerification(String),
}

// ── Light block verification errors ────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LightBlockError {
    #[error("failed to decode hex field '{0}': {1}")]
    HexDecode(&'static str, String),
    #[error("SHA256(block_hash) does not match proposal_payload")]
    PayloadMismatch,
    #[error("signer index {0} out of range for validator set of size {1}")]
    SignerIndexOutOfRange(u32, usize),
    #[error("failed to decode validator public key at index {0}")]
    InvalidPublicKey(usize),
    #[error("failed to decode signature at index {0}")]
    InvalidSignature(usize),
    #[error("signer_indices and signatures have different lengths ({0} vs {1})")]
    LengthMismatch(usize, usize),
    #[error("insufficient valid signatures: got {got}, need {need}")]
    InsufficientSignatures { got: usize, need: usize },
}

// ── Hex helpers ────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(s)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}

fn lb_decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, LightBlockError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| LightBlockError::HexDecode(field, e.to_string()))
}

fn lb_decode_hex_32(field: &'static str, s: &str) -> Result<[u8; 32], LightBlockError> {
    let bytes = lb_decode_hex(field, s)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        LightBlockError::HexDecode(field, format!("expected 32 bytes, got {}", bytes.len()))
    })
}

// ── State root recomputation ───────────────────────────────────────────

/// Recompute the combined module state root from 4 per-module JMT roots.
///
/// `keccak256("_HUB_MODULE_ROOT" || root[0] || root[1] || root[2] || root[3])`
fn recompute_state_root(roots: &[[u8; 32]; 4]) -> B256 {
    let mut buf = Vec::with_capacity(MODULE_ROOT_NAMESPACE.len() + 128);
    buf.extend_from_slice(MODULE_ROOT_NAMESPACE);
    for root in roots {
        buf.extend_from_slice(root);
    }
    keccak256(buf)
}

// ── Public verification functions ──────────────────────────────────────

/// Verify a module state proof against a `module_state_root`.
///
/// 1. Check `all_module_roots[module.index()] == module_root`
/// 2. Recompute combined root and check against `module_state_root`
/// 3. Borsh-deserialize and verify the JMT sparse Merkle proof
pub fn verify_module_state_proof(
    module_state_root: B256,
    proof: &ModuleStateProof,
) -> Result<(), ProofError> {
    let module_root = decode_hex_32(&proof.module_root).map_err(ProofError::ModuleRootHex)?;

    let mut all_roots = [[0u8; 32]; 4];
    for (i, hex_root) in proof.all_module_roots.iter().enumerate() {
        all_roots[i] = decode_hex_32(hex_root).map_err(|e| ProofError::AllModuleRootsHex(i, e))?;
    }

    let idx = proof.module.index();
    if all_roots[idx] != module_root {
        return Err(ProofError::ModuleRootMismatch(idx));
    }

    let recomputed = recompute_state_root(&all_roots);
    if recomputed != module_state_root {
        return Err(ProofError::StateRootMismatch);
    }

    let jmt_proof_bytes = decode_hex(&proof.jmt_proof).map_err(ProofError::JmtProofHex)?;
    let jmt_proof: SparseMerkleProof<Sha256> =
        BorshDeserialize::try_from_slice(&jmt_proof_bytes)
            .map_err(|e| ProofError::JmtProofDeserialize(e.to_string()))?;

    let key_bytes = decode_hex(&proof.key).map_err(ProofError::KeyHex)?;
    let key_hash = KeyHash::with::<Sha256>(&key_bytes);

    let value_bytes = match &proof.value {
        Some(hex_val) => Some(decode_hex(hex_val).map_err(ProofError::ValueHex)?),
        None => None,
    };

    jmt_proof
        .verify(RootHash(module_root), key_hash, value_bytes)
        .map_err(|e| ProofError::JmtVerification(e.to_string()))
}

/// Verify a light block's finalization certificate against its embedded
/// validator set.
///
/// Returns `(state_root, module_state_root)` on success.
///
/// 1. `SHA256(block_hash) == proposal_payload`
/// 2. Reconstruct Simplex `Proposal` and encode it
/// 3. Verify each ed25519 signature against the finalize namespace
/// 4. Check quorum: `valid_sigs >= (2 * validators.len() / 3) + 1`
pub fn verify_light_block(block: &LightBlock) -> Result<(B256, B256), LightBlockError> {
    let block_hash_bytes = lb_decode_hex_32("block_hash", &block.block_hash)?;
    let proposal_payload_bytes = lb_decode_hex_32("proposal_payload", &block.proposal_payload)?;

    let mut hasher = commonware_cryptography::Sha256::default();
    hasher.update(&block_hash_bytes);
    let computed_payload = hasher.finalize();
    if computed_payload.0 != proposal_payload_bytes {
        return Err(LightBlockError::PayloadMismatch);
    }

    if block.signer_indices.len() != block.signatures.len() {
        return Err(LightBlockError::LengthMismatch(
            block.signer_indices.len(),
            block.signatures.len(),
        ));
    }

    let mut finalize_ns = Vec::with_capacity(SIMPLEX_NAMESPACE.len() + FINALIZE_SUFFIX.len());
    finalize_ns.extend_from_slice(SIMPLEX_NAMESPACE);
    finalize_ns.extend_from_slice(FINALIZE_SUFFIX);

    let proposal = Proposal::new(
        Round::new(Epoch::new(block.epoch), View::new(block.view)),
        View::new(block.parent_view),
        ConsensusDigest::from(proposal_payload_bytes),
    );
    let proposal_bytes = proposal.encode();

    let mut validator_keys = Vec::with_capacity(block.validators.len());
    for (i, hex_pk) in block.validators.iter().enumerate() {
        let pk_bytes = lb_decode_hex_32("validators", hex_pk)?;
        let pk = ed25519::PublicKey::decode(pk_bytes.as_ref())
            .map_err(|_| LightBlockError::InvalidPublicKey(i))?;
        validator_keys.push(pk);
    }

    let mut valid_sigs = 0usize;
    for (i, signer_index) in block.signer_indices.iter().enumerate() {
        let idx = *signer_index as usize;
        if idx >= validator_keys.len() {
            return Err(LightBlockError::SignerIndexOutOfRange(
                *signer_index,
                validator_keys.len(),
            ));
        }

        let sig_bytes = lb_decode_hex("signatures", &block.signatures[i])?;
        if sig_bytes.len() != 64 {
            return Err(LightBlockError::InvalidSignature(i));
        }
        let sig = ed25519::Signature::decode(sig_bytes.as_ref())
            .map_err(|_| LightBlockError::InvalidSignature(i))?;

        if validator_keys[idx].verify(&finalize_ns, &proposal_bytes, &sig) {
            valid_sigs += 1;
        }
    }

    let required = (2 * block.validators.len() / 3) + 1;
    if valid_sigs < required {
        return Err(LightBlockError::InsufficientSignatures {
            got: valid_sigs,
            need: required,
        });
    }

    let state_root = B256::from(lb_decode_hex_32("state_root", &block.state_root)?);
    let module_state_root = B256::from(lb_decode_hex_32(
        "module_state_root",
        &block.module_state_root,
    )?);
    Ok((state_root, module_state_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer as _;
    use jmt::{mock::MockTreeStore, Sha256Jmt};

    fn make_jmt_proof(
        key: &[u8],
        value: &[u8],
    ) -> (SparseMerkleProof<Sha256>, [u8; 32], Option<Vec<u8>>) {
        let store = MockTreeStore::default();
        let tree = Sha256Jmt::new(&store);
        let key_hash = KeyHash::with::<Sha256>(key);
        let (root, batch) = tree
            .put_value_set([(key_hash, Some(value.to_vec()))], 1)
            .unwrap();
        store.write_tree_update_batch(batch).unwrap();
        let (val, proof) = tree.get_with_proof(key_hash, 1).unwrap();
        (proof, root.0, val)
    }

    fn encode_hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn existence_proof_roundtrip() {
        let key = b"relationship/policy-1/resource:doc1:reader:did:key:z6Mk";
        let value = b"exists";
        let (jmt_proof, module_root, val) = make_jmt_proof(key, value);
        assert_eq!(val, Some(value.to_vec()));

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let jmt_bytes = borsh::to_vec(&jmt_proof).unwrap();
        let proof = ModuleStateProof {
            module: crate::types::ModuleId::Acp,
            height: 42,
            key: encode_hex(key),
            value: Some(encode_hex(value)),
            jmt_proof: encode_hex(&jmt_bytes),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&all_roots[0]),
                encode_hex(&all_roots[1]),
                encode_hex(&all_roots[2]),
                encode_hex(&all_roots[3]),
            ],
        };

        assert!(verify_module_state_proof(module_state_root, &proof).is_ok());
    }

    #[test]
    fn nonexistence_proof_roundtrip() {
        let store = MockTreeStore::default();
        let tree = Sha256Jmt::new(&store);
        let existing_key = KeyHash::with::<Sha256>(b"existing-key");
        let (root, batch) = tree
            .put_value_set([(existing_key, Some(b"val".to_vec()))], 1)
            .unwrap();
        store.write_tree_update_batch(batch).unwrap();

        let absent_hash = KeyHash::with::<Sha256>(b"absent-key");
        let (val, jmt_proof) = tree.get_with_proof(absent_hash, 1).unwrap();
        assert!(val.is_none());

        let module_root = root.0;
        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let jmt_bytes = borsh::to_vec(&jmt_proof).unwrap();
        let proof = ModuleStateProof {
            module: crate::types::ModuleId::Acp,
            height: 42,
            key: encode_hex(b"absent-key"),
            value: None,
            jmt_proof: encode_hex(&jmt_bytes),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&all_roots[0]),
                encode_hex(&all_roots[1]),
                encode_hex(&all_roots[2]),
                encode_hex(&all_roots[3]),
            ],
        };

        assert!(verify_module_state_proof(module_state_root, &proof).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_value() {
        let key = b"policy/objs/policy-1";
        let value = b"correct-value";
        let (jmt_proof, module_root, _) = make_jmt_proof(key, value);

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let jmt_bytes = borsh::to_vec(&jmt_proof).unwrap();
        let proof = ModuleStateProof {
            module: crate::types::ModuleId::Acp,
            height: 42,
            key: encode_hex(key),
            value: Some(encode_hex(b"tampered-value")),
            jmt_proof: encode_hex(&jmt_bytes),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&all_roots[0]),
                encode_hex(&all_roots[1]),
                encode_hex(&all_roots[2]),
                encode_hex(&all_roots[3]),
            ],
        };

        assert!(matches!(
            verify_module_state_proof(module_state_root, &proof),
            Err(ProofError::JmtVerification(_))
        ));
    }

    #[test]
    fn verify_rejects_state_root_mismatch() {
        let module_root = [0xAAu8; 32];
        let proof = ModuleStateProof {
            module: crate::types::ModuleId::Acp,
            height: 1,
            key: encode_hex(b"test"),
            value: Some(encode_hex(b"val")),
            jmt_proof: encode_hex(&[0]),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&module_root),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
            ],
        };
        let wrong_state_root = B256::repeat_byte(0xFF);
        assert!(matches!(
            verify_module_state_proof(wrong_state_root, &proof),
            Err(ProofError::StateRootMismatch)
        ));
    }

    fn build_valid_light_block(n: usize, signer_count: usize) -> LightBlock {
        let private_keys: Vec<_> = (0..n)
            .map(|i| ed25519::PrivateKey::from_seed(i as u64))
            .collect();
        let mut pubkeys: Vec<_> = private_keys.iter().map(|k| k.public_key()).collect();
        pubkeys.sort();

        let block_hash = B256::repeat_byte(0xAB);
        let mut hasher = commonware_cryptography::Sha256::default();
        hasher.update(block_hash.as_slice());
        let payload = hasher.finalize();

        let epoch = 0u64;
        let view = 1u64;
        let parent_view = 0u64;

        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent_view),
            ConsensusDigest::from(payload.0),
        );
        let proposal_bytes = proposal.encode();

        let mut finalize_ns = Vec::with_capacity(SIMPLEX_NAMESPACE.len() + FINALIZE_SUFFIX.len());
        finalize_ns.extend_from_slice(SIMPLEX_NAMESPACE);
        finalize_ns.extend_from_slice(FINALIZE_SUFFIX);

        let ordered_privkeys: Vec<_> = pubkeys
            .iter()
            .map(|pk| {
                private_keys
                    .iter()
                    .find(|sk| sk.public_key() == *pk)
                    .unwrap()
            })
            .collect();

        let mut signer_indices = Vec::new();
        let mut signatures = Vec::new();
        for i in 0..signer_count {
            let sig = ordered_privkeys[i].sign(&finalize_ns, &proposal_bytes);
            let encoded = sig.encode();
            signer_indices.push(i as u32);
            signatures.push(encode_hex(&encoded));
        }

        let validators: Vec<String> = pubkeys
            .iter()
            .map(|pk| {
                let bytes: &[u8] = pk.as_ref();
                encode_hex(bytes)
            })
            .collect();

        LightBlock {
            block_hash: encode_hex(block_hash.as_slice()),
            parent_hash: encode_hex(B256::repeat_byte(0x01).as_slice()),
            height: 42,
            timestamp: 1_700_000_000,
            state_root: encode_hex(B256::repeat_byte(0xCC).as_slice()),
            module_state_root: encode_hex(B256::repeat_byte(0xDD).as_slice()),
            epoch,
            view,
            parent_view,
            proposal_payload: encode_hex(&payload.0),
            signer_indices,
            signatures,
            validators,
        }
    }

    #[test]
    fn valid_light_block_roundtrip() {
        let lb = build_valid_light_block(4, 3);
        let (state_root, module_state_root) = verify_light_block(&lb).unwrap();
        assert_eq!(state_root, B256::repeat_byte(0xCC));
        assert_eq!(module_state_root, B256::repeat_byte(0xDD));
    }

    #[test]
    fn rejects_tampered_block_hash() {
        let mut lb = build_valid_light_block(4, 3);
        lb.block_hash = encode_hex(&[0xFF; 32]);
        assert!(matches!(
            verify_light_block(&lb),
            Err(LightBlockError::PayloadMismatch)
        ));
    }

    #[test]
    fn rejects_insufficient_quorum() {
        let lb = build_valid_light_block(4, 2);
        assert!(matches!(
            verify_light_block(&lb),
            Err(LightBlockError::InsufficientSignatures { got: 2, need: 3 })
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let lb = build_valid_light_block(4, 3);
        let json = serde_json::to_string(&lb).unwrap();
        let deserialized: LightBlock = serde_json::from_str(&json).unwrap();
        assert!(verify_light_block(&deserialized).is_ok());
    }
}
