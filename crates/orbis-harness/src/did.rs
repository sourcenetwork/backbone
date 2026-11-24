/// Compute the Ed25519 did:key for a given hex private key seed.
///
/// This replicates the behavior of orbis-rs `signer_did_for_pk` which uses
/// the `did-key` crate with Ed25519. The multicodec prefix for Ed25519-pub
/// is `0xed 0x01`, and the public key is the 32-byte compressed form.
///
/// We use the `ed25519-dalek` approach via raw bytes: generate the public key
/// from the seed, then encode as did:key with multicodec + base58btc.
pub fn signer_did_for_pk(private_key_hex: &str) -> String {
    let seed_bytes = hex::decode(private_key_hex).expect("signer_did_pk must be valid hex");

    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &seed_bytes[..32]
            .try_into()
            .expect("seed must be at least 32 bytes"),
    );
    let public_key = signing_key.verifying_key();
    let pk_bytes = public_key.to_bytes();

    // multicodec: varint(0xed) = [0xed, 0x01] for ed25519-pub
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&pk_bytes);

    let encoded = bs58::encode(&multicodec).into_string();
    format!("did:key:z{}", encoded)
}

/// The Ed25519 key of `private_key_hex`'s seed in the form DefraDB's
/// identity flags take: the seed followed by the public key, in hex.
pub fn ed25519_identity_hex(private_key_hex: &str) -> String {
    let seed_bytes = hex::decode(private_key_hex).expect("seed must be valid hex");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &seed_bytes[..32]
            .try_into()
            .expect("seed must be at least 32 bytes"),
    );
    let mut keypair = signing_key.to_bytes().to_vec();
    keypair.extend_from_slice(&signing_key.verifying_key().to_bytes());
    hex::encode(keypair)
}

/// The public key a ring signs with under `derivation` for documents bound
/// to `policy_id`, `resource` and `permission`, in hex.
pub fn derived_public_key(
    ring_pk_hex: &str,
    derivation: &str,
    policy_id: &str,
    resource: &str,
    permission: &str,
) -> eyre::Result<String> {
    use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, ThresholdSigner};
    use crypto::{GroupAffine, SignImpl};

    let ring_pk = GroupAffine::from_bytes(&hex::decode(ring_pk_hex)?)
        .map_err(|e| eyre::eyre!("ring public key: {e}"))?;
    let metadata = SignImpl::encode_metadata(policy_id, resource, permission);
    let derived = SignImpl::derive_public_key(&ring_pk, derivation.as_bytes(), Some(&metadata))
        .map_err(|e| eyre::eyre!("derive public key: {e}"))?;
    Ok(hex::encode(
        derived
            .to_bytes()
            .map_err(|e| eyre::eyre!("serialize derived key: {e}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_did_starts_with_did_key() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let did = signer_did_for_pk(key_hex);
        assert!(did.starts_with("did:key:z"), "got: {}", did);
    }

    #[test]
    fn signer_did_deterministic() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let did1 = signer_did_for_pk(key_hex);
        let did2 = signer_did_for_pk(key_hex);
        assert_eq!(did1, did2);
    }
}
