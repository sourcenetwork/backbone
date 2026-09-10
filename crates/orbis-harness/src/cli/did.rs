/// Compute the Ed25519 did:key for a given hex private key seed.
///
/// This replicates the behavior of orbis-rs `signer_did_for_pk` which uses
/// the `did-key` crate with Ed25519. The multicodec prefix for Ed25519-pub
/// is `0xed 0x01`, and the public key is the 32-byte compressed form.
///
/// We use the `ed25519-dalek` approach via raw bytes: generate the public key
/// from the seed, then encode as did:key with multicodec + base58btc.
/// Build the 64-byte ed25519 private key DefraDB expects for `--identity` or
/// `--signer-orbis-identity`, from a 32-byte seed.
///
/// DefraDB stores an ed25519 private key as seed followed by public key (Go
/// parity) and picks the key type by length, so a 128-character hex string is
/// an ed25519 identity and a 64-character one is secp256k1. The resulting DID
/// is the same one [`signer_did_for_pk`] derives from the seed.
pub fn ed25519_identity_hex(seed_hex: &str) -> String {
    let seed_bytes = hex::decode(seed_hex).expect("seed must be valid hex");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        &seed_bytes[..32]
            .try_into()
            .expect("seed must be at least 32 bytes"),
    );
    let mut key = signing_key.to_bytes().to_vec();
    key.extend_from_slice(&signing_key.verifying_key().to_bytes());
    hex::encode(key)
}

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
    fn ed25519_identity_hex_is_seed_then_public_key() {
        let seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let identity = ed25519_identity_hex(seed);
        assert_eq!(identity.len(), 128, "64 bytes as hex");
        assert!(
            identity.starts_with(seed),
            "the seed is the first half: {}",
            identity
        );
    }

    #[test]
    fn signer_did_deterministic() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let did1 = signer_did_for_pk(key_hex);
        let did2 = signer_did_for_pk(key_hex);
        assert_eq!(did1, did2);
    }
}
