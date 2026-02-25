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
