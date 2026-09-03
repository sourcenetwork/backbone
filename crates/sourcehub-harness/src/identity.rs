use cosmrs::crypto::secp256k1::SigningKey;

/// Bech32 human-readable part for Vera account addresses (`types/constants.go`
/// in sourcenetwork/vera, changed from `source` in PR #139).
pub const VERA_ADDRESS_PREFIX: &str = "vera";

/// Derive a `vera1...` bech32 address from a secp256k1 private key hex string.
///
/// Uses the standard Cosmos SDK derivation:
/// secp256k1 pubkey -> SHA256 -> RIPEMD160 -> bech32("vera", ...)
pub fn source_hub_address(private_key_hex: &str) -> eyre::Result<String> {
    let key_bytes =
        hex::decode(private_key_hex).map_err(|e| eyre::eyre!("invalid hex key: {}", e))?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| eyre::eyre!("invalid secp256k1 private key: {}", e))?;
    let public_key = signing_key.public_key();
    let account_id = public_key
        .account_id(VERA_ADDRESS_PREFIX)
        .map_err(|e| eyre::eyre!("failed to derive vera address: {}", e))?;
    Ok(account_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_vera_address() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let addr = source_hub_address(key_hex).unwrap();
        assert!(
            addr.starts_with("vera1"),
            "expected vera1... prefix, got: {}",
            addr
        );
    }
}
