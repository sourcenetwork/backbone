//! Key management for e2e test clusters.
//!
//! Generates ed25519 identity keys and deterministic ed25519 multisig signing
//! schemes using commonware-cryptography directly (no hub-runner dependency).

use std::{collections::BTreeMap, path::Path};

use commonware_codec::Encode;
use commonware_consensus::simplex::scheme::ed25519::Scheme;
use commonware_cryptography::{ed25519, Signer as _};
use commonware_utils::{ordered::Set, TryCollect as _};

/// Ed25519 multisig signing scheme used for consensus.
pub type Ed25519Scheme = Scheme;

const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";

/// Complete key material for a test cluster.
#[derive(Debug)]
pub struct KeySet {
    identity_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<ed25519::PublicKey>,
    threshold: u32,
    schemes: Vec<Ed25519Scheme>,
    seed: u64,
}

impl KeySet {
    pub fn builder() -> KeySetBuilder {
        KeySetBuilder::default()
    }

    pub const fn node_count(&self) -> usize {
        self.identity_keys.len()
    }

    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub fn identity_key(&self, index: usize) -> &ed25519::PrivateKey {
        &self.identity_keys[index]
    }

    pub fn participants(&self) -> &[ed25519::PublicKey] {
        &self.participants
    }

    pub fn scheme(&self, index: usize) -> &Ed25519Scheme {
        &self.schemes[index]
    }

    /// Write `validator.key` (raw 32-byte ed25519 private key) per node.
    pub fn write_to(&self, node_dirs: &[impl AsRef<Path>]) -> eyre::Result<()> {
        assert_eq!(
            node_dirs.len(),
            self.node_count(),
            "expected {} dirs, got {}",
            self.node_count(),
            node_dirs.len()
        );

        for (i, dir) in node_dirs.iter().enumerate() {
            let dir = dir.as_ref();
            std::fs::create_dir_all(dir)?;
            let key_bytes = Encode::encode(&self.identity_keys[i]);
            std::fs::write(dir.join("validator.key"), key_bytes.as_ref())?;
        }

        Ok(())
    }

    /// Write a peers.json file for use by validator processes.
    pub fn write_peers(&self, path: &Path, p2p_ports: &[u16]) -> eyre::Result<()> {
        let participants_hex: Vec<String> = self
            .participants
            .iter()
            .map(|pk| hex::encode(Encode::encode(pk)))
            .collect();

        let bootstrappers: BTreeMap<String, String> = self
            .participants
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                let pk_hex = hex::encode(Encode::encode(pk));
                let addr = format!("127.0.0.1:{}", p2p_ports[i]);
                (pk_hex, addr)
            })
            .collect();

        let peers_json = serde_json::json!({
            "validators": self.node_count(),
            "threshold": self.threshold,
            "participants": participants_hex,
            "bootstrappers": bootstrappers,
        });

        std::fs::write(path, serde_json::to_string_pretty(&peers_json)?)?;
        Ok(())
    }

    pub const fn is_single_node(&self) -> bool {
        self.schemes.len() == 1
    }
}

#[derive(Debug)]
pub struct KeySetBuilder {
    nodes: usize,
    threshold: Option<u32>,
    seed: Option<u64>,
}

impl Default for KeySetBuilder {
    fn default() -> Self {
        Self {
            nodes: 4,
            threshold: None,
            seed: None,
        }
    }
}

impl KeySetBuilder {
    #[must_use]
    pub const fn nodes(mut self, n: usize) -> Self {
        self.nodes = n;
        self
    }

    #[must_use]
    pub const fn threshold(mut self, t: u32) -> Self {
        self.threshold = Some(t);
        self
    }

    #[must_use]
    pub const fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    pub fn build(self) -> eyre::Result<KeySet> {
        let n = self.nodes;
        if n == 0 {
            return Err(eyre::eyre!("need at least 1 node"));
        }
        if n > 1 && n < 4 {
            return Err(eyre::eyre!(
                "multi-node clusters need at least 4 nodes for BFT quorum (got {})",
                n
            ));
        }

        let seed = self.seed.unwrap_or_else(rand::random);
        let f = if n > 1 { (n - 1) / 3 } else { 0 };
        let threshold = self
            .threshold
            .unwrap_or(if n == 1 { 1 } else { (n - f) as u32 });

        let (participants, schemes) = generate_ed25519_schemes(seed, n)?;

        let seed_keys: Vec<_> = (0..n)
            .map(|i| {
                let key = ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64));
                (key.public_key(), key)
            })
            .collect();

        let identity_keys: Vec<ed25519::PrivateKey> = participants
            .iter()
            .map(|pk| {
                seed_keys
                    .iter()
                    .find(|(p, _)| p == pk)
                    .expect("all participants derived from seed")
                    .1
                    .clone()
            })
            .collect();

        Ok(KeySet {
            identity_keys,
            participants,
            threshold,
            schemes,
            seed,
        })
    }
}

/// Generate deterministic ed25519 signing schemes.
fn generate_ed25519_schemes(
    seed: u64,
    n: usize,
) -> eyre::Result<(Vec<ed25519::PublicKey>, Vec<Ed25519Scheme>)> {
    let private_keys: Vec<ed25519::PrivateKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)))
        .collect();

    let participants: Set<ed25519::PublicKey> = private_keys
        .iter()
        .map(|k| k.public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let ordered_pks: Vec<ed25519::PublicKey> = participants.iter().cloned().collect();

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let private_key = private_keys
            .iter()
            .find(|k| k.public_key() == *pk)
            .expect("private key exists for participant")
            .clone();
        let scheme = Scheme::signer(SIMPLEX_NAMESPACE, participants.clone(), private_key)
            .ok_or_else(|| eyre::eyre!("failed to create signer for participant"))?;
        schemes.push(scheme);
    }

    Ok((ordered_pks, schemes))
}
