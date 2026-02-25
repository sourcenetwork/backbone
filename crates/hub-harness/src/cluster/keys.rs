//! Key management for e2e test clusters.
//!
//! Generates ed25519 identity keys and deterministic BLS12-381 threshold
//! schemes using commonware-cryptography directly (no hub-runner dependency).

use std::{collections::BTreeMap, path::Path};

use commonware_codec::Encode;
use commonware_consensus::simplex::scheme::bls12381_threshold::vrf;
use commonware_cryptography::{
    bls12381::{
        dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, Signer as _,
};
use commonware_utils::{ordered::Set, N3f1, TryCollect as _};
use rand::{rngs::StdRng, SeedableRng as _};

/// BLS12-381 threshold signature scheme used for consensus.
pub type ThresholdScheme = vrf::Scheme<ed25519::PublicKey, MinSig>;

const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";

/// Complete key material for a test cluster.
#[derive(Debug)]
pub struct KeySet {
    identity_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<ed25519::PublicKey>,
    threshold: u32,
    schemes: Vec<ThresholdScheme>,
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

    pub fn scheme(&self, index: usize) -> &ThresholdScheme {
        &self.schemes[index]
    }

    /// Serialized BLS12-381 group public key (G2, 96 bytes compressed).
    pub fn group_public_key(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        commonware_codec::Write::write(self.schemes[0].identity(), &mut buf);
        buf
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

        let (participants, schemes) = generate_threshold_schemes(seed, n)?;

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

/// Generate deterministic threshold BLS signing schemes using trusted-dealer mode.
fn generate_threshold_schemes(
    seed: u64,
    n: usize,
) -> eyre::Result<(Vec<ed25519::PublicKey>, Vec<ThresholdScheme>)> {
    let participants: Set<ed25519::PublicKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)).public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::default(), participants.clone())
            .map_err(|e| eyre::eyre!("dkg deal failed: {}", e))?;

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let share = shares.get_value(pk).expect("share exists").clone();
        let scheme = vrf::Scheme::signer(
            SIMPLEX_NAMESPACE,
            participants.clone(),
            output.public().clone(),
            share,
        )
        .ok_or_else(|| eyre::eyre!("failed to create signer for participant"))?;
        schemes.push(scheme);
    }

    Ok((participants.into(), schemes))
}
