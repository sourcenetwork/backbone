use std::time::Duration;

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_client::VeraClient;
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

const READY_TIMEOUT: Duration = Duration::from_secs(60);
const READY_HEIGHT: u64 = 3;

/// Validators in every deployment.
pub const VALIDATORS: usize = 4;

/// A running vera.rs cluster and the trust material its clients are
/// configured with: the deployment identifier, the consensus key and the
/// genesis block's identifier.
pub struct VeraDeployment {
    cluster: TestCluster,
    deployment_id: u64,
    consensus_key: ConsensusPublicKey,
    genesis_id: B256,
}

impl VeraDeployment {
    /// Start validators keyed from `seed` under `deployment_id`, wait until
    /// they finalize a few blocks and read the genesis identifier.
    ///
    /// The harness runs a lone validator as `verad devnet`, which deals its
    /// own consensus key, so a deployment always has [`VALIDATORS`]: their
    /// key follows from `seed` alone.
    pub async fn start(seed: u64, deployment_id: u64) -> eyre::Result<Self> {
        let nodes = VALIDATORS;
        let cluster = TestCluster::builder()
            .nodes(nodes)
            .seed(seed)
            .chain_id(deployment_id)
            .genesis(GenesisBuilder::devnet())
            .preset(ConsensusPreset::Normal)
            .build()
            .await?;
        cluster.wait_ready(READY_TIMEOUT).await?;
        cluster
            .observe(Duration::from_millis(200))
            .wait_for_height(READY_HEIGHT, READY_TIMEOUT)
            .await?;
        let keys = KeySet::builder().nodes(nodes).seed(seed).build()?;
        let consensus_key = *keys.epoch_info().output.public().public();
        let first = VeraClient::new(cluster.node(0).rpc_url())
            .read_finalized_revision(1, &consensus_key)
            .await?;
        let genesis_id = first.parent_hash.parse()?;
        Ok(Self {
            cluster,
            deployment_id,
            consensus_key,
            genesis_id,
        })
    }

    pub fn cluster(&self) -> &TestCluster {
        &self.cluster
    }

    pub fn rpc_url(&self) -> String {
        self.cluster.node(0).rpc_url()
    }

    pub fn ws_url(&self) -> String {
        self.cluster.node(0).ws_url()
    }

    pub fn client(&self) -> VeraClient {
        VeraClient::new(self.rpc_url())
    }

    pub fn deployment_id(&self) -> u64 {
        self.deployment_id
    }

    pub fn consensus_key(&self) -> &ConsensusPublicKey {
        &self.consensus_key
    }

    /// The consensus key in the hexadecimal encoding operators configure.
    pub fn consensus_key_hex(&self) -> String {
        hex::encode(self.consensus_key.encode())
    }

    /// The genesis block's identifier, which also roots the deployment.
    pub fn genesis_id(&self) -> B256 {
        self.genesis_id
    }

    /// The genesis identifier as 64 hexadecimal digits without a prefix.
    pub fn genesis_id_hex(&self) -> String {
        hex::encode(self.genesis_id)
    }

    /// Connect the administering account to the first node.
    pub async fn admin(&self) -> eyre::Result<crate::VeraAccount> {
        crate::VeraAccount::connect(&self.rpc_url(), self.deployment_id, &crate::ADMIN_KEY).await
    }
}
