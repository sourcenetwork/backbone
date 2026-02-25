use std::path::PathBuf;
use std::time::Duration;

use common::blockchain::ChainConfig;

use crate::defradb::SourceHubConfig;

use super::genesis;
use super::identity::source_hub_address;
use super::SourceHubPorts;

const DEFAULT_CHAIN_ID: &str = "sourcehub-localnet";

/// Well-known test account private key (the "abandon" mnemonic, Cosmos HD path m/44'/118'/0'/0/0).
const TEST_ACCOUNT_HEX_KEY: &str =
    "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";

/// A running SourceHub single-node devnet.
///
/// Provisions genesis, starts the chain, and waits for the first block.
/// Killed on drop via ManagedProcess.
pub struct SourceHubNode {
    #[allow(dead_code)]
    process: test_infra::ManagedProcess,
    /// Cosmos LCD/REST API URL.
    pub lcd_url: String,
    /// CometBFT RPC URL.
    pub comet_rpc_url: String,
    /// gRPC URL.
    pub grpc_url: String,
    /// Chain ID.
    pub chain_id: String,
    /// SourceHub home directory.
    #[allow(dead_code)]
    pub home_dir: PathBuf,
}

impl SourceHubNode {
    /// Provision and start a SourceHub devnet node.
    ///
    /// `identity_keys` are hex-encoded secp256k1 private keys whose derived
    /// `source1...` addresses will be funded in genesis.
    pub async fn start(
        home_dir: PathBuf,
        log_dir: PathBuf,
        ports: &SourceHubPorts,
        identity_keys: &[String],
        ready_timeout: Duration,
    ) -> eyre::Result<Self> {
        let binary = super::resolve_binary()?;
        let chain_id = DEFAULT_CHAIN_ID.to_string();

        let funded_addresses: Vec<String> = identity_keys
            .iter()
            .map(|key| source_hub_address(key))
            .collect::<eyre::Result<_>>()?;

        let faucet_address = source_hub_address(TEST_ACCOUNT_HEX_KEY)?;

        genesis::provision_genesis(
            &binary,
            &home_dir,
            &chain_id,
            &funded_addresses,
            Some(&faucet_address),
            ports,
        )?;

        let home_str = home_dir.display().to_string();
        let comet_rpc_addr = format!("tcp://0.0.0.0:{}", ports.comet_rpc);
        let grpc_addr = format!("0.0.0.0:{}", ports.grpc);
        let lcd_addr = format!("tcp://0.0.0.0:{}", ports.lcd);
        let p2p_addr = format!("tcp://0.0.0.0:{}", ports.p2p);

        let args_owned = vec![
            "start".to_string(),
            "--home".to_string(),
            home_str,
            "--rpc.laddr".to_string(),
            comet_rpc_addr,
            "--grpc.address".to_string(),
            grpc_addr,
            "--api.address".to_string(),
            lcd_addr,
            "--p2p.laddr".to_string(),
            p2p_addr,
            "--minimum-gas-prices".to_string(),
            "0uopen".to_string(),
            "--log_no_color".to_string(),
        ];
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

        let process =
            test_infra::ManagedProcess::spawn("sourcehub", &binary, &args, &[], &log_dir)?;

        let lcd_url = format!("http://127.0.0.1:{}", ports.lcd);

        let client = reqwest::Client::new();
        let health_url = format!("{}/cosmos/base/tendermint/v1beta1/blocks/latest", lcd_url);
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => break,
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(eyre::eyre!(
                    "sourcehubd LCD health check timed out at {}",
                    health_url
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        tracing::info!(
            lcd = %lcd_url,
            comet_rpc = %format!("http://127.0.0.1:{}", ports.comet_rpc),
            grpc = %format!("http://127.0.0.1:{}", ports.grpc),
            "SourceHub devnet ready"
        );

        Ok(Self {
            process,
            lcd_url,
            comet_rpc_url: format!("http://127.0.0.1:{}", ports.comet_rpc),
            grpc_url: format!("http://127.0.0.1:{}", ports.grpc),
            chain_id,
            home_dir,
        })
    }

    /// Build a `ChainConfig` pointing at this SourceHub instance.
    pub fn chain_config(&self) -> ChainConfig {
        ChainConfig {
            chain_id: self.chain_id.clone(),
            rpc_url: self.comet_rpc_url.clone(),
            rest_url: self.lcd_url.clone(),
            grpc_url: self.grpc_url.clone(),
            account_prefix: "source".to_string(),
            default_gas_limit: 300_000,
            gas_price: common::blockchain::GasPrice::default(),
            gas_multiplier: 1.2,
        }
    }

    /// Build a `SourceHubConfig` for DefraDB's ACP integration.
    pub fn defra_config(&self) -> SourceHubConfig {
        SourceHubConfig {
            lcd_url: self.lcd_url.clone(),
            comet_rpc_url: self.comet_rpc_url.clone(),
            chain_id: self.chain_id.clone(),
        }
    }
}
