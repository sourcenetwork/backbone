use std::path::PathBuf;
use std::time::Duration;

use eyre::{Result, WrapErr};

use crate::genesis;
use crate::identity::source_hub_address;
use crate::SourceHubPorts;

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
    #[allow(dead_code)]
    log_tracker: test_infra::LogTracker,
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
    ) -> Result<Self> {
        let binary = crate::resolve_binary()?;
        let chain_id = DEFAULT_CHAIN_ID.to_string();

        let funded_addresses: Vec<String> = identity_keys
            .iter()
            .map(|key| source_hub_address(key))
            .collect::<Result<_>>()
            .wrap_err("deriving source hub addresses from identity keys")?;

        let faucet_address = source_hub_address(TEST_ACCOUNT_HEX_KEY)?;

        genesis::provision_genesis(
            &binary,
            &home_dir,
            &chain_id,
            &funded_addresses,
            Some(&faucet_address),
            ports,
        )
        .wrap_err("provisioning source hub genesis")?;

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

        let stdout_path = log_dir.join("stdout.log");
        let log_tracker =
            test_infra::LogTracker::start(stdout_path, "committed state", sourcehub_patterns());

        let process = test_infra::ManagedProcess::spawn("sourcehub", &binary, &args, &[], &log_dir)
            .wrap_err("failed to spawn sourcehubd")?;

        let _first_block: String = log_tracker
            .wait_for_pattern("first_block", ready_timeout)
            .await
            .wrap_err("sourcehubd did not produce first block")?;

        let lcd_url = format!("http://127.0.0.1:{}", ports.lcd);

        // Health check: wait for LCD to respond
        let client = reqwest::Client::new();
        let health_url = format!("{}/cosmos/base/tendermint/v1beta1/blocks/latest", lcd_url);
        let deadline = tokio::time::Instant::now() + ready_timeout;
        loop {
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => break,
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                eyre::bail!("sourcehubd LCD health check timed out at {}", health_url);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let comet_rpc_url = format!("http://127.0.0.1:{}", ports.comet_rpc);
        let grpc_url = format!("http://127.0.0.1:{}", ports.grpc);

        tracing::info!(
            lcd = %lcd_url,
            comet_rpc = %comet_rpc_url,
            grpc = %grpc_url,
            "SourceHub devnet ready"
        );

        Ok(Self {
            process,
            log_tracker,
            lcd_url,
            comet_rpc_url,
            grpc_url,
            chain_id,
            home_dir,
        })
    }
}

fn sourcehub_patterns() -> Vec<test_infra::NamedPattern> {
    vec![test_infra::NamedPattern {
        name: "first_block",
        regex: regex::Regex::new(r"committed state.*height=1\b").unwrap(),
    }]
}
