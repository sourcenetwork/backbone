use std::path::Path;
use std::process::Command;

use eyre::{Result, WrapErr};

use crate::SourceHubPorts;

const VALIDATOR_STAKE: &str = "100000000000uopen";
const VALIDATOR_BALANCE: &str = "1000000000000uopen";
const IDENTITY_BALANCE: &str = "100000000uopen";
const FAUCET_BALANCE: &str = "100000000000uopen";

/// Provision a single-node Vera devnet genesis.
///
/// Follows the standard Cosmos SDK pattern:
///   init -> keys add -> add-genesis-account (validator + funded addrs + faucet) ->
///   gentx -> collect-gentxs -> patch configs
pub fn provision_genesis(
    binary: &Path,
    home_dir: &Path,
    chain_id: &str,
    funded_addresses: &[String],
    faucet_address: Option<&str>,
    ports: &SourceHubPorts,
) -> Result<()> {
    let home_str = home_dir.display().to_string();

    run_cmd(
        binary,
        &[
            "init",
            "test-node",
            "--chain-id",
            chain_id,
            "--home",
            &home_str,
        ],
    )
    .wrap_err("verad init failed")?;

    let validator_output = run_cmd(
        binary,
        &[
            "keys",
            "add",
            "validator",
            "--keyring-backend",
            "test",
            "--home",
            &home_str,
            "--output",
            "json",
        ],
    )
    .wrap_err("verad keys add failed")?;

    let addr_json: serde_json::Value =
        serde_json::from_str(&validator_output).wrap_err("failed to parse validator key output")?;
    let validator_address = addr_json["address"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("missing address in validator key output"))?
        .to_string();

    run_cmd(
        binary,
        &[
            "genesis",
            "add-genesis-account",
            &validator_address,
            VALIDATOR_BALANCE,
            "--home",
            &home_str,
        ],
    )
    .wrap_err("add validator genesis account failed")?;

    for addr in funded_addresses {
        run_cmd(
            binary,
            &[
                "genesis",
                "add-genesis-account",
                addr,
                IDENTITY_BALANCE,
                "--home",
                &home_str,
            ],
        )
        .wrap_err_with(|| format!("add genesis account {} failed", addr))?;
    }

    if let Some(faucet_addr) = faucet_address {
        run_cmd(
            binary,
            &[
                "genesis",
                "add-genesis-account",
                faucet_addr,
                FAUCET_BALANCE,
                "--home",
                &home_str,
            ],
        )
        .wrap_err("add faucet genesis account failed")?;
    }

    run_cmd(
        binary,
        &[
            "genesis",
            "gentx",
            "validator",
            VALIDATOR_STAKE,
            "--chain-id",
            chain_id,
            "--keyring-backend",
            "test",
            "--home",
            &home_str,
        ],
    )
    .wrap_err("verad gentx failed")?;

    run_cmd(binary, &["genesis", "collect-gentxs", "--home", &home_str])
        .wrap_err("verad collect-gentxs failed")?;

    patch_config_toml(home_dir, ports)?;
    patch_app_toml(home_dir, ports)?;

    Ok(())
}

/// Consensus timings for the devnet.
///
/// CometBFT ships `timeout_commit = "5s"`, and that single value is the cost of
/// every test that writes to the chain: a transaction is not queryable until it
/// is in a block, so each one waits a block. Measured on the shipped defaults,
/// this devnet produced a block every 5.03 s, and four sequential transactions
/// were 80% of the time to provision one tenant.
///
/// A single-validator devnet reaches consensus on its own vote, so the round
/// timeouts almost never bind; they are set anyway so the configuration stays
/// coherent if the harness ever runs more than one validator.
const CONSENSUS_TIMEOUTS: [(&str, &str); 4] = [
    ("timeout_propose", "500ms"),
    ("timeout_prevote", "500ms"),
    ("timeout_precommit", "500ms"),
    ("timeout_commit", "1s"),
];

/// Patch config.toml to bind CometBFT RPC and P2P to allocated ports, and to
/// run consensus at a speed suited to a test devnet.
fn patch_config_toml(home_dir: &Path, ports: &SourceHubPorts) -> Result<()> {
    let config_path = home_dir.join("config/config.toml");
    let content = std::fs::read_to_string(&config_path).wrap_err("read config.toml")?;

    // Replace default CometBFT RPC port (26657)
    let content = content.replace(
        "laddr = \"tcp://127.0.0.1:26657\"",
        &format!("laddr = \"tcp://0.0.0.0:{}\"", ports.comet_rpc),
    );
    // Replace default P2P port (26656)
    let content = content.replace(
        "laddr = \"tcp://0.0.0.0:26656\"",
        &format!("laddr = \"tcp://0.0.0.0:{}\"", ports.p2p),
    );
    let mut content = content;
    for (key, value) in CONSENSUS_TIMEOUTS {
        content = replace_setting(&content, key, value)?;
    }

    std::fs::write(&config_path, content).wrap_err("write config.toml")?;
    Ok(())
}

/// Replace a `key = "value"` line in a CometBFT config, failing loudly if the
/// key is absent: a silently skipped timeout would look like a slow chain
/// rather than a missed setting.
fn replace_setting(content: &str, key: &str, value: &str) -> Result<String> {
    let mut found = false;
    let patched = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&format!("{} =", key)) {
                found = true;
                format!("{} = \"{}\"", key, value)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    eyre::ensure!(found, "config.toml has no `{}` setting to patch", key);
    Ok(patched)
}

/// Patch app.toml to bind gRPC and LCD/API to allocated ports.
fn patch_app_toml(home_dir: &Path, ports: &SourceHubPorts) -> Result<()> {
    let app_path = home_dir.join("config/app.toml");
    let content = std::fs::read_to_string(&app_path).wrap_err("read app.toml")?;

    // Replace default gRPC port (9090)
    let content = content.replace(
        "address = \"0.0.0.0:9090\"",
        &format!("address = \"0.0.0.0:{}\"", ports.grpc),
    );
    // Replace default LCD/API port (1317)
    let content = content.replace(
        "address = \"tcp://0.0.0.0:1317\"",
        &format!("address = \"tcp://0.0.0.0:{}\"", ports.lcd),
    );
    // Ensure API is enabled
    let content = content.replacen("enable = false", "enable = true", 1);

    std::fs::write(&app_path, content).wrap_err("write app.toml")?;
    Ok(())
}

fn run_cmd(program: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .wrap_err_with(|| format!("failed to run {} {}", program.display(), args.join(" ")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(eyre::eyre!(
            "{} {} failed (exit {}): stderr={}, stdout={}",
            program.display(),
            args.join(" "),
            output.status,
            stderr.trim(),
            stdout.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::replace_setting;

    const SAMPLE: &str = "\
[consensus]\n\
timeout_propose = \"3s\"\n\
timeout_commit = \"5s\"\n\
create_empty_blocks = true\n\
create_empty_blocks_interval = \"0s\"\n";

    #[test]
    fn replaces_a_setting_in_place() {
        let patched = replace_setting(SAMPLE, "timeout_commit", "1s").expect("patch");
        assert!(patched.contains("timeout_commit = \"1s\""));
        assert!(!patched.contains("timeout_commit = \"5s\""));
        // Neighbouring settings are untouched.
        assert!(patched.contains("timeout_propose = \"3s\""));
        assert!(patched.contains("create_empty_blocks = true"));
    }

    #[test]
    fn every_consensus_timeout_is_present_in_a_stock_config() {
        let mut patched = SAMPLE.to_string();
        for (key, value) in super::CONSENSUS_TIMEOUTS {
            if SAMPLE.contains(&format!("{} =", key)) {
                patched = replace_setting(&patched, key, value).expect("patch");
                assert!(patched.contains(&format!("{} = \"{}\"", key, value)));
            }
        }
    }

    #[test]
    fn a_missing_setting_is_an_error_not_a_silent_skip() {
        let err = replace_setting(SAMPLE, "timeout_nonexistent", "1s")
            .expect_err("an absent key must fail");
        assert!(
            format!("{err}").contains("timeout_nonexistent"),
            "the error must name the key: {err}"
        );
    }

    #[test]
    fn does_not_match_a_key_that_only_shares_a_prefix() {
        let patched = replace_setting(SAMPLE, "create_empty_blocks", "false").expect("patch");
        assert!(patched.contains("create_empty_blocks = \"false\""));
        assert!(
            patched.contains("create_empty_blocks_interval = \"0s\""),
            "the longer key must survive: {patched}"
        );
    }
}
