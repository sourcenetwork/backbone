//! Genesis configuration builder for e2e test clusters.
//!
//! Uses local mirror types that match hub-genesis's JSON schema exactly,
//! so hub-harness can construct genesis.json without importing hub-genesis.

use std::path::Path;

use serde::Serialize;

/// Matches hub-genesis HubGenesis JSON schema exactly.
#[derive(Clone, Debug, Serialize)]
pub struct HubGenesis {
    pub chain_id: u64,
    pub chain_name: String,
    pub timestamp: u64,
    pub allocations: Vec<GenesisAllocation>,
    pub native_mint: NativeMintConfig,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<GenesisContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_storage: Vec<GenesisStorage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_length: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GenesisAllocation {
    pub address: String,
    pub balance: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorConfig {
    pub evm_address: String,
    pub consensus_pubkey: String,
    pub p2p_address: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NativeMintConfig {
    #[serde(default)]
    pub admin: Option<String>,
    #[serde(default)]
    pub minters: Vec<String>,
    pub denom: String,
}

/// Arbitrary contract bytecode injected at genesis.
#[derive(Clone, Debug, Serialize)]
pub struct GenesisContract {
    pub address: String,
    pub bytecode: String,
}

/// Pre-set storage slot at genesis.
#[derive(Clone, Debug, Serialize)]
pub struct GenesisStorage {
    pub address: String,
    pub slot: String,
    pub value: String,
}

/// Builder for test genesis configurations.
#[derive(Debug)]
pub struct GenesisBuilder {
    chain_id: u64,
    chain_name: String,
    allocations: Vec<GenesisAllocation>,
    native_mint: NativeMintConfig,
    validators: Vec<ValidatorConfig>,
    contracts: Vec<GenesisContract>,
    extra_storage: Vec<GenesisStorage>,
    epoch_length: Option<u64>,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            chain_id: 9001,
            chain_name: "hub-test".to_string(),
            allocations: Vec::new(),
            native_mint: NativeMintConfig::default(),
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_length: None,
        }
    }
}

impl GenesisBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-configured for devnet (matches `HubGenesis::devnet()`).
    pub fn devnet() -> Self {
        Self {
            chain_id: 9001,
            chain_name: "hub-devnet".to_string(),
            allocations: vec![
                GenesisAllocation {
                    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
                GenesisAllocation {
                    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
                    balance: "1000000000000000000000".to_string(),
                },
            ],
            native_mint: NativeMintConfig {
                admin: Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()),
                minters: vec!["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()],
                denom: "abrl".to_string(),
            },
            validators: Vec::new(),
            contracts: Vec::new(),
            extra_storage: Vec::new(),
            epoch_length: None,
        }
    }

    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    #[must_use]
    pub fn chain_name(mut self, name: impl Into<String>) -> Self {
        self.chain_name = name.into();
        self
    }

    #[must_use]
    pub fn allocation(mut self, address: &str, balance: &str) -> Self {
        self.allocations.push(GenesisAllocation {
            address: address.to_string(),
            balance: balance.to_string(),
        });
        self
    }

    /// Add pre-funded test accounts (up to 10).
    #[must_use]
    pub fn funded_accounts(mut self, count: usize, balance: &str) -> Self {
        const TEST_ADDRESSES: [&str; 10] = [
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
            "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
            "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
            "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
            "0x14dC79964da2C08daa4968306Dba23d250591E0A",
            "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
            "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
        ];

        for addr in TEST_ADDRESSES.iter().take(count) {
            self.allocations.push(GenesisAllocation {
                address: (*addr).to_string(),
                balance: balance.to_string(),
            });
        }
        self
    }

    #[must_use]
    pub fn native_mint(mut self, config: NativeMintConfig) -> Self {
        self.native_mint = config;
        self
    }

    #[must_use]
    pub fn validators(mut self, configs: Vec<ValidatorConfig>) -> Self {
        self.validators = configs;
        self
    }

    /// Add arbitrary contract bytecode at genesis.
    #[must_use]
    pub fn contract(mut self, address: &str, bytecode: &str) -> Self {
        self.contracts.push(GenesisContract {
            address: address.to_string(),
            bytecode: bytecode.to_string(),
        });
        self
    }

    /// Pre-set a storage slot at genesis.
    #[must_use]
    pub fn storage(mut self, address: &str, slot: &str, value: &str) -> Self {
        self.extra_storage.push(GenesisStorage {
            address: address.to_string(),
            slot: slot.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn build(self) -> HubGenesis {
        HubGenesis {
            chain_id: self.chain_id,
            chain_name: self.chain_name,
            timestamp: 0,
            allocations: self.allocations,
            native_mint: self.native_mint,
            validators: self.validators,
            contracts: self.contracts,
            extra_storage: self.extra_storage,
            epoch_length: self.epoch_length,
        }
    }

    /// Build and write genesis.json to a directory.
    pub fn build_and_write(&self, dir: &Path) -> eyre::Result<HubGenesis> {
        let genesis = HubGenesis {
            chain_id: self.chain_id,
            chain_name: self.chain_name.clone(),
            timestamp: 0,
            allocations: self.allocations.clone(),
            native_mint: self.native_mint.clone(),
            validators: self.validators.clone(),
            contracts: self.contracts.clone(),
            extra_storage: self.extra_storage.clone(),
            epoch_length: self.epoch_length,
        };

        let json = serde_json::to_string_pretty(&genesis)?;
        std::fs::write(dir.join("genesis.json"), json)?;
        Ok(genesis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_genesis() {
        let genesis = GenesisBuilder::devnet().build();
        assert_eq!(genesis.chain_id, 9001);
        assert_eq!(genesis.allocations.len(), 2);
        assert_eq!(genesis.native_mint.denom, "abrl");
    }

    #[test]
    fn custom_genesis() {
        let genesis = GenesisBuilder::new()
            .chain_id(1337)
            .allocation(
                "0xdead000000000000000000000000000000000000",
                "1000000000000000000000",
            )
            .build();

        assert_eq!(genesis.chain_id, 1337);
        assert_eq!(genesis.allocations.len(), 1);
    }

    #[test]
    fn funded_accounts_genesis() {
        let genesis = GenesisBuilder::new()
            .funded_accounts(3, "1000000000000000000000")
            .build();

        assert_eq!(genesis.allocations.len(), 3);
        assert!(genesis.allocations[0].address.starts_with("0xf39F"));
    }

    #[test]
    fn genesis_with_contracts_and_storage() {
        let genesis = GenesisBuilder::new()
            .contract(
                "0x1234000000000000000000000000000000000000",
                "0x600160005260206000f3",
            )
            .storage("0x1234000000000000000000000000000000000000", "0x0", "0x2a")
            .build();

        assert_eq!(genesis.contracts.len(), 1);
        assert_eq!(genesis.extra_storage.len(), 1);
    }

    #[test]
    fn write_genesis_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = GenesisBuilder::devnet()
            .build_and_write(dir.path())
            .unwrap();

        assert!(dir.path().join("genesis.json").exists());
        assert_eq!(genesis.chain_id, 9001);
    }
}
