//! Finality and state proof verification shared with Vera.

pub use vera_domain::{verify_finalized_block, verify_light_block, LightBlockError};

use commonware_codec::Decode as _;
use vera_domain::{Block, BlockCfg, TxCfg, MAX_BLOCK_TXS, MAX_TX_BYTES};

/// Decode the canonical block of a light block that has already been verified.
pub(crate) fn decode_block(light: &vera_domain::LightBlock) -> Result<Block, LightBlockError> {
    let encoded = light.block.strip_prefix("0x").unwrap_or(&light.block);
    let bytes = hex::decode(encoded).map_err(|error| LightBlockError::Hex {
        field: "block",
        message: error.to_string(),
    })?;
    Ok(Block::decode_cfg(
        commonware_codec::Copying(bytes.as_slice()),
        &BlockCfg {
            max_txs: MAX_BLOCK_TXS,
            tx: TxCfg {
                max_tx_bytes: MAX_TX_BYTES,
            },
        },
    )?)
}
