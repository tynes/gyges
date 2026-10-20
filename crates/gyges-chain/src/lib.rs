//! Chain access for `gygesd` (ARCHITECTURE.md §3.1, SYNC.md).
//!
//! Two implementations of one `CompactBlockSource` trait:
//! * `ZakuraRpcBackend` – JSON-RPC against a local pruned `zakurad`, building
//!   `CompactBlock`s from `getblock(h, 0)`;
//! * `ArtiTorLwdBackend` – lightwalletd `CompactTxStreamer` over an embedded
//!   Tor client, used only below the node's `pruneheight`.

#![forbid(unsafe_code)]

use zcash_protocol::consensus::BlockHeight;

/// What `getblockchaininfo` tells us about the node (OVERVIEW.md Q-D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBounds {
    pub tip_height: BlockHeight,
    pub tip_hash: [u8; 32],
    /// `pruneheight` when `pruned == true`, otherwise 0. The lowest height
    /// whose block body the node still stores.
    pub retained_from: BlockHeight,
}

/// Which route a key is currently scanning through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Case A: local `zakurad` JSON-RPC, `scanned_tip + 1 >= retained_from`.
    ZakuraRpc,
    /// Case B: archival lightwalletd over Tor, below `retained_from`.
    TorLightwalletd,
}

/// Compile-time proof that the upstream module paths cited in the design
/// documents exist under the `package =` renames in `Cargo.toml`.
#[allow(unused_imports)]
mod paths_compile {
    use zcash_client_backend::data_api::chain::{BlockCache, BlockSource, scan_cached_blocks};
    use zcash_client_backend::data_api::{WalletRead, WalletWrite};
    use zcash_client_backend::proto::compact_formats::CompactBlock;
    use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
    use zcash_client_backend::tor;
}
