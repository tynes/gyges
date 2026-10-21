//! Chain access for `gygesd` (ARCHITECTURE.md §3.1, SYNC.md).
//!
//! Two implementations of one `CompactBlockSource` trait:
//! * `ZakuraRpcBackend` – JSON-RPC against a local pruned `zakurad`, building
//!   `CompactBlock`s from `getblock(h, 0)`;
//! * `ArtiTorLwdBackend` – lightwalletd `CompactTxStreamer` over an embedded
//!   Tor client, used only below the node's `pruneheight`.
//!
//! What exists today is the [`ChainBackend`] trait that `gyges-core` needs
//! for account creation (node bounds and the note commitment tree state at
//! a birthday), so that the key registry can be written and tested against
//! a fake node before `ZakuraRpcBackend` lands (ROADMAP.md M1).

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use zcash_client_backend::data_api::chain::ChainState;
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

/// Why the node could not answer.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The node is not reachable (connection refused, timeout, auth failure).
    #[error("node unreachable: {0}")]
    Unreachable(String),
    /// The node answered but cannot serve this request: typically
    /// `z_gettreestate` below `pruneheight` (`HistoricalTreeUnavailable`).
    #[error(
        "tree state at height {height} is not available from the node (retained from {retained_from})"
    )]
    TreeStateUnavailable {
        height: BlockHeight,
        retained_from: BlockHeight,
    },
    /// The node returned an error or an unparseable response.
    #[error("node error: {0}")]
    Rpc(String),
}

/// A boxed future, for the object-safe async methods below.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The node-facing operations the wallet core needs outside of scanning.
///
/// Implemented by `ZakuraRpcBackend` (and by test fakes). Scanning itself
/// goes through `zcash_client_backend`'s `BlockSource` / `BlockCache` over
/// the shared block cache and is not part of this trait.
pub trait ChainBackend: Send + Sync + fmt::Debug {
    /// `getblockchaininfo`, reduced to what the scheduler needs.
    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>>;

    /// The note commitment tree frontiers and block hash as of the end of
    /// block `height` (`z_gettreestate(height)`), used as the prior chain
    /// state of an account born at `height + 1`. A pruned node can only
    /// answer for `height >= retained_from`; below that it returns
    /// [`ChainError::TreeStateUnavailable`].
    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>>;
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
