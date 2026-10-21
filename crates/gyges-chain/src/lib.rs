//! Chain access for `gygesd` (ARCHITECTURE.md §3.1, SYNC.md).
//!
//! * [`ChainBackend`] – the node-facing operations the wallet core and the
//!   sync scheduler need: node bounds, tree states, block hashes and
//!   synthetic `CompactBlock`s for a height range (Case A);
//! * [`rpc::ZakuraRpcBackend`] – its implementation over the JSON-RPC of a
//!   local pruned `zakurad`, building compact blocks from `getblock(h, 0)`;
//! * [`compact`] – the raw-block → `CompactBlock` builder, which also carries
//!   every transparent input and output so that Case A can index transparent
//!   history without a node-side address index;
//! * [`cache::BlockDb`] – the shared `cache/blocks.sqlite`, implementing the
//!   upstream `BlockSource` and `BlockCache` traits so that
//!   `scan_cached_blocks` reads it unchanged.
//!
//! The Tor lightwalletd route (`ArtiTorLwdBackend`, Case B) arrives with
//! ROADMAP.md M2. With the `test-util` feature, the `testing` module provides
//! an in-process fake `zakurad` and a synthetic block builder.

#![forbid(unsafe_code)]

pub mod cache;
pub mod compact;
pub mod rpc;
#[cfg(feature = "test-util")]
pub mod testing;

use std::fmt;
use std::future::Future;
use std::ops::Range;
use std::pin::Pin;
use std::time::SystemTime;

use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::BlockHeight;

pub use cache::{BlockDb, CacheError, Source};
pub use compact::{CompactError, TransparentOutput, TreeSizes};
pub use rpc::ZakuraRpcBackend;

/// What `getblockchaininfo` tells us about the node (OVERVIEW.md Q-D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBounds {
    pub tip_height: BlockHeight,
    /// Internal byte order (the order `CompactBlock.hash` and
    /// `zcash_primitives::block::BlockHash` use); the JSON-RPC shows the
    /// byte-reversed hex. See [`display_hash`].
    pub tip_hash: [u8; 32],
    /// `pruneheight` when `pruned == true`, otherwise 0. The lowest height
    /// whose block body the node still stores.
    pub retained_from: BlockHeight,
}

impl NodeBounds {
    /// Whether the node can serve block `height`'s body (and tree state).
    pub fn retains(&self, height: BlockHeight) -> bool {
        height >= self.retained_from && height <= self.tip_height
    }
}

/// The last thing the node told us, for `GetInfo.node` (API.md) and the
/// scheduler's `Stalled(Offline)` decision. Refreshed by every successful or
/// failed [`ChainBackend::node_bounds`] call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeStatus {
    /// The last poll succeeded.
    pub connected: bool,
    /// Bounds from the last successful poll, kept while disconnected.
    pub bounds: Option<NodeBounds>,
    /// `getblockchaininfo.pruned`.
    pub pruned: bool,
    /// Error from the last poll, empty when healthy.
    pub last_error: String,
    /// When the last poll finished, successful or not.
    pub last_polled: Option<SystemTime>,
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
    /// `z_gettreestate` below `pruneheight`.
    #[error(
        "tree state at height {height} is not available from the node (retained from {retained_from})"
    )]
    TreeStateUnavailable {
        height: BlockHeight,
        retained_from: BlockHeight,
    },
    /// `getblock(h, 0)` for a height whose body the node no longer stores
    /// (or does not have yet). The caller re-polls the bounds (SYNC.md §1).
    #[error("block {height} is not available from the node (pruned or above the tip)")]
    BlockUnavailable { height: BlockHeight },
    /// The node returned an error or an unparseable response.
    #[error("node error: {0}")]
    Rpc(String),
    /// `sendrawtransaction` refused the transaction; the text is the node's
    /// verbatim rejection (`GygesError.node_error`, API.md §3).
    #[error("node rejected the transaction: {0}")]
    Rejected(String),
}

/// A boxed future, for the object-safe async methods below.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The node-facing operations `gygesd` needs.
///
/// Implemented by [`ZakuraRpcBackend`] and by test fakes. Scanning itself
/// goes through `zcash_client_backend`'s `BlockSource` / `BlockCache` over
/// the shared [`BlockDb`]; this trait is how the cache gets filled.
pub trait ChainBackend: Send + Sync + fmt::Debug {
    /// `getblockchaininfo`, reduced to what the scheduler needs. Also
    /// refreshes [`ChainBackend::status`].
    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>>;

    /// The cached outcome of the last [`ChainBackend::node_bounds`] call;
    /// never touches the network.
    fn status(&self) -> NodeStatus;

    /// The note commitment tree frontiers and block hash as of the end of
    /// block `height` (`z_gettreestate(height)`), used as the prior chain
    /// state of an account born at `height + 1`. A pruned node can only
    /// answer for `height >= retained_from`; below that it returns
    /// [`ChainError::TreeStateUnavailable`].
    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>>;

    /// `getblockhash(height)`, in internal byte order. Works at every height
    /// a node has headers for, pruned or not (SYNC.md §1).
    fn block_hash(&self, height: BlockHeight) -> BoxFuture<'_, Result<[u8; 32], ChainError>>;

    /// Synthetic compact blocks for `range` (ascending, contiguous, linked by
    /// `prev_hash`), built from `getblock(h, 0)`. The caller bounds the
    /// range to `cache.fetch_batch`. [`ChainError::BlockUnavailable`] for a
    /// height the node has pruned or does not have yet.
    fn compact_blocks(
        &self,
        range: Range<BlockHeight>,
    ) -> BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>>;

    /// `sendrawtransaction(hex)`: hand a signed transaction to the node's
    /// mempool. Returns the txid in internal byte order. A node that
    /// accepts the connection but refuses the transaction answers
    /// [`ChainError::Rejected`] with its own text, which `tx send` shows
    /// verbatim as `NODE_REJECTED`.
    fn send_raw_transaction(&self, raw: Vec<u8>) -> BoxFuture<'_, Result<[u8; 32], ChainError>>;
}

/// Block and transaction hashes as the JSON-RPC and explorers print them:
/// byte-reversed hex.
pub fn display_hash(internal: &[u8]) -> String {
    let mut bytes = internal.to_vec();
    bytes.reverse();
    hex::encode(bytes)
}

/// The inverse of [`display_hash`]: a 64-character hex string in display
/// order to 32 internal-order bytes.
pub fn parse_display_hash(hex_str: &str) -> Result<[u8; 32], ChainError> {
    let mut bytes = hex::decode(hex_str.trim())
        .map_err(|e| ChainError::Rpc(format!("hash is not hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ChainError::Rpc(format!(
            "hash has {} bytes, expected 32",
            bytes.len()
        )));
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hash_round_trips_and_rejects_bad_lengths() {
        let internal: [u8; 32] = core::array::from_fn(|i| i as u8);
        let shown = display_hash(&internal);
        assert!(shown.starts_with("1f1e1d"), "{shown}");
        assert_eq!(parse_display_hash(&shown).unwrap(), internal);
        assert!(parse_display_hash("abcd").is_err());
        assert!(parse_display_hash("zz").is_err());
    }

    #[test]
    fn bounds_retention_window_is_inclusive() {
        let b = NodeBounds {
            tip_height: BlockHeight::from_u32(100),
            tip_hash: [0; 32],
            retained_from: BlockHeight::from_u32(50),
        };
        assert!(b.retains(BlockHeight::from_u32(50)));
        assert!(b.retains(BlockHeight::from_u32(100)));
        assert!(!b.retains(BlockHeight::from_u32(49)));
        assert!(!b.retains(BlockHeight::from_u32(101)));
    }
}
