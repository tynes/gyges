//! Turning a birthday height into the `AccountBirthday` the wallet database
//! needs (SYNC.md §"New or restored key", DATA_MODEL.md §3 defaults).
//!
//! An account born at height `h` needs the note commitment tree state as of
//! the end of block `h - 1`. Below Sapling activation both trees are empty,
//! so no node is needed; above it the local node's `z_gettreestate` is the
//! only source in this milestone, and a pruned node can answer only for
//! `h - 1 >= retained_from`. Below that, [`resolve_from_fallback`] takes the
//! tree state from the fallback endpoint instead, and the Case B backfill
//! validates it at the handoff (SYNC.md §5).

use gyges_chain::{ChainBackend, ChainError};
use zcash_client_backend::data_api::AccountBirthday;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::network::Network;

/// A birthday height together with the chain state the wallet is seeded with.
#[derive(Clone, Debug)]
pub struct ResolvedBirthday {
    pub height: u32,
    pub birthday: AccountBirthday,
}

/// Why a birthday could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum BirthdayError {
    /// The requested height needs the node's tree state and no node backend
    /// is connected.
    #[error("a connected node is required to {0}")]
    NodeRequired(&'static str),
    #[error("birthday {height} is above the node's tip {tip}")]
    AboveTip { height: u32, tip: u32 },
    /// `height - 1 < retained_from`: the node has pruned the tree state the
    /// account would start from.
    #[error(
        "birthday {height} is below the node's retention window (retained from {retained_from}); \
         a historical restore over Tor is needed"
    )]
    BelowRetention { height: u32, retained_from: u32 },
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The fallback endpoint could not serve the tree state.
    #[error("fallback endpoint: {0}")]
    Fallback(ChainError),
    /// The fallback endpoint's tree state is for a block the node does not
    /// have at that height.
    #[error(
        "the fallback endpoint's tree state at {height} is for block {endpoint_hash}, the node has {node_hash}"
    )]
    FallbackMismatch {
        height: u32,
        endpoint_hash: String,
        node_hash: String,
    },
}

/// Resolve `requested` (or, when `None`, the node's current tip) into a
/// birthday. The result is never below Sapling activation, because nothing
/// shielded can exist before it.
pub async fn resolve(
    network: Network,
    chain: Option<&dyn ChainBackend>,
    requested: Option<u32>,
) -> Result<ResolvedBirthday, BirthdayError> {
    let sapling = network.sapling_activation_height();
    let height = match requested {
        Some(h) => h,
        None => {
            let bounds = chain
                .ok_or(BirthdayError::NodeRequired(
                    "use the chain tip as the birthday; pass --birthday",
                ))?
                .node_bounds()
                .await?;
            u32::from(bounds.tip_height)
        }
    }
    .max(sapling);
    let prior = height - 1;

    if prior < sapling {
        // Empty trees by definition. The scanner only checks continuity
        // between blocks it has scanned itself, so the hash is informational;
        // take the real one when a node is at hand and zeros otherwise.
        let hash = match chain {
            Some(c) => c
                .block_hash(BlockHeight::from_u32(prior))
                .await
                .map(BlockHash)
                .unwrap_or(BlockHash([0; 32])),
            None => BlockHash([0; 32]),
        };
        let state = ChainState::empty(BlockHeight::from_u32(prior), hash);
        return Ok(ResolvedBirthday {
            height,
            birthday: AccountBirthday::from_parts(state, None),
        });
    }

    let chain = chain.ok_or(BirthdayError::NodeRequired(
        "fetch the tree state at the birthday",
    ))?;
    let bounds = chain.node_bounds().await?;
    let tip = u32::from(bounds.tip_height);
    if height > tip + 1 {
        return Err(BirthdayError::AboveTip { height, tip });
    }
    let retained_from = u32::from(bounds.retained_from);
    if prior < retained_from {
        return Err(BirthdayError::BelowRetention {
            height,
            retained_from,
        });
    }
    let state = chain.chain_state(BlockHeight::from_u32(prior)).await?;
    Ok(ResolvedBirthday {
        height,
        birthday: AccountBirthday::from_parts(state, None),
    })
}

/// A birthday below the node's retention window (SYNC.md §9, "New or
/// restored key"): the tree state at `height - 1` comes from the fallback
/// endpoint's `GetTreeState`, and its block hash must equal the node's
/// `getblockhash(height - 1)` (the node keeps headers at every height). The
/// frontier itself cannot be checked against a pruned node here; the root
/// check at the handoff height covers it, since the root there commits to
/// every leaf before the birthday too (SYNC.md §5.2).
pub async fn resolve_from_fallback(
    chain: &dyn ChainBackend,
    fallback: &dyn ChainBackend,
    height: u32,
) -> Result<ResolvedBirthday, BirthdayError> {
    let prior = BlockHeight::from_u32(height.saturating_sub(1));
    let state = fallback
        .chain_state(prior)
        .await
        .map_err(BirthdayError::Fallback)?;
    let node_hash = chain.block_hash(prior).await?;
    if state.block_hash().0 != node_hash {
        return Err(BirthdayError::FallbackMismatch {
            height: u32::from(prior),
            endpoint_hash: gyges_chain::display_hash(&state.block_hash().0),
            node_hash: gyges_chain::display_hash(&node_hash),
        });
    }
    Ok(ResolvedBirthday {
        height,
        birthday: AccountBirthday::from_parts(state, None),
    })
}

/// A node that answers from a fixed tip and empty trees, for tests of the
/// code above `ChainBackend`.
#[derive(Clone, Debug)]
pub struct FixedChain {
    pub tip: u32,
    pub retained_from: u32,
}

impl FixedChain {
    fn bounds(&self) -> gyges_chain::NodeBounds {
        gyges_chain::NodeBounds {
            tip_height: BlockHeight::from_u32(self.tip),
            tip_hash: [0xaa; 32],
            retained_from: BlockHeight::from_u32(self.retained_from),
        }
    }
}

impl ChainBackend for FixedChain {
    fn route(&self) -> gyges_chain::Route {
        gyges_chain::Route::ZakuraRpc
    }

    fn subtree_roots(
        &self,
        _pool: zcash_protocol::ShieldedPool,
        _start_index: u32,
        _max_entries: u32,
    ) -> gyges_chain::BoxFuture<'_, Result<Vec<gyges_chain::SubtreeRoot>, ChainError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn node_bounds(
        &self,
    ) -> gyges_chain::BoxFuture<'_, Result<gyges_chain::NodeBounds, ChainError>> {
        Box::pin(async move { Ok(self.bounds()) })
    }

    fn status(&self) -> gyges_chain::NodeStatus {
        gyges_chain::NodeStatus {
            connected: true,
            bounds: Some(self.bounds()),
            pruned: self.retained_from > 0,
            last_error: String::new(),
            last_polled: Some(std::time::SystemTime::now()),
        }
    }

    fn block_hash(
        &self,
        height: BlockHeight,
    ) -> gyges_chain::BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(async move {
            if u32::from(height) > self.tip {
                return Err(ChainError::BlockUnavailable { height });
            }
            let mut hash = [0xaa; 32];
            hash[..4].copy_from_slice(&u32::from(height).to_le_bytes());
            Ok(hash)
        })
    }

    fn compact_blocks(
        &self,
        range: std::ops::Range<BlockHeight>,
    ) -> gyges_chain::BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for h in u32::from(range.start)..u32::from(range.end) {
                if h < self.retained_from || h > self.tip {
                    return Err(ChainError::BlockUnavailable {
                        height: BlockHeight::from_u32(h),
                    });
                }
                let hash = |x: u32| {
                    let mut b = [0xaa; 32];
                    b[..4].copy_from_slice(&x.to_le_bytes());
                    b.to_vec()
                };
                out.push(CompactBlock {
                    height: u64::from(h),
                    hash: hash(h),
                    prev_hash: hash(h.wrapping_sub(1)),
                    ..Default::default()
                });
            }
            Ok(out)
        })
    }

    fn transaction_status(
        &self,
        _txid: [u8; 32],
    ) -> gyges_chain::BoxFuture<'_, Result<gyges_chain::TxStatus, ChainError>> {
        Box::pin(async move { Ok(gyges_chain::TxStatus::Unknown) })
    }

    fn send_raw_transaction(
        &self,
        _raw: Vec<u8>,
    ) -> gyges_chain::BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(async move {
            Err(ChainError::Rejected(
                "the fixed test chain accepts no transactions".into(),
            ))
        })
    }

    fn chain_state(
        &self,
        height: BlockHeight,
    ) -> gyges_chain::BoxFuture<'_, Result<ChainState, ChainError>> {
        Box::pin(async move {
            if u32::from(height) < self.retained_from {
                return Err(ChainError::TreeStateUnavailable {
                    height,
                    retained_from: BlockHeight::from_u32(self.retained_from),
                });
            }
            Ok(ChainState::empty(height, BlockHash([0xbb; 32])))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pre_sapling_birthdays_need_no_node() {
        let r = resolve(Network::Mainnet, None, Some(419_200))
            .await
            .unwrap();
        assert_eq!(r.height, 419_200);
        assert_eq!(u32::from(r.birthday.height()), 419_200);
        // Anything lower is clamped up to Sapling activation.
        let r = resolve(Network::Mainnet, None, Some(5)).await.unwrap();
        assert_eq!(r.height, 419_200);
        // Regtest: Sapling at 1, prior state at 0.
        let r = resolve(Network::Regtest, None, Some(1)).await.unwrap();
        assert_eq!(r.height, 1);
    }

    #[tokio::test]
    async fn later_birthdays_need_the_node() {
        let err = resolve(Network::Mainnet, None, Some(2_000_000))
            .await
            .unwrap_err();
        assert!(matches!(err, BirthdayError::NodeRequired(_)), "{err}");
        let err = resolve(Network::Regtest, None, None).await.unwrap_err();
        assert!(matches!(err, BirthdayError::NodeRequired(_)), "{err}");
    }

    #[tokio::test]
    async fn node_backed_resolution_respects_tip_and_retention() {
        let chain = FixedChain {
            tip: 1000,
            retained_from: 800,
        };
        let r = resolve(Network::Regtest, Some(&chain), None).await.unwrap();
        assert_eq!(r.height, 1000);
        assert_eq!(u32::from(r.birthday.height()), 1000);

        let r = resolve(Network::Regtest, Some(&chain), Some(801))
            .await
            .unwrap();
        assert_eq!(r.height, 801);
        let err = resolve(Network::Regtest, Some(&chain), Some(800))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                BirthdayError::BelowRetention {
                    height: 800,
                    retained_from: 800
                }
            ),
            "{err}"
        );
        let err = resolve(Network::Regtest, Some(&chain), Some(1002))
            .await
            .unwrap_err();
        assert!(matches!(err, BirthdayError::AboveTip { .. }), "{err}");
        // tip + 1 is allowed: the account starts with the next block.
        resolve(Network::Regtest, Some(&chain), Some(1001))
            .await
            .unwrap();
    }
}
