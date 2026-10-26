//! Handoff validation for the Case B backfill (SYNC.md §5.2).
//!
//! Blocks below the node's retention window come from an untrusted
//! lightwalletd / zaino endpoint. Before the scheduler hands a key back to
//! the node (Case A), what the wallet built from those blocks is compared
//! with what the local node says:
//!
//! 1. [`check_trees`]: the wallet's note commitment tree size and root at the
//!    handoff height `V` equal the frontiers of `z_gettreestate(V)`. The root
//!    covers every leaf before `V`, including the birthday frontier the
//!    endpoint supplied for a restore, so omitted, injected or reordered
//!    commitments anywhere in the backfill show up here.
//! 2. Hash chain: the scheduler compares the hashes the wallet recorded with
//!    `getblockhash` (the node keeps headers at every height); see
//!    `gygesd::sync`.
//! 3. [`agreed_subtree_roots`]: every subtree root the endpoint serves equals
//!    the node's for the same index, before any is handed to the wallet.
//!
//! These functions run under the key's wallet lock and do no I/O beyond the
//! wallet; the node and endpoint calls are the scheduler's.

use std::fmt;

use gyges_chain::SubtreeRoot;
use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::{Address, Hashable, Level, Position};
use shardtree::error::ShardTreeError;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::{WalletCommitmentTrees, WalletRead as _};
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;

use crate::registry::Wallet;
use crate::sync::SyncError;

/// Which of the three checks of SYNC.md §5.2 failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Check 1: note commitment tree size or root at `V`.
    TreeRoots,
    /// Check 2: a block hash differs from the node's.
    HashChain,
    /// Check 3: a subtree root differs from the node's.
    SubtreeRoots,
}

impl Check {
    pub const fn name(self) -> &'static str {
        match self {
            Check::TreeRoots => "tree-roots",
            Check::HashChain => "hash-chain",
            Check::SubtreeRoots => "subtree-roots",
        }
    }
}

/// A failed check, with the two values for the log and `daemon status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub check: Check,
    pub detail: String,
}

impl Mismatch {
    pub fn new(check: Check, detail: impl Into<String>) -> Self {
        Self {
            check,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} check failed: {}", self.check.name(), self.detail)
    }
}

/// Check 3: the endpoint's subtree roots that the node confirms, in the
/// order given. A root (or completing height) that differs from the node's
/// for the same pool and index is a [`Mismatch`]; a root the node does not
/// report (its index is still being built, or the node is behind) is left
/// out, together with every later index of that pool, so that what reaches
/// the wallet stays a contiguous, node-confirmed run.
pub fn agreed_subtree_roots(
    fallback: &[SubtreeRoot],
    node: &[SubtreeRoot],
) -> Result<Vec<SubtreeRoot>, Mismatch> {
    let mut agreed = Vec::new();
    let mut cut: Vec<ShieldedPool> = Vec::new();
    for fb in fallback {
        if cut.contains(&fb.pool) {
            continue;
        }
        let Some(n) = node
            .iter()
            .find(|n| n.pool == fb.pool && n.index == fb.index)
        else {
            cut.push(fb.pool);
            continue;
        };
        if n.root != fb.root || n.end_height != fb.end_height {
            return Err(Mismatch::new(
                Check::SubtreeRoots,
                format!(
                    "{} subtree {}: endpoint has root {} completed at {}, node has {} completed at {}",
                    gyges_chain::pool_name(fb.pool),
                    fb.index,
                    hex::encode(fb.root),
                    u32::from(fb.end_height),
                    hex::encode(n.root),
                    u32::from(n.end_height),
                ),
            ));
        }
        agreed.push(fb.clone());
    }
    Ok(agreed)
}

/// Hand node-confirmed subtree roots to the wallet
/// (`put_{sapling,orchard,ironwood}_subtree_roots`), one contiguous run per
/// pool starting at its first index.
pub fn put_subtree_roots(wallet: &mut Wallet, roots: &[SubtreeRoot]) -> Result<(), SyncError> {
    let err = |e: ShardTreeError<_>| SyncError::Wallet(format!("put subtree roots: {e}"));
    for pool in [
        ShieldedPool::Sapling,
        ShieldedPool::Orchard,
        ShieldedPool::Ironwood,
    ] {
        let run: Vec<&SubtreeRoot> = roots.iter().filter(|r| r.pool == pool).collect();
        let Some(first) = run.first() else {
            continue;
        };
        let start = u64::from(first.index);
        match pool {
            ShieldedPool::Sapling => {
                let nodes: Vec<_> = run.iter().filter_map(|r| r.sapling()).collect();
                wallet
                    .put_sapling_subtree_roots(start, &nodes)
                    .map_err(err)?;
            }
            ShieldedPool::Orchard => {
                let nodes: Vec<_> = run.iter().filter_map(|r| r.orchard()).collect();
                wallet
                    .put_orchard_subtree_roots(start, &nodes)
                    .map_err(err)?;
            }
            ShieldedPool::Ironwood => {
                let nodes: Vec<_> = run.iter().filter_map(|r| r.orchard()).collect();
                wallet
                    .put_ironwood_subtree_roots(start, &nodes)
                    .map_err(err)?;
            }
        }
    }
    Ok(())
}

/// The wallet's own record of block `height`: hash (internal byte order),
/// or `None` if it has not scanned it.
pub fn wallet_hash(wallet: &Wallet, height: BlockHeight) -> Result<Option<[u8; 32]>, SyncError> {
    Ok(wallet
        .block_metadata(height)
        .map_err(crate::sync::wallet_err)?
        .map(|m| m.block_hash().0))
}

/// Check 1 at `height`: for each pool, the tree size the wallet recorded
/// for the block equals the node's frontier size, and the wallet's
/// ShardTree root over that many leaves equals the frontier's root.
/// `Ok(Err(_))` is a failed check; `Err(_)` a wallet failure to retry.
pub fn check_trees(
    wallet: &mut Wallet,
    height: BlockHeight,
    node: &ChainState,
) -> Result<Result<(), Mismatch>, SyncError> {
    let Some(meta) = wallet
        .block_metadata(height)
        .map_err(crate::sync::wallet_err)?
    else {
        return Ok(Err(Mismatch::new(
            Check::TreeRoots,
            format!("the wallet has no record of block {}", u32::from(height)),
        )));
    };

    let size = |s: Option<u32>| u64::from(s.unwrap_or(0));
    let sapling = compare_pool(
        ShieldedPool::Sapling,
        size(meta.sapling_tree_size()),
        node.final_sapling_tree(),
        |pos| {
            wallet.with_sapling_tree_mut(|t| {
                t.root(Address::from_parts(Level::from(32), 0), pos)
                    .map(|n| n.to_bytes())
            })
        },
        |n: &sapling::Node| n.to_bytes(),
    );
    if let Err(m) = sapling {
        return Ok(Err(m));
    }
    let orchard = compare_pool(
        ShieldedPool::Orchard,
        size(meta.orchard_tree_size()),
        node.final_orchard_tree(),
        |pos| {
            wallet.with_orchard_tree_mut(|t| {
                t.root(Address::from_parts(Level::from(32), 0), pos)
                    .map(|n| n.to_bytes())
            })
        },
        orchard::tree::MerkleHashOrchard::to_bytes,
    );
    if let Err(m) = orchard {
        return Ok(Err(m));
    }
    // A wallet without an Ironwood tree (`with_ironwood_tree_mut` answers
    // `None`) has nothing to compare.
    let mut has_ironwood = true;
    let ironwood = compare_pool(
        ShieldedPool::Ironwood,
        size(meta.ironwood_tree_size()),
        node.final_ironwood_tree(),
        |pos| match wallet.with_ironwood_tree_mut(|t| {
            t.root(Address::from_parts(Level::from(32), 0), pos)
                .map(|n| n.to_bytes())
        })? {
            Some(root) => Ok(root),
            None => {
                has_ironwood = false;
                Ok(orchard::tree::MerkleHashOrchard::empty_root(Level::from(32)).to_bytes())
            }
        },
        orchard::tree::MerkleHashOrchard::to_bytes,
    );
    if has_ironwood && let Err(m) = ironwood {
        return Ok(Err(m));
    }
    Ok(Ok(()))
}

type RootResult<E> = Result<[u8; 32], ShardTreeError<E>>;

fn compare_pool<H, E: fmt::Display, const D: u8>(
    pool: ShieldedPool,
    wallet_size: u64,
    node: &Frontier<H, D>,
    wallet_root: impl FnOnce(Position) -> RootResult<E>,
    bytes: impl Fn(&H) -> [u8; 32],
) -> Result<(), Mismatch>
where
    H: Hashable + Clone,
{
    let name = gyges_chain::pool_name(pool);
    let node_size = node.tree_size();
    if wallet_size != node_size {
        return Err(Mismatch::new(
            Check::TreeRoots,
            format!(
                "{name} tree has {wallet_size} leaves from the backfill, the node has {node_size}"
            ),
        ));
    }
    if node_size == 0 {
        return Ok(());
    }
    let node_root = bytes(&node.root());
    let wallet_root = wallet_root(Position::from(node_size)).map_err(|e| {
        Mismatch::new(
            Check::TreeRoots,
            format!("{name} tree root cannot be computed from the backfill: {e}"),
        )
    })?;
    if wallet_root != node_root {
        return Err(Mismatch::new(
            Check::TreeRoots,
            format!(
                "{name} tree root from the backfill is {}, the node's is {}",
                hex::encode(wallet_root),
                hex::encode(node_root)
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(pool: ShieldedPool, index: u32, byte: u8, end: u32) -> SubtreeRoot {
        SubtreeRoot {
            pool,
            index,
            root: [byte; 32],
            end_height: BlockHeight::from_u32(end),
            end_hash: None,
        }
    }

    #[test]
    fn subtree_roots_must_agree_and_stop_where_the_node_stops() {
        use ShieldedPool::{Orchard, Sapling};
        let fb = vec![
            root(Sapling, 0, 1, 10),
            root(Sapling, 1, 2, 20),
            root(Orchard, 0, 3, 15),
        ];
        // The node knows Sapling 0 and Orchard 0 only: Sapling 1 is left out.
        let node = vec![root(Sapling, 0, 1, 10), root(Orchard, 0, 3, 15)];
        let agreed = agreed_subtree_roots(&fb, &node).unwrap();
        assert_eq!(agreed, vec![fb[0].clone(), fb[2].clone()]);
        // A different root, or a different completing height, is refused.
        let node = vec![root(Sapling, 0, 9, 10)];
        let m = agreed_subtree_roots(&fb, &node).unwrap_err();
        assert_eq!(m.check, Check::SubtreeRoots);
        assert!(
            m.to_string()
                .starts_with("subtree-roots check failed: sapling subtree 0")
        );
        let node = vec![root(Sapling, 0, 1, 11)];
        assert!(agreed_subtree_roots(&fb, &node).is_err());
        assert!(agreed_subtree_roots(&[], &node).unwrap().is_empty());
    }
}
