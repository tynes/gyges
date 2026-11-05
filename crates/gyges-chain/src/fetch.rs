//! Filling the shared cache from a [`ChainBackend`] (docs/architecture.md Sync §2.2).
//!
//! Both routes go through the same loop: the range is fetched in
//! `cache.fetch_batch`-sized chunks, each chunk is checked to link to the
//! block the cache already holds below it, and the rows are tagged with
//! the backend's [`ChainBackend::source`]. Nothing of a chunk that does not link is
//! written, so a lying or forked endpoint leaves no trace in the cache.

use std::ops::Range;

use zcash_protocol::consensus::BlockHeight;

use crate::{BlockDb, CacheError, ChainBackend, ChainError, Source, display_hash};

/// Why [`fill_cache`] stopped.
#[derive(Debug, thiserror::Error)]
pub enum FillError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// The first block of a chunk does not link to the cached block below
    /// it: the two sources disagree on the chain (or the cache holds a
    /// reorged block). Nothing of the chunk was cached.
    #[error(
        "block {height} from {} (prev {got}) does not link to the cached block {} ({expected})",
        .from.as_str(),
        .height - 1
    )]
    Unlinked {
        from: Source,
        height: u32,
        expected: String,
        got: String,
    },
}

/// Fetch `range` from `chain` into `cache` in chunks of at most `batch`
/// blocks, tagged with `chain.source()`. Each chunk's first block
/// must link by `prev_hash` to the cached block at `start - 1` (when there
/// is one); the backend itself guarantees the chunk links internally.
/// Returns how many blocks were cached. A short answer from the backend
/// (above its tip) stops with [`ChainError::BlockUnavailable`].
pub async fn fill_cache(
    chain: &dyn ChainBackend,
    cache: &BlockDb,
    range: Range<BlockHeight>,
    batch: u32,
) -> Result<u32, FillError> {
    fill_cache_pipelined(chain, cache, range, batch, 1).await
}

/// [`fill_cache`] with up to `depth` chunks requested at once. Chunks are
/// still checked and stored one at a time, in order, so a chunk that does
/// not link stops the fill with nothing of it (or after it) written; the
/// requests for later chunks are dropped. A short chunk (the backend's tip
/// moved) ends the pipeline, and the rest of the range is asked for again
/// from where it stopped. The node route uses this so that the round trips
/// of one chunk overlap with the next instead of draining between them.
pub async fn fill_cache_pipelined(
    chain: &dyn ChainBackend,
    cache: &BlockDb,
    range: Range<BlockHeight>,
    batch: u32,
    depth: usize,
) -> Result<u32, FillError> {
    use futures_util::StreamExt as _;

    let source = chain.source();
    let batch = batch.max(1);
    let mut next = range.start;
    let mut cached = 0u32;
    while next < range.end {
        let mut chunks = Vec::new();
        let mut at = next;
        while at < range.end {
            let end = (at + batch).min(range.end);
            chunks.push(at..end);
            at = end;
        }
        let mut answers = futures_util::stream::iter(chunks)
            .map(|chunk| async move { (chunk.clone(), chain.compact_blocks(chunk).await) })
            .buffered(depth.max(1));
        let mut short = false;
        while let Some((chunk, blocks)) = answers.next().await {
            let blocks = blocks?;
            let Some(first) = blocks.first() else {
                return Err(ChainError::BlockUnavailable { height: next }.into());
            };
            if next > BlockHeight::from_u32(0)
                && let Some(prev) = cache.hash_at(next - 1)?
                && first.prev_hash != prev
            {
                return Err(FillError::Unlinked {
                    from: source,
                    height: u32::from(next),
                    expected: display_hash(&prev),
                    got: display_hash(&first.prev_hash),
                });
            }
            let fetched = blocks.len() as u32;
            cache.insert_from(source, &blocks)?;
            tracing::debug!(
                source = source.as_str(),
                from = u32::from(next),
                to = u32::from(next) + fetched - 1,
                "blocks cached"
            );
            cached += fetched;
            next = next + fetched;
            if next < chunk.end {
                short = true;
                break;
            }
        }
        if !short {
            break;
        }
    }
    Ok(cached)
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::chain::{BlockCache as _, BlockSource as _};
    use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};

    use super::*;
    use crate::ZakuraRpcBackend;
    use crate::testing::{FakeNode, h, regtest_params};

    /// Several chunks in flight cache the same blocks, in order, as one at
    /// a time, including when the range runs past the tip.
    #[tokio::test]
    async fn a_pipelined_fill_caches_the_same_blocks() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(25);
        let be = ZakuraRpcBackend::new(node.url(), None, regtest_params()).unwrap();
        let one = BlockDb::in_memory("regtest").unwrap();
        let many = BlockDb::in_memory("regtest").unwrap();
        assert_eq!(fill_cache(&be, &one, h(1)..h(21), 3).await.unwrap(), 20);
        assert_eq!(
            fill_cache_pipelined(&be, &many, h(1)..h(21), 3, 4)
                .await
                .unwrap(),
            20
        );
        let all = |db: &BlockDb| {
            let mut v = Vec::new();
            db.with_blocks::<_, ()>(Some(h(1)), None, |b| {
                v.push((b.height, b.hash));
                Ok(())
            })
            .unwrap();
            v
        };
        assert_eq!(all(&one), all(&many));
        let err = fill_cache_pipelined(&be, &many, h(21)..h(40), 3, 4)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FillError::Chain(ChainError::BlockUnavailable { .. })),
            "{err}"
        );
        // The backend refuses a chunk that runs past its tip as a whole, so
        // both fills stop after the last whole chunk below it.
        assert!(fill_cache(&be, &one, h(21)..h(40), 3).await.is_err());
        assert_eq!(all(&one), all(&many));
        assert_eq!(many.bounds().unwrap().map(|(_, hi)| hi), Some(h(23)));
    }

    #[tokio::test]
    async fn fills_in_chunks_tags_the_node_source_and_stops_at_the_tip() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(9);
        let be = ZakuraRpcBackend::new(node.url(), None, regtest_params()).unwrap();
        let cache = BlockDb::in_memory("regtest").unwrap();

        assert_eq!(fill_cache(&be, &cache, h(1)..h(8), 3).await.unwrap(), 7);
        assert_eq!(cache.len().unwrap(), 7);
        assert_eq!(cache.evict_source_below(Source::TorLwd, h(100)).unwrap(), 0);
        // Continues from what is cached, checking the link to block 7.
        assert_eq!(fill_cache(&be, &cache, h(8)..h(10), 3).await.unwrap(), 2);
        let all = cache
            .read(&ScanRange::from_parts(h(1)..h(10), ScanPriority::Historic))
            .await
            .unwrap();
        assert_eq!(all.len(), 9);
        // Past the tip: the first missing height.
        let err = fill_cache(&be, &cache, h(10)..h(12), 3).await.unwrap_err();
        assert!(
            matches!(err, FillError::Chain(ChainError::BlockUnavailable { height }) if height == h(10)),
            "{err}"
        );

        // The cache holds a block the node no longer has (a reorg): the
        // next chunk does not link and nothing is written.
        node.invalidate_from(9);
        node.mine(2);
        let err = fill_cache(&be, &cache, h(10)..h(11), 3).await.unwrap_err();
        assert!(
            matches!(
                &err,
                FillError::Unlinked {
                    from: Source::Node,
                    height: 10,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(cache.len().unwrap(), 9);
        assert!(fill_cache(&be, &cache, h(5)..h(5), 3).await.unwrap() == 0);
    }
}
