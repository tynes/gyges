//! The shared compact block cache, `cache/blocks.sqlite` (DATA_MODEL.md §6,
//! SYNC.md §2.2, OVERVIEW.md Q-Y3).
//!
//! One file per network, shared by every key, so the node is asked for each
//! block once however many profiles exist. It implements the upstream
//! `BlockSource` (what `scan_cached_blocks` reads) and `BlockCache` (what
//! the fetcher writes and the reorg handler truncates). The cache is
//! disposable: deleting it costs a refetch, never wallet state.
//!
//! Rows fetched over Tor (`source = 'tor-lwd'`) reveal an approximate
//! birthday, so the file is `0600` and [`BlockDb::evict_source_below`] lets
//! the scheduler drop them once scanned (`cache.keep_historical = false`).

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use prost::Message as _;
use rusqlite::{Connection, OptionalExtension as _, params};
use zcash_client_backend::data_api::chain::error::Error as ChainScanError;
use zcash_client_backend::data_api::chain::{BlockCache, BlockSource};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::BlockHeight;

/// Schema this build writes; an older file is upgraded in place, a newer one
/// is refused (DATA_MODEL.md §7).
pub const SCHEMA_VERSION: u32 = 1;

/// Where a cached block came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The local `zakurad` (Case A).
    Node,
    /// The archival lightwalletd over Tor (Case B).
    TorLwd,
}

impl Source {
    /// The `source` column value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Node => "node",
            Source::TorLwd => "tor-lwd",
        }
    }
}

/// Why the cache could not be opened or served a request.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("block cache {path}: {source}", path = .path.display())]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("block cache {path}: cannot set permissions: {source}", path = .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("block cache {path}: cached block {height} does not decode: {source}", path = .path.display())]
    Decode {
        path: PathBuf,
        height: u32,
        #[source]
        source: prost::DecodeError,
    },
    #[error(
        "block cache {path} belongs to {found}, not {expected}; delete it (it is only a cache)",
        path = .path.display()
    )]
    NetworkMismatch {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error(
        "block cache {path} has schema version {found}, newer than this daemon's {}; delete it or upgrade",
        SCHEMA_VERSION, path = .path.display()
    )]
    SchemaTooNew { path: PathBuf, found: u32 },
    /// `BlockCache::read` found a hole where contiguous blocks were required.
    #[error(
        "block cache is missing block {missing} inside the requested range starting at {start}"
    )]
    Gap { start: u32, missing: u32 },
}

/// The open cache. Every method takes `&self`; the connection sits behind a
/// mutex because compact-block reads and writes are short.
pub struct BlockDb {
    path: PathBuf,
    conn: Mutex<Connection>,
}

impl fmt::Debug for BlockDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockDb").field("path", &self.path).finish()
    }
}

impl BlockDb {
    /// Open or create the cache at `path` for `network` (the `Network`
    /// name: `mainnet`, `testnet`, `regtest`). WAL journal, `0600`.
    pub fn open(path: &Path, network: &str) -> Result<Self, CacheError> {
        let conn = Connection::open(path).map_err(|source| CacheError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
        // The daemon's umask makes this a no-op; tools without it still get
        // a private file (DATA_MODEL.md §1).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |source| CacheError::Io {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
        let db = Self {
            path: path.to_path_buf(),
            conn: Mutex::new(conn),
        };
        db.init(network)?;
        Ok(db)
    }

    /// An in-memory cache, for tests.
    pub fn in_memory(network: &str) -> Result<Self, CacheError> {
        let path = PathBuf::from(":memory:");
        let conn = Connection::open_in_memory().map_err(|source| CacheError::Sqlite {
            path: path.clone(),
            source,
        })?;
        let db = Self {
            path,
            conn: Mutex::new(conn),
        };
        db.init(network)?;
        Ok(db)
    }

    fn init(&self, network: &str) -> Result<(), CacheError> {
        let conn = self.lock();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS compact_blocks (
                 height     INTEGER NOT NULL PRIMARY KEY,
                 hash       BLOB NOT NULL,
                 prev_hash  BLOB NOT NULL,
                 source     TEXT NOT NULL CHECK (source IN ('node', 'tor-lwd')),
                 data       BLOB NOT NULL,
                 fetched_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS cache_meta (
                 key   TEXT NOT NULL PRIMARY KEY,
                 value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO cache_meta (key, value) VALUES ('schema_version', '1');",
        )
        .map_err(|e| self.sqlite(e))?;
        conn.execute(
            "INSERT OR IGNORE INTO cache_meta (key, value) VALUES ('network', ?1)",
            params![network],
        )
        .map_err(|e| self.sqlite(e))?;

        let found_network: String = conn
            .query_row(
                "SELECT value FROM cache_meta WHERE key = 'network'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| self.sqlite(e))?;
        if found_network != network {
            return Err(CacheError::NetworkMismatch {
                path: self.path.clone(),
                expected: network.to_string(),
                found: found_network,
            });
        }
        let version: String = conn
            .query_row(
                "SELECT value FROM cache_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| self.sqlite(e))?;
        let version: u32 = version.parse().unwrap_or(u32::MAX);
        if version > SCHEMA_VERSION {
            return Err(CacheError::SchemaTooNew {
                path: self.path.clone(),
                found: version,
            });
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A poisoned lock is recovered: SQLite has its own transactions.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sqlite(&self, source: rusqlite::Error) -> CacheError {
        CacheError::Sqlite {
            path: self.path.clone(),
            source,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Insert (or replace) blocks tagged with where they came from. The
    /// `BlockCache::insert` trait method is this with [`Source::Node`].
    pub fn insert_from(&self, source: Source, blocks: &[CompactBlock]) -> Result<(), CacheError> {
        if blocks.is_empty() {
            return Ok(());
        }
        let now = unix_now();
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|e| self.sqlite(e))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO compact_blocks
                         (height, hash, prev_hash, source, data, fetched_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| self.sqlite(e))?;
            for block in blocks {
                stmt.execute(params![
                    block.height,
                    block.hash,
                    block.prev_hash,
                    source.as_str(),
                    block.encode_to_vec(),
                    now,
                ])
                .map_err(|e| self.sqlite(e))?;
            }
        }
        tx.commit().map_err(|e| self.sqlite(e))
    }

    /// The cached hash at `height` (internal byte order), for the per-tick
    /// reorg check against `getblockhash` (SYNC.md §4.3).
    pub fn hash_at(&self, height: BlockHeight) -> Result<Option<[u8; 32]>, CacheError> {
        let conn = self.lock();
        let hash: Option<Vec<u8>> = conn
            .query_row(
                "SELECT hash FROM compact_blocks WHERE height = ?1",
                params![u32::from(height)],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| self.sqlite(e))?;
        Ok(hash.map(|h| crate::compact::to_array(&h)))
    }

    /// Lowest and highest cached heights, `None` when empty.
    pub fn bounds(&self) -> Result<Option<(BlockHeight, BlockHeight)>, CacheError> {
        let conn = self.lock();
        let row: (Option<u32>, Option<u32>) = conn
            .query_row(
                "SELECT MIN(height), MAX(height) FROM compact_blocks",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| self.sqlite(e))?;
        Ok(match row {
            (Some(lo), Some(hi)) => Some((BlockHeight::from_u32(lo), BlockHeight::from_u32(hi))),
            _ => None,
        })
    }

    /// Number of cached blocks.
    pub fn len(&self) -> Result<u64, CacheError> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM compact_blocks", [], |r| r.get(0))
            .map_err(|e| self.sqlite(e))
    }

    pub fn is_empty(&self) -> Result<bool, CacheError> {
        Ok(self.len()? == 0)
    }

    /// Delete every block below `height` (eviction behind the slowest key,
    /// SYNC.md §2.2). Returns how many rows went.
    pub fn evict_below(&self, height: BlockHeight) -> Result<usize, CacheError> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM compact_blocks WHERE height < ?1",
            params![u32::from(height)],
        )
        .map_err(|e| self.sqlite(e))
    }

    /// Delete blocks from `source` below `height`: how Tor-fetched ranges are
    /// dropped once the key that needed them has scanned them.
    pub fn evict_source_below(
        &self,
        source: Source,
        height: BlockHeight,
    ) -> Result<usize, CacheError> {
        let conn = self.lock();
        conn.execute(
            "DELETE FROM compact_blocks WHERE source = ?1 AND height < ?2",
            params![source.as_str(), u32::from(height)],
        )
        .map_err(|e| self.sqlite(e))
    }

    /// Size of the database file as SQLite accounts it (pages × page size),
    /// for the `cache.max_mb` bound.
    pub fn size_bytes(&self) -> Result<u64, CacheError> {
        let conn = self.lock();
        let pages: u64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(|e| self.sqlite(e))?;
        let page_size: u64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| self.sqlite(e))?;
        Ok(pages * page_size)
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)`, run on daemon stop (SYNC.md §8).
    pub fn checkpoint(&self) -> Result<(), CacheError> {
        let conn = self.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| self.sqlite(e))
    }

    /// Decoded blocks in `[from, from + limit)` order, stopping at the first
    /// missing height. `from = None` starts at the lowest cached block.
    fn contiguous_from(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
    ) -> Result<Vec<CompactBlock>, CacheError> {
        let conn = self.lock();
        let start = match from {
            Some(h) => u32::from(h),
            None => {
                let lo: Option<u32> = conn
                    .query_row("SELECT MIN(height) FROM compact_blocks", [], |r| r.get(0))
                    .map_err(|e| self.sqlite(e))?;
                match lo {
                    Some(lo) => lo,
                    None => return Ok(Vec::new()),
                }
            }
        };
        let limit = limit.map_or(i64::MAX, |l| i64::try_from(l).unwrap_or(i64::MAX));
        let mut stmt = conn
            .prepare_cached(
                "SELECT height, data FROM compact_blocks WHERE height >= ?1 ORDER BY height LIMIT ?2",
            )
            .map_err(|e| self.sqlite(e))?;
        let rows = stmt
            .query_map(params![start, limit], |r| {
                Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| self.sqlite(e))?;
        let mut out = Vec::new();
        let mut expected = start;
        for row in rows {
            let (height, data) = row.map_err(|e| self.sqlite(e))?;
            if height != expected {
                break;
            }
            let block = CompactBlock::decode(&data[..]).map_err(|source| CacheError::Decode {
                path: self.path.clone(),
                height,
                source,
            })?;
            out.push(block);
            expected = height.wrapping_add(1);
        }
        Ok(out)
    }
}

impl BlockSource for BlockDb {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainScanError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainScanError<WalletErrT, Self::Error>>,
    {
        let blocks = self
            .contiguous_from(from_height, limit)
            .map_err(ChainScanError::BlockSource)?;
        for block in blocks {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for BlockDb {
    fn get_tip_height(&self, range: Option<&ScanRange>) -> Result<Option<BlockHeight>, CacheError> {
        let conn = self.lock();
        let max: Option<u32> = match range {
            None => conn
                .query_row("SELECT MAX(height) FROM compact_blocks", [], |r| r.get(0))
                .map_err(|e| self.sqlite(e))?,
            Some(range) => {
                let Range { start, end } = range.block_range().clone();
                conn.query_row(
                    "SELECT MAX(height) FROM compact_blocks WHERE height >= ?1 AND height < ?2",
                    params![u32::from(start), u32::from(end)],
                    |r| r.get(0),
                )
                .map_err(|e| self.sqlite(e))?
            }
        };
        Ok(max.map(BlockHeight::from_u32))
    }

    /// Contiguous blocks from `range.start`; a short read is allowed, a hole
    /// after the first block is an error as the trait requires.
    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, CacheError> {
        let Range { start, end } = range.block_range().clone();
        if end <= start {
            return Ok(Vec::new());
        }
        let wanted = usize::try_from(u32::from(end) - u32::from(start)).unwrap_or(usize::MAX);
        let blocks = self.contiguous_from(Some(start), Some(wanted))?;
        if !blocks.is_empty() && blocks.len() < wanted {
            // Something exists after the gap? Then it is a hole, not the end.
            let next_missing = u32::from(start) + blocks.len() as u32;
            let conn = self.lock();
            let later: Option<u32> = conn
                .query_row(
                    "SELECT MIN(height) FROM compact_blocks WHERE height > ?1 AND height < ?2",
                    params![next_missing, u32::from(end)],
                    |r| r.get(0),
                )
                .map_err(|e| self.sqlite(e))?;
            if later.is_some() {
                return Err(CacheError::Gap {
                    start: u32::from(start),
                    missing: next_missing,
                });
            }
        }
        Ok(blocks)
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), CacheError> {
        self.insert_from(Source::Node, &compact_blocks)
    }

    async fn delete(&self, range: ScanRange) -> Result<(), CacheError> {
        let Range { start, end } = range.block_range().clone();
        let conn = self.lock();
        conn.execute(
            "DELETE FROM compact_blocks WHERE height >= ?1 AND height < ?2",
            params![u32::from(start), u32::from(end)],
        )
        .map_err(|e| self.sqlite(e))?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::scanning::ScanPriority;

    fn block(height: u32) -> CompactBlock {
        CompactBlock {
            height: u64::from(height),
            hash: vec![height as u8; 32],
            prev_hash: vec![height.wrapping_sub(1) as u8; 32],
            time: 1,
            ..Default::default()
        }
    }

    fn range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::Historic,
        )
    }

    #[tokio::test]
    async fn insert_read_tip_delete_and_truncate() {
        let db = BlockDb::in_memory("regtest").unwrap();
        assert!(db.is_empty().unwrap());
        assert_eq!(db.get_tip_height(None).unwrap(), None);
        assert!(db.read(&range(1, 5)).await.unwrap().is_empty());

        db.insert((1..=10).map(block).collect()).await.unwrap();
        assert_eq!(db.len().unwrap(), 10);
        assert_eq!(
            db.get_tip_height(None).unwrap(),
            Some(BlockHeight::from_u32(10))
        );
        assert_eq!(
            db.get_tip_height(Some(&range(3, 7))).unwrap(),
            Some(BlockHeight::from_u32(6))
        );
        assert_eq!(
            db.bounds().unwrap(),
            Some((BlockHeight::from_u32(1), BlockHeight::from_u32(10)))
        );
        assert_eq!(db.hash_at(BlockHeight::from_u32(4)).unwrap(), Some([4; 32]));
        assert_eq!(db.hash_at(BlockHeight::from_u32(40)).unwrap(), None);

        let read = db.read(&range(3, 6)).await.unwrap();
        assert_eq!(
            read.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        // Short read past the tip is fine.
        let read = db.read(&range(8, 20)).await.unwrap();
        assert_eq!(read.len(), 3);

        // A hole inside the range is an error.
        db.delete(range(5, 6)).await.unwrap();
        let err = db.read(&range(3, 8)).await.unwrap_err();
        assert!(
            matches!(
                err,
                CacheError::Gap {
                    start: 3,
                    missing: 5
                }
            ),
            "{err}"
        );
        // But reading up to the hole is a short read, not an error.
        assert_eq!(db.read(&range(3, 5)).await.unwrap().len(), 2);

        db.truncate(BlockHeight::from_u32(7)).await.unwrap();
        assert_eq!(
            db.get_tip_height(None).unwrap(),
            Some(BlockHeight::from_u32(7))
        );
        assert_eq!(db.evict_below(BlockHeight::from_u32(3)).unwrap(), 2);
        assert_eq!(
            db.bounds().unwrap(),
            Some((BlockHeight::from_u32(3), BlockHeight::from_u32(7)))
        );
    }

    #[test]
    fn block_source_iterates_contiguously_and_honours_limit() {
        let db = BlockDb::in_memory("regtest").unwrap();
        db.insert_from(Source::Node, &[block(1), block(2), block(3), block(5)])
            .unwrap();
        let mut seen = Vec::new();
        db.with_blocks::<_, ()>(None, None, |b| {
            seen.push(b.height);
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![1, 2, 3], "stops at the hole");
        let mut seen = Vec::new();
        db.with_blocks::<_, ()>(Some(BlockHeight::from_u32(2)), Some(1), |b| {
            seen.push(b.height);
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![2]);
    }

    #[test]
    fn sources_are_tagged_and_evicted_separately() {
        let db = BlockDb::in_memory("regtest").unwrap();
        db.insert_from(Source::TorLwd, &[block(1), block(2)])
            .unwrap();
        db.insert_from(Source::Node, &[block(3), block(4)]).unwrap();
        assert_eq!(
            db.evict_source_below(Source::TorLwd, BlockHeight::from_u32(10))
                .unwrap(),
            2
        );
        assert_eq!(db.len().unwrap(), 2);
        // Re-inserting a height replaces the row.
        db.insert_from(Source::Node, &[block(3)]).unwrap();
        assert_eq!(db.len().unwrap(), 2);
    }

    #[test]
    fn file_is_private_and_network_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.sqlite");
        {
            let db = BlockDb::open(&path, "regtest").unwrap();
            db.insert_from(Source::Node, &[block(1)]).unwrap();
            db.checkpoint().unwrap();
            assert!(db.size_bytes().unwrap() > 0);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:o}");
        }
        // Reopening keeps the data; the wrong network is refused.
        let db = BlockDb::open(&path, "regtest").unwrap();
        assert_eq!(db.len().unwrap(), 1);
        drop(db);
        let err = BlockDb::open(&path, "mainnet").unwrap_err();
        assert!(matches!(err, CacheError::NetworkMismatch { .. }), "{err}");
        // A newer schema is refused too.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE cache_meta SET value = '99' WHERE key = 'schema_version'",
                [],
            )
            .unwrap();
        }
        let err = BlockDb::open(&path, "regtest").unwrap_err();
        assert!(
            matches!(err, CacheError::SchemaTooNew { found: 99, .. }),
            "{err}"
        );
    }
}
