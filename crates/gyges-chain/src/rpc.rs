//! `ZakuraRpcBackend`: [`ChainBackend`] over the JSON-RPC of a local
//! `zakurad` (ARCHITECTURE.md §3.1 step 1, SYNC.md §1–2, OVERVIEW.md Q-D1,
//! Q-D2).
//!
//! Zakura's JSON-RPC is zcashd-style (Zebra-derived); the facts this module
//! relies on were read from `crates/zakura-rpc/src/methods.rs` and are
//! recorded in OVERVIEW.md §4.2:
//!
//! * `getblockchaininfo` has `blocks`, `bestblockhash`, `pruned` and, only
//!   when pruned, `pruneheight`;
//! * `getblock` takes the height as a *string*; verbosity 0 returns the raw
//!   block as hex, verbosity 1 an object with `hash`, `height`, `time`, the
//!   txids and `trees` (`{"sapling":{"size":N},"orchard":{"size":N}}`, each
//!   omitted when empty); a missing body answers `-8 Block not found`;
//! * `z_gettreestate` nests the frontier at `<pool>.commitments.finalState`
//!   and omits it for an inactive pool;
//! * block and transaction hashes are byte-reversed hex on the wire;
//! * the cookie file holds `__cookie__:<secret>` and is presented as HTTP
//!   Basic; the node regenerates it at every start, so it is re-read on
//!   every request rather than cached.

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

use crate::compact::{self, TreeSizes};
use crate::{
    BoxFuture, ChainBackend, ChainError, NodeBounds, NodeStatus, display_hash, parse_display_hash,
};

/// TCP connect bound; the node is local, so anything slower is "down".
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request bound; a 2 MB block as hex over loopback takes milliseconds.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Concurrent `getblock` pairs in flight inside one [`compact_blocks`]
/// call.
///
/// [`compact_blocks`]: ChainBackend::compact_blocks
pub const DEFAULT_CONCURRENCY: usize = 8;

/// JSON-RPC error code zcashd and Zebra use for "no such block".
const RPC_INVALID_PARAMETER: i64 = -8;

/// The node backend. Cheap to share behind an `Arc`.
pub struct ZakuraRpcBackend<P> {
    http: reqwest::Client,
    url: String,
    cookie_path: Option<PathBuf>,
    params: P,
    next_id: AtomicU64,
    status: RwLock<NodeStatus>,
    concurrency: usize,
}

impl<P> fmt::Debug for ZakuraRpcBackend<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZakuraRpcBackend")
            .field("url", &self.url)
            .field("cookie_path", &self.cookie_path)
            .finish()
    }
}

/// What went wrong with one JSON-RPC call, before it is folded into
/// [`ChainError`] with the method name.
#[derive(Debug)]
enum RpcFailure {
    /// Could not connect, timed out, or the node closed the connection.
    Transport(String),
    /// HTTP 401/403: the cookie is wrong, missing or stale.
    Auth,
    /// The node answered with a JSON-RPC error object.
    Json { code: i64, message: String },
    /// The response was not the JSON we expected.
    Decode(String),
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcErrorObject>,
}

#[derive(Deserialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
}

/// `getblockchaininfo`, the fields Gyges reads (unknown ones are ignored).
#[derive(Clone, Debug, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub bestblockhash: String,
    #[serde(default)]
    pub pruned: bool,
    /// Present only when `pruned`.
    #[serde(default)]
    pub pruneheight: Option<u32>,
}

impl BlockchainInfo {
    /// Reduce to [`NodeBounds`] (SYNC.md §1).
    pub fn bounds(&self) -> Result<NodeBounds, ChainError> {
        Ok(NodeBounds {
            tip_height: BlockHeight::from_u32(self.blocks),
            tip_hash: parse_display_hash(&self.bestblockhash)?,
            retained_from: BlockHeight::from_u32(if self.pruned {
                self.pruneheight.unwrap_or(0)
            } else {
                0
            }),
        })
    }
}

/// `getblock(h, 1)`, the fields Gyges reads.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockObject {
    pub hash: String,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub time: Option<i64>,
    /// Txids in display order (verbosity 1).
    #[serde(default)]
    pub tx: Vec<String>,
    #[serde(default)]
    pub trees: Trees,
    #[serde(default)]
    pub previousblockhash: Option<String>,
}

/// `getblock(h, 1).trees`; a pool is omitted while its tree is empty.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Trees {
    #[serde(default)]
    pub sapling: Option<TreeSize>,
    #[serde(default)]
    pub orchard: Option<TreeSize>,
    #[serde(default)]
    pub ironwood: Option<TreeSize>,
}

/// Zebra serialises a tree size as `{"size": N}`; accept a bare number too.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(untagged)]
pub enum TreeSize {
    Object { size: u64 },
    Bare(u64),
}

impl TreeSize {
    fn get(self) -> u64 {
        match self {
            TreeSize::Object { size } | TreeSize::Bare(size) => size,
        }
    }
}

impl Trees {
    /// As `ChainMetadata` carries them.
    pub fn sizes(&self) -> Result<TreeSizes, ChainError> {
        let clamp = |t: Option<TreeSize>, pool: &str| -> Result<u32, ChainError> {
            let n = t.map_or(0, TreeSize::get);
            u32::try_from(n)
                .map_err(|_| ChainError::Rpc(format!("{pool} tree size {n} does not fit a u32")))
        };
        Ok(TreeSizes {
            sapling: clamp(self.sapling, "sapling")?,
            orchard: clamp(self.orchard, "orchard")?,
            ironwood: clamp(self.ironwood, "ironwood")?,
        })
    }
}

#[derive(Deserialize)]
struct TreeStateObject {
    hash: String,
    height: u32,
    #[serde(default)]
    time: u32,
    #[serde(default)]
    sapling: PoolTree,
    #[serde(default)]
    orchard: PoolTree,
    #[serde(default)]
    ironwood: PoolTree,
}

#[derive(Default, Deserialize)]
struct PoolTree {
    #[serde(default)]
    commitments: Commitments,
}

#[derive(Default, Deserialize)]
struct Commitments {
    #[serde(default, rename = "finalState")]
    final_state: Option<String>,
}

impl<P: Parameters + Send + Sync + 'static> ZakuraRpcBackend<P> {
    /// A backend for the node at `url` (`config.zakura_rpc.url`), presenting
    /// the cookie at `cookie_path` when given (`None` for an unauthenticated
    /// listener). Nothing is contacted here; the daemon must start with the
    /// node down.
    pub fn new(
        url: impl Into<String>,
        cookie_path: Option<PathBuf>,
        params: P,
    ) -> Result<Self, ChainError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|e| ChainError::Rpc(format!("cannot build the HTTP client: {e}")))?;
        Ok(Self {
            http,
            url: url.into(),
            cookie_path,
            params,
            next_id: AtomicU64::new(1),
            status: RwLock::new(NodeStatus::default()),
            concurrency: DEFAULT_CONCURRENCY,
        })
    }

    /// Bound the concurrent `getblock` fetches (default
    /// [`DEFAULT_CONCURRENCY`]).
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// `(user, password)` from the cookie file, re-read on every call because
    /// the node rewrites it at each start. `Err` carries a one-line reason
    /// that is only shown when the node then rejects the request.
    fn credentials(&self) -> Result<Option<(String, String)>, String> {
        let Some(path) = &self.cookie_path else {
            return Ok(None);
        };
        match std::fs::read_to_string(path) {
            Ok(text) => match text.trim().split_once(':') {
                Some((user, pass)) => Ok(Some((user.to_string(), pass.to_string()))),
                None => Err(format!(
                    "{} does not look like a zakurad cookie (expected `__cookie__:<secret>`)",
                    path.display()
                )),
            },
            Err(e) => Err(format!("cannot read cookie {}: {e}", path.display())),
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, RpcFailure> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let credentials = self.credentials();
        let mut req = self.http.post(&self.url).json(&body);
        if let Ok(Some((user, pass))) = &credentials {
            req = req.basic_auth(user, Some(pass));
        }
        let resp = req.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                RpcFailure::Transport(connect_error_text(&e))
            } else {
                RpcFailure::Transport(e.to_string())
            }
        })?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(RpcFailure::Auth);
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| RpcFailure::Transport(e.to_string()))?;
        if bytes.is_empty() {
            // Zakura answers a bad cookie with an empty body (see the TODO in
            // its `http_request_compatibility.rs`), so an empty reply is
            // most likely an auth failure.
            return Err(if credentials.is_err() || self.cookie_path.is_some() {
                RpcFailure::Auth
            } else {
                RpcFailure::Decode(format!("empty response (HTTP {status})"))
            });
        }
        let parsed: RpcResponse = serde_json::from_slice(&bytes)
            .map_err(|e| RpcFailure::Decode(format!("{e} (HTTP {status})")))?;
        if let Some(err) = parsed.error {
            return Err(RpcFailure::Json {
                code: err.code,
                message: err.message,
            });
        }
        let result = parsed
            .result
            .ok_or_else(|| RpcFailure::Decode("response has neither result nor error".into()))?;
        serde_json::from_value(result).map_err(|e| RpcFailure::Decode(e.to_string()))
    }

    /// Fold a failure into a [`ChainError`], naming the method.
    fn chain_error(&self, method: &str, failure: RpcFailure) -> ChainError {
        match failure {
            RpcFailure::Transport(detail) => {
                ChainError::Unreachable(format!("{method} at {}: {detail}", self.url))
            }
            RpcFailure::Auth => {
                let hint = match self.credentials() {
                    Ok(Some(_)) => "the cookie was presented but rejected; is zakura_rpc.cookie_path the running node's cookie?".to_string(),
                    Ok(None) => "no cookie configured (zakura_rpc.cookie_path is empty) but the node requires one".to_string(),
                    Err(reason) => reason,
                };
                ChainError::Unreachable(format!(
                    "{method}: the node rejected the credentials; {hint}"
                ))
            }
            RpcFailure::Json { code, message } => {
                ChainError::Rpc(format!("{method}: {message} (code {code})"))
            }
            RpcFailure::Decode(detail) => {
                ChainError::Rpc(format!("{method}: unexpected response: {detail}"))
            }
        }
    }

    fn record(&self, outcome: &Result<(NodeBounds, bool), ChainError>) {
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        status.last_polled = Some(SystemTime::now());
        match outcome {
            Ok((bounds, pruned)) => {
                status.connected = true;
                status.bounds = Some(bounds.clone());
                status.pruned = *pruned;
                status.last_error.clear();
            }
            Err(e) => {
                status.connected = false;
                status.last_error = e.to_string();
            }
        }
    }

    /// `getblockchaininfo`, verbatim.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo, ChainError> {
        let info: BlockchainInfo = self
            .call("getblockchaininfo", vec![])
            .await
            .map_err(|e| self.chain_error("getblockchaininfo", e))?;
        let expected = match self.params.network_type() {
            NetworkType::Main => "main",
            NetworkType::Test => "test",
            NetworkType::Regtest => "regtest",
        };
        if info.chain != expected {
            return Err(ChainError::Rpc(format!(
                "the node at {} serves chain \"{}\", this daemon is for {expected}",
                self.url, info.chain
            )));
        }
        Ok(info)
    }

    /// `getblockhash(height)`, internal byte order.
    pub async fn get_block_hash(&self, height: BlockHeight) -> Result<[u8; 32], ChainError> {
        let hash: String = self
            .call("getblockhash", vec![json!(u32::from(height))])
            .await
            .map_err(|e| match e {
                RpcFailure::Json { .. } => ChainError::BlockUnavailable { height },
                other => self.chain_error("getblockhash", other),
            })?;
        parse_display_hash(&hash)
    }

    /// `getblock(height, 0)`: the raw block, or
    /// [`ChainError::BlockUnavailable`] when the node has no body for it.
    pub async fn get_raw_block(&self, height: BlockHeight) -> Result<Vec<u8>, ChainError> {
        let hex_str: String = self
            .call(
                "getblock",
                vec![json!(u32::from(height).to_string()), json!(0)],
            )
            .await
            .map_err(|e| match e {
                RpcFailure::Json {
                    code: RPC_INVALID_PARAMETER,
                    ..
                } => ChainError::BlockUnavailable { height },
                other => self.chain_error("getblock", other),
            })?;
        hex::decode(hex_str.trim())
            .map_err(|e| ChainError::Rpc(format!("getblock({height}, 0) is not hex: {e}")))
    }

    /// `getblock(height, 1)`: hash, txids and tree sizes.
    pub async fn get_block_object(&self, height: BlockHeight) -> Result<BlockObject, ChainError> {
        self.call(
            "getblock",
            vec![json!(u32::from(height).to_string()), json!(1)],
        )
        .await
        .map_err(|e| match e {
            RpcFailure::Json {
                code: RPC_INVALID_PARAMETER,
                ..
            } => ChainError::BlockUnavailable { height },
            other => self.chain_error("getblock", other),
        })
    }

    /// `sendrawtransaction(hex)`; the node answers the txid as display hex.
    /// A JSON-RPC error is the node's rejection and is passed through
    /// verbatim as [`ChainError::Rejected`]; transport failures stay
    /// [`ChainError::Unreachable`].
    pub async fn send_raw_transaction(&self, raw: &[u8]) -> Result<[u8; 32], ChainError> {
        let txid: String = self
            .call("sendrawtransaction", vec![json!(hex::encode(raw))])
            .await
            .map_err(|e| match e {
                RpcFailure::Json { code, message } => {
                    ChainError::Rejected(format!("{message} (code {code})"))
                }
                other => self.chain_error("sendrawtransaction", other),
            })?;
        parse_display_hash(&txid)
    }

    /// `z_gettreestate(height)` as the `ChainState` an account born at
    /// `height + 1` starts from.
    pub async fn get_tree_state(&self, height: BlockHeight) -> Result<ChainState, ChainError> {
        let obj: TreeStateObject = match self
            .call("z_gettreestate", vec![json!(u32::from(height).to_string())])
            .await
        {
            Ok(obj) => obj,
            Err(RpcFailure::Json {
                code: RPC_INVALID_PARAMETER,
                message,
            }) => {
                // Pruned, or above the tip: re-poll the bounds to say which.
                let retained_from = match self.node_bounds().await {
                    Ok(b) if height < b.retained_from => b.retained_from,
                    _ => {
                        return Err(ChainError::Rpc(format!(
                            "z_gettreestate({height}): {message}"
                        )));
                    }
                };
                return Err(ChainError::TreeStateUnavailable {
                    height,
                    retained_from,
                });
            }
            Err(other) => return Err(self.chain_error("z_gettreestate", other)),
        };
        if obj.height != u32::from(height) {
            return Err(ChainError::Rpc(format!(
                "z_gettreestate({height}) answered for height {}",
                obj.height
            )));
        }
        let tree = |pool: &str, nu: NetworkUpgrade, c: Commitments| -> String {
            match c.final_state {
                Some(hex_tree) => hex_tree,
                None => {
                    if self.params.is_nu_active(nu, height) {
                        // The pool is active, yet the node sent no frontier.
                        // An empty tree is the only reading; say so loudly
                        // because a wrong frontier makes notes unspendable
                        // until a rescan (SYNC.md §9, needs verification).
                        tracing::warn!(
                            %height,
                            pool,
                            "z_gettreestate omitted the frontier of an active pool; assuming an empty tree"
                        );
                    }
                    String::new()
                }
            }
        };
        let state = TreeState {
            network: match self.params.network_type() {
                NetworkType::Main => "main".into(),
                _ => "test".into(),
            },
            height: u64::from(obj.height),
            hash: obj.hash,
            time: obj.time,
            sapling_tree: tree("sapling", NetworkUpgrade::Sapling, obj.sapling.commitments),
            orchard_tree: tree("orchard", NetworkUpgrade::Nu5, obj.orchard.commitments),
            ironwood_tree: tree("ironwood", NetworkUpgrade::Nu6_3, obj.ironwood.commitments),
        };
        state
            .to_chain_state()
            .map_err(|e| ChainError::Rpc(format!("z_gettreestate({height}) does not parse: {e}")))
    }

    /// One compact block: `getblock(h, 0)` parsed with `zcash_primitives`,
    /// cross-checked against `getblock(h, 1)`'s hash and txids, carrying
    /// that object's tree sizes.
    pub async fn compact_block(&self, height: BlockHeight) -> Result<CompactBlock, ChainError> {
        let (raw, obj) =
            tokio::try_join!(self.get_raw_block(height), self.get_block_object(height))?;
        let sizes = obj.trees.sizes()?;
        let block = compact::from_raw(&self.params, height, &raw, Some(sizes))
            .map_err(|e| ChainError::Rpc(e.to_string()))?;
        if !obj.hash.eq_ignore_ascii_case(&display_hash(&block.hash)) {
            // The two calls straddled a reorg; the caller re-polls and retries.
            return Err(ChainError::Rpc(format!(
                "getblock({height}) answered two different blocks ({} and {}): chain moved during the fetch",
                display_hash(&block.hash),
                obj.hash
            )));
        }
        if !obj.tx.is_empty() {
            let ours: Vec<String> = block.vtx.iter().map(|t| display_hash(&t.txid)).collect();
            let theirs: Vec<String> = obj.tx.iter().map(|t| t.to_ascii_lowercase()).collect();
            if ours != theirs {
                return Err(ChainError::Rpc(format!(
                    "block {height}: parsed txids differ from the node's (parsed {}, node {})",
                    ours.len(),
                    theirs.len()
                )));
            }
        }
        Ok(block)
    }
}

/// `reqwest`'s connect errors wrap the OS error several layers deep; the
/// innermost message ("Connection refused") is the useful one.
fn connect_error_text(e: &reqwest::Error) -> String {
    let mut cur: &dyn std::error::Error = e;
    let mut last = e.to_string();
    while let Some(next) = cur.source() {
        last = next.to_string();
        cur = next;
    }
    if e.is_timeout() {
        format!("timed out ({last})")
    } else {
        last
    }
}

impl<P: Parameters + Send + Sync + 'static> ChainBackend for ZakuraRpcBackend<P> {
    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>> {
        Box::pin(async move {
            let outcome = match self.get_blockchain_info().await {
                Ok(info) => info.bounds().map(|b| (b, info.pruned)),
                Err(e) => Err(e),
            };
            self.record(&outcome);
            outcome.map(|(b, _)| b)
        })
    }

    fn status(&self) -> NodeStatus {
        self.status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>> {
        Box::pin(self.get_tree_state(height))
    }

    fn block_hash(&self, height: BlockHeight) -> BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(self.get_block_hash(height))
    }

    fn send_raw_transaction(&self, raw: Vec<u8>) -> BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(async move { self.send_raw_transaction(&raw).await })
    }

    fn compact_blocks(
        &self,
        range: Range<BlockHeight>,
    ) -> BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>> {
        Box::pin(async move {
            let heights = u32::from(range.start)..u32::from(range.end);
            let blocks: Vec<CompactBlock> = stream::iter(heights.map(BlockHeight::from_u32))
                .map(|h| self.compact_block(h))
                .buffered(self.concurrency)
                .try_collect()
                .await?;
            for pair in blocks.windows(2) {
                let (a, b) = (&pair[0], &pair[1]);
                if b.height != a.height + 1 || b.prev_hash != a.hash {
                    return Err(ChainError::Rpc(format!(
                        "blocks {} and {} do not link: chain moved during the fetch",
                        a.height, b.height
                    )));
                }
            }
            Ok(blocks)
        })
    }
}

/// Expand `~` the way `gyges_core::paths::expand_tilde` does, for callers
/// that hand a raw config string to [`ZakuraRpcBackend::new`].
pub fn cookie_path_from_config(value: &str) -> Option<PathBuf> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    Some(if let Some(rest) = v.strip_prefix("~/") {
        std::env::var_os("HOME")
            .map(|h| Path::new(&h).join(rest))
            .unwrap_or_else(|| PathBuf::from(v))
    } else {
        PathBuf::from(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeNode, regtest_params};
    use transparent::address::TransparentAddress;

    fn h(n: u32) -> BlockHeight {
        BlockHeight::from_u32(n)
    }

    fn backend(node: &FakeNode) -> ZakuraRpcBackend<zcash_protocol::local_consensus::LocalNetwork> {
        ZakuraRpcBackend::new(node.url(), None, regtest_params()).unwrap()
    }

    #[test]
    fn blockchain_info_reduces_to_bounds() {
        let info: BlockchainInfo = serde_json::from_value(json!({
            "chain": "regtest", "blocks": 120, "headers": 120,
            "bestblockhash": "00".repeat(31) + "ab", "pruned": true, "pruneheight": 100,
            "estimatedheight": 120, "upgrades": {}, "valuePools": []
        }))
        .unwrap();
        let b = info.bounds().unwrap();
        assert_eq!(b.tip_height, h(120));
        assert_eq!(b.retained_from, h(100));
        assert_eq!(b.tip_hash[0], 0xab, "display order is reversed");

        let info: BlockchainInfo = serde_json::from_value(json!({
            "chain": "main", "blocks": 5, "bestblockhash": "00".repeat(32), "pruned": false
        }))
        .unwrap();
        assert_eq!(info.bounds().unwrap().retained_from, h(0));
    }

    #[test]
    fn trees_accept_both_shapes_and_omissions() {
        let t: Trees =
            serde_json::from_value(json!({"sapling": {"size": 7}, "orchard": 9})).unwrap();
        let s = t.sizes().unwrap();
        assert_eq!((s.sapling, s.orchard, s.ironwood), (7, 9, 0));
        let t: Trees = serde_json::from_value(json!({})).unwrap();
        assert_eq!(t.sizes().unwrap(), TreeSizes::default());
        let t: Trees = serde_json::from_value(json!({"sapling": {"size": u64::MAX}})).unwrap();
        assert!(t.sizes().is_err());
    }

    #[test]
    fn cookie_path_expands_tilde_and_empty_is_none() {
        assert_eq!(cookie_path_from_config(""), None);
        assert_eq!(cookie_path_from_config(" "), None);
        assert_eq!(
            cookie_path_from_config("/tmp/x"),
            Some(PathBuf::from("/tmp/x"))
        );
        let p = cookie_path_from_config("~/.cache/zakura/.cookie").unwrap();
        assert!(!p.to_string_lossy().starts_with('~') || std::env::var_os("HOME").is_none());
    }

    #[tokio::test]
    async fn bounds_status_hashes_and_tree_state_against_the_fake_node() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(10);
        let be = backend(&node);
        assert!(!be.status().connected, "nothing polled yet");

        let bounds = be.node_bounds().await.unwrap();
        assert_eq!(bounds.tip_height, h(10));
        assert_eq!(bounds.retained_from, h(0));
        assert_eq!(bounds.tip_hash, node.tip().1);
        let st = be.status();
        assert!(st.connected && !st.pruned && st.last_error.is_empty());
        assert_eq!(st.bounds.as_ref().unwrap(), &bounds);

        assert_eq!(
            be.block_hash(h(4)).await.unwrap(),
            node.block(4).unwrap().hash
        );
        assert!(matches!(
            be.block_hash(h(11)).await,
            Err(ChainError::BlockUnavailable { .. })
        ));

        // Tree state at the tip: empty trees (the fake has no shielded
        // outputs), the block's hash, the requested height.
        let cs = be.chain_state(h(10)).await.unwrap();
        assert_eq!(cs.block_height(), h(10));
        assert_eq!(cs.block_hash().0, node.tip().1);
        assert!(cs.final_sapling_tree().value().is_none());
        assert!(cs.final_orchard_tree().value().is_none());

        // Pruned: the tree state below pruneheight names the window.
        node.set_prune_height(Some(5));
        let err = be.chain_state(h(3)).await.unwrap_err();
        assert!(
            matches!(
                err,
                ChainError::TreeStateUnavailable { height, retained_from }
                    if height == h(3) && retained_from == h(5)
            ),
            "{err}"
        );
        assert!(be.status().pruned);
        assert_eq!(be.status().bounds.unwrap().retained_from, h(5));
        be.chain_state(h(5)).await.unwrap();
    }

    #[tokio::test]
    async fn compact_blocks_link_carry_transparent_outputs_and_respect_pruning() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(3);
        let addr = TransparentAddress::PublicKeyHash([0x42; 20]);
        let paid = node.mine_with_payments(&[(addr, 50_000)]);
        node.mine(2);
        node.set_tree_sizes(Some(TreeSizes {
            sapling: 11,
            orchard: 22,
            ironwood: 0,
        }));
        let be = backend(&node).with_concurrency(3);

        let blocks = be.compact_blocks(h(1)..h(7)).await.unwrap();
        assert_eq!(blocks.len(), 6);
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(b.height, i as u64 + 1);
            assert_eq!(
                b.chain_metadata
                    .as_ref()
                    .unwrap()
                    .orchard_commitment_tree_size,
                22
            );
        }
        for pair in blocks.windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].hash);
        }
        let outs = compact::transparent_outputs(&blocks[(paid.height - 1) as usize]);
        assert!(
            outs.iter().any(|o| o.address == Some(addr)
                && o.value_zat == 50_000
                && o.txid == paid.txids[1])
        );

        // Every block was asked for exactly once in each form.
        let calls = node.calls();
        assert_eq!(
            calls.iter().filter(|c| c.as_str() == "getblock").count(),
            12
        );

        // An empty range is fine; above the tip is BlockUnavailable.
        assert!(be.compact_blocks(h(3)..h(3)).await.unwrap().is_empty());
        assert!(matches!(
            be.compact_blocks(h(6)..h(8)).await,
            Err(ChainError::BlockUnavailable { height }) if height == h(7)
        ));

        // Pruned bodies are BlockUnavailable, not a parse error.
        node.set_prune_height(Some(4));
        assert!(matches!(
            be.compact_blocks(h(2)..h(5)).await,
            Err(ChainError::BlockUnavailable { height }) if height == h(2) || height == h(3)
        ));
        be.compact_blocks(h(4)..h(7)).await.unwrap();
    }

    #[tokio::test]
    async fn cookie_auth_is_read_per_request_and_failures_are_explained() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(1);
        let dir = tempfile::tempdir().unwrap();
        let cookie = dir.path().join(".cookie");

        // Node requires a cookie we do not have yet.
        node.set_cookie(Some("s3cret".into()));
        let be = ZakuraRpcBackend::new(node.url(), Some(cookie.clone()), regtest_params()).unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("rejected the credentials") && m.contains("cannot read cookie")),
            "{err}"
        );
        assert!(!be.status().connected);
        assert!(be.status().last_error.contains("credentials"));

        // The file appears (node started): the next call picks it up.
        node.write_cookie_file(&cookie);
        be.node_bounds().await.unwrap();
        assert!(be.status().connected);

        // The node restarts with a new cookie: stale file, clear message.
        node.set_cookie(Some("rotated".into()));
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("presented but rejected")),
            "{err}"
        );
        node.write_cookie_file(&cookie);
        be.node_bounds().await.unwrap();

        // No cookie configured but the node wants one.
        let be = ZakuraRpcBackend::new(node.url(), None, regtest_params()).unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("no cookie configured")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn unreachable_and_wrong_chain_are_reported() {
        // A port nobody listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let be = ZakuraRpcBackend::new(url, None, regtest_params()).unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("getblockchaininfo")),
            "{err}"
        );
        let st = be.status();
        assert!(!st.connected && st.bounds.is_none() && st.last_polled.is_some());

        // Mainnet daemon pointed at a regtest node.
        let node = FakeNode::start(regtest_params()).await;
        let be = ZakuraRpcBackend::new(node.url(), None, zcash_protocol::consensus::MAIN_NETWORK)
            .unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("serves chain \"regtest\"")),
            "{err}"
        );
    }
}
