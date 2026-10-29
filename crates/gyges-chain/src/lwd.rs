//! `ArtiTorLwdBackend`: [`ChainBackend`] over a lightwalletd / zaino
//! `CompactTxStreamer` endpoint, for the historical backfill below the
//! node's retention window (ARCHITECTURE.md §3.1 step 2, SYNC.md §5,
//! THREAT_MODEL.md §3 rows 7 and 10, OVERVIEW.md Q-D5 / Q-Y5).
//!
//! Two transports, chosen by `fallback_lightwalletd.use_tor`:
//!
//! * [`Transport::Tor`]: the embedded arti client of
//!   `zcash_client_backend::tor` (its persistent state under
//!   `tor_cache/`), bootstrapped lazily on the first request, `.onion`
//!   endpoints reached as onion services; `https://` endpoints get TLS from
//!   rustls with the webpki roots and the URI host as SNI (OVERVIEW.md §4.4);
//! * [`Transport::Direct`]: plain tonic over TCP, for regtest and CI
//!   (`use_tor = false`), with the same TLS rule for `https://`.
//!
//! The endpoint is untrusted (THREAT_MODEL.md B3): every block batch must
//! carry the heights asked for and link by `prev_hash`, and the handoff
//! validation of SYNC.md §5.2 (`gyges_core::handoff`, run by
//! `gygesd::backfill`) checks the result against the local node before the
//! wallet relies on it. What this module guarantees is only that a batch is
//! internally consistent and that a stalled or short stream is reported
//! rather than waited on forever.
//!
//! Nothing is contacted at construction. The connection (and the Tor
//! client) is made on first use and dropped on any transport failure, so the
//! next call reconnects.

use std::error::Error as _;
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use futures_util::StreamExt as _;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tonic::{Code, Status};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{
    BlockId, BlockRange, ChainSpec, Empty, GetAddressUtxosArg, GetSubtreeRootsArg, RawTransaction,
    ShieldedProtocol, TxFilter,
};
use zcash_client_backend::tor;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    BoxFuture, ChainBackend, ChainError, NodeBounds, NodeStatus, Source, StatusCell, SubtreeRoot,
    TxStatus, bytes32, check_chain_name, display_hash, innermost_error,
};

/// One `GetAddressUtxos` entry: an output the endpoint says is unspent at
/// one of the requested addresses. Untrusted until checked (SYNC.md §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressUtxo {
    /// As requested (`t1…`, `tm…`).
    pub address: String,
    /// Internal byte order, as upstream reads it.
    pub txid: [u8; 32],
    pub index: u32,
    pub script_pubkey: Vec<u8>,
    pub value_zat: u64,
    pub height: BlockHeight,
}

/// How the endpoint is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// `use_tor = false`: plain gRPC over TCP (regtest, CI).
    Direct,
    /// `use_tor = true`: through the embedded arti client, whose state
    /// lives in `tor_dir` (`~/.gyges/<network>/tor_cache/`, created `0700`
    /// if missing).
    Tor { tor_dir: PathBuf },
}

/// Deadlines. Tor circuits are slow and can half-close silently, so every
/// wait is bounded (the upstream `tor::Timeouts` are set from the same
/// values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LwdTimeouts {
    /// Opening the connection (Tor stream and TLS handshake included).
    pub connect: Duration,
    /// Sending a request and receiving its response headers.
    pub request: Duration,
    /// Longest silence tolerated inside a streaming response
    /// (`GetBlockRange`, `GetSubtreeRoots`) before the stream is declared
    /// stalled and the connection dropped.
    pub stream_idle: Duration,
}

impl Default for LwdTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            request: Duration::from_secs(60),
            stream_idle: Duration::from_secs(60),
        }
    }
}

/// The embedded Tor client's state, for `GetInfo.tor` (API.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TorState {
    /// `use_tor = false`.
    Disabled,
    /// Nothing has needed Tor yet.
    NotStarted,
    Bootstrapping,
    Ready,
    Failed(String),
}

/// The endpoint backend. Cheap to share behind an `Arc`.
pub struct ArtiTorLwdBackend<P> {
    endpoint: Uri,
    transport: Transport,
    params: P,
    timeouts: LwdTimeouts,
    status: StatusCell,
    tor_state: RwLock<TorState>,
    conn: tokio::sync::Mutex<Connection>,
}

#[derive(Default)]
struct Connection {
    tor: Option<tor::Client>,
    client: Option<CompactTxStreamerClient<Channel>>,
}

impl<P> fmt::Debug for ArtiTorLwdBackend<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtiTorLwdBackend")
            .field("endpoint", &self.endpoint.to_string())
            .field("transport", &self.transport)
            .finish()
    }
}

impl<P: Parameters + Send + Sync + 'static> ArtiTorLwdBackend<P> {
    /// A backend for `endpoint` (`fallback_lightwalletd.grpc_url`: an
    /// `http://` or `https://` URL with a host; `Config::validate` has
    /// already applied the scheme rules of DATA_MODEL.md §2). Nothing is
    /// contacted here.
    pub fn new(endpoint: &str, transport: Transport, params: P) -> Result<Self, ChainError> {
        let uri: Uri = endpoint.trim().parse().map_err(|e| {
            ChainError::Rpc(format!("fallback endpoint `{endpoint}` is not a URL: {e}"))
        })?;
        match uri.scheme_str() {
            Some("http") | Some("https") => {}
            other => {
                return Err(ChainError::Rpc(format!(
                    "fallback endpoint `{endpoint}` must be http:// or https://, not {}",
                    other.unwrap_or("a bare host")
                )));
            }
        }
        if uri.host().is_none_or(str::is_empty) {
            return Err(ChainError::Rpc(format!(
                "fallback endpoint `{endpoint}` has no host"
            )));
        }
        let tor_state = match transport {
            Transport::Direct => TorState::Disabled,
            Transport::Tor { .. } => TorState::NotStarted,
        };
        Ok(Self {
            endpoint: uri,
            transport,
            params,
            timeouts: LwdTimeouts::default(),
            status: StatusCell::default(),
            tor_state: RwLock::new(tor_state),
            conn: tokio::sync::Mutex::new(Connection::default()),
        })
    }

    /// Replace the default [`LwdTimeouts`].
    pub fn with_timeouts(mut self, timeouts: LwdTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn endpoint(&self) -> String {
        self.endpoint.to_string()
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Whether the endpoint host is a Tor onion service (`.onion`), which
    /// needs no exit node and no TLS to be private (Q-D5).
    pub fn is_onion(&self) -> bool {
        self.endpoint
            .host()
            .is_some_and(|h| h.to_ascii_lowercase().ends_with(".onion"))
    }

    pub fn tor_state(&self) -> TorState {
        self.tor_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_tor_state(&self, state: TorState) {
        *self.tor_state.write().unwrap_or_else(|e| e.into_inner()) = state;
    }

    /// The connected client, connecting (and bootstrapping Tor) on first
    /// use. `GetLightdInfo` is checked once per connection so that an
    /// endpoint for another chain is refused before any block is taken
    /// from it.
    async fn client(&self) -> Result<CompactTxStreamerClient<Channel>, ChainError> {
        let mut conn = self.conn.lock().await;
        if let Some(client) = &conn.client {
            return Ok(client.clone());
        }
        let channel = match &self.transport {
            Transport::Direct => self.connect_direct().await?,
            Transport::Tor { tor_dir } => {
                if conn.tor.is_none() {
                    conn.tor = Some(self.bootstrap_tor(tor_dir).await?);
                }
                let tor = conn.tor.as_ref().expect("set above");
                // A failed circuit is the common case; a client that lost its
                // directory is re-bootstrapped by the next attempt
                // (`ensure_bootstrapped`), so keep it.
                tor.connect_lightwalletd_channel(self.endpoint.clone(), self.is_onion())
                    .await
                    .map_err(|e| {
                        ChainError::Unreachable(format!("{} over Tor: {e}", self.endpoint))
                    })?
            }
        };
        let mut client = CompactTxStreamerClient::new(channel);
        self.check_endpoint(&mut client).await?;
        conn.client = Some(client.clone());
        Ok(client)
    }

    async fn connect_direct(&self) -> Result<Channel, ChainError> {
        let mut endpoint = Endpoint::from(self.endpoint.clone())
            .connect_timeout(self.timeouts.connect)
            .timeout(self.timeouts.request)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(false);
        if self.endpoint.scheme_str() == Some("https") {
            // The same policy as the Tor path (OVERVIEW.md §4.4): webpki
            // roots, SNI and hostname verification from the URI host.
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(|e| ChainError::Rpc(format!("TLS configuration: {e}")))?;
        }
        endpoint.connect().await.map_err(|e| {
            ChainError::Unreachable(format!("{}: {}", self.endpoint, innermost_error(&e)))
        })
    }

    async fn bootstrap_tor(&self, tor_dir: &Path) -> Result<tor::Client, ChainError> {
        if let Err(e) = std::fs::create_dir_all(tor_dir) {
            let msg = format!("cannot create {}: {e}", tor_dir.display());
            self.set_tor_state(TorState::Failed(msg.clone()));
            return Err(ChainError::Unreachable(msg));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(tor_dir, std::fs::Permissions::from_mode(0o700));
        }
        self.set_tor_state(TorState::Bootstrapping);
        tracing::info!(dir = %tor_dir.display(), "bootstrapping the embedded Tor client");
        let timeouts = tor::Timeouts::default()
            .with_connect(self.timeouts.connect)
            .with_request(self.timeouts.request);
        // `|_| {}` keeps arti's own permission checks (the directory must
        // not be group or world writable), which is what DATA_MODEL.md §1
        // demands anyway.
        match tor::Client::create_with_timeouts(tor_dir, |_| {}, timeouts).await {
            Ok(client) => {
                self.set_tor_state(TorState::Ready);
                tracing::info!("Tor bootstrapped");
                Ok(client)
            }
            Err(e) => {
                let msg = format!("Tor bootstrap failed: {e}");
                self.set_tor_state(TorState::Failed(msg.clone()));
                Err(ChainError::Unreachable(msg))
            }
        }
    }

    /// `GetLightdInfo`: refuse an endpoint for another chain. lightwalletd
    /// reports `"main"` or `"test"`, and zaino 0.10.2 reports `"test"` on
    /// regtest too (OVERVIEW.md §4.5); `"regtest"` is accepted as well.
    async fn check_endpoint(
        &self,
        client: &mut CompactTxStreamerClient<Channel>,
    ) -> Result<(), ChainError> {
        let info = client
            .get_lightd_info(Empty {})
            .await
            .map_err(|s| self.status_error("GetLightdInfo", s))?
            .into_inner();
        check_chain_name(
            &self.params,
            &info.chain_name,
            format_args!("the fallback endpoint {}", self.endpoint),
        )?;
        tracing::info!(
            endpoint = %self.endpoint,
            vendor = %info.vendor,
            version = %info.version,
            tip = info.block_height,
            "fallback endpoint connected"
        );
        Ok(())
    }

    /// Map a gRPC status onto [`ChainError`]; transport-level failures drop
    /// the connection so the next call reconnects.
    fn status_error(&self, method: &str, status: Status) -> ChainError {
        match status.code() {
            Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled | Code::Aborted => {
                ChainError::Unreachable(format!(
                    "{method} at {}: {} ({:?})",
                    self.endpoint,
                    status.message(),
                    status.code()
                ))
            }
            Code::Unknown if status.source().is_some() => {
                // tonic reports a dead connection as Unknown with the
                // transport error as its source.
                ChainError::Unreachable(format!(
                    "{method} at {}: {}",
                    self.endpoint,
                    status
                        .source()
                        .map_or_else(|| status.message().to_string(), ToString::to_string)
                ))
            }
            code => ChainError::Rpc(format!(
                "{method} at {}: {} ({code:?})",
                self.endpoint,
                status.message()
            )),
        }
    }

    /// [`ArtiTorLwdBackend::status_error`], except that NotFound,
    /// InvalidArgument and OutOfRange mean the endpoint has no block at
    /// `height`.
    fn block_error(&self, method: &str, height: BlockHeight, status: Status) -> ChainError {
        match status.code() {
            Code::NotFound | Code::InvalidArgument | Code::OutOfRange => {
                ChainError::BlockUnavailable { height }
            }
            _ => self.status_error(method, status),
        }
    }

    /// The next item of a streaming response, `None` at its end. A stream
    /// silent for [`LwdTimeouts::stream_idle`] is [`ChainError::Unreachable`]
    /// with `stalled()`'s text, which drops the connection.
    async fn next_or_stall<T>(
        &self,
        stream: &mut tonic::Streaming<T>,
        method: &str,
        stalled: impl FnOnce() -> String,
    ) -> Result<Option<T>, ChainError> {
        match tokio::time::timeout(self.timeouts.stream_idle, stream.next()).await {
            Err(_elapsed) => Err(ChainError::Unreachable(stalled())),
            Ok(None) => Ok(None),
            Ok(Some(Err(s))) => Err(self.status_error(method, s)),
            Ok(Some(Ok(item))) => Ok(Some(item)),
        }
    }

    /// Run `f` against the client, dropping the connection when the result
    /// is a transport failure.
    async fn call<T, F, Fut>(&self, f: F) -> Result<T, ChainError>
    where
        F: FnOnce(CompactTxStreamerClient<Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<T, ChainError>>,
    {
        let client = self.client().await?;
        let result = f(client).await;
        if matches!(result, Err(ChainError::Unreachable(_))) {
            self.conn.lock().await.client = None;
        }
        result
    }

    /// `GetLatestBlock`: the endpoint's tip. An archival endpoint retains
    /// everything, so `retained_from` is 0.
    async fn latest_block(&self) -> Result<NodeBounds, ChainError> {
        self.call(|mut client| async move {
            let id = client
                .get_latest_block(ChainSpec {})
                .await
                .map_err(|s| self.status_error("GetLatestBlock", s))?
                .into_inner();
            Ok(NodeBounds {
                tip_height: height_of(id.height, "GetLatestBlock")?,
                tip_hash: bytes32(&id.hash, "GetLatestBlock: hash")?,
                retained_from: BlockHeight::from_u32(0),
            })
        })
        .await
    }

    /// `GetTreeState(height)` as the `ChainState` an account born at
    /// `height + 1` starts from. Untrusted until the handoff validation of
    /// SYNC.md §5.2 has covered it (SYNC.md §9).
    async fn tree_state(&self, height: BlockHeight) -> Result<ChainState, ChainError> {
        self.call(|mut client| async move {
            let state = client
                .get_tree_state(block_id(u32::from(height)))
                .await
                .map_err(|s| self.block_error("GetTreeState", height, s))?
                .into_inner();
            if state.height != u64::from(u32::from(height)) {
                return Err(ChainError::Rpc(format!(
                    "GetTreeState({height}) at {} answered height {}",
                    self.endpoint, state.height
                )));
            }
            state.to_chain_state().map_err(|e| {
                ChainError::Rpc(format!(
                    "GetTreeState({height}) at {} does not parse: {e}",
                    self.endpoint
                ))
            })
        })
        .await
    }

    /// `GetBlockRange(start, end - 1)`, collected with the idle timeout and
    /// checked: the heights are exactly the requested ones in order, every
    /// hash is 32 bytes, and consecutive blocks link by `prev_hash`. A
    /// stream that ends early is [`ChainError::BlockUnavailable`] for the
    /// first missing height; one that skips, repeats or forks is
    /// [`ChainError::Rpc`] naming the heights; one that goes silent for
    /// [`LwdTimeouts::stream_idle`] is [`ChainError::Unreachable`] and drops
    /// the connection.
    pub async fn block_range(
        &self,
        range: Range<BlockHeight>,
    ) -> Result<Vec<CompactBlock>, ChainError> {
        if range.end <= range.start {
            return Ok(Vec::new());
        }
        let (start, end) = (u32::from(range.start), u32::from(range.end));
        let wanted = usize::try_from(end - start).unwrap_or(usize::MAX);
        self.call(|mut client| async move {
            let request = BlockRange {
                start: Some(block_id(start)),
                end: Some(block_id(end - 1)),
                // Legacy behaviour: shielded data only. Transparent outputs
                // below `retained_from` come from `GetAddressUtxos`
                // (SYNC.md §5.3).
                pool_types: vec![],
            };
            let mut stream = client
                .get_block_range(request)
                .await
                .map_err(|s| self.status_error("GetBlockRange", s))?
                .into_inner();
            let mut blocks: Vec<CompactBlock> = Vec::with_capacity(wanted);
            loop {
                let stalled = || {
                    format!(
                        "GetBlockRange({start}..{end}) at {} stalled: no block for {:?} after {} of {wanted}",
                        self.endpoint,
                        self.timeouts.stream_idle,
                        blocks.len()
                    )
                };
                let Some(block) = self
                    .next_or_stall(&mut stream, "GetBlockRange", stalled)
                    .await?
                else {
                    break;
                };
                let expected = start + blocks.len() as u32;
                if block.height != u64::from(expected) {
                    return Err(ChainError::Rpc(format!(
                        "GetBlockRange({start}..{end}) at {} answered height {} where {expected} was due",
                        self.endpoint, block.height
                    )));
                }
                bytes32(&block.hash, "GetBlockRange: hash")?;
                if let Some(prev) = blocks.last()
                    && block.prev_hash != prev.hash
                {
                    return Err(ChainError::Rpc(format!(
                        "GetBlockRange({start}..{end}) at {}: block {} (prev {}) does not link to block {} ({})",
                        self.endpoint,
                        block.height,
                        display_hash(&block.prev_hash),
                        prev.height,
                        display_hash(&prev.hash)
                    )));
                }
                blocks.push(block);
                if blocks.len() > wanted {
                    return Err(ChainError::Rpc(format!(
                        "GetBlockRange({start}..{end}) at {} streamed more than {wanted} blocks",
                        self.endpoint
                    )));
                }
            }
            if blocks.len() < wanted {
                return Err(ChainError::BlockUnavailable {
                    height: BlockHeight::from_u32(start + blocks.len() as u32),
                });
            }
            Ok(blocks)
        })
        .await
    }

    /// `GetSubtreeRoots`, collected with the idle timeout.
    async fn get_subtree_roots(
        &self,
        pool: ShieldedPool,
        start_index: u32,
        max_entries: u32,
    ) -> Result<Vec<SubtreeRoot>, ChainError> {
        let protocol = match pool {
            ShieldedPool::Sapling => ShieldedProtocol::Sapling,
            ShieldedPool::Orchard => ShieldedProtocol::Orchard,
            ShieldedPool::Ironwood => ShieldedProtocol::Ironwood,
        };
        self.call(|mut client| async move {
            let request = GetSubtreeRootsArg {
                start_index,
                shielded_protocol: protocol as i32,
                max_entries,
            };
            let mut stream = client
                .get_subtree_roots(request)
                .await
                .map_err(|s| self.status_error("GetSubtreeRoots", s))?
                .into_inner();
            let mut roots = Vec::new();
            loop {
                let stalled = || {
                    format!(
                        "GetSubtreeRoots({pool:?}, {start_index}) at {} stalled after {} roots",
                        self.endpoint,
                        roots.len()
                    )
                };
                let Some(root) = self
                    .next_or_stall(&mut stream, "GetSubtreeRoots", stalled)
                    .await?
                else {
                    break;
                };
                let index = start_index + roots.len() as u32;
                roots.push(SubtreeRoot {
                    pool,
                    index,
                    root: bytes32(&root.root_hash, "GetSubtreeRoots: hash")?,
                    end_height: height_of(root.completing_block_height, "GetSubtreeRoots")?,
                });
            }
            Ok(roots)
        })
        .await
    }

    /// `GetAddressUtxos(addresses, start)`: the outputs the endpoint
    /// reports unspent at `addresses`, mined at `start` or above. A reply
    /// that does not parse (txid length, negative value or index) is
    /// [`ChainError::Rpc`]: the endpoint is misbehaving.
    pub async fn address_utxos(
        &self,
        addresses: Vec<String>,
        start: BlockHeight,
    ) -> Result<Vec<AddressUtxo>, ChainError> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        self.call(|mut client| async move {
            let reply = client
                .get_address_utxos(GetAddressUtxosArg {
                    addresses,
                    start_height: u64::from(u32::from(start)),
                    max_entries: 0,
                })
                .await
                .map_err(|s| self.status_error("GetAddressUtxos", s))?
                .into_inner();
            reply
                .address_utxos
                .into_iter()
                .map(|u| {
                    let bad = |what: &str| {
                        ChainError::Rpc(format!("GetAddressUtxos at {}: {what}", self.endpoint))
                    };
                    Ok(AddressUtxo {
                        txid: bytes32(
                            &u.txid,
                            format_args!("GetAddressUtxos at {}: txid", self.endpoint),
                        )?,
                        index: u32::try_from(u.index).map_err(|_| bad("negative output index"))?,
                        value_zat: u64::try_from(u.value_zat).map_err(|_| bad("negative value"))?,
                        height: height_of(u.height, "GetAddressUtxos")?,
                        address: u.address,
                        script_pubkey: u.script,
                    })
                })
                .collect()
        })
        .await
    }

    /// `GetTransaction(txid)`: the raw bytes and the height the endpoint
    /// reports (0 for its mempool, `u64::MAX` for a fork); `None` when it
    /// does not have the transaction (lightwalletd's NOT_FOUND, or zaino's
    /// `Internal` carrying the node's -5).
    pub async fn raw_transaction(
        &self,
        txid: [u8; 32],
    ) -> Result<Option<(Vec<u8>, u64)>, ChainError> {
        self.call(|mut client| async move {
            match client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash: txid.to_vec(),
                })
                .await
            {
                Ok(r) => {
                    let raw = r.into_inner();
                    Ok(Some((raw.data, raw.height)))
                }
                Err(s) if s.code() == Code::NotFound => Ok(None),
                Err(s) if s.code() == Code::Internal && zaino_tx_not_found(s.message()) => Ok(None),
                Err(s) => Err(self.status_error("GetTransaction", s)),
            }
        })
        .await
    }

    /// `SendTransaction`: broadcast through the endpoint (`tx send
    /// --via-tor`, `broadcast_via_tor`). lightwalletd answers the node's
    /// `sendrawtransaction` result: `error_code` 0 (with the txid in
    /// `error_message`, which Gyges does not need), or the node's rejection
    /// code and text, which is
    /// passed through as [`ChainError::Rejected`]. zaino answers a refusal
    /// as `Internal` instead; [`zaino_rejection`] picks the node's text out
    /// of it.
    async fn send_transaction(&self, raw: Vec<u8>) -> Result<(), ChainError> {
        self.call(|mut client| async move {
            let resp = client
                .send_transaction(RawTransaction {
                    data: raw.clone(),
                    height: 0,
                })
                .await
                .map_err(|s| match s.code() {
                    Code::Internal => match zaino_rejection(s.message()) {
                        Some(text) => ChainError::Rejected(text.to_string()),
                        None => self.status_error("SendTransaction", s),
                    },
                    _ => self.status_error("SendTransaction", s),
                })?
                .into_inner();
            if resp.error_code != 0 {
                return Err(ChainError::Rejected(format!(
                    "{} (code {})",
                    resp.error_message, resp.error_code
                )));
            }
            Ok(())
        })
        .await
    }
}

/// Whether a zaino `Internal` answer to `GetTransaction` is the node's
/// "no such transaction" (OVERVIEW.md §4.5, deviation 1). zaino 0.10.2
/// passes the node's JSON-RPC error through as
/// `RPC error: LegacyRpcError { code: -5, message: "No such mempool or main chain transaction" }`
/// where lightwalletd answers NOT_FOUND. Both the code and the text must
/// match. With the node down zaino answers `Internal` too, with a transport
/// text, and that stays an error.
fn zaino_tx_not_found(message: &str) -> bool {
    message
        .split_once("LegacyRpcError { code: ")
        .and_then(|(_, rest)| rest.split_once(','))
        .is_some_and(|(code, rest)| {
            code.trim() == "-5" && rest.contains("No such mempool or main chain transaction")
        })
}

/// The node's own text when a zaino `Internal` answer to `SendTransaction`
/// is the node refusing the transaction (OVERVIEW.md §4.5, deviation 2);
/// `None` when zaino could not reach or authenticate to the node.
///
/// zaino 0.10.2 drops the node's JSON-RPC code and keeps one of two shapes
/// after its `InternalServerError: error receiving data from backing node:
/// critical error in backing block source:` wrapper:
/// * `validator rejected the query: <text>`: the node answered -22
///   (malformed) or -25 to -27 (refused). Always a rejection.
/// * `validator unreachable: <text>`: every other failure. zaino prints a
///   node's JSON-RPC error as the node's message alone, but any other
///   failure as one of `zaino-rpc`'s own error texts (`http error: …` for a
///   stopped node or a stale cookie, `http status …`, and so on), or as a
///   bare failure kind. So `<text>` is the node's rejection exactly when it
///   is none of those. zakurad answers a mempool refusal (a duplicate, say)
///   with -1, which takes this path after about 2.5 s of zaino retries.
///
/// zaino also retries -1 and -28 as "work queue full" and "warming up". A
/// node answering those comes out as a rejection here, which is what
/// [`crate::ZakuraRpcBackend`] does with every JSON-RPC error on the direct
/// route.
fn zaino_rejection(message: &str) -> Option<&str> {
    if let Some((_, text)) = message.split_once("validator rejected the query: ") {
        return Some(text);
    }
    let (_, text) = message.split_once("validator unreachable: ")?;
    /// `zaino_rpc::RpcError`'s texts other than a node's JSON-RPC error.
    const TRANSPORT: [&str; 6] = [
        "http error: ",
        "json error: ",
        "http status ",
        "work queue full after ",
        "null result without error",
        "response body exceeded ",
    ];
    let text = text.trim();
    let transport = TRANSPORT.iter().any(|p| text.starts_with(p))
        // `zaino_source::FailureMode`'s names, printed when there is no text.
        || matches!(text, "" | "Connection" | "Timeout" | "Auth" | "Parse")
        || text.starts_with("HttpStatus(")
        || text.starts_with("RpcError(");
    (!transport).then_some(text)
}

fn height_of(height: u64, method: &str) -> Result<BlockHeight, ChainError> {
    u32::try_from(height)
        .map(BlockHeight::from_u32)
        .map_err(|_| ChainError::Rpc(format!("{method}: height {height} does not fit a u32")))
}

/// A `BlockId` by height alone.
fn block_id(height: u32) -> BlockId {
    BlockId {
        height: u64::from(height),
        hash: vec![],
    }
}

impl<P: Parameters + Send + Sync + 'static> ChainBackend for ArtiTorLwdBackend<P> {
    fn source(&self) -> Source {
        Source::TorLwd
    }

    fn node_bounds(&self) -> BoxFuture<'_, Result<NodeBounds, ChainError>> {
        Box::pin(async move {
            let outcome = self.latest_block().await.map(|b| (b, false));
            self.status.record(outcome)
        })
    }

    fn status(&self) -> NodeStatus {
        self.status.get()
    }

    fn chain_state(&self, height: BlockHeight) -> BoxFuture<'_, Result<ChainState, ChainError>> {
        Box::pin(self.tree_state(height))
    }

    /// `GetBlock(height)`; [`ChainError::BlockUnavailable`] when the
    /// endpoint has no block at that height.
    fn block_hash(&self, height: BlockHeight) -> BoxFuture<'_, Result<[u8; 32], ChainError>> {
        Box::pin(self.call(move |mut client| async move {
            let block = client
                .get_block(block_id(u32::from(height)))
                .await
                .map_err(|s| self.block_error("GetBlock", height, s))?
                .into_inner();
            if block.height != u64::from(u32::from(height)) {
                return Err(ChainError::Rpc(format!(
                    "GetBlock({height}) at {} answered height {}",
                    self.endpoint, block.height
                )));
            }
            bytes32(&block.hash, "GetBlock: hash")
        }))
    }

    fn compact_blocks(
        &self,
        range: Range<BlockHeight>,
    ) -> BoxFuture<'_, Result<Vec<CompactBlock>, ChainError>> {
        Box::pin(self.block_range(range))
    }

    fn send_raw_transaction(&self, raw: Vec<u8>) -> BoxFuture<'_, Result<(), ChainError>> {
        Box::pin(self.send_transaction(raw))
    }

    /// `GetTransaction(txid)`: lightwalletd reports `height` 0 for the
    /// mempool, `u64::MAX` for a transaction mined only on a fork, else the
    /// main-chain height (OVERVIEW.md §4.4); NOT_FOUND (zaino: `Internal`
    /// with the node's -5) is [`TxStatus::Unknown`].
    fn transaction_status(&self, txid: [u8; 32]) -> BoxFuture<'_, Result<TxStatus, ChainError>> {
        Box::pin(async move {
            Ok(match self.raw_transaction(txid).await? {
                None | Some((_, u64::MAX)) => TxStatus::Unknown,
                Some((_, 0)) => TxStatus::InMempool,
                Some((_, h)) => TxStatus::Mined(height_of(h, "GetTransaction")?),
            })
        })
    }

    fn subtree_roots(
        &self,
        pool: ShieldedPool,
        start_index: u32,
        max_entries: u32,
    ) -> BoxFuture<'_, Result<Vec<SubtreeRoot>, ChainError>> {
        Box::pin(self.get_subtree_roots(pool, start_index, max_entries))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use transparent::address::TransparentAddress;
    use zcash_client_backend::data_api::chain::BlockCache as _;
    use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;
    use zcash_protocol::local_consensus::LocalNetwork;

    use super::*;
    use crate::testing::{FakeLightwalletd, FakeNode, FakeSubtreeRoot, h, regtest_params};
    use crate::{BlockDb, Source, fill_cache};

    fn backend(lwd: &FakeLightwalletd) -> ArtiTorLwdBackend<LocalNetwork> {
        ArtiTorLwdBackend::new(lwd.url(), Transport::Direct, regtest_params()).unwrap()
    }

    fn scan_range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(h(start)..h(end), ScanPriority::Historic)
    }

    #[test]
    fn endpoint_urls_are_checked_up_front() {
        let p = regtest_params();
        for bad in ["", "127.0.0.1:9067", "ftp://x", "grpc://x:1", "https://"] {
            let err = ArtiTorLwdBackend::new(bad, Transport::Direct, p).unwrap_err();
            assert!(matches!(err, ChainError::Rpc(_)), "{bad}: {err}");
        }
        let be = ArtiTorLwdBackend::new("https://zec.rocks:443", Transport::Direct, p).unwrap();
        assert!(!be.is_onion());
        assert_eq!(be.tor_state(), TorState::Disabled);
        assert_eq!(be.source(), Source::TorLwd);
        assert!(!be.status().connected, "nothing contacted yet");
        let dir = tempfile::tempdir().unwrap();
        let be = ArtiTorLwdBackend::new(
            "http://abcdefghijklmnop.onion:9067",
            Transport::Tor {
                tor_dir: dir.path().join("tor_cache"),
            },
            p,
        )
        .unwrap();
        assert!(be.is_onion());
        assert_eq!(be.tor_state(), TorState::NotStarted);
        assert!(
            !dir.path().join("tor_cache").exists(),
            "the Tor directory is created on first use, not at construction"
        );
    }

    #[tokio::test]
    async fn streams_the_chain_into_the_cache_tagged_as_the_tor_source() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(5);
        let paid = node.mine_with_payments(&[(TransparentAddress::PublicKeyHash([0x42; 20]), 7)]);
        node.mine(14);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let be = backend(&lwd);

        // Bounds: the endpoint's tip, nothing retained-from.
        let bounds = be.node_bounds().await.unwrap();
        assert_eq!(bounds.tip_height, h(20));
        assert_eq!(bounds.tip_hash, node.tip().1);
        assert_eq!(bounds.retained_from, h(0));
        let st = be.status();
        assert!(st.connected && st.last_error.is_empty() && !st.pruned);
        assert_eq!(
            lwd.calls(),
            vec!["GetLightdInfo", "GetLatestBlock"],
            "the chain is checked once, on connect"
        );

        // Blocks: same as the node route minus the transparent fields,
        // linked, in `fetch_batch`-sized chunks, tagged `tor-lwd`.
        let cache = BlockDb::in_memory("regtest").unwrap();
        let n = fill_cache(&be, &cache, h(1)..h(21), 7).await.unwrap();
        assert_eq!(n, 20);
        let fetched = cache.read(&scan_range(1, 21)).await.unwrap();
        assert_eq!(fetched.len(), 20);
        let from_node = node.compact_chain();
        for b in &fetched {
            let expected = &from_node[b.height as usize];
            assert_eq!(b.hash, expected.hash);
            assert_eq!(b.prev_hash, expected.prev_hash);
            assert_eq!(b.chain_metadata, expected.chain_metadata);
            assert_eq!(b.vtx.len(), expected.vtx.len());
            for (ours, theirs) in b.vtx.iter().zip(&expected.vtx) {
                assert_eq!(ours.txid, theirs.txid);
                assert!(
                    ours.vin.is_empty() && ours.vout.is_empty(),
                    "no transparent data over the Tor route"
                );
            }
        }
        assert_eq!(fetched[(paid.height - 1) as usize].vtx.len(), 2);
        let ranges = lwd
            .calls()
            .iter()
            .filter(|c| c.as_str() == "GetBlockRange")
            .count();
        assert_eq!(ranges, 3, "20 blocks in batches of 7");
        assert_eq!(
            cache.evict_source_below(Source::TorLwd, h(100)).unwrap(),
            20,
            "every row carries the Tor source"
        );

        // Hash and tree state by height, both checked against the node.
        assert_eq!(
            be.block_hash(h(9)).await.unwrap(),
            node.block(9).unwrap().hash
        );
        let cs = be.chain_state(h(10)).await.unwrap();
        assert_eq!(cs.block_height(), h(10));
        assert_eq!(cs.block_hash().0, node.block(10).unwrap().hash);
        assert!(cs.final_orchard_tree().value().is_none());
        assert!(matches!(
            be.block_hash(h(21)).await,
            Err(ChainError::BlockUnavailable { height }) if height == h(21)
        ));
        assert!(matches!(
            be.chain_state(h(21)).await,
            Err(ChainError::BlockUnavailable { height }) if height == h(21)
        ));

        // Above the tip: the first missing height, nothing cached from it.
        let err = be.compact_blocks(h(18)..h(25)).await.unwrap_err();
        assert!(
            matches!(err, ChainError::BlockUnavailable { height } if height == h(21)),
            "{err}"
        );
        assert!(be.compact_blocks(h(5)..h(5)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_skipped_forked_or_overlong_stream_is_refused() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(12);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let be = backend(&lwd);
        let cache = BlockDb::in_memory("regtest").unwrap();
        fill_cache(&be, &cache, h(1)..h(6), 100).await.unwrap();

        // A hole: height 8 follows 6.
        lwd.omit_block(7);
        let err = be.compact_blocks(h(6)..h(10)).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("height 8 where 7 was due")),
            "{err}"
        );

        // A fork inside the batch: 9 does not link to 8.
        let lwd = FakeLightwalletd::from_node(&node).await;
        lwd.fork_from(9);
        let be = backend(&lwd);
        let err = be.compact_blocks(h(6)..h(12)).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("block 9") && m.contains("does not link to block 8")),
            "{err}"
        );
        // A batch that starts on the fork is internally fine but does not
        // link to the cache: refused by the filler, nothing cached.
        let lwd = FakeLightwalletd::from_node(&node).await;
        lwd.fork_from(6);
        let be = backend(&lwd);
        let err = fill_cache(&be, &cache, h(6)..h(9), 100).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::FillError::Unlinked {
                    from: Source::TorLwd,
                    height: 6,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            cache.len().unwrap(),
            5,
            "nothing of the forked batch was cached"
        );

        // Hash length is checked too.
        let mut blocks = node.compact_chain();
        blocks[3].hash.truncate(31);
        lwd.set_blocks(blocks);
        let err = be.compact_blocks(h(3)..h(4)).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("31 bytes")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_hung_stream_times_out_and_the_next_call_reconnects() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(10);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let be = backend(&lwd).with_timeouts(LwdTimeouts {
            stream_idle: Duration::from_millis(200),
            ..LwdTimeouts::default()
        });
        be.node_bounds().await.unwrap();

        lwd.hang_after(Some(3));
        let started = std::time::Instant::now();
        let err = be.compact_blocks(h(1)..h(11)).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("stalled") && m.contains("after 3 of 10")),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));

        // The connection was dropped; the next call reconnects (another
        // GetLightdInfo) and succeeds once the endpoint behaves.
        lwd.hang_after(None);
        let blocks = be.compact_blocks(h(1)..h(11)).await.unwrap();
        assert_eq!(blocks.len(), 10);
        assert_eq!(
            lwd.calls()
                .iter()
                .filter(|c| c.as_str() == "GetLightdInfo")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn subtree_roots_for_every_pool() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(3);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let root = |i: u8| FakeSubtreeRoot {
            root: [i; 32],
            end_height: u32::from(i) * 1000,
            end_hash: node.block(1).unwrap().hash,
        };
        lwd.set_subtree_roots(ShieldedPool::Sapling, vec![root(1), root(2), root(3)]);
        lwd.set_subtree_roots(ShieldedPool::Orchard, vec![root(4)]);
        let be = backend(&lwd);

        let sapling = be.subtree_roots(ShieldedPool::Sapling, 0, 0).await.unwrap();
        assert_eq!(sapling.len(), 3);
        assert_eq!(sapling[2].index, 2);
        assert_eq!(sapling[2].root, [3; 32]);
        assert_eq!(sapling[2].end_height, h(3000));
        assert_eq!(sapling[2].pool, ShieldedPool::Sapling);
        let upstream = sapling[0].sapling().expect("a valid Sapling node");
        assert_eq!(upstream.subtree_end_height(), h(1000));
        assert!(sapling[0].orchard().is_none(), "pool is checked");

        // From an index, bounded.
        let tail = be.subtree_roots(ShieldedPool::Sapling, 1, 1).await.unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].index, 1);
        assert_eq!(tail[0].root, [2; 32]);

        let orchard = be.subtree_roots(ShieldedPool::Orchard, 0, 0).await.unwrap();
        assert_eq!(orchard.len(), 1);
        assert!(orchard[0].orchard().is_some());
        assert!(
            be.subtree_roots(ShieldedPool::Ironwood, 0, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn address_utxos_and_raw_transactions() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(3);
        let a = TransparentAddress::PublicKeyHash([0xa1; 20]);
        let b = TransparentAddress::PublicKeyHash([0xb2; 20]);
        let first = node.mine_with_payments(&[(a, 5_000), (b, 7_000)]);
        node.mine(2);
        let second = node.mine_with_payments(&[(a, 9_000)]);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let be = backend(&lwd);
        let enc = |t: &TransparentAddress| {
            crate::compact::encode_transparent_address(
                zcash_protocol::consensus::NetworkType::Regtest,
                t,
            )
        };

        let mut utxos = be.address_utxos(vec![enc(&a)], h(0)).await.unwrap();
        utxos.sort_by_key(|u| u.height);
        assert_eq!(utxos.len(), 2, "{utxos:?}");
        assert_eq!(
            (utxos[0].height, utxos[0].value_zat),
            (h(first.height), 5_000)
        );
        assert_eq!(
            (utxos[1].height, utxos[1].value_zat),
            (h(second.height), 9_000)
        );
        assert!(utxos.iter().all(|u| u.address == enc(&a)));
        // `start` filters by height; no addresses asks nothing.
        let later = be
            .address_utxos(vec![enc(&a), enc(&b)], h(second.height))
            .await
            .unwrap();
        assert_eq!(later.len(), 1);
        assert!(be.address_utxos(vec![], h(0)).await.unwrap().is_empty());

        // The raw transaction hashes to the reported txid.
        let (raw, height) = be.raw_transaction(utxos[1].txid).await.unwrap().unwrap();
        assert_eq!(height, u64::from(second.height));
        let branch = BranchId::for_height(&regtest_params(), h(second.height));
        let tx = Transaction::read(&raw[..], branch).unwrap();
        assert_eq!(*tx.txid().as_ref(), utxos[1].txid);
        let out = &tx.transparent_bundle().unwrap().vout[utxos[1].index as usize];
        assert_eq!(out.value().into_u64(), 9_000);
        assert!(be.raw_transaction([0x77; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_chain_unreachable_and_broadcasts() {
        // Mainnet lightwalletd, regtest daemon: refused on connect.
        let lwd = FakeLightwalletd::start("main", vec![], vec![]).await;
        let be = backend(&lwd);
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("serves chain \"main\"")),
            "{err}"
        );
        assert!(!be.status().connected);
        assert!(be.status().last_error.contains("serves chain"));

        // Nobody listening.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let be = ArtiTorLwdBackend::new(&url, Transport::Direct, regtest_params()).unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(matches!(&err, ChainError::Unreachable(_)), "{err}");
        assert!(be.status().last_polled.is_some());

        // Broadcast through the endpoint: accepted, then refused.
        let node = FakeNode::start(regtest_params()).await;
        node.mine(2);
        let lwd = FakeLightwalletd::from_node(&node).await;
        let be = backend(&lwd);
        let raw = node.block(2).unwrap().tx_raw[0].clone();
        be.send_raw_transaction(raw.clone()).await.unwrap();
        assert_eq!(lwd.broadcasts(), vec![raw.clone()]);
        lwd.set_reject_broadcasts(Some("tx-expired".into()));
        let err = be.send_raw_transaction(raw).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rejected(m) if m.contains("tx-expired")),
            "{err}"
        );

        // Transaction status: mined at its block, unknown otherwise.
        let mined = node.block(2).unwrap().txids[0];
        assert_eq!(
            be.transaction_status(mined).await.unwrap(),
            TxStatus::Mined(h(2))
        );
        assert_eq!(
            be.transaction_status([0x55; 32]).await.unwrap(),
            TxStatus::Unknown
        );
    }

    /// zaino 0.10.2's answers, verbatim from the runs in OVERVIEW.md §4.5.
    const ZAINO_UNKNOWN_TXID: &str = r#"RPC error: LegacyRpcError { code: -5, message: "No such mempool or main chain transaction" }"#;
    const ZAINO_DUPLICATE: &str = "InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: any transaction with the same effects will be rejected from the mempool until a chain reset: transaction was committed to the best chain";
    const ZAINO_MALFORMED: &str = "InternalServerError: error receiving data from backing node: critical error in backing block source: validator rejected the query: malformed transaction: parse error: bad tx header";
    /// A stopped node, and a restarted one zaino holds a stale cookie for:
    /// the same text.
    const ZAINO_NODE_DOWN: &str = "InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: http error: error sending request for url (http://127.0.0.1:41232/)";

    #[test]
    fn zaino_answers_are_told_apart() {
        assert!(zaino_tx_not_found(ZAINO_UNKNOWN_TXID));
        assert!(!zaino_tx_not_found(ZAINO_NODE_DOWN));
        assert!(!zaino_tx_not_found(
            r#"RPC error: LegacyRpcError { code: -50, message: "No such mempool or main chain transaction" }"#
        ));
        assert!(!zaino_tx_not_found(
            r#"RPC error: LegacyRpcError { code: -5, message: "Invalid address" }"#
        ));

        assert_eq!(
            zaino_rejection(ZAINO_DUPLICATE),
            Some(
                "any transaction with the same effects will be rejected from the mempool until a chain reset: transaction was committed to the best chain"
            )
        );
        assert_eq!(
            zaino_rejection(ZAINO_MALFORMED),
            Some("malformed transaction: parse error: bad tx header")
        );
        assert_eq!(zaino_rejection(ZAINO_NODE_DOWN), None);
        assert_eq!(zaino_rejection(ZAINO_UNKNOWN_TXID), None);
        let wrap = |t: &str| {
            format!(
                "InternalServerError: error receiving data from backing node: critical error in backing block source: validator unreachable: {t}"
            )
        };
        for transport in [
            "http status 401",
            "http status 503",
            "json error: expected value at line 1 column 1",
            "work queue full after 5 attempts",
            "null result without error",
            "response body exceeded 1048576 bytes",
            "Connection",
            "Timeout",
            "Auth",
            "HttpStatus(502)",
            "",
        ] {
            assert_eq!(zaino_rejection(&wrap(transport)), None, "{transport:?}");
        }
    }

    #[tokio::test]
    async fn zaino_internal_answers_map_like_lightwalletd_ones() {
        let node = FakeNode::start(regtest_params()).await;
        node.mine(2);
        let lwd = FakeLightwalletd::from_node(&node).await;
        lwd.set_zaino_errors(true);
        let be = backend(&lwd);

        // Unknown txid: not an error.
        assert!(be.raw_transaction([0x77; 32]).await.unwrap().is_none());
        assert_eq!(
            be.transaction_status([0x55; 32]).await.unwrap(),
            TxStatus::Unknown
        );
        let mined = node.block(2).unwrap().txids[0];
        assert_eq!(
            be.transaction_status(mined).await.unwrap(),
            TxStatus::Mined(h(2))
        );

        // The node refused the broadcast: its text, as a rejection.
        let raw = node.block(2).unwrap().tx_raw[0].clone();
        lwd.set_reject_broadcasts(Some("transaction was committed to the best chain".into()));
        let err = be.send_raw_transaction(raw.clone()).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rejected(m) if m == "transaction was committed to the best chain"),
            "{err}"
        );

        // zaino cannot reach its node: not a rejection.
        lwd.set_reject_broadcasts(Some(
            "http error: error sending request for url (http://127.0.0.1:41232/)".into(),
        ));
        let err = be.send_raw_transaction(raw).await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Rpc(m) if m.contains("validator unreachable: http error")),
            "{err}"
        );
        assert!(lwd.broadcasts().is_empty());
    }

    #[tokio::test]
    async fn tor_transport_needs_a_bootstrap_before_any_request() {
        // No network here: a bootstrap attempt cannot be exercised in unit
        // tests (TESTING.md §1, nightly tier). What can be checked is that
        // the backend creates its directory and reports the failure through
        // `TorState` rather than hanging: an unreachable directory makes the
        // bootstrap fail before Tor is touched.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let be = ArtiTorLwdBackend::new(
            "http://abcdefghijklmnop.onion:9067",
            Transport::Tor {
                tor_dir: file.join("tor_cache"),
            },
            regtest_params(),
        )
        .unwrap();
        let err = be.node_bounds().await.unwrap_err();
        assert!(
            matches!(&err, ChainError::Unreachable(m) if m.contains("cannot create")),
            "{err}"
        );
        assert!(matches!(be.tor_state(), TorState::Failed(m) if m.contains("cannot create")));
    }
}
