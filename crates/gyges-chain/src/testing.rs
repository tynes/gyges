//! Test support (`test-util` feature): synthetic transparent-only blocks that
//! `zcash_primitives::block::Block::read` accepts, and an in-process fake
//! `zakurad` JSON-RPC server speaking the subset of methods
//! [`crate::ZakuraRpcBackend`] uses, with the response shapes recorded in
//! OVERVIEW.md §4.2. Used by this crate's tests, by `gygesd`'s, and by the
//! regtest harness until a pinned `zakurad` is wired in (TESTING.md §2).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use transparent::address::{Script, TransparentAddress};
use transparent::bundle::{Authorized, Bundle, OutPoint, TxIn, TxOut};
use zcash_primitives::block::{BlockHash, BlockHeaderData};
use zcash_primitives::transaction::{
    Authorized as TxAuthorized, Transaction, TransactionData, TxVersion,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;

use crate::compact::TreeSizes;
use crate::display_hash;

/// Regtest parameters with every network upgrade active from height 1, the
/// same table `gyges_core::network::ConsensusParams::Regtest` uses.
pub fn regtest_params() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: one,
        nu6: one,
        nu6_1: one,
        nu6_2: one,
        nu6_3: one,
        nu7: None,
    }
}

/// Where the fake coinbase pays.
pub const COINBASE_ADDRESS: TransparentAddress = TransparentAddress::PublicKeyHash([0xc0; 20]);

/// A block to build: coinbase plus one payment transaction when there are
/// payments.
#[derive(Clone, Debug)]
pub struct BlockSpec {
    pub height: BlockHeight,
    pub prev_hash: [u8; 32],
    pub time: u32,
    pub payments: Vec<(TransparentAddress, u64)>,
}

/// A built block: what the fake node serves and what tests compare against.
#[derive(Clone, Debug)]
pub struct BuiltBlock {
    pub height: u32,
    /// Internal byte order.
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub time: u32,
    pub raw: Vec<u8>,
    /// Internal byte order, block order.
    pub txids: Vec<[u8; 32]>,
}

impl BlockSpec {
    pub fn new(height: BlockHeight, prev_hash: [u8; 32], time: u32) -> Self {
        Self {
            height,
            prev_hash,
            time,
            payments: Vec::new(),
        }
    }

    pub fn with_payment(mut self, to: TransparentAddress, zatoshis: u64) -> Self {
        self.payments.push((to, zatoshis));
        self
    }

    /// Serialise the block. Transparent only; the consensus branch id is the
    /// one `params` prescribes for `height`, as `Block::read` demands.
    pub fn build<P: Parameters>(&self, params: &P) -> BuiltBlock {
        let branch = BranchId::for_height(params, self.height);
        let height = u32::from(self.height);
        let mut vtx = vec![coinbase_tx(branch, height)];
        if !self.payments.is_empty() {
            vtx.push(payment_tx(branch, height, &self.payments));
        }
        let header = BlockHeaderData {
            version: 4,
            prev_block: BlockHash(self.prev_hash),
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: self.time,
            bits: 0x1f07_ffff,
            nonce: [0; 32],
            solution: Vec::new(),
        }
        .freeze()
        .expect("header serialises");
        let mut raw = Vec::new();
        header.write(&mut raw).expect("header");
        assert!(vtx.len() < 0xfd, "compact size");
        raw.push(vtx.len() as u8);
        let mut txids = Vec::new();
        for tx in &vtx {
            tx.write(&mut raw).expect("tx");
            txids.push(*tx.txid().as_ref());
        }
        BuiltBlock {
            height,
            hash: header.hash().0,
            prev_hash: self.prev_hash,
            time: self.time,
            raw,
            txids,
        }
    }
}

fn coinbase_tx(branch: BranchId, height: u32) -> Transaction {
    let bundle = Bundle {
        vin: vec![TxIn::from_parts(
            OutPoint::NULL,
            script_from_bytes(&height_push(height)),
            0xffff_ffff,
        )],
        vout: vec![TxOut::new(
            Zatoshis::const_from_u64(625_000_000),
            Script::from(COINBASE_ADDRESS.script()),
        )],
        authorization: Authorized,
    };
    // A v5 txid does not commit to the scriptSig, so the height push alone
    // would give every coinbase the same txid; consensus makes a v5 coinbase
    // set `nExpiryHeight` to its block height, which is what keeps them
    // distinct.
    transparent_only_tx(branch, BlockHeight::from_u32(height), Some(bundle))
}

fn payment_tx(
    branch: BranchId,
    height: u32,
    payments: &[(TransparentAddress, u64)],
) -> Transaction {
    // A made-up previous output; `Block::read` only insists it is not null.
    let mut prev = [0x11u8; 32];
    prev[..4].copy_from_slice(&height.to_le_bytes());
    let bundle = Bundle {
        vin: vec![TxIn::from_parts(
            OutPoint::new(prev, 0),
            Script::default(),
            0xffff_ffff,
        )],
        vout: payments
            .iter()
            .map(|(to, zat)| TxOut::new(Zatoshis::const_from_u64(*zat), Script::from(to.script())))
            .collect(),
        authorization: Authorized,
    };
    transparent_only_tx(branch, BlockHeight::from_u32(0), Some(bundle))
}

fn transparent_only_tx(
    branch: BranchId,
    expiry_height: BlockHeight,
    bundle: Option<Bundle<Authorized>>,
) -> Transaction {
    TransactionData::<TxAuthorized>::from_parts(
        TxVersion::V5,
        branch,
        0,
        expiry_height,
        bundle,
        None,
        None,
        None,
    )
    .freeze()
    .expect("transparent-only v5 transaction")
}

/// A `Script` from raw bytes, through the length-prefixed reader so this
/// module needs no direct `zcash_script` dependency.
fn script_from_bytes(bytes: &[u8]) -> Script {
    let mut encoded = Vec::with_capacity(bytes.len() + 3);
    assert!(bytes.len() < 0xfd);
    encoded.push(bytes.len() as u8);
    encoded.extend_from_slice(bytes);
    Script::read(Cursor::new(encoded)).expect("script")
}

/// The BIP 34 height push a coinbase scriptSig starts with (minimal
/// `CScriptNum` encoding).
pub fn height_push(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut le: Vec<u8> = height.to_le_bytes().to_vec();
            while le.len() > 1 && le[le.len() - 1] == 0 && le[le.len() - 2] & 0x80 == 0 {
                le.pop();
            }
            if le[le.len() - 1] & 0x80 != 0 {
                le.push(0);
            }
            let mut out = vec![le.len() as u8];
            out.extend(le);
            out
        }
    }
}

/// Hex of an empty `CommitmentTree` as `write_commitment_tree` emits it:
/// no left leaf, no right leaf, zero parents.
pub const EMPTY_TREE_HEX: &str = "000000";

struct State {
    chain_name: &'static str,
    params: DynParams,
    blocks: BTreeMap<u32, BuiltBlock>,
    prune_height: Option<u32>,
    cookie: Option<String>,
    tree_sizes: Option<TreeSizes>,
    calls: Vec<String>,
    /// Bumped by `invalidate_from`, so re-mined blocks differ from the
    /// ones they replace.
    forks: u32,
}

impl State {
    fn tip(&self) -> (u32, [u8; 32]) {
        let (h, b) = self.blocks.iter().next_back().expect("genesis exists");
        (*h, b.hash)
    }

    fn pruned(&self, height: u32) -> bool {
        height != 0 && self.prune_height.is_some_and(|p| height < p)
    }

    fn append(&mut self, payments: &[(TransparentAddress, u64)]) -> BuiltBlock {
        let (tip, prev) = self.tip();
        let height = tip + 1;
        let time = 1_700_000_000 + height * 75 + self.forks * 7;
        let spec = BlockSpec {
            height: BlockHeight::from_u32(height),
            prev_hash: prev,
            time,
            payments: payments.to_vec(),
        };
        let built = spec.build(&self.params);
        self.blocks.insert(height, built.clone());
        built
    }
}

/// Type-erased `Parameters` (the trait requires `Sized`, so no `dyn`), so
/// the server state is not generic.
#[derive(Clone)]
struct DynParams {
    network_type: zcash_protocol::consensus::NetworkType,
    activation:
        Arc<dyn Fn(zcash_protocol::consensus::NetworkUpgrade) -> Option<BlockHeight> + Send + Sync>,
}

impl DynParams {
    fn new<P: Parameters + Send + Sync + 'static>(params: P) -> Self {
        Self {
            network_type: params.network_type(),
            activation: Arc::new(move |nu| params.activation_height(nu)),
        }
    }
}

impl Parameters for DynParams {
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        self.network_type
    }

    fn activation_height(
        &self,
        nu: zcash_protocol::consensus::NetworkUpgrade,
    ) -> Option<BlockHeight> {
        (self.activation)(nu)
    }
}

/// An in-process `zakurad` stand-in. Dropping it stops the server.
pub struct FakeNode {
    url: String,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for FakeNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeNode").field("url", &self.url).finish()
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeNode {
    /// Start listening on a loopback port with a genesis block (height 0).
    pub async fn start<P: Parameters + Clone + Send + Sync + 'static>(params: P) -> Self {
        let chain_name = match params.network_type() {
            zcash_protocol::consensus::NetworkType::Main => "main",
            zcash_protocol::consensus::NetworkType::Test => "test",
            zcash_protocol::consensus::NetworkType::Regtest => "regtest",
        };
        let params = DynParams::new(params);
        let genesis =
            BlockSpec::new(BlockHeight::from_u32(0), [0; 32], 1_700_000_000).build(&params);
        let mut blocks = BTreeMap::new();
        blocks.insert(0, genesis);
        let state = Arc::new(Mutex::new(State {
            chain_name,
            params,
            blocks,
            prune_height: None,
            cookie: None,
            tree_sizes: None,
            calls: Vec::new(),
            forks: 0,
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let st = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| handle(st.clone(), req));
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            url: format!("http://{addr}"),
            state,
            task,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Append `n` empty blocks; returns the new tip height.
    pub fn mine(&self, n: u32) -> u32 {
        let mut st = self.lock();
        for _ in 0..n {
            st.append(&[]);
        }
        st.tip().0
    }

    /// Append one block whose second transaction pays `payments`.
    pub fn mine_with_payments(&self, payments: &[(TransparentAddress, u64)]) -> BuiltBlock {
        self.lock().append(payments)
    }

    /// Drop every block at or above `height` (the first step of a reorg;
    /// mine again to grow a different chain).
    pub fn invalidate_from(&self, height: u32) {
        assert!(height > 0, "cannot invalidate genesis");
        let mut st = self.lock();
        st.blocks.retain(|h, _| *h < height);
        st.forks += 1;
    }

    /// `pruneheight`: bodies below it answer `-8 Block not found`.
    pub fn set_prune_height(&self, height: Option<u32>) {
        self.lock().prune_height = height;
    }

    /// Require `Authorization: Basic __cookie__:<secret>` on every request.
    pub fn set_cookie(&self, secret: Option<String>) {
        self.lock().cookie = secret;
    }

    /// Write the node's cookie file as `zakurad` would (`__cookie__:<secret>`).
    pub fn write_cookie_file(&self, path: &Path) {
        let secret = self.lock().cookie.clone().expect("set_cookie first");
        std::fs::write(path, format!("__cookie__:{secret}")).expect("write cookie");
    }

    /// Tree sizes reported in `getblock(h, 1).trees` for every block
    /// (`None`: omitted, as a node with empty trees does).
    pub fn set_tree_sizes(&self, sizes: Option<TreeSizes>) {
        self.lock().tree_sizes = sizes;
    }

    /// Method names of every request served so far.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn tip(&self) -> (u32, [u8; 32]) {
        self.lock().tip()
    }

    pub fn block(&self, height: u32) -> Option<BuiltBlock> {
        self.lock().blocks.get(&height).cloned()
    }
}

async fn handle(
    state: Arc<Mutex<State>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let auth = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = req.into_body().collect().await?.to_bytes();
    let request: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Ok(plain(StatusCode::BAD_REQUEST, "")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let params = request
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    st.calls.push(method.clone());
    if let Some(secret) = &st.cookie {
        let expected = format!("__cookie__:{secret}");
        let presented = auth
            .as_deref()
            .and_then(|a| a.split_whitespace().nth(1))
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok());
        if presented.as_deref() != Some(expected.as_str()) {
            // Zakura answers an empty 401.
            return Ok(plain(StatusCode::UNAUTHORIZED, ""));
        }
    }

    let outcome = dispatch(&st, &method, &params);
    drop(st);
    let body = match outcome {
        Ok(result) => json!({ "result": result, "error": Value::Null, "id": id }),
        Err((code, message)) => json!({
            "result": Value::Null,
            "error": { "code": code, "message": message },
            "id": id
        }),
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("response"))
}

fn plain(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("response")
}

type RpcResult = Result<Value, (i64, String)>;

/// Zebra takes `hash_or_height` as a string; accept a number as well.
fn height_param(st: &State, v: Option<&Value>) -> Result<u32, (i64, String)> {
    let v = v.ok_or((-32602, "missing hash_or_height".to_string()))?;
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).map_err(|_| (-8, "Block not found".into()));
    }
    let s = v.as_str().ok_or((-8, "Block not found".to_string()))?;
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    if s.len() == 64 {
        let shown = s.to_ascii_lowercase();
        return st
            .blocks
            .iter()
            .find(|(_, b)| display_hash(&b.hash) == shown)
            .map(|(h, _)| *h)
            .ok_or((-8, "Block not found".into()));
    }
    Err((-8, "Block not found".into()))
}

fn dispatch(st: &State, method: &str, params: &[Value]) -> RpcResult {
    let (tip, tip_hash) = st.tip();
    match method {
        "getblockchaininfo" => {
            let mut info = json!({
                "chain": st.chain_name,
                "blocks": tip,
                "headers": tip,
                "bestblockhash": display_hash(&tip_hash),
                "estimatedheight": tip,
                "size_on_disk": 0,
                "chainwork": 0,
                "commitments": 0,
                "difficulty": 1.0,
                "verificationprogress": 1.0,
                "pruned": st.prune_height.is_some(),
                "valuePools": [],
                "upgrades": {},
                "consensus": { "chaintip": "c8e71055", "nextblock": "c8e71055" },
            });
            if let Some(p) = st.prune_height {
                info["pruneheight"] = json!(p);
            }
            Ok(info)
        }
        "getblockhash" => {
            let h = params
                .first()
                .and_then(Value::as_i64)
                .ok_or((-32602, "missing height".to_string()))?;
            if h < 0 {
                return Err((-32602, "Provided index is not valid".into()));
            }
            let h = u32::try_from(h)
                .map_err(|_| (-32602, "Provided index is not valid".to_string()))?;
            if h > tip {
                return Err((
                    -32602,
                    "Provided index is greater than the current tip".into(),
                ));
            }
            Ok(json!(display_hash(&st.blocks[&h].hash)))
        }
        "getblock" => {
            let h = height_param(st, params.first())?;
            let verbosity = params.get(1).and_then(Value::as_u64).unwrap_or(1);
            let Some(block) = st.blocks.get(&h) else {
                return Err((-8, "Block not found".into()));
            };
            match verbosity {
                0 => {
                    if st.pruned(h) {
                        return Err((-8, "Block not found".into()));
                    }
                    Ok(json!(hex::encode(&block.raw)))
                }
                1 => {
                    let mut trees = serde_json::Map::new();
                    if let Some(s) = st.tree_sizes {
                        if s.sapling > 0 {
                            trees.insert("sapling".into(), json!({ "size": s.sapling }));
                        }
                        if s.orchard > 0 {
                            trees.insert("orchard".into(), json!({ "size": s.orchard }));
                        }
                        if s.ironwood > 0 {
                            trees.insert("ironwood".into(), json!({ "size": s.ironwood }));
                        }
                    }
                    let mut obj = json!({
                        "hash": display_hash(&block.hash),
                        "confirmations": tip - h + 1,
                        "size": block.raw.len(),
                        "height": h,
                        "version": 4,
                        "merkleroot": "00".repeat(32),
                        "nTx": block.txids.len(),
                        "tx": block.txids.iter().map(|t| display_hash(t)).collect::<Vec<_>>(),
                        "time": block.time,
                        "trees": Value::Object(trees),
                    });
                    if h > 0 {
                        obj["previousblockhash"] = json!(display_hash(&block.prev_hash));
                    }
                    if let Some(next) = st.blocks.get(&(h + 1)) {
                        obj["nextblockhash"] = json!(display_hash(&next.hash));
                    }
                    Ok(obj)
                }
                _ => Err((-8, "invalid verbosity value".into())),
            }
        }
        "z_gettreestate" => {
            let h = height_param(st, params.first())?;
            let Some(block) = st.blocks.get(&h) else {
                return Err((-8, "the requested block is not in the main chain".into()));
            };
            if st.pruned(h) {
                return Err((-8, "the requested block is not in the main chain".into()));
            }
            // Explicit empty frontiers for every pool (all are active from
            // height 1 on regtest); `sprout` is the `{}` an inactive pool gets.
            let empty = json!({ "commitments": { "finalRoot": "00".repeat(32), "finalState": EMPTY_TREE_HEX } });
            Ok(json!({
                "hash": display_hash(&block.hash),
                "height": h,
                "time": block.time,
                "sprout": { "commitments": {} },
                "sapling": empty,
                "orchard": empty,
                "ironwood": empty,
            }))
        }
        _ => Err((-32601, format!("Method not found: {method}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_push_is_minimal() {
        assert_eq!(height_push(0), vec![0x00]);
        assert_eq!(height_push(1), vec![0x51]);
        assert_eq!(height_push(16), vec![0x60]);
        assert_eq!(height_push(17), vec![0x01, 0x11]);
        assert_eq!(height_push(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(height_push(1000), vec![0x02, 0xe8, 0x03]);
        assert_eq!(height_push(2_650_000), vec![0x03, 0x90, 0x6f, 0x28]);
    }

    #[test]
    fn empty_tree_hex_is_an_empty_frontier() {
        let state = zcash_client_backend::proto::service::TreeState {
            network: "test".into(),
            height: 3,
            hash: "00".repeat(32),
            time: 0,
            sapling_tree: EMPTY_TREE_HEX.into(),
            orchard_tree: EMPTY_TREE_HEX.into(),
            ironwood_tree: String::new(),
        };
        let cs = state.to_chain_state().unwrap();
        assert!(cs.final_sapling_tree().value().is_none());
        assert!(cs.final_orchard_tree().value().is_none());
        assert!(cs.final_ironwood_tree().value().is_none());
    }

    #[test]
    fn coinbase_txids_differ_per_height() {
        let params = regtest_params();
        let a = BlockSpec::new(BlockHeight::from_u32(10), [0; 32], 1).build(&params);
        let b = BlockSpec::new(BlockHeight::from_u32(11), a.hash, 2).build(&params);
        assert_ne!(a.txids[0], b.txids[0]);
    }

    #[tokio::test]
    async fn fake_node_grows_links_and_prunes() {
        let node = FakeNode::start(regtest_params()).await;
        assert_eq!(node.tip().0, 0);
        assert_eq!(node.mine(3), 3);
        let b3 = node.block(3).unwrap();
        assert_eq!(b3.prev_hash, node.block(2).unwrap().hash);
        node.invalidate_from(2);
        assert_eq!(node.tip().0, 1);
        let b2 = node.mine_with_payments(&[(TransparentAddress::ScriptHash([1; 20]), 5)]);
        assert_eq!(b2.height, 2);
        assert_eq!(b2.txids.len(), 2);
        // An empty re-mined block also differs from the one it replaced.
        node.invalidate_from(2);
        let b2_again = node.mine(1);
        assert_eq!(b2_again, 2);
        assert_ne!(node.block(2).unwrap().hash, b2.hash);
        assert_ne!(node.block(2).unwrap().hash, b3.prev_hash);
    }
}
