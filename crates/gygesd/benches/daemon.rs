//! Whole-daemon sync timings for `docs/testing.md` §9: an in-process
//! `gygesd` on an in-memory node (`gyges_core::testing::MemChain`) serving a
//! deterministic synthetic chain, driven over its Unix socket like the CLI.
//!
//! ```console
//! cargo bench -p gygesd --bench daemon
//! GYGES_BENCH_BLOCKS=10000 GYGES_BENCH_RUNS=5 cargo bench -p gygesd --bench daemon
//! ```
//!
//! Two scenarios:
//!
//! * **time to synced:** restore 1, 4 or 8 keys at height 1, then raise the
//!   node's tip to the end of the chain and time until every key's
//!   `WaitSync(SCANNED)` returns. The node answers instantly or after a fixed
//!   delay per request (a stand-in for the RPC round trip; a batch of blocks
//!   pays it once per eight blocks, as the node backend's ordered fetches
//!   do).
//! * **reads under sync:** the same with two keys on a longer chain, while
//!   reader clients call `GetInfo` (sent on every CLI connect), `ListKeys`
//!   and `GetBalance` in a loop; then the same readers for as long again with
//!   the daemon idle. Samples from every run are pooled. The percentiles show
//!   how long a read waits behind sync, the call rates how much reading it
//!   allows.
//!
//! Not Criterion: one run is seconds long and the interesting number for
//! reads is a tail latency. Results print as a table and are written to
//! `target/bench-results/daemon.json`. Environment: `GYGES_BENCH_BLOCKS`
//! (default 3,000), `GYGES_BENCH_READ_BLOCKS` (10,000, the reads scenario's
//! chain), `GYGES_BENCH_RUNS` (3), `GYGES_BENCH_READERS` (8),
//! `GYGES_BENCH_CONFIG` (TOML appended to the daemon's config, e.g.
//! `[cache]\nscan_batch = 500`).

#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gyges_core::testing::{ChainSpec, MemChain, SyntheticChain, TestKey};
use gyges_core::{Home, Network, perms};
use gyges_proto::uds;
use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    GetBalanceRequest, GetInfoRequest, ListKeysRequest, RestoreKeyRequest, ShutdownRequest,
    SyncTarget, WaitSyncRequest,
};
use gygesd::{Daemon, Options};
use tokio_stream::StreamExt as _;
use tonic::transport::Channel;

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Running {
    _home: tempfile::TempDir,
    socket: PathBuf,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(chain: Arc<MemChain>) -> Running {
    let dir = tempfile::tempdir().unwrap();
    perms::set_mode(dir.path(), 0o700).unwrap();
    let home = Home::new(dir.path());
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(&net).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::create_private_file(&home.config_path(Network::Regtest)).unwrap();
    // A low scrypt work factor keeps the restores out of the way; a
    // one-second poll is the floor, and every wait below wakes the
    // scheduler anyway.
    let mut config = "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
                      [mempool]\nscan = false\n"
        .to_string();
    if let Ok(extra) = std::env::var("GYGES_BENCH_CONFIG") {
        config.push_str(&extra.replace("\\n", "\n"));
        config.push('\n');
    }
    std::fs::write(home.config_path(Network::Regtest), config).unwrap();

    let mut opts = Options::new(home, Network::Regtest);
    opts.chain = Some(chain);
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..1_000 {
        if uds::probe(&socket).await.is_ok() {
            return Running {
                _home: dir,
                socket,
                task,
            };
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon did not open {}", socket.display());
}

async fn client(socket: &PathBuf) -> GygesClient<Channel> {
    GygesClient::new(uds::connect(socket).await.expect("connect"))
}

async fn stop(running: Running) {
    let mut c = client(&running.socket).await;
    let _ = c.shutdown(ShutdownRequest { graceful: false }).await;
    let _ = tokio::time::timeout(Duration::from_secs(30), running.task).await;
}

fn key_id(i: usize) -> String {
    format!("k{i}")
}

/// A daemon on a fresh `blocks`-block chain paying `keys` keys, with every
/// key restored at height 1 while the node's tip is still at 1.
async fn setup(blocks: u32, keys: usize, latency: Duration) -> (Running, Arc<MemChain>) {
    let test_keys: Vec<TestKey> = (0..keys)
        .map(|i| TestKey::new(Network::Regtest, i as u8))
        .collect();
    let recipients: Vec<_> = test_keys.iter().map(|k| k.recipient).collect();
    let chain = SyntheticChain::generate(ChainSpec::sparse(blocks), &recipients);
    let node = Arc::new(MemChain::new(Arc::new(chain)).with_latency(latency));
    node.set_tip(1);
    let running = start(node.clone()).await;
    let mut c = client(&running.socket).await;
    for (i, k) in test_keys.iter().enumerate() {
        c.restore_key(RestoreKeyRequest {
            key_id: key_id(i),
            mnemonic: k.mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 1,
            ..Default::default()
        })
        .await
        .expect("restore");
    }
    wait_scanned(&running.socket, keys).await;
    (running, node)
}

/// `WaitSync(SCANNED)` for every key at once; returns when all have ended.
async fn wait_scanned(socket: &PathBuf, keys: usize) {
    let mut waits = Vec::new();
    for i in 0..keys {
        let mut c = client(socket).await;
        waits.push(tokio::spawn(async move {
            let mut stream = c
                .wait_sync(WaitSyncRequest {
                    key_id: key_id(i),
                    until: SyncTarget::Scanned as i32,
                    ..Default::default()
                })
                .await
                .expect("wait_sync")
                .into_inner();
            while let Some(p) = stream.next().await {
                if p.expect("progress").done {
                    return;
                }
            }
        }));
    }
    for w in waits {
        w.await.expect("waiter");
    }
}

#[derive(Debug, serde::Serialize)]
struct SyncResult {
    blocks: u32,
    keys: usize,
    latency_ms: u64,
    runs_secs: Vec<f64>,
    median_secs: f64,
    blocks_per_sec_per_key: f64,
}

async fn time_to_synced(blocks: u32, keys: usize, latency: Duration, runs: u32) -> SyncResult {
    let mut runs_secs = Vec::new();
    for _ in 0..runs {
        let (running, node) = setup(blocks, keys, latency).await;
        let t0 = Instant::now();
        node.set_tip(blocks);
        wait_scanned(&running.socket, keys).await;
        runs_secs.push(t0.elapsed().as_secs_f64());
        stop(running).await;
    }
    let mut sorted = runs_secs.clone();
    sorted.sort_by(f64::total_cmp);
    let median_secs = sorted[sorted.len() / 2];
    SyncResult {
        blocks,
        keys,
        latency_ms: latency.as_millis() as u64,
        runs_secs,
        median_secs,
        blocks_per_sec_per_key: f64::from(blocks) / median_secs,
    }
}

#[derive(Debug, Default, serde::Serialize)]
struct Latencies {
    calls: usize,
    p50_ms: f64,
    p90_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

fn summarize(mut samples: Vec<Duration>) -> Latencies {
    if samples.is_empty() {
        return Latencies::default();
    }
    samples.sort();
    let at = |q: f64| {
        let i = ((samples.len() as f64 - 1.0) * q).round() as usize;
        samples[i].as_secs_f64() * 1e3
    };
    Latencies {
        calls: samples.len(),
        p50_ms: at(0.50),
        p90_ms: at(0.90),
        p95_ms: at(0.95),
        p99_ms: at(0.99),
        max_ms: at(1.0),
    }
}

#[derive(Debug, Default)]
struct Samples {
    get_info: Vec<Duration>,
    list_keys: Vec<Duration>,
    get_balance: Vec<Duration>,
}

impl Samples {
    fn len(&self) -> usize {
        self.get_info.len() + self.list_keys.len() + self.get_balance.len()
    }

    fn extend(&mut self, other: Samples) {
        self.get_info.extend(other.get_info);
        self.list_keys.extend(other.list_keys);
        self.get_balance.extend(other.get_balance);
    }
}

/// One reader: `GetInfo`, `ListKeys`, `GetBalance` round-robin until `stop`
/// is set.
async fn reader(socket: PathBuf, keys: usize, stop: Arc<AtomicBool>) -> Samples {
    let mut c = client(&socket).await;
    let mut s = Samples::default();
    let mut n = 0usize;
    while !stop.load(Ordering::Relaxed) {
        let t = Instant::now();
        match n % 3 {
            0 => {
                c.get_info(GetInfoRequest {}).await.expect("get_info");
                s.get_info.push(t.elapsed());
            }
            1 => {
                c.list_keys(ListKeysRequest {}).await.expect("list_keys");
                s.list_keys.push(t.elapsed());
            }
            _ => {
                c.get_balance(GetBalanceRequest {
                    key_id: key_id(n % keys),
                    min_confirmations: 0,
                })
                .await
                .expect("get_balance");
                s.get_balance.push(t.elapsed());
            }
        }
        n += 1;
    }
    s
}

#[derive(Debug, serde::Serialize)]
struct ReadResult {
    blocks: u32,
    keys: usize,
    readers: usize,
    runs: u32,
    /// Summed over the runs; the idle phase lasts as long again.
    sync_secs: f64,
    calls_per_sec_during_sync: f64,
    calls_per_sec_idle: f64,
    during_sync: [(&'static str, Latencies); 3],
    idle: [(&'static str, Latencies); 3],
}

fn by_rpc(s: Samples) -> [(&'static str, Latencies); 3] {
    [
        ("GetInfo", summarize(s.get_info)),
        ("ListKeys", summarize(s.list_keys)),
        ("GetBalance", summarize(s.get_balance)),
    ]
}

/// `readers` readers until `phase` resolves; their pooled samples.
async fn read_while(
    socket: &std::path::Path,
    keys: usize,
    readers: usize,
    phase: impl std::future::Future<Output = ()>,
) -> Samples {
    let stop = Arc::new(AtomicBool::new(false));
    let tasks: Vec<_> = (0..readers)
        .map(|_| tokio::spawn(reader(socket.to_path_buf(), keys, stop.clone())))
        .collect();
    phase.await;
    stop.store(true, Ordering::Relaxed);
    let mut all = Samples::default();
    for t in tasks {
        all.extend(t.await.expect("reader"));
    }
    all
}

async fn reads_under_sync(blocks: u32, keys: usize, readers: usize, runs: u32) -> ReadResult {
    let (mut during, mut idle) = (Samples::default(), Samples::default());
    let mut sync_secs = 0.0;
    for _ in 0..runs {
        let (running, node) = setup(blocks, keys, Duration::ZERO).await;
        let t0 = Instant::now();
        let synced = async {
            node.set_tip(blocks);
            wait_scanned(&running.socket, keys).await;
        };
        during.extend(read_while(&running.socket, keys, readers, synced).await);
        let took = t0.elapsed();
        sync_secs += took.as_secs_f64();
        // As long again with nothing scanning.
        idle.extend(read_while(&running.socket, keys, readers, tokio::time::sleep(took)).await);
        stop(running).await;
    }
    ReadResult {
        blocks,
        keys,
        readers,
        runs,
        sync_secs,
        calls_per_sec_during_sync: during.len() as f64 / sync_secs,
        calls_per_sec_idle: idle.len() as f64 / sync_secs,
        during_sync: by_rpc(during),
        idle: by_rpc(idle),
    }
}

fn results_path() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    target.join("bench-results").join("daemon.json")
}

fn main() {
    // `cargo test --benches` and `cargo bench -- --test` pass `--test`: a
    // smoke run, not a measurement.
    let smoke = std::env::args().any(|a| a == "--test");
    let blocks = if smoke {
        200
    } else {
        env_u32("GYGES_BENCH_BLOCKS", 3_000)
    };
    let runs = if smoke {
        1
    } else {
        env_u32("GYGES_BENCH_RUNS", 3)
    };
    let read_blocks = if smoke {
        200
    } else {
        env_u32("GYGES_BENCH_READ_BLOCKS", 10_000)
    };
    let readers = env_u32("GYGES_BENCH_READERS", 8) as usize;
    let rt = tokio::runtime::Runtime::new().expect("a runtime");
    rt.block_on(async {
        let mut sync = Vec::new();
        let cases: &[(usize, u64)] = if smoke {
            &[(1, 0)]
        } else {
            &[(1, 0), (1, 5), (4, 0), (4, 5), (8, 0)]
        };
        for &(keys, latency_ms) in cases {
            let r = time_to_synced(blocks, keys, Duration::from_millis(latency_ms), runs).await;
            println!(
                "time-to-synced  blocks={:<6} keys={:<2} latency={:>2}ms  median {:>7.2}s  ({:>7.0} blocks/s per key)  runs {:?}",
                r.blocks,
                r.keys,
                r.latency_ms,
                r.median_secs,
                r.blocks_per_sec_per_key,
                r.runs_secs
                    .iter()
                    .map(|s| format!("{s:.2}"))
                    .collect::<Vec<_>>()
            );
            sync.push(r);
        }
        let reads = reads_under_sync(read_blocks, 2, readers, runs).await;
        println!(
            "reads-under-sync blocks={} keys={} readers={} runs={} (sync took {:.2}s in all; {:.0} calls/s during sync, {:.0} idle)",
            reads.blocks,
            reads.keys,
            reads.readers,
            reads.runs,
            reads.sync_secs,
            reads.calls_per_sec_during_sync,
            reads.calls_per_sec_idle
        );
        for (label, rows) in [("during sync", &reads.during_sync), ("idle", &reads.idle)] {
            for (rpc, l) in rows {
                println!(
                    "  {label:<11} {rpc:<10} calls {:>6}  p50 {:>8.2}ms  p90 {:>8.2}ms  p95 {:>8.2}ms  p99 {:>8.2}ms  max {:>8.2}ms",
                    l.calls, l.p50_ms, l.p90_ms, l.p95_ms, l.p99_ms, l.max_ms
                );
            }
        }
        if !smoke {
            let path = results_path();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let json = serde_json::json!({ "time_to_synced": sync, "reads_under_sync": reads });
            std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
            println!("wrote {}", path.display());
        }
    });
}
