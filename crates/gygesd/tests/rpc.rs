//! In-process daemon against a temporary `GYGES_HOME`, driven with the
//! generated client over the Unix socket (THREAT_MODEL.md §5 rows for the
//! peer check, socket mode and permission sweep; API.md §8 air-gapped list).

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gyges_chain::testing::{FakeLightwalletd, FakeNode, regtest_params};
use gyges_core::birthday::FixedChain;
use gyges_core::{Home, Network, perms};
use gyges_proto::uds;
use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    AbortSigningSessionRequest, ErrorReason, ExportSeedRequest, ExportUfvkRequest,
    GetBalanceRequest, GetBalanceResponse, GetInfoRequest, GetSyncStatusRequest, GygesError,
    ImportKeystoneRequest, InitKeyRequest, InitKeyResponse, ListKeysRequest,
    ListSigningSessionsRequest, LockKeyRequest, Proposal, RestoreKeyRequest, RunSyncRequest,
    SendEvent, SendTransactionRequest, SessionStatus, ShieldFundsRequest, ShutdownRequest,
    SignatureKind, SigningMode, StreamLogsRequest, SyncProgress, SyncState, SyncTarget,
    UnlockKeyRequest, UnlockScope, WaitSyncRequest, send_event,
};
use gygesd::{Daemon, DaemonState, LogHub, Options};
use tokio_stream::StreamExt as _;
use tonic::transport::Channel;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::WalletRead as _;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::BlockHeight;

struct Running {
    _home: tempfile::TempDir,
    socket: PathBuf,
    pid: PathBuf,
    state: Arc<DaemonState>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// A low scrypt work factor keeps `InitKey` / `RestoreKey` fast here
/// (production uses the default of 20); a one-second poll keeps the sync
/// tests short.
const TEST_CONFIG: &str =
    "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n";

/// [`TEST_CONFIG`] plus `min_confirmations = 1`, so a payment is spendable
/// once it is mined (the fake-node send tests mine one block at a time).
const ONE_CONF_CONFIG: &str = "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
     [policy]\nmin_confirmations = 1\n";

fn fresh_home() -> (tempfile::TempDir, Home) {
    fresh_home_with(TEST_CONFIG)
}

fn fresh_home_with(config: &str) -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    perms::set_mode(dir.path(), 0o700).unwrap();
    let home = Home::new(dir.path());
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(&net).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::create_private_file(&home.config_path(Network::Regtest)).unwrap();
    std::fs::write(home.config_path(Network::Regtest), config).unwrap();
    (dir, home)
}

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
fn known_mnemonic() -> String {
    "abandon ".repeat(23) + "art"
}

/// One log hub for the whole test binary, fed by the production capture
/// layer (`info` and every audit event, like a default daemon); every daemon
/// started here shares it, so tests filter by their own key ids.
/// `RUST_LOG=debug cargo test -- --nocapture` shows the daemon's tracing.
fn test_hub() -> Arc<LogHub> {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::filter::FilterExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    static HUB: std::sync::OnceLock<Arc<LogHub>> = std::sync::OnceLock::new();
    HUB.get_or_init(|| {
        let hub = Arc::new(LogHub::default());
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
            )
            .with(
                hub.layer().with_filter(
                    tracing_subscriber::filter::filter_fn(|m| {
                        m.target() == gygesd::keys::AUDIT_TARGET
                    })
                    .or(tracing_subscriber::filter::LevelFilter::INFO),
                ),
            )
            .try_init();
        hub
    })
    .clone()
}

async fn start(configure: impl FnOnce(&mut Options)) -> Running {
    start_with(TEST_CONFIG, configure).await
}

async fn start_with(config: &str, configure: impl FnOnce(&mut Options)) -> Running {
    let (dir, _) = fresh_home_with(config);
    start_in(dir, configure).await
}

/// Start a daemon on an existing home: a restart, once the previous
/// daemon's task has returned.
async fn start_in(dir: tempfile::TempDir, configure: impl FnOnce(&mut Options)) -> Running {
    let home = Home::new(dir.path());
    let mut opts = Options::new(home.clone(), Network::Regtest);
    opts.log_hub = Some(test_hub());
    configure(&mut opts);
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let pid = home.pid_path(Network::Regtest);
    let state = daemon.state.clone();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            return Running {
                _home: dir,
                socket,
                pid,
                state,
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

/// A fake node with `blocks` blocks mined.
async fn mined_node(blocks: u32) -> FakeNode {
    let node = FakeNode::start(regtest_params()).await;
    node.mine(blocks);
    node
}

/// A daemon on `node` under `config`, and a client of it.
async fn start_on(node: &FakeNode, config: &str) -> (Running, GygesClient<Channel>) {
    let url = node.url().to_string();
    let running = start_with(config, |o| o.zakura_rpc = Some(url)).await;
    let c = client(&running.socket).await;
    (running, c)
}

/// [`start_on`] with `lwd` as the fallback endpoint, reached directly.
async fn start_with_fallback(
    node: &FakeNode,
    lwd: &FakeLightwalletd,
    config: &str,
) -> (Running, GygesClient<Channel>) {
    let (url, lwd_url) = (node.url().to_string(), lwd.url().to_string());
    let running = start_with(config, |o| {
        o.zakura_rpc = Some(url);
        o.fallback_lwd = Some(lwd_url);
        o.no_tor = true;
    })
    .await;
    let c = client(&running.socket).await;
    (running, c)
}

/// The typed reason of a refusal.
fn reason(err: &tonic::Status) -> ErrorReason {
    GygesError::from_status(err).expect("typed error").reason()
}

/// `InitKey` of `key_id` under the passphrase "pw".
async fn init_key(c: &mut GygesClient<Channel>, key_id: &str) -> InitKeyResponse {
    c.init_key(InitKeyRequest {
        key_id: key_id.into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("init_key {key_id}: {e:?}"))
    .into_inner()
}

/// A daemon-scoped `UnlockKey` of `key_id` with the passphrase "pw".
async fn unlock_daemon(c: &mut GygesClient<Channel>, key_id: &str) {
    c.unlock_key(UnlockKeyRequest {
        key_id: key_id.into(),
        passphrase: "pw".into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    })
    .await
    .unwrap_or_else(|e| panic!("unlock_key {key_id}: {e:?}"));
}

/// The transparent receivers of `key_id`'s account, in the wallet's order.
fn transparent_receivers(state: &DaemonState, key_id: &str) -> Vec<TransparentAddress> {
    let key = state.registry.resolve(key_id).unwrap();
    let w = key.wallet().unwrap();
    let account = w.get_account_ids().unwrap()[0];
    w.get_transparent_receivers(account, false, false)
        .unwrap()
        .into_keys()
        .collect()
}

/// The first of `key_id`'s transparent receivers.
fn transparent_receiver(state: &DaemonState, key_id: &str) -> TransparentAddress {
    transparent_receivers(state, key_id)
        .into_iter()
        .next()
        .expect("a transparent receiver")
}

/// `z` zatoshis, as a request's amount.
fn zats(z: i64) -> Option<gyges_proto::v1::Amount> {
    Some(gyges_proto::v1::Amount {
        value: Some(gyges_proto::v1::amount::Value::Zatoshis(z)),
    })
}

/// A regtest P2PKH address of no key here (pubkey hash `0x42…`): the
/// transparent recipient of the send tests.
fn t_recipient() -> String {
    zcash_keys::address::Address::Transparent(TransparentAddress::PublicKeyHash([0x42; 20]))
        .encode(&Network::Regtest.consensus_params())
}

/// A `RestoreKey` of [`known_mnemonic`] as `key_id` under "pw", born at
/// `birthday_height` (0: the default).
fn restore_req(key_id: &str, birthday_height: u32) -> RestoreKeyRequest {
    RestoreKeyRequest {
        key_id: key_id.into(),
        mnemonic: known_mnemonic(),
        passphrase: "pw".into(),
        birthday_height,
        ..Default::default()
    }
}

/// `key_id`'s balance at zero confirmations.
async fn balance(c: &mut GygesClient<Channel>, key_id: &str) -> GetBalanceResponse {
    c.get_balance(GetBalanceRequest {
        key_id: key_id.into(),
        min_confirmations: 0,
    })
    .await
    .unwrap()
    .into_inner()
}

/// A loopback URL nobody listens on, so "no node" tests do not depend on
/// whether the developer runs a zakurad on the default port.
fn closed_port_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    url
}

#[tokio::test]
async fn get_info_over_uds_and_socket_is_owner_only() {
    let running = start(|_| {}).await;
    let mode = std::fs::metadata(&running.socket).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket mode {mode:o}");
    assert_eq!(
        std::fs::read_to_string(&running.pid).unwrap().trim(),
        std::process::id().to_string()
    );

    let mut c = client(&running.socket).await;
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.network, gyges_proto::v1::Network::Regtest as i32);
    let api = info.api_version.unwrap();
    assert_eq!(
        (api.major, api.minor),
        (gyges_proto::API_MAJOR, gyges_proto::API_MINOR)
    );
    assert!(!info.airgapped);
    assert_eq!(info.started_at, running.state.started_at);

    // Unimplemented RPCs answer UNIMPLEMENTED without a GygesError detail.
    let err = c
        .delete_key(gyges_proto::v1::DeleteKeyRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
    assert!(GygesError::from_status(&err).is_none());

    running.task.abort();
}

#[tokio::test]
async fn airgapped_daemon_refuses_networked_rpcs_with_typed_error() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert!(info.airgapped);

    let err = c
        .get_balance(GetBalanceRequest::default())
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).expect("typed error");
    assert_eq!(detail.reason(), ErrorReason::Airgapped);
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    // Shutdown is on the allow-list and actually stops the server.
    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), running.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!running.socket.exists());
}

#[tokio::test]
async fn shutdown_rpc_removes_socket_and_pid_file() {
    let running = start(|_| {}).await;
    let mut c = client(&running.socket).await;
    c.shutdown(ShutdownRequest { graceful: false })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), running.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!running.socket.exists(), "socket removed");
    assert!(!running.pid.exists(), "pid file removed");
    assert!(uds::probe(&running.socket).await.is_err());
}

#[tokio::test]
async fn second_daemon_for_the_same_home_is_refused() {
    let running = start(|_| {}).await;
    let home = Home::new(running._home.path());
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    assert!(format!("{err:#}").contains("already running"), "{err:#}");
    // The failed attempt must not have disturbed the running daemon.
    assert!(running.socket.exists());
    assert_eq!(
        std::fs::read_to_string(&running.pid).unwrap().trim(),
        std::process::id().to_string()
    );
    running.task.abort();
}

#[test]
fn wide_permissions_refuse_start_with_a_chmod_hint() {
    let (dir, home) = fresh_home();
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(net.join("keys")).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::set_mode(&net.join("keys"), 0o755).unwrap();
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&format!("chmod 700 {}", net.join("keys").display())),
        "{msg}"
    );
    drop(dir);
}

#[test]
fn config_for_another_network_refuses_start() {
    let (_dir, home) = fresh_home();
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(&net).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::create_private_file(&home.config_path(Network::Regtest)).unwrap();
    std::fs::write(
        home.config_path(Network::Regtest),
        "network = \"mainnet\"\n[vault]\nscrypt_work_factor = 10\n",
    )
    .unwrap();
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    assert!(
        format!("{err:#}").contains("network = \"mainnet\""),
        "{err:#}"
    );
}

#[test]
fn fallback_without_endpoint_refuses_start() {
    let (_dir, home) = fresh_home();
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(&net).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::create_private_file(&home.config_path(Network::Regtest)).unwrap();
    std::fs::write(
        home.config_path(Network::Regtest),
        "network = \"regtest\"\n[fallback_lightwalletd]\nenabled = true\n[vault]\nscrypt_work_factor = 10\n",
    )
    .unwrap();
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    assert!(format!("{err:#}").contains("grpc_url"), "{err:#}");
}

/// ROADMAP.md M2, first item: the fallback endpoint backend is built at
/// start from `[fallback_lightwalletd]` and contacts nothing until a backfill
/// needs it (no Tor directory, no connection).
#[tokio::test]
async fn fallback_backend_is_built_from_the_config_and_touches_nothing() {
    let url = closed_port_url();
    let running = start(|o| {
        o.chain = Some(Arc::new(FixedChain {
            tip: 10,
            retained_from: 0,
        }));
        o.fallback_lwd = Some(url.clone());
        o.no_tor = true;
    })
    .await;
    let fallback = running
        .state
        .fallback
        .as_ref()
        .expect("fallback configured");
    assert_eq!(fallback.transport(), &gyges_chain::Transport::Direct);
    assert_eq!(fallback.tor_state(), gyges_chain::TorState::Disabled);
    assert!(fallback.endpoint().starts_with(&url));
    assert!(
        !gyges_chain::ChainBackend::status(fallback.as_ref()).connected,
        "nothing contacted at start"
    );
    let info = client(&running.socket)
        .await
        .get_info(GetInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    let fb = info.fallback.unwrap();
    assert!(fb.enabled && !fb.use_tor);
    assert_eq!(fb.grpc_url, url);

    // Over Tor (the default): the arti state goes under tor_cache/, which
    // is created only when Tor is first bootstrapped.
    let running = start(|o| {
        o.chain = Some(Arc::new(FixedChain {
            tip: 10,
            retained_from: 0,
        }));
        o.fallback_lwd = Some("http://abcdefghijklmnop.onion:9067".into());
    })
    .await;
    let fallback = running
        .state
        .fallback
        .as_ref()
        .expect("fallback configured");
    let tor_dir = running._home.path().join("regtest").join("tor_cache");
    assert_eq!(
        fallback.transport(),
        &gyges_chain::Transport::Tor {
            tor_dir: tor_dir.clone()
        }
    );
    assert!(fallback.is_onion());
    assert_eq!(fallback.tor_state(), gyges_chain::TorState::NotStarted);
    assert!(!tor_dir.exists());

    // Air-gapped: no fallback whatever the config says.
    let running = start(|o| {
        o.airgapped = true;
        o.fallback_lwd = Some("http://127.0.0.1:1".into());
    })
    .await;
    assert!(running.state.fallback.is_none());
}

#[tokio::test]
async fn init_key_needs_a_node_unless_airgapped() {
    let url = closed_port_url();
    let running = start(|o| o.zakura_rpc = Some(url.clone())).await;
    let mut c = client(&running.socket).await;

    // The real backend was built from the configuration and polled once
    // before the socket opened: `daemon status` says why it is down.
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    let node = info.node.unwrap();
    assert!(!node.connected);
    assert!(
        node.last_error.contains("getblockchaininfo"),
        "{}",
        node.last_error
    );
    assert!(node.last_error.contains(&url), "{}", node.last_error);
    assert_eq!(node.tip_height, 0);

    let err = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).expect("typed");
    assert_eq!(detail.reason(), ErrorReason::NodeUnreachable);
    assert!(
        detail.detail.contains("key restore --birthday"),
        "{}",
        detail.detail
    );
    assert!(detail.detail.contains("unreachable"), "{}", detail.detail);
    assert!(
        c.list_keys(ListKeysRequest {})
            .await
            .unwrap()
            .into_inner()
            .keys
            .is_empty()
    );
    assert!(!running._home.path().join("regtest/keys/main").exists());
    running.task.abort();
}

#[tokio::test]
async fn init_and_restore_against_a_fake_node() {
    let running = start(|o| {
        o.chain = Some(Arc::new(FixedChain {
            tip: 50,
            retained_from: 0,
        }));
    })
    .await;
    let mut c = client(&running.socket).await;

    // Argument checks happen before anything is written.
    for (key_id, passphrase, word_count) in [("", "pw", 0), ("main", "", 0), ("main", "pw", 12)] {
        let err = c
            .init_key(InitKeyRequest {
                key_id: key_id.into(),
                passphrase: passphrase.into(),
                word_count,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(
            reason(&err),
            ErrorReason::InvalidArgument,
            "{key_id:?} {passphrase:?} {word_count}"
        );
    }
    let err = c
        .init_key(InitKeyRequest {
            key_id: "Main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::InvalidArgument);
    assert_eq!(detail.key_id, "Main");

    let resp = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            set_default: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.key_id, "main");
    assert_eq!(resp.mnemonic.split_whitespace().count(), 24);
    assert_eq!(resp.birthday_height, 50, "the node's tip");
    assert!(resp.ufvk.starts_with("uviewregtest1"), "{}", resp.ufvk);

    let dir = running._home.path().join("regtest/keys/main");
    for f in ["profile.json", "seed.age", "wallet.sqlite"] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f} is {mode:o}");
    }
    assert!(
        std::fs::read_to_string(dir.join("seed.age"))
            .unwrap()
            .starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );

    let keys = c
        .list_keys(ListKeysRequest {})
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, "main");
    assert_eq!(keys[0].signing_mode(), SigningMode::LocalSeed);
    assert!(keys[0].is_default, "set_default was honoured");
    assert!(keys[0].locked);
    assert_eq!(keys[0].birthday_height, 50);
    assert_eq!(keys[0].scanned_tip, 0);
    assert_eq!(keys[0].seed_fingerprint.len(), 64);
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.default_key, "main");
    assert_eq!(info.keys, keys);

    let err = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyExists);
    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    // Restore the mnemonic we were just given under another id: same UFVK.
    let restored = c
        .restore_key(RestoreKeyRequest {
            key_id: "copy".into(),
            mnemonic: resp.mnemonic.clone(),
            passphrase: "other".into(),
            birthday_height: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(restored.ufvk, resp.ufvk);
    assert_eq!(restored.birthday_height, 10);
    assert_eq!(restored.backfill_blocks, 0);

    // Bad mnemonics are INVALID_ARGUMENT and leak no words.
    let err = c
        .restore_key(RestoreKeyRequest {
            mnemonic: "abandon ".repeat(23) + "zzzzq",
            ..restore_req("bad", 0)
        })
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::InvalidArgument);
    assert!(!detail.detail.contains("zzzzq"), "{}", detail.detail);
    // Above the tip is refused too.
    let err = c.restore_key(restore_req("future", 52)).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument);
    assert_eq!(
        c.list_keys(ListKeysRequest {})
            .await
            .unwrap()
            .into_inner()
            .keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        ["copy", "main"]
    );

    // A restart over the same home loads both keys back.
    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), running.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let home = Home::new(running._home.path());
    let daemon = Daemon::prepare(Options::new(home, Network::Regtest)).expect("reopen");
    assert_eq!(daemon.state.registry.key_ids(), ["copy", "main"]);
    assert_eq!(
        daemon
            .state
            .registry
            .resolve("copy")
            .unwrap()
            .ufvk()
            .as_deref(),
        Some(resp.ufvk.as_str())
    );
    // The in-memory default did not persist (config.toml is never rewritten).
    assert_eq!(daemon.state.registry.default_key(), "");
}

#[tokio::test]
async fn restore_below_the_retention_window_is_refused_in_two_steps() {
    let running = start(|o| {
        o.chain = Some(Arc::new(FixedChain {
            tip: 500,
            retained_from: 400,
        }));
    })
    .await;
    let mut c = client(&running.socket).await;
    let req = restore_req("old", 300);
    let err = c.restore_key(req.clone()).await.unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::ConfirmationRequired);
    assert!(detail.detail.contains("100 blocks"), "{}", detail.detail);
    let err = c
        .restore_key(RestoreKeyRequest {
            allow_backfill: true,
            ..req
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::FallbackUnavailable);
    assert!(!running._home.path().join("regtest/keys/old").exists());

    // The default birthday (Sapling activation = 1 on regtest) needs no
    // tree state, but blocks 1..400 are pruned: the same two steps.
    let genesis = restore_req("genesis", 0);
    let err = c.restore_key(genesis.clone()).await.unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::ConfirmationRequired);
    assert!(detail.detail.contains("399 blocks"), "{}", detail.detail);
    let err = c
        .restore_key(RestoreKeyRequest {
            allow_backfill: true,
            ..genesis
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::FallbackUnavailable);
    assert!(!running._home.path().join("regtest/keys/genesis").exists());
    // At the window's edge: prior state at 400 is served.
    let ok = c
        .restore_key(restore_req("edge", 401))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.birthday_height, 401);
    running.task.abort();
}

/// The Keystone pairing export of [`known_mnemonic`]'s accounts, as the
/// device shows it: each UFVK with its Orchard and transparent items only
/// (the device's UFVK has no Sapling component), the ZIP 32 seed
/// fingerprint, and `device_version`. Returns the frames, one per line, and
/// the fingerprint.
fn keystone_export(accounts: &[u32], device_version: Option<&str>) -> (String, [u8; 32]) {
    keystone_export_with(accounts, device_version, Network::Regtest)
}

fn keystone_export_with(
    accounts: &[u32],
    device_version: Option<&str>,
    network: Network,
) -> (String, [u8; 32]) {
    use secrecy::ExposeSecret as _;
    use zcash_address::unified::{Container as _, Encoding as _, Fvk, Ufvk};
    let entropy = gyges_core::vault::entropy_from_phrase(&known_mnemonic()).unwrap();
    let seed = gyges_core::vault::seed_from_entropy(&entropy);
    let params = network.consensus_params();
    let accounts = accounts
        .iter()
        .map(|&index| {
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &params,
                seed.expose_secret(),
                zip32::AccountId::try_from(index).unwrap(),
            )
            .unwrap();
            let full = usk.to_unified_full_viewing_key().encode(&params);
            let (net, ufvk) = Ufvk::decode(&full).unwrap();
            let items: Vec<Fvk> = ufvk
                .items()
                .into_iter()
                .filter(|i| !matches!(i, Fvk::Sapling(_)))
                .collect();
            gyges_qr::Account {
                ufvk: Ufvk::try_from_items(items).unwrap().encode(&net),
                index,
                name: Some(format!("Keystone {index}")),
            }
        })
        .collect();
    let fp = zip32::fingerprint::SeedFingerprint::from_seed(seed.expose_secret())
        .unwrap()
        .to_bytes();
    let payload = gyges_qr::Payload::Accounts(gyges_qr::Accounts {
        seed_fingerprint: fp.to_vec(),
        accounts,
        device_version: device_version.map(Into::into),
    });
    (frames_of(&payload, gyges_qr::DEFAULT_FRAGMENT_LEN), fp)
}

/// Every frame a camera would see in two loops of `payload`'s animation,
/// one per line.
fn frames_of(payload: &gyges_qr::Payload, fragment_len: usize) -> String {
    let mut frames = payload.frames(fragment_len).unwrap();
    let n = if frames.is_single() {
        1
    } else {
        2 * frames.fragment_count()
    };
    (0..n)
        .map(|_| frames.next_frame().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn keystone_req(key_id: &str, payload: &str, birthday_height: u32) -> ImportKeystoneRequest {
    ImportKeystoneRequest {
        key_id: key_id.into(),
        payload: payload.into(),
        birthday_height,
        ..Default::default()
    }
}

/// ROADMAP.md M5, second item. The same seed restored as `local-seed` and
/// imported from its Keystone export is the same account: same seed
/// fingerprint and account index, the same payment seen by both. The
/// Keystone key has no Sapling receiver, spends Orchard, Ironwood and
/// transparent, builds PCZTs whose inputs name the device's seed and
/// account (what the device needs to sign them), and refuses to sign or
/// unlock on the host.
#[tokio::test]
async fn a_keystone_import_is_the_seeds_account_and_builds_pczts_for_the_device() {
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    c.restore_key(restore_req("seed", 1)).await.unwrap();
    let (frames, fp) = keystone_export(&[0], Some("13.2.0"));
    let resp = c
        .import_keystone(keystone_req("ks", &frames, 1))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.key_id, "ks");
    assert_eq!(resp.seed_fingerprint, hex::encode(fp));
    assert_eq!(resp.device_version, "13.2.0");
    assert_eq!(resp.account_index, 0);
    assert_eq!(resp.account_name, "Keystone 0");
    assert_eq!(resp.birthday_height, 1);
    assert!(resp.warnings.is_empty(), "{:?}", resp.warnings);
    use gyges_proto::v1::Pool;
    let pools = vec![
        Pool::Orchard as i32,
        Pool::Ironwood as i32,
        Pool::Transparent as i32,
    ];
    assert_eq!(resp.spend_pools, pools);

    let keys = c
        .list_keys(ListKeysRequest {})
        .await
        .unwrap()
        .into_inner()
        .keys;
    let seed = keys.iter().find(|k| k.key_id == "seed").unwrap();
    let ks = keys.iter().find(|k| k.key_id == "ks").unwrap();
    assert_eq!(ks.signing_mode(), SigningMode::KeystoneQr);
    assert_eq!(ks.device_version, "13.2.0");
    assert_eq!(ks.seed_fingerprint, seed.seed_fingerprint);
    assert_eq!(
        (ks.spend_pools.clone(), ks.receive_pools.clone()),
        (pools.clone(), pools)
    );
    let profile = running
        .state
        .registry
        .resolve("ks")
        .unwrap()
        .profile()
        .clone();
    assert_eq!(profile.account_index, 0);
    assert_eq!(profile.seed_format, None);
    assert!(
        !running
            ._home
            .path()
            .join("regtest/keys/ks/seed.age")
            .exists()
    );

    // The exported UFVK is the device's: no Sapling item.
    let ufvk = c
        .export_ufvk(ExportUfvkRequest {
            key_id: "ks".into(),
        })
        .await
        .unwrap()
        .into_inner()
        .ufvk;
    assert_eq!(ufvk, resp.ufvk);
    {
        use zcash_address::unified::{Container as _, Encoding as _, Fvk, Ufvk};
        let (_, u) = Ufvk::decode(&ufvk).unwrap();
        assert!(u.items().iter().any(|i| matches!(i, Fvk::Orchard(_))));
        assert!(!u.items().iter().any(|i| matches!(i, Fvk::Sapling(_))));
    }

    // One payment to the Keystone key's transparent receiver is the
    // restored key's too. (Their default addresses differ: without a
    // Sapling item the first diversifier index is valid, while the seed's
    // default is the first index valid for Sapling. Both wallets track the
    // same range of BIP 44 indices.)
    let paid = transparent_receiver(&running.state, "ks");
    assert!(transparent_receivers(&running.state, "seed").contains(&paid));
    fund(&node, &running.state, &mut c, "ks", 300_000_000).await;
    wait_spendable(&mut c, "seed").await;
    let (ks_bal, seed_bal) = (balance(&mut c, "ks").await, balance(&mut c, "seed").await);
    assert_eq!(balance_of(&ks_bal, Pool::Transparent).0, 300_000_000);
    assert_eq!(
        balance_of(&ks_bal, Pool::Transparent),
        balance_of(&seed_bal, Pool::Transparent)
    );

    // `pczt create` works, and every transparent input names the device's
    // seed fingerprint and account 0 in its BIP 44 derivation.
    let created = c
        .create_pczt(gyges_proto::v1::CreatePcztRequest {
            key_id: "ks".into(),
            to: t_recipient(),
            amount: zats(100_000_000),
            memo: Vec::new(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let pczt = pczt::Pczt::parse(&created.pczts[0]).unwrap();
    let seed_fp = zip32::fingerprint::SeedFingerprint::from_bytes(fp);
    let coin = bip32::ChildNumber(1 | bip32::ChildNumber::HARDENED_FLAG);
    let mut inputs = 0;
    pczt::roles::verifier::Verifier::new(pczt)
        .with_transparent::<std::convert::Infallible, _>(|bundle| {
            for input in bundle.inputs() {
                inputs += 1;
                let fields = input
                    .bip32_derivation()
                    .values()
                    .find_map(|d| d.extract_bip_44_fields(&seed_fp, coin));
                assert!(
                    matches!(fields, Some((account, _, _)) if account == zip32::AccountId::ZERO),
                    "{fields:?}"
                );
            }
            Ok(())
        })
        .unwrap();
    assert!(inputs > 0);

    // Nothing is signed on the host: a send waits for the device (here the
    // single-PCZT protocol, since the funds are transparent), and the key
    // cannot be unlocked.
    let mut s = c
        .clone()
        .send_transaction(SendTransactionRequest {
            key_id: "ks".into(),
            to: t_recipient(),
            amount: zats(100_000_000),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let req = until_signature_required(&mut s).await;
    assert_eq!(req.kind(), SignatureKind::KeystoneSinglePczt);
    c.abort_signing_session(AbortSigningSessionRequest {
        session_id: req.session_id,
    })
    .await
    .unwrap();
    let err = c
        .unlock_key(UnlockKeyRequest {
            key_id: "ks".into(),
            passphrase: "pw".into(),
            scope: UnlockScope::Daemon as i32,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("no seed"), "{err:?}");
    running.task.abort();
}

/// Every refusal of `ImportKeystone` leaves nothing on disk: the wrong
/// payload (exit 6), the device's content refused (exit 9), an unknown
/// firmware version without the flag and a birthday below the node's
/// window without consent (exit 4). Then a multi-frame export of two
/// accounts, the second one chosen, and an unknown version allowed.
#[tokio::test]
async fn keystone_import_refusals_and_account_choice() {
    let running = start(|o| {
        o.chain = Some(Arc::new(FixedChain {
            tip: 500,
            retained_from: 400,
        }));
    })
    .await;
    let mut c = client(&running.socket).await;
    let keys_dir = running._home.path().join("regtest/keys");
    let (good, _) = keystone_export(&[0], Some("13.2.0"));
    let ufvk = |p: &str| -> String {
        let mut asm = gyges_qr::Assembler::new();
        for f in p.lines() {
            asm.receive(f).unwrap();
        }
        match gyges_qr::Payload::from_assembler(&asm).unwrap().unwrap() {
            gyges_qr::Payload::Accounts(a) => a.accounts[0].ufvk.clone(),
            _ => unreachable!(),
        }
    };
    let bare = ufvk(&good);
    let lone = frames_of(
        &gyges_qr::Payload::Ufvk(gyges_qr::Account {
            ufvk: bare.clone(),
            index: 0,
            name: None,
        }),
        200,
    );
    let (old, _) = keystone_export(&[0], Some("13.0.1"));
    let (silent, _) = keystone_export(&[0], None);
    let (mainnet, _) = keystone_export_with(&[0], Some("13.2.0"), Network::Mainnet);
    let (two, _) = keystone_export(&[0, 1], Some("13.2.0-C"));
    assert!(
        two.lines().count() > 1,
        "two accounts should take several frames"
    );
    let first_frame = two.lines().next().unwrap().to_string();
    let short_fp = frames_of(
        &gyges_qr::Payload::Accounts(gyges_qr::Accounts {
            seed_fingerprint: vec![0xd1; 16],
            accounts: vec![gyges_qr::Account {
                ufvk: bare.clone(),
                index: 0,
                name: None,
            }],
            device_version: Some("13.2.0".into()),
        }),
        400,
    );

    let cases: Vec<(&str, ImportKeystoneRequest, ErrorReason, &str)> = vec![
        (
            "empty",
            keystone_req("k", "", 450),
            ErrorReason::InvalidArgument,
            "no ur:zcash-accounts",
        ),
        (
            "bare ufvk",
            keystone_req("k", &bare, 450),
            ErrorReason::InvalidArgument,
            "import-ufvk",
        ),
        (
            "ufvk ur",
            keystone_req("k", &lone, 450),
            ErrorReason::InvalidArgument,
            "seed fingerprint",
        ),
        (
            "psbt",
            keystone_req(
                "k",
                "ur:crypto-psbt/hdcxlkahssqzwfvslofzoxwkrewngotktbmwjkwdcmnefsaaehrlolkskncnktlbaypkvoonhknt",
                450,
            ),
            ErrorReason::InvalidArgument,
            "expected ur:zcash-accounts",
        ),
        (
            "one of many frames",
            keystone_req("k", &first_frame, 450),
            ErrorReason::InvalidArgument,
            "incomplete",
        ),
        (
            "old firmware",
            keystone_req("k", &old, 450),
            ErrorReason::HardwareSigner,
            "13.0.1 (v3.0.1 on the device)",
        ),
        (
            "no version",
            keystone_req("k", &silent, 450),
            ErrorReason::ConfirmationRequired,
            "--allow-unknown-firmware",
        ),
        (
            "mainnet key",
            keystone_req("k", &mainnet, 450),
            ErrorReason::HardwareSigner,
            "not a regtest viewing key",
        ),
        (
            "short fingerprint",
            keystone_req("k", &short_fp, 450),
            ErrorReason::HardwareSigner,
            "16 bytes",
        ),
        (
            "missing account",
            ImportKeystoneRequest {
                account_index: 3,
                ..keystone_req("k", &two, 450)
            },
            ErrorReason::InvalidArgument,
            "lists account 0, 1",
        ),
        // NU5 is height 1 on regtest: 399 blocks below the window.
        (
            "default birthday",
            keystone_req("k", &good, 0),
            ErrorReason::ConfirmationRequired,
            "399 blocks",
        ),
        (
            "no fallback",
            ImportKeystoneRequest {
                allow_backfill: true,
                ..keystone_req("k", &good, 0)
            },
            ErrorReason::FallbackUnavailable,
            "fallback",
        ),
    ];
    for (what, req, want, needle) in cases {
        let err = c.import_keystone(req).await.expect_err(what);
        let e = GygesError::from_status(&err).unwrap();
        assert_eq!(e.reason(), want, "{what}: {}", e.detail);
        assert!(
            e.detail.contains(needle),
            "{what}: {needle:?} not in {:?}",
            e.detail
        );
        assert!(!keys_dir.join("k").exists(), "{what} left a key directory");
    }

    // The second account of a fountain-coded export.
    let resp = c
        .import_keystone(ImportKeystoneRequest {
            account_index: 1,
            ..keystone_req("second", &two, 450)
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (resp.account_index, resp.account_name.as_str()),
        (1, "Keystone 1")
    );
    assert_eq!(resp.device_version, "13.2.0-C");
    assert_eq!(
        running
            .state
            .registry
            .resolve("second")
            .unwrap()
            .profile()
            .account_index,
        1
    );
    // An unknown version, allowed: recorded as such, with a warning.
    let resp = c
        .import_keystone(ImportKeystoneRequest {
            allow_unknown_firmware: true,
            ..keystone_req("silent", &silent, 450)
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.device_version, "unknown");
    assert!(
        resp.warnings.iter().any(|w| w.contains("v3.0.2")),
        "{:?}",
        resp.warnings
    );
    // The id is taken now.
    let err = c
        .import_keystone(keystone_req("second", &two, 450))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyExists, "{err:?}");
    running.task.abort();
}

// ---------------------------------------------------------------------------
// An emulated Keystone (ROADMAP.md M5, third item)
// ---------------------------------------------------------------------------

/// The spending key a Keystone paired with [`keystone_export`] holds for
/// `account`.
fn keystone_usk(account: u32) -> zcash_keys::keys::UnifiedSpendingKey {
    use secrecy::ExposeSecret as _;
    let entropy = gyges_core::vault::entropy_from_phrase(&known_mnemonic()).unwrap();
    let seed = gyges_core::vault::seed_from_entropy(&entropy);
    zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &Network::Regtest.consensus_params(),
        seed.expose_secret(),
        zip32::AccountId::try_from(account).unwrap(),
    )
    .unwrap()
}

fn keystone_fingerprint() -> zip32::fingerprint::SeedFingerprint {
    use secrecy::ExposeSecret as _;
    let entropy = gyges_core::vault::entropy_from_phrase(&known_mnemonic()).unwrap();
    let seed = gyges_core::vault::seed_from_entropy(&entropy);
    zip32::fingerprint::SeedFingerprint::from_seed(seed.expose_secret()).unwrap()
}

/// `cbor` carried through a camera: fountain frames of `ur_type`, shuffled,
/// a fifth dropped, reassembled.
fn through_camera(ur_type: &'static str, cbor: &[u8]) -> Vec<u8> {
    let mut frames = gyges_qr::Frames::new(ur_type, cbor, 120).unwrap();
    let n = frames.fragment_count();
    let mut sent: Vec<String> = (0..3 * n).map(|_| frames.next_frame().unwrap()).collect();
    let mut x = 0x9e37_79b9_7f4a_7c15_u64;
    for i in (1..sent.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        sent.swap(i, (x % (i as u64 + 1)) as usize);
    }
    sent.truncate(sent.len() * 4 / 5);
    let mut asm = gyges_qr::Assembler::new();
    for f in &sent {
        if asm.is_complete() {
            break;
        }
        asm.receive(f).unwrap();
    }
    while !asm.is_complete() {
        asm.receive(&frames.next_frame().unwrap()).unwrap();
    }
    asm.message().unwrap().unwrap().1
}

/// The emulated device holding `account`'s key.
fn keystone_device(account: u32) -> gyges_core::keystone::emulator::Device {
    gyges_core::keystone::emulator::Device {
        usk: keystone_usk(account),
        fingerprint: keystone_fingerprint(),
        coin_type: 1,
    }
}

/// The device's batch signatures for a request that came through the
/// camera.
fn keystone_batch_signatures(
    payload: &[u8],
    account: u32,
) -> (Vec<u8>, Vec<Vec<pczt::roles::signer::SpendAuthSignature>>) {
    let cbor = through_camera(gyges_qr::ur_types::ZCASH_SIGN_BATCH, payload);
    gyges_core::keystone::emulator::batch_signatures(&keystone_device(account), &cbor)
}

use gyges_core::keystone::emulator::{batch_answer, pczt_answer};

/// The device's signed PCZT for a single-PCZT request that came through
/// the camera.
fn keystone_signed_pczt(payload: &[u8]) -> Vec<u8> {
    let cbor = through_camera(gyges_qr::ur_types::ZCASH_PCZT, payload);
    gyges_core::keystone::emulator::signed_pczt(&keystone_device(0), &cbor)
}

/// What a correctly working device answers.
fn keystone_answer(req: &gyges_proto::v1::SignatureRequired) -> Vec<u8> {
    match req.kind() {
        SignatureKind::KeystoneBatch => {
            let (id, sigs) = keystone_batch_signatures(&req.payload, 0);
            batch_answer(id, sigs)
        }
        SignatureKind::KeystoneSinglePczt => pczt_answer(keystone_signed_pczt(&req.payload)),
        other => panic!("not a Keystone kind: {other:?}"),
    }
}

/// TESTING.md §4's Redactor test, on what the device is actually shown: no
/// `gyges.*` tag, no witness, no existing signature in the batch view, and
/// every output's value as the approved proposal has it (the batch view
/// after `resolve_fields`, since it compacts what can be recomputed).
fn assert_device_view(req: &gyges_proto::v1::SignatureRequired) {
    let mut view = match req.kind() {
        SignatureKind::KeystoneBatch => {
            let gyges_qr::Payload::SignBatch { data, .. } = gyges_qr::Payload::from_cbor(
                gyges_qr::ur_types::ZCASH_SIGN_BATCH,
                req.payload.clone(),
            )
            .unwrap() else {
                unreachable!()
            };
            let r = pczt::roles::signer::batch::BatchSignRequest::parse(&data).unwrap();
            assert_eq!(r.pczts().len(), 1);
            r.pczts()[0].clone()
        }
        _ => {
            let gyges_qr::Payload::Pczt(bytes) =
                gyges_qr::Payload::from_cbor(gyges_qr::ur_types::ZCASH_PCZT, req.payload.clone())
                    .unwrap()
            else {
                unreachable!()
            };
            pczt::Pczt::parse(&bytes).unwrap()
        }
    };
    assert!(
        !view
            .global()
            .proprietary()
            .keys()
            .any(|k| k.starts_with("gyges.")),
        "{:?}",
        view.global().proprietary().keys().collect::<Vec<_>>()
    );
    for bundle in [view.orchard(), view.ironwood()] {
        for a in bundle.actions() {
            assert!(
                a.spend().witness().is_none(),
                "a witness reached the device"
            );
            if req.kind() == SignatureKind::KeystoneBatch {
                assert!(
                    a.spend().spend_auth_sig().is_none(),
                    "an existing signature reached the device"
                );
            }
        }
    }
    if req.kind() == SignatureKind::KeystoneBatch {
        view.resolve_fields().unwrap();
    }
    let mut shown: Vec<u64> = Vec::new();
    let mut addresses: Vec<String> = Vec::new();
    for bundle in [view.orchard(), view.ironwood()] {
        for a in bundle.actions() {
            if let Some(v) = a.output().value().filter(|v| *v > 0) {
                assert!(
                    a.output().recipient().is_some(),
                    "an output of value {v} reached the device without its recipient"
                );
                shown.push(v);
            }
            addresses.extend(a.output().user_address().clone());
        }
    }
    for o in view.transparent().outputs() {
        shown.push(*o.value());
        addresses.extend(o.user_address().clone());
    }
    shown.sort_unstable();
    // Every payment's address, as the user approved it, is there for the
    // device to display.
    let summary = req.summary.as_ref().unwrap();
    for out in summary.steps[0].outputs.iter().filter(|o| !o.is_change) {
        assert!(
            addresses.contains(&out.address),
            "the payment to {} reached the device without its address: {addresses:?}",
            out.address
        );
    }
    let mut approved: Vec<u64> = summary.steps[0]
        .outputs
        .iter()
        .map(|o| o.value as u64)
        .filter(|v| *v > 0)
        .collect();
    approved.sort_unstable();
    assert_eq!(
        shown, approved,
        "the device must be shown every output value"
    );
}

/// Read a send stream up to its `SignatureRequired`.
async fn until_signature_required(
    s: &mut tonic::Streaming<SendEvent>,
) -> gyges_proto::v1::SignatureRequired {
    while let Some(ev) = s.next().await {
        if let Some(send_event::Event::SignatureRequired(r)) = ev.unwrap().event {
            return r;
        }
    }
    panic!("the stream ended without SignatureRequired");
}

async fn complete(
    c: &mut GygesClient<Channel>,
    session_id: &str,
    payload: Vec<u8>,
) -> Result<gyges_proto::v1::CompleteKeystoneSignResponse, tonic::Status> {
    c.complete_keystone_sign(gyges_proto::v1::CompleteKeystoneSignRequest {
        session_id: session_id.into(),
        payload,
    })
    .await
    .map(tonic::Response::into_inner)
}

async fn keystone_sessions(
    c: &mut GygesClient<Channel>,
    include_finished: bool,
) -> Vec<gyges_proto::v1::SigningSession> {
    c.list_signing_sessions(ListSigningSessionsRequest {
        key_id: "ks".into(),
        include_finished,
    })
    .await
    .unwrap()
    .into_inner()
    .sessions
}

/// A daemon on `node` with the Keystone key `ks` (the known mnemonic's
/// account 0) holding `z` zatoshis on a transparent receiver.
async fn funded_keystone(node: &FakeNode, z: u64) -> (Running, GygesClient<Channel>) {
    let (running, mut c) = start_on(node, ONE_CONF_CONFIG).await;
    let (frames, _) = keystone_export(&[0], Some("13.2.0"));
    c.import_keystone(keystone_req("ks", &frames, 1))
        .await
        .unwrap();
    wait_spendable(&mut c, "ks").await;
    fund(node, &running.state, &mut c, "ks", z).await;
    (running, c)
}

/// The Redactor on a PCZT that carries the `gyges.*` tags (`pczt create`
/// writes them; a send's PCZT has none): neither device view keeps any.
#[tokio::test]
async fn the_device_never_sees_gyges_tags() {
    let node = mined_node(10).await;
    let (running, mut c) = funded_keystone(&node, 300_000_000).await;
    let created = c
        .create_pczt(gyges_proto::v1::CreatePcztRequest {
            key_id: "ks".into(),
            to: t_recipient(),
            amount: zats(100_000_000),
            memo: Vec::new(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let tagged = pczt::Pczt::parse(&created.pczts[0]).unwrap();
    assert!(
        tagged
            .global()
            .proprietary()
            .keys()
            .any(|k| k.starts_with("gyges.")),
        "the fixture must carry the tags"
    );
    for protocol in [
        gyges_core::sessions::Protocol::KeystoneBatch,
        gyges_core::sessions::Protocol::KeystonePczt,
    ] {
        let view = gyges_core::keystone::device_view(&tagged, protocol);
        let keys: Vec<&String> = view.global().proprietary().keys().collect();
        assert!(
            !keys.iter().any(|k| k.starts_with("gyges.")),
            "{protocol:?}: {keys:?}"
        );
    }
    running.task.abort();
}

/// ROADMAP.md M5, third item, the happy path and every refused answer.
/// Shielding (transparent inputs) goes by the single-PCZT protocol, a
/// shielded send by the batch protocol; the device is shown a redacted,
/// unproven PCZT; the stream resumes once `CompleteKeystoneSign` arrives
/// from another connection; each refused answer leaves the session
/// awaiting, and the right one still completes it; a second completion is
/// `SESSION_NOT_FOUND`; the balance moves.
#[tokio::test]
async fn keystone_shield_and_send_through_both_protocols() {
    let node = mined_node(10).await;
    let (running, mut c) = funded_keystone(&node, 300_000_000).await;
    let mut other = client(&running.socket).await;

    // Shield: single PCZT.
    let mut s = c
        .shield_funds(ShieldFundsRequest {
            key_id: "ks".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let req = until_signature_required(&mut s).await;
    assert_eq!(req.kind(), SignatureKind::KeystoneSinglePczt);
    assert_eq!(req.key_id, "ks");
    let summary = req.summary.clone().unwrap();
    assert!(
        summary.expiry_height >= summary.anchor_height + gygesd::roles::PCZT_EXPIRY_BLOCKS,
        "a Keystone send gets a day to be signed: {summary:?}"
    );
    assert_device_view(&req);
    let listed = keystone_sessions(&mut other, false).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].session_id, req.session_id);
    assert_eq!(listed[0].payload, req.payload);
    assert_eq!(
        listed[0].status(),
        gyges_proto::v1::SessionStatus::AwaitingSignature
    );

    // A second spend while this one waits is refused, naming it.
    let err = collect_events(
        c.clone()
            .send_transaction(SendTransactionRequest {
                key_id: "ks".into(),
                to: t_recipient(),
                amount: zats(10_000),
                ..Default::default()
            })
            .await,
    )
    .await
    .unwrap_err();
    let e = GygesError::from_status(&err).unwrap();
    assert_eq!(e.reason(), ErrorReason::SignatureRequired, "{}", e.detail);
    assert_eq!(e.session_id, req.session_id);

    // A PCZT with one output value changed: the Combiner refuses it.
    let signed = keystone_signed_pczt(&req.payload);
    let change = summary.steps[0].outputs[0].value as u64;
    let tampered = {
        // The value occurs more than once in a PCZT; one changed copy is
        // a device that lies about one field.
        let (from, to) = (varint(change), varint(change - 1));
        assert_eq!(from.len(), to.len());
        let at = (0..=signed.len() - from.len())
            .find(|&i| signed[i..i + from.len()] == from[..])
            .expect("the value is in the PCZT");
        let mut t = signed.clone();
        t[at..at + to.len()].copy_from_slice(&to);
        t
    };
    let err = complete(&mut other, &req.session_id, pczt_answer(tampered))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::HardwareSigner, "{err:?}");
    let listed = keystone_sessions(&mut other, false).await;
    assert!(!listed[0].last_error.is_empty(), "{listed:?}");
    // A batch answer to a single-PCZT session.
    let err = complete(
        &mut other,
        &req.session_id,
        batch_answer(vec![0; 16], vec![vec![]]),
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::HardwareSigner, "{err:?}");
    // The device's real answer completes it; the stream resumes.
    let done = complete(&mut other, &req.session_id, pczt_answer(signed))
        .await
        .unwrap();
    let Some(gyges_proto::v1::complete_keystone_sign_response::Result::Broadcast(txids)) =
        done.result
    else {
        panic!("{done:?}")
    };
    let rest: Vec<SendEvent> = s.map(|e| e.unwrap()).collect().await;
    assert_eq!(event_names(&rest), ["signed", "broadcast"], "{rest:?}");
    assert_eq!(broadcast_txid(&rest), txids.txids[0]);
    let err = complete(&mut other, &req.session_id, keystone_answer(&req))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SessionNotFound, "{err:?}");
    node.mine(1);
    wait_spendable(&mut c, "ks").await;
    let b = balance(&mut c, "ks").await;
    let shielded = balance_of(&b, gyges_proto::v1::Pool::Ironwood).0;
    assert!(shielded > 299_000_000, "{b:?}");

    // Send from the shielded funds: batch.
    let mut s = c
        .send_transaction(SendTransactionRequest {
            key_id: "ks".into(),
            to: t_recipient(),
            amount: zats(100_000_000),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let req = until_signature_required(&mut s).await;
    assert_eq!(req.kind(), SignatureKind::KeystoneBatch);
    assert_device_view(&req);
    let (id, sigs) = keystone_batch_signatures(&req.payload, 0);
    assert!(!sigs[0].is_empty());
    // Refused, each leaving the session awaiting: another request id; a
    // signature that does not verify (one bit off, as a signature over
    // another transaction or by another key would); a missing signature;
    // two entries.
    let mut wrong_id = id.clone();
    wrong_id[0] ^= 1;
    let corrupt: Vec<Vec<_>> = vec![
        sigs[0]
            .iter()
            .map(|s| {
                let mut bytes = *s.signature();
                bytes[0] ^= 1;
                pczt::roles::signer::SpendAuthSignature::from_parts(
                    s.value_pool(),
                    s.action_index(),
                    bytes,
                )
            })
            .collect(),
    ];
    for (what, answer, needle) in [
        (
            "request id",
            batch_answer(wrong_id, sigs.clone()),
            "another request",
        ),
        (
            "bad signature",
            batch_answer(id.clone(), corrupt),
            "does not verify",
        ),
        ("missing", batch_answer(id.clone(), vec![vec![]]), "missing"),
        (
            "two entries",
            batch_answer(id.clone(), vec![sigs[0].clone(), sigs[0].clone()]),
            "2 PCZT entries",
        ),
    ] {
        let err = complete(&mut other, &req.session_id, answer)
            .await
            .expect_err(what);
        let e = GygesError::from_status(&err).unwrap();
        assert_eq!(
            e.reason(),
            ErrorReason::HardwareSigner,
            "{what}: {}",
            e.detail
        );
        assert!(
            e.detail.contains(needle),
            "{what}: {needle:?} not in {:?}",
            e.detail
        );
    }
    let done = complete(&mut other, &req.session_id, batch_answer(id, sigs))
        .await
        .unwrap();
    assert_eq!(
        done.session.unwrap().status(),
        gyges_proto::v1::SessionStatus::Completed
    );
    let rest: Vec<SendEvent> = s.map(|e| e.unwrap()).collect().await;
    assert_eq!(event_names(&rest), ["signed", "broadcast"], "{rest:?}");
    node.mine(1);
    wait_spendable(&mut c, "ks").await;
    let after = balance_of(
        &balance(&mut c, "ks").await,
        gyges_proto::v1::Pool::Ironwood,
    )
    .0;
    assert!(
        after < shielded - 100_000_000 && after > shielded - 101_000_000,
        "{after}"
    );
    assert!(keystone_sessions(&mut other, false).await.is_empty());
    assert_eq!(keystone_sessions(&mut other, true).await.len(), 2);
    running.task.abort();
}

/// A Keystone session outlives everything but its own expiry: an abort
/// ends the waiting stream with `CANCELLED`; a client that leaves after
/// `SignatureRequired` and a daemon restart lose nothing, and the session
/// completes from the listed payload alone; once the chain passes the
/// transaction's expiry height, completing it is refused before anything
/// is recorded.
#[tokio::test]
async fn a_keystone_session_survives_a_restart_and_expires_with_its_transaction() {
    let node = mined_node(10).await;
    let (running, mut c) = funded_keystone(&node, 300_000_000).await;
    let shield = || ShieldFundsRequest {
        key_id: "ks".into(),
        ..Default::default()
    };

    // Abort.
    let mut s = c.clone().shield_funds(shield()).await.unwrap().into_inner();
    let req = until_signature_required(&mut s).await;
    let aborted = c
        .abort_signing_session(AbortSigningSessionRequest {
            session_id: req.session_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(aborted.status(), gyges_proto::v1::SessionStatus::Aborted);
    let err = s.next().await.expect("an end").unwrap_err();
    assert_eq!(reason(&err), ErrorReason::Cancelled, "{err:?}");
    let err = complete(&mut c, &req.session_id, keystone_answer(&req))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SessionNotFound, "{err:?}");

    // The client leaves, the daemon restarts.
    let mut s = c.clone().shield_funds(shield()).await.unwrap().into_inner();
    let req = until_signature_required(&mut s).await;
    drop(s);
    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    let Running {
        _home: home, task, ..
    } = running;
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("shutdown within 30 s")
        .unwrap()
        .unwrap();
    let running = start_in(home, |o| o.zakura_rpc = Some(node.url().to_string())).await;
    let mut c = client(&running.socket).await;
    let listed = keystone_sessions(&mut c, false).await;
    assert_eq!(listed.len(), 1, "{listed:?}");
    let pending = &listed[0];
    assert_eq!(pending.session_id, req.session_id);
    assert_eq!(pending.payload, req.payload);
    // Completed from what the list shows, by a process that never saw the
    // stream.
    let again = gyges_proto::v1::SignatureRequired {
        kind: pending.kind,
        payload: pending.payload.clone(),
        ..Default::default()
    };
    let done = complete(&mut c, &pending.session_id, keystone_answer(&again))
        .await
        .unwrap();
    assert!(done.result.is_some(), "{done:?}");
    node.mine(1);
    wait_spendable(&mut c, "ks").await;
    assert!(
        balance_of(
            &balance(&mut c, "ks").await,
            gyges_proto::v1::Pool::Ironwood
        )
        .0 > 0
    );

    // Expiry: a send left pending while the chain passes its expiry.
    let mut s = c
        .clone()
        .send_transaction(SendTransactionRequest {
            key_id: "ks".into(),
            to: t_recipient(),
            amount: zats(10_000_000),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let req = until_signature_required(&mut s).await;
    drop(s);
    let expiry = req.summary.as_ref().unwrap().expiry_height;
    let (tip, _) = node.tip();
    node.mine(expiry - tip);
    wait_spendable(&mut c, "ks").await;
    let err = complete(&mut c, &req.session_id, keystone_answer(&req))
        .await
        .unwrap_err();
    let e = GygesError::from_status(&err).unwrap();
    assert_eq!(e.reason(), ErrorReason::NotSynced, "{}", e.detail);
    assert!(e.detail.contains("can no longer be mined"), "{}", e.detail);
    let all = keystone_sessions(&mut c, true).await;
    let row = all.iter().find(|r| r.session_id == req.session_id).unwrap();
    assert_eq!(
        row.status(),
        gyges_proto::v1::SessionStatus::Expired,
        "{row:?}"
    );
    // Nothing was recorded: the funds are still spendable.
    let b = balance(&mut c, "ks").await;
    assert!(
        balance_of(&b, gyges_proto::v1::Pool::Ironwood).0 > 290_000_000,
        "{b:?}"
    );
    running.task.abort();
}

#[tokio::test]
async fn airgapped_init_key_creates_a_signer_only_profile() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let resp = init_key(&mut c, "box").await;
    assert_eq!(resp.mnemonic.split_whitespace().count(), 24);
    assert_eq!(resp.birthday_height, 0);
    assert_eq!(resp.ufvk, "");
    let keys = c
        .list_keys(ListKeysRequest {})
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert_eq!(keys[0].signing_mode(), SigningMode::SignerOnly);
    assert_eq!(keys[0].birthday_height, 0);
    let dir = running._home.path().join("regtest/keys/box");
    assert!(dir.join("seed.age").is_file());
    assert!(!dir.join("wallet.sqlite").exists());

    // Restores need the network and are refused by the policy layer.
    let err = c.restore_key(restore_req("x", 0)).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::Airgapped);
    running.task.abort();
}

#[test]
fn a_broken_key_directory_refuses_start() {
    let (_dir, home) = fresh_home();
    let key = home.key_dir(Network::Regtest, "main");
    std::fs::create_dir_all(&key).unwrap();
    perms::set_mode(&home.keys_dir(Network::Regtest), 0o700).unwrap();
    perms::set_mode(&key, 0o700).unwrap();
    perms::create_private_file(&key.join("profile.json")).unwrap();
    std::fs::write(key.join("profile.json"), "{\"schema_version\": 99}").unwrap();
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("key \"main\""), "{msg}");
    assert!(msg.contains("profile.json"), "{msg}");
}

#[tokio::test]
async fn daemon_unlock_lock_and_the_key_list_window() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        set_default: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Locked: a signer-only key cannot even export its UFVK.
    let err = c
        .export_ufvk(ExportUfvkRequest { key_id: "".into() })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::VaultLocked);
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let resp = c
        .unlock_key(UnlockKeyRequest {
            key_id: "".into(),
            passphrase: "pw".into(),
            ttl_secs: 120,
            scope: UnlockScope::Daemon as i32,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.session_token.is_empty(), "daemon scope has no token");
    assert_eq!(resp.scope(), UnlockScope::Daemon);
    assert!(
        resp.expires_at >= before + 119 && resp.expires_at <= before + 122,
        "{}",
        resp.expires_at
    );

    let keys = c
        .list_keys(ListKeysRequest {})
        .await
        .unwrap()
        .into_inner()
        .keys;
    assert!(!keys[0].locked);
    assert_eq!(keys[0].unlock_expires_at, resp.expires_at);
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert!(!info.keys[0].locked);

    // Unlocked: the UFVK is derived on demand.
    let ufvk = c
        .export_ufvk(ExportUfvkRequest {
            key_id: "main".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(ufvk.ufvk.starts_with("uviewregtest1"), "{}", ufvk.ufvk);
    assert_eq!(ufvk.birthday_height, 0);

    let locked = c
        .lock_key(LockKeyRequest {
            key_id: "main".into(),
            all: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(locked.locked_key_ids, ["main"]);
    assert!(
        c.list_keys(ListKeysRequest {})
            .await
            .unwrap()
            .into_inner()
            .keys[0]
            .locked
    );
    let again = c
        .lock_key(LockKeyRequest {
            key_id: "".into(),
            all: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(again.locked_key_ids.is_empty());
    let err = c
        .lock_key(LockKeyRequest {
            key_id: "nope".into(),
            all: false,
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);

    // A bound session id is refused until signing sessions exist.
    let err = c
        .unlock_key(UnlockKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            session_id: "abcd".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SessionNotFound);
    running.task.abort();
}

#[tokio::test]
async fn connection_unlock_dies_with_its_connection_and_shutdown_zeroizes() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    init_key(&mut c, "main").await;

    let resp = c
        .unlock_key(UnlockKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.session_token.len(), 32);
    assert_eq!(resp.scope(), UnlockScope::Connection);
    assert_eq!(running.state.vault.unlock_count(), 1);
    // Not visible as unlocked to anyone, and not usable without the token.
    assert!(
        c.list_keys(ListKeysRequest {})
            .await
            .unwrap()
            .into_inner()
            .keys[0]
            .locked
    );
    let err = c
        .export_ufvk(ExportUfvkRequest {
            key_id: "main".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::VaultLocked);

    // Closing the connection drops it.
    drop(c);
    eventually("the unlock to end with its connection", || {
        running.state.vault.unlock_count() == 0
    })
    .await;

    // A daemon unlock survives the connection but not the daemon.
    let mut c = client(&running.socket).await;
    unlock_daemon(&mut c, "main").await;
    drop(c);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(running.state.vault.unlock_count(), 1);
    let mut c = client(&running.socket).await;
    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), running.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(running.state.vault.unlock_count(), 0, "zeroized on stop");
}

#[tokio::test]
async fn wrong_passphrases_are_rate_limited_per_key() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    for id in ["a", "b"] {
        init_key(&mut c, id).await;
    }
    let attempt = |key_id: &str, pass: &str| UnlockKeyRequest {
        key_id: key_id.into(),
        passphrase: pass.into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    };
    let err = c.unlock_key(attempt("a", "wrong")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidPassphrase);
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    // Even the right passphrase waits now, on a new connection too.
    let mut c2 = client(&running.socket).await;
    let err = c2.unlock_key(attempt("a", "pw")).await.unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::RateLimited);
    assert!(detail.detail.contains("retry in 1s"), "{}", detail.detail);
    assert_eq!(detail.key_id, "a");
    // Key b is unaffected.
    c.unlock_key(attempt("b", "pw")).await.unwrap();
    // Empty passphrase is an argument error, not an attempt.
    let err = c.unlock_key(attempt("b", "")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument);
    running.task.abort();
}

/// `StreamLogs` (API.md §4.5): the audit tail replays the events of an
/// unlock with key id, event and scope only; a follower sees the lock that
/// comes next; the main tail carries no passphrase. Air-gapped, so the key
/// is `signer-only` and nothing else writes to the logs meanwhile.
#[tokio::test]
async fn stream_logs_replays_the_audit_trail_and_follows() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let key_id = format!("logs-{}", std::process::id());
    let passphrase = "correct-horse-battery-staple-7731";
    c.init_key(InitKeyRequest {
        key_id: key_id.clone(),
        passphrase: passphrase.into(),
        ..Default::default()
    })
    .await
    .unwrap();
    c.unlock_key(UnlockKeyRequest {
        key_id: key_id.clone(),
        passphrase: passphrase.into(),
        scope: UnlockScope::Daemon as i32,
        ttl_secs: 60,
        ..Default::default()
    })
    .await
    .unwrap();

    // Replay of the audit log: exactly one `unlock` for this key, with the
    // documented fields and nothing else.
    let mut s = c
        .stream_logs(StreamLogsRequest {
            lines: 1000,
            audit: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut mine = Vec::new();
    while let Some(e) = s.message().await.unwrap() {
        assert_eq!(e.target, gygesd::keys::AUDIT_TARGET);
        assert_eq!(e.level(), gyges_proto::v1::LogLevel::Info);
        if e.fields.get("key_id") == Some(&key_id) {
            mine.push(e);
        }
    }
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0].fields["event"], "unlock");
    assert!(mine[0].fields["scope"].contains("Daemon"), "{:?}", mine[0]);
    let mut keys: Vec<&str> = mine[0].fields.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["event", "key_id", "scope"]);
    assert!(mine[0].timestamp_unix_ms >= running.state.started_at * 1000);

    // A follower started now sees the lock, and only new entries.
    let mut follow = c
        .stream_logs(StreamLogsRequest {
            lines: 0,
            follow: true,
            audit: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    c.lock_key(LockKeyRequest {
        key_id: key_id.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    let locked = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let e = follow.message().await.unwrap().expect("stream open");
            if e.fields.get("key_id") == Some(&key_id) {
                return e;
            }
        }
    })
    .await
    .expect("lock event followed");
    assert_eq!(locked.fields["event"], "lock");
    drop(follow);

    // The main log has the daemon's lines for this key and no secret.
    let mut s = c
        .stream_logs(StreamLogsRequest {
            lines: 1000,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut main = Vec::new();
    while let Some(e) = s.message().await.unwrap() {
        let text = format!("{e:?}");
        assert!(!text.contains(passphrase), "{text}");
        if e.fields.get("key_id") == Some(&key_id) {
            main.push(e.message);
        }
    }
    assert!(
        main.iter().any(|m| m == "key created") && main.iter().any(|m| m == "key locked"),
        "{main:?}"
    );

    running.task.abort();
}

#[tokio::test]
async fn export_seed_round_trips_with_its_guards() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let created = init_key(&mut c, "main").await;
    let req = |pass: &str, confirmation: &str| ExportSeedRequest {
        key_id: "main".into(),
        passphrase: pass.into(),
        confirmation: confirmation.into(),
    };
    let err = c.export_seed(req("pw", "reveal")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::ConfirmationRequired);
    let err = c.export_seed(req("nope", "reveal seed")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidPassphrase);
    // The failed attempt counts against the same back-off as unlocks.
    let err = c.export_seed(req("pw", "reveal seed")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::RateLimited);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let resp = c
        .export_seed(req("pw", "reveal seed"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.mnemonic, created.mnemonic);
    // Exporting never created an unlock.
    assert_eq!(running.state.vault.unlock_count(), 0);
    running.task.abort();
}

#[tokio::test]
async fn seed_export_can_be_disabled_by_config() {
    let running = start_with(
        "[vault]\nscrypt_work_factor = 10\nallow_seed_export = false\n",
        |o| o.airgapped = true,
    )
    .await;
    let mut c = client(&running.socket).await;
    init_key(&mut c, "main").await;
    let err = c
        .export_seed(ExportSeedRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            confirmation: "reveal seed".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SeedExportDisabled);
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    running.task.abort();
}

#[tokio::test]
async fn real_backend_against_the_fake_node_reports_bounds_and_seeds_birthdays() {
    let node = mined_node(42).await;
    let (running, mut c) = start_on(&node, TEST_CONFIG).await;

    // The first poll ran before the socket opened.
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    let status = info.node.unwrap();
    assert!(status.connected, "{}", status.last_error);
    assert_eq!(status.tip_height, 42);
    assert_eq!(status.tip_hash, gyges_chain::display_hash(&node.tip().1));
    assert_eq!(status.retained_from, 0);
    assert!(!status.pruned);
    assert!(status.last_error.is_empty());

    // The shared block cache exists, private, bound to this network.
    let cache = running._home.path().join("regtest/cache/blocks.sqlite");
    assert!(cache.is_file());
    assert_eq!(std::fs::metadata(&cache).unwrap().mode() & 0o777, 0o600);
    let db = running.state.block_cache.as_ref().expect("cache open");
    assert!(db.is_empty().unwrap());

    // `key init` takes its birthday from the live tip through the real
    // backend: tree state at 41, account born at 42.
    let resp = init_key(&mut c, "main").await;
    assert_eq!(resp.birthday_height, 42);
    assert!(resp.ufvk.starts_with("uviewregtest"), "{}", resp.ufvk);
    let calls = node.calls();
    assert!(calls.iter().any(|m| m == "z_gettreestate"), "{calls:?}");

    // A restore below the (now) pruned window is refused with the window.
    node.set_prune_height(Some(30));
    let err = c
        .restore_key(RestoreKeyRequest {
            allow_backfill: true,
            ..restore_req("old", 20)
        })
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::FallbackUnavailable);
    assert!(
        detail.detail.contains("retained from 30"),
        "{}",
        detail.detail
    );

    // Inside the window it works and reads the node's tree state.
    let ok = c
        .restore_key(restore_req("old", 31))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.birthday_height, 31);

    // Shutdown checkpoints the cache (no -wal left behind).
    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    running.task.await.unwrap().unwrap();
    let wal = cache.with_extension("sqlite-wal");
    assert!(
        !wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0,
        "WAL not checkpointed"
    );
}

/// Drain a `WaitSync` / `RunSync` stream; returns the final element.
async fn drain(
    stream: Result<tonic::Response<tonic::Streaming<SyncProgress>>, tonic::Status>,
) -> Result<SyncProgress, tonic::Status> {
    let mut stream = stream?.into_inner();
    let mut last = None;
    while let Some(item) = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("stream element within 30s")
    {
        let p = item?;
        let done = p.done;
        last = Some(p);
        if done {
            break;
        }
    }
    Ok(last.expect("at least one element"))
}

async fn wait_spendable(
    c: &mut GygesClient<Channel>,
    key_id: &str,
) -> gyges_proto::v1::KeySyncStatus {
    let p = drain(
        c.wait_sync(WaitSyncRequest {
            key_id: key_id.into(),
            until: SyncTarget::Spendable as i32,
            ..Default::default()
        })
        .await,
    )
    .await
    .expect("wait_sync");
    assert!(p.done);
    p.status.expect("status")
}

#[tokio::test]
async fn scheduler_scans_to_the_tip_credits_transparent_outputs_and_survives_a_reorg() {
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, TEST_CONFIG).await;

    // No keys: an empty status, and WaitSync on an unknown key is typed.
    let st = c
        .get_sync_status(GetSyncStatusRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert!(st.keys.is_empty());
    let err = drain(
        c.wait_sync(WaitSyncRequest {
            key_id: "nope".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);

    // A key born at the tip is scanned and spendable after one batch.
    let resp = init_key(&mut c, "main").await;
    assert_eq!(resp.birthday_height, 10);
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 10, "{status:?}");
    assert_eq!(status.chain_tip, 10);
    assert!(status.scanned && status.spendable);
    assert_eq!(status.state(), SyncState::Idle);
    assert_eq!(status.blocks_remaining, 0);
    let st = c
        .get_sync_status(GetSyncStatusRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.keys.len(), 1);
    assert!(
        st.keys[0].detail.starts_with("synced"),
        "{}",
        st.keys[0].detail
    );

    // Pay the key's first transparent receiver in a new block, mine two
    // more, and watch the scheduler pick it all up from its poll.
    let key = running.state.registry.resolve("main").unwrap();
    let account = key.wallet().unwrap().get_account_ids().unwrap()[0];
    let receiver = transparent_receiver(&running.state, "main");
    let paid = node.mine_with_payments(&[(receiver, 70_000)]);
    assert_eq!(paid.height, 11);
    node.mine(2);
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 13, "{status:?}");
    {
        let w = key.wallet().unwrap();
        let summary = w
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .expect("summary");
        let balance = &summary.account_balances()[&account];
        assert_eq!(
            u64::from(balance.unshielded_balance().total()),
            70_000,
            "the transparent output was credited from the raw block"
        );
        assert_eq!(
            w.block_metadata(BlockHeight::from_u32(13))
                .unwrap()
                .unwrap()
                .block_hash()
                .0,
            node.block(13).unwrap().hash
        );
    }
    let cache = running.state.block_cache.as_ref().unwrap();
    assert_eq!(
        cache.hash_at(BlockHeight::from_u32(11)).unwrap(),
        Some(paid.hash)
    );

    // A second key born at the tip (13): its only scanned blocks are about
    // to be reorged away, so its rewind cannot truncate (nothing scanned at
    // or below the fork) and resets to the node's tree state instead.
    let late = init_key(&mut c, "late").await;
    assert_eq!(late.birthday_height, 13);
    let status = wait_spendable(&mut c, "late").await;
    assert_eq!(status.scanned_tip, 13, "{status:?}");

    // A 2-block reorg: the node drops 12 and 13 and mines 12, 13, 14 anew.
    let old_12 = node.block(12).unwrap().hash;
    node.invalidate_from(12);
    node.mine(3);
    let new_12 = node.block(12).unwrap().hash;
    assert_ne!(old_12, new_12);
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 14, "{status:?}");
    let status = wait_spendable(&mut c, "late").await;
    assert_eq!(status.scanned_tip, 14, "{status:?}");
    {
        // Its fork point is 12 (it never scanned lower, so there is nothing
        // older to disagree about): the reset to the node's state at 12
        // keeps the birthday at 13 and rescans 13 and 14 on the new chain.
        let late_key = running.state.registry.resolve("late").unwrap();
        let w = late_key.wallet().unwrap();
        assert_eq!(
            w.get_wallet_birthday().unwrap(),
            Some(BlockHeight::from_u32(13))
        );
        assert!(
            w.block_metadata(BlockHeight::from_u32(12))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            w.block_metadata(BlockHeight::from_u32(13))
                .unwrap()
                .unwrap()
                .block_hash()
                .0,
            node.block(13).unwrap().hash,
            "the late key follows the new chain from its birthday"
        );
        assert_eq!(
            w.block_fully_scanned().unwrap().map(|m| m.block_height()),
            Some(BlockHeight::from_u32(14))
        );
    }
    {
        let w = key.wallet().unwrap();
        assert_eq!(
            w.block_metadata(BlockHeight::from_u32(12))
                .unwrap()
                .unwrap()
                .block_hash()
                .0,
            new_12,
            "the wallet follows the new chain"
        );
        // Block 11 (below the fork) and its output survived the rewind.
        let summary = w
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        assert_eq!(
            u64::from(
                summary.account_balances()[&account]
                    .unshielded_balance()
                    .total()
            ),
            70_000
        );
    }
    assert_eq!(
        cache.hash_at(BlockHeight::from_u32(12)).unwrap(),
        Some(new_12)
    );

    // RunSync: a rewind needs confirmation, then rescans to the tip.
    let err = drain(
        c.run_sync(RunSyncRequest {
            key_id: "main".into(),
            from_height: 11,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::ConfirmationRequired);
    let p = drain(
        c.run_sync(RunSyncRequest {
            key_id: "main".into(),
            from_height: 11,
            confirm_rewind: true,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let status = p.status.unwrap();
    assert!(status.spendable && status.scanned_tip == 14, "{status:?}");
    {
        let w = key.wallet().unwrap();
        let summary = w
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        assert_eq!(
            u64::from(
                summary.account_balances()[&account]
                    .unshielded_balance()
                    .total()
            ),
            70_000,
            "re-indexed after the rescan"
        );
    }

    // Pruning past the key's position stalls it with the documented fix,
    // WaitSync fails fast, and the key recovers when the window widens.
    node.mine(5);
    node.set_prune_height(Some(18));
    let stalled = wait_status(&mut c, "main", "stalled", |k| {
        k.state() == SyncState::Stalled
    })
    .await;
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::PrunedPastScanTip
    );
    assert!(
        stalled.detail.contains("retains from 18"),
        "{}",
        stalled.detail
    );
    let err = drain(
        c.wait_sync(WaitSyncRequest {
            key_id: "main".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    let typed = GygesError::from_status(&err).unwrap();
    assert_eq!(typed.reason(), ErrorReason::NotSynced);
    assert!(
        typed.detail.contains("pruned-past-scan-tip"),
        "{}",
        typed.detail
    );

    // Widen the window again: the next tick re-evaluates the invariant and
    // the key leaves STALLED on its own. (WaitSync on a stalled key fails
    // at once by design, so wait for the state to clear first.)
    node.set_prune_height(None);
    wait_status(&mut c, "main", "unstalled", |k| {
        k.state() != SyncState::Stalled
    })
    .await;
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 19, "{status:?}");

    // Signer-only profiles have nothing to sync.
    let err = c
        .get_sync_status(GetSyncStatusRequest {
            key_id: "nope".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);
    running.task.abort();
}

#[tokio::test]
async fn offline_node_keeps_keys_initializing_then_stalls_after_the_grace() {
    let url = closed_port_url();
    let running = start_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[daemon]\noffline_grace = \"2s\"\n",
        |o| o.zakura_rpc = Some(url),
    )
    .await;
    let mut c = client(&running.socket).await;
    // A wallet-bearing key without a node: restore at the default birthday.
    c.restore_key(restore_req("r", 0)).await.unwrap();

    // Initializing (IDLE) on every pass until the grace runs out.
    let stalled = wait_status(&mut c, "r", "stalled", |k| {
        if k.state() == SyncState::Stalled {
            return true;
        }
        assert_eq!(k.state(), SyncState::Idle, "{k:?}");
        false
    })
    .await;
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::NodeUnreachable
    );
    assert!(
        stalled.detail.contains("node unreachable"),
        "{}",
        stalled.detail
    );
    running.task.abort();
}

/// Every `(from, to)` of a "batch scanned" line for `key_id` from now on.
/// A follower on the shared hub, so a line the ring later evicts (every
/// test in this binary logs there) is still counted.
fn batch_ranges(key_id: &'static str) -> Arc<std::sync::Mutex<Vec<(u32, u32)>>> {
    let out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = out.clone();
    let mut stream = test_hub().stream(&StreamLogsRequest {
        follow: true,
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Some(Ok(e)) = stream.next().await {
            if e.message == "batch scanned"
                && e.fields.get("key_id").map(String::as_str) == Some(key_id)
            {
                let field = |k: &str| e.fields[k].parse::<u32>().unwrap();
                sink.lock().unwrap().push((field("from"), field("to")));
            }
        }
    });
    out
}

/// Run `f` every `every` until it returns `Ok`, for at most `timeout`. An
/// `Err` carries what was seen instead, for the panic message.
async fn poll_until<T, D: std::fmt::Debug>(
    what: &str,
    timeout: Duration,
    every: Duration,
    mut f: impl AsyncFnMut() -> Result<T, D>,
) -> T {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let seen = match f().await {
            Ok(v) => return v,
            Err(seen) => seen,
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}; last seen {seen:?}"
        );
        tokio::time::sleep(every).await;
    }
}

/// Wait until `f` holds, polling every 20 ms for at most 30 s.
async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    poll_until(
        what,
        Duration::from_secs(30),
        Duration::from_millis(20),
        async || if f() { Ok(()) } else { Err(()) },
    )
    .await;
}

/// Small batches, so a 300-block chain is thirty of them.
fn small_batch_config() -> String {
    format!("{ONE_CONF_CONFIG}[cache]\nscan_batch = 10\nfetch_batch = 10\n")
}

/// TESTING.md §3 row 16: `daemon stop` mid-scan. The node holds the
/// scheduler's next fetch, so the stop lands deterministically inside a
/// batch. Shutdown waits for that batch to finish (one more batch is
/// committed after the stop was asked for, not zero), checkpoints the
/// cache, and the restarted daemon goes on from where the wallet is,
/// scanning no range it had scanned before.
#[tokio::test]
async fn daemon_stop_mid_scan_finishes_the_batch_and_restart_does_not_rescan() {
    let _ = test_hub();
    let node = mined_node(300).await;
    let (running, mut c) = start_on(&node, &small_batch_config()).await;
    let batches = batch_ranges("row16");

    node.hold_after_raw_blocks(120);
    c.restore_key(restore_req("row16", 1)).await.unwrap();
    eventually("the scheduler to wait on the node", || {
        node.held_requests() > 0
    })
    .await;
    let before = batches.lock().unwrap().len();
    assert!(before > 0, "some batches were scanned before the stop");

    c.shutdown(ShutdownRequest { graceful: true })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let Running {
        _home: home,
        state,
        task,
        ..
    } = running;
    assert!(
        !task.is_finished(),
        "shutdown waits for the batch the scheduler is fetching"
    );
    node.release();
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("shutdown within 30 s")
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stopped: Vec<(u32, u32)> = batches.lock().unwrap().clone();
    assert_eq!(
        stopped.len(),
        before + 1,
        "exactly the batch in hand was finished: {stopped:?}"
    );

    // What the wallet committed is exactly what was logged as scanned: no
    // batch was cut off between its commit and its log line.
    let max_scanned = state
        .registry
        .resolve("row16")
        .unwrap()
        .wallet()
        .unwrap()
        .block_max_scanned()
        .unwrap()
        .expect("scanned something")
        .block_height();
    let logged_max = stopped.iter().map(|&(_, to)| to).max().unwrap();
    assert_eq!(u32::from(max_scanned), logged_max, "{stopped:?}");
    assert!(logged_max < 300, "the stop landed mid-scan: {stopped:?}");
    let wal = home.path().join("regtest/cache/blocks.sqlite-wal");
    assert!(
        !wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0,
        "WAL not checkpointed"
    );
    drop(state);

    // Restart on the same home: the key resumes and reaches the tip
    // without scanning any range again.
    let running = start_in(home, |o| o.zakura_rpc = Some(node.url().to_string())).await;
    let mut c = client(&running.socket).await;
    wait_spendable(&mut c, "row16").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let all: Vec<(u32, u32)> = batches.lock().unwrap().clone();
    let after = &all[stopped.len()..];
    assert!(!after.is_empty(), "the restart scanned the rest: {all:?}");
    for &(a_from, a_to) in after {
        for &(b_from, b_to) in &stopped {
            assert!(
                a_to < b_from || b_to < a_from,
                "{a_from}..={a_to} after the restart rescans {b_from}..={b_to}: {all:?}"
            );
        }
    }
    running.task.abort();
}

/// TESTING.md §3 row 17: three keys over one node share the block cache, so
/// each block is fetched from the node once. A block costs two `getblock`
/// calls (verbosity 0 for the body, 1 for the tree sizes), so the count is
/// twice the chain's length, not six times.
#[tokio::test]
async fn three_keys_fetch_each_block_from_the_node_once() {
    const BLOCKS: usize = 60;
    let _ = test_hub();
    let node = mined_node(BLOCKS as u32).await;
    let (running, mut c) = start_on(&node, &small_batch_config()).await;
    let getblocks = |node: &FakeNode| node.calls().iter().filter(|m| *m == "getblock").count();
    let before = getblocks(&node);

    for id in ["row17a", "row17b", "row17c"] {
        c.restore_key(restore_req(id, 1)).await.unwrap();
    }
    for id in ["row17a", "row17b", "row17c"] {
        wait_spendable(&mut c, id).await;
    }
    assert_eq!(
        getblocks(&node) - before,
        2 * BLOCKS,
        "each of the {BLOCKS} blocks fetched once, at both verbosities"
    );
    running.task.abort();
}

// ---------------------------------------------------------------------------
// The transaction engine (ROADMAP.md M1, TxEngine)
// ---------------------------------------------------------------------------

/// Every event of a send stream, or the status that ended it.
async fn collect_events(
    stream: Result<tonic::Response<tonic::Streaming<SendEvent>>, tonic::Status>,
) -> Result<Vec<SendEvent>, tonic::Status> {
    let mut s = stream?.into_inner();
    let mut out = Vec::new();
    while let Some(item) = s.next().await {
        out.push(item?);
    }
    Ok(out)
}

fn event_names(events: &[SendEvent]) -> Vec<&'static str> {
    events
        .iter()
        .map(|e| match e.event {
            Some(send_event::Event::Proposed(_)) => "proposed",
            Some(send_event::Event::Proving(_)) => "proving",
            Some(send_event::Event::SignatureRequired(_)) => "signature_required",
            Some(send_event::Event::Signed(_)) => "signed",
            Some(send_event::Event::Broadcast(_)) => "broadcast",
            Some(send_event::Event::TexQueued(_)) => "tex_queued",
            Some(send_event::Event::Mined(_)) => "mined",
            None => "none",
        })
        .collect()
}

fn proposal_of(events: &[SendEvent]) -> Proposal {
    match &events[0].event {
        Some(send_event::Event::Proposed(p)) => p.clone(),
        other => panic!("expected Proposed first, got {other:?}"),
    }
}

fn broadcast_txid(events: &[SendEvent]) -> String {
    events
        .iter()
        .find_map(|e| match &e.event {
            Some(send_event::Event::Broadcast(b)) => Some(b.txid.clone()),
            _ => None,
        })
        .expect("a Broadcast event")
}

fn mined_height(events: &[SendEvent]) -> u32 {
    events
        .iter()
        .find_map(|e| match &e.event {
            Some(send_event::Event::Mined(m)) => Some(m.height),
            _ => None,
        })
        .expect("a Mined event")
}

/// Answer a passphrase `SignatureRequired` with `passphrase` through
/// `UnlockKey { session_id }` (the inline unlock flow of API.md §6.2).
async fn answer_session(
    c: &mut GygesClient<Channel>,
    r: &gyges_proto::v1::SignatureRequired,
    passphrase: &str,
) -> Result<(), tonic::Status> {
    assert_eq!(r.kind(), SignatureKind::Passphrase);
    assert_eq!(r.session_id.len(), 32);
    assert!(r.summary.is_some());
    c.unlock_key(UnlockKeyRequest {
        key_id: r.key_id.clone(),
        passphrase: passphrase.into(),
        session_id: r.session_id.clone(),
        ..Default::default()
    })
    .await?;
    Ok(())
}

/// Drive a send stream to completion on `c`, answering `SignatureRequired`
/// with `passphrase` and showing every event to `on_event` as it arrives.
/// Returns every event; each must come within 60 s.
async fn send_with_session(
    c: &mut GygesClient<Channel>,
    req: SendTransactionRequest,
    passphrase: &str,
    mut on_event: impl FnMut(&SendEvent),
) -> Result<Vec<SendEvent>, tonic::Status> {
    let mut s = c.send_transaction(req).await?.into_inner();
    let mut out = Vec::new();
    while let Some(item) = tokio::time::timeout(Duration::from_secs(60), s.next())
        .await
        .expect("a send event within 60 s")
    {
        let ev = item?;
        if let Some(send_event::Event::SignatureRequired(r)) = &ev.event {
            answer_session(c, r, passphrase).await?;
        }
        on_event(&ev);
        out.push(ev);
    }
    Ok(out)
}

/// Pay `z` zatoshis to `key_id`'s first transparent receiver in a new
/// block, mine one more and wait until the key is spendable. Returns the
/// paying block.
async fn fund(
    node: &FakeNode,
    state: &DaemonState,
    c: &mut GygesClient<Channel>,
    key_id: &str,
    z: u64,
) -> gyges_chain::testing::BuiltBlock {
    let paid = node.mine_with_payments(&[(transparent_receiver(state, key_id), z)]);
    node.mine(1);
    wait_spendable(c, key_id).await;
    paid
}

/// [`fund`], then shield it all under a daemon-scoped unlock, which stays.
/// The shield is left in the mempool; returns its events.
async fn fund_and_shield(
    node: &FakeNode,
    state: &DaemonState,
    c: &mut GygesClient<Channel>,
    key_id: &str,
    z: u64,
) -> Vec<SendEvent> {
    fund(node, state, c, key_id, z).await;
    unlock_daemon(c, key_id).await;
    let events = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: key_id.into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        event_names(&events).last(),
        Some(&"broadcast"),
        "{events:?}"
    );
    events
}

fn balance_of(resp: &GetBalanceResponse, pool: gyges_proto::v1::Pool) -> (i64, i64) {
    resp.pools
        .iter()
        .find(|p| p.pool() == pool)
        .map(|p| (p.spendable, p.pending))
        .unwrap_or((0, 0))
}

/// The key's current unified address, as `gyges address current` prints it.
async fn current_address(c: &mut GygesClient<Channel>, key_id: &str) -> String {
    c.get_current_address(gyges_proto::v1::GetCurrentAddressRequest {
        key_id: key_id.into(),
    })
    .await
    .unwrap()
    .into_inner()
    .address
}

/// Fund a transparent receiver, shield it, spend Orchard to the key's own
/// unified address through the inline-unlock session, pay a transparent
/// recipient with `max`, and see the balance move at every step; also the
/// documented refusals (insufficient funds, memo to a t-addr, tex1, node
/// rejection, an aborted session, a wrong passphrase).
#[tokio::test]
async fn tx_engine_shields_spends_orchard_and_pays_transparent_through_the_fake_node() {
    use gyges_proto::v1::Pool;
    let _ = test_hub();
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    let state = &running.state;
    let params = Network::Regtest.consensus_params();

    // No key yet: a typed error before any stream.
    let err = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);

    init_key(&mut c, "main").await;
    wait_spendable(&mut c, "main").await;

    let key = state.registry.resolve("main").unwrap();
    let t_recipient = t_recipient();

    // Empty wallet: INSUFFICIENT_FUNDS arrives as the stream's error.
    let err = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: zats(1_000),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InsufficientFunds, "{err:?}");

    // Argument checks happen before the stream opens.
    for (to, memo, want) in [
        (
            t_recipient.clone(),
            b"hi".to_vec(),
            ErrorReason::InvalidArgument,
        ),
        (
            "t1nonsense".to_string(),
            vec![],
            ErrorReason::InvalidArgument,
        ),
        (
            // A memo cannot go to a ZIP 320 recipient either.
            zcash_keys::address::Address::Tex([9; 20]).encode(&params),
            b"hi".to_vec(),
            ErrorReason::InvalidArgument,
        ),
    ] {
        let Err(err) = c
            .send_transaction(SendTransactionRequest {
                key_id: "main".into(),
                to,
                amount: zats(1_000),
                memo,
                ..Default::default()
            })
            .await
        else {
            panic!("expected a refusal before streaming");
        };
        assert_eq!(reason(&err), want, "{err:?}");
    }

    // Fund the transparent receiver with 1 ZEC and let it confirm.
    fund(&node, state, &mut c, "main", 100_000_000).await;
    let b = balance(&mut c, "main").await;
    assert_eq!(balance_of(&b, Pool::Transparent), (100_000_000, 0), "{b:?}");
    assert_eq!(b.total_spendable, 100_000_000);
    assert_eq!(b.min_confirmations, 1);

    // Shield with a daemon-scoped unlock already in place: no
    // SignatureRequired, the stream runs to Broadcast on its own.
    unlock_daemon(&mut c, "main").await;
    let dry = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "main".into(),
            dry_run: true,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(event_names(&dry), ["proposed"]);
    let p = proposal_of(&dry);
    assert_eq!(p.steps.len(), 1);
    assert_eq!(p.steps[0].inputs[0].pool(), Pool::Transparent);
    assert_eq!(p.steps[0].inputs[0].value, 100_000_000);
    let shield_fee = p.total_fee;
    assert!(shield_fee > 0 && shield_fee < 100_000, "{p:?}");
    assert!(p.expiry_height > p.anchor_height, "{p:?}");
    assert!(!p.upstream_proposal.is_empty());

    let events = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "main".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        event_names(&events),
        ["proposed", "proving", "proving", "signed", "broadcast"],
        "{events:?}"
    );
    let shield_txid = broadcast_txid(&events);
    assert_eq!(
        node.mempool(),
        vec![gyges_chain::parse_display_hash(&shield_txid).unwrap()]
    );
    c.lock_key(LockKeyRequest {
        key_id: "main".into(),
        all: false,
    })
    .await
    .unwrap();

    // Mined: the transparent value is gone and the change is Ironwood (the
    // live Orchard-protocol pool after NU6.3; see OVERVIEW.md §4.3).
    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let b = balance(&mut c, "main").await;
    assert_eq!(balance_of(&b, Pool::Transparent), (0, 0), "{b:?}");
    let orchard_after_shield = 100_000_000 - shield_fee;
    assert_eq!(
        balance_of(&b, Pool::Ironwood),
        (orchard_after_shield, 0),
        "{b:?}"
    );
    assert_eq!(balance_of(&b, Pool::Orchard), (0, 0), "{b:?}");
    {
        let w = key.wallet().unwrap();
        let h = w
            .get_tx_height(zcash_protocol::TxId::from_bytes(
                gyges_chain::parse_display_hash(&shield_txid).unwrap(),
            ))
            .unwrap();
        assert_eq!(h, Some(BlockHeight::from_u32(13)), "shield mined at 13");
    }

    // An Orchard spend to our own unified address through the session
    // flow: a wrong passphrase is refused (and rate-limited) without ending
    // the stream, then the right one signs.
    let ua = current_address(&mut c, "main").await;
    let mut s = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: ua.clone(),
            amount: zats(30_000_000),
            memo: b"to myself".to_vec(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut names = Vec::new();
    let mut send_fee = 0;
    while let Some(item) = s.next().await {
        let ev = item.unwrap();
        match &ev.event {
            Some(send_event::Event::Proposed(p)) => {
                send_fee = p.total_fee;
                assert_eq!(p.total_debit, 30_000_000 + send_fee);
                let outs = &p.steps[0].outputs;
                assert!(
                    outs.iter().any(|o| o.address == ua && o.has_memo),
                    "{outs:?}"
                );
                assert!(outs.iter().any(|o| o.is_change), "{outs:?}");
                names.push("proposed");
            }
            Some(send_event::Event::SignatureRequired(r)) => {
                names.push("signature_required");
                let sessions = c
                    .list_signing_sessions(ListSigningSessionsRequest::default())
                    .await
                    .unwrap()
                    .into_inner()
                    .sessions;
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].session_id, r.session_id);
                assert_eq!(sessions[0].status(), SessionStatus::AwaitingSignature);
                let err = c
                    .unlock_key(UnlockKeyRequest {
                        key_id: "main".into(),
                        passphrase: "wrong".into(),
                        session_id: r.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                assert_eq!(reason(&err), ErrorReason::InvalidPassphrase);
                let err = c
                    .unlock_key(UnlockKeyRequest {
                        key_id: "main".into(),
                        passphrase: "pw".into(),
                        session_id: r.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                assert_eq!(reason(&err), ErrorReason::RateLimited);
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let resp = c
                    .unlock_key(UnlockKeyRequest {
                        key_id: "main".into(),
                        passphrase: "pw".into(),
                        session_id: r.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .into_inner();
                assert!(
                    resp.session_token.is_empty(),
                    "a session unlock returns no token"
                );
                // Satisfied once only.
                let err = c
                    .unlock_key(UnlockKeyRequest {
                        key_id: "main".into(),
                        passphrase: "pw".into(),
                        session_id: r.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                assert_eq!(reason(&err), ErrorReason::SessionNotFound);
            }
            Some(send_event::Event::Proving(_)) => names.push("proving"),
            Some(send_event::Event::Signed(_)) => names.push("signed"),
            Some(send_event::Event::Broadcast(_)) => names.push("broadcast"),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        names,
        [
            "proposed",
            "proving",
            "proving",
            "signature_required",
            "signed",
            "broadcast"
        ]
    );
    assert_eq!(
        state.vault.unlock_count(),
        0,
        "no unlock survives the session"
    );
    let finished = c
        .list_signing_sessions(ListSigningSessionsRequest {
            key_id: "main".into(),
            include_finished: true,
        })
        .await
        .unwrap()
        .into_inner()
        .sessions;
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].status(), SessionStatus::Completed);

    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let b = balance(&mut c, "main").await;
    let orchard_after_self_send = orchard_after_shield - send_fee;
    assert_eq!(
        balance_of(&b, Pool::Ironwood),
        (orchard_after_self_send, 0),
        "a send to ourselves costs the fee only: {b:?}"
    );

    // The node refuses: NODE_REJECTED with its text, nothing in the mempool.
    node.set_reject_broadcasts(Some("tx-expired-test".into()));
    let err = send_with_session(
        &mut c,
        SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: zats(1_000_000),
            ..Default::default()
        },
        "pw",
        |_| {},
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::NodeRejected, "{err:?}");
    assert!(
        GygesError::from_status(&err)
            .unwrap()
            .node_error
            .contains("tx-expired-test")
    );
    assert!(node.mempool().is_empty());
    node.set_reject_broadcasts(None);
    // The refused transaction stays in the wallet as a pending spend until
    // it expires, so the notes it chose are not spendable meanwhile; mine
    // past its expiry so the rest of the test sees the funds again.
    node.mine(45);
    wait_spendable(&mut c, "main").await;

    // An aborted session ends its stream with CANCELLED.
    let mut s = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: zats(1_000_000),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut aborted = None;
    loop {
        match s.next().await {
            Some(Ok(ev)) => {
                if let Some(send_event::Event::SignatureRequired(r)) = ev.event {
                    let x = c
                        .abort_signing_session(AbortSigningSessionRequest {
                            session_id: r.session_id.clone(),
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    assert_eq!(x.status(), SessionStatus::Aborted);
                    aborted = Some(r.session_id);
                }
            }
            Some(Err(status)) => {
                assert_eq!(reason(&status), ErrorReason::Cancelled, "{status:?}");
                assert_eq!(
                    GygesError::from_status(&status).unwrap().session_id,
                    aborted.clone().unwrap()
                );
                break;
            }
            None => panic!("the stream ended without an error after the abort"),
        }
    }
    let err = c
        .abort_signing_session(AbortSigningSessionRequest {
            session_id: "00".repeat(16),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SessionNotFound);

    // `max` to a transparent recipient empties the shielded pool (no
    // change), and `wait_for_mined` keeps the stream open until the block
    // that includes it is scanned: mine once Broadcast has been seen.
    let max = SendTransactionRequest {
        key_id: "main".into(),
        to: t_recipient.clone(),
        amount: Some(gyges_proto::v1::Amount {
            value: Some(gyges_proto::v1::amount::Value::Max(true)),
        }),
        wait_for_mined: true,
        ..Default::default()
    };
    let events = send_with_session(&mut c, max, "pw", |ev| {
        if let Some(send_event::Event::Broadcast(_)) = ev.event {
            node.mine(2);
        }
    })
    .await
    .unwrap_or_else(|e| panic!("max send: {e:?}"));
    let p = proposal_of(&events);
    let paid = p.steps[0]
        .outputs
        .iter()
        .find(|o| o.address == t_recipient)
        .expect("the payment")
        .value;
    assert_eq!(paid + p.total_fee, orchard_after_self_send, "{p:?}");
    // Upstream always carries an Ironwood change output in a shielded
    // spend, zero-valued when there is nothing left; `max` leaves no value
    // behind.
    assert!(
        p.steps[0]
            .outputs
            .iter()
            .all(|o| !o.is_change || o.value == 0),
        "max leaves no change value: {p:?}"
    );
    assert_eq!(
        event_names(&events).last(),
        Some(&"mined"),
        "{:?}",
        event_names(&events)
    );
    assert_eq!(
        mined_height(&events),
        node.tip().0 - 1,
        "mined in the first of the two blocks"
    );
    wait_spendable(&mut c, "main").await;
    let b = balance(&mut c, "main").await;
    assert_eq!(b.total_spendable, 0, "{b:?}");
    assert_eq!(b.total_pending, 0, "{b:?}");

    running.task.abort();
}

/// A fully transparent send without change (transparent inputs, one
/// transparent output) has nothing scanning can find: no nullifier of ours
/// and no shielded output. Upstream queues it for a status lookup, and the
/// scheduler asks the node and records the mined height, so
/// `wait_for_mined`, `WaitSync { txid }` and `ListTransactions` see it
/// (ROADMAP.md M1 leftovers). Before that, `wait_for_mined` never ended.
#[tokio::test]
async fn a_fully_transparent_send_is_marked_mined_from_the_node() {
    use gyges_proto::v1::Pool;
    let _ = test_hub();
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    let state = &running.state;

    init_key(&mut c, "tsend").await;
    wait_spendable(&mut c, "tsend").await;
    fund(&node, state, &mut c, "tsend", 100_000_000).await;
    unlock_daemon(&mut c, "tsend").await;
    let key = state.registry.resolve("tsend").unwrap();

    // `wait_for_mined`: each event within 60 s, or it never ended.
    let max = SendTransactionRequest {
        key_id: "tsend".into(),
        to: t_recipient(),
        amount: Some(gyges_proto::v1::Amount {
            value: Some(gyges_proto::v1::amount::Value::Max(true)),
        }),
        wait_for_mined: true,
        ..Default::default()
    };
    let events = send_with_session(&mut c, max, "pw", |ev| {
        if let Some(send_event::Event::Broadcast(b)) = &ev.event {
            // Scanning cannot see it, so upstream queued it for a status
            // lookup (the reason this test exists).
            let mut internal = hex::decode(&b.txid).unwrap();
            internal.reverse();
            let queued = gyges_core::sync::pending_status(&key.wallet().unwrap()).unwrap();
            assert!(
                queued.iter().any(|t| t[..] == internal[..]),
                "not queued for a status lookup: {queued:?}"
            );
            node.mine(2);
        }
    })
    .await
    .unwrap_or_else(|e| panic!("transparent send: {e:?}"));
    let p = proposal_of(&events);
    let step = &p.steps[0];
    assert!(
        step.inputs.iter().all(|i| i.pool() == Pool::Transparent),
        "{p:?}"
    );
    assert!(
        step.outputs.iter().all(|o| o.pool() == Pool::Transparent),
        "fully transparent, no change output: {p:?}"
    );
    assert_eq!(
        event_names(&events).last(),
        Some(&"mined"),
        "{:?}",
        event_names(&events)
    );
    let txid = broadcast_txid(&events);
    assert_eq!(
        mined_height(&events),
        node.tip().0 - 1,
        "the first of the two blocks"
    );

    // `sync wait --txid` reads the same mined height.
    tokio::time::timeout(
        Duration::from_secs(60),
        drain(
            c.wait_sync(WaitSyncRequest {
                key_id: "tsend".into(),
                txid: txid.clone(),
                confirmations: 1,
                ..Default::default()
            })
            .await,
        ),
    )
    .await
    .expect("WaitSync on the txid never ended")
    .expect("wait_sync");
    let queued = gyges_core::sync::pending_status(&key.wallet().unwrap()).unwrap();
    assert!(queued.is_empty(), "still queued after mining: {queued:?}");

    let b = balance(&mut c, "tsend").await;
    assert_eq!(b.total_spendable, 0, "{b:?}");
    assert_eq!(b.total_pending, 0, "{b:?}");

    running.task.abort();
}

/// A daemon with `main` holding 1 ZEC (less the shielding fee) in Ironwood
/// and `bob` empty, both spendable, `main` still unlocked.
async fn sender_and_recipient(config: &str) -> (FakeNode, Running, GygesClient<Channel>) {
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, config).await;
    init_key(&mut c, "main").await;
    init_key(&mut c, "bob").await;
    wait_spendable(&mut c, "main").await;
    fund_and_shield(&node, &running.state, &mut c, "main", 100_000_000).await;
    node.mine(2);
    wait_spendable(&mut c, "main").await;
    wait_spendable(&mut c, "bob").await;
    (node, running, c)
}

/// `main` pays `bob` `amount` and the transaction stays in the mempool.
async fn pay_bob_unmined(node: &FakeNode, c: &mut GygesClient<Channel>, amount: i64) -> String {
    let to = current_address(c, "bob").await;
    let events = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to,
            amount: zats(amount),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let txid = broadcast_txid(&events);
    assert_eq!(
        node.mempool(),
        vec![gyges_chain::parse_display_hash(&txid).unwrap()]
    );
    txid
}

/// SYNC.md §7 with `mempool.scan` on (the default): a payment to another
/// key of the daemon shows as pending for it while still in the mempool,
/// and becomes spendable once mined. `ScanMempool` reports the pass.
#[tokio::test]
async fn the_mempool_loop_shows_an_unmined_payment_as_pending() {
    const AMOUNT: i64 = 10_000_000;
    let _ = test_hub();
    let (node, running, mut c) = sender_and_recipient(ONE_CONF_CONFIG).await;
    pay_bob_unmined(&node, &mut c, AMOUNT).await;

    let every = Duration::from_millis(50);
    let b = poll_until(
        "bob's pending payment",
        Duration::from_secs(15),
        every,
        async || {
            let b = balance(&mut c, "bob").await;
            if b.total_pending == AMOUNT {
                Ok(b)
            } else {
                Err(b)
            }
        },
    )
    .await;
    assert_eq!((b.total_spendable, b.total_pending), (0, AMOUNT), "{b:?}");

    // A forced pass rescans the whole mempool; `bob` has one note there.
    let r = c
        .scan_mempool(gyges_proto::v1::ScanMempoolRequest {
            key_id: "bob".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((r.transactions_scanned, r.notes_found), (1, 1), "{r:?}");
    let err = c
        .scan_mempool(gyges_proto::v1::ScanMempoolRequest {
            key_id: "nobody".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);

    node.mine(1);
    wait_spendable(&mut c, "bob").await;
    let b = balance(&mut c, "bob").await;
    assert_eq!((b.total_spendable, b.total_pending), (AMOUNT, 0), "{b:?}");
    let r = c
        .scan_mempool(gyges_proto::v1::ScanMempoolRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!((r.transactions_scanned, r.notes_found), (0, 0), "{r:?}");
    running.task.abort();
}

/// With `mempool.scan = false` nothing is pending until `ScanMempool`
/// forces a pass (CLI_SPEC.md `sync mempool`).
#[tokio::test]
async fn scan_mempool_forces_a_pass_when_the_loop_is_off() {
    const AMOUNT: i64 = 20_000_000;
    let _ = test_hub();
    let config = format!("{ONE_CONF_CONFIG}[mempool]\nscan = false\n");
    let (node, running, mut c) = sender_and_recipient(&config).await;
    pay_bob_unmined(&node, &mut c, AMOUNT).await;
    // Two whole scheduler ticks begun after the payment reached the
    // mempool: with the loop on, the second would have found it.
    let sync = &running.state.sync;
    let need = sync.ticks().0 + 2;
    eventually("two more scheduler ticks", || sync.ticks().1 >= need).await;
    let b = balance(&mut c, "bob").await;
    assert_eq!((b.total_spendable, b.total_pending), (0, 0), "{b:?}");

    // No key: every key's notes are counted (bob's payment and main's
    // change).
    let r = c
        .scan_mempool(gyges_proto::v1::ScanMempoolRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!((r.transactions_scanned, r.notes_found), (1, 2), "{r:?}");
    let b = balance(&mut c, "bob").await;
    assert_eq!((b.total_spendable, b.total_pending), (0, AMOUNT), "{b:?}");
    running.task.abort();
}

// ---------------------------------------------------------------------------
// ZIP 320 (ROADMAP.md M3)
// ---------------------------------------------------------------------------

/// The ZIP 320 row for `step1_txid`, once it reaches `want` (polling
/// `ListSigningSessions`, whose `tex_transfers` carry the queue's rows).
async fn wait_tex_state(
    c: &mut GygesClient<Channel>,
    step1_txid: &str,
    want: gyges_proto::v1::TexState,
) -> gyges_proto::v1::TexQueueEntry {
    wait_tex(c, step1_txid, &format!("{want:?}"), |r| r.state() == want).await
}

/// The ZIP 320 row for `step1_txid`, once `ok` holds for it.
async fn wait_tex(
    c: &mut GygesClient<Channel>,
    step1_txid: &str,
    what: &str,
    ok: impl Fn(&gyges_proto::v1::TexQueueEntry) -> bool,
) -> gyges_proto::v1::TexQueueEntry {
    let what = format!("the tex row to reach {what}");
    let mut last = None;
    poll_until(
        &what,
        Duration::from_secs(90),
        Duration::from_millis(200),
        async || {
            let req = ListSigningSessionsRequest {
                key_id: String::new(),
                include_finished: true,
            };
            let resp = c.list_signing_sessions(req).await.unwrap().into_inner();
            if let Some(row) = resp
                .tex_transfers
                .into_iter()
                .find(|r| r.step1_txid == step1_txid)
            {
                if ok(&row) {
                    return Ok(row);
                }
                last = Some(row);
            }
            Err(last.clone())
        },
    )
    .await
}

/// Wait until the fake node's mempool holds `txid`.
async fn wait_in_mempool(node: &FakeNode, txid: &str) {
    let want = gyges_chain::parse_display_hash(txid).unwrap();
    let what = format!("{txid} to reach the mempool");
    poll_until(
        &what,
        Duration::from_secs(30),
        Duration::from_millis(100),
        async || {
            let pool = node.mempool();
            if pool.contains(&want) {
                Ok(())
            } else {
                Err(pool)
            }
        },
    )
    .await;
}

/// The mined transaction `txid` from the fake node's block at `height`.
fn mined_tx(
    node: &FakeNode,
    height: u32,
    txid: &str,
) -> zcash_primitives::transaction::Transaction {
    let want = gyges_chain::parse_display_hash(txid).unwrap();
    let block = node.block(height).expect("block exists");
    let i = block
        .txids
        .iter()
        .position(|t| *t == want)
        .unwrap_or_else(|| panic!("{txid} not in block {height}"));
    let branch = zcash_protocol::consensus::BranchId::for_height(
        &regtest_params(),
        BlockHeight::from_u32(height),
    );
    zcash_primitives::transaction::Transaction::read(&block.tx_raw[i][..], branch).unwrap()
}

fn tex_queued(events: &[SendEvent]) -> (String, String) {
    events
        .iter()
        .find_map(|e| match &e.event {
            Some(send_event::Event::TexQueued(t)) => {
                Some((t.step1_txid.clone(), t.step2_txid.clone()))
            }
            _ => None,
        })
        .expect("a TexQueued event")
}

/// Pay a ZIP 320 address three times through the fake node (TESTING.md §3
/// rows 9–11 in miniature): chained in the mempool and mined together;
/// against a node that refuses step 2 until step 1 is mined (the queue
/// finishes it); and with step 2 left to expire after step 1 was mined, so
/// that `ResumeTexTransfer` rebuilds it through a signing session. Every
/// step 2 is checked on the chain: one input (step 1's ephemeral output),
/// one output of exactly the amount to the TEX pubkey hash.
#[tokio::test]
async fn zip320_sends_through_the_fake_node() {
    use gyges_proto::v1::{AbortTexTransferRequest, Pool, ResumeTexTransferRequest, TexState};
    let _ = test_hub();
    let node = mined_node(10).await;
    let config = format!("{ONE_CONF_CONFIG}[tex]\nrebroadcast_interval = \"1s\"\n");
    let (running, mut c) = start_on(&node, &config).await;
    let state = &running.state;
    let params = Network::Regtest.consensus_params();

    // A funded, shielded wallet: 3 ZEC in Ironwood.
    init_key(&mut c, "main").await;
    wait_spendable(&mut c, "main").await;
    fund_and_shield(&node, state, &mut c, "main", 300_000_000).await;
    c.lock_key(LockKeyRequest {
        key_id: "main".into(),
        all: false,
    })
    .await
    .unwrap();
    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let ironwood = async |c: &mut GygesClient<Channel>| {
        balance_of(&balance(c, "main").await, Pool::Ironwood).0
    };
    let funded = ironwood(&mut c).await;
    assert!(funded > 299_000_000 && funded < 300_000_000, "{funded}");

    let tex_pkh = [0x42u8; 20];
    let tex_addr = zcash_keys::address::Address::Tex(tex_pkh).encode(&params);
    assert!(tex_addr.starts_with("texregtest1"), "{tex_addr}");

    // --dry-run: both steps, every fee (ARCHITECTURE.md §3.3 step 4).
    let dry = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: tex_addr.clone(),
            amount: zats(50_000_000),
            dry_run: true,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(event_names(&dry), ["proposed"]);
    let p = proposal_of(&dry);
    assert_eq!(p.steps.len(), 2, "{p:?}");
    assert!(
        !p.steps[0].transparent_only && p.steps[1].transparent_only,
        "{p:?}"
    );
    let step2_fee = p.steps[1].fee;
    assert!(step2_fee > 0, "{p:?}");
    let ephemeral = p.steps[0]
        .outputs
        .iter()
        .find(|o| o.is_ephemeral)
        .expect("an ephemeral output");
    assert_eq!(ephemeral.pool(), Pool::Transparent);
    assert_eq!(ephemeral.value, 50_000_000 + step2_fee, "{p:?}");
    assert_eq!(p.steps[1].inputs.len(), 1);
    assert_eq!(p.steps[1].inputs[0].pool(), Pool::Transparent);
    assert_eq!(p.steps[1].inputs[0].value, 50_000_000 + step2_fee);
    assert_eq!(p.steps[1].outputs.len(), 1);
    assert_eq!(p.steps[1].outputs[0].address, tex_addr);
    assert_eq!(p.steps[1].outputs[0].value, 50_000_000);
    assert_eq!(p.total_fee, p.steps[0].fee + step2_fee);
    assert_eq!(p.total_debit, 50_000_000 + p.total_fee);
    let fee_a = p.total_fee;

    // 1. Mempool chaining (row 9): one session signs both steps, both are
    //    offered at once and mined in the same block.
    let events = send_with_session(
        &mut c,
        SendTransactionRequest {
            key_id: "main".into(),
            to: tex_addr.clone(),
            amount: zats(50_000_000),
            ..Default::default()
        },
        "pw",
        |_| {},
    )
    .await
    .unwrap();
    let names = event_names(&events);
    assert_eq!(&names[..2], ["proposed", "signature_required"], "{names:?}");
    let tail: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| !matches!(*n, "proposed" | "signature_required" | "proving"))
        .collect();
    assert_eq!(
        tail,
        ["signed", "signed", "broadcast", "tex_queued", "broadcast"],
        "{names:?}"
    );
    let (s1, s2) = tex_queued(&events);
    assert_eq!(
        node.mempool(),
        vec![
            gyges_chain::parse_display_hash(&s1).unwrap(),
            gyges_chain::parse_display_hash(&s2).unwrap()
        ]
    );
    let row = wait_tex_state(&mut c, &s1, TexState::Step2Broadcast).await;
    assert_eq!(row.step2_txid, s2);
    assert_eq!(row.amount, 50_000_000);
    assert_eq!(row.recipient, tex_addr);
    assert_eq!(row.key_id, "main");
    assert_eq!(row.expiry_height, p.expiry_height, "{row:?}");
    // Too late to abort: both are with the node.
    let err = c
        .abort_tex_transfer(AbortTexTransferRequest {
            key_id: "main".into(),
            step1_txid: s1.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    node.mine(1);
    let (mined_at, _) = node.tip();
    let row = wait_tex_state(&mut c, &s1, TexState::Step2Mined).await;
    assert!(row.last_error.is_empty(), "{row:?}");
    let tx2 = mined_tx(&node, mined_at, &s2);
    let _ = mined_tx(&node, mined_at, &s1);
    let bundle = tx2.transparent_bundle().expect("transparent");
    assert_eq!(bundle.vin.len(), 1);
    assert_eq!(
        bundle.vin[0].prevout().txid().to_string(),
        s1,
        "step 2 spends step 1"
    );
    assert_eq!(bundle.vout.len(), 1, "no change on the ephemeral address");
    assert_eq!(bundle.vout[0].value().into_u64(), 50_000_000);
    assert_eq!(
        bundle.vout[0].recipient_address(),
        Some(transparent::address::TransparentAddress::PublicKeyHash(
            tex_pkh
        ))
    );
    // Nothing to resume on a finished transfer.
    let err = c
        .resume_tex_transfer(ResumeTexTransferRequest {
            key_id: "main".into(),
            step1_txid: s1.clone(),
            session_token: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    // That answer depends on neither the scan nor the node: with the node
    // unreachable (it now wants a cookie the daemon does not send), a
    // finished transfer still has nothing to resume, not NODE_UNREACHABLE.
    let chain = state.chain.clone().expect("networked daemon");
    let wait_connected = async |want: bool| {
        eventually(&format!("node connected={want}"), || {
            gyges_chain::ChainBackend::status(chain.as_ref()).connected == want
        })
        .await
    };
    node.set_cookie(Some("rotated".into()));
    wait_connected(false).await;
    let err = c
        .resume_tex_transfer(ResumeTexTransferRequest {
            key_id: "main".into(),
            step1_txid: s1.clone(),
            session_token: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("nothing to resume"), "{err:?}");
    node.set_cookie(None);
    wait_connected(true).await;
    wait_spendable(&mut c, "main").await;
    let after_a = ironwood(&mut c).await;
    assert_eq!(
        after_a,
        funded - 50_000_000 - fee_a,
        "both fees left the pool"
    );

    // 2. A node that will not chain mempool transactions (row 10): step 2
    //    is refused until step 1 is mined, then the queue gets it in.
    node.set_reject_transparent_only(Some("bad-txns-inputs-missingorspent".into()));
    let events = send_with_session(
        &mut c,
        SendTransactionRequest {
            key_id: "main".into(),
            to: tex_addr.clone(),
            amount: zats(20_000_000),
            ..Default::default()
        },
        "pw",
        |_| {},
    )
    .await
    .unwrap();
    let names = event_names(&events);
    assert_eq!(
        names.iter().filter(|n| **n == "broadcast").count(),
        1,
        "{names:?}"
    );
    assert!(names.contains(&"tex_queued"), "{names:?}");
    let (s1, s2) = tex_queued(&events);
    let row = wait_tex_state(&mut c, &s1, TexState::Step1Broadcast).await;
    assert!(row.last_error.contains("missingorspent"), "{row:?}");
    assert_eq!(row.attempts, 2, "{row:?}");
    node.mine(1);
    let row = wait_tex_state(&mut c, &s1, TexState::Step1Mined).await;
    assert_eq!(row.step2_txid, s2);
    node.set_reject_transparent_only(None);
    wait_in_mempool(&node, &s2).await;
    node.mine(1);
    let (mined_at, _) = node.tip();
    wait_tex_state(&mut c, &s1, TexState::Step2Mined).await;
    let tx2 = mined_tx(&node, mined_at, &s2);
    let bundle = tx2.transparent_bundle().expect("transparent");
    assert_eq!(bundle.vout[0].value().into_u64(), 20_000_000);
    assert_eq!(bundle.vin[0].prevout().txid().to_string(), s1);

    // 3. Step 1 mined, step 2 expired (row 11): `step2_failed`, then
    //    `ResumeTexTransfer` through a session builds a new step 2.
    node.set_reject_transparent_only(Some("bad-txns-inputs-missingorspent".into()));
    let events = send_with_session(
        &mut c,
        SendTransactionRequest {
            key_id: "main".into(),
            to: tex_addr.clone(),
            amount: zats(10_000_000),
            ..Default::default()
        },
        "pw",
        |_| {},
    )
    .await
    .unwrap();
    let (s1, old_s2) = tex_queued(&events);
    let row = wait_tex_state(&mut c, &s1, TexState::Step1Broadcast).await;
    let expiry = row.expiry_height;
    node.mine(1);
    wait_tex_state(&mut c, &s1, TexState::Step1Mined).await;
    let (tip, _) = node.tip();
    node.mine(expiry - tip + 1);
    let row = wait_tex_state(&mut c, &s1, TexState::Step2Failed).await;
    assert!(row.last_error.contains("tx resume"), "{row:?}");
    wait_spendable(&mut c, "main").await;
    node.set_reject_transparent_only(None);
    // Without a key: a session, answered with the passphrase.
    let err = c
        .resume_tex_transfer(ResumeTexTransferRequest {
            key_id: "main".into(),
            step1_txid: s1.clone(),
            session_token: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::SignatureRequired, "{err:?}");
    let session_id = GygesError::from_status(&err).unwrap().session_id;
    assert_eq!(session_id.len(), 32);
    let sessions = c
        .list_signing_sessions(ListSigningSessionsRequest {
            key_id: "main".into(),
            include_finished: false,
        })
        .await
        .unwrap()
        .into_inner();
    let s = sessions
        .sessions
        .iter()
        .find(|s| s.session_id == session_id)
        .expect("the resume session is listed");
    assert_eq!(s.step, 2);
    assert_eq!(s.status(), SessionStatus::AwaitingSignature);
    // A second resume while the session is pending does not open another.
    let row = c
        .resume_tex_transfer(ResumeTexTransferRequest {
            key_id: "main".into(),
            step1_txid: s1.clone(),
            session_token: Vec::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(row.state(), TexState::Step2Failed);
    c.unlock_key(UnlockKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        session_id: session_id.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    // The row keeps `step1_mined` (the furthest state) while the queue
    // offers the fresh step 2.
    let row = wait_tex(&mut c, &s1, "a new step 2", |r| r.step2_txid != old_s2).await;
    assert_eq!(row.state(), TexState::Step1Mined, "{row:?}");
    assert!(row.expiry_height > expiry, "{row:?}");
    assert!(row.last_error.is_empty(), "{row:?}");
    let new_s2 = row.step2_txid.clone();
    wait_in_mempool(&node, &new_s2).await;
    node.mine(1);
    let (mined_at, _) = node.tip();
    wait_tex_state(&mut c, &s1, TexState::Step2Mined).await;
    let tx2 = mined_tx(&node, mined_at, &new_s2);
    let bundle = tx2.transparent_bundle().expect("transparent");
    assert_eq!(bundle.vin.len(), 1);
    assert_eq!(bundle.vin[0].prevout().txid().to_string(), s1);
    assert_eq!(bundle.vout.len(), 1);
    assert_eq!(bundle.vout[0].value().into_u64(), 10_000_000);
    assert_eq!(
        bundle.vout[0].recipient_address(),
        Some(transparent::address::TransparentAddress::PublicKeyHash(
            tex_pkh
        ))
    );
    let sessions = c
        .list_signing_sessions(ListSigningSessionsRequest {
            key_id: "main".into(),
            include_finished: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        sessions.tex_transfers.len(),
        3,
        "every transfer is listed with --include-finished"
    );
    assert!(
        sessions
            .tex_transfers
            .iter()
            .all(|r| r.state() == TexState::Step2Mined),
        "{:?}",
        sessions.tex_transfers
    );
    wait_spendable(&mut c, "main").await;
    let final_balance = ironwood(&mut c).await;
    assert!(
        final_balance < after_a - 30_000_000 && final_balance > after_a - 30_200_000,
        "{final_balance} after {after_a}"
    );

    // The audit trail: a `tex_queued` per send, broadcasts, the resume.
    let events: Vec<String> = state
        .logs
        .recent(true, 1000)
        .iter()
        .filter(|e| e.fields.get("key_id").map(String::as_str) == Some("main"))
        .filter_map(|e| e.fields.get("event").cloned())
        .collect();
    assert_eq!(
        events.iter().filter(|e| *e == "tex_queued").count(),
        3,
        "{events:?}"
    );
    assert_eq!(
        events.iter().filter(|e| *e == "tex_resumed").count(),
        1,
        "{events:?}"
    );
    assert!(
        events.iter().filter(|e| *e == "broadcast").count() >= 7,
        "{events:?}"
    );

    running.task.abort();
}

// ---------------------------------------------------------------------------
// The PCZT pipeline (ROADMAP.md M4, first item)
// ---------------------------------------------------------------------------

/// Postcard's unsigned varint (LEB128: seven bits per byte, low bits
/// first, high bit set on every byte but the last).
fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A PCZT with the one occurrence of the value `old` replaced by `new`
/// (same encoded length), which is what a tampered file looks like
/// (TESTING.md §3 row 13): the bytes still parse, only an output value
/// differs from the approved proposal.
fn tamper_value(bytes: &[u8], old: u64, new: u64) -> Vec<u8> {
    let from = varint(old);
    let to = varint(new);
    assert_eq!(from.len(), to.len(), "pick values of equal varint length");
    let hits: Vec<usize> = (0..=bytes.len() - from.len())
        .filter(|&i| bytes[i..i + from.len()] == from[..])
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected the value once in the file: {hits:?}"
    );
    let mut out = bytes.to_vec();
    out[hits[0]..hits[0] + to.len()].copy_from_slice(&to);
    out
}

/// Drive `SignPczt` to its signed bytes, answering `SignatureRequired`
/// with `passphrase` through `UnlockKey { session_id }`.
async fn sign_pczt_with_session(
    c: &mut GygesClient<Channel>,
    pczt: Vec<u8>,
    passphrase: &str,
) -> Result<(Vec<u8>, usize), tonic::Status> {
    use gyges_proto::v1::{SignPcztRequest, sign_pczt_event};
    let mut s = c
        .sign_pczt(SignPcztRequest {
            pczt,
            session_token: Vec::new(),
            key_id: String::new(),
        })
        .await?
        .into_inner();
    let mut prompts = 0;
    let mut signed = None;
    while let Some(item) = s.next().await {
        match item?.event {
            Some(sign_pczt_event::Event::SignatureRequired(r)) => {
                prompts += 1;
                answer_session(c, &r, passphrase).await?;
            }
            Some(sign_pczt_event::Event::Signed(bytes)) => signed = Some(bytes),
            None => {}
        }
    }
    Ok((signed.expect("a Signed event"), prompts))
}

/// `create → inspect → prove → sign → combine → broadcast` over the RPCs
/// with the bytes handed back and forth like files; the balance moves; the
/// tags are read from the file and `key_id` is only an assertion; a
/// tampered file is refused by the Verifier with `INVALID_ARGUMENT`; the
/// documented refusals (unproven, unsigned, already broadcast, mixed keys,
/// a tex1 recipient, garbage).
#[tokio::test]
async fn pczt_pipeline_round_trips_and_the_verifier_refuses_a_tampered_file() {
    use gyges_proto::v1::{
        BroadcastPcztRequest, CombinePcztRequest, CreatePcztRequest, InspectPcztRequest, PcztRole,
        Pool, ProvePcztRequest,
    };
    let _ = test_hub();
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    let state = &running.state;
    let params = Network::Regtest.consensus_params();
    let t_recipient = t_recipient();

    // Two funded keys: `main` for the pipeline, `second` for the mixed-key
    // combine.
    for id in ["main", "second"] {
        init_key(&mut c, id).await;
        wait_spendable(&mut c, id).await;
        let receiver = transparent_receiver(state, id);
        node.mine_with_payments(&[(receiver, 100_000_000)]);
    }
    node.mine(1);
    wait_spendable(&mut c, "main").await;
    wait_spendable(&mut c, "second").await;
    let create = |key_id: &str, to: &str, z: i64| CreatePcztRequest {
        key_id: key_id.into(),
        to: to.into(),
        amount: zats(z),
        memo: Vec::new(),
        min_confirmations: 0,
    };

    // Create: one PCZT, the proposal, the session id; the expiry is the
    // file's long one.
    let created = c
        .create_pczt(create("main", &t_recipient, 50_000_000))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.pczts.len(), 1);
    assert_eq!(created.session_id.len(), 32);
    let proposal = created.proposal.clone().unwrap();
    assert_eq!(proposal.steps.len(), 1);
    let fee = proposal.total_fee;
    assert!(fee > 0);
    assert_eq!(proposal.total_debit, 50_000_000 + fee);
    // The target height is a few blocks above the anchor; the file's
    // expiry is the long one, not `target + 40`.
    assert!(
        proposal.expiry_height >= proposal.anchor_height + gygesd::roles::PCZT_EXPIRY_BLOCKS
            && proposal.expiry_height
                < proposal.anchor_height + gygesd::roles::PCZT_EXPIRY_BLOCKS + 20,
        "{proposal:?}"
    );
    let unsigned = created.pczts[0].clone();
    assert!(!unsigned.is_empty());

    // Inspect reads the tags and the proposal from the file alone.
    let inspect = |c: &mut GygesClient<Channel>, pczt: Vec<u8>, key_id: &str| {
        let req = InspectPcztRequest {
            pczt,
            key_id: key_id.into(),
        };
        let mut c = c.clone();
        async move { c.inspect_pczt(req).await.map(|r| r.into_inner()) }
    };
    let insp = inspect(&mut c, unsigned.clone(), "").await.unwrap();
    assert_eq!(insp.key_id, "main");
    assert_eq!(insp.network(), gyges_proto::v1::Network::Regtest);
    assert_eq!(insp.session_id, created.session_id);
    let s = insp.summary.clone().unwrap();
    assert_eq!(s.expiry_height, proposal.expiry_height);
    assert_eq!(s.total_fee, fee, "{s:?}");
    assert_eq!(s.total_debit, proposal.total_debit, "{s:?}");
    let step = &s.steps[0];
    assert_eq!(step.inputs.len(), 1);
    assert_eq!(step.inputs[0].pool(), Pool::Transparent);
    assert_eq!(step.inputs[0].value, 100_000_000);
    let payment = step
        .outputs
        .iter()
        .find(|o| o.address == t_recipient)
        .expect("the payment");
    assert_eq!(payment.value, 50_000_000);
    assert!(!payment.is_change);
    let change: i64 = step
        .outputs
        .iter()
        .filter(|o| o.is_change && o.pool() == Pool::Ironwood)
        .map(|o| o.value)
        .sum();
    assert_eq!(change, 100_000_000 - 50_000_000 - fee, "{step:?}");
    assert_eq!(
        insp.completed_roles().collect::<Vec<_>>(),
        [
            PcztRole::Creator,
            PcztRole::Constructor,
            PcztRole::IoFinalizer,
            PcztRole::Updater
        ],
        "{insp:?}"
    );
    let pool = |insp: &gyges_proto::v1::InspectPcztResponse, p: Pool| {
        insp.pools
            .iter()
            .find(|x| x.pool() == p)
            .cloned()
            .unwrap_or_else(|| panic!("no {p:?} in {insp:?}"))
    };
    let t = pool(&insp, Pool::Transparent);
    assert_eq!((t.spends, t.outputs), (1, 1));
    assert_eq!((t.signatures_present, t.signatures_required), (0, 1));
    let iw = pool(&insp, Pool::Ironwood);
    assert!(!iw.proofs_present);
    // Both Ironwood actions of a transparent-funded send are dummy spends,
    // which the IO Finalizer signs with their dummy keys: already
    // "signed" by count, while the transparent input still waits.
    assert!(iw.signatures_required >= 2, "{iw:?}");
    assert!(iw.signatures_present <= iw.signatures_required, "{iw:?}");

    // `--key` is an assertion only.
    let err = inspect(&mut c, unsigned.clone(), "second")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyMismatch, "{err:?}");
    assert_eq!(GygesError::from_status(&err).unwrap().key_id, "main");
    assert!(inspect(&mut c, unsigned.clone(), "main").await.is_ok());
    let err = inspect(&mut c, b"not a pczt".to_vec(), "")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");

    // Prove (no key), and broadcasting before signing is refused by name.
    let proven = c
        .prove_pczt(ProvePcztRequest {
            pczt: unsigned.clone(),
            session_token: Vec::new(),
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pczt;
    let insp = inspect(&mut c, proven.clone(), "").await.unwrap();
    assert!(insp.completed_roles().any(|r| r == PcztRole::Prover));
    assert!(pool(&insp, Pool::Ironwood).proofs_present);
    let broadcast = |c: &mut GygesClient<Channel>, pczt: Vec<u8>| {
        let req = BroadcastPcztRequest {
            pczt,
            via_tor: false,
            key_id: String::new(),
        };
        let mut c = c.clone();
        async move { c.broadcast_pczt(req).await.map(|r| r.into_inner()) }
    };
    let err = broadcast(&mut c, proven.clone()).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("not fully signed"), "{err:?}");
    let err = broadcast(&mut c, unsigned.clone()).await.unwrap_err();
    assert!(err.message().contains("not proven"), "{err:?}");

    // Sign through the passphrase session (the key is locked).
    let (signed, prompts) = sign_pczt_with_session(&mut c, proven.clone(), "pw")
        .await
        .unwrap();
    assert_eq!(prompts, 1);
    let insp = inspect(&mut c, signed.clone(), "").await.unwrap();
    assert!(
        insp.completed_roles().any(|r| r == PcztRole::Signer),
        "{insp:?}"
    );
    let t = pool(&insp, Pool::Transparent);
    assert_eq!((t.signatures_present, t.signatures_required), (1, 1));
    let iw = pool(&insp, Pool::Ironwood);
    assert_eq!(iw.signatures_present, iw.signatures_required);

    // Combine: proven ⊕ signed is the signed one; one file is refused; a
    // file of another key is refused before upstream sees it.
    let combined = c
        .combine_pczt(CombinePcztRequest {
            pczts: vec![proven.clone(), signed.clone()],
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pczt;
    let insp = inspect(&mut c, combined.clone(), "").await.unwrap();
    assert!(insp.completed_roles().any(|r| r == PcztRole::Signer));
    let err = c
        .combine_pczt(CombinePcztRequest {
            pczts: vec![signed.clone()],
            key_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument);
    let other = c
        .create_pczt(create("second", &t_recipient, 10_000_000))
        .await
        .unwrap()
        .into_inner();
    let err = c
        .combine_pczt(CombinePcztRequest {
            pczts: vec![signed.clone(), other.pczts[0].clone()],
            key_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyMismatch, "{err:?}");

    // A tampered file: one output value changed on the way, which inspect
    // shows and the Verifier refuses (exit 6), nothing broadcast.
    let tampered = tamper_value(&unsigned, 50_000_000, 50_000_001);
    let insp = inspect(&mut c, tampered.clone(), "").await.unwrap();
    assert!(
        insp.summary.as_ref().unwrap().steps[0]
            .outputs
            .iter()
            .any(|o| o.value == 50_000_001),
        "{insp:?}"
    );
    let tampered_proven = c
        .prove_pczt(ProvePcztRequest {
            pczt: tampered,
            session_token: Vec::new(),
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pczt;
    let (tampered_signed, _) = sign_pczt_with_session(&mut c, tampered_proven, "pw")
        .await
        .unwrap();
    let err = broadcast(&mut c, tampered_signed).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(
        err.message().contains("differs from the approved proposal"),
        "{err:?}"
    );
    assert!(node.mempool().is_empty());

    // `--via-tor` without a fallback endpoint is refused, not sent to the
    // node.
    let err = c
        .broadcast_pczt(BroadcastPcztRequest {
            pczt: combined.clone(),
            via_tor: true,
            key_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::FallbackUnavailable, "{err:?}");
    assert!(node.mempool().is_empty());

    // The genuine one: broadcast, mined, the balance moves; twice is
    // refused.
    let txid = broadcast(&mut c, combined.clone()).await.unwrap().txid;
    assert_eq!(txid.len(), 64);
    wait_in_mempool(&node, &txid).await;
    let err = broadcast(&mut c, combined).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("already broadcast"), "{err:?}");
    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let b = balance(&mut c, "main").await;
    assert_eq!(balance_of(&b, Pool::Transparent), (0, 0), "{b:?}");
    assert_eq!(
        balance_of(&b, Pool::Ironwood).0,
        100_000_000 - 50_000_000 - fee,
        "{b:?}"
    );

    // A ZIP 320 recipient is refused at create (single-step PCZTs only).
    let err = c
        .create_pczt(create(
            "main",
            &zcash_keys::address::Address::Tex([9; 20]).encode(&params),
            1_000,
        ))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("tx send"), "{err:?}");

    // The audit trail names the file session, the signature and the
    // broadcast.
    let events: Vec<String> = state
        .logs
        .recent(true, 1000)
        .iter()
        .filter(|e| e.fields.get("key_id").map(String::as_str) == Some("main"))
        .filter_map(|e| e.fields.get("event").cloned())
        .collect();
    assert!(events.iter().any(|e| e == "session_created"), "{events:?}");
    assert!(events.iter().any(|e| e == "sign"), "{events:?}");
    assert!(events.iter().any(|e| e == "broadcast"), "{events:?}");

    running.task.abort();
}

/// `address current/new/inspect`, `notes`, `tx list` and `tx status`
/// through the fake node: a fresh key's current address is the account's
/// default address (before the first sync too) and stays put until
/// `NewAddress` hands out another; labels and receiver sets; every address
/// kind inspected; then fund → shield → a memo'd self-send, with the notes,
/// the history pages and the node's status after each step.
#[tokio::test]
async fn addresses_notes_and_history_through_the_fake_node() {
    use gyges_proto::v1::{
        AddressKind, GetCurrentAddressRequest, GetTransactionStatusRequest, InspectAddressRequest,
        ListNotesRequest, ListTransactionsRequest, NewAddressRequest, Pool, SpentFilter,
        StatusSource, TransactionStatus,
    };
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
    let _ = test_hub();
    let node = mined_node(10).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    let state = &running.state;
    let params = Network::Regtest.consensus_params();

    let err = c
        .get_current_address(GetCurrentAddressRequest {
            key_id: "main".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::KeyNotFound);

    init_key(&mut c, "main").await;

    // Current = the account's default address (upstream exposes it with
    // every receiver when it creates the account), stable.
    let first = c
        .get_current_address(GetCurrentAddressRequest {
            key_id: "main".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let ufvk = UnifiedFullViewingKey::decode(
        &params,
        &state.registry.resolve("main").unwrap().ufvk().unwrap(),
    )
    .unwrap();
    let (expected, j) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .unwrap();
    assert_eq!(first.address, expected.encode(&params));
    assert!(first.address.starts_with("uregtest1"), "{first:?}");
    assert_eq!(
        first.diversifier_index,
        gyges_core::addresses::diversifier_decimal(j)
    );
    let pools: Vec<Pool> = first.receivers.iter().map(|r| r.pool()).collect();
    assert_eq!(
        pools,
        [Pool::Orchard, Pool::Sapling, Pool::Transparent],
        "{first:?}"
    );
    assert!(first.receivers[0].encoded.is_empty());
    assert!(first.receivers[1].encoded.starts_with("zregtestsapling1"));
    assert!(first.receivers[2].encoded.starts_with("tm"));
    assert!(first.label.is_empty());
    assert_eq!(current_address(&mut c, "main").await, first.address);

    // NewAddress needs the chain tip, which the first scan records.
    wait_spendable(&mut c, "main").await;
    let labelled = c
        .new_address(NewAddressRequest {
            key_id: "main".into(),
            receivers: vec![],
            label: "shop".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_ne!(labelled.address, first.address);
    assert_eq!(labelled.label, "shop");
    let pools: Vec<Pool> = labelled.receivers.iter().map(|r| r.pool()).collect();
    assert_eq!(pools, [Pool::Orchard, Pool::Sapling]);
    let now = c
        .get_current_address(GetCurrentAddressRequest {
            key_id: "main".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        now, labelled,
        "the newest address is current, label included"
    );

    let with_t = c
        .new_address(NewAddressRequest {
            key_id: "main".into(),
            receivers: vec![Pool::Ironwood as i32, Pool::Transparent as i32],
            label: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let pools: Vec<Pool> = with_t.receivers.iter().map(|r| r.pool()).collect();
    assert_eq!(pools, [Pool::Orchard, Pool::Transparent], "{with_t:?}");
    assert!(with_t.receivers[1].encoded.starts_with("tm"), "{with_t:?}");
    for (receivers, label, want) in [
        (
            vec![Pool::Transparent as i32],
            "",
            ErrorReason::InvalidArgument,
        ),
        (
            vec![Pool::Unspecified as i32],
            "",
            ErrorReason::InvalidArgument,
        ),
        (vec![], "two\nlines", ErrorReason::InvalidArgument),
    ] {
        let err = c
            .new_address(NewAddressRequest {
                key_id: "main".into(),
                receivers,
                label: label.into(),
            })
            .await
            .unwrap_err();
        assert_eq!(reason(&err), want, "{err:?}");
    }

    // Inspect: the same receivers as AddressInfo; other kinds; refusals.
    let i = c
        .inspect_address(InspectAddressRequest {
            address: with_t.address.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(i.valid, "{i:?}");
    assert_eq!(i.network(), gyges_proto::v1::Network::Regtest);
    assert_eq!(i.kind(), AddressKind::Unified);
    assert_eq!(i.receivers, with_t.receivers);
    assert!(!i.transparent_source_only);
    let tex = zcash_keys::address::Address::Tex([9; 20]).encode(&params);
    let i = c
        .inspect_address(InspectAddressRequest { address: tex })
        .await
        .unwrap()
        .into_inner();
    assert!(i.valid && i.transparent_source_only, "{i:?}");
    assert_eq!(i.kind(), AddressKind::Tex);
    assert_eq!(i.receivers[0].pool(), Pool::Transparent);
    let t = with_t.receivers[1].encoded.clone();
    let i = c
        .inspect_address(InspectAddressRequest { address: t })
        .await
        .unwrap()
        .into_inner();
    assert!(i.valid, "{i:?}");
    assert_eq!(i.network(), gyges_proto::v1::Network::Regtest, "{i:?}");
    assert_eq!(i.kind(), AddressKind::TransparentP2pkh);
    let mainnet = zcash_keys::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([7; 20]),
    )
    .encode(&Network::Mainnet.consensus_params());
    let i = c
        .inspect_address(InspectAddressRequest { address: mainnet })
        .await
        .unwrap()
        .into_inner();
    assert!(!i.valid, "{i:?}");
    assert_eq!(i.network(), gyges_proto::v1::Network::Mainnet);
    assert!(i.error.contains("mainnet"), "{i:?}");
    let i = c
        .inspect_address(InspectAddressRequest {
            address: "nonsense".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!i.valid && !i.error.is_empty(), "{i:?}");
    assert_eq!(i.kind(), AddressKind::Unspecified);

    // Nothing received yet.
    let notes = |spent: SpentFilter, pool: Pool| ListNotesRequest {
        key_id: "main".into(),
        pool: pool as i32,
        spent: spent as i32,
    };
    let list = |limit: u32, before: &str| ListTransactionsRequest {
        key_id: "main".into(),
        limit,
        before_txid: before.into(),
    };
    let n = c
        .list_notes(notes(SpentFilter::All, Pool::Unspecified))
        .await
        .unwrap()
        .into_inner();
    assert!(n.notes.is_empty(), "{n:?}");
    let h = c.list_transactions(list(0, "")).await.unwrap().into_inner();
    assert!(h.transactions.is_empty(), "{h:?}");

    // 1 ZEC to a transparent receiver: one UTXO.
    let fund_height = fund(&node, state, &mut c, "main", 100_000_000).await;
    let n = c
        .list_notes(notes(SpentFilter::Unspecified, Pool::Unspecified))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(n.notes.len(), 1, "{n:?}");
    let utxo = n.notes[0].clone();
    assert_eq!(utxo.pool(), Pool::Transparent);
    assert_eq!(utxo.value, 100_000_000);
    assert_eq!(utxo.height, fund_height.height);
    assert!(
        utxo.witness_ready && !utxo.spent && !utxo.ephemeral,
        "{utxo:?}"
    );

    // Shield it (daemon-scoped unlock: no session round trip).
    unlock_daemon(&mut c, "main").await;
    let events = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "main".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let shield_txid = broadcast_txid(&events);
    let shield_fee = proposal_of(&events).total_fee;

    // Unmined: the node has it in its mempool; the UTXO counts as spent.
    let st = c
        .get_transaction_status(GetTransactionStatusRequest {
            key_id: "main".into(),
            txid: shield_txid.clone(),
            via_pir: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.status(), TransactionStatus::Pending, "{st:?}");
    assert_eq!((st.height, st.confirmations), (0, 0));
    assert_eq!(st.source(), StatusSource::Node);
    let h = c.list_transactions(list(0, "")).await.unwrap().into_inner();
    assert_eq!(h.transactions[0].txid, shield_txid, "{h:?}");
    assert_eq!(h.transactions[0].status(), TransactionStatus::Pending);
    assert_eq!(h.transactions[0].height, 0);

    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let shield_height = node.tip().0 - 1;
    let n = c
        .list_notes(notes(SpentFilter::Spent, Pool::Unspecified))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(n.notes.len(), 1, "{n:?}");
    assert_eq!(n.notes[0].txid, utxo.txid);
    assert!(n.notes[0].spent);
    assert_eq!(n.notes[0].spent_txid, shield_txid);
    let n = c
        .list_notes(notes(SpentFilter::Unspent, Pool::Ironwood))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(n.notes.len(), 1, "{n:?}");
    assert_eq!(n.notes[0].value, 100_000_000 - shield_fee);
    assert_eq!(n.notes[0].txid, shield_txid);
    assert_eq!(n.notes[0].height, shield_height);
    assert!(n.notes[0].witness_ready, "{n:?}");
    let n = c
        .list_notes(notes(SpentFilter::All, Pool::Transparent))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(n.notes.len(), 1, "{n:?}");
    let st = c
        .get_transaction_status(GetTransactionStatusRequest {
            key_id: "main".into(),
            txid: shield_txid.clone(),
            via_pir: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.status(), TransactionStatus::Mined, "{st:?}");
    assert_eq!(st.height, shield_height);
    assert_eq!(st.confirmations, 2);
    assert_eq!(st.source(), StatusSource::Node);

    // A memo'd payment to the labelled address of our own.
    let events = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: labelled.address.clone(),
            amount: zats(30_000_000),
            memo: b"hello".to_vec(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let send_txid = broadcast_txid(&events);
    let send_fee = proposal_of(&events).total_fee;
    node.mine(1);
    wait_spendable(&mut c, "main").await;

    let h = c.list_transactions(list(0, "")).await.unwrap().into_inner();
    let txids: Vec<&str> = h.transactions.iter().map(|t| t.txid.as_str()).collect();
    assert_eq!(
        txids,
        [send_txid.as_str(), shield_txid.as_str(), utxo.txid.as_str()]
    );
    let send = &h.transactions[0];
    assert_eq!(send.status(), TransactionStatus::Mined, "{send:?}");
    assert_eq!(send.height, node.tip().0);
    assert_eq!(send.fee, send_fee);
    assert_eq!(send.net_value, -send_fee, "a self-send costs the fee");
    assert!(send.timestamp > 0, "{send:?}");
    assert!(send.tex.is_none());
    let paid = send
        .outputs
        .iter()
        .find(|o| o.address == labelled.address)
        .unwrap_or_else(|| panic!("an output to the labelled address: {send:?}"));
    assert_eq!(paid.value, 30_000_000);
    assert_eq!(paid.memo, b"hello");
    assert!(send.outputs.iter().any(|o| o.is_change), "{send:?}");
    let fund = &h.transactions[2];
    assert_eq!(fund.net_value, 100_000_000, "{fund:?}");
    assert_eq!(fund.height, fund_height.height);

    // Paging.
    let page = c.list_transactions(list(1, "")).await.unwrap().into_inner();
    assert_eq!(page.transactions.len(), 1);
    assert_eq!(page.transactions[0].txid, send_txid);
    let page = c
        .list_transactions(list(1, &send_txid))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.transactions[0].txid, shield_txid);
    let err = c
        .list_transactions(list(1, &"00".repeat(32)))
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument);
    let err = c.list_transactions(list(1, "xyz")).await.unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument);

    // The received note carries the memo preview.
    let n = c
        .list_notes(notes(SpentFilter::Unspent, Pool::Unspecified))
        .await
        .unwrap()
        .into_inner();
    assert!(
        n.notes
            .iter()
            .any(|x| x.value == 30_000_000 && x.memo_preview == "hello" && x.txid == send_txid),
        "{n:?}"
    );

    // tx status refusals.
    for (txid, via_pir) in [
        ("00".repeat(32), false),
        ("nothex".to_string(), false),
        (send_txid.clone(), true),
    ] {
        let err = c
            .get_transaction_status(GetTransactionStatusRequest {
                key_id: "main".into(),
                txid,
                via_pir,
            })
            .await
            .unwrap_err();
        assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    }

    running.task.abort();
}

// ---------------------------------------------------------------------------
// Case B: backfill below the node's window and the handoff (ROADMAP.md M2,
// second and third items; SYNC.md §4.2, §5)
// ---------------------------------------------------------------------------

/// Poll `GetSyncStatus` until `done` holds for the key's row.
async fn wait_status(
    c: &mut GygesClient<Channel>,
    key_id: &str,
    what: &str,
    done: impl Fn(&gyges_proto::v1::KeySyncStatus) -> bool,
) -> gyges_proto::v1::KeySyncStatus {
    let every = Duration::from_millis(50);
    poll_until(what, Duration::from_secs(60), every, async || {
        let req = GetSyncStatusRequest {
            key_id: key_id.into(),
        };
        let k = c.get_sync_status(req).await.unwrap().into_inner().keys[0].clone();
        if done(&k) { Ok(k) } else { Err(k) }
    })
    .await
}

/// Mine a chain with one shielding transaction in it (so that the backfill
/// carries real Ironwood commitments): a key born at the tip is funded on a
/// transparent receiver, shields, and the shield is mined. Returns the
/// key's mnemonic, its Ironwood balance and the shield's height.
async fn chain_with_a_shielded_note(node: &FakeNode) -> (String, i64, u32) {
    use gyges_proto::v1::Pool;
    node.mine(5);
    let (running, mut c) = start_on(node, ONE_CONF_CONFIG).await;
    let resp = init_key(&mut c, "orig").await;
    wait_spendable(&mut c, "orig").await;
    fund_and_shield(node, &running.state, &mut c, "orig", 100_000_000).await;
    node.mine(1);
    let shield_height = node.tip().0;
    wait_spendable(&mut c, "orig").await;
    let b = balance(&mut c, "orig").await;
    let (ironwood, pending) = balance_of(&b, Pool::Ironwood);
    assert!(ironwood > 0 && pending == 0, "{b:?}");
    running.task.abort();
    (resp.mnemonic, ironwood, shield_height)
}

/// Item 3 for a restore: a birthday below the node's window is accepted
/// once a fallback endpoint is configured; the scheduler backfills from it
/// (blocks tagged with its source), validates at `retained_from + k` and
/// hands back to the node, and the note below the window is found. Then
/// item 2's tree check: an endpoint serving the same chain with one
/// commitment changed (same hashes, same sizes) is refused at the handoff,
/// marked untrusted and the key stalls.
#[tokio::test]
async fn restore_below_the_window_backfills_from_the_fallback_and_a_wrong_root_is_refused() {
    use gyges_proto::v1::{FallbackTrust, Pool};
    let node = FakeNode::start(regtest_params()).await;
    let (mnemonic, ironwood, shield_height) = chain_with_a_shielded_note(&node).await;
    node.mine(40);
    let tip = node.tip().0;
    node.set_prune_height(Some(30));
    let lwd = FakeLightwalletd::from_node(&node).await;

    let (running, mut c) = start_with_fallback(&node, &lwd, TEST_CONFIG).await;
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Untested);
    assert_eq!(
        info.tor.unwrap().state(),
        gyges_proto::v1::TorState::Disabled
    );

    // Consent first, then the restore is accepted with the block count.
    let req = RestoreKeyRequest {
        mnemonic: mnemonic.clone(),
        ..restore_req("copy", 4)
    };
    let err = c.restore_key(req.clone()).await.unwrap_err();
    let typed = GygesError::from_status(&err).unwrap();
    assert_eq!(typed.reason(), ErrorReason::ConfirmationRequired);
    assert!(typed.detail.contains("(directly)"), "{}", typed.detail);
    let resp = c
        .restore_key(RestoreKeyRequest {
            allow_backfill: true,
            ..req
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.birthday_height, 4);
    // Up to the handoff at 30 + 10.
    assert_eq!(resp.backfill_blocks, 40 + 1 - 4);

    let status = wait_spendable(&mut c, "copy").await;
    assert_eq!(status.scanned_tip, tip, "{status:?}");
    assert_eq!(
        status.backend(),
        gyges_proto::v1::SyncBackend::ZakuraRpc,
        "back on the node after the handoff"
    );
    let b = balance(&mut c, "copy").await;
    assert_eq!(
        balance_of(&b, Pool::Ironwood),
        (ironwood, 0),
        "the note at {shield_height}, below the window, was found in the backfill: {b:?}"
    );
    let calls = lwd.calls();
    assert!(calls.iter().any(|m| m == "GetBlockRange"), "{calls:?}");
    assert!(calls.iter().any(|m| m == "GetTreeState"), "{calls:?}");
    assert!(calls.iter().any(|m| m == "GetSubtreeRoots"), "{calls:?}");
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Verified);
    let key = running.state.registry.resolve("copy").unwrap();
    assert!(!key.dir().join("backfill.json").exists());
    // The endpoint's blocks are dropped once scanned
    // (`cache.keep_historical = false`).
    let cache = running.state.block_cache.as_ref().unwrap();
    assert_eq!(
        cache
            .evict_source_below(gyges_chain::Source::TorLwd, BlockHeight::from_u32(u32::MAX))
            .unwrap(),
        0
    );
    running.task.abort();

    // The same chain with one Ironwood commitment changed in the shield's
    // block: hashes and tree sizes still agree with the node, the root
    // does not.
    let mut blocks = lwd.blocks();
    let block = blocks
        .iter_mut()
        .find(|b| b.height == u64::from(shield_height))
        .unwrap();
    let action = block
        .vtx
        .iter_mut()
        .flat_map(|tx| tx.ironwood_actions.iter_mut())
        .next()
        .expect("the shield has an Ironwood action");
    action.cmx = vec![0; 32];
    let liar = FakeLightwalletd::from_node(&node).await;
    liar.set_blocks(blocks);
    let (running, mut c) = start_with_fallback(&node, &liar, TEST_CONFIG).await;
    c.restore_key(RestoreKeyRequest {
        mnemonic,
        allow_backfill: true,
        ..restore_req("copy", 4)
    })
    .await
    .unwrap();
    let stalled = wait_status(&mut c, "copy", "stalled", |k| {
        k.state() == SyncState::Stalled
    })
    .await;
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::FallbackUntrusted,
        "{stalled:?}"
    );
    assert!(stalled.detail.contains("tree-roots"), "{}", stalled.detail);
    assert!(stalled.detail.contains("ironwood"), "{}", stalled.detail);
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Untrusted);
    // Nothing the endpoint served is left in the wallet.
    {
        let key = running.state.registry.resolve("copy").unwrap();
        let w = key.wallet().unwrap();
        assert!(
            w.block_max_scanned().unwrap().is_none(),
            "truncated to the birthday"
        );
    }
    let b = balance(&mut c, "copy").await;
    assert_eq!(b.total_spendable, 0, "{b:?}");
    running.task.abort();
}

/// Item 2's hash-chain check: an endpoint serving a fork from the
/// birthday up (well linked, but not the node's chain) is refused before
/// anything from it is scanned, the endpoint is marked untrusted (and
/// persisted), and further restores below the window are refused.
#[tokio::test]
async fn a_fallback_serving_a_fork_is_refused_and_marked_untrusted() {
    use gyges_proto::v1::FallbackTrust;
    let node = mined_node(40).await;
    node.set_prune_height(Some(25));
    let lwd = FakeLightwalletd::from_node(&node).await;
    lwd.fork_from(5);
    let (running, mut c) = start_with_fallback(&node, &lwd, TEST_CONFIG).await;
    c.restore_key(RestoreKeyRequest {
        allow_backfill: true,
        ..restore_req("old", 5)
    })
    .await
    .unwrap();
    let stalled = wait_status(&mut c, "old", "stalled", |k| {
        k.state() == SyncState::Stalled
    })
    .await;
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::FallbackUntrusted,
        "{stalled:?}"
    );
    assert!(stalled.detail.contains("hash-chain"), "{}", stalled.detail);
    assert!(stalled.scanned_tip < 25, "{stalled:?}");
    // WaitSync fails fast on the stalled key.
    let err = drain(
        c.wait_sync(WaitSyncRequest {
            key_id: "old".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::NotSynced);

    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Untrusted);
    assert!(
        running
            ._home
            .path()
            .join("regtest/fallback_trust.json")
            .exists()
    );
    let err = c
        .restore_key(RestoreKeyRequest {
            allow_backfill: true,
            ..restore_req("other", 6)
        })
        .await
        .unwrap_err();
    let typed = GygesError::from_status(&err).unwrap();
    assert_eq!(typed.reason(), ErrorReason::FallbackUnavailable);
    assert!(typed.detail.contains("untrusted"), "{}", typed.detail);
    running.task.abort();
}

/// ROADMAP.md M2, the ShardTree item: an endpoint serving the node's blocks
/// (every hash and tree size right) but a forged tree state at a batch
/// boundary below the window. The next batch's prior frontier then
/// disagrees with the leaves the wallet already holds, so `put_blocks`
/// refuses the insertion. That is the endpoint's data, so the key stalls
/// with `UntrustedBackfill` instead of retrying the wallet error every tick.
#[tokio::test]
async fn a_fallback_whose_tree_state_the_wallet_refuses_is_marked_untrusted() {
    use gyges_proto::v1::FallbackTrust;
    let node = FakeNode::start(regtest_params()).await;
    let (mnemonic, _, shield_height) = chain_with_a_shielded_note(&node).await;
    node.mine(40);
    let retained_from = 30;
    node.set_prune_height(Some(retained_from));
    let honest = FakeLightwalletd::from_node(&node).await;

    // Same leaf count, other leaves: zero the left and right leaves of the
    // legacy `CommitmentTree` hex (`01 <left> 01 <right> <parents>`; zero is
    // a valid Pallas element). Every height from the shield up to the window
    // lies, so whichever batch boundary falls there is served the forgery;
    // the birthday's `birthday - 1` stays honest.
    let forge = |hex: &str| {
        assert!(hex.starts_with("01"), "a non-empty Ironwood tree: {hex}");
        let mut out = format!("01{}", "0".repeat(64));
        let rest = &hex[66..];
        if let Some(parents) = rest.strip_prefix("01") {
            out.push_str(&format!("01{}{}", "0".repeat(64), &parents[64..]));
        } else {
            out.push_str(rest);
        }
        assert_ne!(out, hex);
        out
    };
    let states = (0..=node.tip().0)
        .map(|h| {
            let mut ts = node.tree_state(h);
            if (shield_height..retained_from).contains(&h) {
                ts.ironwood_tree = forge(&ts.ironwood_tree);
            }
            ts
        })
        .collect();
    let liar = FakeLightwalletd::start("test", honest.blocks(), states).await;

    // Several batches below the window, so a later one takes its prior
    // tree state from the endpoint after the shield's block is scanned.
    let config = format!("{TEST_CONFIG}[cache]\nscan_batch = 10\nfetch_batch = 10\n");
    let (running, mut c) = start_with_fallback(&node, &liar, &config).await;
    let birthday = 4;
    c.restore_key(RestoreKeyRequest {
        mnemonic,
        allow_backfill: true,
        ..restore_req("copy", birthday)
    })
    .await
    .unwrap();
    let stalled = wait_status(&mut c, "copy", "stalled", |k| {
        k.state() == SyncState::Stalled
    })
    .await;
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::FallbackUntrusted,
        "{stalled:?}"
    );
    // Refused while scanning a batch, not at the handoff's root check.
    assert!(
        stalled.detail.contains("commitment tree refused"),
        "{}",
        stalled.detail
    );
    assert!(stalled.detail.contains("ironwood"), "{}", stalled.detail);

    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Untrusted);
    assert!(
        running
            ._home
            .path()
            .join("regtest/fallback_trust.json")
            .exists()
    );
    // Truncated to the block before the backfill (`birthday - 1`): nothing
    // the endpoint served is left in the wallet, nor in the cache.
    {
        let key = running.state.registry.resolve("copy").unwrap();
        let w = key.wallet().unwrap();
        assert!(
            w.block_max_scanned().unwrap().is_none(),
            "truncated to {}",
            birthday - 1
        );
        assert!(!key.dir().join("backfill.json").exists());
    }
    let cache = running.state.block_cache.as_ref().unwrap();
    assert_eq!(
        cache
            .evict_source_below(gyges_chain::Source::TorLwd, BlockHeight::from_u32(u32::MAX))
            .unwrap(),
        0
    );
    // It stays stalled: the next ticks do not retry the endpoint.
    let block_ranges = || {
        liar.calls()
            .iter()
            .filter(|m| *m == "GetBlockRange")
            .count()
    };
    let before = block_ranges();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let k = wait_status(&mut c, "copy", "still stalled", |_| true).await;
    assert_eq!(
        k.stall_reason(),
        gyges_proto::v1::StallReason::FallbackUntrusted,
        "{k:?}"
    );
    assert_eq!(block_ranges(), before, "{:?}", liar.calls());
    running.task.abort();
}

/// Item 3, the pruning race: the node prunes past a key while it scans
/// (after the first batch); the key falls back to the endpoint, validates
/// at `retained_from + k` and finishes on the node.
#[tokio::test]
async fn node_pruning_past_the_scan_tip_mid_scan_falls_back_and_recovers() {
    use gyges_proto::v1::FallbackTrust;
    let node = mined_node(10).await;
    let lwd = FakeLightwalletd::from_node(&node).await;
    let config = format!("{TEST_CONFIG}[cache]\nscan_batch = 10\nfetch_batch = 10\n");
    let (running, mut c) = start_with_fallback(&node, &lwd, &config).await;
    init_key(&mut c, "main").await;
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 10);
    assert!(lwd.calls().is_empty(), "nothing needed the endpoint yet");

    // The node prunes below 50 once it has served one more batch of raw
    // blocks: the key is then at 20 with 50 blocks to go.
    node.prune_after_raw_blocks(10, 50);
    node.mine(60);
    lwd.resync(&node);
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 70, "{status:?}");
    assert_eq!(status.backend(), gyges_proto::v1::SyncBackend::ZakuraRpc);
    assert!(
        lwd.calls().iter().any(|m| m == "GetBlockRange"),
        "{:?}",
        lwd.calls()
    );
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.node.unwrap().retained_from, 50);
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Verified);
    running.task.abort();
}

/// `--via-tor` (ROADMAP.md M2): without a Tor endpoint the send is refused
/// before anything is proposed, and with one the transaction goes to the
/// endpoint's `SendTransaction`, never to the node. The endpoint is reached
/// directly here (`use_tor = false`, accepted on regtest only); the Tor
/// transport itself is the nightly tier.
#[tokio::test(flavor = "multi_thread")]
async fn via_tor_broadcasts_through_the_fallback_endpoint_and_never_falls_back_to_the_node() {
    let node = mined_node(10).await;
    let params = Network::Regtest.consensus_params();
    let t_recipient = t_recipient();

    // No endpoint configured: FALLBACK_UNAVAILABLE before the stream.
    let (plain, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    init_key(&mut c, "main").await;
    wait_spendable(&mut c, "main").await;
    let Err(err) = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: zats(1_000),
            via_tor: true,
            ..Default::default()
        })
        .await
    else {
        panic!("--via-tor without an endpoint must be refused before streaming");
    };
    assert_eq!(reason(&err), ErrorReason::FallbackUnavailable, "{err:?}");
    plain.task.abort();

    // With an endpoint: fund, then send with --via-tor.
    let lwd = FakeLightwalletd::from_node(&node).await;
    let (running, mut c) = start_with_fallback(&node, &lwd, ONE_CONF_CONFIG).await;
    init_key(&mut c, "main").await;
    wait_spendable(&mut c, "main").await;
    let receiver = transparent_receiver(&running.state, "main");
    // Two coins, so the second send has one the first left unspent.
    node.mine_with_payments(&[(receiver, 100_000_000)]);
    node.mine_with_payments(&[(receiver, 100_000_000)]);
    node.mine(1);
    wait_spendable(&mut c, "main").await;
    unlock_daemon(&mut c, "main").await;

    // A tex1 recipient is refused: the ZIP 320 queue broadcasts through the
    // node.
    let Err(err) = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: zcash_keys::address::Address::Tex([9; 20]).encode(&params),
            amount: zats(1_000),
            via_tor: true,
            ..Default::default()
        })
        .await
    else {
        panic!("--via-tor to tex1 must be refused before streaming");
    };
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("tex1"), "{err:?}");

    let events = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient,
            amount: zats(10_000_000),
            via_tor: true,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        event_names(&events).last(),
        Some(&"broadcast"),
        "{events:?}"
    );
    assert_eq!(
        lwd.broadcasts().len(),
        1,
        "the endpoint got the transaction"
    );
    assert!(node.mempool().is_empty(), "the node did not");

    // A refusal by the endpoint is the node's rejection passed through.
    lwd.set_reject_broadcasts(Some("bad-txns-inputs-spent".into()));
    let err = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: zcash_keys::address::Address::Transparent(
                transparent::address::TransparentAddress::PublicKeyHash([0x43; 20]),
            )
            .encode(&params),
            amount: zats(1_000_000),
            via_tor: true,
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::NodeRejected, "{err:?}");
    assert_eq!(lwd.broadcasts().len(), 1);
    assert!(node.mempool().is_empty());
    running.task.abort();
}

/// TESTING.md §3 row 13, air-gapped half (ROADMAP.md M4): the online daemon
/// creates and proves a transparent-funded PCZT, an `--airgapped` daemon
/// holding the same seed as a `signer-only` profile (no `wallet.sqlite`)
/// signs it from the inputs' BIP 44 derivations, and the online daemon
/// verifies and broadcasts it. A PCZT whose inputs name another seed is
/// refused by the offline signer.
#[tokio::test(flavor = "multi_thread")]
async fn an_airgapped_signer_only_daemon_signs_transparent_inputs() {
    use gyges_proto::v1::{BroadcastPcztRequest, CreatePcztRequest, Pool, ProvePcztRequest};
    let node = mined_node(10).await;
    let t_recipient = t_recipient();

    // The offline box makes the seed; the online daemon restores it.
    let offline = start(|o| o.airgapped = true).await;
    let mut off = client(&offline.socket).await;
    let mnemonic = off
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "offline-pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .mnemonic;
    assert!(
        !offline
            ._home
            .path()
            .join("regtest/keys/main/wallet.sqlite")
            .exists()
    );

    let (online, mut on) = start_on(&node, ONE_CONF_CONFIG).await;
    on.restore_key(RestoreKeyRequest {
        key_id: "main".into(),
        mnemonic,
        passphrase: "online-pw".into(),
        birthday_height: 5,
        ..Default::default()
    })
    .await
    .unwrap();
    // A second online key whose seed the offline box does not hold.
    init_key(&mut on, "other").await;
    for id in ["main", "other"] {
        wait_spendable(&mut on, id).await;
        let receiver = transparent_receiver(&online.state, id);
        node.mine_with_payments(&[(receiver, 100_000_000)]);
    }
    node.mine(1);
    wait_spendable(&mut on, "main").await;
    wait_spendable(&mut on, "other").await;

    let creator = on.clone();
    let create_and_prove = |key_id: &'static str| {
        let mut on = creator.clone();
        let to = t_recipient.clone();
        async move {
            let created = on
                .create_pczt(CreatePcztRequest {
                    key_id: key_id.into(),
                    to,
                    amount: zats(50_000_000),
                    memo: Vec::new(),
                    min_confirmations: 0,
                })
                .await
                .unwrap()
                .into_inner();
            let p = created.proposal.unwrap();
            assert_eq!(p.steps[0].inputs[0].pool(), Pool::Transparent, "{p:?}");
            on.prove_pczt(ProvePcztRequest {
                pczt: created.pczts[0].clone(),
                session_token: Vec::new(),
                key_id: String::new(),
            })
            .await
            .unwrap()
            .into_inner()
            .pczt
        }
    };

    // Signed offline through the passphrase session, broadcast online.
    let proven = create_and_prove("main").await;
    let (signed, prompts) = sign_pczt_with_session(&mut off, proven, "offline-pw")
        .await
        .unwrap();
    assert_eq!(prompts, 1);
    let txid = on
        .broadcast_pczt(BroadcastPcztRequest {
            pczt: signed,
            via_tor: false,
            key_id: "main".into(),
        })
        .await
        .unwrap()
        .into_inner()
        .txid;
    wait_in_mempool(&node, &txid).await;
    node.mine(1);
    wait_spendable(&mut on, "main").await;
    let b = balance(&mut on, "main").await;
    assert_eq!(balance_of(&b, Pool::Transparent), (0, 0), "{b:?}");
    assert!(
        b.total_spendable > 0 && b.total_spendable < 50_000_000,
        "{b:?}"
    );

    // A signer-only key under the same name but another seed: the inputs'
    // derivations name a seed it does not hold.
    init_key(&mut off, "other").await;
    let proven = create_and_prove("other").await;
    let err = sign_pczt_with_session(&mut off, proven, "pw")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("BIP 44 derivation"), "{err:?}");
    offline.task.abort();
    online.task.abort();
}

/// The output checks of `gyges_core::tx::check_change` (note and value
/// commitments, labels, change ownership) on a Sapling payment: `tx send`
/// and the PCZT pipeline to a `zs` address both go through, and the
/// recipient's Sapling balance moves.
#[tokio::test(flavor = "multi_thread")]
async fn sapling_payments_pass_the_output_checks() {
    use gyges_proto::v1::{
        BroadcastPcztRequest, CreatePcztRequest, NewAddressRequest, Pool, ProvePcztRequest,
    };
    // Sapling outputs need ZIP 212 enforced for a PCZT, which starts
    // `ZIP212_GRACE_PERIOD` (32,256) blocks after Canopy; every upgrade is
    // at height 1 on regtest.
    let node = mined_node(32_300).await;
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    for id in ["main", "bob"] {
        init_key(&mut c, id).await;
        wait_spendable(&mut c, id).await;
    }
    fund_and_shield(&node, &running.state, &mut c, "main", 100_000_000).await;
    node.mine(2);
    wait_spendable(&mut c, "main").await;

    let bob = c
        .new_address(NewAddressRequest {
            key_id: "bob".into(),
            receivers: vec![],
            label: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let zs = bob
        .receivers
        .iter()
        .find(|r| r.pool() == Pool::Sapling)
        .expect("a Sapling receiver")
        .encoded
        .clone();

    // tx send: proven, signed (check_change), verified, broadcast.
    let events = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: zs.clone(),
            amount: zats(20_000_000),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        event_names(&events).last(),
        Some(&"broadcast"),
        "{events:?}"
    );
    node.mine(2);
    wait_spendable(&mut c, "main").await;

    // The PCZT pipeline to the same address.
    let created = c
        .create_pczt(CreatePcztRequest {
            key_id: "main".into(),
            to: zs,
            amount: zats(10_000_000),
            memo: Vec::new(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let proven = c
        .prove_pczt(ProvePcztRequest {
            pczt: created.pczts[0].clone(),
            session_token: Vec::new(),
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pczt;
    let (signed, _) = sign_pczt_with_session(&mut c, proven, "pw").await.unwrap();
    let txid = c
        .broadcast_pczt(BroadcastPcztRequest {
            pczt: signed,
            via_tor: false,
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .txid;
    wait_in_mempool(&node, &txid).await;
    node.mine(2);
    wait_spendable(&mut c, "bob").await;
    let b = balance(&mut c, "bob").await;
    assert_eq!(balance_of(&b, Pool::Sapling), (30_000_000, 0), "{b:?}");
    running.task.abort();
}

/// Replace every occurrence of `old` in `bytes` with `new` (equal lengths):
/// a value or address an attacker changes everywhere the file carries it.
fn replace_all(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    assert_eq!(old.len(), new.len());
    let mut out = bytes.to_vec();
    let mut hits = 0;
    let mut i = 0;
    while i + old.len() <= out.len() {
        if out[i..i + old.len()] == *old {
            out[i..i + old.len()].copy_from_slice(new);
            hits += 1;
            i += old.len();
        } else {
            i += 1;
        }
    }
    assert!(hits > 0, "the bytes do not occur");
    out
}

/// Replace the one occurrence of `old` in `bytes` with `new`.
fn replace_once(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let hits: Vec<usize> = bytes
        .windows(old.len())
        .enumerate()
        .filter(|(_, w)| *w == old)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "expected the bytes exactly once");
    let mut out = bytes.to_vec();
    out[hits[0]..hits[0] + old.len()].copy_from_slice(new);
    out
}

/// THREAT_MODEL.md §6 item 8 (ROADMAP.md M4, third item): a PCZT whose
/// change output is redirected to another key's address is refused by
/// `pczt sign` before anything is signed, and a signed file with its change
/// redirected afterwards is refused by the Verifier at `pczt broadcast`,
/// although the value, the fee and every payment are unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn redirected_change_is_refused_at_sign_and_at_broadcast() {
    use gyges_proto::v1::{BroadcastPcztRequest, CreatePcztRequest, ProvePcztRequest};
    let node = mined_node(10).await;
    let params = Network::Regtest.consensus_params();
    let (running, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    for id in ["main", "thief"] {
        init_key(&mut c, id).await;
        wait_spendable(&mut c, id).await;
    }
    let internal = |id: &str| {
        let encoded = running.state.registry.resolve(id).unwrap().ufvk().unwrap();
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&params, &encoded).unwrap();
        ufvk.orchard()
            .unwrap()
            .address_at(0u32, orchard::keys::Scope::Internal)
            .to_raw_address_bytes()
    };
    let (ours, theirs) = (internal("main"), internal("thief"));
    fund(&node, &running.state, &mut c, "main", 100_000_000).await;

    let t_recipient = t_recipient();
    let created = c
        .create_pczt(CreatePcztRequest {
            key_id: "main".into(),
            to: t_recipient,
            amount: zats(10_000_000),
            memo: Vec::new(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let prove = |pczt: Vec<u8>| {
        let mut c = c.clone();
        async move {
            c.prove_pczt(ProvePcztRequest {
                pczt,
                session_token: Vec::new(),
                key_id: String::new(),
            })
            .await
            .unwrap()
            .into_inner()
            .pczt
        }
    };
    let proven = prove(created.pczts[0].clone()).await;

    // The recipient field alone rewritten to another key's address: it no
    // longer matches the note commitment, so the signer refuses the file.
    // (This moves no funds by itself; the commitment and the proof still
    // pay us. It is the consistency check.)
    let redirected = replace_once(&proven, &ours, &theirs);
    let err = sign_pczt_with_session(&mut c, redirected, "pw")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("note commitment"), "{err:?}");

    // The case that moves funds: the change output still names our
    // internal address, but its note commitment (what the transaction
    // pays) is another note's. A check that reads only the recipient field
    // signs this; the note commitment check refuses it.
    let parsed = pczt::Pczt::parse(&proven).unwrap();
    let actions = parsed.ironwood().actions();
    let change = actions
        .iter()
        .position(|a| *a.output().recipient() == Some(ours))
        .expect("the change action names our internal address");
    let other = (0..actions.len()).find(|&i| i != change).unwrap();
    let change_cmx = actions[change]
        .output()
        .cmx()
        .expect("the file carries cmx");
    let other_cmx = actions[other].output().cmx().expect("the file carries cmx");
    let recommitted = replace_once(&proven, &change_cmx, &other_cmx);
    let err = sign_pczt_with_session(&mut c, recommitted, "pw")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("note commitment"), "{err:?}");

    // A payment whose script is changed under its address label: the label
    // the user is shown no longer names what the output pays.
    let relabelled = replace_once(&proven, &[0x42; 20], &[0x43; 20]);
    let err = sign_pczt_with_session(&mut c, relabelled, "pw")
        .await
        .unwrap_err();
    assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
    assert!(err.message().contains("label does not match"), "{err:?}");

    // Property, at sign time: a random rewrite of the change's recipient or
    // value, or of the payment's script under its label, is refused before
    // anything is signed. A daemon-scoped unlock spares each case a
    // session.
    {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, TestRunner};
        let fee = u64::try_from(created.proposal.as_ref().unwrap().total_fee).unwrap();
        let change_value = 100_000_000 - 10_000_000 - fee;
        let thief = {
            let encoded = running
                .state
                .registry
                .resolve("thief")
                .unwrap()
                .ufvk()
                .unwrap();
            zcash_keys::keys::UnifiedFullViewingKey::decode(&params, &encoded).unwrap()
        };
        unlock_daemon(&mut c, "main").await;
        let strategy = prop_oneof![
            (0u32..1_000, any::<bool>()).prop_map(|(j, ext)| (0u8, j, ext, [0u8; 20], 0u64)),
            ((1u64 << 21)..(1u64 << 28)).prop_map(|v| (1u8, 0, false, [0u8; 20], v)),
            any::<[u8; 20]>().prop_map(|h| (2u8, 0, false, h, 0)),
        ];
        let mut runner = TestRunner::new(Config {
            cases: 24,
            failure_persistence: None,
            ..Config::default()
        });
        let handle = tokio::runtime::Handle::current();
        let tried = std::sync::atomic::AtomicUsize::new(0);
        runner
            .run(&strategy, |(kind, j, external, h, v)| {
                let (bytes, want) = match kind {
                    0 => {
                        let scope = if external {
                            orchard::keys::Scope::External
                        } else {
                            orchard::keys::Scope::Internal
                        };
                        let to = thief
                            .orchard()
                            .unwrap()
                            .address_at(j, scope)
                            .to_raw_address_bytes();
                        (replace_all(&proven, &ours, &to), "note commitment")
                    }
                    1 if v != change_value => (
                        replace_all(&proven, &varint(change_value), &varint(v)),
                        "commitment",
                    ),
                    2 if h != [0x42; 20] => (
                        replace_all(&proven, &[0x42; 20], &h),
                        "label does not match",
                    ),
                    _ => return Ok(()),
                };
                tried.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut c = c.clone();
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(sign_pczt_with_session(&mut c, bytes, "pw"))
                });
                let err = match result {
                    Ok(_) => return Err(TestCaseError::fail("a rewritten file was signed")),
                    Err(e) => e,
                };
                prop_assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{:?}", err);
                prop_assert!(err.message().contains(want), "{:?}", err);
                Ok(())
            })
            .unwrap();
        assert!(
            tried.into_inner() >= 20,
            "the mutations were mostly skipped"
        );
        c.lock_key(LockKeyRequest {
            key_id: "main".into(),
            all: false,
        })
        .await
        .unwrap();
    }

    // Signed as created, then rewritten: the Verifier refuses each at
    // broadcast, and the node sees nothing.
    let (signed, _) = sign_pczt_with_session(&mut c, proven.clone(), "pw")
        .await
        .unwrap();
    for (bytes, want) in [
        (replace_once(&signed, &ours, &theirs), "note commitment"),
        (
            replace_once(&signed, &change_cmx, &other_cmx),
            "note commitment",
        ),
        (
            replace_once(&signed, &[0x42; 20], &[0x43; 20]),
            "label does not match",
        ),
    ] {
        let err = c
            .broadcast_pczt(BroadcastPcztRequest {
                pczt: bytes,
                via_tor: false,
                key_id: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{err:?}");
        assert!(err.message().contains(want), "{err:?}");
    }
    assert!(node.mempool().is_empty());

    // Property: any one change to an output's value or recipient, or to the
    // input's value, in the signed file is refused at broadcast, and the
    // node sees nothing. Each case is one BroadcastPczt; a refusal leaves
    // the session signed, so the cases are independent.
    {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, TestRunner};
        #[derive(Debug, Clone)]
        enum Mutation {
            /// Output or input value `values[.0]` becomes `.1`.
            Value(usize, u64),
            /// The change goes to the thief's address at this index and scope.
            Change(u32, bool),
            /// The payment goes to another pubkey hash.
            Payment([u8; 20]),
        }
        let fee = u64::try_from(created.proposal.as_ref().unwrap().total_fee).unwrap();
        let values = [10_000_000u64, 100_000_000 - 10_000_000 - fee, 100_000_000];
        let thief = {
            let encoded = running
                .state
                .registry
                .resolve("thief")
                .unwrap()
                .ufvk()
                .unwrap();
            zcash_keys::keys::UnifiedFullViewingKey::decode(&params, &encoded).unwrap()
        };
        let strategy = prop_oneof![
            (0usize..3, (1u64 << 21)..(1u64 << 28)).prop_map(|(t, v)| Mutation::Value(t, v)),
            (0u32..1_000, any::<bool>()).prop_map(|(j, ext)| Mutation::Change(j, ext)),
            any::<[u8; 20]>().prop_map(Mutation::Payment),
        ];
        let mut runner = TestRunner::new(Config {
            cases: 48,
            failure_persistence: None,
            ..Config::default()
        });
        let handle = tokio::runtime::Handle::current();
        let signed = signed.clone();
        let tried = std::sync::atomic::AtomicUsize::new(0);
        runner
            .run(&strategy, |m| {
                let bytes = match m {
                    Mutation::Value(t, v) if v != values[t] => {
                        replace_all(&signed, &varint(values[t]), &varint(v))
                    }
                    Mutation::Change(j, external) => {
                        let scope = if external {
                            orchard::keys::Scope::External
                        } else {
                            orchard::keys::Scope::Internal
                        };
                        let to = thief
                            .orchard()
                            .unwrap()
                            .address_at(j, scope)
                            .to_raw_address_bytes();
                        replace_all(&signed, &ours, &to)
                    }
                    Mutation::Payment(h) if h != [0x42; 20] => {
                        replace_all(&signed, &[0x42; 20], &h)
                    }
                    _ => return Ok(()),
                };
                tried.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut c = c.clone();
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(c.broadcast_pczt(BroadcastPcztRequest {
                        pczt: bytes,
                        via_tor: false,
                        key_id: String::new(),
                    }))
                });
                let err = match result {
                    Ok(r) => {
                        return Err(TestCaseError::fail(format!(
                            "broadcast {:?}",
                            r.into_inner().txid
                        )));
                    }
                    Err(e) => e,
                };
                prop_assert_eq!(reason(&err), ErrorReason::InvalidArgument, "{:?}", err);
                prop_assert!(node.mempool().is_empty());
                Ok(())
            })
            .unwrap();
        assert!(
            tried.into_inner() >= 40,
            "the mutations were mostly skipped"
        );
    }

    // The genuine file still goes through.
    let txid = c
        .broadcast_pczt(BroadcastPcztRequest {
            pczt: signed,
            via_tor: false,
            key_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .txid;
    wait_in_mempool(&node, &txid).await;
    running.task.abort();
}

/// SYNC.md §5.3 (ROADMAP.md M2, fourth item): a restore below the node's
/// window recovers the key's transparent outputs from the endpoint's
/// `GetAddressUtxos`, one below `retained_from` (placed through the
/// endpoint's block, whose hash is the node's) and one between
/// `retained_from` and the handoff (checked in the node's own block; the
/// backfilled blocks there carry no transparent outputs, so nothing else
/// finds it). Two fabricated outputs are discarded: one whose transaction
/// the endpoint does not have, one claiming an output index its transaction
/// lacks. The endpoint answers errors as zaino does, so the missing
/// transaction comes back as `Internal` with the node's -5 rather than
/// NOT_FOUND, and is still discarded rather than retried (OVERVIEW.md §4.5,
/// deviation 1). The restore warns that transparent history below the
/// window is best-effort, and `GetInfo` repeats it for the key.
#[tokio::test(flavor = "multi_thread")]
async fn restore_below_the_window_recovers_transparent_outputs_and_discards_fabricated_ones() {
    use gyges_chain::testing::FakeUtxo;
    use gyges_proto::v1::Pool;
    let node = mined_node(5).await;

    // A first daemon only to learn the seed and two of its receivers.
    let (first, mut c) = start_on(&node, ONE_CONF_CONFIG).await;
    let mnemonic = init_key(&mut c, "orig").await.mnemonic;
    let (r0, r1) = {
        let mut rs = transparent_receivers(&first.state, "orig");
        rs.sort_by_key(|a| format!("{a:?}"));
        assert!(rs.len() >= 2, "{rs:?}");
        (rs[0], rs[1])
    };
    first.task.abort();

    // 3 ZEC to r0 at height 6 (below the window), 2 ZEC to r1 at 35
    // (inside the window, below the handoff at 30 + 10).
    let low = node.mine_with_payments(&[(r0, 300_000_000)]);
    node.mine(34 - low.height);
    let mid = node.mine_with_payments(&[(r1, 200_000_000)]);
    assert_eq!(mid.height, 35);
    node.mine(15);
    node.set_prune_height(Some(30));
    let lwd = FakeLightwalletd::from_node(&node);
    let lwd = lwd.await;
    let enc = |a| {
        gyges_chain::compact::encode_transparent_address(
            zcash_protocol::consensus::NetworkType::Regtest,
            &a,
        )
    };
    let real = lwd
        .utxos()
        .into_iter()
        .find(|u| u.height == low.height && u.address == enc(r0))
        .expect("the endpoint reports the real output");
    // lightwalletd lists only transactions with shielded parts in compact
    // blocks; drop the transparent-only payment from its block, so the
    // output below the window cannot be placed (best-effort).
    let blocks = lwd
        .blocks()
        .into_iter()
        .map(|mut b| {
            b.vtx.retain(|tx| tx.txid[..] != real.txid[..]);
            b
        })
        .collect();
    lwd.set_blocks(blocks);
    lwd.inject_utxo(FakeUtxo {
        txid: [0x99; 32],
        height: 9,
        ..real.clone()
    });
    lwd.inject_utxo(FakeUtxo {
        index: 7,
        value_zat: 500_000_000,
        ..real.clone()
    });
    lwd.set_zaino_errors(true);

    let (running, mut c) = start_with_fallback(&node, &lwd, ONE_CONF_CONFIG).await;
    let resp = c
        .restore_key(RestoreKeyRequest {
            mnemonic,
            allow_backfill: true,
            ..restore_req("copy", 4)
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.warnings.len(), 1, "{resp:?}");
    assert!(resp.warnings[0].contains("best-effort"), "{resp:?}");
    assert!(resp.warnings[0].contains("below height 30"), "{resp:?}");

    wait_spendable(&mut c, "copy").await;
    let b = balance(&mut c, "copy").await;
    assert_eq!(
        balance_of(&b, Pool::Transparent),
        (500_000_000, 0),
        "both real outputs, neither fabricated one: {b:?}"
    );
    assert!(lwd.calls().iter().any(|m| m == "GetAddressUtxos"));

    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            running
                ._home
                .path()
                .join("regtest/keys/copy/transparent_recovery.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(report["credited"], 2, "{report}");
    assert_eq!(report["discarded"], 2, "{report}");
    assert_eq!(
        report["unplaced"], 1,
        "the transparent-only payment below the window: {report}"
    );
    assert_eq!(report["best_effort_below"], 30, "{report}");
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    let k = info.keys.iter().find(|k| k.key_id == "copy").unwrap();
    assert_eq!(k.transparent_best_effort_below, 30);
    running.task.abort();
}

/// A node that answers a ZIP 320 send's broadcasts with "already in
/// mempool" has the transactions: the send goes on as for an accepted
/// broadcast (as the queue does), and the queue later finds both steps
/// missing, offers them again and sees them mined.
#[tokio::test]
async fn zip320_send_treats_already_known_as_accepted() {
    use gyges_proto::v1::TexState;
    let _ = test_hub();
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let url = node.url().to_string();
    let running = start_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [policy]\nmin_confirmations = 1\n[tex]\nrebroadcast_interval = \"1s\"\n",
        |o| o.zakura_rpc = Some(url),
    )
    .await;
    let mut c = client(&running.socket).await;
    init_key(&mut c, "known").await;
    wait_spendable(&mut c, "known").await;
    let receiver = transparent_receiver(&running.state, "known");
    node.mine_with_payments(&[(receiver, 300_000_000)]);
    node.mine(1);
    wait_spendable(&mut c, "known").await;
    unlock_daemon(&mut c, "known").await;
    let shield = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "known".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let _ = broadcast_txid(&shield);
    node.mine(2);
    wait_spendable(&mut c, "known").await;

    let tex_addr =
        zcash_keys::address::Address::Tex([0x42; 20]).encode(&Network::Regtest.consensus_params());
    node.set_reject_broadcasts(Some("transaction already in mempool".into()));
    let events = send_with_session(
        &mut c,
        SendTransactionRequest {
            key_id: "known".into(),
            to: tex_addr,
            amount: zats(50_000_000),
            ..Default::default()
        },
        "pw",
        |_| {},
    )
    .await
    .unwrap();
    let names = event_names(&events);
    assert!(
        names.ends_with(&["broadcast", "tex_queued", "broadcast"]),
        "{names:?}"
    );
    let (s1, _) = tex_queued(&events);
    let row = wait_tex_state(&mut c, &s1, TexState::Step2Broadcast).await;
    assert!(row.last_error.is_empty(), "{row:?}");

    node.set_reject_broadcasts(None);
    wait_in_mempool(&node, &s1).await;
    node.mine(1);
    wait_tex_state(&mut c, &s1, TexState::Step2Mined).await;
    running.task.abort();
}
