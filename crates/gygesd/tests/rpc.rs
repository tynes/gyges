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
    InitKeyRequest, ListKeysRequest, ListNotesRequest, ListSigningSessionsRequest, LockKeyRequest,
    Proposal, RestoreKeyRequest, RunSyncRequest, SendEvent, SendTransactionRequest, SessionStatus,
    ShieldFundsRequest, ShutdownRequest, SignatureKind, SigningMode, StreamLogsRequest,
    SyncProgress, SyncState, SyncTarget, UnlockKeyRequest, UnlockScope, WaitSyncRequest,
    send_event,
};
use gygesd::{Daemon, DaemonState, LogHub, Options};
use tokio_stream::StreamExt as _;
use tonic::transport::Channel;
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
    let (dir, home) = fresh_home_with(config);
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
    let err = c.list_notes(ListNotesRequest::default()).await.unwrap_err();
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
            GygesError::from_status(&err).unwrap().reason(),
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
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::KeyExists
    );
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
            key_id: "bad".into(),
            mnemonic: "abandon ".repeat(23) + "zzzzq",
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    let detail = GygesError::from_status(&err).unwrap();
    assert_eq!(detail.reason(), ErrorReason::InvalidArgument);
    assert!(!detail.detail.contains("zzzzq"), "{}", detail.detail);
    // Above the tip is refused too.
    let err = c
        .restore_key(RestoreKeyRequest {
            key_id: "future".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 52,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::InvalidArgument
    );
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
    let req = RestoreKeyRequest {
        key_id: "old".into(),
        mnemonic: known_mnemonic(),
        passphrase: "pw".into(),
        birthday_height: 300,
        ..Default::default()
    };
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
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::FallbackUnavailable
    );
    assert!(!running._home.path().join("regtest/keys/old").exists());

    // The default birthday (Sapling activation = 1 on regtest) needs no
    // tree state from the node and is inside no retention window.
    let ok = c
        .restore_key(RestoreKeyRequest {
            key_id: "genesis".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.birthday_height, 1);
    // At the window's edge: prior state at 400 is served.
    let ok = c
        .restore_key(RestoreKeyRequest {
            key_id: "edge".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 401,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.birthday_height, 401);
    running.task.abort();
}

#[tokio::test]
async fn airgapped_init_key_creates_a_signer_only_profile() {
    let running = start(|o| o.airgapped = true).await;
    let mut c = client(&running.socket).await;
    let resp = c
        .init_key(InitKeyRequest {
            key_id: "box".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
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
    let err = c
        .restore_key(RestoreKeyRequest {
            key_id: "x".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::Airgapped
    );
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

fn reason(err: &tonic::Status) -> ErrorReason {
    GygesError::from_status(err).expect("typed error").reason()
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
    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();

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
    for _ in 0..200 {
        if running.state.vault.unlock_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        running.state.vault.unlock_count(),
        0,
        "unlock outlived its connection"
    );

    // A daemon unlock survives the connection but not the daemon.
    let mut c = client(&running.socket).await;
    c.unlock_key(UnlockKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    })
    .await
    .unwrap();
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
        c.init_key(InitKeyRequest {
            key_id: id.into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap();
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
    let created = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
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
    let (dir, home) = fresh_home();
    std::fs::write(
        home.config_path(Network::Regtest),
        "[vault]\nscrypt_work_factor = 10\nallow_seed_export = false\n",
    )
    .unwrap();
    let mut opts = Options::new(home, Network::Regtest);
    opts.airgapped = true;
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut c = client(&socket).await;
    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();
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
    task.abort();
    drop(dir);
}

#[tokio::test]
async fn real_backend_against_the_fake_node_reports_bounds_and_seeds_birthdays() {
    let node = FakeNode::start(regtest_params()).await;
    node.mine(42);
    let url = node.url().to_string();
    let running = start(|o| o.zakura_rpc = Some(url)).await;
    let mut c = client(&running.socket).await;

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
    let resp = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.birthday_height, 42);
    assert!(resp.ufvk.starts_with("uviewregtest"), "{}", resp.ufvk);
    let calls = node.calls();
    assert!(calls.iter().any(|m| m == "z_gettreestate"), "{calls:?}");

    // A restore below the (now) pruned window is refused with the window.
    node.set_prune_height(Some(30));
    let err = c
        .restore_key(RestoreKeyRequest {
            key_id: "old".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 20,
            allow_backfill: true,
            ..Default::default()
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
        .restore_key(RestoreKeyRequest {
            key_id: "old".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 31,
            ..Default::default()
        })
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
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let url = node.url().to_string();
    let running = start(|o| o.zakura_rpc = Some(url)).await;
    let mut c = client(&running.socket).await;

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
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::KeyNotFound
    );

    // A key born at the tip is scanned and spendable after one batch.
    let resp = c
        .init_key(InitKeyRequest {
            key_id: "main".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
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
    let (account, receiver) = {
        let w = key.wallet().unwrap();
        let account = w.get_account_ids().unwrap()[0];
        let receivers = w.get_transparent_receivers(account, false, false).unwrap();
        let addr = *receivers.keys().next().expect("a transparent receiver");
        (account, addr)
    };
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
    let late = c
        .init_key(InitKeyRequest {
            key_id: "late".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
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
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::ConfirmationRequired
    );
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let stalled = loop {
        let st = c
            .get_sync_status(GetSyncStatusRequest {
                key_id: "main".into(),
            })
            .await
            .unwrap()
            .into_inner();
        let k = st.keys[0].clone();
        if k.state() == SyncState::Stalled {
            break k;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never stalled: {k:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let st = c
            .get_sync_status(GetSyncStatusRequest {
                key_id: "main".into(),
            })
            .await
            .unwrap()
            .into_inner();
        if st.keys[0].state() != SyncState::Stalled {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "still stalled: {:?}",
            st.keys[0]
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 19, "{status:?}");

    // Signer-only profiles have nothing to sync.
    let err = c
        .get_sync_status(GetSyncStatusRequest {
            key_id: "nope".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        GygesError::from_status(&err).unwrap().reason(),
        ErrorReason::KeyNotFound
    );
    running.task.abort();
}

#[tokio::test]
async fn offline_node_keeps_keys_initializing_then_stalls_after_the_grace() {
    let url = closed_port_url();
    let (dir, home) = fresh_home_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[daemon]\noffline_grace = \"2s\"\n",
    );
    let mut opts = Options::new(home.clone(), Network::Regtest);
    opts.zakura_rpc = Some(url);
    // A wallet-bearing key without a node: restore at the default birthday.
    let daemon = Daemon::prepare(opts).unwrap();
    let socket = daemon.socket_path();
    let state = daemon.state.clone();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut c = client(&socket).await;
    c.restore_key(RestoreKeyRequest {
        key_id: "r".into(),
        mnemonic: known_mnemonic(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let stalled = loop {
        let st = c
            .get_sync_status(GetSyncStatusRequest::default())
            .await
            .unwrap()
            .into_inner();
        let k = st.keys[0].clone();
        if k.state() == SyncState::Stalled {
            break k;
        }
        assert_eq!(k.state(), SyncState::Idle, "{k:?}");
        assert!(
            tokio::time::Instant::now() < deadline,
            "never stalled: {k:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        stalled.stall_reason(),
        gyges_proto::v1::StallReason::NodeUnreachable
    );
    assert!(
        stalled.detail.contains("node unreachable"),
        "{}",
        stalled.detail
    );
    drop(state);
    task.abort();
    drop(dir);
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

/// Drive a send stream to completion, answering `SignatureRequired` with
/// `passphrase` through `UnlockKey { session_id }` on `c` (the inline
/// unlock flow of API.md §6.2). Returns every event.
async fn send_with_session(
    c: &mut GygesClient<Channel>,
    req: SendTransactionRequest,
    passphrase: &str,
) -> Result<Vec<SendEvent>, tonic::Status> {
    let mut s = c.send_transaction(req).await?.into_inner();
    let mut out = Vec::new();
    while let Some(item) = s.next().await {
        let ev = item?;
        if let Some(send_event::Event::SignatureRequired(r)) = &ev.event {
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
        }
        out.push(ev);
    }
    Ok(out)
}

fn balance_of(resp: &GetBalanceResponse, pool: gyges_proto::v1::Pool) -> (i64, i64) {
    resp.pools
        .iter()
        .find(|p| p.pool() == pool)
        .map(|p| (p.spendable, p.pending))
        .unwrap_or((0, 0))
}

/// The key's current unified address (every receiver), from its UFVK.
fn unified_address(state: &DaemonState, key_id: &str) -> String {
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
    let params = Network::Regtest.consensus_params();
    let key = state.registry.resolve(key_id).unwrap();
    let ufvk = UnifiedFullViewingKey::decode(&params, &key.ufvk().unwrap()).unwrap();
    let (ua, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .unwrap();
    ua.encode(&params)
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
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let url = node.url().to_string();
    let (dir, home) = fresh_home_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n",
    );
    let mut opts = Options::new(home.clone(), Network::Regtest);
    opts.zakura_rpc = Some(url);
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let state = daemon.state.clone();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut c = client(&socket).await;
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

    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    wait_spendable(&mut c, "main").await;

    let key = state.registry.resolve("main").unwrap();
    let (account, receiver) = {
        let w = key.wallet().unwrap();
        let account = w.get_account_ids().unwrap()[0];
        let receivers = w.get_transparent_receivers(account, false, false).unwrap();
        let addr = *receivers.keys().next().expect("a transparent receiver");
        (account, addr)
    };
    let _ = account;
    let t_recipient = zcash_keys::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]),
    )
    .encode(&params);
    let amount = |z: i64| {
        Some(gyges_proto::v1::Amount {
            value: Some(gyges_proto::v1::amount::Value::Zatoshis(z)),
        })
    };

    // Empty wallet: INSUFFICIENT_FUNDS arrives as the stream's error.
    let err = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: amount(1_000),
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
                amount: amount(1_000),
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
    node.mine_with_payments(&[(receiver, 100_000_000)]);
    node.mine(1);
    wait_spendable(&mut c, "main").await;
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "main".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(balance_of(&b, Pool::Transparent), (100_000_000, 0), "{b:?}");
    assert_eq!(b.total_spendable, 100_000_000);
    assert_eq!(b.min_confirmations, 1);

    // Shield with a daemon-scoped unlock already in place: no
    // SignatureRequired, the stream runs to Broadcast on its own.
    c.unlock_key(UnlockKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    })
    .await
    .unwrap();
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
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "main".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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
    let ua = unified_address(&state, "main");
    let mut s = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: ua.clone(),
            amount: amount(30_000_000),
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
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "main".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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
            amount: amount(1_000_000),
            ..Default::default()
        },
        "pw",
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
            amount: amount(1_000_000),
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
    let mut s = c
        .send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: t_recipient.clone(),
            amount: Some(gyges_proto::v1::Amount {
                value: Some(gyges_proto::v1::amount::Value::Max(true)),
            }),
            wait_for_mined: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut events = Vec::new();
    while let Some(item) = s.next().await {
        let ev = item.unwrap_or_else(|e| panic!("max send: {e:?}"));
        match &ev.event {
            Some(send_event::Event::SignatureRequired(r)) => {
                c.unlock_key(UnlockKeyRequest {
                    key_id: r.key_id.clone(),
                    passphrase: "pw".into(),
                    session_id: r.session_id.clone(),
                    ..Default::default()
                })
                .await
                .unwrap();
            }
            Some(send_event::Event::Broadcast(_)) => {
                node.mine(2);
            }
            _ => {}
        }
        events.push(ev);
    }
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
    let mined_height = events
        .iter()
        .find_map(|e| match &e.event {
            Some(send_event::Event::Mined(m)) => Some(m.height),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        mined_height,
        node.tip().0 - 1,
        "mined in the first of the two blocks"
    );
    wait_spendable(&mut c, "main").await;
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "main".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(b.total_spendable, 0, "{b:?}");
    assert_eq!(b.total_pending, 0, "{b:?}");

    drop(state);
    task.abort();
    drop(dir);
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut last = None;
    loop {
        let resp = c
            .list_signing_sessions(ListSigningSessionsRequest {
                key_id: String::new(),
                include_finished: true,
            })
            .await
            .unwrap()
            .into_inner();
        if let Some(row) = resp
            .tex_transfers
            .iter()
            .find(|r| r.step1_txid == step1_txid)
        {
            if ok(row) {
                return row.clone();
            }
            last = Some(row.clone());
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tex row never reached {what}; last seen {last:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Wait until the fake node's mempool holds `txid`.
async fn wait_in_mempool(node: &FakeNode, txid: &str) {
    let want = gyges_chain::parse_display_hash(txid).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !node.mempool().contains(&want) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{txid} never reached the mempool: {:?}",
            node.mempool()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let url = node.url().to_string();
    let (dir, home) = fresh_home_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [policy]\nmin_confirmations = 1\n[tex]\nrebroadcast_interval = \"1s\"\n",
    );
    let mut opts = Options::new(home.clone(), Network::Regtest);
    opts.zakura_rpc = Some(url);
    opts.log_hub = Some(test_hub());
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let state = daemon.state.clone();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut c = client(&socket).await;
    let params = Network::Regtest.consensus_params();
    let amount = |z: i64| {
        Some(gyges_proto::v1::Amount {
            value: Some(gyges_proto::v1::amount::Value::Zatoshis(z)),
        })
    };

    // A funded, shielded wallet: 3 ZEC in Ironwood.
    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    wait_spendable(&mut c, "main").await;
    let key = state.registry.resolve("main").unwrap();
    let receiver = {
        let w = key.wallet().unwrap();
        let account = w.get_account_ids().unwrap()[0];
        *w.get_transparent_receivers(account, false, false)
            .unwrap()
            .keys()
            .next()
            .expect("a transparent receiver")
    };
    node.mine_with_payments(&[(receiver, 300_000_000)]);
    node.mine(1);
    wait_spendable(&mut c, "main").await;
    c.unlock_key(UnlockKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    })
    .await
    .unwrap();
    let events = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "main".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    let _ = broadcast_txid(&events);
    c.lock_key(LockKeyRequest {
        key_id: "main".into(),
        all: false,
    })
    .await
    .unwrap();
    node.mine(2);
    wait_spendable(&mut c, "main").await;
    let balance = |c: &mut GygesClient<Channel>| {
        let mut c = c.clone();
        async move {
            let b = c
                .get_balance(GetBalanceRequest {
                    key_id: "main".into(),
                    min_confirmations: 0,
                })
                .await
                .unwrap()
                .into_inner();
            balance_of(&b, Pool::Ironwood).0
        }
    };
    let funded = balance(&mut c).await;
    assert!(funded > 299_000_000 && funded < 300_000_000, "{funded}");

    let tex_pkh = [0x42u8; 20];
    let tex_addr = zcash_keys::address::Address::Tex(tex_pkh).encode(&params);
    assert!(tex_addr.starts_with("texregtest1"), "{tex_addr}");

    // --dry-run: both steps, every fee (ARCHITECTURE.md §3.3 step 4).
    let dry = collect_events(
        c.send_transaction(SendTransactionRequest {
            key_id: "main".into(),
            to: tex_addr.clone(),
            amount: amount(50_000_000),
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
            amount: amount(50_000_000),
            ..Default::default()
        },
        "pw",
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
    let wait_connected = |want: bool| {
        let chain = chain.clone();
        async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while gyges_chain::ChainBackend::status(chain.as_ref()).connected != want {
                assert!(
                    std::time::Instant::now() < deadline,
                    "node never connected={want}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
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
    let after_a = balance(&mut c).await;
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
            amount: amount(20_000_000),
            ..Default::default()
        },
        "pw",
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
            amount: amount(10_000_000),
            ..Default::default()
        },
        "pw",
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
    let final_balance = balance(&mut c).await;
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

    drop(state);
    task.abort();
    drop(dir);
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
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let url = node.url().to_string();
    let (dir, home) = fresh_home_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n[policy]\nmin_confirmations = 1\n",
    );
    let mut opts = Options::new(home.clone(), Network::Regtest);
    opts.zakura_rpc = Some(url);
    opts.log_hub = Some(test_hub());
    let daemon = Daemon::prepare(opts).expect("prepare");
    let socket = daemon.socket_path();
    let state = daemon.state.clone();
    let task = tokio::spawn(daemon.serve(std::future::pending()));
    for _ in 0..400 {
        if uds::probe(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut c = client(&socket).await;
    let params = Network::Regtest.consensus_params();
    let amount = |z: i64| {
        Some(gyges_proto::v1::Amount {
            value: Some(gyges_proto::v1::amount::Value::Zatoshis(z)),
        })
    };
    let t_recipient = zcash_keys::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([0x42; 20]),
    )
    .encode(&params);

    // Two funded keys: `main` for the pipeline, `second` for the mixed-key
    // combine.
    for id in ["main", "second"] {
        c.init_key(InitKeyRequest {
            key_id: id.into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        wait_spendable(&mut c, id).await;
        let receiver = {
            let key = state.registry.resolve(id).unwrap();
            let w = key.wallet().unwrap();
            let account = w.get_account_ids().unwrap()[0];
            *w.get_transparent_receivers(account, false, false)
                .unwrap()
                .keys()
                .next()
                .expect("a transparent receiver")
        };
        node.mine_with_payments(&[(receiver, 100_000_000)]);
    }
    node.mine(1);
    wait_spendable(&mut c, "main").await;
    wait_spendable(&mut c, "second").await;
    let create = |key_id: &str, to: &str, z: i64| CreatePcztRequest {
        key_id: key_id.into(),
        to: to.into(),
        amount: amount(z),
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
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "main".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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

    drop(state);
    task.abort();
    drop(dir);
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let st = c
            .get_sync_status(GetSyncStatusRequest {
                key_id: key_id.into(),
            })
            .await
            .unwrap()
            .into_inner();
        let k = st.keys[0].clone();
        if done(&k) {
            return k;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never {what}: {k:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Mine a chain with one shielding transaction in it (so that the backfill
/// carries real Ironwood commitments): a key born at the tip is funded on a
/// transparent receiver, shields, and the shield is mined. Returns the
/// key's mnemonic, its Ironwood balance and the shield's height.
async fn chain_with_a_shielded_note(node: &FakeNode) -> (String, i64, u32) {
    use gyges_proto::v1::Pool;
    node.mine(5);
    let url = node.url().to_string();
    let running = start_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [policy]\nmin_confirmations = 1\n",
        |o| o.zakura_rpc = Some(url),
    )
    .await;
    let mut c = client(&running.socket).await;
    let resp = c
        .init_key(InitKeyRequest {
            key_id: "orig".into(),
            passphrase: "pw".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    wait_spendable(&mut c, "orig").await;
    let receiver = {
        let key = running.state.registry.resolve("orig").unwrap();
        let w = key.wallet().unwrap();
        let account = w.get_account_ids().unwrap()[0];
        *w.get_transparent_receivers(account, false, false)
            .unwrap()
            .keys()
            .next()
            .unwrap()
    };
    node.mine_with_payments(&[(receiver, 100_000_000)]);
    node.mine(1);
    wait_spendable(&mut c, "orig").await;
    c.unlock_key(UnlockKeyRequest {
        key_id: "orig".into(),
        passphrase: "pw".into(),
        scope: UnlockScope::Daemon as i32,
        ..Default::default()
    })
    .await
    .unwrap();
    let events = collect_events(
        c.shield_funds(ShieldFundsRequest {
            key_id: "orig".into(),
            ..Default::default()
        })
        .await,
    )
    .await
    .unwrap();
    assert!(event_names(&events).contains(&"broadcast"), "{events:?}");
    node.mine(1);
    let shield_height = node.tip().0;
    wait_spendable(&mut c, "orig").await;
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "orig".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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

    let (node_url, lwd_url) = (node.url().to_string(), lwd.url().to_string());
    let running = start(|o| {
        o.zakura_rpc = Some(node_url);
        o.fallback_lwd = Some(lwd_url);
        o.no_tor = true;
    })
    .await;
    let mut c = client(&running.socket).await;
    let info = c.get_info(GetInfoRequest {}).await.unwrap().into_inner();
    assert_eq!(info.fallback.unwrap().trust(), FallbackTrust::Untested);
    assert_eq!(
        info.tor.unwrap().state(),
        gyges_proto::v1::TorState::Disabled
    );

    // Consent first, then the restore is accepted with the block count.
    let req = RestoreKeyRequest {
        key_id: "copy".into(),
        mnemonic: mnemonic.clone(),
        passphrase: "pw".into(),
        birthday_height: 4,
        ..Default::default()
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
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "copy".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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
    let (node_url, liar_url) = (node.url().to_string(), liar.url().to_string());
    let running = start(|o| {
        o.zakura_rpc = Some(node_url);
        o.fallback_lwd = Some(liar_url);
        o.no_tor = true;
    })
    .await;
    let mut c = client(&running.socket).await;
    c.restore_key(RestoreKeyRequest {
        key_id: "copy".into(),
        mnemonic,
        passphrase: "pw".into(),
        birthday_height: 4,
        allow_backfill: true,
        ..Default::default()
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
    let b = c
        .get_balance(GetBalanceRequest {
            key_id: "copy".into(),
            min_confirmations: 0,
        })
        .await
        .unwrap()
        .into_inner();
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
    let node = FakeNode::start(regtest_params()).await;
    node.mine(40);
    node.set_prune_height(Some(25));
    let lwd = FakeLightwalletd::from_node(&node).await;
    lwd.fork_from(5);
    let (node_url, lwd_url) = (node.url().to_string(), lwd.url().to_string());
    let running = start(|o| {
        o.zakura_rpc = Some(node_url);
        o.fallback_lwd = Some(lwd_url);
        o.no_tor = true;
    })
    .await;
    let mut c = client(&running.socket).await;
    c.restore_key(RestoreKeyRequest {
        key_id: "old".into(),
        mnemonic: known_mnemonic(),
        passphrase: "pw".into(),
        birthday_height: 5,
        allow_backfill: true,
        ..Default::default()
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
            key_id: "other".into(),
            mnemonic: known_mnemonic(),
            passphrase: "pw".into(),
            birthday_height: 6,
            allow_backfill: true,
            ..Default::default()
        })
        .await
        .unwrap_err();
    let typed = GygesError::from_status(&err).unwrap();
    assert_eq!(typed.reason(), ErrorReason::FallbackUnavailable);
    assert!(typed.detail.contains("untrusted"), "{}", typed.detail);
    running.task.abort();
}

/// Item 3, the pruning race: the node prunes past a key while it scans
/// (after the first batch); the key falls back to the endpoint, validates
/// at `retained_from + k` and finishes on the node.
#[tokio::test]
async fn node_pruning_past_the_scan_tip_mid_scan_falls_back_and_recovers() {
    use gyges_proto::v1::FallbackTrust;
    let node = FakeNode::start(regtest_params()).await;
    node.mine(10);
    let lwd = FakeLightwalletd::from_node(&node).await;
    let (node_url, lwd_url) = (node.url().to_string(), lwd.url().to_string());
    let running = start_with(
        "[vault]\nscrypt_work_factor = 10\n[zakura_rpc]\npoll_interval_secs = 1\n\
         [cache]\nscan_batch = 10\nfetch_batch = 10\n",
        |o| {
            o.zakura_rpc = Some(node_url);
            o.fallback_lwd = Some(lwd_url);
            o.no_tor = true;
        },
    )
    .await;
    let mut c = client(&running.socket).await;
    c.init_key(InitKeyRequest {
        key_id: "main".into(),
        passphrase: "pw".into(),
        ..Default::default()
    })
    .await
    .unwrap();
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
