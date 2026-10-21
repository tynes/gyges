//! In-process daemon against a temporary `GYGES_HOME`, driven with the
//! generated client over the Unix socket (THREAT_MODEL.md §5 rows for the
//! peer check, socket mode and permission sweep; API.md §8 air-gapped list).

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gyges_chain::testing::{FakeNode, regtest_params};
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
    let (dir, home) = fresh_home();
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

    // A 2-block reorg: the node drops 12 and 13 and mines 12, 13, 14 anew.
    let old_12 = node.block(12).unwrap().hash;
    node.invalidate_from(12);
    node.mine(3);
    let new_12 = node.block(12).unwrap().hash;
    assert_ne!(old_12, new_12);
    let status = wait_spendable(&mut c, "main").await;
    assert_eq!(status.scanned_tip, 14, "{status:?}");
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
            zcash_keys::address::Address::Tex([9; 20]).encode(&params),
            vec![],
            ErrorReason::UnsupportedPool,
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
