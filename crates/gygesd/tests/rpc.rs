//! In-process daemon against a temporary `GYGES_HOME`, driven with the
//! generated client over the Unix socket (THREAT_MODEL.md §5 rows for the
//! peer check, socket mode and permission sweep; API.md §8 air-gapped list).

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gyges_core::birthday::FixedChain;
use gyges_core::{Home, Network, perms};
use gyges_proto::uds;
use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    ErrorReason, ExportSeedRequest, ExportUfvkRequest, GetBalanceRequest, GetInfoRequest,
    GygesError, InitKeyRequest, ListKeysRequest, LockKeyRequest, RestoreKeyRequest,
    ShutdownRequest, SigningMode, UnlockKeyRequest, UnlockScope,
};
use gygesd::{Daemon, DaemonState, Options};
use tonic::transport::Channel;

struct Running {
    _home: tempfile::TempDir,
    socket: PathBuf,
    pid: PathBuf,
    state: Arc<DaemonState>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

fn fresh_home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    perms::set_mode(dir.path(), 0o700).unwrap();
    let home = Home::new(dir.path());
    // A low scrypt work factor keeps `InitKey` / `RestoreKey` fast here;
    // production uses the default of 20.
    let net = home.network_dir(Network::Regtest);
    std::fs::create_dir_all(&net).unwrap();
    perms::set_mode(&net, 0o700).unwrap();
    perms::create_private_file(&home.config_path(Network::Regtest)).unwrap();
    std::fs::write(
        home.config_path(Network::Regtest),
        "[vault]\nscrypt_work_factor = 10\n",
    )
    .unwrap();
    (dir, home)
}

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
fn known_mnemonic() -> String {
    "abandon ".repeat(23) + "art"
}

async fn start(configure: impl FnOnce(&mut Options)) -> Running {
    let (dir, home) = fresh_home();
    let mut opts = Options::new(home.clone(), Network::Regtest);
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
        .get_balance(GetBalanceRequest::default())
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

#[tokio::test]
async fn init_key_needs_a_node_unless_airgapped() {
    let running = start(|_| {}).await;
    let mut c = client(&running.socket).await;
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
