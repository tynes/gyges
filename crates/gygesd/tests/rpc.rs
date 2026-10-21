//! In-process daemon against a temporary `GYGES_HOME`, driven with the
//! generated client over the Unix socket (THREAT_MODEL.md §5 rows for the
//! peer check, socket mode and permission sweep; API.md §8 air-gapped list).

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gyges_core::{Home, Network, perms};
use gyges_proto::uds;
use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{
    ErrorReason, GetBalanceRequest, GetInfoRequest, GygesError, ShutdownRequest,
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
    (dir, home)
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
        "network = \"mainnet\"\n",
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
        "network = \"regtest\"\n[fallback_lightwalletd]\nenabled = true\n",
    )
    .unwrap();
    let err = Daemon::prepare(Options::new(home, Network::Regtest)).unwrap_err();
    assert!(format!("{err:#}").contains("grpc_url"), "{err:#}");
}
