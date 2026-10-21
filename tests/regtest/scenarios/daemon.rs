//! Daemon lifecycle and handshake scenarios (TESTING.md §3 row 15 and the
//! THREAT_MODEL.md §5 rows for socket mode, permission sweep and the
//! single-instance lock). No node is involved yet.

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use gyges_regtest::Fixture;

#[test]
fn status_reports_version_network_and_json_schema() {
    let mut fx = Fixture::new("regtest");
    fx.start_daemon(&[]).unwrap();

    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stdout.contains("(API 0.1) on regtest"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("node:         not connected"),
        "{}",
        run.stdout
    );

    let run = fx.gyges(&["daemon", "status", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    let json = run.json();
    assert_eq!(json["schema_version"], "0.1");
    assert_eq!(json["network"], "NETWORK_REGTEST");
    // proto3 JSON omits zero values, so a major of 0 is absent.
    assert_eq!(json["api_version"]["major"].as_u64().unwrap_or(0), 0);
    assert_eq!(json["api_version"]["minor"], 1);
    assert_eq!(json["daemon_version"], env!("CARGO_PKG_VERSION"));
    assert!(
        json.get("airgapped").is_none(),
        "false is omitted in proto3 JSON"
    );
    assert!(json["started_at"].is_string(), "int64 is a JSON string");

    // Without --network the CLI adopts the daemon's; with --socket as well.
    let run = fx
        .gyges_no_network(&[
            "--socket",
            fx.socket().to_str().unwrap(),
            "daemon",
            "status",
            "-j",
        ])
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["network"], "NETWORK_REGTEST");
}

/// TESTING.md scenario 15.
#[test]
fn network_mismatch_exits_6_before_any_other_rpc() {
    let mut fx = Fixture::new("regtest");
    fx.start_daemon(&[]).unwrap();
    let socket = fx.socket();
    let run = fx
        .gyges_no_network(&[
            "-n",
            "testnet",
            "--socket",
            socket.to_str().unwrap(),
            "daemon",
            "status",
        ])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("serves regtest"), "{}", run.stderr);
    assert!(run.stderr.contains("testnet"), "{}", run.stderr);

    let run = fx
        .gyges_no_network(&[
            "-n",
            "testnet",
            "--socket",
            socket.to_str().unwrap(),
            "daemon",
            "status",
            "--json",
        ])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    let json = run.json();
    assert_eq!(json["schema_version"], "0.1");
    assert_eq!(json["error"]["reason"], "ERROR_REASON_NETWORK_MISMATCH");
}

#[test]
fn missing_daemon_exits_3_with_the_fix() {
    let fx = Fixture::new("regtest");
    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 3, "{run:?}");
    assert!(
        run.stderr
            .contains("gygesd is not running; start it with 'gyges daemon start'"),
        "{}",
        run.stderr
    );

    let run = fx.gyges(&["daemon", "stop", "--json"]).run();
    assert_eq!(run.code(), 3, "{run:?}");
    let json = run.json();
    // A client-side failure has no daemon reason; proto3 JSON omits the
    // zero value, so `reason` is absent rather than "ERROR_REASON_UNSPECIFIED".
    assert!(json["error"].get("reason").is_none(), "{json}");
    assert!(
        json["error"]["detail"]
            .as_str()
            .unwrap()
            .contains("gygesd is not running"),
        "{json}"
    );
}

#[test]
fn stop_removes_the_socket_and_the_daemon_exits_cleanly() {
    let mut fx = Fixture::new("regtest");
    fx.start_daemon(&[]).unwrap();
    assert!(fx.pid_file().is_file());
    let pid = fx.daemon_pid().unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.pid_file()).unwrap().trim(),
        pid.to_string()
    );

    let run = fx.gyges(&["daemon", "stop"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("gygesd stopped"), "{}", run.stderr);
    assert!(!fx.socket().exists(), "socket removed");
    let status = fx.wait_daemon(Duration::from_secs(10)).unwrap();
    assert!(status.success(), "{status}");
    assert!(!fx.pid_file().exists(), "pid file removed");

    let run = fx.gyges(&["daemon", "status"]).run();
    assert_eq!(run.code(), 3, "{run:?}");
}

#[test]
fn start_and_stop_through_the_cli_daemonizes() {
    let fx = Fixture::new("regtest");
    let run = fx.gyges(&["daemon", "start", "--airgapped"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr.contains("gygesd started for regtest (pid "),
        "{}",
        run.stderr
    );
    assert!(fx.socket().exists());
    assert!(fx.pid_file().is_file());

    // Idempotent.
    let run = fx.gyges(&["daemon", "start"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("already running"), "{}", run.stderr);

    let run = fx.gyges(&["daemon", "status", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["airgapped"], true);

    // Everything the daemon wrote is private (umask 077 + 0700 dirs).
    for entry in walk(&fx.network_dir()) {
        let mode = std::fs::symlink_metadata(&entry)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0, "{} is mode {mode:o}", entry.display());
    }
    let logs: Vec<_> = std::fs::read_dir(fx.network_dir().join("logs"))
        .unwrap()
        .flatten()
        .collect();
    assert!(!logs.is_empty(), "a log file was written");

    let run = fx.gyges(&["daemon", "stop"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(!fx.socket().exists());
    // The detached daemon removes its pid file on the way out.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while fx.pid_file().exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!fx.pid_file().exists(), "pid file removed");
}

#[test]
fn second_daemon_for_the_same_home_refuses_to_start() {
    let mut fx = Fixture::new("regtest");
    fx.start_daemon(&[]).unwrap();
    let run = fx.run_daemon_to_exit(&[]);
    assert_ne!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("already running"), "{}", run.stderr);
    assert!(
        run.stderr.contains(&fx.daemon_pid().unwrap().to_string()),
        "{}",
        run.stderr
    );
    // The first daemon is unharmed.
    assert_eq!(fx.gyges(&["daemon", "status"]).run().code(), 0);
}

#[test]
fn wide_permissions_refuse_start_with_a_chmod_hint() {
    let fx = Fixture::new("regtest");
    let keys = fx.network_dir().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::set_permissions(fx.network_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = fx.run_daemon_to_exit(&[]);
    assert_ne!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr
            .contains(&format!("chmod 700 {}", keys.display())),
        "{}",
        run.stderr
    );
    assert!(!fx.socket().exists());
}

#[test]
fn config_errors_refuse_start_and_cli_start_relays_them() {
    let fx = Fixture::new("regtest");
    fx.write_config("network = \"regtest\"\n[vault]\nunlock_tll = \"5m\"\n");
    let run = fx.run_daemon_to_exit(&[]);
    assert_ne!(run.code(), 0, "{run:?}");
    assert!(run.stderr.contains("unknown field"), "{}", run.stderr);

    let run = fx.gyges(&["daemon", "start"]).run();
    assert_eq!(run.code(), 1, "{run:?}");
    assert!(
        run.stderr.contains("gygesd failed to start"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("unknown field"), "{}", run.stderr);
    assert!(!fx.socket().exists());
}

#[test]
fn unimplemented_commands_exit_1_not_2() {
    let fx = Fixture::new("regtest");
    let run = fx.gyges(&["key", "backup", "-o", "x.tar"]).run();
    assert_eq!(run.code(), 1, "{run:?}");
    assert!(run.stderr.contains("not implemented yet"), "{}", run.stderr);
    // Usage errors are still exit 2.
    let run = fx.gyges(&["daemon", "frobnicate"]).run();
    assert_eq!(run.code(), 2, "{run:?}");
    let run = fx
        .gyges_no_network(&["-n", "devnet", "daemon", "status"])
        .run();
    assert_eq!(run.code(), 2, "{run:?}");
}

#[test]
fn logs_command_reports_unimplemented_rpc_as_exit_1() {
    let mut fx = Fixture::new("regtest");
    fx.start_daemon(&[]).unwrap();
    let run = fx.gyges(&["daemon", "logs", "--lines", "5"]).run();
    assert_eq!(run.code(), 1, "{run:?}");
    assert!(run.stderr.contains("Unimplemented"), "{}", run.stderr);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
