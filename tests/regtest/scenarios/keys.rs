//! `gyges key list / init / restore` through the binaries (CLI_SPEC.md
//! §2.2, THREAT_MODEL.md §5 rows for `seed.age` and the permission sweep).
//! No node is involved: `key init` therefore needs `--airgapped`
//! (signer-only) and `key restore` works only with the default birthday.

use std::os::unix::fs::PermissionsExt as _;

use gyges_regtest::Fixture;

/// 23×abandon + art: the all-zero-entropy BIP 39 vector.
fn known_mnemonic() -> String {
    "abandon ".repeat(23) + "art\n"
}

fn fast_scrypt(fx: &Fixture) {
    fx.write_config("[vault]\nscrypt_work_factor = 10\n");
}

#[test]
fn list_is_empty_on_a_fresh_home() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&[]).unwrap();
    let run = fx.gyges(&["key", "list"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("no keys"), "{}", run.stdout);
    let run = fx.gyges(&["key", "list", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["schema_version"], "0.1");
    assert!(
        run.json().get("keys").is_none(),
        "empty repeated is omitted"
    );
}

#[test]
fn init_needs_a_terminal_or_the_scripted_form() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&["--airgapped"]).unwrap();

    // No TTY, no passphrase source: exit 4 before any RPC.
    let run = fx.gyges(&["key", "init", "--id", "main"]).run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("--passphrase-fd"), "{}", run.stderr);
    assert!(!fx.key_dir("main").exists());

    // --json without a passphrase source is still interactive-only.
    let run = fx.gyges(&["key", "init", "--id", "main", "--json"]).run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_CONFIRMATION_REQUIRED"
    );
}

#[test]
fn scripted_init_on_an_airgapped_daemon_creates_a_signer_only_key() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&["--airgapped"]).unwrap();
    let pw = fx.passphrase_file("correct horse");

    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let json = run.json();
    assert_eq!(json["key_id"], "main");
    assert_eq!(
        json["mnemonic"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .count(),
        24
    );
    assert!(
        json.get("birthday_height").is_none(),
        "signer-only: no birthday"
    );
    assert!(json.get("ufvk").is_none(), "signer-only: no viewing key");

    let dir = fx.key_dir("main");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for f in ["profile.json", "seed.age"] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f} is {mode:o}");
    }
    assert!(!dir.join("wallet.sqlite").exists());
    let profile: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("profile.json")).unwrap()).unwrap();
    assert_eq!(profile["signing_mode"], "signer-only");
    assert_eq!(profile["seed_format"], "age-scrypt-v1");
    assert_eq!(profile["network"], "regtest");

    let run = fx.gyges(&["key", "list"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(run.stdout.contains("main"), "{}", run.stdout);
    assert!(run.stdout.contains("signer-only"), "{}", run.stdout);
    assert!(run.stdout.contains("locked"), "{}", run.stdout);
    let run = fx.gyges(&["daemon", "status"]).run();
    assert!(run.stdout.contains("main"), "{}", run.stdout);

    // Same id again: exit 6, KEY_EXISTS.
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert_eq!(run.json()["error"]["reason"], "ERROR_REASON_KEY_EXISTS");
    assert_eq!(run.json()["error"]["key_id"], "main");

    // The daemon log never contains the passphrase or a mnemonic word.
    let mut log = String::new();
    for entry in std::fs::read_dir(fx.network_dir().join("logs"))
        .unwrap()
        .flatten()
    {
        log.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
    }
    assert!(!log.contains("correct horse"), "passphrase in log");
    // Single BIP 39 words ("key", "daemon", "start") occur in ordinary log
    // lines; any three consecutive words of the phrase would not.
    let words: Vec<&str> = json["mnemonic"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .collect();
    for run in words.windows(3) {
        let needle = run.join(" ");
        assert!(
            !log.contains(&needle),
            "mnemonic fragment {needle:?} in log"
        );
    }

    // Survives a restart: the key is listed by the next daemon.
    let run = fx.gyges(&["daemon", "stop"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    fx.wait_daemon(std::time::Duration::from_secs(10)).unwrap();
    fx.start_daemon(&["--airgapped"]).unwrap();
    let run = fx.gyges(&["key", "list", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["keys"][0]["key_id"], "main");
    assert_eq!(
        run.json()["keys"][0]["signing_mode"],
        "SIGNING_MODE_SIGNER_ONLY"
    );
}

#[test]
fn init_without_a_node_is_exit_7() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&[]).unwrap();
    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 7, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_NODE_UNREACHABLE"
    );
    assert!(!fx.key_dir("main").exists());
}

#[test]
fn restore_from_stdin_with_the_default_birthday() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&[]).unwrap();
    let pw = fx.passphrase_file("pw");

    let run = fx
        .gyges(&["key", "restore", "--id", "r", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(known_mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let json = run.json();
    assert_eq!(json["key_id"], "r");
    assert_eq!(json["birthday_height"], 1, "regtest Sapling activation");
    assert!(
        json["ufvk"].as_str().unwrap().starts_with("uviewregtest1"),
        "{json}"
    );
    assert!(run.stderr.contains("no --birthday"), "{}", run.stderr);
    let dir = fx.key_dir("r");
    for f in ["profile.json", "seed.age", "wallet.sqlite"] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f} is {mode:o}");
    }

    let run = fx.gyges(&["key", "list", "--json"]).run();
    let keys = &run.json()["keys"];
    assert_eq!(keys[0]["key_id"], "r");
    assert_eq!(keys[0]["signing_mode"], "SIGNING_MODE_LOCAL_SEED");
    assert_eq!(keys[0]["birthday_height"], 1);
    assert_eq!(keys[0]["locked"], true);

    // The same words restore to the same viewing key.
    let run = fx
        .gyges(&[
            "key",
            "restore",
            "--id",
            "r2",
            "--stdin",
            "--birthday",
            "1",
            "-q",
            "--json",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(known_mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["ufvk"], json["ufvk"]);

    // A later birthday needs the node: exit 7, nothing created.
    let run = fx
        .gyges(&[
            "key",
            "restore",
            "--id",
            "later",
            "--stdin",
            "--birthday",
            "100",
            "--json",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(known_mnemonic())
        .run();
    assert_eq!(run.code(), 7, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_NODE_UNREACHABLE"
    );
    assert!(!fx.key_dir("later").exists());

    // Bad words are refused client-side (count) and daemon-side (checksum).
    let run = fx
        .gyges(&["key", "restore", "--id", "x", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin("abandon abandon\n")
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    let run = fx
        .gyges(&["key", "restore", "--id", "x", "--stdin", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin("abandon ".repeat(23) + "abandon\n")
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_INVALID_ARGUMENT"
    );

    // Without a passphrase source and without a TTY: exit 4, no RPC.
    let run = fx
        .gyges(&["key", "restore", "--id", "y", "--stdin", "--json"])
        .stdin(known_mnemonic())
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert_eq!(run.json()["error"]["reason"], "ERROR_REASON_VAULT_LOCKED");
}

#[test]
fn a_wide_key_file_refuses_the_next_start() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&["--airgapped"]).unwrap();
    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "init", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    fx.gyges(&["daemon", "stop"]).run();
    fx.wait_daemon(std::time::Duration::from_secs(10)).unwrap();

    let seed = fx.key_dir("main").join("seed.age");
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o644)).unwrap();
    let run = fx.run_daemon_to_exit(&["--airgapped"]);
    assert_ne!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr
            .contains(&format!("chmod 600 {}", seed.display())),
        "{}",
        run.stderr
    );
}

#[test]
fn unlock_lock_and_export_through_the_cli() {
    let mut fx = Fixture::new("regtest");
    fast_scrypt(&fx);
    fx.start_daemon(&[]).unwrap();
    let pw = fx.passphrase_file("pw");
    let run = fx
        .gyges(&["key", "restore", "--id", "main", "--stdin", "-q", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .stdin(known_mnemonic())
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    let ufvk = run.json()["ufvk"].as_str().unwrap().to_string();

    // export-ufvk needs no unlock for a local-seed key; --key is honoured.
    let run = fx.gyges(&["-k", "main", "key", "export-ufvk"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.stdout.trim(), ufvk);
    let run = fx
        .gyges(&["key", "export-ufvk", "--id", "main", "--json"])
        .run();
    assert_eq!(run.json()["ufvk"], ufvk);
    assert_eq!(run.json()["birthday_height"], 1);
    // No default key configured: an empty id is exit 6.
    let run = fx.gyges(&["key", "export-ufvk"]).run();
    assert_eq!(run.code(), 6, "{run:?}");
    assert!(run.stderr.contains("no default key"), "{}", run.stderr);

    // Unlock without a passphrase source and no terminal: exit 4, VAULT_LOCKED.
    let run = fx.gyges(&["key", "unlock", "--id", "main", "--json"]).run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert_eq!(run.json()["error"]["reason"], "ERROR_REASON_VAULT_LOCKED");

    // Wrong passphrase: exit 4, then rate limited on the next try.
    let bad = fx.passphrase_file("nope");
    let run = fx
        .gyges(&["key", "unlock", "--id", "main", "--json"])
        .env("GYGES_PASSPHRASE_FILE", &bad)
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert_eq!(
        run.json()["error"]["reason"],
        "ERROR_REASON_INVALID_PASSPHRASE"
    );
    let run = fx
        .gyges(&["key", "unlock", "--id", "main"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("retry in"), "{}", run.stderr);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let run = fx
        .gyges(&[
            "key",
            "unlock",
            "--id",
            "main",
            "--timeout",
            "90s",
            "--json",
        ])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["scope"], "UNLOCK_SCOPE_DAEMON");
    assert!(run.json().get("session_token").is_none(), "{}", run.stdout);
    let run = fx.gyges(&["key", "list"]).run();
    assert!(run.stdout.contains("UNLOCKED until"), "{}", run.stdout);
    let run = fx.gyges(&["daemon", "status"]).run();
    assert!(run.stdout.contains("UNLOCKED"), "{}", run.stdout);

    let run = fx.gyges(&["key", "lock", "--all", "--json"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert_eq!(run.json()["locked_key_ids"][0], "main");
    let run = fx.gyges(&["key", "list", "--json"]).run();
    assert_eq!(run.json()["keys"][0]["locked"], true);
    let run = fx.gyges(&["key", "lock", "--id", "main"]).run();
    assert_eq!(run.code(), 0, "{run:?}");
    assert!(
        run.stderr.contains("nothing was unlocked"),
        "{}",
        run.stderr
    );

    // export-seed: never JSON (exit 6), never without a terminal (exit 4).
    let run = fx
        .gyges(&["key", "export-seed", "--id", "main", "--json"])
        .run();
    assert_eq!(run.code(), 6, "{run:?}");
    let run = fx
        .gyges(&["key", "export-seed", "--id", "main"])
        .env("GYGES_PASSPHRASE_FILE", &pw)
        .run();
    assert_eq!(run.code(), 4, "{run:?}");
    assert!(run.stderr.contains("terminal"), "{}", run.stderr);
    assert!(
        !run.stdout.contains("abandon"),
        "no words without a terminal"
    );
}
