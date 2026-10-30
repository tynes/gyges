//! Keystone signing through the binaries against the fake node
//! (docs/interface.md API §4.3). Without a terminal `tx shield` and
//! `tx send` print the request's frames (or write them with `--qr-out`) and
//! exit 4 with the session left open; `pczt qr-export --session` shows the
//! same frames again; the emulated device answers from the frames alone;
//! `pczt qr-import --session` completes the session from a file or from
//! positional frames and prints the txid; an aborted session cannot be
//! completed. `pczt qr-scan` needs the `camera` feature, which this build
//! lacks.

use gyges_core::keystone::emulator;
use gyges_regtest::{
    FakeNodeHandle, Fixture, SPEND_CONFIG, burn_t_address, keystone_device, keystone_export,
    pool_spendable, sync_wait_within, transparent_receivers,
};

/// The `ur:` lines of some output.
fn ur_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .map(str::to_string)
        .collect()
}

/// What the device shows back for a request given as frames: its answer
/// as frames, one per line.
fn device_answer(request: &[String]) -> Vec<String> {
    let mut asm = gyges_qr::Assembler::new();
    for f in request {
        asm.receive(f).unwrap();
    }
    let (ur_type, cbor) = asm.message().unwrap().expect("the request reassembles");
    let (answer_type, answer) = emulator::answer(&keystone_device(), &ur_type, &cbor);
    gyges_qr::Frames::new(answer_type, &answer, gyges_qr::DEFAULT_FRAGMENT_LEN)
        .unwrap()
        .take_loops(1)
        .unwrap()
}

/// The one Keystone session awaiting the device.
fn pending_session(fx: &Fixture) -> String {
    let v = fx
        .gyges(&["-k", "ks", "tx", "sessions", "--json"])
        .ok()
        .json();
    let sessions = v["sessions"].as_array().expect("a pending session");
    assert_eq!(sessions.len(), 1, "{v}");
    sessions[0]["session_id"].as_str().unwrap().to_string()
}

fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn keystone_signing_through_the_binaries() {
    let n = FakeNodeHandle::start(10);
    let mut fx = Fixture::new("regtest");
    fx.write_config(SPEND_CONFIG);
    fx.start_daemon(&["--zakura-rpc", n.url()]).unwrap();
    fx.gyges(&["key", "import-keystone", "--id", "ks", "--birthday", "1"])
        .stdin(keystone_export(Some("13.2.0")))
        .ok();
    sync_wait_within(&fx, "ks", "60s", &[]);
    let receiver = transparent_receivers(&fx, "ks")[0];
    n.node.mine_with_payments(&[(receiver, 300_000_000)]);
    n.node.mine(1);
    sync_wait_within(&fx, "ks", "60s", &[]);

    // Shield without a terminal: the frames on stdout, exit 4, the session
    // left open.
    let run = fx.gyges(&["-k", "ks", "tx", "shield", "--yes"]).code(4);
    run.stderr_has("gyges pczt qr-import --session");
    let request = ur_lines(&run.stdout);
    assert!(!request.is_empty(), "{run:?}");
    assert!(request[0].starts_with("ur:zcash-pczt/"), "{}", request[0]);
    let sid = pending_session(&fx);
    let burn = burn_t_address();
    let send = |amount: &str| {
        fx.gyges(&[
            "-k", "ks", "tx", "send", "--to", &burn, "--amount", amount, "--yes",
        ])
    };
    // A second spend waits for this one.
    send("0.1").code(4).stderr_has(&sid);
    // This build has no camera (feature `camera` is off by default).
    fx.gyges(&["pczt", "qr-scan", "--session", &sid])
        .code(1)
        .stderr_has("built without the camera");
    // `qr-export` shows the same frames again.
    let again = fx.gyges(&["pczt", "qr-export", "--session", &sid]).ok();
    assert_eq!(ur_lines(&again.stdout), request);
    // A partial answer (one frame of several) is refused before the daemon
    // sees it.
    fx.gyges(&["pczt", "qr-import", "--session", &sid, &request[0]])
        .code(6)
        .stderr_has("incomplete");
    // The device's answer, from a file.
    let answer = device_answer(&request);
    let path = fx.home().join("answer.txt");
    std::fs::write(&path, answer.join("\n")).unwrap();
    let run = fx
        .gyges(&["pczt", "qr-import", "--session", &sid, "--from-file"])
        .arg(&path)
        .ok();
    assert!(is_txid(run.stdout.trim()), "{run:?}");
    n.node.mine(1);
    sync_wait_within(&fx, "ks", "60s", &[]);
    let b = fx.gyges(&["-k", "ks", "balance", "--json"]).ok().json();
    assert!(
        pool_spendable(&b, "POOL_IRONWOOD").unwrap_or(0) > 299_000_000,
        "{b}"
    );

    // Send with `--qr-out`: the request in a file, the batch answer as
    // positional frames.
    let req_path = fx.home().join("request.txt");
    send("0.5")
        .arg("--qr-out")
        .arg(&req_path)
        .code(4)
        .stderr_has("written to");
    let request = ur_lines(&std::fs::read_to_string(&req_path).unwrap());
    assert!(
        request[0].starts_with("ur:zcash-sign-batch/"),
        "{}",
        request[0]
    );
    let sid = pending_session(&fx);
    let run = fx
        .gyges(&["pczt", "qr-import", "--session", &sid])
        .args(device_answer(&request))
        .ok();
    assert!(is_txid(run.stdout.trim()), "{run:?}");

    n.node.mine(1);
    sync_wait_within(&fx, "ks", "60s", &[]);

    // An aborted session cannot be completed.
    let run = send("0.1").code(4);
    let request = ur_lines(&run.stdout);
    let sid = pending_session(&fx);
    fx.gyges(&["tx", "abort", &sid]).ok();
    fx.gyges(&["pczt", "qr-import", "--session", &sid])
        .args(device_answer(&request))
        .code(6)
        .stderr_has("no Keystone signing session");
}
