//! `gyges tui` through the binaries against the in-process fake `zakurad`
//! (docs/interface.md CLI §2.7).
//!
//! Covers, with `--dump` (the frame a terminal would show, drawn without
//! one): the header's tip and Tor state, the wallet list, a funded
//! transparent balance on the Overview, the funding note on the Notes tab,
//! the receipt on the Transactions tab, and the screen of a daemon that is
//! not running. And, on a pseudo-terminal with typed keys: a send from the
//! form through the dry run, the confirmation and the passphrase to the
//! node's mempool.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gyges_regtest::{
    Fixture, PASSPHRASE, SPEND_CONFIG, binary, burn_t_address, fund_transparent, sweep_logs,
    synced_key,
};

/// A frame of the TUI on `tab`, after its first full load.
fn dump(fx: &Fixture, tab: &str) -> String {
    fx.gyges(&["-k", "main", "tui", "--dump", "160x40", "--tab", tab])
        .ok()
        .stdout
}

#[test]
fn the_dashboard_shows_the_tip_the_wallet_and_a_receipt() {
    let (n, fx, _pw) = synced_key(10, SPEND_CONFIG);

    let s = dump(&fx, "overview");
    assert!(s.contains("regtest"), "{s}");
    assert!(s.contains("tip 10"), "{s}");
    assert!(s.contains("node ● connected"), "{s}");
    assert!(s.contains("Tor ○ off"), "{s}");
    assert!(s.contains("▸ main"), "{s}");
    assert!(s.contains("local-seed · locked"), "{s}");
    assert!(s.contains("synced"), "{s}");
    assert!(s.contains("total") && s.contains("0.00000000"), "{s}");

    fund_transparent(&n, &fx, 100_000_000);

    let s = dump(&fx, "overview");
    assert!(s.contains("transparent") && s.contains("1.00000000"), "{s}");
    assert!(s.contains("1 unspent notes · 1 transactions"), "{s}");

    let s = dump(&fx, "notes");
    assert!(s.contains("Notes · unspent · 1 · 1.00000000 ZEC"), "{s}");
    assert!(s.contains("transparent") && s.contains("unspent"), "{s}");

    let s = dump(&fx, "transactions");
    assert!(s.contains("+1.00000000") && s.contains("mined"), "{s}");

    // The current address, the same one `address current` prints, with its
    // code beside it.
    let ua = fx
        .gyges(&["-k", "main", "address", "current"])
        .ok()
        .stdout
        .trim()
        .to_string();
    let s = dump(&fx, "addresses");
    assert!(s.contains("current address (unified)"), "{s}");
    assert!(s.contains(&ua[..40]), "{s}");
    assert!(s.contains("receiver transparent"), "{s}");
    assert!(s.contains('█'), "the QR code is drawn: {s}");

    // The node URL comes from GetInfo (API 0.2), not from a config file.
    let info = fx.gyges(&["daemon", "status", "--json"]).ok().json();
    assert_eq!(info["node"]["rpc_url"], n.url(), "{info}");
    let s = dump(&fx, "endpoints");
    assert!(s.contains(n.url()), "{s}");
    assert!(s.contains("gygesd.sock"), "{s}");
    assert!(s.contains("archival fallback   not configured"), "{s}");

    // The live log: under --dump the stream replays without following, and
    // the newest entries fill the pane.
    let s = dump(&fx, "logs");
    assert!(s.contains("Logs · daemon log · level daemon's"), "{s}");
    assert!(s.contains(" INFO "), "{s}");
    assert!(s.contains("replayed"), "{s}");
}

#[test]
fn a_stopped_daemon_gets_the_reconnect_screen() {
    let fx = Fixture::new("regtest");
    let s = fx.gyges(&["tui", "--dump", "120x20"]).ok().stdout;
    assert!(s.contains("gygesd is not reachable"), "{s}");
    assert!(s.contains("gyges daemon start"), "{s}");
}

/// `gyges tui` on a pseudo-terminal: keys go in through the master, and
/// everything the TUI draws is collected (without its escape sequences) so
/// a test can wait for text to appear.
struct Pty {
    child: std::process::Child,
    master: std::fs::File,
    screen: Arc<Mutex<String>>,
}

impl Pty {
    fn spawn(fx: &Fixture, args: &[&str]) -> Self {
        let size = nix::pty::Winsize {
            ws_row: 50,
            ws_col: 160,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(Some(&size), None).unwrap();
        let slave = std::fs::File::from(pty.slave);
        let child = Command::new(binary("gyges"))
            .args(["--network", "regtest"])
            .args(args)
            .env("GYGES_HOME", fx.home())
            .env("TERM", "xterm-256color")
            .env_remove("GYGES_SOCKET")
            .env_remove("GYGES_NETWORK")
            .env_remove("GYGES_KEY")
            .env_remove("GYGES_PASSPHRASE_FILE")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();
        let master = std::fs::File::from(pty.master);
        let screen = Arc::new(Mutex::new(String::new()));
        // Drain the master, or the TUI blocks once the pty's buffer fills.
        let mut reader = master.try_clone().unwrap();
        let sink = screen.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let text = strip_escapes(&String::from_utf8_lossy(&buf[..n]));
                sink.lock().unwrap().push_str(&text);
            }
        });
        Self {
            child,
            master,
            screen,
        }
    }

    fn keys(&mut self, s: &str) {
        self.master.write_all(s.as_bytes()).unwrap();
        self.master.flush().unwrap();
        std::thread::sleep(Duration::from_millis(150));
    }

    /// Wait for `text` to be drawn after `from` bytes of output.
    fn wait_for(&self, text: &str, from: usize, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let s = self.screen.lock().unwrap();
                if let Some(at) = s.get(from..).and_then(|t| t.find(text)) {
                    return from + at + text.len();
                }
                if Instant::now() > deadline {
                    let tail: String = s
                        .chars()
                        .rev()
                        .take(3000)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    panic!("{text:?} never drawn; the last output was:\n{tail}");
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Text with its CSI and OSC escape sequences removed.
fn strip_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[test]
fn a_send_typed_into_the_tui_reaches_the_node() {
    let (n, fx, _pw) = synced_key(10, SPEND_CONFIG);
    fund_transparent(&n, &fx, 100_000_000);
    let to = burn_t_address();

    let mut tui = Pty::spawn(&fx, &["-k", "main", "tui", "--interval", "500ms"]);
    let at = tui.wait_for("local-seed", 0, Duration::from_secs(30));
    tui.keys("s");
    let at = tui.wait_for("Send from main", at, Duration::from_secs(10));
    tui.keys(&to);
    tui.keys("\t");
    tui.keys("0.5");
    tui.keys("\r");
    // The dry run's proposal, then the confirmation.
    let at = tui.wait_for("in total?", at, Duration::from_secs(30));
    assert!(
        n.node.mempool().is_empty(),
        "nothing is sent before the yes"
    );
    tui.keys("\r");
    let at = tui.wait_for("passphrase for main", at, Duration::from_secs(60));
    tui.keys("not-the-passphrase\r");
    let at = tui.wait_for("wrong passphrase (1 of 3)", at, Duration::from_secs(30));
    // Past the daemon's one-second back-off after a wrong passphrase.
    std::thread::sleep(Duration::from_millis(1500));
    tui.keys(PASSPHRASE);
    tui.keys("\r");
    tui.wait_for("Done.", at, Duration::from_secs(60));

    let mempool = n.node.mempool();
    assert_eq!(mempool.len(), 1, "one transaction broadcast");
    let txid = gyges_chain::display_hash(&mempool[0]);
    assert!(
        tui.screen.lock().unwrap().contains(&txid),
        "the TUI shows the txid {txid}"
    );
    tui.keys("\r");
    tui.keys("q");
    drop(tui);
    sweep_logs(
        &fx.network_dir().join("logs"),
        &[PASSPHRASE, "not-the-passphrase"],
    );
}
