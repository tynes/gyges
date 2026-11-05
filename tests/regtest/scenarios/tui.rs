//! `gyges tui --dump` through the binaries against the in-process fake
//! `zakurad` (docs/interface.md CLI §2.7): the frame a terminal would show,
//! drawn without one.
//!
//! Covers: the header's tip and Tor state, the wallet list, a funded
//! transparent balance on the Overview, the funding note on the Notes tab,
//! the receipt on the Transactions tab, and the screen of a daemon that is
//! not running.

use gyges_regtest::{Fixture, SPEND_CONFIG, fund_transparent, synced_key};

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
}

#[test]
fn a_stopped_daemon_gets_the_reconnect_screen() {
    let fx = Fixture::new("regtest");
    let s = fx.gyges(&["tui", "--dump", "120x20"]).ok().stdout;
    assert!(s.contains("gygesd is not reachable"), "{s}");
    assert!(s.contains("gyges daemon start"), "{s}");
}
