//! Node polling (SYNC.md §1): refresh `NodeBounds` every
//! `zakura_rpc.poll_interval_secs`, log connectivity transitions, and warn
//! once when the node's retention window is shorter than
//! `zakura_rpc.min_retention_blocks`.
//!
//! The sync scheduler (`crate::sync`) calls [`poll_once`] on every tick.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use gyges_chain::ChainBackend;

use crate::service::DaemonState;

/// Bound on the first poll, which runs before the socket is bound so that a
/// `daemon status` right after `daemon start` is accurate. A refused
/// connection returns at once; this only bites on a black-holed address.
pub const FIRST_POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// What the previous poll saw, so that only transitions are logged and a
/// node that stays down produces one warning rather than one per tick.
#[derive(Debug, Default)]
pub struct Link(AtomicU8);

// 0 (the default) means "never polled"; both transitions below log.
const UP: u8 = 1;
const DOWN: u8 = 2;

/// Whether `url` points at this machine: `localhost` or a loopback address.
/// Anything else is a remote node, which THREAT_MODEL.md §3 row 6 says
/// moves the node operator into the trusted base; the first successful poll
/// warns once.
pub fn is_local_host(url: &str) -> bool {
    let Ok(uri) = url.parse::<http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One poll. Returns whether the node answered.
pub async fn poll_once(state: &DaemonState, chain: &dyn ChainBackend, link: &Link) -> bool {
    let before = link.0.load(Ordering::Relaxed);
    let url = &state.config.zakura_rpc.url;
    match chain.node_bounds().await {
        Ok(bounds) => {
            if before != UP {
                let status = chain.status();
                let tip = u32::from(bounds.tip_height);
                let retained_from = u32::from(bounds.retained_from);
                tracing::info!(
                    tip,
                    retained_from,
                    pruned = status.pruned,
                    url = %url,
                    "node connected"
                );
                if !is_local_host(url) {
                    tracing::warn!(
                        url = %url,
                        "zakura_rpc.url is not this machine: the node's operator sees every \
                         block the wallet fetches, every transaction it broadcasts and when \
                         (THREAT_MODEL.md §3 row 6)"
                    );
                }
                let window = tip.saturating_sub(retained_from);
                let min = state.config.zakura_rpc.min_retention_blocks;
                if status.pruned && window < min {
                    tracing::warn!(
                        retains = window,
                        min_retention_blocks = min,
                        "the node retains fewer blocks than zakura_rpc.min_retention_blocks; \
                         a daemon that is down longer than that will need the Tor fallback \
                         (SYNC.md §4.2)"
                    );
                }
            }
            link.0.store(UP, Ordering::Relaxed);
            true
        }
        Err(e) => {
            if before != DOWN {
                tracing::warn!(error = %e, url = %url, "node unreachable");
            }
            link.0.store(DOWN, Ordering::Relaxed);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_localhost_are_local_and_nothing_else_is() {
        for url in [
            "http://127.0.0.1:8232",
            "http://127.1.2.3:18232/",
            "http://localhost:8232",
            "http://LocalHost",
            "http://[::1]:8232",
            "http://user:pw@127.0.0.1:8232",
        ] {
            assert!(is_local_host(url), "{url}");
        }
        for url in [
            "http://192.168.1.5:8232",
            "http://10.0.0.1",
            "http://node.example:8232",
            "http://[2001:db8::1]:8232",
            "http://localhost.example",
            "not a url",
            "",
        ] {
            assert!(!is_local_host(url), "{url}");
        }
    }

    #[test]
    fn link_starts_unknown() {
        let l = Link::default();
        assert_ne!(l.0.load(Ordering::Relaxed), UP);
        assert_ne!(l.0.load(Ordering::Relaxed), DOWN);
    }
}
