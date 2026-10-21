//! Node polling (SYNC.md §1): refresh `NodeBounds` every
//! `zakura_rpc.poll_interval_secs`, log connectivity transitions, and warn
//! once when the node's retention window is shorter than
//! `zakura_rpc.min_retention_blocks`.
//!
//! The sync scheduler (ROADMAP.md M1, next item) will drive its ticks from
//! the same poll; until then the poll only feeds `GetInfo.node`.

use std::sync::Arc;
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

/// Poll forever at the configured interval. The caller has just polled, so
/// the first interval tick (which fires immediately) is skipped.
pub fn spawn_poller(
    state: Arc<DaemonState>,
    chain: Arc<dyn ChainBackend>,
    link: Arc<Link>,
) -> tokio::task::JoinHandle<()> {
    let every = Duration::from_secs(u64::from(state.config.zakura_rpc.poll_interval_secs.max(1)));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            poll_once(&state, chain.as_ref(), &link).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_starts_unknown() {
        let l = Link::default();
        assert_ne!(l.0.load(Ordering::Relaxed), UP);
        assert_ne!(l.0.load(Ordering::Relaxed), DOWN);
    }
}
