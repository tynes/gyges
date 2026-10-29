//! Where a signed transaction goes and how it gets there: the node's
//! `sendrawtransaction`, or the fallback endpoint over Tor for `--via-tor`
//! (THREAT_MODEL.md §3 row 10).

use std::sync::Arc;

use gyges_chain::{ChainBackend, ChainError};
use gyges_core::KeyEntry;
use gyges_core::db::sessions::SessionState;
use gyges_proto::v1::{ErrorReason, GygesError};
use tonic::Status;

use crate::errors::broadcast_error;
use crate::service::DaemonState;
use crate::sessions::set_session_state;

/// The node backend for a broadcast, refused when air-gapped or offline.
pub(crate) fn connected_chain(
    state: &DaemonState,
    key_id: &str,
) -> Result<Arc<dyn ChainBackend>, Status> {
    let refuse = |reason, detail: &str| GygesError::new(reason, detail).with_key(key_id);
    let chain = state.chain.clone().ok_or_else(|| {
        refuse(
            ErrorReason::Airgapped,
            "an air-gapped daemon cannot broadcast",
        )
    })?;
    if !chain.status().connected {
        return Err(refuse(
            ErrorReason::NodeUnreachable,
            "the node is not connected; the transaction could not be broadcast",
        )
        .into());
    }
    Ok(chain)
}

/// Where a transaction goes: the node's `sendrawtransaction`, or the
/// fallback endpoint's `SendTransaction` for `--via-tor` and
/// `broadcast_via_tor` (THREAT_MODEL.md §3 row 10).
#[derive(Clone)]
pub(crate) enum Route {
    Node,
    Endpoint(Arc<dyn gyges_chain::ChainBackend>),
}

impl Route {
    /// The `via` field of the `broadcast` audit event.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Route::Node => "node",
            Route::Endpoint(_) => "fallback",
        }
    }

    /// Broadcast `raw` over this route; `node` is used for [`Route::Node`].
    pub(crate) async fn send(
        &self,
        node: &Arc<dyn gyges_chain::ChainBackend>,
        raw: Vec<u8>,
        key_id: &str,
    ) -> Result<(), GygesError> {
        match self {
            Route::Node => node
                .send_raw_transaction(raw)
                .await
                .map_err(|e| broadcast_error(e, key_id)),
            Route::Endpoint(endpoint) => {
                endpoint
                    .send_raw_transaction(raw)
                    .await
                    .map_err(|e| match e {
                        ChainError::Unreachable(detail) => GygesError::new(
                            ErrorReason::FallbackUnavailable,
                            format!(
                                "the fallback endpoint could not be reached for the --via-tor broadcast \
                                 (it stays in the wallet as unmined until it expires): {detail}"
                            ),
                        )
                        .with_key(key_id),
                        other => broadcast_error(other, key_id),
                    })
            }
        }
    }
}

/// The route for a broadcast, decided before anything is proven or signed.
/// `requested` is the request's `via_tor`; `broadcast_via_tor` in
/// `config.toml` turns it on for every broadcast. Asking for Tor never falls
/// back to the node: without a Tor endpoint the request is refused. A
/// `use_tor = false` endpoint stands in on regtest only, as it does for
/// backfill in CI (TESTING.md §2).
pub(crate) fn broadcast_route(
    state: &DaemonState,
    requested: bool,
    key_id: &str,
) -> Result<Route, Status> {
    if !(requested || state.config.fallback_lightwalletd.broadcast_via_tor) {
        return Ok(Route::Node);
    }
    let refuse = |detail: &str| {
        GygesError::new(ErrorReason::FallbackUnavailable, detail)
            .with_key(key_id)
            .into_status()
    };
    let Some(endpoint) = state.fallback.clone() else {
        return Err(refuse(
            "--via-tor broadcasts through the fallback endpoint's Tor client, and none is configured \
             ([fallback_lightwalletd] enabled = true with a grpc_url); nothing was broadcast",
        ));
    };
    match endpoint.transport() {
        gyges_chain::Transport::Tor { .. } => {}
        gyges_chain::Transport::Direct if state.network == gyges_core::Network::Regtest => {
            tracing::warn!(
                key_id,
                "--via-tor on regtest with fallback_lightwalletd.use_tor = false: broadcasting to the endpoint directly"
            );
        }
        gyges_chain::Transport::Direct => {
            return Err(refuse(
                "--via-tor needs fallback_lightwalletd.use_tor = true; the configured endpoint is reached \
                 directly, which would show it this host's address; nothing was broadcast",
            ));
        }
    }
    Ok(Route::Endpoint(endpoint))
}

/// Broadcast a signed session's transaction over `route`. A failure is
/// recorded on the row (still `Signed`, with the node's text when it gave
/// one) and returned.
pub(crate) async fn broadcast_signed(
    key: &Arc<KeyEntry>,
    chain: &Arc<dyn ChainBackend>,
    route: &Route,
    session_id: &str,
    raw: Vec<u8>,
) -> Result<(), GygesError> {
    let Err(e) = route.send(chain, raw, key.key_id()).await else {
        return Ok(());
    };
    let text = if e.node_error.is_empty() {
        &e.detail
    } else {
        &e.node_error
    };
    let _ = set_session_state(key, session_id, SessionState::Signed, None, Some(text)).await;
    Err(e)
}
