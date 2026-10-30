//! The end of every send: the Verifier against what the user approved,
//! then the broadcast. Where a signed transaction goes is the node's
//! `sendrawtransaction`, or the fallback endpoint over Tor for `--via-tor`
//! (docs/security.md §3 row 10).
//!
//! `SendTransaction`, `BroadcastPczt` and `CompleteKeystoneSign` all end
//! here: [`verified`], then the wallet's own record of the transaction
//! (`extract_and_store`, which each caller runs itself because a Keystone
//! completion claims its session row first), then [`broadcast`].

use std::sync::Arc;

use gyges_chain::{ChainBackend, ChainError};
use gyges_core::KeyEntry;
use gyges_core::db::sessions::SessionState;
use gyges_core::tx::{self as core_tx, Expected, TxError};
use gyges_proto::v1::{ErrorReason, GygesError};
use pczt::Pczt;
use tonic::Status;
use zcash_protocol::TxId;

use crate::errors::{broadcast_error, tx_error};
use crate::keys::AUDIT_TARGET;
use crate::service::DaemonState;
use crate::sessions::set_session_state;
use crate::wallet_rpc;

/// The Verifier (Q-K7): `pczt` against the approved proposal, every change
/// output against what the key owns (docs/security.md §6 item 8). Runs under
/// the key's wallet lock, which reading the owner needs. The outer error is
/// the wallet's (the key's typed error); the inner one is the Verifier's
/// refusal, which each caller maps itself (`INVALID_ARGUMENT` for a file or
/// a send, `HARDWARE_SIGNER` for a Keystone's answer).
pub(crate) async fn verified(
    state: &DaemonState,
    key: &Arc<KeyEntry>,
    pczt: Pczt,
    expected: Expected,
) -> Result<Result<Pczt, TxError>, Status> {
    let params = state.registry.params();
    wallet_rpc(key, move |w| {
        let owner = core_tx::Owner::of_wallet(&params, w)?;
        Ok(core_tx::verify(pczt, &expected, &owner))
    })
    .await
}

/// Broadcast `raw` (the transaction `txid`) over `route`, record it on the
/// session row when there is one (a `pczt create` file or a Keystone
/// session), write the audit event and wake the sync scheduler. A failed
/// broadcast leaves the row `Signed` with the node's text (or the error's,
/// when the node gave none) and is returned.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn broadcast(
    state: &DaemonState,
    key: &Arc<KeyEntry>,
    chain: &Arc<dyn ChainBackend>,
    route: &Route,
    raw: Vec<u8>,
    txid: TxId,
    session_id: Option<&str>,
) -> Result<(), GygesError> {
    let key_id = key.key_id();
    if let Err(e) = route.send(chain, raw, key_id).await {
        if let Some(sid) = session_id {
            let text = if e.node_error.is_empty() {
                &e.detail
            } else {
                &e.node_error
            };
            let _ = set_session_state(key, sid, SessionState::Signed, None, Some(text)).await;
        }
        return Err(e);
    }
    if let Some(sid) = session_id {
        set_session_state(
            key,
            sid,
            SessionState::Broadcast,
            Some(*txid.as_ref()),
            None,
        )
        .await
        .map_err(|e| tx_error(e, key_id))?;
    }
    tracing::info!(target: AUDIT_TARGET, key_id, event = "broadcast", via = route.name());
    tracing::info!(
        key_id,
        session_id,
        via = route.name(),
        "transaction broadcast"
    );
    state.sync.wake();
    Ok(())
}

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
/// `broadcast_via_tor` (docs/security.md §3 row 10).
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
/// backfill in CI (docs/testing.md §2).
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
