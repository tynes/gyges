//! Connection and RPC admission (API.md §1.2 peer credentials, §8 air-gapped
//! allow-list).
//!
//! Two gates, in order:
//!
//! 1. [`PeerPolicy::admit`] runs in the accept loop on every connection. A
//!    peer whose uid is neither the daemon's own nor in
//!    `daemon.allowed_uids` is dropped before any byte of HTTP/2 is read.
//! 2. [`PolicyLayer`] wraps the tonic router. It re-checks the uid from the
//!    connection info (defence in depth; a request that somehow arrives from
//!    a foreign uid gets `PERMISSION_DENIED`) and, when the daemon runs
//!    `--airgapped`, answers every RPC outside the allow-list with
//!    `AIRGAPPED` before the handler runs.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use gyges_proto::v1::{ErrorReason, GygesError};
use http::{Request, Response};
use tokio::net::UnixStream;
use tonic::body::Body;
use tower::{Layer, Service};

use crate::conn::ConnInfo;

/// Who may connect to the socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPolicy {
    daemon_uid: u32,
    allowed_uids: Vec<u32>,
}

/// Why a connection was dropped at accept time.
#[derive(Debug, thiserror::Error)]
pub enum PeerRejected {
    #[error("peer uid {0} is not the daemon's uid and not in daemon.allowed_uids")]
    Uid(u32),
    #[error("peer credentials unavailable: {0}")]
    Unavailable(std::io::Error),
}

impl PeerPolicy {
    /// `daemon_uid` is always allowed; `allowed_uids` is `daemon.allowed_uids`.
    pub fn new(daemon_uid: u32, allowed_uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            daemon_uid,
            allowed_uids: allowed_uids.into_iter().collect(),
        }
    }

    pub fn allows(&self, uid: u32) -> bool {
        uid == self.daemon_uid || self.allowed_uids.contains(&uid)
    }

    /// Read the peer's credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`
    /// on macOS, via tokio) and decide. Returns the admitted uid, which
    /// [`crate::conn::Conn`] carries into every request.
    pub fn admit(&self, stream: &UnixStream) -> Result<u32, PeerRejected> {
        let cred = stream.peer_cred().map_err(PeerRejected::Unavailable)?;
        let uid = cred.uid();
        if self.allows(uid) {
            Ok(uid)
        } else {
            Err(PeerRejected::Uid(uid))
        }
    }
}

/// Method names (without the `/gyges.v1.Gyges/` prefix) served when the
/// daemon runs `--airgapped` (API.md §8). `Shutdown` is included so that an
/// air-gapped daemon can be stopped over the socket; it touches no network.
pub const AIRGAPPED_METHODS: &[&str] = &[
    "GetInfo",
    "Shutdown",
    "StreamLogs",
    "ListKeys",
    "InitKey",
    "UnlockKey",
    "LockKey",
    "ExportSeed",
    "ExportUfvk",
    "DeleteKey",
    "BackupKey",
    "ImportBackup",
    "InspectPczt",
    "ProvePczt",
    "SignPczt",
    "CombinePczt",
    "ListSigningSessions",
    "AbortSigningSession",
    "CompleteKeystoneSign",
];

/// The `/gyges.v1.Gyges/` prefix of every Gyges RPC path.
fn service_prefix() -> String {
    format!("/{}/", gyges_proto::v1::gyges_server::SERVICE_NAME)
}

/// Whether an HTTP/2 request path may be served while air-gapped. Paths that
/// do not belong to the Gyges service are left to tonic (`UNIMPLEMENTED`).
pub fn allowed_when_airgapped(path: &str) -> bool {
    match path.strip_prefix(service_prefix().as_str()) {
        Some(method) => AIRGAPPED_METHODS.contains(&method),
        None => true,
    }
}

/// Tower layer applying [`PeerPolicy`] and the air-gapped allow-list.
#[derive(Clone, Debug)]
pub struct PolicyLayer {
    peer: PeerPolicy,
    airgapped: bool,
}

impl PolicyLayer {
    pub fn new(peer: PeerPolicy, airgapped: bool) -> Self {
        Self { peer, airgapped }
    }
}

impl<S> Layer<S> for PolicyLayer {
    type Service = Policy<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Policy {
            inner,
            peer: self.peer.clone(),
            airgapped: self.airgapped,
        }
    }
}

/// The service produced by [`PolicyLayer`].
#[derive(Clone, Debug)]
pub struct Policy<S> {
    inner: S,
    peer: PeerPolicy,
    airgapped: bool,
}

impl<S> Policy<S> {
    /// The error to answer with instead of routing, if any.
    fn refuse<B>(&self, req: &Request<B>) -> Option<GygesError> {
        if let Some(info) = req.extensions().get::<ConnInfo>() {
            match info.uid {
                Some(uid) if self.peer.allows(uid) => {}
                Some(uid) => {
                    return Some(GygesError::new(
                        ErrorReason::PermissionDenied,
                        format!("uid {uid} may not use this daemon"),
                    ));
                }
                None => {
                    return Some(GygesError::new(
                        ErrorReason::PermissionDenied,
                        "peer credentials unavailable on this connection",
                    ));
                }
            }
        }
        if self.airgapped && !allowed_when_airgapped(req.uri().path()) {
            return Some(GygesError::new(
                ErrorReason::Airgapped,
                "this daemon runs --airgapped; the operation needs the network",
            ));
        }
        None
    }
}

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

impl<S, B> Service<Request<B>> for Policy<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        if let Some(err) = self.refuse(&req) {
            tracing::warn!(path = req.uri().path(), reason = ?err.reason(), "request refused");
            let status = err.into_status();
            return Box::pin(async move { Ok(status.into_http()) });
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_policy_allows_own_uid_and_listed_uids_only() {
        let p = PeerPolicy::new(501, [1000, 1001]);
        assert!(p.allows(501));
        assert!(p.allows(1000));
        assert!(p.allows(1001));
        assert!(!p.allows(0));
        assert!(!p.allows(502));
    }

    #[test]
    fn airgapped_allow_list_matches_api_md_section_8() {
        for m in [
            "GetInfo",
            "Shutdown",
            "ListKeys",
            "SignPczt",
            "StreamLogs",
            "CompleteKeystoneSign",
        ] {
            assert!(
                allowed_when_airgapped(&format!("/gyges.v1.Gyges/{m}")),
                "{m}"
            );
        }
        for m in [
            "GetBalance",
            "SendTransaction",
            "ShieldFunds",
            "RunSync",
            "WaitSync",
            "GetSyncStatus",
            "ScanMempool",
            "GetCurrentAddress",
            "NewAddress",
            "InspectAddress",
            "ListNotes",
            "ListTransactions",
            "GetTransactionStatus",
            "ResumeTexTransfer",
            "AbortTexTransfer",
            "RestoreKey",
            "ImportKeystone",
            "ImportUfvk",
            "CreatePczt",
            "BroadcastPczt",
        ] {
            assert!(
                !allowed_when_airgapped(&format!("/gyges.v1.Gyges/{m}")),
                "{m}"
            );
        }
        // Foreign services are not this layer's business.
        assert!(allowed_when_airgapped("/grpc.health.v1.Health/Check"));
    }

    /// THREAT_MODEL.md §5, first row: the tower layer refuses a request
    /// whose connection carries a foreign uid, or none, before it reaches a
    /// handler, and applies the air-gapped allow-list to the rest. Stands in
    /// for the accept-loop check that CI cannot run as a second user.
    #[tokio::test]
    async fn the_layer_refuses_foreign_uids_and_airgapped_methods_before_routing() {
        use gyges_core::vault::manager::ConnId;
        use tower::ServiceExt as _;

        async fn call(airgapped: bool, uid: Option<u32>, method: &str) -> Response<Body> {
            let inner = tower::service_fn(|_req: Request<()>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
            });
            let mut svc = PolicyLayer::new(PeerPolicy::new(501, [1000]), airgapped).layer(inner);
            let mut req = Request::builder()
                .uri(format!("/gyges.v1.Gyges/{method}"))
                .body(())
                .unwrap();
            req.extensions_mut().insert(ConnInfo { id: ConnId(1), uid });
            svc.ready().await.unwrap().call(req).await.unwrap()
        }
        fn grpc_status(resp: &Response<Body>) -> Option<i32> {
            resp.headers()
                .get("grpc-status")
                .map(|v| v.to_str().unwrap().parse().unwrap())
        }
        let denied = tonic::Code::PermissionDenied as i32;
        let airgapped = GygesError::new(ErrorReason::Airgapped, "")
            .into_status()
            .code() as i32;

        // (air-gapped, peer uid, method, grpc-status). `None`: the inner
        // service answered.
        let cases = [
            // Own and listed uids reach the handler.
            (false, Some(501), "GetBalance", None),
            (false, Some(1000), "GetBalance", None),
            // A foreign uid, or no credentials, never does.
            (false, Some(502), "GetInfo", Some(denied)),
            (false, Some(0), "GetInfo", Some(denied)),
            (false, None, "GetInfo", Some(denied)),
            // Air-gapped: the allow-list applies after the uid check.
            (true, Some(501), "GetInfo", None),
            (true, Some(501), "GetBalance", Some(airgapped)),
            (true, Some(502), "GetInfo", Some(denied)),
        ];
        for (airgapped, uid, method, want) in cases {
            let got = grpc_status(&call(airgapped, uid, method).await);
            assert_eq!(got, want, "airgapped={airgapped} uid={uid:?} {method}");
        }
    }

    #[test]
    fn every_allow_listed_method_exists_in_the_proto() {
        let proto = include_str!("../../../proto/gyges.proto");
        for m in AIRGAPPED_METHODS {
            assert!(
                proto.contains(&format!("rpc {m}(")),
                "{m} is not an RPC in gyges.proto"
            );
        }
    }
}
