//! gRPC contract between `gyges` (CLI) and `gygesd` (daemon).
//!
//! The source of truth is `proto/gyges.proto`; `API.md` is its human-readable
//! companion. The generated code lives in [`v1`]. Hand-written here, because
//! both sides need them identically:
//!
//! * the API version constants (API.md §2);
//! * [`GygesError`] ⇄ [`tonic::Status`] conversion through
//!   `grpc-status-details-bin` (API.md §3);
//! * the `google.rpc.Status` envelope those details travel in;
//! * [`uds::connect`], the Unix-domain-socket connector (API.md §1.1);
//! * [`v1::Network`] name conversions shared by the CLI flags and the daemon.

#![forbid(unsafe_code)]

use prost::Message;

/// Generated `gyges.v1` package: messages, `gyges_server::Gyges` trait,
/// `gyges_client::GygesClient`, and `serde` implementations for every message
/// (proto3 JSON with proto field names).
#[allow(clippy::all, missing_debug_implementations)]
pub mod v1 {
    tonic::include_proto!("gyges.v1");
    include!(concat!(env!("OUT_DIR"), "/gyges.v1.serde.rs"));
}

/// The `google.rpc.Status` message that carries a [`v1::GygesError`] in the
/// `grpc-status-details-bin` trailer. Hand-written so that the proto tree does
/// not need the googleapis include path.
pub mod google {
    pub mod rpc {
        /// `google.rpc.Status`: the standard rich-error envelope.
        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Status {
            #[prost(int32, tag = "1")]
            pub code: i32,
            #[prost(string, tag = "2")]
            pub message: String,
            #[prost(message, repeated, tag = "3")]
            pub details: Vec<prost_types::Any>,
        }
    }
}

/// API major version. The CLI requires an equal major (OVERVIEW.md Q-O3).
pub const API_MAJOR: u32 = 0;
/// API minor version. A newer daemon minor produces a warning, never an error.
pub const API_MINOR: u32 = 1;

/// `"<major>.<minor>"`, the `schema_version` value in `--json` output.
pub const fn schema_version() -> &'static str {
    // Kept in step with API_MAJOR / API_MINOR by `tests::schema_version_matches`.
    "0.1"
}

/// Type URL of the one detail every failed Gyges RPC carries (API.md §3).
pub const GYGES_ERROR_TYPE_URL: &str = "type.googleapis.com/gyges.v1.GygesError";

impl v1::ErrorReason {
    /// The gRPC status code sent alongside this reason, chosen to make sense
    /// to generic gRPC clients. The CLI never dispatches on it (API.md §3).
    pub fn grpc_code(self) -> tonic::Code {
        use tonic::Code;
        use v1::ErrorReason as R;
        match self {
            R::Unspecified | R::Internal => Code::Internal,
            R::VaultLocked
            | R::SignatureRequired
            | R::ConfirmationRequired
            | R::NotSynced
            | R::Airgapped
            | R::FallbackUnavailable => Code::FailedPrecondition,
            R::SeedExportDisabled | R::PermissionDenied => Code::PermissionDenied,
            R::InvalidPassphrase => Code::Unauthenticated,
            R::RateLimited => Code::ResourceExhausted,
            R::InsufficientFunds => Code::FailedPrecondition,
            R::InvalidArgument
            | R::NetworkMismatch
            | R::KeyMismatch
            | R::UnsupportedPool
            | R::ApiVersionMismatch => Code::InvalidArgument,
            R::KeyNotFound | R::SessionNotFound => Code::NotFound,
            R::KeyExists => Code::AlreadyExists,
            R::NodeUnreachable => Code::Unavailable,
            R::Cancelled => Code::Cancelled,
            R::HardwareSigner => Code::FailedPrecondition,
            R::NodeRejected => Code::Aborted,
        }
    }
}

impl v1::GygesError {
    /// A new error with `reason` and a human-readable `detail` (which must not
    /// contain addresses, amounts, memos or key material).
    pub fn new(reason: v1::ErrorReason, detail: impl Into<String>) -> Self {
        Self {
            reason: reason as i32,
            key_id: String::new(),
            session_id: String::new(),
            detail: detail.into(),
            node_error: String::new(),
        }
    }

    /// Attach the key the error concerns.
    pub fn with_key(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = key_id.into();
        self
    }

    /// Attach the signing session the client can resume or abort.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Encode this error as the single detail of a gRPC status whose code
    /// follows [`v1::ErrorReason::grpc_code`]. (The generated `reason()`
    /// accessor yields `Unspecified` for values this build does not know.)
    pub fn into_status(self) -> tonic::Status {
        let code = self.reason().grpc_code();
        let message = self.detail.clone();
        let any = prost_types::Any {
            type_url: GYGES_ERROR_TYPE_URL.to_string(),
            value: self.encode_to_vec(),
        };
        let envelope = google::rpc::Status {
            code: code as i32,
            message: message.clone(),
            details: vec![any],
        };
        tonic::Status::with_details(code, message, envelope.encode_to_vec().into())
    }

    /// Decode the `GygesError` detail from a failed RPC, if the status carries
    /// one. Statuses produced by tonic itself (transport failures, the
    /// generated `UNIMPLEMENTED` stubs) carry none.
    pub fn from_status(status: &tonic::Status) -> Option<Self> {
        let envelope = google::rpc::Status::decode(status.details()).ok()?;
        envelope
            .details
            .iter()
            .find(|any| any.type_url == GYGES_ERROR_TYPE_URL)
            .and_then(|any| Self::decode(any.value.as_slice()).ok())
    }
}

impl From<v1::GygesError> for tonic::Status {
    fn from(err: v1::GygesError) -> Self {
        err.into_status()
    }
}

impl v1::Network {
    /// The CLI / directory name: `mainnet`, `testnet`, `regtest`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    /// Parse a CLI / directory name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }
}

/// gRPC over a Unix domain socket (API.md §1.1).
pub mod uds {
    use std::path::{Path, PathBuf};

    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Channel, Endpoint, Uri};
    use tower::service_fn;

    /// Open a lazily-connected channel to the daemon socket at `path`.
    ///
    /// The URI is a placeholder: HTTP/2 needs an authority but the connector
    /// ignores it and opens `path`. Connection errors (missing socket, no
    /// listener) surface on the first RPC as `UNAVAILABLE`; callers that need
    /// to distinguish "daemon not running" should probe with
    /// [`probe`] first.
    pub fn connect_lazy(path: impl AsRef<Path>) -> Result<Channel, tonic::transport::Error> {
        let path: PathBuf = path.as_ref().to_path_buf();
        let endpoint = Endpoint::try_from("http://gygesd.invalid")?;
        Ok(
            endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
                let path = path.clone();
                async move { UnixStream::connect(path).await.map(TokioIo::new) }
            })),
        )
    }

    /// Open one connection to the socket and close it again, returning the
    /// `io::Error` the kernel gave (`NotFound` for a missing socket file,
    /// `ConnectionRefused` for a stale one with no listener).
    pub async fn probe(path: impl AsRef<Path>) -> std::io::Result<()> {
        UnixStream::connect(path.as_ref()).await.map(drop)
    }

    /// [`probe`] followed by [`connect_lazy`].
    pub async fn connect(path: impl AsRef<Path>) -> Result<Channel, ConnectError> {
        probe(&path).await.map_err(ConnectError::Io)?;
        connect_lazy(path).map_err(ConnectError::Transport)
    }

    /// Why [`connect`] failed.
    #[derive(Debug)]
    pub enum ConnectError {
        /// The socket could not be opened; see the kind.
        Io(std::io::Error),
        /// The tonic endpoint could not be built (never expected in practice).
        Transport(tonic::transport::Error),
    }

    impl std::fmt::Display for ConnectError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "cannot connect to the daemon socket: {e}"),
                Self::Transport(e) => write!(f, "cannot build the gRPC channel: {e}"),
            }
        }
    }

    impl std::error::Error for ConnectError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Io(e) => Some(e),
                Self::Transport(e) => Some(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::{ErrorReason, GygesError};

    #[test]
    fn schema_version_matches() {
        assert_eq!(schema_version(), format!("{API_MAJOR}.{API_MINOR}"));
    }

    #[test]
    fn error_round_trips_through_status() {
        let err = GygesError::new(ErrorReason::VaultLocked, "key is locked")
            .with_key("main")
            .with_session("abcd");
        let status: tonic::Status = err.clone().into();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "key is locked");
        let decoded = GygesError::from_status(&status).expect("details present");
        assert_eq!(decoded, err);
        assert_eq!(decoded.reason(), ErrorReason::VaultLocked);
    }

    #[test]
    fn plain_status_has_no_gyges_error() {
        let status = tonic::Status::unimplemented("Not yet implemented");
        assert!(GygesError::from_status(&status).is_none());
    }

    #[test]
    fn unknown_reason_decodes_as_unspecified() {
        let err = GygesError {
            reason: 9999,
            ..Default::default()
        };
        assert_eq!(err.reason(), ErrorReason::Unspecified);
    }

    #[test]
    fn json_uses_proto_field_names_and_enum_names() {
        let info = v1::GetInfoResponse {
            network: v1::Network::Regtest as i32,
            daemon_version: "0.1.0".into(),
            api_version: Some(v1::ApiVersion {
                major: API_MAJOR,
                minor: API_MINOR,
            }),
            started_at: 1_700_000_000,
            ..Default::default()
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["network"], "NETWORK_REGTEST");
        assert_eq!(json["api_version"]["minor"], 1);
        // int64 is a JSON string in proto3 JSON.
        assert_eq!(json["started_at"], "1700000000");
        // Unset / default fields are omitted.
        assert!(json.get("airgapped").is_none());
        assert!(json.get("node").is_none());
        let back: v1::GetInfoResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn network_names_round_trip() {
        for n in [
            v1::Network::Mainnet,
            v1::Network::Testnet,
            v1::Network::Regtest,
        ] {
            assert_eq!(v1::Network::from_name(n.name()), Some(n));
        }
        assert_eq!(v1::Network::from_name("mainnet "), None);
    }
}
