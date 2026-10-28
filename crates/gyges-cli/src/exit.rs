//! Process exit codes and the one function that chooses them (API.md §3.1,
//! CLI_SPEC.md §1.3).

use std::path::PathBuf;
use std::process::ExitCode;

use gyges_proto::v1::{ErrorReason, GygesError};

/// Exit codes, by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    Ok = 0,
    Failure = 1,
    Usage = 2,
    DaemonUnreachable = 3,
    AuthorizationRequired = 4,
    InsufficientFunds = 5,
    InvalidArgument = 6,
    NotReady = 7,
    Cancelled = 8,
    HardwareSigner = 9,
    NodeRejected = 10,
}

impl From<Exit> for ExitCode {
    fn from(e: Exit) -> Self {
        ExitCode::from(e as u8)
    }
}

/// The only place a `GygesError.reason` becomes an exit code. The match is
/// exhaustive on purpose: a new `ErrorReason` variant fails to compile until
/// it has a row here (TESTING.md §6).
pub fn exit_for_reason(reason: ErrorReason) -> Exit {
    use ErrorReason as R;
    match reason {
        R::Unspecified | R::Internal => Exit::Failure,
        R::VaultLocked
        | R::SignatureRequired
        | R::SeedExportDisabled
        | R::ConfirmationRequired
        | R::InvalidPassphrase
        | R::RateLimited
        | R::PermissionDenied => Exit::AuthorizationRequired,
        R::InsufficientFunds => Exit::InsufficientFunds,
        R::InvalidArgument
        | R::NetworkMismatch
        | R::KeyMismatch
        | R::KeyNotFound
        | R::KeyExists
        | R::SessionNotFound
        | R::UnsupportedPool
        | R::ApiVersionMismatch => Exit::InvalidArgument,
        R::NotSynced | R::NodeUnreachable | R::Airgapped | R::FallbackUnavailable => Exit::NotReady,
        R::Cancelled => Exit::Cancelled,
        R::HardwareSigner => Exit::HardwareSigner,
        R::NodeRejected => Exit::NodeRejected,
    }
}

/// The message printed when the socket is absent or refuses the connection.
pub const NOT_RUNNING: &str = "gygesd is not running; start it with 'gyges daemon start' or install a service with 'gyges daemon install'";

/// Everything that can end a `gyges` invocation unsuccessfully.
#[derive(Debug)]
pub enum CliError {
    /// Exit 3: the socket is missing or nothing listens on it.
    Unreachable {
        socket: PathBuf,
        cause: std::io::Error,
    },
    /// A typed daemon error (or one the CLI synthesised client-side for the
    /// handshake checks); exit code from [`exit_for_reason`].
    Daemon(GygesError),
    /// Exit 1: a gRPC status without a `GygesError` detail (transport
    /// failure, or an RPC the daemon has not implemented).
    Rpc(tonic::Status),
    /// Exit 8: SIGINT during a prompt or stream.
    Cancelled,
    /// Exit 1: a command this build does not implement yet.
    NotImplemented(&'static str),
    /// Exit 1: anything else.
    Other(anyhow::Error),
}

impl CliError {
    /// Classify a failed RPC.
    pub fn from_status(status: tonic::Status) -> Self {
        match GygesError::from_status(&status) {
            Some(err) => CliError::Daemon(err),
            None => CliError::Rpc(status),
        }
    }

    /// Exit 6: a client-side `INVALID_ARGUMENT`.
    pub fn invalid(detail: impl Into<String>) -> Self {
        GygesError::new(ErrorReason::InvalidArgument, detail).into()
    }

    /// Exit 4: a client-side `CONFIRMATION_REQUIRED` (no terminal to ask on).
    pub fn confirmation_required(detail: impl Into<String>) -> Self {
        GygesError::new(ErrorReason::ConfirmationRequired, detail).into()
    }

    pub fn exit(&self) -> Exit {
        match self {
            CliError::Unreachable { .. } => Exit::DaemonUnreachable,
            CliError::Daemon(err) => exit_for_reason(err.reason()),
            CliError::Rpc(_) | CliError::NotImplemented(_) | CliError::Other(_) => Exit::Failure,
            CliError::Cancelled => Exit::Cancelled,
        }
    }

    /// One line for stderr.
    pub fn message(&self) -> String {
        match self {
            CliError::Unreachable { socket, cause } => match cause.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    format!("{NOT_RUNNING} (socket: {})", socket.display())
                }
                _ => format!("cannot connect to {}: {cause}", socket.display()),
            },
            CliError::Daemon(err) => {
                let mut s = err.detail.clone();
                if s.is_empty() {
                    s = format!("{:?}", err.reason());
                }
                if !err.key_id.is_empty() {
                    s = format!("key '{}': {s}", err.key_id);
                }
                if !err.session_id.is_empty() {
                    s = format!("{s} (session {})", err.session_id);
                }
                if !err.node_error.is_empty() {
                    s = format!("{s}: {}", err.node_error);
                }
                s
            }
            CliError::Rpc(status) => {
                format!("daemon returned {:?}: {}", status.code(), status.message())
            }
            CliError::Cancelled => "cancelled".to_string(),
            CliError::NotImplemented(what) => {
                format!("`gyges {what}` is not implemented yet; see ROADMAP.md")
            }
            CliError::Other(e) => format!("{e:#}"),
        }
    }

    /// The `error` object for `--json` output (API.md §3.1): the daemon's
    /// `GygesError` verbatim, or a synthesised one for client-side failures.
    pub fn as_gyges_error(&self) -> GygesError {
        match self {
            CliError::Daemon(err) => err.clone(),
            CliError::Cancelled => GygesError::new(ErrorReason::Cancelled, self.message()),
            CliError::Rpc(status) if status.code() == tonic::Code::Unimplemented => {
                GygesError::new(ErrorReason::Internal, self.message())
            }
            _ => GygesError::new(ErrorReason::Unspecified, self.message()),
        }
    }
}

impl From<tonic::Status> for CliError {
    fn from(status: tonic::Status) -> Self {
        Self::from_status(status)
    }
}

impl From<GygesError> for CliError {
    fn from(err: GygesError) -> Self {
        CliError::Daemon(err)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(e: anyhow::Error) -> Self {
        CliError::Other(e)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Other(e.into())
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Other(e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table from API.md §3.1; the exhaustive `match` in `exit_for_reason`
    /// is what catches a new variant, this test catches a wrong row.
    #[test]
    fn exit_codes_match_api_md() {
        use ErrorReason as R;
        let rows = [
            (R::Unspecified, 1),
            (R::Internal, 1),
            (R::VaultLocked, 4),
            (R::SignatureRequired, 4),
            (R::SeedExportDisabled, 4),
            (R::ConfirmationRequired, 4),
            (R::InvalidPassphrase, 4),
            (R::RateLimited, 4),
            (R::PermissionDenied, 4),
            (R::InsufficientFunds, 5),
            (R::InvalidArgument, 6),
            (R::NetworkMismatch, 6),
            (R::KeyMismatch, 6),
            (R::KeyNotFound, 6),
            (R::KeyExists, 6),
            (R::SessionNotFound, 6),
            (R::UnsupportedPool, 6),
            (R::ApiVersionMismatch, 6),
            (R::NotSynced, 7),
            (R::NodeUnreachable, 7),
            (R::Airgapped, 7),
            (R::FallbackUnavailable, 7),
            (R::Cancelled, 8),
            (R::HardwareSigner, 9),
            (R::NodeRejected, 10),
        ];
        for (reason, code) in rows {
            assert_eq!(exit_for_reason(reason) as u8, code, "{reason:?}");
        }
        // Every value the proto defines has a row above.
        let mut n = 0;
        while ErrorReason::try_from(n).is_ok() {
            n += 1;
        }
        assert_eq!(
            n as usize,
            rows.len(),
            "ErrorReason has {n} values but the table has {}",
            rows.len()
        );
    }

    #[test]
    fn client_side_errors_pick_their_codes() {
        let e = CliError::Unreachable {
            socket: "/tmp/x.sock".into(),
            cause: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert_eq!(e.exit(), Exit::DaemonUnreachable);
        assert!(e.message().starts_with(NOT_RUNNING));
        assert_eq!(
            CliError::Rpc(tonic::Status::unimplemented("x")).exit(),
            Exit::Failure
        );
        assert_eq!(CliError::Cancelled.exit(), Exit::Cancelled);
        assert_eq!(
            CliError::Daemon(GygesError::new(ErrorReason::NetworkMismatch, "")).exit(),
            Exit::InvalidArgument
        );
    }
}
