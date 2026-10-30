//! Socket resolution, connection and the `GetInfo` handshake (docs/interface.md API §1).

use std::path::PathBuf;

use gyges_proto::v1::gyges_client::GygesClient;
use gyges_proto::v1::{ErrorReason, GetInfoRequest, GetInfoResponse, GygesError, Network};
use gyges_proto::{API_MAJOR, API_MINOR, uds};
use tonic::transport::Channel;

use crate::Global;
use crate::exit::CliError;
use crate::prompt::Prompter;

/// The global options, resolved.
#[derive(Clone, Debug)]
pub struct Ctx {
    pub socket: PathBuf,
    /// Given explicitly (flag or `GYGES_NETWORK`); checked against the daemon.
    pub network: Option<Network>,
    /// `--key` / `GYGES_KEY`, passed through verbatim; empty means the
    /// daemon's default (docs/interface.md API §1.4).
    pub key: String,
    pub json: bool,
    pub quiet: bool,
    pub prompter: Prompter,
}

/// A connected, handshaken client.
#[derive(Debug)]
pub struct Conn {
    pub client: GygesClient<Channel>,
    pub info: GetInfoResponse,
}

impl Ctx {
    /// `--json`: `value` as one JSON line on stdout; otherwise `human()`
    /// printed to stdout as is.
    pub fn print<T: serde::Serialize>(
        &self,
        value: &T,
        human: impl FnOnce() -> String,
    ) -> Result<(), CliError> {
        if self.json {
            println!("{}", crate::output::to_json(value)?);
        } else {
            print!("{}", human());
        }
        Ok(())
    }

    /// `--json`: `value` as one JSON line on stdout; otherwise `note()`
    /// (a human note, usually on stderr), unless `-q`.
    pub fn report<T: serde::Serialize>(
        &self,
        value: &T,
        note: impl FnOnce(),
    ) -> Result<(), CliError> {
        if self.json {
            println!("{}", crate::output::to_json(value)?);
        } else if !self.quiet {
            note();
        }
        Ok(())
    }

    /// The next item of a server stream; `CliError::Cancelled` on Ctrl-C.
    pub async fn next_or_cancel<T>(
        stream: &mut tonic::Streaming<T>,
    ) -> Result<Option<T>, CliError> {
        tokio::select! {
            r = stream.message() => Ok(r?),
            _ = tokio::signal::ctrl_c() => Err(CliError::Cancelled),
        }
    }

    /// A human note on stderr, unless `--json` or `-q`.
    pub fn note(&self, msg: impl std::fmt::Display) {
        if !self.quiet && !self.json {
            eprintln!("{msg}");
        }
    }

    pub fn new(g: Global) -> Result<Self, CliError> {
        let socket = match g.socket {
            Some(p) => p,
            None => default_socket(g.network.unwrap_or(Network::Mainnet))?,
        };
        Ok(Self {
            socket,
            network: g.network,
            key: g.key.unwrap_or_default(),
            json: g.json,
            quiet: g.quiet,
            prompter: Prompter {
                non_interactive: g.non_interactive,
                passphrase_fd: g.passphrase_fd,
            },
        })
    }

    /// The network the daemon is asked to serve by `daemon start`.
    pub fn network_name(&self) -> &'static str {
        self.network.unwrap_or(Network::Mainnet).name()
    }

    /// Connect and run the handshake checks of docs/interface.md API §1.3.
    pub async fn connect(&self) -> Result<Conn, CliError> {
        let channel = match uds::connect(&self.socket).await {
            Ok(c) => c,
            Err(uds::ConnectError::Io(cause)) => {
                return Err(CliError::Unreachable {
                    socket: self.socket.clone(),
                    cause,
                });
            }
            Err(e) => return Err(CliError::Other(e.into())),
        };
        let mut client = GygesClient::new(channel);
        let info = client.get_info(GetInfoRequest {}).await?.into_inner();
        check_handshake(&info, self.network, self.quiet)?;
        Ok(Conn { client, info })
    }
}

/// API version and network checks; the warning for a newer daemon minor goes
/// to stderr once per invocation.
pub fn check_handshake(
    info: &GetInfoResponse,
    expected: Option<Network>,
    quiet: bool,
) -> Result<(), CliError> {
    let api = info.api_version.unwrap_or_default();
    if api.major != API_MAJOR {
        return Err(CliError::Daemon(GygesError::new(
            ErrorReason::ApiVersionMismatch,
            format!(
                "gygesd speaks API {}.{} but this gyges speaks {API_MAJOR}.{API_MINOR}; \
                 install matching versions of gyges and gygesd",
                api.major, api.minor
            ),
        )));
    }
    if api.minor > API_MINOR && !quiet {
        eprintln!(
            "warning: gygesd API {}.{} is newer than this gyges ({API_MAJOR}.{API_MINOR}); \
             some features may be unavailable",
            api.major, api.minor
        );
    }
    if let Some(want) = expected {
        let have = info.network();
        if have != want {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::NetworkMismatch,
                format!(
                    "the daemon serves {} but this command asked for {}",
                    have.name(),
                    want.name()
                ),
            )));
        }
    }
    Ok(())
}

/// `$GYGES_HOME`, else `~/.gyges` (docs/architecture.md Data model §1). Duplicated from
/// `gyges-core` on purpose: the CLI must not link the wallet stack.
pub fn gyges_home() -> Result<PathBuf, CliError> {
    match std::env::var_os("GYGES_HOME") {
        Some(dir) if !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => std::env::home_dir()
            .map(|h| h.join(".gyges"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot determine the home directory; set GYGES_HOME or pass --socket"
                )
                .into()
            }),
    }
}

/// `$GYGES_HOME/<network>/gygesd.sock`.
pub fn default_socket(network: Network) -> Result<PathBuf, CliError> {
    Ok(gyges_home()?.join(network.name()).join("gygesd.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_proto::v1::ApiVersion;

    fn info(major: u32, minor: u32, network: Network) -> GetInfoResponse {
        GetInfoResponse {
            api_version: Some(ApiVersion { major, minor }),
            network: network as i32,
            ..Default::default()
        }
    }

    #[test]
    fn major_mismatch_is_exit_6() {
        let err =
            check_handshake(&info(API_MAJOR + 1, 0, Network::Mainnet), None, true).unwrap_err();
        assert_eq!(err.exit(), crate::exit::Exit::InvalidArgument);
        assert_eq!(
            err.as_gyges_error().reason(),
            ErrorReason::ApiVersionMismatch
        );
    }

    #[test]
    fn newer_minor_is_accepted() {
        check_handshake(
            &info(API_MAJOR, API_MINOR + 1, Network::Mainnet),
            None,
            true,
        )
        .unwrap();
    }

    #[test]
    fn network_checked_only_when_given() {
        let i = info(API_MAJOR, API_MINOR, Network::Regtest);
        check_handshake(&i, None, true).unwrap();
        check_handshake(&i, Some(Network::Regtest), true).unwrap();
        let err = check_handshake(&i, Some(Network::Testnet), true).unwrap_err();
        assert_eq!(err.as_gyges_error().reason(), ErrorReason::NetworkMismatch);
        assert!(err.message().contains("regtest") && err.message().contains("testnet"));
    }

    #[test]
    fn socket_path_follows_gyges_home() {
        // Only the shape is asserted; the environment is not modified.
        let p = default_socket(Network::Testnet).unwrap();
        assert!(p.ends_with("testnet/gygesd.sock"), "{}", p.display());
    }
}
