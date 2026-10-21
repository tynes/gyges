//! `gygesd` – the Gyges wallet daemon (ARCHITECTURE.md §3.6).
//!
//! The binary in `main.rs` is a thin wrapper: it parses flags, daemonises,
//! installs logging and signal handlers, and calls [`Daemon::prepare`] then
//! [`Daemon::serve`]. Everything else lives here so that integration tests
//! can run a daemon in-process against a temporary `GYGES_HOME`.
//!
//! Startup order (each step refuses to continue on failure, naming the fix):
//!
//! 1. create `$GYGES_HOME/<network>/` (0700) and sweep its permissions
//!    (DATA_MODEL.md §1, Q-S7);
//! 2. load `config.toml`, apply the command-line overrides, validate;
//! 3. take the advisory lock on `gygesd.pid`;
//! 4. load every `keys/<id>/` profile and open its wallet database
//!    (`KeyRegistry`), refusing on a broken or too-wide key directory;
//! 5. unless air-gapped, build the node backend (`ZakuraRpcBackend`, which
//!    contacts nothing yet) and open the shared block cache
//!    (`cache/blocks.sqlite`), refusing a cache from another network;
//! 6. poll the node once (bounded), bind `gygesd.sock`, set its mode, serve
//!    until a shutdown signal; checkpoint the cache on the way out.

#![forbid(unsafe_code)]

pub mod conn;
pub mod keys;
pub mod lifecycle;
pub mod logs;
pub mod node;
pub mod policy;
pub mod service;
pub mod sync;
pub mod tx;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use gyges_chain::{BlockDb, ChainBackend, ZakuraRpcBackend};
use gyges_core::{Config, Home, KeyRegistry, Network, VaultManager, perms};
use gyges_proto::v1::gyges_server::GygesServer;
use tokio::net::UnixListener;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

pub use conn::{Conn, ConnInfo};
pub use lifecycle::{PidLock, PidLockError};
pub use logs::LogHub;
pub use policy::{PeerPolicy, PolicyLayer};
pub use service::{DaemonState, GygesService};

/// What the command line decided (CLI_SPEC.md §2.1 `gyges daemon start`).
#[derive(Clone, Debug)]
pub struct Options {
    pub home: Home,
    pub network: Network,
    /// `--airgapped`: forces `config.airgapped = true`.
    pub airgapped: bool,
    /// `--zakura-rpc URL`.
    pub zakura_rpc: Option<String>,
    /// `--zakura-cookie PATH`.
    pub zakura_cookie: Option<String>,
    /// `--fallback-lwd GRPC_URL`: enables the fallback with this endpoint.
    pub fallback_lwd: Option<String>,
    /// `--no-tor`.
    pub no_tor: bool,
    /// The node backend. `None` means "build a `ZakuraRpcBackend` from the
    /// configuration" (or nothing, when air-gapped); tests inject a fake.
    pub chain: Option<Arc<dyn ChainBackend>>,
    /// The in-memory log tail `StreamLogs` serves. `main` creates it before
    /// installing the subscriber; `None` means an empty hub that nothing
    /// feeds (tests that install no capture layer).
    pub log_hub: Option<Arc<LogHub>>,
}

impl Options {
    pub fn new(home: Home, network: Network) -> Self {
        Self {
            home,
            network,
            airgapped: false,
            zakura_rpc: None,
            zakura_cookie: None,
            fallback_lwd: None,
            no_tor: false,
            chain: None,
            log_hub: None,
        }
    }

    /// Apply the command-line overrides to a loaded configuration
    /// ("override the corresponding keys for that process only").
    pub fn apply_to(&self, config: &mut Config) {
        if self.airgapped {
            config.airgapped = true;
        }
        if let Some(url) = &self.zakura_rpc {
            config.zakura_rpc.url = url.clone();
        }
        if let Some(path) = &self.zakura_cookie {
            config.zakura_rpc.cookie_path = path.clone();
        }
        if let Some(url) = &self.fallback_lwd {
            config.fallback_lightwalletd.enabled = true;
            config.fallback_lightwalletd.grpc_url = url.clone();
        }
        if self.no_tor {
            config.fallback_lightwalletd.use_tor = false;
        }
    }
}

/// A daemon that has passed every startup check and holds the pid lock, but
/// is not yet listening.
#[derive(Debug)]
pub struct Daemon {
    pub home: Home,
    pub network: Network,
    pub state: Arc<DaemonState>,
    _pid: PidLock,
}

impl Daemon {
    /// Steps 1–3 of the startup order. Synchronous so that the daemoniser in
    /// `main` can run it before forking and report problems on its own stderr.
    pub fn prepare(opts: Options) -> anyhow::Result<Self> {
        let home = opts.home.clone();
        let network = opts.network;
        let dir = home.network_dir(network);

        perms::ensure_private_dir(home.root())?;
        perms::ensure_private_dir(&dir)?;
        perms::check_tree(&dir).context("refusing to start on unsafe permissions")?;
        for sub in [
            home.keys_dir(network),
            home.cache_dir(network),
            home.logs_dir(network),
        ] {
            perms::ensure_private_dir(&sub)?;
        }

        let config_path = home.config_path(network);
        let mut config = Config::load(&config_path)?;
        opts.apply_to(&mut config);
        config
            .validate(network)
            .with_context(|| format!("invalid configuration in {}", config_path.display()))?;

        let pid = PidLock::acquire(&home.pid_path(network))?;
        // Only after the lock: opening the wallet databases runs their
        // migrations, which must not race a running daemon.
        let registry = KeyRegistry::open(home.clone(), network, &config)
            .context("refusing to start: a key directory is unusable")?;
        let vault = VaultManager::new(&config.vault);
        let chain: Option<Arc<dyn ChainBackend>> = match opts.chain {
            Some(injected) => Some(injected),
            None if config.airgapped => None,
            None => Some(Arc::new(
                ZakuraRpcBackend::new(
                    config.zakura_rpc.url.clone(),
                    config.zakura_cookie_path(),
                    network.consensus_params(),
                )
                .context("cannot set up the node backend")?,
            )),
        };
        let block_cache = if config.airgapped {
            None
        } else {
            let path = home.block_cache_path(network);
            Some(Arc::new(
                BlockDb::open(&path, network.name())
                    .with_context(|| format!("cannot open the block cache {}", path.display()))?,
            ))
        };
        let state = Arc::new(DaemonState::new(
            config,
            network,
            registry,
            vault,
            chain,
            block_cache,
            opts.log_hub.unwrap_or_default(),
        ));
        Ok(Self {
            home,
            network,
            state,
            _pid: pid,
        })
    }

    pub fn config(&self) -> &Config {
        &self.state.config
    }

    pub fn socket_path(&self) -> PathBuf {
        self.home.socket_path(self.network)
    }

    /// Step 5: bind the socket and serve until `shutdown` resolves or the
    /// `Shutdown` RPC is called. Removes the socket file afterwards; the pid
    /// file goes when `self` is dropped.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
        let socket = self.socket_path();
        let cfg = &self.state.config;
        let peer = PeerPolicy::new(
            nix::unistd::getuid().as_raw(),
            cfg.daemon.allowed_uids.iter().copied(),
        );

        let listener = bind(&socket, &cfg.daemon.socket_group)?;
        let incoming = UnixListenerStream::new(listener).filter_map({
            let peer = peer.clone();
            let vault = self.state.vault.clone();
            move |item| match item {
                Ok(stream) => match peer.admit(&stream) {
                    Ok(uid) => {
                        let conn = Conn::new(stream, Some(uid), vault.clone());
                        tracing::debug!(uid, conn = conn.info().id.0, "connection accepted");
                        Some(Ok(conn))
                    }
                    Err(reason) => {
                        tracing::warn!(%reason, "connection rejected");
                        None
                    }
                },
                // Accept errors are passed through so tonic logs them.
                Err(e) => Some(Err(e)),
            }
        });

        // Idle unlocks are also evicted lazily on every use; the sweep bounds
        // how long expired entropy can sit in memory untouched.
        let sweeper = tokio::spawn({
            let vault = self.state.vault.clone();
            async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    vault.evict_expired();
                }
            }
        });

        // Ask the node once before accepting clients, so that the `daemon
        // status` a user runs right after `daemon start` reflects it; then
        // hand the polling to the sync scheduler, which keeps every key at
        // the tip (SYNC.md §1, §3).
        let scheduler = match (&self.state.chain, &self.state.block_cache) {
            (Some(chain), Some(cache)) => {
                let link = node::Link::default();
                let _ = tokio::time::timeout(
                    node::FIRST_POLL_TIMEOUT,
                    node::poll_once(&self.state, chain.as_ref(), &link),
                )
                .await;
                Some(sync::spawn(
                    self.state.clone(),
                    chain.clone(),
                    cache.clone(),
                    link,
                ))
            }
            _ => None,
        };

        tracing::info!(
            network = %self.network,
            socket = %socket.display(),
            airgapped = cfg.airgapped,
            version = env!("CARGO_PKG_VERSION"),
            "gygesd listening"
        );

        let state = self.state.clone();
        let signal = async move {
            tokio::select! {
                () = state.shutdown.notified() => {}
                () = shutdown => {}
            }
            tracing::info!("shutting down");
        };

        let result = Server::builder()
            .layer(PolicyLayer::new(peer, cfg.airgapped))
            .add_service(GygesServer::new(GygesService::new(self.state.clone())))
            .serve_with_incoming_shutdown(incoming, signal)
            .await
            .context("gRPC server failed");

        // The listener is closed; unlink its file first so that a `daemon
        // stop` waiting on it returns while the rest of the shutdown runs.
        if let Err(e) = std::fs::remove_file(&socket)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, "could not remove socket file");
        }
        sweeper.abort();
        // Cancel at the next batch boundary: `scan_cached_blocks` commits per
        // batch, so no partial batch is ever visible (SYNC.md §8 step 1).
        if let Some(s) = scheduler {
            s.abort();
        }
        // Zeroize every decrypted key before the process goes away
        // (CLI_SPEC.md §2.1 `daemon stop`).
        let locked = self.state.vault.lock_all();
        if !locked.is_empty() {
            tracing::info!(keys = locked.len(), "keys zeroized on stop");
        }
        // SYNC.md §8 step 3: leave the cache without a WAL to replay.
        if let Some(cache) = &self.state.block_cache
            && let Err(e) = cache.checkpoint()
        {
            tracing::warn!(error = %e, "block cache checkpoint failed");
        }
        tracing::info!("gygesd stopped");
        result
    }
}

/// Bind the listener and apply the socket mode: `0600`, or `0660` owned by
/// `socket_group` when that is set (API.md §1.1, DATA_MODEL.md §1).
fn bind(socket: &Path, socket_group: &str) -> anyhow::Result<UnixListener> {
    // We hold the pid lock, so an existing socket file is stale.
    match std::fs::remove_file(socket) {
        Ok(()) => tracing::info!(socket = %socket.display(), "removed stale socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot remove {}", socket.display())),
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("cannot bind {}", socket.display()))?;
    if socket_group.is_empty() {
        perms::set_mode(socket, 0o600)?;
    } else {
        let gid = resolve_group(socket_group)?;
        std::os::unix::fs::chown(socket, None, Some(gid))
            .with_context(|| format!("cannot chgrp {} to {socket_group}", socket.display()))?;
        perms::set_mode(socket, 0o660)?;
    }
    Ok(listener)
}

/// `daemon.socket_group` is a group name or a numeric gid.
fn resolve_group(name: &str) -> anyhow::Result<u32> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    match nix::unistd::Group::from_name(name) {
        Ok(Some(group)) => Ok(group.gid.as_raw()),
        Ok(None) => anyhow::bail!("daemon.socket_group = \"{name}\" is not a group on this system"),
        Err(e) => Err(e).with_context(|| format!("cannot look up group {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_only_touch_what_was_given() {
        let home = Home::new("/nonexistent");
        let mut opts = Options::new(home, Network::Regtest);
        let mut cfg = Config::default();
        opts.apply_to(&mut cfg);
        assert_eq!(cfg, Config::default());

        opts.airgapped = true;
        opts.zakura_rpc = Some("http://127.0.0.1:18232".into());
        opts.fallback_lwd = Some("http://127.0.0.1:9067".into());
        opts.no_tor = true;
        opts.apply_to(&mut cfg);
        assert!(cfg.airgapped);
        assert_eq!(cfg.zakura_rpc.url, "http://127.0.0.1:18232");
        assert!(cfg.fallback_lightwalletd.enabled);
        assert_eq!(cfg.fallback_lightwalletd.grpc_url, "http://127.0.0.1:9067");
        assert!(!cfg.fallback_lightwalletd.use_tor);
    }

    #[test]
    fn numeric_group_needs_no_lookup() {
        assert_eq!(resolve_group("20").unwrap(), 20);
        assert!(resolve_group("no-such-group-gyges-test").is_err());
    }
}
