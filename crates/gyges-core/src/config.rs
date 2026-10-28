//! `config.toml` (DATA_MODEL.md §2).
//!
//! Every key is optional and defaults to the value shown in the DATA_MODEL.md
//! example; unknown keys are an error so a typo cannot silently fall back to a
//! default. Durations are `humantime` strings (`60s`, `5m`, `24h`). The CLI
//! never reads this file (OVERVIEW.md Q-C1).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::network::Network;

/// The whole daemon configuration.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Must match the directory the file lives in when set; omitted means
    /// "the directory's network".
    pub network: Option<Network>,
    /// Substituted by the daemon when a request has an empty `key_id`; empty
    /// means "no default, pass --key".
    pub default_key: String,
    /// Disables every network interface (Tor, RPC, indexer); PCZT proving and
    /// signing only (API.md §8).
    pub airgapped: bool,
    pub daemon: DaemonConfig,
    pub zakura_rpc: ZakuraRpcConfig,
    pub fallback_lightwalletd: FallbackConfig,
    pub vault: VaultConfig,
    pub cache: CacheConfig,
    pub mempool: MempoolConfig,
    pub tex: TexConfig,
    pub policy: PolicyConfig,
}

/// `[daemon]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    /// Non-empty: socket mode 0660 owned by this group (name or numeric gid).
    pub socket_group: String,
    /// Peer uids other than the daemon's own that may connect (API.md §1.2).
    pub allowed_uids: Vec<u32>,
    /// `tracing` filter; overridden by `RUST_LOG`.
    pub log_level: String,
    /// Node unreachable longer than this -> `Stalled(NodeUnreachable)`.
    #[serde(with = "humantime_serde")]
    pub offline_grace: Duration,
    /// Bound on how long `Shutdown { graceful: true }` waits for in-flight
    /// proving and ZIP 320 step-2 broadcasts.
    #[serde(with = "humantime_serde")]
    pub shutdown_grace: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_group: String::new(),
            allowed_uids: Vec::new(),
            log_level: "info".into(),
            offline_grace: Duration::from_secs(120),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// `[zakura_rpc]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZakuraRpcConfig {
    pub url: String,
    /// HTTP Basic from the cookie; `""` for an unauthenticated listener.
    pub cookie_path: String,
    /// gRPC indexer (`zakurad [rpc] indexer_listen_addr`); `""` = poll JSON-RPC.
    pub indexer_url: String,
    pub poll_interval_secs: u32,
    /// Warn at startup if the node retains fewer blocks than this.
    pub min_retention_blocks: u32,
}

impl Default for ZakuraRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8232".into(),
            cookie_path: "~/.cache/zakura/.cookie".into(),
            indexer_url: String::new(),
            poll_interval_secs: 15,
            min_retention_blocks: 10_000,
        }
    }
}

/// `[fallback_lightwalletd]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FallbackConfig {
    pub enabled: bool,
    /// Required when enabled. No default: the operator is chosen deliberately
    /// (OVERVIEW.md Q-D5).
    pub grpc_url: String,
    /// `false` only for regtest / CI.
    pub use_tor: bool,
    /// `tx send --via-tor` default.
    pub broadcast_via_tor: bool,
    /// `k` in SYNC.md §5.
    pub overlap_blocks: u32,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            grpc_url: String::new(),
            use_tor: true,
            broadcast_via_tor: false,
            overlap_blocks: 10,
        }
    }
}

/// `[vault]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    /// Idle timer for `gyges key unlock`; single source of truth.
    #[serde(with = "humantime_serde")]
    pub unlock_ttl: Duration,
    /// Persisted Keystone / non-interactive sessions.
    #[serde(with = "humantime_serde")]
    pub signing_session_ttl: Duration,
    /// `false` disables `ExportSeed` entirely.
    pub allow_seed_export: bool,
    /// Exponential back-off cap on failed unlocks, per key.
    #[serde(with = "humantime_serde")]
    pub unlock_backoff_max: Duration,
    /// log2(N) for age passphrase recipients; ~1 s on a 2024 laptop.
    pub scrypt_work_factor: u8,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            unlock_ttl: Duration::from_secs(5 * 60),
            signing_session_ttl: Duration::from_secs(24 * 60 * 60),
            allow_seed_export: true,
            unlock_backoff_max: Duration::from_secs(30),
            scrypt_work_factor: 20,
        }
    }
}

/// `[cache]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Kept behind the slowest key for cheap rewinds.
    pub retain_blocks: u32,
    pub max_mb: u32,
    /// `true` keeps Tor-fetched ranges after they are scanned.
    pub keep_historical: bool,
    pub fetch_batch: u32,
    pub scan_batch: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            retain_blocks: 1000,
            max_mb: 2048,
            keep_historical: false,
            fetch_batch: 100,
            scan_batch: 1000,
        }
    }
}

/// `[mempool]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MempoolConfig {
    pub scan: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self { scan: true }
    }
}

/// `[tex]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TexConfig {
    /// How often non-terminal `tex_queue` rows are re-checked.
    #[serde(with = "humantime_serde")]
    pub rebroadcast_interval: Duration,
    /// 0 = retry until `expiry_height`.
    pub max_attempts: u32,
}

impl Default for TexConfig {
    fn default() -> Self {
        Self {
            rebroadcast_interval: Duration::from_secs(60),
            max_attempts: 0,
        }
    }
}

/// `[policy]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Anchor depth used for "Spendable" and note selection.
    pub min_confirmations: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            min_confirmations: 10,
        }
    }
}

/// Why a configuration could not be loaded or is unusable.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}", path = .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}", path = .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("config.toml sets network = \"{configured}\" but the directory is for {directory}")]
    NetworkMismatch {
        configured: Network,
        directory: Network,
    },
    #[error(
        "[fallback_lightwalletd] enabled = true requires grpc_url (no default endpoint; see DATA_MODEL.md §2)"
    )]
    FallbackUrlMissing,
    #[error(
        "[fallback_lightwalletd] grpc_url must be https:// or an .onion host; http:// is allowed on regtest only"
    )]
    FallbackUrlInsecure,
    #[error(
        "[fallback_lightwalletd] broadcast_via_tor = true needs enabled = true and use_tor = true (use_tor = false is accepted on regtest only)"
    )]
    BroadcastViaTorUnavailable,
    #[error("[vault] scrypt_work_factor must be between 10 and 30 (log2 N), got {0}")]
    ScryptWorkFactor(u8),
}

/// The commented `config.toml` the daemon writes on first start when none
/// exists (DATA_MODEL.md §2, OVERVIEW.md Q-D5). Every line is a comment, so
/// it parses to [`Config::default`]: the file names the knobs and the
/// public archival endpoints without choosing any of them for the user.
pub fn template(network: Network) -> String {
    let endpoints = match network {
        Network::Mainnet => {
            "# Public archival endpoints, operator named. Uncomment one deliberately.\n\
             # Prefer an operator's .onion address when it publishes one: with\n\
             # use_tor = true a clearnet endpoint is reached through a Tor exit relay,\n\
             # an .onion endpoint without one.\n\
             # grpc_url = \"https://zec.rocks:443\"                   # operated by zec.rocks\n\
             # grpc_url = \"https://mainnet.lightwalletd.com:9067\"   # operated by Electric Coin Co.\n"
        }
        Network::Testnet => {
            "# A testnet lightwalletd or zaino you choose; prefer an .onion address.\n\
             # grpc_url = \"https://<endpoint>:443\"\n"
        }
        Network::Regtest => {
            "# A local zaino or lightwalletd; http:// is accepted on regtest only.\n\
             # grpc_url = \"http://127.0.0.1:9067\"\n\
             # use_tor = false\n"
        }
    };
    format!(
        "# Gyges daemon configuration for {network}. Every key is optional; the\n\
         # values shown are the defaults. See DATA_MODEL.md §2 for each one.\n\
         #\n\
         # default_key = \"main\"\n\
         # airgapped = false\n\
         \n\
         [daemon]\n\
         # socket_group = \"\"\n\
         # allowed_uids = []\n\
         # log_level = \"info\"\n\
         # offline_grace = \"2m\"\n\
         # shutdown_grace = \"30s\"\n\
         \n\
         [zakura_rpc]\n\
         # url = \"http://127.0.0.1:8232\"\n\
         # cookie_path = \"~/.cache/zakura/.cookie\"\n\
         # poll_interval_secs = 15\n\
         # min_retention_blocks = 10000\n\
         \n\
         # The archival endpoint for history below the node's retention window\n\
         # (SYNC.md §5). It learns the block ranges you fetch (about a restored\n\
         # key's birthday) and, for transparent recovery, the key's transparent\n\
         # addresses. There is no default endpoint.\n\
         [fallback_lightwalletd]\n\
         # enabled = false\n\
         # use_tor = true\n\
         # broadcast_via_tor = false\n\
         # overlap_blocks = 10\n\
         {endpoints}\
         \n\
         [vault]\n\
         # unlock_ttl = \"5m\"\n\
         # allow_seed_export = true\n\
         # unlock_backoff_max = \"30s\"\n\
         # scrypt_work_factor = 20\n\
         \n\
         [policy]\n\
         # min_confirmations = 10\n"
    )
}

impl Config {
    /// Write [`template`] to `path` (0600) unless a file is already there.
    /// Returns whether it wrote one.
    pub fn write_template(path: &Path, network: Network) -> std::io::Result<bool> {
        use std::io::Write as _;
        if path.exists() {
            return Ok(false);
        }
        crate::perms::create_private_file(path)?.write_all(template(network).as_bytes())?;
        Ok(true)
    }

    /// Parse a TOML document.
    pub fn parse(text: &str) -> Result<Self, Box<toml::de::Error>> {
        toml::from_str(text).map_err(Box::new)
    }

    /// Load `path`; a missing file yields the defaults. The result is not yet
    /// validated against the directory's network: call [`Config::validate`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|source| ConfigError::Parse {
                path: path.into(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.into(),
                source,
            }),
        }
    }

    /// Cross-field rules from DATA_MODEL.md §2 and THREAT_MODEL.md (Q-D5).
    pub fn validate(&self, directory: Network) -> Result<(), ConfigError> {
        if let Some(configured) = self.network
            && configured != directory
        {
            return Err(ConfigError::NetworkMismatch {
                configured,
                directory,
            });
        }
        let fb = &self.fallback_lightwalletd;
        if fb.enabled {
            if fb.grpc_url.is_empty() {
                return Err(ConfigError::FallbackUrlMissing);
            }
            if !fallback_url_allowed(&fb.grpc_url, directory) {
                return Err(ConfigError::FallbackUrlInsecure);
            }
        }
        // Every broadcast would otherwise be refused, so say so at start.
        if fb.broadcast_via_tor
            && !self.airgapped
            && (!fb.enabled || (!fb.use_tor && directory != Network::Regtest))
        {
            return Err(ConfigError::BroadcastViaTorUnavailable);
        }
        let wf = self.vault.scrypt_work_factor;
        if !(10..=30).contains(&wf) {
            return Err(ConfigError::ScryptWorkFactor(wf));
        }
        Ok(())
    }

    /// The zakurad cookie path with `~` expanded; `None` when unauthenticated.
    pub fn zakura_cookie_path(&self) -> Option<PathBuf> {
        let p = self.zakura_rpc.cookie_path.trim();
        (!p.is_empty()).then(|| crate::paths::expand_tilde(p))
    }
}

/// `https://` anywhere; `.onion` hosts with any scheme; `http://` on regtest.
fn fallback_url_allowed(url: &str, network: Network) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return true;
    }
    let host = lower.split("://").nth(1).unwrap_or(&lower);
    let host = host.split('/').next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.ends_with(".onion") {
        return true;
    }
    network == Network::Regtest && lower.starts_with("http://")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example in DATA_MODEL.md §2 is the schema's documentation; it must
    /// parse with `deny_unknown_fields` so the two cannot drift apart.
    fn data_model_example() -> String {
        let doc = include_str!("../../../DATA_MODEL.md");
        let start = doc
            .find("```toml\n")
            .expect("DATA_MODEL.md has a toml block")
            + "```toml\n".len();
        let end = doc[start..].find("```").expect("toml block closed") + start;
        doc[start..end].to_string()
    }

    #[test]
    fn empty_document_is_the_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        Config::default().validate(Network::Mainnet).unwrap();
    }

    #[test]
    fn data_model_example_parses_and_matches_defaults_where_it_claims_to() {
        let text = data_model_example();
        let cfg = Config::parse(&text).unwrap();
        cfg.validate(Network::Mainnet).unwrap();
        assert_eq!(cfg.default_key, "main");
        assert_eq!(cfg.network, Some(Network::Mainnet));
        // Everything except default_key and network in the example is the
        // default value.
        let expected = Config {
            default_key: "main".into(),
            network: Some(Network::Mainnet),
            ..Config::default()
        };
        assert_eq!(cfg, expected);
        // Durations round-trip through humantime strings.
        assert_eq!(cfg.vault.unlock_ttl, Duration::from_secs(300));
        assert_eq!(cfg.vault.signing_session_ttl, Duration::from_secs(86_400));
        assert_eq!(cfg.daemon.offline_grace, Duration::from_secs(120));
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = Config::parse("[vault]\nunlock_tll = \"5m\"\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let err = Config::parse("defualt_key = \"main\"\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn network_must_match_directory_when_set() {
        let cfg = Config::parse("network = \"testnet\"").unwrap();
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::NetworkMismatch {
                configured: Network::Testnet,
                directory: Network::Mainnet
            })
        ));
        cfg.validate(Network::Testnet).unwrap();
        // Omitted: any directory is fine.
        for n in Network::ALL {
            Config::default().validate(n).unwrap();
        }
    }

    #[test]
    fn fallback_requires_an_explicit_endpoint() {
        let cfg = Config::parse("[fallback_lightwalletd]\nenabled = true\n").unwrap();
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::FallbackUrlMissing)
        ));
    }

    #[test]
    fn fallback_url_scheme_rules() {
        assert!(fallback_url_allowed(
            "https://zec.rocks:443",
            Network::Mainnet
        ));
        assert!(fallback_url_allowed(
            "http://abc.onion:9067",
            Network::Mainnet
        ));
        assert!(fallback_url_allowed(
            "http://user@abc.onion/",
            Network::Mainnet
        ));
        assert!(!fallback_url_allowed(
            "http://127.0.0.1:9067",
            Network::Mainnet
        ));
        assert!(fallback_url_allowed(
            "http://127.0.0.1:9067",
            Network::Regtest
        ));
        assert!(!fallback_url_allowed("127.0.0.1:9067", Network::Regtest));
        let mut cfg = Config::default();
        cfg.fallback_lightwalletd.enabled = true;
        cfg.fallback_lightwalletd.grpc_url = "http://localhost:9067".into();
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::FallbackUrlInsecure)
        ));
        cfg.validate(Network::Regtest).unwrap();
    }

    #[test]
    fn the_template_parses_to_the_defaults_and_names_no_endpoint() {
        for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let text = template(net);
            assert_eq!(Config::parse(&text).unwrap(), Config::default(), "{net}");
            assert!(
                text.lines()
                    .filter(|l| l.contains("grpc_url"))
                    .all(|l| l.trim_start().starts_with('#')),
                "no endpoint is chosen for the user ({net})"
            );
        }
        assert!(template(Network::Mainnet).contains(".onion"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(Config::write_template(&path, Network::Regtest).unwrap());
        assert!(
            !Config::write_template(&path, Network::Regtest).unwrap(),
            "kept"
        );
        assert_eq!(Config::load(&path).unwrap(), Config::default());
    }

    #[test]
    fn broadcast_via_tor_needs_a_tor_endpoint() {
        let mut cfg = Config::default();
        cfg.fallback_lightwalletd.broadcast_via_tor = true;
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::BroadcastViaTorUnavailable)
        ));
        cfg.airgapped = true;
        cfg.validate(Network::Mainnet).unwrap();
        cfg.airgapped = false;
        cfg.fallback_lightwalletd.enabled = true;
        cfg.fallback_lightwalletd.grpc_url = "https://zec.rocks:443".into();
        cfg.validate(Network::Mainnet).unwrap();
        cfg.fallback_lightwalletd.use_tor = false;
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::BroadcastViaTorUnavailable)
        ));
        cfg.validate(Network::Regtest).unwrap();
    }

    #[test]
    fn scrypt_work_factor_bounds() {
        let mut cfg = Config::default();
        cfg.vault.scrypt_work_factor = 5;
        assert!(matches!(
            cfg.validate(Network::Mainnet),
            Err(ConfigError::ScryptWorkFactor(5))
        ));
    }

    #[test]
    fn missing_file_loads_defaults_and_other_io_errors_surface() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg, Config::default());
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "network = 3").unwrap();
        assert!(matches!(Config::load(&bad), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn cookie_path_expands_tilde_and_empty_means_none() {
        let mut cfg = Config::default();
        assert!(
            cfg.zakura_cookie_path().unwrap().is_absolute() || crate::paths::home_dir().is_none()
        );
        cfg.zakura_rpc.cookie_path = String::new();
        assert_eq!(cfg.zakura_cookie_path(), None);
    }
}
