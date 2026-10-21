//! The on-disk layout under `GYGES_HOME` (DATA_MODEL.md §1).
//!
//! ```text
//! $GYGES_HOME/                 default ~/.gyges
//! └── <network>/
//!     ├── config.toml
//!     ├── gygesd.sock
//!     ├── gygesd.pid
//!     ├── tor_cache/
//!     ├── cache/blocks.sqlite
//!     ├── logs/{gygesd.log,audit.log}
//!     └── keys/<key_id>/{profile.json,wallet.sqlite,seed.age}
//! ```

use std::path::{Path, PathBuf};

use crate::network::Network;

/// Environment variable that overrides the root directory.
pub const HOME_ENV: &str = "GYGES_HOME";

/// The root of every Gyges file on this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// `$GYGES_HOME`, else `~/.gyges`. Returns `None` only when neither the
    /// variable nor a home directory is available.
    pub fn from_env() -> Option<Self> {
        match std::env::var_os(HOME_ENV) {
            Some(dir) if !dir.is_empty() => Some(Self::new(PathBuf::from(dir))),
            _ => home_dir().map(|h| Self::new(h.join(".gyges"))),
        }
    }

    /// Use `root` as the home.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn network_dir(&self, network: Network) -> PathBuf {
        self.root.join(network.name())
    }

    pub fn config_path(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("config.toml")
    }

    pub fn socket_path(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("gygesd.sock")
    }

    pub fn pid_path(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("gygesd.pid")
    }

    pub fn tor_cache_dir(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("tor_cache")
    }

    pub fn cache_dir(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("cache")
    }

    pub fn block_cache_path(&self, network: Network) -> PathBuf {
        self.cache_dir(network).join("blocks.sqlite")
    }

    pub fn logs_dir(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("logs")
    }

    pub fn keys_dir(&self, network: Network) -> PathBuf {
        self.network_dir(network).join("keys")
    }

    pub fn key_dir(&self, network: Network, key_id: &str) -> PathBuf {
        self.keys_dir(network).join(key_id)
    }
}

/// The user's home directory, if the platform knows it.
pub fn home_dir() -> Option<PathBuf> {
    std::env::home_dir()
}

/// Expand a leading `~` or `~/` in a configured path (DATA_MODEL.md §1:
/// "tilde in any configured path is expanded by the daemon").
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }
    match path.strip_prefix("~/") {
        Some(rest) => match home_dir() {
            Some(home) => home.join(rest),
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

/// Validate a key id against `^[a-z0-9][a-z0-9_-]{0,31}$` (DATA_MODEL.md §1).
pub fn is_valid_key_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    id.len() <= 32
        && first.is_ascii_lowercase() | first.is_ascii_digit()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_data_model() {
        let home = Home::new("/x");
        let n = Network::Regtest;
        assert_eq!(home.network_dir(n), Path::new("/x/regtest"));
        assert_eq!(home.config_path(n), Path::new("/x/regtest/config.toml"));
        assert_eq!(home.socket_path(n), Path::new("/x/regtest/gygesd.sock"));
        assert_eq!(home.pid_path(n), Path::new("/x/regtest/gygesd.pid"));
        assert_eq!(
            home.block_cache_path(n),
            Path::new("/x/regtest/cache/blocks.sqlite")
        );
        assert_eq!(home.logs_dir(n), Path::new("/x/regtest/logs"));
        assert_eq!(home.key_dir(n, "main"), Path::new("/x/regtest/keys/main"));
    }

    #[test]
    fn tilde_expansion() {
        let home = home_dir().expect("test host has a home directory");
        assert_eq!(expand_tilde("~/.cache/x"), home.join(".cache/x"));
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(expand_tilde("/abs/~/x"), PathBuf::from("/abs/~/x"));
        assert_eq!(expand_tilde("~user/x"), PathBuf::from("~user/x"));
    }

    #[test]
    fn key_id_grammar() {
        for ok in ["main", "a", "0", "keystone-vault", "k_1", &"a".repeat(32)] {
            assert!(is_valid_key_id(ok), "{ok}");
        }
        for bad in ["", "Main", "-a", "_a", "a b", "a/b", &"a".repeat(33)] {
            assert!(!is_valid_key_id(bad), "{bad}");
        }
    }
}
