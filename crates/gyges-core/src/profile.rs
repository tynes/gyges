//! `keys/<key_id>/profile.json` (DATA_MODEL.md §3).
//!
//! The profile is the one file that describes a key without opening SQLite:
//! how it signs, which pools it may spend from and receive to, its birthday,
//! and how `seed.age` is encrypted. It is written once by `key init` /
//! `key restore` / the import commands, rewritten atomically by migrations,
//! and never contains key material.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::network::Network;
use crate::paths::is_valid_key_id;
use crate::perms;
use crate::{Pool, SigningMode};

/// File name inside the key directory.
pub const PROFILE_FILE: &str = "profile.json";
/// File name of the encrypted entropy (DATA_MODEL.md §4).
pub const SEED_FILE: &str = "seed.age";
/// File name of the `zcash_client_sqlite` database (DATA_MODEL.md §5).
pub const WALLET_FILE: &str = "wallet.sqlite";

/// The `schema_version` this build writes and understands.
pub const SCHEMA_VERSION: u32 = 1;

/// What `local-seed` profiles spent from before Sapling spending landed
/// (ROADMAP.md M6); see [`KeyProfile::upgrade`].
pub const PRE_SAPLING_LOCAL_SEED_SPEND_POOLS: [Pool; 3] =
    [Pool::Orchard, Pool::Ironwood, Pool::Transparent];
/// The only `seed_format` today: an armored age file with one scrypt
/// passphrase recipient over the 32-byte BIP 39 entropy.
pub const SEED_FORMAT_AGE_SCRYPT_V1: &str = "age-scrypt-v1";

/// One key's metadata. Field semantics are the table in DATA_MODEL.md §3;
/// [`KeyProfile::validate`] enforces the per-mode rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProfile {
    pub schema_version: u32,
    /// Equals the directory name.
    pub key_id: String,
    /// Must equal the home's network.
    pub network: Network,
    pub signing_mode: SigningMode,
    /// Required for every mode except `signer-only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u32>,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// Input selection is restricted to these; empty for `watch-only`.
    pub spend_pools: Vec<Pool>,
    /// Default receivers for `address new`; empty for `signer-only`.
    #[serde(default)]
    pub receive_pools: Vec<Pool>,
    /// `local-seed` and `signer-only` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_format: Option<String>,
    /// ZIP 32 seed fingerprint, hex; every mode that derives from a seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_fingerprint: Option<String>,
    /// `keystone-qr` only, from `zcash-accounts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_version: Option<String>,
    /// ZIP 32 account index; 0 unless imported otherwise.
    #[serde(default)]
    pub account_index: u32,
    /// `keystone-qr` and `watch-only`: the imported UFVK, kept here so the
    /// profile is readable without SQLite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ufvk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Why a profile could not be read, written or accepted.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("cannot read {path}: {source}", path = .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write {path}: {source}", path = .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: {source}", path = .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "profile.json schema_version {found} is newer than this daemon understands ({SCHEMA_VERSION}); upgrade gygesd"
    )]
    SchemaTooNew { found: u32 },
    #[error("profile.json schema_version {found} is not supported")]
    SchemaUnsupported { found: u32 },
    #[error("profile.json key_id \"{found}\" does not match its directory \"{directory}\"")]
    KeyIdMismatch { found: String, directory: String },
    #[error("key id \"{0}\" is invalid; expected ^[a-z0-9][a-z0-9_-]{{0,31}}$")]
    InvalidKeyId(String),
    #[error("profile.json is for {found} but this home is {expected}")]
    NetworkMismatch { found: Network, expected: Network },
    #[error("profile.json ({mode}): {detail}")]
    Invalid { mode: SigningMode, detail: String },
}

impl fmt::Display for SigningMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SigningMode::LocalSeed => "local-seed",
            SigningMode::KeystoneQr => "keystone-qr",
            SigningMode::WatchOnly => "watch-only",
            SigningMode::SignerOnly => "signer-only",
        })
    }
}

impl KeyProfile {
    /// Read and parse `path` (no validation; call [`KeyProfile::validate`]).
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let text = std::fs::read_to_string(path).map_err(|source| ProfileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| ProfileError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Write `path` atomically: a `0600` temporary in the same directory,
    /// then rename over the destination.
    pub fn save(&self, path: &Path) -> Result<(), ProfileError> {
        let write = |source| ProfileError::Write {
            path: path.to_path_buf(),
            source,
        };
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self).map_err(|e| write(io::Error::other(e)))?;
        {
            use std::io::Write as _;
            let mut f = perms::create_private_file(&tmp).map_err(write)?;
            f.write_all(text.as_bytes()).map_err(write)?;
            f.write_all(b"\n").map_err(write)?;
            f.sync_all().map_err(write)?;
        }
        std::fs::rename(&tmp, path).map_err(write)
    }

    /// Bring a profile written by an older build up to date, in memory;
    /// `true` when something changed and the caller should save it. Before
    /// M6 every `local-seed` profile was written with exactly
    /// [`PRE_SAPLING_LOCAL_SEED_SPEND_POOLS`] and no command could change
    /// it, so that list is a default, not a choice: it gains Sapling now
    /// that Sapling notes can be spent (ROADMAP.md M6, first item). Any
    /// other list is left alone.
    pub fn upgrade(&mut self) -> bool {
        if self.signing_mode == SigningMode::LocalSeed
            && self.spend_pools == PRE_SAPLING_LOCAL_SEED_SPEND_POOLS
        {
            self.spend_pools = Pool::ALL.to_vec();
            return true;
        }
        false
    }

    /// The per-mode rules of DATA_MODEL.md §3 plus the identity checks:
    /// schema version, key id grammar and directory name, network.
    pub fn validate(&self, expected_network: Network, directory: &str) -> Result<(), ProfileError> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(ProfileError::SchemaTooNew {
                found: self.schema_version,
            });
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProfileError::SchemaUnsupported {
                found: self.schema_version,
            });
        }
        if !is_valid_key_id(&self.key_id) {
            return Err(ProfileError::InvalidKeyId(self.key_id.clone()));
        }
        if self.key_id != directory {
            return Err(ProfileError::KeyIdMismatch {
                found: self.key_id.clone(),
                directory: directory.to_string(),
            });
        }
        if self.network != expected_network {
            return Err(ProfileError::NetworkMismatch {
                found: self.network,
                expected: expected_network,
            });
        }
        let mode = self.signing_mode;
        let invalid = |detail: &str| ProfileError::Invalid {
            mode,
            detail: detail.to_string(),
        };
        let has_seed = matches!(mode, SigningMode::LocalSeed | SigningMode::SignerOnly);
        let has_wallet = mode != SigningMode::SignerOnly;

        if has_wallet && self.birthday_height.is_none() {
            return Err(invalid("birthday_height is required"));
        }
        if !has_wallet && self.birthday_height.is_some() {
            return Err(invalid("birthday_height must be absent"));
        }
        match (&self.seed_format, has_seed) {
            (Some(f), true) if f != SEED_FORMAT_AGE_SCRYPT_V1 => {
                return Err(invalid(&format!("unknown seed_format \"{f}\"")));
            }
            (None, true) => return Err(invalid("seed_format is required")),
            (Some(_), false) => return Err(invalid("seed_format must be absent")),
            _ => {}
        }
        if mode != SigningMode::WatchOnly {
            match &self.seed_fingerprint {
                Some(fp) if fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()) => {}
                Some(_) => return Err(invalid("seed_fingerprint must be 64 hex characters")),
                None => return Err(invalid("seed_fingerprint is required")),
            }
        }
        if matches!(mode, SigningMode::KeystoneQr | SigningMode::WatchOnly)
            && self.ufvk.as_deref().unwrap_or("").is_empty()
        {
            return Err(invalid("ufvk is required"));
        }
        if mode == SigningMode::KeystoneQr && self.device_version.is_none() {
            return Err(invalid("device_version is required"));
        }
        if mode == SigningMode::WatchOnly && !self.spend_pools.is_empty() {
            return Err(invalid("spend_pools must be empty"));
        }
        if mode == SigningMode::SignerOnly && !self.receive_pools.is_empty() {
            return Err(invalid("receive_pools must be empty"));
        }
        Ok(())
    }

    /// Whether this mode keeps `seed.age`.
    pub fn has_seed_file(&self) -> bool {
        matches!(
            self.signing_mode,
            SigningMode::LocalSeed | SigningMode::SignerOnly
        )
    }

    /// Whether this mode keeps `wallet.sqlite`.
    pub fn has_wallet(&self) -> bool {
        self.signing_mode != SigningMode::SignerOnly
    }
}

/// `t` as Unix seconds (0 before the epoch, saturating far after it).
pub fn unix_secs(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Now as Unix seconds.
pub fn unix_now() -> i64 {
    unix_secs(std::time::SystemTime::now())
}

/// `SystemTime::now()` as RFC 3339 with second precision.
pub fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_seed() -> KeyProfile {
        KeyProfile {
            schema_version: SCHEMA_VERSION,
            key_id: "main".into(),
            network: Network::Mainnet,
            signing_mode: SigningMode::LocalSeed,
            birthday_height: Some(2_650_000),
            created_at: "2026-10-20T10:00:00Z".into(),
            spend_pools: vec![Pool::Orchard, Pool::Transparent],
            receive_pools: vec![Pool::Orchard, Pool::Sapling, Pool::Transparent],
            seed_format: Some(SEED_FORMAT_AGE_SCRYPT_V1.into()),
            seed_fingerprint: Some("f0".repeat(32)),
            device_version: None,
            account_index: 0,
            ufvk: None,
            label: Some("Main wallet".into()),
        }
    }

    /// The JSON blocks in DATA_MODEL.md §3 are the schema's documentation;
    /// the full example must parse (the mode fragments are not complete
    /// profiles and are checked by hand in the validation tests).
    #[test]
    fn data_model_example_parses_and_validates() {
        let doc = include_str!("../../../DATA_MODEL.md");
        let section = doc.find("## 3. `profile.json`").expect("section 3");
        let start = doc[section..].find("```json\n").expect("json block") + section + 8;
        let end = doc[start..].find("```").expect("closed") + start;
        let text = doc[start..end].replace("f0a1…", &"f0a1".repeat(16));
        let p: KeyProfile = serde_json::from_str(&text).unwrap();
        p.validate(Network::Mainnet, "main").unwrap();
        assert_eq!(p.signing_mode, SigningMode::LocalSeed);
        assert_eq!(p.birthday_height, Some(2_650_000));
        assert_eq!(p.seed_format.as_deref(), Some(SEED_FORMAT_AGE_SCRYPT_V1));
    }

    #[test]
    fn round_trips_through_disk_with_private_mode() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROFILE_FILE);
        let p = local_seed();
        p.save(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(!path.with_extension("json.tmp").exists());
        let back = KeyProfile::load(&path).unwrap();
        assert_eq!(back, p);
        // Optional fields are omitted rather than written as null.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("null"), "{text}");
        assert!(!text.contains("device_version"), "{text}");
    }

    #[test]
    fn unknown_fields_and_bad_json_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROFILE_FILE);
        std::fs::write(&path, "{\"schema_version\": 1, \"bogus\": 1}").unwrap();
        assert!(matches!(
            KeyProfile::load(&path),
            Err(ProfileError::Parse { .. })
        ));
        assert!(matches!(
            KeyProfile::load(&dir.path().join("missing.json")),
            Err(ProfileError::Read { .. })
        ));
    }

    #[test]
    fn identity_checks() {
        let p = local_seed();
        p.validate(Network::Mainnet, "main").unwrap();
        assert!(matches!(
            p.validate(Network::Testnet, "main"),
            Err(ProfileError::NetworkMismatch { .. })
        ));
        assert!(matches!(
            p.validate(Network::Mainnet, "other"),
            Err(ProfileError::KeyIdMismatch { .. })
        ));
        let mut newer = p.clone();
        newer.schema_version = SCHEMA_VERSION + 1;
        assert!(matches!(
            newer.validate(Network::Mainnet, "main"),
            Err(ProfileError::SchemaTooNew { .. })
        ));
        let mut bad_id = p.clone();
        bad_id.key_id = "Main".into();
        assert!(matches!(
            bad_id.validate(Network::Mainnet, "Main"),
            Err(ProfileError::InvalidKeyId(_))
        ));
    }

    #[test]
    fn per_mode_rules() {
        let base = local_seed();

        let mut no_birthday = base.clone();
        no_birthday.birthday_height = None;
        assert!(no_birthday.validate(Network::Mainnet, "main").is_err());

        let mut bad_format = base.clone();
        bad_format.seed_format = Some("age-argon2".into());
        assert!(bad_format.validate(Network::Mainnet, "main").is_err());

        let mut no_fp = base.clone();
        no_fp.seed_fingerprint = None;
        assert!(no_fp.validate(Network::Mainnet, "main").is_err());

        // signer-only: seed, no wallet, no birthday, no receive pools.
        let mut signer = base.clone();
        signer.signing_mode = SigningMode::SignerOnly;
        signer.birthday_height = None;
        signer.receive_pools.clear();
        signer.spend_pools = vec![Pool::Orchard, Pool::Sapling, Pool::Transparent];
        signer.validate(Network::Mainnet, "main").unwrap();
        assert!(!signer.has_wallet() && signer.has_seed_file());
        let mut signer_with_birthday = signer.clone();
        signer_with_birthday.birthday_height = Some(1);
        assert!(
            signer_with_birthday
                .validate(Network::Mainnet, "main")
                .is_err()
        );

        // watch-only: ufvk, no seed, no spend pools, no fingerprint needed.
        let mut watch = base.clone();
        watch.signing_mode = SigningMode::WatchOnly;
        watch.seed_format = None;
        watch.seed_fingerprint = None;
        watch.spend_pools.clear();
        watch.ufvk = Some("uview1x".into());
        watch.validate(Network::Mainnet, "main").unwrap();
        assert!(!watch.has_seed_file() && watch.has_wallet());
        let mut watch_spends = watch.clone();
        watch_spends.spend_pools = vec![Pool::Orchard];
        assert!(watch_spends.validate(Network::Mainnet, "main").is_err());
        let mut watch_no_ufvk = watch.clone();
        watch_no_ufvk.ufvk = None;
        assert!(watch_no_ufvk.validate(Network::Mainnet, "main").is_err());

        // keystone-qr: ufvk, device_version, fingerprint, no seed.
        let mut keystone = base.clone();
        keystone.signing_mode = SigningMode::KeystoneQr;
        keystone.seed_format = None;
        keystone.ufvk = Some("uview1x".into());
        keystone.device_version = Some("2.1.0".into());
        keystone.receive_pools = vec![Pool::Orchard, Pool::Transparent];
        keystone.validate(Network::Mainnet, "main").unwrap();
        keystone.device_version = None;
        assert!(keystone.validate(Network::Mainnet, "main").is_err());

        // Ironwood is the live shielded pool after NU6.3 (OVERVIEW.md §4.3).
        let mut ironwood = base;
        ironwood.spend_pools.push(Pool::Ironwood);
        ironwood.validate(Network::Mainnet, "main").unwrap();
    }
}
