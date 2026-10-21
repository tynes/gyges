//! `KeyRegistry` (ARCHITECTURE.md §2.1): enumerates `keys/<id>/profile.json`,
//! opens one `WalletDb` per key, enforces the 0700/0600 rule on every key
//! directory, resolves `default_key`, and creates new `local-seed` and
//! `signer-only` profiles for `key init` / `key restore`.
//!
//! A key directory is created in one go and removed again if any step
//! fails, so a half-written profile never survives to the next start.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use age::secrecy::SecretString;
use secrecy::ExposeSecret as _;
use zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode;
use zcash_client_backend::data_api::{Account as _, WalletRead as _, WalletWrite as _};
use zcash_client_sqlite::WalletDb;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::{WalletMigrationError, init_wallet_db};
use zcash_keys::keys::UnifiedSpendingKey;
use zip32::fingerprint::SeedFingerprint;

use crate::birthday::ResolvedBirthday;
use crate::config::Config;
use crate::network::{ConsensusParams, Network};
use crate::paths::{Home, is_valid_key_id};
use crate::perms::{self, PermissionError};
use crate::profile::{
    self, KeyProfile, PROFILE_FILE, ProfileError, SEED_FILE, SEED_FORMAT_AGE_SCRYPT_V1, WALLET_FILE,
};
use crate::vault::{self, Entropy, VaultError};
use crate::{Pool, SigningMode};

/// Operating-system randomness, infallible.
pub type Rng = rand::rand_core::UnwrapErr<rand::rngs::SysRng>;

/// The upstream wallet database as Gyges instantiates it.
pub type Wallet = WalletDb<rusqlite::Connection, ConsensusParams, SystemClock, Rng>;

/// `key_source` recorded in the upstream `accounts` table.
const KEY_SOURCE: &str = "gyges";

/// Why the registry could not be opened or a key could not be created.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("key id \"{0}\" is invalid; expected ^[a-z0-9][a-z0-9_-]{{0,31}}$")]
    InvalidKeyId(String),
    #[error("key \"{0}\" already exists")]
    Exists(String),
    #[error("key \"{0}\" does not exist")]
    NotFound(String),
    #[error("no default key; pass --key")]
    NoDefault,
    #[error("key \"{key_id}\": {source}")]
    Profile {
        key_id: String,
        #[source]
        source: ProfileError,
    },
    #[error(transparent)]
    Permission(#[from] PermissionError),
    #[error("key \"{key_id}\": {source}")]
    Vault {
        key_id: String,
        #[source]
        source: VaultError,
    },
    #[error(
        "key \"{key_id}\": {file} is missing; restore it from a backup or delete the key directory"
    )]
    MissingFile { key_id: String, file: &'static str },
    #[error("key \"{key_id}\": wallet.sqlite: {detail}")]
    Wallet { key_id: String, detail: String },
    #[error(
        "key \"{0}\": a wallet migration needs the seed; this release cannot unlock at startup, \
         see ROADMAP.md"
    )]
    SeedRequiredForMigration(String),
    #[error("{context} {path}: {source}", path = .path.display())]
    Io {
        context: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

/// One loaded key: its profile, its directory and (except for
/// `signer-only`) its open wallet database.
pub struct KeyEntry {
    profile: KeyProfile,
    dir: PathBuf,
    params: ConsensusParams,
    wallet: Option<Mutex<Wallet>>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("key_id", &self.profile.key_id)
            .field("signing_mode", &self.profile.signing_mode)
            .field("dir", &self.dir)
            .field("wallet", &self.wallet.is_some())
            .finish()
    }
}

impl KeyEntry {
    pub fn key_id(&self) -> &str {
        &self.profile.key_id
    }

    pub fn profile(&self) -> &KeyProfile {
        &self.profile
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn seed_path(&self) -> PathBuf {
        self.dir.join(SEED_FILE)
    }

    pub fn wallet_path(&self) -> PathBuf {
        self.dir.join(WALLET_FILE)
    }

    /// The wallet database, `None` for `signer-only` profiles. A poisoned
    /// lock is recovered: the database has its own transactions.
    pub fn wallet(&self) -> Option<MutexGuard<'_, Wallet>> {
        self.wallet
            .as_ref()
            .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Highest block the wallet has scanned, 0 if none yet.
    pub fn scanned_tip(&self) -> u32 {
        self.wallet()
            .and_then(|w| w.block_max_scanned().ok().flatten())
            .map(|m| u32::from(m.block_height()))
            .unwrap_or(0)
    }

    /// Derive the account's UFVK from decrypted entropy, for profiles whose
    /// viewing key is not on disk (`signer-only`).
    pub fn derive_ufvk(&self, entropy: &Entropy) -> Result<String, RegistryError> {
        let account = zip32::AccountId::try_from(self.profile.account_index)
            .map_err(|_| RegistryError::Invalid("account index out of range".into()))?;
        let seed = vault::seed_from_entropy(entropy);
        let usk = UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account)
            .map_err(|e| RegistryError::Invalid(format!("key derivation failed: {e:?}")))?;
        Ok(usk.to_unified_full_viewing_key().encode(&self.params))
    }

    /// The account's encoded UFVK. `None` for `signer-only` (whose viewing
    /// key lives behind the passphrase) and for a wallet without accounts.
    pub fn ufvk(&self) -> Option<String> {
        if let Some(u) = &self.profile.ufvk {
            return Some(u.clone());
        }
        let wallet = self.wallet()?;
        let id = *wallet.get_account_ids().ok()?.first()?;
        let account = wallet.get_account(id).ok()??;
        account.ufvk().map(|k| k.encode(&self.params))
    }
}

/// What `key init` / `key restore` hand to [`KeyRegistry::create_local_seed`].
pub struct NewLocalSeedKey<'a> {
    pub key_id: &'a str,
    pub entropy: &'a Entropy,
    pub passphrase: SecretString,
    pub birthday: &'a ResolvedBirthday,
    /// ZIP 32 account index, normally 0.
    pub account_index: u32,
    pub label: Option<String>,
}

impl fmt::Debug for NewLocalSeedKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewLocalSeedKey")
            .field("key_id", &self.key_id)
            .field("birthday", &self.birthday.height)
            .field("account_index", &self.account_index)
            .finish_non_exhaustive()
    }
}

/// All keys of one network.
pub struct KeyRegistry {
    home: Home,
    network: Network,
    params: ConsensusParams,
    scrypt_work_factor: u8,
    default_key: RwLock<String>,
    keys: RwLock<BTreeMap<String, Arc<KeyEntry>>>,
}

impl fmt::Debug for KeyRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRegistry")
            .field("network", &self.network)
            .field("default_key", &self.default_key())
            .field("keys", &self.key_ids())
            .finish()
    }
}

impl KeyRegistry {
    /// Load every key under `keys/`, refusing to continue on the first one
    /// that is unreadable, invalid or too widely readable.
    pub fn open(home: Home, network: Network, config: &Config) -> Result<Self, RegistryError> {
        let keys_dir = home.keys_dir(network);
        perms::ensure_private_dir(&keys_dir)?;
        let reg = Self {
            home,
            network,
            params: network.consensus_params(),
            scrypt_work_factor: config.vault.scrypt_work_factor,
            default_key: RwLock::new(config.default_key.clone()),
            keys: RwLock::new(BTreeMap::new()),
        };
        let entries = std::fs::read_dir(&keys_dir).map_err(|source| RegistryError::Io {
            context: "cannot list",
            path: keys_dir.clone(),
            source,
        })?;
        let mut loaded = BTreeMap::new();
        for entry in entries {
            let entry = entry.map_err(|source| RegistryError::Io {
                context: "cannot list",
                path: keys_dir.clone(),
                source,
            })?;
            let path = entry.path();
            if !path.is_dir() {
                // Stray files (editor backups, .DS_Store) are ignored; the
                // permission sweep has already checked them.
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_valid_key_id(&name) {
                return Err(RegistryError::Invalid(format!(
                    "{} is not a valid key directory name; move it out of {}",
                    path.display(),
                    keys_dir.display()
                )));
            }
            let key = reg.load_entry(&path, &name)?;
            tracing::info!(key_id = %name, mode = %key.profile.signing_mode, "key loaded");
            loaded.insert(name, Arc::new(key));
        }
        let default = reg.default_key();
        if !default.is_empty() && !loaded.contains_key(&default) {
            tracing::warn!(
                default_key = %default,
                "config.toml names a default_key that does not exist"
            );
        }
        *reg.keys.write().unwrap_or_else(|e| e.into_inner()) = loaded;
        Ok(reg)
    }

    fn load_entry(&self, dir: &Path, key_id: &str) -> Result<KeyEntry, RegistryError> {
        perms::check_tree(dir)?;
        let with_key = |source| RegistryError::Profile {
            key_id: key_id.to_string(),
            source,
        };
        let profile = KeyProfile::load(&dir.join(PROFILE_FILE)).map_err(with_key)?;
        profile.validate(self.network, key_id).map_err(with_key)?;
        if profile.has_seed_file() && !dir.join(SEED_FILE).is_file() {
            return Err(RegistryError::MissingFile {
                key_id: key_id.to_string(),
                file: SEED_FILE,
            });
        }
        let wallet = if profile.has_wallet() {
            let path = dir.join(WALLET_FILE);
            if !path.is_file() {
                return Err(RegistryError::MissingFile {
                    key_id: key_id.to_string(),
                    file: WALLET_FILE,
                });
            }
            let wallet = self.open_wallet(key_id, &path)?;
            if wallet
                .get_account_ids()
                .map_err(|e| wallet_error(key_id, e))?
                .is_empty()
            {
                return Err(RegistryError::Wallet {
                    key_id: key_id.to_string(),
                    detail: "no account; the database was never initialised".into(),
                });
            }
            Some(Mutex::new(wallet))
        } else {
            None
        };
        Ok(KeyEntry {
            profile,
            dir: dir.to_path_buf(),
            params: self.params,
            wallet,
        })
    }

    /// Open (creating if absent) and migrate a wallet database.
    fn open_wallet(&self, key_id: &str, path: &Path) -> Result<Wallet, RegistryError> {
        let mut wallet = WalletDb::for_path(
            path,
            self.params,
            SystemClock,
            rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        )
        .map_err(|e| wallet_error(key_id, e))?
        // Per-handle, not persisted: transparent discovery in Case A reads the
        // local node's raw blocks (SYNC.md §2.1), which upstream classes as
        // the "public" ledger source; Zakura's transparent APIs fail closed
        // until a mode is chosen.
        .with_transparent_ledger_mode(TransparentLedgerMode::Public);
        // The daemon's umask makes this a no-op; tests and tools without it
        // still get a private file.
        perms::set_mode(path, 0o600).map_err(|source| RegistryError::Io {
            context: "cannot chmod",
            path: path.to_path_buf(),
            source,
        })?;
        match init_wallet_db(&mut wallet, None) {
            Ok(()) => Ok(wallet),
            Err(schemerz::MigratorError::Migration {
                error: WalletMigrationError::SeedRequired,
                ..
            }) => Err(RegistryError::SeedRequiredForMigration(key_id.to_string())),
            Err(e) => Err(RegistryError::Wallet {
                key_id: key_id.to_string(),
                detail: e.to_string(),
            }),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn params(&self) -> ConsensusParams {
        self.params
    }

    /// `vault.scrypt_work_factor`.
    pub fn scrypt_work_factor(&self) -> u8 {
        self.scrypt_work_factor
    }

    /// The key an empty `key_id` resolves to; empty if none.
    pub fn default_key(&self) -> String {
        self.default_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Change the default for this daemon's lifetime. `config.toml` is never
    /// rewritten by the daemon (DATA_MODEL.md §7), so the caller tells the
    /// user to set `default_key` there to make it stick.
    pub fn set_default_key(&self, key_id: &str) -> Result<(), RegistryError> {
        if !self.keys().contains_key(key_id) {
            return Err(RegistryError::NotFound(key_id.to_string()));
        }
        *self.default_key.write().unwrap_or_else(|e| e.into_inner()) = key_id.to_string();
        Ok(())
    }

    fn keys(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Arc<KeyEntry>>> {
        self.keys.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Sorted key ids.
    pub fn key_ids(&self) -> Vec<String> {
        self.keys().keys().cloned().collect()
    }

    /// Every key, sorted by id.
    pub fn list(&self) -> Vec<Arc<KeyEntry>> {
        self.keys().values().cloned().collect()
    }

    /// Resolve a request's `key_id` (API.md §1.4): empty means the default.
    pub fn resolve(&self, key_id: &str) -> Result<Arc<KeyEntry>, RegistryError> {
        let id = if key_id.is_empty() {
            let d = self.default_key();
            if d.is_empty() {
                return Err(RegistryError::NoDefault);
            }
            d
        } else {
            key_id.to_string()
        };
        self.keys()
            .get(&id)
            .cloned()
            .ok_or(RegistryError::NotFound(id))
    }

    /// Reserve a fresh `keys/<id>/` directory, failing if the id is taken.
    fn reserve_dir(&self, key_id: &str) -> Result<PathBuf, RegistryError> {
        if !is_valid_key_id(key_id) {
            return Err(RegistryError::InvalidKeyId(key_id.to_string()));
        }
        if self.keys().contains_key(key_id) {
            return Err(RegistryError::Exists(key_id.to_string()));
        }
        let dir = self.home.key_dir(self.network, key_id);
        if dir.exists() {
            return Err(RegistryError::Exists(key_id.to_string()));
        }
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|source| RegistryError::Io {
                context: "cannot create",
                path: dir.clone(),
                source,
            })?;
        Ok(dir)
    }

    /// `key init` / `key restore`: encrypt the entropy, initialise the wallet
    /// with one account derived from it, write the profile, register it.
    pub fn create_local_seed(
        &self,
        req: NewLocalSeedKey<'_>,
    ) -> Result<Arc<KeyEntry>, RegistryError> {
        let dir = self.reserve_dir(req.key_id)?;
        let result = self.populate_local_seed(&dir, req);
        self.finish_create(dir, result)
    }

    /// `key init` on an air-gapped daemon: seed and profile only, no wallet
    /// and no birthday (DATA_MODEL.md §3, Q-K5).
    pub fn create_signer_only(
        &self,
        key_id: &str,
        entropy: &Entropy,
        passphrase: SecretString,
        label: Option<String>,
    ) -> Result<Arc<KeyEntry>, RegistryError> {
        let dir = self.reserve_dir(key_id)?;
        let result = (|| {
            let fingerprint = self.write_seed(&dir, key_id, entropy, passphrase)?;
            let profile = KeyProfile {
                schema_version: profile::SCHEMA_VERSION,
                key_id: key_id.to_string(),
                network: self.network,
                signing_mode: SigningMode::SignerOnly,
                birthday_height: None,
                created_at: profile::now_rfc3339(),
                spend_pools: vec![Pool::Orchard, Pool::Sapling, Pool::Transparent],
                receive_pools: Vec::new(),
                seed_format: Some(SEED_FORMAT_AGE_SCRYPT_V1.into()),
                seed_fingerprint: Some(fingerprint),
                device_version: None,
                account_index: 0,
                ufvk: None,
                label,
            };
            self.write_profile(&dir, key_id, &profile)?;
            Ok(KeyEntry {
                profile,
                dir: dir.clone(),
                params: self.params,
                wallet: None,
            })
        })();
        self.finish_create(dir, result)
    }

    fn populate_local_seed(
        &self,
        dir: &Path,
        req: NewLocalSeedKey<'_>,
    ) -> Result<KeyEntry, RegistryError> {
        let key_id = req.key_id;
        let account_index = zip32::AccountId::try_from(req.account_index).map_err(|_| {
            RegistryError::Invalid(format!(
                "account index {} is out of range",
                req.account_index
            ))
        })?;
        let fingerprint = self.write_seed(dir, key_id, req.entropy, req.passphrase)?;

        let wallet_path = dir.join(WALLET_FILE);
        let mut wallet = self.open_wallet(key_id, &wallet_path)?;
        let seed = vault::seed_from_entropy(req.entropy);
        // The returned USK is not kept: it is re-derived from `seed.age` at
        // unlock time. (`UnifiedSpendingKey` has no `Drop`; the sensitive
        // material it wraps is zeroized by its own fields.)
        let (_account, _usk): (_, UnifiedSpendingKey) = wallet
            .import_account_hd(
                key_id,
                &seed,
                account_index,
                &req.birthday.birthday,
                Some(KEY_SOURCE),
            )
            .map_err(|e| wallet_error(key_id, e))?;
        drop(seed);

        let profile = KeyProfile {
            schema_version: profile::SCHEMA_VERSION,
            key_id: key_id.to_string(),
            network: self.network,
            signing_mode: SigningMode::LocalSeed,
            birthday_height: Some(req.birthday.height),
            created_at: profile::now_rfc3339(),
            // MVP pools (ROADMAP.md "Pools are data"): Sapling receive-only.
            spend_pools: vec![Pool::Orchard, Pool::Transparent],
            receive_pools: vec![Pool::Orchard, Pool::Sapling, Pool::Transparent],
            seed_format: Some(SEED_FORMAT_AGE_SCRYPT_V1.into()),
            seed_fingerprint: Some(fingerprint),
            device_version: None,
            account_index: req.account_index,
            ufvk: None,
            label: req.label,
        };
        self.write_profile(dir, key_id, &profile)?;
        Ok(KeyEntry {
            profile,
            dir: dir.to_path_buf(),
            params: self.params,
            wallet: Some(Mutex::new(wallet)),
        })
    }

    /// Encrypt and write `seed.age`; returns the hex ZIP 32 seed fingerprint.
    fn write_seed(
        &self,
        dir: &Path,
        key_id: &str,
        entropy: &Entropy,
        passphrase: SecretString,
    ) -> Result<String, RegistryError> {
        let vault_err = |source| RegistryError::Vault {
            key_id: key_id.to_string(),
            source,
        };
        let armored =
            vault::seal(entropy, passphrase, self.scrypt_work_factor).map_err(vault_err)?;
        vault::write_new(&dir.join(SEED_FILE), &armored).map_err(vault_err)?;
        let seed = vault::seed_from_entropy(entropy);
        let fp = SeedFingerprint::from_seed(seed.expose_secret())
            .ok_or_else(|| RegistryError::Invalid("seed length out of range".into()))?;
        Ok(hex::encode(fp.to_bytes()))
    }

    fn write_profile(
        &self,
        dir: &Path,
        key_id: &str,
        profile: &KeyProfile,
    ) -> Result<(), RegistryError> {
        let with_key = |source| RegistryError::Profile {
            key_id: key_id.to_string(),
            source,
        };
        profile.validate(self.network, key_id).map_err(with_key)?;
        profile.save(&dir.join(PROFILE_FILE)).map_err(with_key)
    }

    /// Register a fully written key, or remove the directory of a failed one.
    fn finish_create(
        &self,
        dir: PathBuf,
        result: Result<KeyEntry, RegistryError>,
    ) -> Result<Arc<KeyEntry>, RegistryError> {
        match result {
            Ok(entry) => {
                // Everything the daemon just wrote must pass the same sweep a
                // restart would run.
                perms::check_tree(&dir)?;
                let entry = Arc::new(entry);
                self.keys
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(entry.key_id().to_string(), entry.clone());
                tracing::info!(key_id = entry.key_id(), mode = %entry.profile.signing_mode, "key created");
                Ok(entry)
            }
            Err(e) => {
                if let Err(rm) = std::fs::remove_dir_all(&dir) {
                    tracing::warn!(path = %dir.display(), error = %rm, "could not remove the failed key directory");
                }
                Err(e)
            }
        }
    }
}

fn wallet_error(key_id: &str, e: impl fmt::Display) -> RegistryError {
    RegistryError::Wallet {
        key_id: key_id.to_string(),
        detail: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::birthday::resolve;
    use std::os::unix::fs::MetadataExt as _;

    const LOG_N: u8 = 10;

    fn home() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        perms::set_mode(dir.path(), 0o700).unwrap();
        let home = Home::new(dir.path());
        (dir, home)
    }

    fn config(default_key: &str) -> Config {
        let mut c = Config {
            default_key: default_key.into(),
            ..Config::default()
        };
        c.vault.scrypt_work_factor = LOG_N;
        c
    }

    fn pass() -> SecretString {
        SecretString::from("pw".to_string())
    }

    async fn birthday() -> ResolvedBirthday {
        resolve(Network::Regtest, None, Some(1)).await.unwrap()
    }

    fn zero_entropy() -> Entropy {
        vault::entropy_from_phrase(&("abandon ".repeat(23) + "art")).unwrap()
    }

    #[tokio::test]
    async fn create_reload_and_resolve() {
        let (_tmp, home) = home();
        let reg = KeyRegistry::open(home.clone(), Network::Regtest, &config("main")).unwrap();
        assert!(reg.list().is_empty());
        assert!(matches!(reg.resolve(""), Err(RegistryError::NotFound(_))));

        let b = birthday().await;
        let entropy = zero_entropy();
        let key = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "main",
                entropy: &entropy,
                passphrase: pass(),
                birthday: &b,
                account_index: 0,
                label: Some("Main".into()),
            })
            .unwrap();
        assert_eq!(key.key_id(), "main");
        assert_eq!(key.profile().birthday_height, Some(1));
        assert_eq!(key.scanned_tip(), 0);
        let ufvk = key.ufvk().expect("ufvk");
        assert!(ufvk.starts_with("uviewregtest1"), "{ufvk}");

        let dir = home.key_dir(Network::Regtest, "main");
        for f in [PROFILE_FILE, SEED_FILE, WALLET_FILE] {
            let m = std::fs::metadata(dir.join(f)).unwrap();
            assert_eq!(m.mode() & 0o777, 0o600, "{f}");
        }
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // The seed file opens with the passphrase and holds the entropy.
        let armored = std::fs::read(dir.join(SEED_FILE)).unwrap();
        let back = vault::open(&armored, pass(), LOG_N).unwrap();
        assert_eq!(back.expose_secret(), entropy.expose_secret());

        // Resolution: default, explicit, unknown.
        assert_eq!(reg.resolve("").unwrap().key_id(), "main");
        assert_eq!(reg.resolve("main").unwrap().key_id(), "main");
        assert!(matches!(
            reg.resolve("nope"),
            Err(RegistryError::NotFound(_))
        ));

        // Duplicate and invalid ids are refused without touching the disk.
        let err = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "main",
                entropy: &entropy,
                passphrase: pass(),
                birthday: &b,
                account_index: 0,
                label: None,
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::Exists(_)), "{err}");
        let err = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "Main",
                entropy: &entropy,
                passphrase: pass(),
                birthday: &b,
                account_index: 0,
                label: None,
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::InvalidKeyId(_)), "{err}");
        // Nothing but `main` on disk (checked by count: the host filesystem
        // may be case-insensitive, so `Main` would alias `main`).
        assert_eq!(
            std::fs::read_dir(home.keys_dir(Network::Regtest))
                .unwrap()
                .count(),
            1
        );

        // A second registry over the same home loads it back identically.
        drop(reg);
        let reg = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap();
        assert_eq!(reg.key_ids(), ["main"]);
        let key = reg.resolve("main").unwrap();
        assert_eq!(key.ufvk().as_deref(), Some(ufvk.as_str()));
        assert_eq!(key.profile().seed_fingerprint.as_ref().unwrap().len(), 64);
        assert!(matches!(reg.resolve(""), Err(RegistryError::NoDefault)));
        reg.set_default_key("main").unwrap();
        assert_eq!(reg.resolve("").unwrap().key_id(), "main");
        assert!(reg.set_default_key("nope").is_err());
    }

    #[tokio::test]
    async fn same_seed_gives_same_ufvk_and_fingerprint() {
        let (_tmp, home) = home();
        let reg = KeyRegistry::open(home, Network::Regtest, &config("")).unwrap();
        let b = birthday().await;
        let entropy = zero_entropy();
        let a = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "a",
                entropy: &entropy,
                passphrase: pass(),
                birthday: &b,
                account_index: 0,
                label: None,
            })
            .unwrap();
        let again = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "b",
                entropy: &entropy,
                passphrase: SecretString::from("other".to_string()),
                birthday: &b,
                account_index: 0,
                label: None,
            })
            .unwrap();
        assert_eq!(a.ufvk(), again.ufvk());
        assert_eq!(
            a.profile().seed_fingerprint,
            again.profile().seed_fingerprint
        );
        let other = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "c",
                entropy: &vault::generate_entropy(),
                passphrase: pass(),
                birthday: &b,
                account_index: 0,
                label: None,
            })
            .unwrap();
        assert_ne!(a.ufvk(), other.ufvk());
        assert_eq!(reg.key_ids(), ["a", "b", "c"]);
    }

    #[test]
    fn signer_only_has_seed_and_profile_only() {
        let (_tmp, home) = home();
        let reg = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap();
        let key = reg
            .create_signer_only("box", &zero_entropy(), pass(), None)
            .unwrap();
        assert!(key.wallet().is_none());
        assert_eq!(key.ufvk(), None);
        assert_eq!(key.profile().birthday_height, None);
        let dir = home.key_dir(Network::Regtest, "box");
        assert!(dir.join(SEED_FILE).is_file());
        assert!(!dir.join(WALLET_FILE).exists());
        let reg = KeyRegistry::open(home, Network::Regtest, &config("")).unwrap();
        assert_eq!(
            reg.resolve("box").unwrap().profile().signing_mode,
            SigningMode::SignerOnly
        );
    }

    #[test]
    fn broken_key_directories_refuse_to_load() {
        let (_tmp, home) = home();
        let keys = home.keys_dir(Network::Regtest);
        // An invalid directory name.
        perms::ensure_private_dir(&keys.join("Bad Name")).unwrap();
        let err = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap_err();
        assert!(matches!(err, RegistryError::Invalid(_)), "{err}");
        std::fs::remove_dir(keys.join("Bad Name")).unwrap();

        // A valid name without a profile.
        perms::ensure_private_dir(&keys.join("empty")).unwrap();
        let err = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap_err();
        assert!(matches!(err, RegistryError::Profile { .. }), "{err}");

        // A profile for another network.
        let p = KeyProfile {
            schema_version: profile::SCHEMA_VERSION,
            key_id: "empty".into(),
            network: Network::Mainnet,
            signing_mode: SigningMode::SignerOnly,
            birthday_height: None,
            created_at: profile::now_rfc3339(),
            spend_pools: vec![Pool::Orchard],
            receive_pools: vec![],
            seed_format: Some(SEED_FORMAT_AGE_SCRYPT_V1.into()),
            seed_fingerprint: Some("00".repeat(32)),
            device_version: None,
            account_index: 0,
            ufvk: None,
            label: None,
        };
        p.save(&keys.join("empty").join(PROFILE_FILE)).unwrap();
        let err = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::Profile {
                    source: ProfileError::NetworkMismatch { .. },
                    ..
                }
            ),
            "{err}"
        );

        // Right network but the seed file is missing.
        KeyProfile {
            network: Network::Regtest,
            ..p
        }
        .save(&keys.join("empty").join(PROFILE_FILE))
        .unwrap();
        let err = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::MissingFile {
                    file: SEED_FILE,
                    ..
                }
            ),
            "{err}"
        );

        // Too-wide permissions on a key file.
        std::fs::write(keys.join("empty").join(SEED_FILE), "x").unwrap();
        perms::set_mode(&keys.join("empty").join(SEED_FILE), 0o644).unwrap();
        let err = KeyRegistry::open(home, Network::Regtest, &config("")).unwrap_err();
        assert!(matches!(err, RegistryError::Permission(_)), "{err}");
    }

    #[tokio::test]
    async fn failed_creation_leaves_no_directory() {
        let (_tmp, home) = home();
        let reg = KeyRegistry::open(home.clone(), Network::Regtest, &config("")).unwrap();
        let b = birthday().await;
        let err = reg
            .create_local_seed(NewLocalSeedKey {
                key_id: "k",
                entropy: &zero_entropy(),
                passphrase: pass(),
                birthday: &b,
                account_index: u32::MAX,
                label: None,
            })
            .unwrap_err();
        assert!(matches!(err, RegistryError::Invalid(_)), "{err}");
        assert!(!home.key_dir(Network::Regtest, "k").exists());
        assert!(reg.list().is_empty());
    }
}
