//! `VaultManager` (ARCHITECTURE.md §2.1, §3.2; API.md §6.3; OVERVIEW.md
//! Q-S1…S3): decrypts `seed.age`, keeps the entropy in RAM for exactly as
//! long as an unlock allows, and rate-limits failed passphrases.
//!
//! Two unlock scopes exist:
//!
//! * **connection** – bound to the calling socket connection and to a
//!   32-byte token returned once; usable only when both match, dies when the
//!   connection closes or the idle timer runs out;
//! * **daemon** – no token; any admitted client may use the key until the
//!   idle timer runs out or `lock` is called. The weaker mode, for scripts.
//!
//! Every use refreshes the idle timer. Decrypted material is
//! `secrecy::Secret` (zeroized on drop); locking, expiry, connection close
//! and daemon shutdown all drop it. Failed unlocks back off exponentially
//! **per key id**, so a new connection does not reset the clock (Q-S2).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use age::secrecy::SecretString;

use super::{Entropy, VaultError};
use crate::config::VaultConfig;
use crate::registry::KeyEntry;

/// Identifies one socket connection for the lifetime of the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// The token a connection-scoped unlock returns. Compared in constant time;
/// never printed.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Token([u8; 32]);

impl Token {
    fn random() -> Self {
        use rand::Rng as _;
        let mut t = [0u8; 32];
        rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut t);
        Self(t)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse the bytes a client sent back; anything but 32 bytes is no token.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }

    fn matches(&self, other: &Token) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([redacted])")
    }
}

/// Which kind of unlock to create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Connection(ConnId),
    Daemon,
}

/// How a caller proves it may use an unlocked key.
#[derive(Clone, Debug)]
pub enum Auth<'a> {
    /// A connection-scoped token presented on connection `conn`.
    Token { conn: ConnId, token: &'a Token },
    /// No token: only a daemon-scoped unlock qualifies.
    Daemon,
}

/// What an unlock returns.
#[derive(Clone, Debug)]
pub struct Unlocked {
    /// Present for connection scope only.
    pub token: Option<Token>,
    pub expires_at: SystemTime,
    pub scope: Scope,
}

/// What `list` reports per key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockState {
    pub key_id: String,
    pub scope: Scope,
    pub expires_at: SystemTime,
}

struct Unlock {
    key_id: String,
    scope: Scope,
    token: Option<Token>,
    entropy: Entropy,
    idle: Duration,
    last_used: Instant,
}

impl Unlock {
    fn expires(&self) -> Instant {
        self.last_used + self.idle
    }

    fn expired(&self, now: Instant) -> bool {
        now >= self.expires()
    }

    fn expires_at_system(&self, now: Instant) -> SystemTime {
        SystemTime::now() + self.expires().saturating_duration_since(now)
    }
}

/// Per-key failed-attempt state.
#[derive(Clone, Copy, Debug)]
struct Backoff {
    failures: u32,
    until: Instant,
}

#[derive(Default)]
struct Inner {
    unlocks: Vec<Unlock>,
    backoff: HashMap<String, Backoff>,
}

/// See the module documentation.
pub struct VaultManager {
    unlock_ttl: Duration,
    backoff_max: Duration,
    max_work_factor: u8,
    allow_seed_export: bool,
    inner: Mutex<Inner>,
}

impl fmt::Debug for VaultManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("VaultManager")
            .field("unlock_ttl", &self.unlock_ttl)
            .field("unlocks", &inner.unlocks.len())
            .field("keys_in_backoff", &inner.backoff.len())
            .finish()
    }
}

/// First back-off step; doubles per failure up to `vault.unlock_backoff_max`.
const BACKOFF_BASE: Duration = Duration::from_secs(1);

impl VaultManager {
    pub fn new(config: &VaultConfig) -> Self {
        Self {
            unlock_ttl: config.unlock_ttl,
            backoff_max: config.unlock_backoff_max,
            // Files written by a stricter configuration still open; a header
            // asking for much more work than configured is refused.
            max_work_factor: config.scrypt_work_factor.saturating_add(2),
            allow_seed_export: config.allow_seed_export,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// `vault.unlock_ttl`.
    pub fn unlock_ttl(&self) -> Duration {
        self.unlock_ttl
    }

    /// `vault.allow_seed_export`.
    pub fn allow_seed_export(&self) -> bool {
        self.allow_seed_export
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Decrypt `seed.age` with `passphrase`, honouring the per-key back-off.
    /// The scrypt work runs outside the lock. On success the key's back-off
    /// state is cleared.
    pub fn verify_passphrase(
        &self,
        key: &KeyEntry,
        passphrase: SecretString,
    ) -> Result<Entropy, VaultError> {
        self.verify_passphrase_at(key, passphrase, Instant::now())
    }

    fn verify_passphrase_at(
        &self,
        key: &KeyEntry,
        passphrase: SecretString,
        now: Instant,
    ) -> Result<Entropy, VaultError> {
        if !key.profile().has_seed_file() {
            return Err(VaultError::NoSeed);
        }
        let key_id = key.key_id();
        {
            let inner = self.inner();
            if let Some(b) = inner.backoff.get(key_id)
                && now < b.until
            {
                return Err(VaultError::RateLimited(b.until - now));
            }
        }
        let armored = std::fs::read(key.seed_path()).map_err(|source| VaultError::Io {
            context: "reading seed.age",
            source,
        })?;
        match super::open(&armored, passphrase, self.max_work_factor) {
            Ok(entropy) => {
                self.inner().backoff.remove(key_id);
                Ok(entropy)
            }
            Err(VaultError::WrongPassphrase) => {
                let mut inner = self.inner();
                let failures = inner.backoff.get(key_id).map_or(0, |b| b.failures) + 1;
                let delay = BACKOFF_BASE
                    .checked_mul(1u32 << (failures - 1).min(31))
                    .unwrap_or(self.backoff_max)
                    .min(self.backoff_max);
                inner.backoff.insert(
                    key_id.to_string(),
                    Backoff {
                        failures,
                        until: now + delay,
                    },
                );
                tracing::warn!(key_id, failures, "unlock failed");
                Err(VaultError::WrongPassphrase)
            }
            Err(e) => Err(e),
        }
    }

    /// Create an unlock. `ttl` of `None` means `vault.unlock_ttl`. A daemon
    /// unlock replaces an existing daemon unlock of the same key.
    pub fn unlock(
        &self,
        key: &KeyEntry,
        passphrase: SecretString,
        scope: Scope,
        ttl: Option<Duration>,
    ) -> Result<Unlocked, VaultError> {
        self.unlock_at(key, passphrase, scope, ttl, Instant::now())
    }

    fn unlock_at(
        &self,
        key: &KeyEntry,
        passphrase: SecretString,
        scope: Scope,
        ttl: Option<Duration>,
        now: Instant,
    ) -> Result<Unlocked, VaultError> {
        let entropy = self.verify_passphrase_at(key, passphrase, now)?;
        let idle = ttl.filter(|d| !d.is_zero()).unwrap_or(self.unlock_ttl);
        let token = matches!(scope, Scope::Connection(_)).then(Token::random);
        let unlock = Unlock {
            key_id: key.key_id().to_string(),
            scope,
            token: token.clone(),
            entropy,
            idle,
            last_used: now,
        };
        let expires_at = unlock.expires_at_system(now);
        let mut inner = self.inner();
        inner.evict_expired(now);
        if scope == Scope::Daemon {
            inner
                .unlocks
                .retain(|u| !(u.key_id == key.key_id() && u.scope == Scope::Daemon));
        }
        inner.unlocks.push(unlock);
        tracing::info!(
            key_id = key.key_id(),
            ?scope,
            idle_secs = idle.as_secs(),
            "key unlocked"
        );
        Ok(Unlocked {
            token,
            expires_at,
            scope,
        })
    }

    /// Run `f` with the entropy of an unlock that `auth` is entitled to,
    /// refreshing its idle timer. `Err(Locked)` when there is none.
    pub fn with_entropy<T>(
        &self,
        key_id: &str,
        auth: Auth<'_>,
        f: impl FnOnce(&Entropy) -> T,
    ) -> Result<T, VaultError> {
        self.with_entropy_at(key_id, auth, Instant::now(), f)
    }

    fn with_entropy_at<T>(
        &self,
        key_id: &str,
        auth: Auth<'_>,
        now: Instant,
        f: impl FnOnce(&Entropy) -> T,
    ) -> Result<T, VaultError> {
        let mut inner = self.inner();
        inner.evict_expired(now);
        let unlock = inner.unlocks.iter_mut().find(|u| {
            u.key_id == key_id
                && match (&auth, u.scope, &u.token) {
                    (Auth::Token { conn, token }, Scope::Connection(c), Some(t)) => {
                        *conn == c && t.matches(token)
                    }
                    // A token holder may also use a daemon-wide unlock.
                    (_, Scope::Daemon, _) => true,
                    _ => false,
                }
        });
        match unlock {
            Some(u) => {
                u.last_used = now;
                Ok(f(&u.entropy))
            }
            None => Err(VaultError::Locked),
        }
    }

    /// Drop every unlock of `key_id`. Returns whether there was one.
    pub fn lock(&self, key_id: &str) -> bool {
        let mut inner = self.inner();
        let before = inner.unlocks.len();
        inner.unlocks.retain(|u| u.key_id != key_id);
        let removed = inner.unlocks.len() != before;
        if removed {
            tracing::info!(key_id, "key locked");
        }
        removed
    }

    /// Drop every unlock (`daemon stop`, `key lock --all`). Returns the ids
    /// that were unlocked, sorted and deduplicated.
    pub fn lock_all(&self) -> Vec<String> {
        let mut inner = self.inner();
        let mut ids: Vec<String> = inner.unlocks.drain(..).map(|u| u.key_id).collect();
        ids.sort();
        ids.dedup();
        if !ids.is_empty() {
            tracing::info!(keys = ids.len(), "all keys locked");
        }
        ids
    }

    /// Drop every unlock bound to a connection that closed.
    pub fn connection_closed(&self, conn: ConnId) {
        let mut inner = self.inner();
        let before = inner.unlocks.len();
        inner.unlocks.retain(|u| u.scope != Scope::Connection(conn));
        let dropped = before - inner.unlocks.len();
        if dropped > 0 {
            tracing::debug!(conn = conn.0, dropped, "connection closed; unlocks dropped");
        }
    }

    /// Zeroize unlocks whose idle timer ran out (a periodic sweep; every
    /// other entry point also evicts lazily).
    pub fn evict_expired(&self) {
        self.inner().evict_expired(Instant::now());
    }

    /// Daemon-scoped unlocks, the only ones visible to other clients
    /// (API.md §6.3: `key list` shows the window).
    pub fn daemon_unlocks(&self) -> Vec<UnlockState> {
        self.daemon_unlocks_at(Instant::now())
    }

    fn daemon_unlocks_at(&self, now: Instant) -> Vec<UnlockState> {
        let mut inner = self.inner();
        inner.evict_expired(now);
        inner
            .unlocks
            .iter()
            .filter(|u| u.scope == Scope::Daemon)
            .map(|u| UnlockState {
                key_id: u.key_id.clone(),
                scope: u.scope,
                expires_at: u.expires_at_system(now),
            })
            .collect()
    }

    /// Number of live unlocks of any scope (tests, `Debug`).
    pub fn unlock_count(&self) -> usize {
        let mut inner = self.inner();
        inner.evict_expired(Instant::now());
        inner.unlocks.len()
    }
}

impl Inner {
    fn evict_expired(&mut self, now: Instant) {
        let before = self.unlocks.len();
        self.unlocks.retain(|u| !u.expired(now));
        let evicted = before - self.unlocks.len();
        if evicted > 0 {
            tracing::info!(evicted, "unlocks expired");
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;
    use crate::config::Config;
    use crate::network::Network;
    use crate::paths::Home;
    use crate::perms;
    use crate::registry::KeyRegistry;
    use std::sync::Arc;

    const LOG_N: u8 = 10;

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    fn setup() -> (tempfile::TempDir, Arc<KeyEntry>, VaultManager, Entropy) {
        let dir = tempfile::tempdir().unwrap();
        perms::set_mode(dir.path(), 0o700).unwrap();
        let mut cfg = Config::default();
        cfg.vault.scrypt_work_factor = LOG_N;
        cfg.vault.unlock_ttl = Duration::from_secs(300);
        cfg.vault.unlock_backoff_max = Duration::from_secs(8);
        let reg = KeyRegistry::open(Home::new(dir.path()), Network::Regtest, &cfg).unwrap();
        let entropy = super::super::generate_entropy();
        let key = reg
            .create_signer_only("k", &entropy, pass("pw"), None)
            .unwrap();
        let vault = VaultManager::new(&cfg.vault);
        (dir, key, vault, entropy)
    }

    /// Whether `auth` reaches key `k`'s entropy at `t`.
    fn can_use(vault: &VaultManager, auth: Auth<'_>, t: Instant) -> bool {
        match vault.with_entropy_at("k", auth, t, |_| ()) {
            Ok(()) => true,
            Err(VaultError::Locked) => false,
            Err(e) => panic!("{e:?}"),
        }
    }

    /// The wait the right passphrase is refused with at `t`.
    fn rate_limited(vault: &VaultManager, key: &KeyEntry, t: Instant) -> Duration {
        match vault.unlock_at(key, pass("pw"), Scope::Daemon, None, t) {
            Err(VaultError::RateLimited(d)) => d,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn daemon_unlock_is_usable_without_a_token_until_locked_or_expired() {
        let (_d, key, vault, entropy) = setup();
        let t0 = Instant::now();
        assert!(!can_use(&vault, Auth::Daemon, t0));
        let u = vault
            .unlock_at(&key, pass("pw"), Scope::Daemon, None, t0)
            .unwrap();
        assert!(u.token.is_none());
        assert_eq!(u.scope, Scope::Daemon);
        let seen = vault
            .with_entropy_at("k", Auth::Daemon, t0 + Duration::from_secs(10), |e| {
                *e.expose_secret()
            })
            .unwrap();
        assert_eq!(&seen, entropy.expose_secret());
        assert_eq!(vault.daemon_unlocks_at(t0).len(), 1);
        assert_eq!(vault.daemon_unlocks_at(t0)[0].key_id, "k");

        // Use refreshed the timer: 10 + 300 s from t0 is still inside.
        assert!(can_use(&vault, Auth::Daemon, t0 + Duration::from_secs(305)));
        // Idle for the full TTL: gone.
        assert!(!can_use(
            &vault,
            Auth::Daemon,
            t0 + Duration::from_secs(700)
        ));
        assert_eq!(vault.unlock_count(), 0);

        vault
            .unlock_at(
                &key,
                pass("pw"),
                Scope::Daemon,
                Some(Duration::from_secs(60)),
                t0,
            )
            .unwrap();
        assert!(vault.lock("k"));
        assert!(!vault.lock("k"));
        assert!(!can_use(&vault, Auth::Daemon, t0));
    }

    #[test]
    fn connection_unlock_needs_the_token_on_the_same_connection() {
        let (_d, key, vault, _e) = setup();
        let t0 = Instant::now();
        let a = ConnId(1);
        let b = ConnId(2);
        let u = vault
            .unlock_at(&key, pass("pw"), Scope::Connection(a), None, t0)
            .unwrap();
        let token = u.token.clone().expect("token");
        assert_eq!(token.as_bytes().len(), 32);
        assert!(can_use(
            &vault,
            Auth::Token {
                conn: a,
                token: &token
            },
            t0
        ));
        // Another connection with the stolen token: no.
        assert!(!can_use(
            &vault,
            Auth::Token {
                conn: b,
                token: &token
            },
            t0
        ));
        // Same connection, wrong token: no.
        let wrong = Token::random();
        assert!(!can_use(
            &vault,
            Auth::Token {
                conn: a,
                token: &wrong
            },
            t0
        ));
        // No token at all: no (it is not daemon-scoped).
        assert!(!can_use(&vault, Auth::Daemon, t0));
        assert!(
            vault.daemon_unlocks_at(t0).is_empty(),
            "not shown as unlocked"
        );
        // The connection closes: the unlock goes with it.
        vault.connection_closed(a);
        assert_eq!(vault.unlock_count(), 0);
        assert!(!can_use(
            &vault,
            Auth::Token {
                conn: a,
                token: &token
            },
            t0
        ));
    }

    #[test]
    fn wrong_passphrases_back_off_per_key_and_reset_on_success() {
        let (_d, key, vault, _e) = setup();
        let t0 = Instant::now();
        assert!(matches!(
            vault.unlock_at(&key, pass("nope"), Scope::Daemon, None, t0),
            Err(VaultError::WrongPassphrase)
        ));
        // Immediately after: rate limited for ~1 s, even with the right one.
        assert_eq!(rate_limited(&vault, &key, t0), Duration::from_secs(1));
        // After the wait, a second failure doubles the delay.
        let t1 = t0 + Duration::from_secs(1);
        assert!(matches!(
            vault.unlock_at(&key, pass("nope"), Scope::Daemon, None, t1),
            Err(VaultError::WrongPassphrase)
        ));
        assert_eq!(rate_limited(&vault, &key, t1), Duration::from_secs(2));
        // Keeps doubling, capped at unlock_backoff_max (8 s here).
        let mut t = t1 + Duration::from_secs(2);
        for expected in [4u64, 8, 8] {
            assert!(
                vault
                    .unlock_at(&key, pass("nope"), Scope::Daemon, None, t)
                    .is_err()
            );
            assert_eq!(rate_limited(&vault, &key, t), Duration::from_secs(expected));
            t += Duration::from_secs(expected);
        }
        // Success clears the state.
        vault
            .unlock_at(&key, pass("pw"), Scope::Daemon, None, t)
            .unwrap();
        assert!(
            vault
                .unlock_at(&key, pass("nope"), Scope::Daemon, None, t)
                .is_err()
        );
        assert_eq!(rate_limited(&vault, &key, t), Duration::from_secs(1));
    }

    #[test]
    fn lock_all_and_daemon_unlock_replacement() {
        let (_d, key, vault, _e) = setup();
        let t0 = Instant::now();
        vault
            .unlock_at(
                &key,
                pass("pw"),
                Scope::Daemon,
                Some(Duration::from_secs(5)),
                t0,
            )
            .unwrap();
        vault
            .unlock_at(
                &key,
                pass("pw"),
                Scope::Daemon,
                Some(Duration::from_secs(50)),
                t0,
            )
            .unwrap();
        vault
            .unlock_at(&key, pass("pw"), Scope::Connection(ConnId(9)), None, t0)
            .unwrap();
        assert_eq!(
            vault.unlock_count(),
            2,
            "one daemon (replaced) + one connection"
        );
        let shown = vault.daemon_unlocks_at(t0);
        assert_eq!(shown.len(), 1);
        assert_eq!(vault.lock_all(), ["k"]);
        assert_eq!(vault.unlock_count(), 0);
        assert!(vault.lock_all().is_empty());
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = Token::random();
        assert_eq!(format!("{t:?}"), "Token([redacted])");
        assert!(Token::from_slice(&[0u8; 31]).is_none());
        assert!(Token::from_slice(t.as_bytes()).unwrap().matches(&t));
    }
}
