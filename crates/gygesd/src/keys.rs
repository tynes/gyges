//! The key RPCs (`ListKeys`, `InitKey`, `RestoreKey`) and the mapping from
//! `gyges-core` errors to `GygesError` (API.md §3, §4).
//!
//! Passphrases and mnemonics arrive as plain strings in the request message
//! (`[debug_redact]` in the proto keeps them out of `Debug` output). They are
//! moved into zeroizing wrappers as the first thing each handler does and
//! never appear in a log line or an error detail.

use std::sync::Arc;

use age::secrecy::SecretString;
use gyges_chain::ChainError;
use gyges_core::registry::NewLocalSeedKey;
use gyges_core::{BirthdayError, KeyEntry, RegistryError, SigningMode, birthday, vault};
use gyges_proto::v1::{
    self, ErrorReason, GygesError, InitKeyRequest, InitKeyResponse, KeySummary, RestoreKeyRequest,
    RestoreKeyResponse,
};
use tonic::Status;
use zeroize::Zeroizing;

use crate::service::DaemonState;

/// `gyges_core::SigningMode` → wire enum.
pub fn proto_signing_mode(mode: SigningMode) -> v1::SigningMode {
    match mode {
        SigningMode::LocalSeed => v1::SigningMode::LocalSeed,
        SigningMode::KeystoneQr => v1::SigningMode::KeystoneQr,
        SigningMode::WatchOnly => v1::SigningMode::WatchOnly,
        SigningMode::SignerOnly => v1::SigningMode::SignerOnly,
    }
}

/// `gyges_core::Pool` → wire enum.
pub fn proto_pool(pool: gyges_core::Pool) -> v1::Pool {
    match pool {
        gyges_core::Pool::Transparent => v1::Pool::Transparent,
        gyges_core::Pool::Sapling => v1::Pool::Sapling,
        gyges_core::Pool::Orchard => v1::Pool::Orchard,
        gyges_core::Pool::Ironwood => v1::Pool::Ironwood,
    }
}

/// One `KeySummary` row. Every key reports `locked`: the vault sessions
/// that could say otherwise are the next ROADMAP.md item.
pub fn summary(entry: &KeyEntry, default_key: &str) -> KeySummary {
    let p = entry.profile();
    KeySummary {
        key_id: p.key_id.clone(),
        signing_mode: proto_signing_mode(p.signing_mode) as i32,
        is_default: p.key_id == default_key,
        locked: true,
        unlock_expires_at: 0,
        birthday_height: p.birthday_height.unwrap_or(0),
        scanned_tip: entry.scanned_tip(),
        spend_pools: p
            .spend_pools
            .iter()
            .map(|&x| proto_pool(x) as i32)
            .collect(),
        receive_pools: p
            .receive_pools
            .iter()
            .map(|&x| proto_pool(x) as i32)
            .collect(),
        device_version: p.device_version.clone().unwrap_or_default(),
        seed_fingerprint: p.seed_fingerprint.clone().unwrap_or_default(),
    }
}

/// Every key, sorted by id (`ListKeys`, `GetInfo.keys`).
pub fn summaries(state: &DaemonState) -> Vec<KeySummary> {
    let default = state.registry.default_key();
    state
        .registry
        .list()
        .iter()
        .map(|e| summary(e, &default))
        .collect()
}

/// `RegistryError` → the typed error the CLI dispatches on.
pub fn registry_error(e: RegistryError) -> GygesError {
    use RegistryError as R;
    match e {
        R::InvalidKeyId(id) => GygesError::new(
            ErrorReason::InvalidArgument,
            "key id must match ^[a-z0-9][a-z0-9_-]{0,31}$",
        )
        .with_key(id),
        R::Exists(id) => {
            GygesError::new(ErrorReason::KeyExists, "a key with this id already exists")
                .with_key(id)
        }
        R::NotFound(id) => GygesError::new(ErrorReason::KeyNotFound, "no such key").with_key(id),
        R::NoDefault => GygesError::new(ErrorReason::KeyNotFound, "no default key; pass --key"),
        R::Vault {
            key_id,
            source: vault::VaultError::WrongPassphrase,
        } => GygesError::new(ErrorReason::InvalidPassphrase, "wrong passphrase").with_key(key_id),
        R::Vault {
            key_id,
            source: vault::VaultError::Mnemonic(m),
        } => GygesError::new(
            ErrorReason::InvalidArgument,
            format!("invalid mnemonic: {m}"),
        )
        .with_key(key_id),
        R::Invalid(detail) => GygesError::new(ErrorReason::InvalidArgument, detail),
        other => {
            // Paths and SQLite messages, never key material.
            tracing::error!(error = %other, "key registry failure");
            GygesError::new(ErrorReason::Internal, other.to_string())
        }
    }
}

/// `BirthdayError` → typed error. `BelowRetention` is not mapped here: the
/// callers decide between `CONFIRMATION_REQUIRED` and `FALLBACK_UNAVAILABLE`
/// depending on `allow_backfill`.
pub fn birthday_error(e: BirthdayError) -> GygesError {
    match e {
        BirthdayError::NodeRequired(what) => GygesError::new(
            ErrorReason::NodeUnreachable,
            format!("a connected node is required to {what}"),
        ),
        BirthdayError::AboveTip { height, tip } => GygesError::new(
            ErrorReason::InvalidArgument,
            format!("birthday {height} is above the node's tip {tip}"),
        ),
        BirthdayError::BelowRetention {
            height,
            retained_from,
        } => GygesError::new(
            ErrorReason::FallbackUnavailable,
            format!(
                "birthday {height} is below the node's retention window (retained from {retained_from}) \
                 and historical restore over Tor is not implemented yet (ROADMAP.md M2)"
            ),
        ),
        BirthdayError::Chain(ChainError::Unreachable(detail) | ChainError::Rpc(detail)) => {
            GygesError::new(ErrorReason::NodeUnreachable, detail)
        }
        BirthdayError::Chain(e @ ChainError::TreeStateUnavailable { .. }) => {
            GygesError::new(ErrorReason::FallbackUnavailable, e.to_string())
        }
    }
}

fn invalid(detail: &str) -> Status {
    GygesError::new(ErrorReason::InvalidArgument, detail).into_status()
}

/// Move the passphrase out of the request into a zeroizing wrapper.
fn take_passphrase(passphrase: &mut String) -> Result<SecretString, Status> {
    let p = std::mem::take(passphrase);
    if p.is_empty() {
        return Err(invalid("a passphrase is required"));
    }
    Ok(SecretString::from(p))
}

fn require_key_id(key_id: &str) -> Result<(), Status> {
    if key_id.is_empty() {
        return Err(invalid("--id is required"));
    }
    Ok(())
}

/// Apply `set_default`, which lasts for this daemon's lifetime (the daemon
/// never rewrites `config.toml`, DATA_MODEL.md §7).
fn maybe_set_default(state: &DaemonState, key_id: &str, set_default: bool) {
    if set_default {
        if let Err(e) = state.registry.set_default_key(key_id) {
            tracing::warn!(error = %e, "set_default ignored");
        } else {
            tracing::warn!(
                key_id,
                "default key changed for this run only; set default_key in config.toml to persist it"
            );
        }
    }
}

/// `InitKey`: fresh 24-word entropy, `seed.age`, and either a `local-seed`
/// wallet born at the node's tip or, on an air-gapped daemon, a
/// `signer-only` profile with no wallet and no birthday.
pub async fn init_key(
    state: Arc<DaemonState>,
    mut req: InitKeyRequest,
) -> Result<InitKeyResponse, Status> {
    require_key_id(&req.key_id)?;
    if req.word_count != 0 && req.word_count != vault::WORD_COUNT {
        return Err(invalid("only 24-word mnemonics are supported"));
    }
    let passphrase = take_passphrase(&mut req.passphrase)?;
    let key_id = req.key_id.clone();
    let entropy = vault::generate_entropy();
    let mnemonic = vault::mnemonic_phrase(&entropy);

    let (entry, birthday_height) = if state.config.airgapped {
        let st = state.clone();
        let id = key_id.clone();
        let entry = tokio::task::spawn_blocking(move || {
            st.registry
                .create_signer_only(&id, &entropy, passphrase, None)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| registry_error(e).into_status())?;
        (entry, 0)
    } else {
        let birthday = birthday::resolve(state.network, state.chain.as_deref(), None)
            .await
            .map_err(|e| match e {
                BirthdayError::NodeRequired(_) => GygesError::new(
                    ErrorReason::NodeUnreachable,
                    "key init takes the birthday from the node's tip, and no node is connected; \
                     use `key restore --birthday` for a known seed, or `--airgapped` for a signer-only key",
                ),
                other => birthday_error(other),
            }
            .into_status())?;
        let height = birthday.height;
        let st = state.clone();
        let id = key_id.clone();
        let entry = tokio::task::spawn_blocking(move || {
            st.registry.create_local_seed(NewLocalSeedKey {
                key_id: &id,
                entropy: &entropy,
                passphrase,
                birthday: &birthday,
                account_index: 0,
                label: None,
            })
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| registry_error(e).into_status())?;
        (entry, height)
    };
    maybe_set_default(&state, &key_id, req.set_default);
    Ok(InitKeyResponse {
        key_id,
        mnemonic: mnemonic.to_string(),
        birthday_height,
        ufvk: entry.ufvk().unwrap_or_default(),
    })
}

/// `RestoreKey`: a known mnemonic with a birthday that the local node can
/// serve a tree state for. Below the node's retention window the restore
/// needs the Tor backfill of ROADMAP.md M2, so it is refused: with
/// `CONFIRMATION_REQUIRED` until the client has asked the user, then with
/// `FALLBACK_UNAVAILABLE`.
pub async fn restore_key(
    state: Arc<DaemonState>,
    mut req: RestoreKeyRequest,
) -> Result<RestoreKeyResponse, Status> {
    require_key_id(&req.key_id)?;
    let passphrase = take_passphrase(&mut req.passphrase)?;
    let phrase = Zeroizing::new(std::mem::take(&mut req.mnemonic));
    let entropy = vault::entropy_from_phrase(&phrase)
        .map_err(|e| invalid(&format!("invalid mnemonic: {e}")))?;
    drop(phrase);

    let requested = if req.birthday_height == 0 {
        state.network.sapling_activation_height()
    } else {
        req.birthday_height
    };
    let birthday = birthday::resolve(state.network, state.chain.as_deref(), Some(requested))
        .await
        .map_err(|e| match e {
            BirthdayError::BelowRetention {
                height,
                retained_from,
            } if !req.allow_backfill => GygesError::new(
                ErrorReason::ConfirmationRequired,
                format!(
                    "{} blocks below the node's retention height ({retained_from}) would have to be \
                     fetched from the fallback endpoint; confirm with --yes",
                    retained_from - height
                ),
            ),
            other => birthday_error(other),
        }
        .into_status())?;

    let key_id = req.key_id.clone();
    let height = birthday.height;
    let st = state.clone();
    let id = key_id.clone();
    let entry = tokio::task::spawn_blocking(move || {
        st.registry.create_local_seed(NewLocalSeedKey {
            key_id: &id,
            entropy: &entropy,
            passphrase,
            birthday: &birthday,
            account_index: 0,
            label: None,
        })
    })
    .await
    .map_err(|e| Status::internal(e.to_string()))?
    .map_err(|e| registry_error(e).into_status())?;
    maybe_set_default(&state, &key_id, req.set_default);
    Ok(RestoreKeyResponse {
        key_id,
        birthday_height: height,
        ufvk: entry.ufvk().unwrap_or_default(),
        backfill_blocks: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_errors_map_to_the_documented_reasons() {
        assert_eq!(
            registry_error(RegistryError::Exists("a".into())).reason(),
            ErrorReason::KeyExists
        );
        assert_eq!(
            registry_error(RegistryError::NotFound("a".into())).key_id,
            "a"
        );
        assert_eq!(
            registry_error(RegistryError::NoDefault).detail,
            "no default key; pass --key"
        );
        assert_eq!(
            registry_error(RegistryError::InvalidKeyId("A".into())).reason(),
            ErrorReason::InvalidArgument
        );
        assert_eq!(
            registry_error(RegistryError::Vault {
                key_id: "a".into(),
                source: vault::VaultError::WrongPassphrase
            })
            .reason(),
            ErrorReason::InvalidPassphrase
        );
        assert_eq!(
            birthday_error(BirthdayError::NodeRequired("x")).reason(),
            ErrorReason::NodeUnreachable
        );
        assert_eq!(
            birthday_error(BirthdayError::BelowRetention {
                height: 1,
                retained_from: 2
            })
            .reason(),
            ErrorReason::FallbackUnavailable
        );
    }
}
