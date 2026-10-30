//! `gyges-core` and `gyges-chain` errors → the typed `GygesError` the CLI
//! dispatches on (docs/interface.md API §3).

use gyges_chain::ChainError;
use gyges_core::vault::{self, VaultError};
use gyges_core::{BirthdayError, RegistryError, TxError};
use gyges_proto::v1::{ErrorReason, GygesError};
use tonic::Status;

/// A `gyges-core` failure as the key's typed status: `.for_key(&key_id)?`.
pub(crate) trait ForKey<T> {
    fn for_key(self, key_id: &str) -> Result<T, Status>;
}

impl<T> ForKey<T> for Result<T, TxError> {
    fn for_key(self, key_id: &str) -> Result<T, Status> {
        self.map_err(|e| tx_error(e, key_id).into_status())
    }
}

impl<T> ForKey<T> for Result<T, VaultError> {
    fn for_key(self, key_id: &str) -> Result<T, Status> {
        self.map_err(|e| vault_error(e, key_id).into_status())
    }
}

/// `TxError` → the typed error (docs/interface.md API §3).
pub(crate) fn tx_error(e: TxError, key_id: &str) -> GygesError {
    let err = match e {
        TxError::InsufficientFunds {
            available,
            required,
        } => GygesError::new(
            ErrorReason::InsufficientFunds,
            format!("insufficient funds: {available} zatoshis spendable, {required} needed"),
        ),
        TxError::NotSynced(detail) => GygesError::new(ErrorReason::NotSynced, detail),
        TxError::InvalidArgument(detail) => GygesError::new(ErrorReason::InvalidArgument, detail),
        TxError::UnsupportedPool(detail) => GygesError::new(ErrorReason::UnsupportedPool, detail),
        // A tampered or stale PCZT is the client's problem (exit 6), not a
        // daemon failure.
        TxError::Verifier(detail) => GygesError::new(ErrorReason::InvalidArgument, detail),
        TxError::Internal(detail) => {
            // Upstream error texts can quote addresses or values, so the
            // detail goes to the client and to `debug` only (docs/interface.md API §4.5).
            tracing::error!(key_id, "transaction engine failure");
            tracing::debug!(key_id, error = %detail, "transaction engine failure detail");
            GygesError::new(ErrorReason::Internal, detail)
        }
    };
    err.with_key(key_id)
}

pub(crate) fn broadcast_error(e: ChainError, key_id: &str) -> GygesError {
    match e {
        ChainError::Rejected(text) => {
            let mut err = GygesError::new(
                ErrorReason::NodeRejected,
                "the node rejected the transaction; it stays in the wallet as unmined until it expires",
            )
            .with_key(key_id);
            err.node_error = text;
            err
        }
        ChainError::Unreachable(detail) => {
            GygesError::new(ErrorReason::NodeUnreachable, detail).with_key(key_id)
        }
        other => GygesError::new(ErrorReason::Internal, other.to_string()).with_key(key_id),
    }
}

/// `VaultError` → typed error.
pub(crate) fn vault_error(e: VaultError, key_id: &str) -> GygesError {
    let err = match e {
        VaultError::WrongPassphrase => {
            GygesError::new(ErrorReason::InvalidPassphrase, "wrong passphrase")
        }
        VaultError::RateLimited(wait) => GygesError::new(
            ErrorReason::RateLimited,
            format!(
                "too many failed unlock attempts; retry in {}s",
                wait.as_secs().max(1)
            ),
        ),
        VaultError::Locked => GygesError::new(
            ErrorReason::VaultLocked,
            "the key is locked; run `gyges key unlock` or pass --passphrase-fd",
        ),
        VaultError::NoSeed => GygesError::new(
            ErrorReason::InvalidArgument,
            "this profile has no seed on disk and cannot be unlocked",
        ),
        other => {
            tracing::error!(error = %other, key_id, "vault failure");
            GygesError::new(ErrorReason::Internal, other.to_string())
        }
    };
    err.with_key(key_id)
}

/// `RegistryError` → the typed error the CLI dispatches on.
pub(crate) fn registry_error(e: RegistryError) -> GygesError {
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

/// `BirthdayError` → typed error. `BelowRetention` maps to
/// `FALLBACK_UNAVAILABLE` (no fallback endpoint); callers that can backfill
/// intercept it first and decide on `allow_backfill` (`below_retention`).
pub(crate) fn birthday_error(e: BirthdayError) -> GygesError {
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
                 and no fallback endpoint is configured; enable [fallback_lightwalletd] to backfill \
                 the blocks below the window, or restore with a later birthday"
            ),
        ),
        BirthdayError::Fallback(e) => GygesError::new(
            ErrorReason::FallbackUnavailable,
            format!("the fallback endpoint cannot serve the birthday's tree state: {e}"),
        ),
        e @ BirthdayError::FallbackMismatch { .. } => {
            GygesError::new(ErrorReason::FallbackUnavailable, e.to_string())
        }
        BirthdayError::Chain(
            ChainError::Unreachable(detail)
            | ChainError::Rpc(detail)
            | ChainError::Rejected(detail),
        ) => GygesError::new(ErrorReason::NodeUnreachable, detail),
        BirthdayError::Chain(
            e @ (ChainError::TreeStateUnavailable { .. } | ChainError::BlockUnavailable { .. }),
        ) => GygesError::new(ErrorReason::FallbackUnavailable, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_errors_map_to_the_documented_reasons() {
        assert_eq!(
            tx_error(
                TxError::InsufficientFunds {
                    available: 1,
                    required: 2
                },
                "k"
            )
            .reason(),
            ErrorReason::InsufficientFunds
        );
        assert_eq!(
            tx_error(TxError::NotSynced("x".into()), "k").reason(),
            ErrorReason::NotSynced
        );
        assert_eq!(
            tx_error(TxError::UnsupportedPool("x".into()), "k").reason(),
            ErrorReason::UnsupportedPool
        );
        let e = broadcast_error(ChainError::Rejected("tx-expired".into()), "k");
        assert_eq!(e.reason(), ErrorReason::NodeRejected);
        assert_eq!(e.node_error, "tx-expired");
        assert_eq!(
            broadcast_error(ChainError::Unreachable("down".into()), "k").reason(),
            ErrorReason::NodeUnreachable
        );
    }

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
