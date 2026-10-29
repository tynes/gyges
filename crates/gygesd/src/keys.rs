//! The key RPCs (`ListKeys`, `InitKey`, `RestoreKey`, `ImportKeystone`,
//! `UnlockKey`, `LockKey`, `ExportUfvk`, `ExportSeed`) and the mapping from
//! `gyges-core` errors to `GygesError` (API.md §3, §4).
//!
//! Passphrases and mnemonics arrive as plain strings in the request message
//! (`[debug_redact]` in the proto keeps them out of `Debug` output). They are
//! moved into zeroizing wrappers as the first thing each handler does and
//! never appear in a log line or an error detail.

use std::sync::Arc;
use std::time::Duration;

use age::secrecy::SecretString;
use gyges_chain::ChainError;
use gyges_core::registry::{NewKeystoneKey, NewLocalSeedKey};
use gyges_core::vault::VaultError;
use gyges_core::vault::manager::{Auth, Scope, UnlockState};
use gyges_core::{
    BirthdayError, KeyEntry, Network, RegistryError, ResolvedBirthday, SigningMode, birthday, vault,
};
use gyges_proto::v1::{
    self, ErrorReason, ExportSeedRequest, ExportSeedResponse, ExportUfvkRequest,
    ExportUfvkResponse, GygesError, ImportKeystoneRequest, ImportKeystoneResponse, InitKeyRequest,
    InitKeyResponse, KeySummary, LockKeyRequest, LockKeyResponse, RestoreKeyRequest,
    RestoreKeyResponse, UnlockKeyRequest, UnlockKeyResponse, UnlockScope,
};
use gyges_qr::{Assembler, Payload};
use tonic::Status;
use zcash_keys::keys::UnifiedFullViewingKey;
use zeroize::Zeroizing;
use zip32::fingerprint::SeedFingerprint;

use crate::conn::ConnInfo;
use crate::service::{DaemonState, invalid};

/// Security-relevant events, key id and time only (OVERVIEW.md Q-O1). The
/// target is how `logs` routes them to `audit.log`.
pub const AUDIT_TARGET: &str = "gyges::audit";

/// The literal `ExportSeed.confirmation` must equal (CLI_SPEC.md §2.2).
pub(crate) const REVEAL_SEED: &str = "reveal seed";

/// `gyges_core::SigningMode` → wire enum.
pub(crate) fn proto_signing_mode(mode: SigningMode) -> v1::SigningMode {
    match mode {
        SigningMode::LocalSeed => v1::SigningMode::LocalSeed,
        SigningMode::KeystoneQr => v1::SigningMode::KeystoneQr,
        SigningMode::WatchOnly => v1::SigningMode::WatchOnly,
        SigningMode::SignerOnly => v1::SigningMode::SignerOnly,
    }
}

/// `gyges_core::Pool` → wire enum.
pub(crate) fn proto_pool(pool: gyges_core::Pool) -> v1::Pool {
    match pool {
        gyges_core::Pool::Transparent => v1::Pool::Transparent,
        gyges_core::Pool::Sapling => v1::Pool::Sapling,
        gyges_core::Pool::Orchard => v1::Pool::Orchard,
        gyges_core::Pool::Ironwood => v1::Pool::Ironwood,
    }
}

fn proto_pools(pools: &[gyges_core::Pool]) -> Vec<i32> {
    pools.iter().map(|&p| proto_pool(p) as i32).collect()
}

/// One `KeySummary` row. `locked` is false only for a daemon-scoped unlock:
/// connection-scoped ones are usable by nobody else and are not shown
/// (API.md §6.3).
pub(crate) fn summary(entry: &KeyEntry, default_key: &str, unlocks: &[UnlockState]) -> KeySummary {
    let p = entry.profile();
    let unlock = unlocks.iter().find(|u| u.key_id == p.key_id);
    KeySummary {
        key_id: p.key_id.clone(),
        signing_mode: proto_signing_mode(p.signing_mode) as i32,
        is_default: p.key_id == default_key,
        locked: unlock.is_none(),
        unlock_expires_at: unlock.map_or(0, |u| gyges_core::profile::unix_secs(u.expires_at)),
        birthday_height: p.birthday_height.unwrap_or(0),
        scanned_tip: entry.scanned_tip(),
        spend_pools: proto_pools(&p.spend_pools),
        receive_pools: proto_pools(&p.receive_pools),
        device_version: p.device_version.clone().unwrap_or_default(),
        seed_fingerprint: p.seed_fingerprint.clone().unwrap_or_default(),
        transparent_best_effort_below: crate::backfill::load_report(entry)
            .map_or(0, |r| r.best_effort_below),
    }
}

/// Every key, sorted by id (`ListKeys`, `GetInfo.keys`).
pub(crate) fn summaries(state: &DaemonState) -> Vec<KeySummary> {
    let default = state.registry.default_key();
    let unlocks = state.vault.daemon_unlocks();
    state
        .registry
        .list()
        .iter()
        .map(|e| summary(e, &default, &unlocks))
        .collect()
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

/// Create a `local-seed` profile on a blocking thread.
async fn create_local_seed(
    state: &Arc<DaemonState>,
    key_id: &str,
    entropy: vault::Entropy,
    passphrase: SecretString,
    birthday: ResolvedBirthday,
) -> Result<Arc<KeyEntry>, Status> {
    let st = state.clone();
    let id = key_id.to_string();
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
    .map_err(registry_error)?;
    Ok(entry)
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
pub(crate) async fn init_key(
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
        .map_err(registry_error)?;
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
                BirthdayError::Chain(ChainError::Unreachable(detail)) => GygesError::new(
                    ErrorReason::NodeUnreachable,
                    format!(
                        "key init takes the birthday from the node's tip, and the node is unreachable ({detail}); \
                         use `key restore --birthday` for a known seed, or `--airgapped` for a signer-only key"
                    ),
                ),
                other => birthday_error(other),
            }
            .into_status())?;
        let height = birthday.height;
        let entry = create_local_seed(&state, &key_id, entropy, passphrase, birthday).await?;
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

/// `RestoreKey`: a known mnemonic and a birthday. Inside the node's
/// retention window the node serves the birthday's tree state. Below it the
/// blocks up to the window must come from the fallback endpoint (Case B,
/// SYNC.md §5): refused with `CONFIRMATION_REQUIRED` until the client has
/// asked the user (`allow_backfill`), then with `FALLBACK_UNAVAILABLE` when
/// no endpoint is configured or it is marked untrusted; otherwise the tree
/// state comes from the endpoint (its block hash checked against the node)
/// and the scheduler backfills and validates at the handoff.
pub(crate) async fn restore_key(
    state: Arc<DaemonState>,
    mut req: RestoreKeyRequest,
) -> Result<RestoreKeyResponse, Status> {
    require_key_id(&req.key_id)?;
    let passphrase = take_passphrase(&mut req.passphrase)?;
    let phrase = Zeroizing::new(std::mem::take(&mut req.mnemonic));
    let entropy = vault::entropy_from_phrase(&phrase)
        .map_err(|e| invalid(format!("invalid mnemonic: {e}")))?;
    drop(phrase);

    let requested = if req.birthday_height == 0 {
        state.network.sapling_activation_height()
    } else {
        req.birthday_height
    };
    let (birthday, backfill_blocks, warnings) =
        resolve_import_birthday(&state, requested, req.allow_backfill).await?;

    let key_id = req.key_id.clone();
    let height = birthday.height;
    let entry = create_local_seed(&state, &key_id, entropy, passphrase, birthday).await?;
    maybe_set_default(&state, &key_id, req.set_default);
    Ok(RestoreKeyResponse {
        key_id,
        birthday_height: height,
        ufvk: entry.ufvk().unwrap_or_default(),
        backfill_blocks,
        warnings,
    })
}

/// The birthday of a key whose history is known to exist (`RestoreKey`,
/// `ImportKeystone`): inside the node's window from the node, below it
/// through [`below_retention`], with the best-effort warning. Returns the
/// birthday, the blocks the backfill fetches, and the warnings.
async fn resolve_import_birthday(
    state: &DaemonState,
    requested: u32,
    allow_backfill: bool,
) -> Result<(ResolvedBirthday, u32, Vec<String>), Status> {
    match birthday::resolve(state.network, state.chain.as_deref(), Some(requested)).await {
        Ok(b) => Ok((b, 0, Vec::new())),
        Err(BirthdayError::BelowRetention {
            height,
            retained_from,
        }) => {
            let (b, n) = below_retention(state, height, retained_from, allow_backfill).await?;
            let warning = format!(
                "transparent history below height {retained_from} comes from the fallback \
                 endpoint and is best-effort: an output it leaves out cannot be detected \
                 (SYNC.md §5.3)"
            );
            Ok((b, n, vec![warning]))
        }
        Err(other) => Err(birthday_error(other).into_status()),
    }
}

/// `ImportKeystone` (ARCHITECTURE.md §3.4): a `keystone-qr` profile from the
/// device's `ur:zcash-accounts` export. Every check of the export runs
/// before the birthday is resolved and before anything is written, so a
/// refused export touches neither the node nor the disk.
pub(crate) async fn import_keystone(
    state: Arc<DaemonState>,
    req: ImportKeystoneRequest,
) -> Result<ImportKeystoneResponse, Status> {
    require_key_id(&req.key_id)?;
    let export = check_accounts_export(
        state.network,
        &req.payload,
        req.account_index,
        req.allow_unknown_firmware,
    )?;

    let requested = if req.birthday_height == 0 {
        state.network.nu5_activation_height()
    } else {
        req.birthday_height
    };
    let (birthday, backfill_blocks, mut warnings) =
        resolve_import_birthday(&state, requested, req.allow_backfill).await?;
    warnings.extend(export.warning.clone());

    let key_id = req.key_id.clone();
    let height = birthday.height;
    let st = state.clone();
    let (id, ex) = (key_id.clone(), export.clone());
    let entry = tokio::task::spawn_blocking(move || {
        st.registry.create_keystone(NewKeystoneKey {
            key_id: &id,
            ufvk: &ex.ufvk,
            seed_fingerprint: ex.seed_fingerprint,
            account_index: ex.account_index,
            device_version: ex.device_version.clone(),
            birthday: &birthday,
            label: ex.name.clone(),
        })
    })
    .await
    .map_err(|e| Status::internal(e.to_string()))?
    .map_err(registry_error)?;
    maybe_set_default(&state, &key_id, req.set_default);
    tracing::info!(
        key_id,
        account = u32::from(export.account_index),
        device_version = %export.device_version,
        birthday = height,
        "Keystone account imported"
    );
    let profile = entry.profile();
    Ok(ImportKeystoneResponse {
        key_id,
        seed_fingerprint: profile.seed_fingerprint.clone().unwrap_or_default(),
        device_version: export.device_version,
        ufvk: entry.ufvk().unwrap_or_default(),
        spend_pools: proto_pools(&profile.spend_pools),
        birthday_height: height,
        backfill_blocks,
        warnings,
        account_index: u32::from(export.account_index),
        account_name: export.name.unwrap_or_default(),
    })
}

/// A `zcash-accounts` export that passed every check.
#[derive(Clone)]
struct AccountsExport {
    ufvk: UnifiedFullViewingKey,
    seed_fingerprint: SeedFingerprint,
    account_index: zip32::AccountId,
    /// As reported, or `"unknown"`.
    device_version: String,
    name: Option<String>,
    /// For an unknown firmware version imported anyway.
    warning: Option<String>,
}

/// Decode and check an `ImportKeystone` payload. `INVALID_ARGUMENT` (exit 6)
/// when it is not a complete `ur:zcash-accounts` export or names an account
/// it does not list; `HARDWARE_SIGNER` (exit 9) when it decodes but the
/// device's content is refused; `CONFIRMATION_REQUIRED` (exit 4) for an
/// unknown firmware version without `allow_unknown_firmware`.
fn check_accounts_export(
    network: Network,
    payload: &str,
    account_index: u32,
    allow_unknown_firmware: bool,
) -> Result<AccountsExport, GygesError> {
    let bad = |detail: String| GygesError::new(ErrorReason::InvalidArgument, detail);
    let device = |detail: String| GygesError::new(ErrorReason::HardwareSigner, detail);
    let not_accounts = |what: &str| {
        bad(format!(
            "{what} carries no seed fingerprint, so the Keystone could not recognise its key in a \
             PCZT; export the accounts from the device (Connect Software Wallet) and pass the \
             ur:zcash-accounts QR"
        ))
    };

    let frames: Vec<&str> = payload.split_whitespace().collect();
    let Some(first) = frames.first() else {
        return Err(bad("no ur:zcash-accounts frame given".into()));
    };
    if first.to_ascii_lowercase().starts_with("uview") {
        return Err(not_accounts("a bare UFVK"));
    }
    let mut asm = Assembler::new();
    for f in &frames {
        asm.receive(f)
            .map_err(|e| bad(format!("not a Keystone accounts export: {e}")))?;
    }
    match asm.ur_type() {
        Some(gyges_qr::ur_types::ZCASH_ACCOUNTS) => {}
        Some(gyges_qr::ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY) => {
            return Err(not_accounts("ur:zcash-unified-full-viewing-key"));
        }
        other => {
            return Err(bad(format!(
                "expected ur:zcash-accounts, got ur:{}",
                other.unwrap_or("?")
            )));
        }
    }
    if !asm.is_complete() {
        let (resolved, total) = asm.progress();
        return Err(bad(format!(
            "the accounts export is incomplete ({resolved} of {total} fragments); pass every frame"
        )));
    }
    let accounts = match Payload::from_assembler(&asm) {
        Ok(Some(Payload::Accounts(a))) => a,
        Ok(_) => return Err(bad("the accounts export is incomplete".into())),
        Err(e) => return Err(device(format!("the accounts export does not decode: {e}"))),
    };

    let fp: [u8; 32] = accounts
        .seed_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| {
            device(format!(
                "the export's seed fingerprint is {} bytes, not the 32 of ZIP 32",
                accounts.seed_fingerprint.len()
            ))
        })?;
    let seed_fingerprint = SeedFingerprint::from_bytes(fp);

    let mut indices: Vec<u32> = accounts.accounts.iter().map(|a| a.index).collect();
    indices.sort_unstable();
    if indices.windows(2).any(|w| w[0] == w[1]) {
        return Err(device("the export lists an account index twice".into()));
    }
    let account = match accounts.accounts.as_slice() {
        [] => return Err(device("the export lists no accounts".into())),
        [only] if account_index == 0 || only.index == account_index => only,
        list => list
            .iter()
            .find(|a| a.index == account_index)
            .ok_or_else(|| {
                let have: Vec<String> = indices.iter().map(u32::to_string).collect();
                bad(format!(
                    "account {account_index} is not in the export, which lists account {}; pass \
                     --account",
                    have.join(", ")
                ))
            })?,
    };
    let index = zip32::AccountId::try_from(account.index)
        .map_err(|_| device(format!("account index {} is out of range", account.index)))?;
    let ufvk =
        UnifiedFullViewingKey::decode(&network.consensus_params(), &account.ufvk).map_err(|e| {
            device(format!(
                "account {}'s UFVK is not a {} viewing key: {e}",
                account.index,
                network.name()
            ))
        })?;
    if ufvk.orchard().is_none() {
        return Err(device(format!(
            "account {}'s UFVK has no Orchard component, which every Keystone account has",
            account.index
        )));
    }

    use gyges_qr::firmware::{self, FirmwareCheck};
    let reported = accounts.device_version.as_deref();
    let (device_version, warning) = match firmware::check(reported) {
        FirmwareCheck::Supported(_) => (reported.unwrap_or_default().to_string(), None),
        FirmwareCheck::TooOld(v) => return Err(device(firmware::too_old_message(v))),
        FirmwareCheck::Unknown if allow_unknown_firmware => (
            reported.unwrap_or("unknown").to_string(),
            Some(format!(
                "{}; it was imported anyway (--allow-unknown-firmware)",
                firmware::unknown_message(reported)
            )),
        ),
        FirmwareCheck::Unknown => {
            return Err(GygesError::new(
                ErrorReason::ConfirmationRequired,
                format!(
                    "{}; update it and export again, or pass --allow-unknown-firmware to import \
                     it anyway",
                    firmware::unknown_message(reported)
                ),
            ));
        }
    };
    Ok(AccountsExport {
        ufvk,
        seed_fingerprint,
        account_index: index,
        device_version,
        name: account.name.clone(),
        warning,
    })
}

/// A restore below the node's window: consent, an endpoint that is not
/// marked untrusted, and the birthday's tree state from it. Returns the
/// birthday and how many blocks the backfill fetches from the endpoint
/// (up to the handoff height, SYNC.md §5.1).
async fn below_retention(
    state: &DaemonState,
    height: u32,
    retained_from: u32,
    allow_backfill: bool,
) -> Result<(birthday::ResolvedBirthday, u32), GygesError> {
    let below = retained_from - height;
    let fallback = state.fallback.as_ref();
    if !allow_backfill {
        let from = fallback.map_or_else(
            || "the fallback endpoint".to_string(),
            |f| {
                let how = if matches!(f.transport(), gyges_chain::Transport::Direct) {
                    "directly"
                } else {
                    "over Tor"
                };
                format!("{} ({how})", f.endpoint())
            },
        );
        return Err(GygesError::new(
            ErrorReason::ConfirmationRequired,
            format!(
                "{below} blocks below the node's retention height ({retained_from}) would have to be \
                 fetched from {from}; confirm with --yes"
            ),
        ));
    }
    let (Some(fallback), Some(chain)) = (fallback, state.chain.as_deref()) else {
        return Err(birthday_error(BirthdayError::BelowRetention {
            height,
            retained_from,
        }));
    };
    if let crate::backfill::Trust::Untrusted { reason } = state.fallback_trust.get() {
        return Err(GygesError::new(
            ErrorReason::FallbackUnavailable,
            format!(
                "the fallback endpoint is marked untrusted ({reason}); set another \
                 fallback_lightwalletd.grpc_url to restore below the node's window"
            ),
        ));
    }
    let resolved = birthday::resolve_from_fallback(chain, fallback.as_ref(), height)
        .await
        .map_err(birthday_error)?;
    let overlap = state.config.fallback_lightwalletd.overlap_blocks;
    let tip = chain
        .status()
        .bounds
        .map_or(retained_from + overlap, |b| u32::from(b.tip_height));
    let handoff = (retained_from + overlap).min(tip);
    tracing::info!(
        height,
        retained_from,
        endpoint = %fallback.endpoint(),
        "restore below the node's window; the scheduler backfills from the fallback endpoint"
    );
    Ok((resolved, (handoff + 1).saturating_sub(height)))
}

/// `UnlockKey` (API.md §6.3). Without `session_id`: a reusable unlock in
/// the requested scope. With one: single-use, satisfies the signing session
/// a paused `SendTransaction` stream is waiting on (API.md §6.2) and
/// returns no token.
pub(crate) async fn unlock_key(
    state: Arc<DaemonState>,
    conn: Option<ConnInfo>,
    mut req: UnlockKeyRequest,
) -> Result<UnlockKeyResponse, Status> {
    let passphrase = take_passphrase(&mut req.passphrase)?;
    if !req.session_id.is_empty() {
        return crate::tx::satisfy_session(state, req.session_id, passphrase).await;
    }
    let key = state.resolve_key(&req.key_id)?;
    let scope = match req.scope() {
        UnlockScope::Daemon => Scope::Daemon,
        UnlockScope::Connection | UnlockScope::Unspecified => Scope::Connection(
            conn.ok_or_else(|| Status::internal("no connection info on this request"))?
                .id,
        ),
    };
    let ttl = (req.ttl_secs > 0).then(|| Duration::from_secs(u64::from(req.ttl_secs)));
    let key_id = key.key_id().to_string();
    let st = state.clone();
    let k = key.clone();
    let unlocked = tokio::task::spawn_blocking(move || st.vault.unlock(&k, passphrase, scope, ttl))
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| vault_error(e, &key_id).into_status())?;
    tracing::info!(target: AUDIT_TARGET, key_id, event = "unlock", scope = ?unlocked.scope);
    Ok(UnlockKeyResponse {
        session_token: unlocked
            .token
            .as_ref()
            .map(|t| t.as_bytes().to_vec())
            .unwrap_or_default(),
        expires_at: gyges_core::profile::unix_secs(unlocked.expires_at),
        scope: match unlocked.scope {
            Scope::Daemon => UnlockScope::Daemon,
            Scope::Connection(_) => UnlockScope::Connection,
        } as i32,
    })
}

/// `LockKey`: one key (every scope) or all of them.
pub(crate) fn lock_key(
    state: &DaemonState,
    req: LockKeyRequest,
) -> Result<LockKeyResponse, Status> {
    let locked_key_ids = if req.all {
        state.vault.lock_all()
    } else {
        let key = state.resolve_key(&req.key_id)?;
        if state.vault.lock(key.key_id()) {
            vec![key.key_id().to_string()]
        } else {
            Vec::new()
        }
    };
    for key_id in &locked_key_ids {
        tracing::info!(target: AUDIT_TARGET, key_id, event = "lock");
    }
    Ok(LockKeyResponse { locked_key_ids })
}

/// `ExportUfvk`. A `signer-only` profile keeps no viewing key on disk, so
/// it needs a live daemon-scoped unlock (`VAULT_LOCKED` otherwise).
pub(crate) fn export_ufvk(
    state: &DaemonState,
    req: ExportUfvkRequest,
) -> Result<ExportUfvkResponse, Status> {
    let key = state.resolve_key(&req.key_id)?;
    let ufvk = match key.ufvk() {
        Some(u) => u,
        None => state
            .vault
            .with_entropy(key.key_id(), Auth::Daemon, |e| key.derive_ufvk(e))
            .map_err(|e| vault_error(e, key.key_id()).into_status())?
            .map_err(registry_error)?,
    };
    Ok(ExportUfvkResponse {
        ufvk,
        birthday_height: key.profile().birthday_height.unwrap_or(0),
    })
}

/// `ExportSeed` (OVERVIEW.md Q-S4): disabled by config, a fresh passphrase
/// (never a session), the literal confirmation, audit-logged.
pub(crate) async fn export_seed(
    state: Arc<DaemonState>,
    mut req: ExportSeedRequest,
) -> Result<ExportSeedResponse, Status> {
    if !state.vault.allow_seed_export() {
        return Err(GygesError::new(
            ErrorReason::SeedExportDisabled,
            "seed export is disabled by vault.allow_seed_export = false",
        )
        .into_status());
    }
    let passphrase = take_passphrase(&mut req.passphrase)?;
    if req.confirmation != REVEAL_SEED {
        return Err(GygesError::new(
            ErrorReason::ConfirmationRequired,
            format!("type `{REVEAL_SEED}` to confirm"),
        )
        .into_status());
    }
    let key = state.resolve_key(&req.key_id)?;
    let key_id = key.key_id().to_string();
    let st = state.clone();
    let k = key.clone();
    let entropy = tokio::task::spawn_blocking(move || st.vault.verify_passphrase(&k, passphrase))
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| vault_error(e, &key_id).into_status())?;
    let mnemonic = vault::mnemonic_phrase(&entropy);
    drop(entropy);
    tracing::info!(target: AUDIT_TARGET, key_id, event = "export_seed");
    Ok(ExportSeedResponse {
        mnemonic: mnemonic.to_string(),
        birthday_height: key.profile().birthday_height.unwrap_or(0),
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
