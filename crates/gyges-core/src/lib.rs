//! Daemon-side wallet logic (ARCHITECTURE.md §2, DATA_MODEL.md).
//!
//! Components, each with its own module:
//! * [`registry::KeyRegistry`] – enumerates `keys/<id>/profile.json`, owns one
//!   `WalletDb` per key, validates permissions at startup (Q-S7);
//! * [`vault::manager::VaultManager`] – `seed.age` encryption, connection- and
//!   daemon-scoped unlocks with idle TTL, per-key back-off (Q-S1…S3, Q-S5);
//! * [`sync`] – the per-key state machine's types and the scan, transparent
//!   indexing and rewind steps over `gyges_chain` (SYNC.md); the scheduler
//!   that drives them lives in `gygesd`;
//! * [`tx`] – the `TxEngine`: proposal → PCZT roles → raw transaction
//!   (Q-K3, Q-K4, Q-K7); the daemon streams the steps and broadcasts;
//! * `TexQueue` – durable two-step ZIP 320 broadcaster (Q-T1…T3);
//! * [`log::Sensitive`] – the redaction wrapper every address, amount, memo,
//!   txid and secret goes through before it can reach a log line (Q-O1).

#![forbid(unsafe_code)]

pub mod addresses;
pub mod birthday;
pub mod config;
pub mod handoff;
pub mod history;
pub mod log;
pub mod network;
pub mod paths;
pub mod pczt_io;
pub mod perms;
pub mod profile;
pub mod registry;
pub mod sessions;
pub mod sync;
pub mod tex;
pub mod tx;
pub mod vault;

pub use birthday::{BirthdayError, ResolvedBirthday};
pub use config::{Config, ConfigError};
pub use log::Sensitive;
pub use network::{ConsensusParams, Network};
pub use paths::Home;
pub use profile::{KeyProfile, ProfileError};
pub use registry::{KeyEntry, KeyRegistry, NewLocalSeedKey, RegistryError};
pub use sync::{KeyProgress, StallReason, SyncError, SyncState};
pub use tx::{Provers, TxError};
pub use vault::manager::VaultManager;

/// How a key profile signs (DATA_MODEL.md `profile.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode {
    /// `seed.age` on disk, unlocked with a passphrase.
    LocalSeed,
    /// Keystone 3 Pro over BC-UR QR codes.
    KeystoneQr,
    /// UFVK only; can create and (for Orchard) prove, never sign.
    WatchOnly,
    /// `seed.age` without `wallet.sqlite`; the `--airgapped` signing box (Q-K5).
    SignerOnly,
}

/// Shielded and transparent pools, as data rather than code paths (Q-D7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pool {
    #[default]
    Transparent,
    Sapling,
    Orchard,
    Ironwood,
}

/// States of a `tex_queue` row (Q-T1, Q-T2; DATA_MODEL.md §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TexState {
    Built,
    Step1Broadcast,
    Step2Broadcast,
    Step1Mined,
    Step2Mined,
    Step2Failed,
    Expired,
    Failed,
    Aborted,
}

impl TexState {
    pub const ALL: [TexState; 9] = [
        TexState::Built,
        TexState::Step1Broadcast,
        TexState::Step2Broadcast,
        TexState::Step1Mined,
        TexState::Step2Mined,
        TexState::Step2Failed,
        TexState::Expired,
        TexState::Failed,
        TexState::Aborted,
    ];

    /// The `state` column value and the CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            TexState::Built => "built",
            TexState::Step1Broadcast => "step1_broadcast",
            TexState::Step2Broadcast => "step2_broadcast",
            TexState::Step1Mined => "step1_mined",
            TexState::Step2Mined => "step2_mined",
            TexState::Step2Failed => "step2_failed",
            TexState::Expired => "expired",
            TexState::Failed => "failed",
            TexState::Aborted => "aborted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// Nothing the queue can do with the row any more. `Step2Failed` is
    /// not terminal: `tx resume` rebuilds its second step.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TexState::Step2Mined | TexState::Expired | TexState::Failed | TexState::Aborted
        )
    }
}

/// Compile-time proof that the upstream APIs the design relies on exist under
/// the `package =` renames in `Cargo.toml` (OVERVIEW.md §2.1, Q-D4, Q-K3, Q-T1).
#[allow(unused_imports)]
mod paths_compile {
    use pczt::Pczt;
    use pczt::roles::{
        combiner::Combiner, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor,
        signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
        updater::Updater, verifier::Verifier,
    };
    use zcash_address::ZcashAddress;
    use zcash_client_backend::data_api::wallet::{
        create_pczt_from_proposal, create_proposed_transactions,
        extract_and_store_transaction_from_pczt, propose_standard_transfer_to_address,
        propose_transfer,
    };
    use zcash_client_backend::data_api::{WalletRead, WalletWrite};
    use zcash_client_sqlite::WalletDb;
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_proofs::prover::LocalTxProver;
}
