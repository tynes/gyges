//! A Keystone pairing export (`ur:zcash-accounts`, 49201) read from its
//! frames: the check the CLI makes before it asks anything and the daemon
//! makes again at `ImportKeystone`, kept here so the two cannot drift.

use crate::fountain::Assembler;
use crate::registry::{Accounts, Payload};
use crate::{QrError, ur_types};

/// Why a set of frames is not one complete `ur:zcash-accounts` export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("no ur:zcash-accounts frame given")]
    NoFrames,
    /// A bare UFVK or a lone `ur:zcash-unified-full-viewing-key`: a viewing
    /// key the device could not recognise as its own in a PCZT.
    #[error(
        "{0} carries no seed fingerprint, so the Keystone could not recognise its key in a \
         PCZT; export the accounts from the device (Connect Software Wallet) and pass the \
         ur:zcash-accounts QR"
    )]
    NoSeedFingerprint(&'static str),
    #[error("not a Keystone accounts export: {0}")]
    BadFrame(QrError),
    #[error("expected ur:zcash-accounts, got ur:{0}")]
    WrongType(String),
    #[error(
        "the accounts export is incomplete ({resolved} of {total} fragments); pass every frame"
    )]
    Incomplete { resolved: usize, total: usize },
    /// Every fragment arrived but the body is not a valid export.
    #[error("the accounts export does not decode: {0}")]
    Undecodable(QrError),
}

impl ExportError {
    /// Whether the device's content is at fault (`HARDWARE_SIGNER`) rather
    /// than the input the user passed (`INVALID_ARGUMENT`).
    pub fn is_device_fault(&self) -> bool {
        matches!(self, Self::Undecodable(_))
    }
}

/// Assemble `frames` (in any order) into a complete `ur:zcash-accounts`
/// export and decode it.
pub fn read_accounts_export<'a>(
    frames: impl IntoIterator<Item = &'a str>,
) -> Result<Accounts, ExportError> {
    let mut asm = Assembler::new();
    for frame in frames {
        if frame.to_ascii_lowercase().starts_with("uview") {
            return Err(ExportError::NoSeedFingerprint("a bare UFVK"));
        }
        asm.receive(frame).map_err(ExportError::BadFrame)?;
    }
    match asm.ur_type() {
        None => return Err(ExportError::NoFrames),
        Some(ur_types::ZCASH_ACCOUNTS) => {}
        Some(ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY) => {
            return Err(ExportError::NoSeedFingerprint(
                "ur:zcash-unified-full-viewing-key",
            ));
        }
        Some(other) => return Err(ExportError::WrongType(other.to_string())),
    }
    let incomplete = || {
        let (resolved, total) = asm.progress();
        ExportError::Incomplete { resolved, total }
    };
    if !asm.is_complete() {
        return Err(incomplete());
    }
    match Payload::from_assembler(&asm) {
        Ok(Some(Payload::Accounts(accounts))) => Ok(accounts),
        Ok(_) => Err(incomplete()),
        Err(e) => Err(ExportError::Undecodable(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Account;
    use crate::{DEFAULT_FRAGMENT_LEN, Frames};

    fn export(accounts: usize) -> Accounts {
        Accounts {
            seed_fingerprint: vec![7; 32],
            accounts: (0..accounts as u32)
                .map(|index| Account {
                    // Long enough that a few accounts span several frames.
                    ufvk: format!("uview1{}", "q".repeat(300)),
                    index,
                    name: None,
                })
                .collect(),
            device_version: Some("13.2.0".into()),
        }
    }

    /// Every fragment once.
    fn frames_of(payload: &Payload) -> Vec<String> {
        let mut frames = payload.frames(DEFAULT_FRAGMENT_LEN).unwrap();
        (0..frames.fragment_count())
            .map(|_| frames.next_frame().unwrap())
            .collect()
    }

    #[test]
    fn a_complete_export_in_any_order_decodes() {
        let want = export(3);
        let mut frames = frames_of(&Payload::Accounts(want.clone()));
        assert!(frames.len() > 1, "the export should span frames");
        frames.reverse();
        let got = read_accounts_export(frames.iter().map(String::as_str)).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn everything_else_is_refused_with_its_reason() {
        let frames = frames_of(&Payload::Accounts(export(3)));
        let lone = frames_of(&Payload::Ufvk(export(1).accounts.remove(0)));
        let pczt = frames_of(&Payload::Pczt(vec![1, 2, 3]));
        let not_cbor = Frames::new(ur_types::ZCASH_ACCOUNTS, &[0xff], DEFAULT_FRAGMENT_LEN)
            .unwrap()
            .next_frame()
            .unwrap();
        let refuse = |frames: &[&str]| read_accounts_export(frames.iter().copied()).unwrap_err();

        let e = refuse(&[]);
        assert!(matches!(e, ExportError::NoFrames), "{e:?}");
        let e = refuse(&["uview1qqqq"]);
        assert!(
            matches!(e, ExportError::NoSeedFingerprint("a bare UFVK")),
            "{e:?}"
        );
        let e = refuse(&[&lone[0]]);
        assert!(matches!(e, ExportError::NoSeedFingerprint(_)), "{e:?}");
        let e = refuse(&[&pczt[0]]);
        assert!(
            matches!(&e, ExportError::WrongType(t) if t == "zcash-pczt"),
            "{e:?}"
        );
        let e = refuse(&[&frames[0]]);
        assert!(
            matches!(e, ExportError::Incomplete { total, .. } if total > 1),
            "{e:?}"
        );
        let e = refuse(&["ur:zcash-accounts/not-bytewords"]);
        assert!(matches!(e, ExportError::BadFrame(_)), "{e:?}");
        assert!(!e.is_device_fault());

        // Every fragment arrived, so the device's content is at fault.
        let e = refuse(&[&not_cbor]);
        assert!(matches!(e, ExportError::Undecodable(_)), "{e:?}");
        assert!(e.is_device_fault());
    }
}
