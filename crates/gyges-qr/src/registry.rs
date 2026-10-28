//! The Keystone Zcash UR registry types Gyges speaks (OVERVIEW.md §4.1,
//! Q-K6), as plain Rust values over `ur-registry`'s CBOR codecs, so callers
//! never depend on `ur-registry` themselves.
//!
//! `zcash-full-viewing-key` (49202) is reserved upstream with no codec and
//! `zcash-sign-result` (49206) belongs to a protocol Gyges does not use (the
//! batch protocol returns 49207), so both are refused.

use ur_registry::zcash::{
    zcash_accounts::ZcashAccounts, zcash_batch_sig_result::ZcashBatchSigResult,
    zcash_pczt::ZcashPczt, zcash_sign_batch::ZcashSignBatch,
    zcash_unified_full_viewing_key::ZcashUnifiedFullViewingKey,
};

use crate::fountain::{Assembler, Frames};
use crate::{QrError, ur_types};

/// One account of a `zcash-accounts` export, or a lone
/// `zcash-unified-full-viewing-key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// The encoded UFVK (`uview1…`).
    pub ufvk: String,
    /// ZIP 32 account index.
    pub index: u32,
    pub name: Option<String>,
}

/// `ur:zcash-accounts` (49201), what the device shows to pair. It carries no
/// birthday height (Q-K4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accounts {
    /// ZIP 32 seed fingerprint.
    pub seed_fingerprint: Vec<u8>,
    pub accounts: Vec<Account>,
    /// Firmware version as the device reports it (`"1.2.3"`), when it does.
    pub device_version: Option<String>,
}

/// A decoded registry payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// 49201.
    Accounts(Accounts),
    /// 49203.
    Ufvk(Account),
    /// 49204: a whole PCZT, sent for signing or returned signed.
    Pczt(Vec<u8>),
    /// 49205: a serialized `pczt::roles::signer::batch::BatchSignRequest`.
    SignBatch { request_id: Vec<u8>, data: Vec<u8> },
    /// 49207: a serialized `BatchSignResponse`, with the request id echoed
    /// and the device's `[major, minor, build]` firmware version.
    BatchSigResult {
        request_id: Vec<u8>,
        data: Vec<u8>,
        firmware_version: [u8; 3],
    },
}

impl Payload {
    pub fn ur_type(&self) -> &'static str {
        match self {
            Payload::Accounts(_) => ur_types::ZCASH_ACCOUNTS,
            Payload::Ufvk(_) => ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY,
            Payload::Pczt(_) => ur_types::ZCASH_PCZT,
            Payload::SignBatch { .. } => ur_types::ZCASH_SIGN_BATCH,
            Payload::BatchSigResult { .. } => ur_types::ZCASH_BATCH_SIG_RESULT,
        }
    }

    /// The CBOR body of the UR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, QrError> {
        let cbor: Result<Vec<u8>, _> = match self.clone() {
            Payload::Accounts(a) => {
                let mut v = ZcashAccounts::new(
                    a.seed_fingerprint,
                    a.accounts.into_iter().map(to_registry_ufvk).collect(),
                );
                if let Some(version) = a.device_version {
                    v.set_device_version(version);
                }
                v.try_into()
            }
            Payload::Ufvk(a) => to_registry_ufvk(a).try_into(),
            Payload::Pczt(data) => ZcashPczt::new(data).try_into(),
            Payload::SignBatch { request_id, data } => {
                ZcashSignBatch::new(request_id, data).try_into()
            }
            Payload::BatchSigResult {
                request_id,
                data,
                firmware_version,
            } => ZcashBatchSigResult::new(request_id, data, firmware_version).try_into(),
        };
        cbor.map_err(|e| QrError::Cbor(e.to_string()))
    }

    /// Decode the CBOR body of a UR of type `ur_type`.
    pub fn from_cbor(ur_type: &str, cbor: Vec<u8>) -> Result<Self, QrError> {
        let cbor_err = |e: ur_registry::error::URError| QrError::Cbor(e.to_string());
        Ok(match ur_type {
            ur_types::ZCASH_ACCOUNTS => {
                let v = ZcashAccounts::try_from(cbor).map_err(cbor_err)?;
                Payload::Accounts(Accounts {
                    seed_fingerprint: v.get_seed_fingerprint(),
                    accounts: v
                        .get_accounts()
                        .into_iter()
                        .map(from_registry_ufvk)
                        .collect(),
                    device_version: v.get_device_version(),
                })
            }
            ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY => Payload::Ufvk(from_registry_ufvk(
                ZcashUnifiedFullViewingKey::try_from(cbor).map_err(cbor_err)?,
            )),
            ur_types::ZCASH_PCZT => {
                Payload::Pczt(ZcashPczt::try_from(cbor).map_err(cbor_err)?.get_data())
            }
            ur_types::ZCASH_SIGN_BATCH => {
                let v = ZcashSignBatch::try_from(cbor).map_err(cbor_err)?;
                Payload::SignBatch {
                    request_id: v.get_request_id().to_vec(),
                    data: v.get_data().to_vec(),
                }
            }
            ur_types::ZCASH_BATCH_SIG_RESULT => {
                let v = ZcashBatchSigResult::try_from(cbor).map_err(cbor_err)?;
                Payload::BatchSigResult {
                    request_id: v.get_request_id().to_vec(),
                    data: v.get_data().to_vec(),
                    firmware_version: *v.get_firmware_version(),
                }
            }
            other => return Err(QrError::UnsupportedType(other.to_string())),
        })
    }

    /// The frames that carry this payload.
    pub fn frames(&self, max_fragment_len: usize) -> Result<Frames, QrError> {
        Frames::new(self.ur_type(), &self.to_cbor()?, max_fragment_len)
    }

    /// The payload an assembler has completed, or `None` while frames are
    /// still missing.
    pub fn from_assembler(asm: &Assembler) -> Result<Option<Self>, QrError> {
        asm.message()?
            .map(|(ur_type, cbor)| Self::from_cbor(&ur_type, cbor))
            .transpose()
    }
}

fn to_registry_ufvk(a: Account) -> ZcashUnifiedFullViewingKey {
    ZcashUnifiedFullViewingKey::new(a.ufvk, a.index, a.name)
}

fn from_registry_ufvk(v: ZcashUnifiedFullViewingKey) -> Account {
    Account {
        ufvk: v.get_ufvk(),
        index: v.get_index(),
        name: v.get_name(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::tests::Rng;

    const UFVK: &str = "uview1qqqqqqqqqqqqqq8rzd0efkm6ej5n0twzum9czt9kj5y7jxjm9qz3uq9qgpqqqqqqqqqqqqqq9en0hkucteqncqcfqcqcpz4wuwl";

    fn samples() -> Vec<Payload> {
        let mut rng = Rng::new(49201);
        vec![
            Payload::Accounts(Accounts {
                seed_fingerprint: rng.bytes(32),
                accounts: vec![
                    Account {
                        ufvk: UFVK.into(),
                        index: 0,
                        name: Some("Keystone 1".into()),
                    },
                    Account {
                        ufvk: UFVK.into(),
                        index: 1,
                        name: None,
                    },
                ],
                device_version: Some("2.3.4".into()),
            }),
            Payload::Accounts(Accounts {
                seed_fingerprint: rng.bytes(32),
                accounts: vec![],
                device_version: None,
            }),
            Payload::Ufvk(Account {
                ufvk: UFVK.into(),
                index: 7,
                name: Some("savings".into()),
            }),
            Payload::Pczt(rng.bytes(5000)),
            Payload::SignBatch {
                request_id: rng.bytes(16),
                data: rng.bytes(3000),
            },
            Payload::BatchSigResult {
                request_id: rng.bytes(16),
                data: rng.bytes(140),
                firmware_version: [2, 1, 0],
            },
        ]
    }

    /// Every type through CBOR, frames and back.
    #[test]
    fn every_payload_round_trips_through_frames() {
        for p in samples() {
            let mut frames = p.frames(150).unwrap();
            let mut asm = Assembler::new();
            let mut sent = 0;
            while !asm.is_complete() {
                asm.receive(&frames.next_frame().unwrap()).unwrap();
                sent += 1;
                assert!(sent < 1000, "{}", p.ur_type());
            }
            assert_eq!(asm.ur_type(), Some(p.ur_type()));
            assert_eq!(Payload::from_assembler(&asm).unwrap(), Some(p.clone()));
        }
    }

    /// `ur-registry`'s own vector: an accounts export with no accounts and
    /// device version "1.2.3".
    #[test]
    fn decodes_the_registry_accounts_vector() {
        let cbor = hex::decode("a30150d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d102800365312e322e33").unwrap();
        let p = Payload::from_cbor("zcash-accounts", cbor.clone()).unwrap();
        assert_eq!(
            p,
            Payload::Accounts(Accounts {
                seed_fingerprint: vec![0xd1; 16],
                accounts: vec![],
                device_version: Some("1.2.3".into()),
            })
        );
        assert_eq!(p.to_cbor().unwrap(), cbor);
    }

    #[test]
    fn unsupported_and_malformed_payloads_are_refused() {
        for t in ["zcash-full-viewing-key", "zcash-sign-result", "crypto-psbt"] {
            assert!(
                matches!(Payload::from_cbor(t, vec![0xa0]), Err(QrError::UnsupportedType(ref s)) if s == t),
                "{t}"
            );
        }
        // Missing the seed fingerprint.
        let err = Payload::from_cbor("zcash-accounts", hex::decode("a10280").unwrap()).unwrap_err();
        assert!(matches!(err, QrError::Cbor(_)), "{err}");
        let err = Payload::from_cbor("zcash-pczt", vec![0xff, 0x00]).unwrap_err();
        assert!(matches!(err, QrError::Cbor(_)), "{err}");
    }
}
