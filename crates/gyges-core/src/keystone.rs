//! The two Keystone signing protocols (ARCHITECTURE.md §3.4, OVERVIEW.md
//! Q-K2): what the device is shown, and how its answer is applied to the
//! daemon's own proven copy of the PCZT.
//!
//! - **Batch** (`zcash-sign-batch` 49205 → `zcash-batch-sig-result` 49207)
//!   for transactions without transparent inputs. The device gets
//!   upstream's batch view (no viewing keys, no proofs, no existing
//!   signatures), derives its own key, and returns only
//!   `(pool, action_index, signature)` tuples, so the answer is one frame.
//!   Each one is applied with the Signer role, which verifies it against the
//!   action's randomized key first, so a signature for another transaction
//!   or from another key is refused.
//! - **Single PCZT** (`zcash-pczt` 49204 both ways) when there are
//!   transparent inputs, which the batch protocol rejects. The device gets
//!   upstream's full signer view and returns it signed; the Combiner merges
//!   it into the proven copy and refuses one that describes another
//!   transaction.
//!
//! The device is shown the PCZT before it is proven, as Zodl does: proofs
//! are not signed over, and leaving them out keeps the QR loop short.
//! Gyges' own `gyges.*` tags are stripped first (THREAT_MODEL.md §5 row 9);
//! nothing the device displays (amounts, recipients, memos) is.

use pczt::Pczt;
use pczt::roles::combiner::Combiner;
use pczt::roles::redactor::Redactor;
use pczt::roles::signer::Signer;
use pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse};
use rand::TryRng as _;
use zcash_client_backend::data_api::wallet::{
    SignerView, redact_pczt_for_batch_signer, redact_pczt_for_signer,
};

use crate::db::sessions::Protocol;
use crate::pczt_io::{TAG_KEY_ID, TAG_NETWORK, TAG_SESSION_ID};

/// Why a device's answer was refused. The session stays open: the user can
/// scan the device again.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("the answer is not a {expected} payload: {detail}")]
    Payload {
        expected: &'static str,
        detail: String,
    },
    #[error(
        "the answer is for another request (request id {got}, this session's is {want}); scan \
         the device's answer to this session"
    )]
    RequestMismatch { got: String, want: String },
    #[error("the batch answer carries {0} PCZT entries; this session sent one")]
    EntryCount(usize),
    #[error("the device's signature for {pool} action {index} does not verify: {detail}")]
    BadSignature {
        pool: &'static str,
        index: usize,
        detail: String,
    },
    #[error("the device returned a different transaction: {0}")]
    Mismatch(String),
    #[error("{0}")]
    Pczt(String),
}

/// Which protocol a PCZT goes by: the single-PCZT one when it spends a
/// transparent input, the batch one otherwise.
pub fn protocol_for(pczt: &Pczt) -> Protocol {
    if pczt.transparent().inputs().is_empty() {
        Protocol::KeystoneBatch
    } else {
        Protocol::KeystonePczt
    }
}

/// What the device is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequest {
    pub protocol: Protocol,
    /// The CBOR body of the `zcash-sign-batch` or `zcash-pczt` UR.
    pub payload: Vec<u8>,
    /// The batch protocol's request id (16 random bytes), echoed in the
    /// answer.
    pub request_id: Option<Vec<u8>>,
}

/// Remove Gyges' `gyges.*` tags from the global proprietary map.
pub fn strip_gyges_tags(pczt: Pczt) -> Pczt {
    Redactor::new(pczt)
        .redact_global_with(|mut g| {
            for tag in [TAG_KEY_ID, TAG_NETWORK, TAG_SESSION_ID] {
                g.redact_proprietary(tag);
            }
        })
        .finish()
}

/// The device's view of `pczt` under `protocol`, before CBOR: upstream's
/// batch view, or its full signer view. `pczt` is the unproven PCZT.
pub fn device_view(pczt: &Pczt, protocol: Protocol) -> Pczt {
    let stripped = strip_gyges_tags(pczt.clone());
    match protocol {
        Protocol::KeystoneBatch => redact_pczt_for_batch_signer(&stripped),
        _ => redact_pczt_for_signer(&stripped, SignerView::Full),
    }
}

/// Build the request for an unproven PCZT.
pub fn device_request(pczt: &Pczt) -> Result<DeviceRequest, DeviceError> {
    let protocol = protocol_for(pczt);
    let view = device_view(pczt, protocol);
    let pczt_err = |e: &dyn std::fmt::Debug| DeviceError::Pczt(format!("{e:?}"));
    let (payload, request_id) = match protocol {
        Protocol::KeystoneBatch => {
            let mut id = vec![0u8; 16];
            rand::rngs::SysRng
                .try_fill_bytes(&mut id)
                .map_err(|e| DeviceError::Pczt(format!("no randomness for the request id: {e}")))?;
            let data = BatchSignRequest::new(vec![view])
                .serialize()
                .map_err(|e| pczt_err(&e))?;
            let payload = gyges_qr::Payload::SignBatch {
                request_id: id.clone(),
                data,
            };
            (payload, Some(id))
        }
        _ => (
            gyges_qr::Payload::Pczt(view.serialize().map_err(|e| pczt_err(&e))?),
            None,
        ),
    };
    let cbor = payload
        .to_cbor()
        .map_err(|e| DeviceError::Pczt(e.to_string()))?;
    Ok(DeviceRequest {
        protocol,
        payload: cbor,
        request_id,
    })
}

/// Apply the device's answer (the CBOR body of its UR) to the proven copy.
/// The caller still runs the Verifier and checks that every signature is
/// present.
pub fn apply_answer(
    protocol: Protocol,
    proven: Pczt,
    request_id: Option<&[u8]>,
    answer: Vec<u8>,
) -> Result<Pczt, DeviceError> {
    match protocol {
        Protocol::KeystoneBatch => apply_batch(proven, request_id.unwrap_or_default(), answer),
        _ => combine_single(proven, answer),
    }
}

fn apply_batch(proven: Pczt, request_id: &[u8], answer: Vec<u8>) -> Result<Pczt, DeviceError> {
    let expected = gyges_qr::ur_types::ZCASH_BATCH_SIG_RESULT;
    let payload_err = |detail: String| DeviceError::Payload { expected, detail };
    let gyges_qr::Payload::BatchSigResult {
        request_id: got,
        data,
        firmware_version,
    } = gyges_qr::Payload::from_cbor(expected, answer).map_err(|e| payload_err(e.to_string()))?
    else {
        unreachable!("from_cbor answers in the requested type");
    };
    if got != request_id {
        return Err(DeviceError::RequestMismatch {
            got: hex::encode(got),
            want: hex::encode(request_id),
        });
    }
    tracing::info!(
        firmware = %format!("{}.{}.{}", firmware_version[0], firmware_version[1], firmware_version[2]),
        "Keystone batch answer"
    );
    let response = BatchSignResponse::parse(&data).map_err(|e| payload_err(format!("{e:?}")))?;
    let [signatures] = response.signatures() else {
        return Err(DeviceError::EntryCount(response.signatures().len()));
    };
    let mut signer = Signer::new(proven).map_err(|e| DeviceError::Pczt(format!("{e:?}")))?;
    for sig in signatures {
        signer
            .apply_orchard_spend_auth_signature(sig)
            .map_err(|e| DeviceError::BadSignature {
                pool: match sig.value_pool() {
                    orchard::ValuePool::Orchard => "Orchard",
                    orchard::ValuePool::Ironwood => "Ironwood",
                },
                index: sig.action_index(),
                detail: format!("{e:?}"),
            })?;
    }
    Ok(signer.finish())
}

fn combine_single(proven: Pczt, answer: Vec<u8>) -> Result<Pczt, DeviceError> {
    let expected = gyges_qr::ur_types::ZCASH_PCZT;
    let payload_err = |detail: String| DeviceError::Payload { expected, detail };
    let gyges_qr::Payload::Pczt(bytes) =
        gyges_qr::Payload::from_cbor(expected, answer).map_err(|e| payload_err(e.to_string()))?
    else {
        unreachable!("from_cbor answers in the requested type");
    };
    let signed = Pczt::parse(&bytes).map_err(|e| payload_err(format!("{e:?}")))?;
    Combiner::new(vec![proven, signed])
        .combine()
        .map_err(|e| DeviceError::Mismatch(format!("{e:?}")))
}

/// A Keystone in software, for tests: it answers a request as the device
/// does, from the payload alone, with upstream's Signer roles only (the
/// batch side as upstream's own batch test does), never with Gyges' own
/// signing code, so a redaction mistake cannot be hidden by it.
#[cfg(feature = "test-util")]
pub mod emulator {
    use pczt::Pczt;
    use pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse};
    use pczt::roles::signer::{SpendAuthSignature, extract_orchard_spend_auth_signatures};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::fingerprint::SeedFingerprint;

    /// The device's key: the account's spending key and its seed's
    /// fingerprint, on the coin type of `coin_type`.
    #[derive(Clone, Debug)]
    pub struct Device {
        pub usk: UnifiedSpendingKey,
        pub fingerprint: SeedFingerprint,
        pub coin_type: u32,
    }

    /// The batch side: sign every unsigned action that carries a
    /// randomizer, return the request id and the new signatures per PCZT.
    pub fn batch_signatures(
        device: &Device,
        payload: &[u8],
    ) -> (Vec<u8>, Vec<Vec<SpendAuthSignature>>) {
        let gyges_qr::Payload::SignBatch { request_id, data } =
            gyges_qr::Payload::from_cbor(gyges_qr::ur_types::ZCASH_SIGN_BATCH, payload.to_vec())
                .expect("a zcash-sign-batch payload")
        else {
            unreachable!()
        };
        let request = BatchSignRequest::parse(&data).expect("a batch request");
        let ask = orchard::keys::SpendAuthorizingKey::from(device.usk.orchard());
        let sigs = request
            .pczts()
            .iter()
            .map(|view| {
                let sighash = pczt::roles::signer::Signer::new(view.clone())
                    .expect("a signable view")
                    .shielded_sighash();
                let sign = |bundle: &mut orchard::pczt::Bundle| {
                    for action in bundle.actions_mut() {
                        if action.spend().alpha().is_some()
                            && action.spend().spend_auth_sig().is_none()
                        {
                            action
                                .sign(
                                    sighash,
                                    &ask,
                                    rand::rand_core::UnwrapErr(rand::rngs::SysRng),
                                )
                                .expect("the device's own spend");
                        }
                    }
                };
                use pczt::roles::low_level_signer::{OrchardParseError, Signer};
                let signed = Signer::new(view.clone())
                    .sign_orchard_with::<OrchardParseError, _>(|_, b, _| {
                        sign(b);
                        Ok(())
                    })
                    .expect("orchard bundle")
                    .sign_ironwood_with::<OrchardParseError, _>(|_, b, _| {
                        sign(b);
                        Ok(())
                    })
                    .expect("ironwood bundle")
                    .finish();
                extract_orchard_spend_auth_signatures(&signed)
            })
            .collect();
        (request_id, sigs)
    }

    /// A `zcash-batch-sig-result` body, from firmware 13.2.0 (v3.2.0).
    pub fn batch_answer(request_id: Vec<u8>, sigs: Vec<Vec<SpendAuthSignature>>) -> Vec<u8> {
        gyges_qr::Payload::BatchSigResult {
            request_id,
            data: BatchSignResponse::new(sigs)
                .serialize()
                .expect("a batch response"),
            firmware_version: [13, 2, 0],
        }
        .to_cbor()
        .expect("cbor")
    }

    /// The single-PCZT side with the high-level Signer role: Orchard and
    /// Ironwood spends with the spend authorizing key, each transparent
    /// input with the key at its BIP 44 path. Returns the signed PCZT.
    pub fn signed_pczt(device: &Device, payload: &[u8]) -> Vec<u8> {
        let gyges_qr::Payload::Pczt(bytes) =
            gyges_qr::Payload::from_cbor(gyges_qr::ur_types::ZCASH_PCZT, payload.to_vec())
                .expect("a zcash-pczt payload")
        else {
            unreachable!()
        };
        let view = Pczt::parse(&bytes).expect("a PCZT");
        let ask = orchard::keys::SpendAuthorizingKey::from(device.usk.orchard());
        let coin = bip32::ChildNumber(device.coin_type | bip32::ChildNumber::HARDENED_FLAG);
        let mut paths = Vec::new();
        let view = pczt::roles::verifier::Verifier::new(view)
            .with_transparent::<std::convert::Infallible, _>(|bundle| {
                for input in bundle.inputs() {
                    paths.push(
                        input
                            .bip32_derivation()
                            .values()
                            .find_map(|d| d.extract_bip_44_fields(&device.fingerprint, coin))
                            .map(|(_, scope, index)| (scope, index))
                            .expect("every input names the device's seed"),
                    );
                }
                Ok(())
            })
            .expect("transparent bundle")
            .finish();
        let (n_orchard, n_ironwood) = (
            view.orchard().actions().len(),
            view.ironwood().actions().len(),
        );
        let mut signer = pczt::roles::signer::Signer::new(view).expect("a signable view");
        // Dummy actions are already signed and fail with this key; skip them.
        for i in 0..n_orchard {
            let _ = signer.sign_orchard(i, &ask);
        }
        for i in 0..n_ironwood {
            let _ = signer.sign_ironwood(i, &ask);
        }
        for (i, (scope, index)) in paths.into_iter().enumerate() {
            let sk = device
                .usk
                .transparent()
                .derive_secret_key(scope, index)
                .expect("a transparent key");
            signer
                .sign_transparent(i, &sk)
                .expect("the device's own input");
        }
        signer.finish().serialize().expect("serialize")
    }

    pub fn pczt_answer(bytes: Vec<u8>) -> Vec<u8> {
        gyges_qr::Payload::Pczt(bytes).to_cbor().expect("cbor")
    }

    /// What a working device answers to a request of `ur_type`.
    pub fn answer(device: &Device, ur_type: &str, payload: &[u8]) -> Vec<u8> {
        match ur_type {
            gyges_qr::ur_types::ZCASH_SIGN_BATCH => {
                let (id, sigs) = batch_signatures(device, payload);
                batch_answer(id, sigs)
            }
            gyges_qr::ur_types::ZCASH_PCZT => pczt_answer(signed_pczt(device, payload)),
            other => panic!("not a Keystone request: ur:{other}"),
        }
    }
}
