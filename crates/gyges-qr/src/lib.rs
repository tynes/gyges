//! Terminal QR rendering and BC-UR encoding/decoding for the Keystone flow.
//!
//! Responsibilities (ARCHITECTURE.md §3.4, OVERVIEW.md Q-K2/Q-K6):
//! * [`render`]: a QR code as UTF-8 half-block characters, for an address
//!   ([`render_str`]) or one `ur:` frame ([`render_frame`]);
//! * [`Frames`] / [`Assembler`]: a payload split into BC-UR fountain frames
//!   and put back together from frames in any order, with gaps;
//! * [`Payload`]: the Keystone Zcash registry types 49201, 49203, 49204,
//!   49205 and 49207 to and from their CBOR bodies;
//! * [`Animation`]: the 8 FPS loop that shows a multi-frame payload;
//! * [`firmware`]: the device version a pairing export reports, and the
//!   minimum Gyges accepts.
//!
//! Frames from a camera arrive with M5's `qr-scan`; the CLI's `qr-export`,
//! `qr-import` and `sign --qr-out` with the signing protocols.

#![forbid(unsafe_code)]

mod animate;
pub mod firmware;
mod fountain;
mod registry;
mod render;

pub use animate::{Animation, DEFAULT_FPS};
pub use fountain::{Assembler, DEFAULT_FRAGMENT_LEN, Frames};
pub use registry::{Account, Accounts, Payload};
pub use render::{render, render_frame, render_str};

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    /// More data than a version 40 QR code holds.
    #[error("too much data for one QR code: {0}")]
    TooLong(String),
    /// Not a well-formed `ur:` frame, or one inconsistent with the frames
    /// already received.
    #[error("bad UR frame: {0}")]
    Ur(String),
    #[error("expected a ur:{expected} frame, got ur:{got}")]
    MixedTypes { expected: String, got: String },
    #[error("unsupported UR type ur:{0}")]
    UnsupportedType(String),
    #[error("bad CBOR payload: {0}")]
    Cbor(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// CBOR tags of the Keystone Zcash UR registry types, as documented in
/// `keystone-sdk-rust/registry_types.rs`. Kept as literals so that a change in
/// the `ur-registry` crate is caught by `tests::registry_tags_are_stable`.
pub mod tags {
    pub const ZCASH_ACCOUNTS: u64 = 49201;
    /// Reserved upstream, no implementation. Not accepted by Gyges.
    pub const ZCASH_FULL_VIEWING_KEY: u64 = 49202;
    pub const ZCASH_UNIFIED_FULL_VIEWING_KEY: u64 = 49203;
    pub const ZCASH_PCZT: u64 = 49204;
    pub const ZCASH_SIGN_BATCH: u64 = 49205;
    pub const ZCASH_SIGN_RESULT: u64 = 49206;
    pub const ZCASH_BATCH_SIG_RESULT: u64 = 49207;
}

/// UR type strings paired with the tags above.
pub mod ur_types {
    pub const ZCASH_ACCOUNTS: &str = "zcash-accounts";
    pub const ZCASH_UNIFIED_FULL_VIEWING_KEY: &str = "zcash-unified-full-viewing-key";
    pub const ZCASH_PCZT: &str = "zcash-pczt";
    pub const ZCASH_SIGN_BATCH: &str = "zcash-sign-batch";
    pub const ZCASH_BATCH_SIG_RESULT: &str = "zcash-batch-sig-result";
}

#[cfg(test)]
mod tests {
    use super::{tags, ur_types};
    use ur_registry::registry_types as reg;

    /// Q-K6: a registry change must fail CI, not silently mis-tag a payload.
    #[test]
    fn registry_tags_are_stable() {
        assert_eq!(tags::ZCASH_ACCOUNTS, 49201);
        assert_eq!(tags::ZCASH_FULL_VIEWING_KEY, 49202);
        assert_eq!(tags::ZCASH_UNIFIED_FULL_VIEWING_KEY, 49203);
        assert_eq!(tags::ZCASH_PCZT, 49204);
        assert_eq!(tags::ZCASH_SIGN_BATCH, 49205);
        assert_eq!(tags::ZCASH_SIGN_RESULT, 49206);
        assert_eq!(tags::ZCASH_BATCH_SIG_RESULT, 49207);
    }

    /// The literals above agree with the `ur-registry` crate the codecs
    /// come from (TESTING.md §4 `registry_tags`).
    #[test]
    fn registry_tags_match_ur_registry() {
        for (registry, tag, ur_type) in [
            (
                reg::ZCASH_ACCOUNTS,
                tags::ZCASH_ACCOUNTS,
                Some(ur_types::ZCASH_ACCOUNTS),
            ),
            (
                reg::ZCASH_FULL_VIEWING_KEY,
                tags::ZCASH_FULL_VIEWING_KEY,
                None,
            ),
            (
                reg::ZCASH_UNIFIED_FULL_VIEWING_KEY,
                tags::ZCASH_UNIFIED_FULL_VIEWING_KEY,
                Some(ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY),
            ),
            (
                reg::ZCASH_PCZT,
                tags::ZCASH_PCZT,
                Some(ur_types::ZCASH_PCZT),
            ),
            (
                reg::ZCASH_SIGN_BATCH,
                tags::ZCASH_SIGN_BATCH,
                Some(ur_types::ZCASH_SIGN_BATCH),
            ),
            (reg::ZCASH_SIGN_RESULT, tags::ZCASH_SIGN_RESULT, None),
            (
                reg::ZCASH_BATCH_SIG_RESULT,
                tags::ZCASH_BATCH_SIG_RESULT,
                Some(ur_types::ZCASH_BATCH_SIG_RESULT),
            ),
        ] {
            assert_eq!(registry.get_tag(), tag);
            if let Some(t) = ur_type {
                assert_eq!(registry.get_type(), t);
            }
        }
    }
}
