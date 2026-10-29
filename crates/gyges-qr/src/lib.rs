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
//!   minimum Gyges accepts;
//! * [`scan`]: decoded camera frames fed to an [`Assembler`] until the
//!   answer reassembles; `camera` (feature `camera`) supplies the frames.

#![forbid(unsafe_code)]

mod animate;
#[cfg(feature = "camera")]
pub mod camera;
pub mod firmware;
mod fountain;
mod registry;
mod render;
pub mod scan;

pub use animate::{Animation, DEFAULT_FPS};
pub use fountain::{Assembler, DEFAULT_FRAGMENT_LEN, Frames};
pub use registry::{Account, Accounts, Payload};
pub use render::{render, render_frame, render_str};
pub use scan::{FrameSource, LumaFrame, Progress, ScanEnd, Scanner, scan_answer};

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

/// UR type strings of the Keystone Zcash registry types Gyges accepts
/// (CBOR tags 49201, 49203, 49204, 49205 and 49207; `tests` pins them
/// against the `ur-registry` crate).
pub mod ur_types {
    pub const ZCASH_ACCOUNTS: &str = "zcash-accounts";
    pub const ZCASH_UNIFIED_FULL_VIEWING_KEY: &str = "zcash-unified-full-viewing-key";
    pub const ZCASH_PCZT: &str = "zcash-pczt";
    pub const ZCASH_SIGN_BATCH: &str = "zcash-sign-batch";
    pub const ZCASH_BATCH_SIG_RESULT: &str = "zcash-batch-sig-result";
}

#[cfg(test)]
mod tests {
    use super::ur_types;
    use ur_registry::registry_types as reg;

    /// Q-K6: a change in the `ur-registry` crate must fail CI, not silently
    /// mis-tag a payload (TESTING.md §4 `registry_tags`). The tags are the
    /// literals from `keystone-sdk-rust/registry_types.rs`; 49202 (reserved
    /// upstream, no implementation) and 49206 have no UR type in Gyges and
    /// are refused.
    #[test]
    fn registry_tags_match_ur_registry() {
        for (registry, tag, ur_type) in [
            (reg::ZCASH_ACCOUNTS, 49201, Some(ur_types::ZCASH_ACCOUNTS)),
            (reg::ZCASH_FULL_VIEWING_KEY, 49202, None),
            (
                reg::ZCASH_UNIFIED_FULL_VIEWING_KEY,
                49203,
                Some(ur_types::ZCASH_UNIFIED_FULL_VIEWING_KEY),
            ),
            (reg::ZCASH_PCZT, 49204, Some(ur_types::ZCASH_PCZT)),
            (
                reg::ZCASH_SIGN_BATCH,
                49205,
                Some(ur_types::ZCASH_SIGN_BATCH),
            ),
            (reg::ZCASH_SIGN_RESULT, 49206, None),
            (
                reg::ZCASH_BATCH_SIG_RESULT,
                49207,
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
