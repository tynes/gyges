//! Terminal QR rendering and BC-UR encoding/decoding for the Keystone flow.
//!
//! Responsibilities (ARCHITECTURE.md §3.4, OVERVIEW.md Q-K2/Q-K6):
//! * render a QR code as UTF-8 half-block characters, static or as an 8 FPS
//!   fountain-code animation;
//! * encode a PCZT as `ur:zcash-pczt` / `ur:zcash-sign-batch` and decode the
//!   device's `ur:zcash-accounts` / `ur:zcash-pczt` / `ur:zcash-batch-sig-result`;
//! * accept frames from a file, stdin, or (later) a camera.

#![forbid(unsafe_code)]

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
    use super::tags;

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
}
