//! gRPC contract between `gyges` (CLI) and `gygesd` (daemon).
//!
//! The source of truth is `proto/gyges.proto`; `API.md` is its human-readable
//! companion. Nothing in this crate is hand-written apart from this module.

#![forbid(unsafe_code)]

/// Generated `gyges.v1` package: messages, `gyges_server::Gyges` trait and
/// `gyges_client::GygesClient`.
pub mod v1 {
    tonic::include_proto!("gyges.v1");
}

/// API major version. The CLI requires an equal major (OVERVIEW.md Q-O3).
pub const API_MAJOR: u32 = 0;
/// API minor version. A newer daemon minor produces a warning, never an error.
pub const API_MINOR: u32 = 1;
