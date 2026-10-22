//! With the `test-util` feature: generate the server side of the lightwalletd
//! `CompactTxStreamer` service from `proto/service.proto`, for the fake
//! endpoint in `gyges_chain::testing`. Every message is mapped onto the type
//! `zakura-client-backend` already ships, so the fake speaks exactly what the
//! real client parses. Needs `protoc` 22 or newer on `PATH`, like
//! `gyges-proto`. Without the feature nothing is generated and `protoc` is not
//! needed.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/service.proto");
    println!("cargo:rerun-if-changed=proto/compact_formats.proto");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_UTIL");
    if std::env::var_os("CARGO_FEATURE_TEST_UTIL").is_none() {
        return Ok(());
    }

    const PKG: &str = ".cash.z.wallet.sdk.rpc";
    const COMPACT: &str = "::zcash_client_backend::proto::compact_formats";
    const SERVICE: &str = "::zcash_client_backend::proto::service";
    let mut builder = tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        // The fake implements the methods the tests drive; the rest answer
        // UNIMPLEMENTED.
        .generate_default_stubs(true)
        .out_dir(PathBuf::from(std::env::var("OUT_DIR")?));
    for name in [
        "ChainMetadata",
        "CompactBlock",
        "CompactTx",
        "CompactTxIn",
        "TxOut",
        "CompactSaplingSpend",
        "CompactSaplingOutput",
        "CompactOrchardAction",
    ] {
        builder = builder.extern_path(format!("{PKG}.{name}"), format!("{COMPACT}::{name}"));
    }
    for name in [
        "BlockID",
        "PoolType",
        "BlockRange",
        "TxFilter",
        "RawTransaction",
        "SendResponse",
        "ChainSpec",
        "Empty",
        "LightdInfo",
        "TreeState",
        "ShieldedProtocol",
        "GetSubtreeRootsArg",
        "SubtreeRoot",
        "GetAddressUtxosArg",
        "GetAddressUtxosReply",
        "GetAddressUtxosReplyList",
    ] {
        // prost names `BlockID` `BlockId`.
        let rust = if name == "BlockID" { "BlockId" } else { name };
        builder = builder.extern_path(format!("{PKG}.{name}"), format!("{SERVICE}::{rust}"));
    }
    builder.compile_protos(&["proto/service.proto"], &["proto"])?;
    Ok(())
}
