//! Compiles `proto/gyges.proto` into Rust with tonic 0.14 + prost 0.14, then
//! generates proto3-JSON `serde` implementations for every message with
//! `pbjson-build` (API.md §5: `--json` output is the proto message, 1:1).
//!
//! Requires `protoc` 22 or newer on `PATH` (for the `debug_redact` field option;
//! Homebrew `protobuf` is fine, Ubuntu's apt `protobuf-compiler` 3.21 is not).
//! Vendoring the compiler is deliberately avoided for now; see TESTING.md.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/gyges.proto";
    println!("cargo:rerun-if-changed={proto}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("gyges_descriptor.bin");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Every RPC the daemon has not implemented yet answers UNIMPLEMENTED
        // instead of failing to compile; the service struct implements only
        // what ROADMAP.md has reached.
        .generate_default_stubs(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&[proto], &["../../proto"])?;

    let descriptors = std::fs::read(&descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptors)?
        // Keep the proto field names (`api_version`) rather than the
        // lowerCamelCase the proto3 JSON printer would emit, so that `--json`
        // output reads like `gyges.proto` and like the `schema_version` key
        // the CLI adds (API.md §5).
        .preserve_proto_field_names()
        .build(&[".gyges.v1"])?;
    Ok(())
}
