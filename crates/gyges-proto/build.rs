//! Compiles `proto/gyges.proto` into Rust with tonic 0.14 + prost 0.14.
//!
//! Requires `protoc` 22 or newer on `PATH` (for the `debug_redact` field option;
//! Homebrew `protobuf` is fine, Ubuntu's apt `protobuf-compiler` 3.21 is not).
//! Vendoring the compiler is deliberately avoided for now; see TESTING.md.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/gyges.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Serde derives give `--json` output for free (OVERVIEW.md Q-C3); add once
        // the message set is stable:
        // .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
