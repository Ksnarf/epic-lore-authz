// THIS BUILD SCRIPT IS THE CRUX OF THE WHOLE PRODUCT.
//
// Upstream (github.com/EpicGames/lore, commit f205899adf24b13b2d28e5c08d9256ac99c69f0c,
// lore-proto/build.rs) compiles auth_api.proto and rebac_api.proto with
// `.build_server(false)`: it ships gRPC CLIENT stubs only for these two
// services, because Epic's own auth/rebac service is not open source.
// Everywhere else this project might touch lore, it is a strict downstream
// consumer; here it is not. We vendor byte-identical copies of the same two
// proto files (see proto/vendor/, provenance in proto/vendor/UPSTREAM.md) and
// compile them with `.build_server(true)` below. That one flag flip is the
// entire reason epic-lore-authz exists: it generates the SERVER traits
// (UrcAuthApi, RebacApi) that the unmodified upstream lore-server and lore
// CLI already know how to call as a client.
//
// We do not depend on the lore-proto crate itself: it hardcodes
// build_server(false) for these two files and pulls in the rest of the Epic
// workspace's proto surface, which this project has no reason to couple to.
// Vendoring two small MIT-licensed files is the correct trade (see plan
// section B.3 in the design doc this repo was scaffolded from).
//
// protoc must be on PATH or pointed to via the PROTOC env var for this build
// script to succeed. Unlike upstream, we do not check in a pregenerated
// fallback under src/, because this is a fresh scaffold with no prior
// generated output to fall back to.

use std::env;
use std::path::Path;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"));
    // proto/vendor lives at the repo root, two levels up from this crate.
    let proto_dir = manifest_dir
        .join("..")
        .join("..")
        .join("proto")
        .join("vendor");
    let auth_api = proto_dir.join("auth_api.proto");
    let rebac_api = proto_dir.join("rebac_api.proto");

    for proto in [&auth_api, &rebac_api] {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rerun-if-env-changed=PROTOC");

    let out_dir: PathBuf = env::var("OUT_DIR").expect("OUT_DIR is set by cargo").into();

    // Config mirrors the shape upstream lore-proto/build.rs uses for its own
    // codegen calls (enable_type_names, bytes(["."])) so generated code has
    // the same wire-level characteristics as the client stubs lore-server
    // and the lore CLI already link against.
    let mut config = tonic_prost_build::Config::new();
    config.enable_type_names();
    config.bytes(["."]);

    tonic_prost_build::configure()
        .out_dir(&out_dir)
        .protoc_arg("--experimental_allow_proto3_optional")
        .build_server(true) // <-- the crux. Upstream sets this to false.
        .build_client(true) // keep client stubs too, for tests that exercise
        // this server the way the real lore CLI / lore-server would.
        .compile_with_config(
            config,
            &[path_str(&auth_api), path_str(&rebac_api)],
            &[path_str(&proto_dir)],
        )?;

    Ok(())
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("proto paths are valid UTF-8")
}
