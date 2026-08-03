//! Generated gRPC surface for the vendored lore auth contracts.
//!
//! See `proto/vendor/UPSTREAM.md` for where these two `.proto` files came
//! from, and `build.rs` in this crate for why they are compiled with
//! `build_server(true)` when upstream compiles them with `build_server(false)`.
//!
//! We use `tonic::include_proto!`, verified against tonic 0.14.6: it expands
//! to exactly `include!(concat!(env!("OUT_DIR"), "/<package>.rs"))`, the same
//! `OUT_DIR` layout `tonic-prost-build` writes in `build.rs`. tonic-prost
//! 0.14's split moved codegen into `tonic-prost-build`, but the include
//! macro itself still lives in `tonic` (see `tonic::macros`), unchanged from
//! pre-split tonic-build usage.

#![allow(clippy::doc_markdown)]

/// `package epic_urc;` from `auth_api.proto` -- the `UrcAuthApi` service.
/// This is the primary contract of the whole project.
pub mod epic_urc {
    tonic::include_proto!("epic_urc");
}

/// `package ucs.auth;` from `rebac_api.proto` -- the `RebacApi` service.
pub mod ucs {
    pub mod auth {
        tonic::include_proto!("ucs.auth");
    }
}

// Re-export the pieces callers actually need so downstream crates in this
// workspace don't have to spell out the nested module paths.
pub use epic_urc::urc_auth_api_client::UrcAuthApiClient;
pub use epic_urc::urc_auth_api_server::UrcAuthApi;
pub use epic_urc::urc_auth_api_server::UrcAuthApiServer;
pub use ucs::auth::rebac_api_client::RebacApiClient;
pub use ucs::auth::rebac_api_server::RebacApi;
pub use ucs::auth::rebac_api_server::RebacApiServer;
