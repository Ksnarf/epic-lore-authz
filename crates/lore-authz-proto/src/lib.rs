//! Generated gRPC surface for the vendored lore auth contracts.
//!
//! See `proto/vendor/UPSTREAM.md` for where these two `.proto` files came
//! from, and `build.rs` in this crate for why they are compiled with
//! `build_server(true)` when upstream compiles them with `build_server(false)`.
//!
//! We `include!` the generated code directly from `OUT_DIR` rather than using
//! a `tonic::include_proto!`-style sugar macro. This is a deliberate, boring
//! choice: it has no dependency on which crate (`tonic` vs `tonic-prost`)
//! happens to export that macro in a given tonic 0.14.x point release, which
//! we could not verify on the machine this scaffold was written on (no local
//! Rust toolchain to compile-check against). If a future contributor
//! confirms the macro location, switching to it is a pure convenience change.

#![allow(clippy::doc_markdown)]

/// `package epic_urc;` from `auth_api.proto` -- the `UrcAuthApi` service.
/// This is the primary contract of the whole project.
pub mod epic_urc {
    include!(concat!(env!("OUT_DIR"), "/epic_urc.rs"));
}

/// `package ucs.auth;` from `rebac_api.proto` -- the `RebacApi` service.
pub mod ucs {
    pub mod auth {
        include!(concat!(env!("OUT_DIR"), "/ucs.auth.rs"));
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
