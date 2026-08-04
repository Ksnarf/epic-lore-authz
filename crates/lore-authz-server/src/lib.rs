//! Library surface for the epic-lore-authz sidecar. `main.rs` is a thin
//! binary wrapper around this crate; splitting it out this way is what lets
//! `tests/` (real integration tests, notably the lore compat test -- see
//! docs/protocol-notes.md and tasks.md Phase 0) exercise the signing and
//! minting code directly without spinning up gRPC/HTTP listeners.

pub mod config;
pub mod grpc;
pub mod http;
pub mod minting;
pub mod signing;
