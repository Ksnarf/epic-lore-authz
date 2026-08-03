//! Domain layer for epic-lore-authz. No I/O lives in this crate: no sqlx, no
//! reqwest, no jsonwebtoken signing calls. It defines the shapes and trait
//! boundaries that `lore-authz-server` wires up to real implementations.
//!
//! Start with `docs/protocol-notes.md` in the repo root before touching
//! `claims` -- the claim shape is the single most fragile contract in this
//! project (see CLAIM-SHAPE DRIFT in the design plan this repo was scaffolded
//! from).

pub mod claims;
pub mod error;
pub mod model;
pub mod policy;

pub use error::AuthzError;
