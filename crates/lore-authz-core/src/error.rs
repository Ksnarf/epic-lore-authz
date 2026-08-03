use thiserror::Error;

/// Domain-level error type. `lore-authz-server` maps this to `tonic::Status`
/// (gRPC) or an HTTP status code at the edge; this crate stays transport
/// agnostic.
#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("not authorized")]
    NotAuthorized,

    #[error("principal not found")]
    PrincipalNotFound,

    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    #[error("auth session not found or expired")]
    SessionNotFound,

    #[error("auth session already consumed")]
    SessionAlreadyConsumed,

    #[error("client_state mismatch")]
    ClientStateMismatch,

    #[error("no signing key available")]
    NoActiveSigningKey,

    #[error("identity provider error: {0}")]
    IdpError(String),

    #[error("this operation is not implemented (see comment at the call site for the phase that fills it in)")]
    Unimplemented,

    #[error("internal error")]
    Internal,
}
