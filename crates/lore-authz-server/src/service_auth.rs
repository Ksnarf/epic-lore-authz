//! Caller-identity gate for `RebacApi` (`CreateResource` / `DeleteResource`)
//! -- closes the finding tracked in `docs/open-questions.md` Q6/Q12: as
//! shipped before this module existed, both RPCs performed NO caller-identity
//! check at all, so anything that could reach the gRPC port could
//! create/delete resource rows, including mass-revoking every grant by
//! iterating the predictable `urc-{repository_id}` convention.
//!
//! ## Why this is NOT `crate::caller`'s bearer-JWT pattern
//!
//! `crate::caller::caller_principal_id` verifies a user-facing bearer JWT
//! signed by this service's own key and resolves it to a `principals` row.
//! That does not fit this hop: `lore-server` is the caller here, not an end
//! user, and it has no `principals` row of its own to resolve to. More to
//! the point, reading the upstream `lore-server` client code this project
//! integrates against shows the wrong KIND of credential arrives, not the
//! absence of one. `lore-server/src/authnz/rebac.rs`'s `RebacClientHelper`
//! builds its gRPC channel with only a `CorrelationInterceptor` (tracing
//! correlation id), but the call sites (`repository_create_auth_resource` /
//! `repository_delete_auth_resource`) build their requests through
//! `create_request_with_authorization`, so what actually lands on this hop
//! is the END USER's own bearer token, forwarded verbatim from the request
//! that triggered the repository create or delete. That is a user
//! credential, not a service one: verifying it the way
//! `caller_principal_id` does would authenticate the human, not
//! `lore-server`, and would let any user who can reach `RepositoryCreate`
//! call `CreateResource` directly with that same token. The caller on this
//! hop is `lore-server` acting on its own behalf, and it has no
//! `principals` row to resolve to.
//!
//! ## What this uses instead
//!
//! A static shared secret, configured via `REBAC_SERVICE_TOKEN`
//! (`docs/configuration.md`), presented the same way a user bearer token
//! would be -- `authorization: Bearer <secret>` -- so it reuses the same
//! metadata extraction the rest of this crate already has
//! (`crate::grpc::authorization_header`), just with a different
//! verification rule: constant-time equality against the configured value,
//! not a JWT decode. This matches the design plan's own recommendation
//! (`docs/open-questions.md` Q6) that this hop be gated by a shared secret
//! or mTLS rather than a user token.
//!
//! ## FAIL CLOSED
//!
//! If `REBAC_SERVICE_TOKEN` is not configured, every call is denied --
//! deliberately. An unconfigured gate defaulting to "allow everyone" would
//! reproduce the exact vulnerability this module exists to close. See
//! `verify_rebac_caller`'s `None` branch below.
//!
//! ## Known operational gap, stated honestly
//!
//! By default `lore-server` forwards the end user's own bearer token on
//! this hop rather than a service credential (see above), so
//! `REBAC_SERVICE_TOKEN` alone does nothing for a deployment where nothing
//! on `lore-server`'s side replaces that token with one.
//!
//! An optional `[server.auth] rebac_service_token` setting exists as a
//! not-yet-upstreamed patch on the `epic-lore` repository's
//! `feat/rebac-service-token` branch (`epic-lore` is `lore-server`'s own,
//! separate repository, not part of this project). When configured, it
//! makes `lore-server`'s rebac client replace the forwarded caller token
//! with `authorization: Bearer <token>` on this hop only; when absent,
//! behavior is unchanged from the paragraph above. Proven end to end on
//! 2026-08-06: the correct token lets `RepositoryCreate` succeed and
//! creates a row in this service's `resources` table; a wrong token is
//! rejected; leaving the setting unset leaves behavior unchanged.
//!
//! Deployments running a stock, unpatched `lore-server` binary are still
//! affected: they have no config surface to send a service credential at
//! all, so the caller's own token still lands here, and something else on
//! the network path -- e.g. a sidecar or reverse proxy the operator
//! controls -- is still needed to attach a real header before
//! `REBAC_SERVICE_TOKEN` here does anything for them. See
//! `docs/open-questions.md` Q6 for the full writeup and `docs/
//! configuration.md`'s `REBAC_SERVICE_TOKEN` entry for the config surface.
//! What this module guarantees on ITS side of that boundary is narrow but
//! real: nobody without the configured secret can call these two RPCs.

use tonic::Status;

use crate::secret::constant_time_eq;

/// Strips a leading `"Bearer "` prefix, matching `crate::caller::
/// strip_bearer`'s convention, and treats an empty string as "no token
/// present" for the same reason documented there (lore-server's own
/// `create_request_with_authorization` forwards a literal empty string, not
/// a missing header, when it has nothing to forward).
fn strip_bearer(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.strip_prefix("Bearer ").unwrap_or(trimmed))
}

/// Verifies the caller of a `RebacApi` RPC. `configured_secret` is
/// `AuthApiService`/`RebacApiService`'s own `REBAC_SERVICE_TOKEN` value
/// (`None` when unset).
///
/// Denies (`Status::unauthenticated`) on every path except "a secret IS
/// configured, AND the presented value matches it exactly": unconfigured
/// gate, missing header, empty header, or a mismatched value all deny
/// identically -- deliberately not distinguished in the response, so a probe
/// cannot use the error to tell "you're close" from "this is completely
/// unconfigured".
pub fn verify_rebac_caller(
    raw_authorization: Option<&str>,
    configured_secret: Option<&str>,
) -> Result<(), Status> {
    let expected = configured_secret.filter(|s| !s.is_empty()).ok_or_else(|| {
        Status::unauthenticated(
            "RebacApi caller authentication is not configured (REBAC_SERVICE_TOKEN unset) -- \
             denying all callers until it is set; see docs/configuration.md",
        )
    })?;

    let presented = raw_authorization
        .and_then(strip_bearer)
        .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(Status::unauthenticated("invalid service token"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "correct-horse-battery-staple";

    #[test]
    fn valid_bearer_token_is_allowed() {
        let bearer = format!("Bearer {SECRET}");
        assert!(verify_rebac_caller(Some(&bearer), Some(SECRET)).is_ok());
    }

    #[test]
    fn missing_authorization_denies() {
        let err = verify_rebac_caller(None, Some(SECRET)).expect_err("must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn empty_authorization_denies_same_as_missing() {
        let err = verify_rebac_caller(Some(""), Some(SECRET)).expect_err("must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn wrong_token_denies() {
        let bearer = "Bearer not-the-right-secret".to_string();
        let err = verify_rebac_caller(Some(&bearer), Some(SECRET)).expect_err("must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn a_token_that_is_a_prefix_of_the_real_one_still_denies() {
        // Regression guard for a naive `starts_with`-style comparison bug:
        // a strict prefix of the real secret must NOT pass.
        let prefix = &SECRET[..SECRET.len() - 1];
        let bearer = format!("Bearer {prefix}");
        let err = verify_rebac_caller(Some(&bearer), Some(SECRET)).expect_err("must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn unconfigured_secret_denies_even_with_a_presented_token() {
        let bearer = format!("Bearer {SECRET}");
        let err = verify_rebac_caller(Some(&bearer), None)
            .expect_err("an unconfigured gate must deny every caller, never default to allow");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn empty_string_configured_secret_is_treated_as_unconfigured() {
        // An operator setting REBAC_SERVICE_TOKEN="" should not accidentally
        // produce an "empty secret matches empty bearer" allow-all; treat it
        // the same as unset.
        let err = verify_rebac_caller(Some(""), Some("")).expect_err("must deny");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
