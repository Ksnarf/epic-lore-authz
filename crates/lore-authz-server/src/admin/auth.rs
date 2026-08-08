//! The gate on the ENTIRE admin surface: a shared secret from configuration
//! (`ADMIN_API_TOKEN`), presented as `authorization: Bearer <value>`,
//! compared in constant time, failing closed when it is not configured.
//!
//! ## Why this is the same mechanism as `crate::service_auth`, not
//! `crate::caller`
//!
//! `crate::caller::caller_principal_id` verifies a user-facing bearer JWT
//! this service signed and resolves it to a `principals` row. That is the
//! wrong instrument here, for the same reason it is wrong for `RebacApi` (see
//! `crate::service_auth`'s module doc comment): the caller of an admin route
//! is an OPERATOR or an automation acting on the deployment's own behalf, not
//! an end user, and it has no `principals` row to resolve to. Worse, using
//! the user path would make the admin surface reachable by anyone holding
//! ANY valid user token, since nothing in this product's data model yet
//! expresses "this principal may administer the authorization service
//! itself" (`role_bindings` grant access to `urc-*` REPOSITORIES, not to
//! this API). A shared secret is the smaller, auditable surface, and it is
//! the one this project already uses for its other service-to-service hop.
//!
//! ## FAIL CLOSED, with no bypass
//!
//! Every path except "a token IS configured, AND the presented value matches
//! it exactly" denies:
//!
//! - `ADMIN_API_TOKEN` unset -> deny (this is the important one: the admin
//!   surface can MINT AUTHORITY -- create a principal and bind it to `urc-*`
//!   with the `admin` role -- so a gate that defaulted to open when
//!   unconfigured would be strictly worse than any bug this project has
//!   fixed).
//! - `ADMIN_API_TOKEN` set to the empty string -> deny, treated as unset
//!   (`Config::from_env` collapses the two via `env_var_opt`, and
//!   `verify_admin_caller` re-checks it here rather than trusting that).
//! - No `authorization` header, an empty one, or a mismatched value -> deny.
//!
//! There is deliberately no "development mode" flag, no `ADMIN_API_INSECURE`
//! escape hatch, and no way to enable the routes without a token.
//!
//! ## What the response says, and what it does not
//!
//! Every denial is the IDENTICAL `401` with the identical body, whatever the
//! actual cause -- following the same rule the browser login routes already
//! follow (`crate::http`'s module doc comment): an unconfigured deployment
//! and a wrong token are indistinguishable to the caller, so a probe cannot
//! use the error text to learn that a deployment has no admin token set and
//! is therefore not worth attacking further. The distinction IS visible to
//! the operator, once, in the startup log (`main.rs`).
//!
//! The presented token is never logged, never echoed into a response body,
//! and never included in an error. Nothing in this module formats
//! `presented` or `expected` at all.

use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;

use crate::http::AppState;
use crate::secret::constant_time_eq;
use crate::secret::strip_bearer;

/// The one denial response for every admin route. `WWW-Authenticate` names
/// the scheme (RFC 6750 section 3) so a client knows HOW to present a
/// credential, which reveals nothing about whether one is configured.
fn denied() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            ("www-authenticate", "Bearer"),
            ("content-type", "text/plain; charset=utf-8"),
        ],
        "admin surface: a valid bearer token is required (see docs/configuration.md, \
         ADMIN_API_TOKEN)\n",
    )
        .into_response()
}

/// The denial. A type with NO fields, on purpose: unconfigured gate, missing
/// header, empty header and wrong value are one outcome here, and giving this
/// type a reason field would be the first step toward a response that
/// distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

/// Verifies an admin caller. `configured_token` is the deployment's
/// `ADMIN_API_TOKEN` (`None` when unset).
///
/// Returns `Err(Denied)` on every path except a configured token matching the
/// presented one exactly. The caller turns that into `denied()`; there is
/// nothing to distinguish because nothing should be distinguished.
pub fn verify_admin_caller(
    raw_authorization: Option<&str>,
    configured_token: Option<&str>,
) -> Result<(), Denied> {
    // An empty configured value is treated as unset, so that
    // `ADMIN_API_TOKEN=` in an env file cannot produce an "empty secret
    // matches empty bearer" allow-all. `Config::from_env` already filters
    // this, and this check makes the property hold for every caller of this
    // function, including tests that construct state by hand.
    let expected = configured_token
        .filter(|token| !token.is_empty())
        .ok_or(Denied)?;
    let presented = raw_authorization.and_then(strip_bearer).ok_or(Denied)?;

    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(Denied)
    }
}

/// Reads the `authorization` header, if it is present and valid UTF-8.
///
/// A header whose bytes are not valid UTF-8 is treated as absent rather than
/// as an error: it cannot possibly equal the configured token (a `String`),
/// so the outcome is the same denial either way, and there is no reason to
/// give it its own code path.
fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(AUTHORIZATION)?.to_str().ok()
}

/// axum middleware wrapping every `/admin/**` route. Applied with
/// `Router::layer` (not `route_layer`) in `crate::admin::router`, so it
/// covers the admin router's own 404 fallback too -- an unauthenticated
/// caller cannot map which admin paths exist by probing for the difference
/// between a 404 and a 401.
pub async fn require_admin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = authorization_header(request.headers()).map(str::to_owned);
    match verify_admin_caller(
        presented.as_deref(),
        state.admin_api_token.as_deref().map(String::as_str),
    ) {
        Ok(()) => next.run(request).await,
        Err(Denied) => {
            // Method and path only. Never the header, never the token, and
            // deliberately not "which of the three reasons" -- the operator
            // gets the unconfigured case from the startup warning in
            // main.rs, and an attacker gets nothing from a log they cannot
            // read.
            tracing::warn!(
                method = %request.method(),
                path = %request.uri().path(),
                "admin request denied"
            );
            denied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "admin-token-for-tests-only-not-a-real-secret";

    #[test]
    fn a_matching_bearer_token_is_allowed() {
        let bearer = format!("Bearer {TOKEN}");
        assert!(verify_admin_caller(Some(&bearer), Some(TOKEN)).is_ok());
    }

    #[test]
    fn a_bare_token_without_the_bearer_prefix_is_allowed() {
        // `strip_bearer` returns the value verbatim when there is no prefix,
        // so a client that sends the token alone still authenticates. That is
        // the existing convention in this crate (see `crate::secret::
        // strip_bearer`), stated here so it is a tested decision rather than
        // an accident.
        assert!(verify_admin_caller(Some(TOKEN), Some(TOKEN)).is_ok());
    }

    #[test]
    fn a_missing_authorization_header_denies() {
        assert!(verify_admin_caller(None, Some(TOKEN)).is_err());
    }

    #[test]
    fn an_empty_authorization_header_denies() {
        assert!(verify_admin_caller(Some(""), Some(TOKEN)).is_err());
        assert!(verify_admin_caller(Some("Bearer "), Some(TOKEN)).is_err());
    }

    #[test]
    fn a_wrong_token_denies() {
        let bearer = "Bearer definitely-not-the-admin-token".to_string();
        assert!(verify_admin_caller(Some(&bearer), Some(TOKEN)).is_err());
    }

    #[test]
    fn a_token_that_is_a_prefix_of_the_real_one_denies() {
        // Regression guard against a naive `starts_with` comparison: a strict
        // prefix of the real token must not pass.
        let prefix = &TOKEN[..TOKEN.len() - 1];
        let bearer = format!("Bearer {prefix}");
        assert!(verify_admin_caller(Some(&bearer), Some(TOKEN)).is_err());
    }

    #[test]
    fn an_unconfigured_token_denies_even_when_the_caller_presents_one() {
        let bearer = format!("Bearer {TOKEN}");
        assert!(
            verify_admin_caller(Some(&bearer), None).is_err(),
            "an unconfigured admin gate must deny every caller, never default to allow"
        );
    }

    #[test]
    fn an_empty_configured_token_is_treated_as_unconfigured() {
        assert!(verify_admin_caller(Some(""), Some("")).is_err());
        assert!(verify_admin_caller(Some("Bearer "), Some("")).is_err());
        assert!(verify_admin_caller(Some("Bearer anything"), Some("")).is_err());
    }

    /// The denial response must not carry any hint of the configured value,
    /// and must be identical whatever the cause. Asserted on the response
    /// this module actually returns, not on the reasoning above it.
    #[test]
    fn the_denial_response_is_a_401_that_names_no_secret() {
        let response = denied();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer")
        );
    }
}
