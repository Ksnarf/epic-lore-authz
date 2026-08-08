//! Same-origin enforcement on every state-changing admin request: the second
//! gate on `/admin/**`, applied INSIDE the bearer gate in
//! `crate::admin::router`.
//!
//! ## The hole this closes
//!
//! `crate::admin::auth` is a header-only credential, and the reasoning that
//! used to sit in `crate::admin::panel` was that CSRF therefore does not
//! apply: a browser cannot attach an `Authorization` header to an
//! address-bar navigation, so a cross-origin page cannot forge an
//! authenticated admin request.
//!
//! That is true of the header IN ISOLATION and false of the deployment this
//! project DOCUMENTS. `docs/configuration.md` ships a reverse-proxy example
//! that injects the admin bearer into every request arriving from an
//! allowlisted IP range. The moment a proxy does that, the credential is no
//! longer something the caller must possess -- it is something the caller's
//! NETWORK POSITION earns, which is the definition of ambient authority, the
//! same property that makes cookie-authenticated sites CSRF-able. mTLS has
//! the identical problem: a client certificate is also presented ambiently on
//! a cross-origin navigation.
//!
//! The exploit that follows is plain HTML, no JavaScript required. Every
//! `/admin/ui/*` mutation route takes an `axum::Form`, so it accepts
//! `application/x-www-form-urlencoded` -- one of the three enctypes a
//! `<form>` can submit, none of which trigger a CORS preflight. An operator
//! on the allowlisted network loads any hostile page; the page
//! auto-submits a form to `/admin/ui/grants` with
//! `role=admin&resource_pattern=urc-*&principal_kind=user&principal_id=<the
//! attacker's own principal>`; the proxy authenticates the request by source
//! IP and injects the real token; the attacker holds `admin` over every
//! repository.
//!
//! ## Why the JSON API is not in the same position
//!
//! Every mutating `/admin/v1` route takes `axum::Json` (POST) or no body at
//! all with a `DELETE` method (see `crate::admin::api`). A `<form>` cannot
//! send `content-type: application/json` and cannot issue a `DELETE`, so
//! neither shape is reachable from a plain cross-origin form. A cross-origin
//! `fetch` could set either, but only after a CORS preflight, and this
//! service mounts no CORS layer anywhere -- no `OPTIONS` handler, no
//! `access-control-allow-origin` on any response -- so the browser refuses
//! the real request. That is a property of THIS router, so it is worth
//! keeping true rather than assuming: adding a permissive CORS layer to
//! `/admin` would re-open exactly this hole.
//!
//! ## The rule, and why it is scoped the way it is
//!
//! On any method other than `GET`/`HEAD`, anywhere under `/admin`:
//!
//! 1. `Origin` present -> it must equal this service's own origin, or DENY.
//! 2. No `Origin`, `Referer` present -> its scheme+host+port must equal this
//!    service's own origin, or DENY.
//! 3. NEITHER header present:
//!    - under `/admin/ui/**` (the HTML form routes) -> DENY. This is the
//!      fail-closed choice and it is correct here: a browser ALWAYS sends
//!      `Origin` on a cross-origin form POST, so a form submission that
//!      declares no origin at all is not a browser doing what browsers do.
//!      Nothing legitimate is lost, because the panel's own forms are served
//!      from this origin and therefore always carry one.
//!    - under the rest of `/admin` (the JSON API) -> ALLOW. This is the one
//!      deliberate asymmetry. `curl`, a deployment script and any other
//!      non-browser client send neither header, and the JSON API is the
//!      documented interface for exactly those callers; denying them would
//!      break every automation this product tells operators to write, in
//!      exchange for closing an attack the previous section shows a browser
//!      cannot mount anyway. Rules 1 and 2 still apply to `/admin/v1`, so a
//!      request that DOES declare a foreign origin is refused there too --
//!      that costs automation nothing (it declares none) and keeps the
//!      defence in place if a future route ever becomes form-reachable.
//!
//! ## When `PUBLIC_BASE_URL` is not configured
//!
//! There is then no origin to compare against, and this gate DENIES every
//! request that declares one, plus every state-changing form request
//! (rule 3). It never falls back to allowing: an unverifiable claim about
//! where a request came from is not a weaker credential, it is no credential.
//! Concretely, the panel's forms stop working until `PUBLIC_BASE_URL` is set,
//! and the JSON API keeps working for header-less automation. `main.rs` warns
//! about this at startup, and `docs/configuration.md` documents it.
//!
//! `PUBLIC_BASE_URL` is reused rather than duplicated on purpose: the OIDC
//! login flow already derives this service's browser-facing origin from it
//! (`crate::config::Config::from_env`, falling back to the origin of
//! `OIDC_REDIRECT_URL`), and a second, separately-configured notion of "our
//! origin" is a setting that can silently disagree with the first.
//!
//! ## What the denial says
//!
//! One `403`, one body, for every cause. Applied with `Router::layer` like
//! the bearer gate, so it also covers the admin router's 404 fallback: a
//! cross-origin POST to a path that does not exist is refused identically to
//! one aimed at a route that does, and cannot be used to map the surface.
//! It runs INSIDE `crate::admin::auth::require_admin`, so a caller without a
//! valid bearer token still sees only the existing `401` and learns nothing
//! about this check at all.

use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::Method;
use axum::http::StatusCode;
use axum::http::header::ORIGIN;
use axum::http::header::REFERER;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;

use crate::config::origin_of;
use crate::http::AppState;

/// The one denial response for every same-origin failure.
fn denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        [("content-type", "text/plain; charset=utf-8")],
        "admin surface: a state-changing request must come from this service's own origin (see \
         docs/configuration.md, \"Same-origin enforcement\")\n",
    )
        .into_response()
}

/// The denial. Field-less for the same reason `crate::admin::auth::Denied`
/// is: "foreign origin", "unparseable origin", "no origin declared at all"
/// and "this deployment has no origin configured" are ONE outcome, and a
/// reason field would be the first step toward a response that tells a probe
/// which of them it hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossOrigin;

/// True for the HTML form routes (`/admin/ui/**`), which is where rule 3
/// (neither header -> deny) applies.
///
/// The prefix is stripped defensively: this middleware is layered onto the
/// router that `crate::http::router` `nest`s at `/admin`, and axum strips the
/// nest prefix from the URI the inner service sees, so the path here is
/// normally `/ui/grants` rather than `/admin/ui/grants`. Accepting both
/// spellings means this function keeps working if the mount point ever
/// changes, and it cannot accidentally start returning `false` (which would
/// silently downgrade the form routes to the JSON API's weaker rule).
fn is_form_route(path: &str) -> bool {
    let relative = path.strip_prefix("/admin").unwrap_or(path);
    relative == "/ui" || relative.starts_with("/ui/")
}

/// The origin a request declares: `Origin` when present, otherwise `Referer`.
///
/// An empty header value is treated as absent -- it declares nothing, and
/// `origin_of` would reject it anyway; this only decides whether the
/// `Referer` fallback is reached.
fn declared_origin<'h>(origin: Option<&'h str>, referer: Option<&'h str>) -> Option<&'h str> {
    origin
        .filter(|value| !value.is_empty())
        .or(referer.filter(|value| !value.is_empty()))
}

/// The whole rule, as a pure function so it is testable without a server.
///
/// `public_base_url` is the deployment's `PUBLIC_BASE_URL` (`None`, or empty,
/// when unset). `path` is the request path as seen by this middleware.
pub fn verify_same_origin(
    method: &Method,
    path: &str,
    origin_header: Option<&str>,
    referer_header: Option<&str>,
    public_base_url: Option<&str>,
) -> Result<(), CrossOrigin> {
    // Safe methods are exempt. Reading the panel is a `GET`, and every
    // mutation on this surface is a `POST` or a `DELETE`; anything that is
    // neither `GET` nor `HEAD` is treated as state-changing, so a method
    // added later is covered by default rather than by remembering to add it.
    if *method == Method::GET || *method == Method::HEAD {
        return Ok(());
    }

    // Both sides go through the SAME normalization, so `https://a.example.com`
    // and `https://a.example.com:443` compare equal, a trailing path or slash
    // on either is ignored, and scheme/host case cannot produce a false
    // mismatch. `Origin: null` (a sandboxed iframe, some redirect chains) is
    // not a parseable URL, so it lands on `Err` -- which is right: it is
    // explicitly NOT this origin.
    let expected = public_base_url
        .filter(|value| !value.is_empty())
        .and_then(origin_of);

    match declared_origin(origin_header, referer_header) {
        Some(declared) => {
            let expected = expected.ok_or(CrossOrigin)?;
            let declared = origin_of(declared).ok_or(CrossOrigin)?;
            if declared == expected {
                Ok(())
            } else {
                Err(CrossOrigin)
            }
        }
        None if is_form_route(path) => Err(CrossOrigin),
        None => Ok(()),
    }
}

/// Reads a header as UTF-8, treating invalid bytes as absent -- such a value
/// could never equal a parsed origin, so the outcome is the same either way
/// and it does not need its own code path (the same reasoning
/// `crate::admin::auth::authorization_header` applies).
fn header(headers: &HeaderMap, name: axum::http::HeaderName) -> Option<&str> {
    headers.get(name)?.to_str().ok()
}

/// axum middleware wrapping every `/admin/**` route, applied with
/// `Router::layer` INSIDE `crate::admin::auth::require_admin` -- see this
/// module's doc comment for both halves of that ordering.
pub async fn require_same_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let origin = header(request.headers(), ORIGIN).map(str::to_owned);
    let referer = header(request.headers(), REFERER).map(str::to_owned);

    match verify_same_origin(
        request.method(),
        request.uri().path(),
        origin.as_deref(),
        referer.as_deref(),
        state.public_base_url.as_deref().map(String::as_str),
    ) {
        Ok(()) => next.run(request).await,
        Err(CrossOrigin) => {
            // The NORMALIZED origin only (scheme + host + port), never the
            // raw header: this is attacker-controlled text, and a parsed
            // origin cannot carry a newline or a control character into the
            // log. An unparseable value logs as absent, which is all an
            // operator can act on anyway.
            let declared = declared_origin(origin.as_deref(), referer.as_deref())
                .and_then(origin_of)
                .unwrap_or_else(|| "<none or unparseable>".to_string());
            tracing::warn!(
                method = %request.method(),
                path = %request.uri().path(),
                declared_origin = %declared,
                "admin request refused: not same-origin"
            );
            denied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "https://authz.example.com";
    const THEIRS: &str = "https://hostile.example.com";
    const FORM_ROUTE: &str = "/ui/grants";
    const JSON_ROUTE: &str = "/v1/grants";

    fn post(path: &str, origin: Option<&str>, referer: Option<&str>) -> Result<(), CrossOrigin> {
        verify_same_origin(&Method::POST, path, origin, referer, Some(OURS))
    }

    #[test]
    fn a_foreign_origin_is_refused_on_every_admin_route() {
        for path in [FORM_ROUTE, JSON_ROUTE, "/does-not-exist"] {
            assert!(post(path, Some(THEIRS), None).is_err());
        }
    }

    #[test]
    fn our_own_origin_is_allowed() {
        assert!(post(FORM_ROUTE, Some(OURS), None).is_ok());
        assert!(post(JSON_ROUTE, Some(OURS), None).is_ok());
    }

    /// The `Origin` header is compared as an ORIGIN, not as a string: a
    /// default port written out, a trailing slash, and a mixed-case host all
    /// name the same origin and must not be refused.
    #[test]
    fn the_comparison_normalizes_both_sides() {
        for equivalent in [
            "https://authz.example.com:443",
            "https://authz.example.com/",
            "https://AUTHZ.EXAMPLE.COM",
        ] {
            assert!(
                post(FORM_ROUTE, Some(equivalent), None).is_ok(),
                "{equivalent} names the same origin as {OURS}"
            );
        }
        // ...and a non-default port, a different scheme, or a host that
        // merely CONTAINS ours does not.
        for different in [
            "https://authz.example.com:8443",
            "http://authz.example.com",
            "https://authz.example.com.hostile.example.com",
            "https://hostile.example.com/authz.example.com",
        ] {
            assert!(
                post(FORM_ROUTE, Some(different), None).is_err(),
                "{different} is NOT the same origin as {OURS}"
            );
        }
    }

    /// `Origin: null` is what a sandboxed iframe (and some redirect chains)
    /// sends. It is not this origin, so it is refused rather than treated as
    /// "no origin declared".
    #[test]
    fn an_unparseable_origin_is_refused_not_treated_as_absent() {
        assert!(post(FORM_ROUTE, Some("null"), None).is_err());
        assert!(post(JSON_ROUTE, Some("null"), None).is_err());
    }

    #[test]
    fn the_referer_is_the_fallback_when_no_origin_is_present() {
        assert!(post(FORM_ROUTE, None, Some("https://authz.example.com/admin/ui")).is_ok());
        assert!(post(FORM_ROUTE, None, Some("https://hostile.example.com/page")).is_err());
        // A relative `Referer` names no origin at all, so it cannot satisfy
        // the check.
        assert!(post(FORM_ROUTE, None, Some("/admin/ui")).is_err());
    }

    /// `Origin` wins when both are present: a matching `Referer` must not
    /// rescue a foreign `Origin`.
    #[test]
    fn a_matching_referer_does_not_rescue_a_foreign_origin() {
        assert!(
            post(
                FORM_ROUTE,
                Some(THEIRS),
                Some("https://authz.example.com/admin/ui")
            )
            .is_err()
        );
    }

    /// Rule 3, both halves: a form route with neither header denies, the JSON
    /// API with neither header allows (that is `curl`).
    #[test]
    fn neither_header_denies_a_form_route_and_allows_the_json_api() {
        assert!(post(FORM_ROUTE, None, None).is_err());
        assert!(post("/ui", None, None).is_err());
        assert!(post("/ui/principals/status", None, None).is_err());
        assert!(post("/ui/does-not-exist", None, None).is_err());

        assert!(post(JSON_ROUTE, None, None).is_ok());
        assert!(post("/v1/principals", None, None).is_ok());
        assert!(post("/does-not-exist", None, None).is_ok());
    }

    /// Both spellings of the path, because axum's `nest` strips the `/admin`
    /// prefix before this middleware sees it and the mount point could move.
    #[test]
    fn the_form_routes_are_recognized_with_or_without_the_admin_prefix() {
        assert!(is_form_route("/ui"));
        assert!(is_form_route("/ui/grants"));
        assert!(is_form_route("/admin/ui"));
        assert!(is_form_route("/admin/ui/grants"));

        assert!(!is_form_route("/v1/grants"));
        assert!(!is_form_route("/admin/v1/grants"));
        assert!(!is_form_route("/uievil"));
        assert!(!is_form_route("/admin/uievil"));
    }

    #[test]
    fn safe_methods_are_never_refused() {
        for method in [Method::GET, Method::HEAD] {
            for path in [FORM_ROUTE, JSON_ROUTE] {
                assert!(
                    verify_same_origin(&method, path, Some(THEIRS), Some(THEIRS), Some(OURS))
                        .is_ok(),
                    "{method} {path} reads state and must not be refused"
                );
                // Even with no origin configured at all.
                assert!(verify_same_origin(&method, path, None, None, None).is_ok());
            }
        }
    }

    /// Every method that is not `GET`/`HEAD` is treated as state-changing, so
    /// a route added later with a different method inherits the check.
    #[test]
    fn every_other_method_is_checked() {
        for method in [
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::PATCH,
            Method::OPTIONS,
        ] {
            assert!(
                verify_same_origin(&method, JSON_ROUTE, Some(THEIRS), None, Some(OURS)).is_err(),
                "{method} from a foreign origin must be refused"
            );
        }
    }

    /// With no `PUBLIC_BASE_URL` there is nothing to compare against, so
    /// anything declaring an origin is refused -- INCLUDING one that would
    /// have matched -- and so is every form POST. Header-less JSON automation
    /// is unaffected.
    #[test]
    fn an_unconfigured_public_base_url_never_falls_back_to_allowing() {
        for unset in [None, Some("")] {
            for declared in [Some(OURS), Some(THEIRS)] {
                assert!(
                    verify_same_origin(&Method::POST, FORM_ROUTE, declared, None, unset).is_err()
                );
                assert!(
                    verify_same_origin(&Method::POST, JSON_ROUTE, declared, None, unset).is_err()
                );
            }
            assert!(verify_same_origin(&Method::POST, FORM_ROUTE, None, None, unset).is_err());
            assert!(verify_same_origin(&Method::POST, JSON_ROUTE, None, None, unset).is_ok());
        }
    }

    /// The denial must be a fixed `403` that names nothing about the request.
    #[test]
    fn the_denial_response_is_a_403_that_reflects_nothing() {
        let response = denied();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
