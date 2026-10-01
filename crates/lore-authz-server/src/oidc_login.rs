//! Joins the OIDC client (`crate::oidc`) to the login session state machine
//! (`crate::login`) and to principal provisioning (PHASE 1b, see tasks.md).
//!
//! Three entry points, one per leg of a login:
//!  1. `start` -- called by `StartAuthSession`. Mints the per-session OIDC
//!     transients and persists a pending session.
//!  2. `authorize_redirect` -- called by `GET /login/{login_code}` when the
//!     operator's browser follows the URL the CLI gave them. Turns the
//!     stored transients into the provider's authorization request URL.
//!  3. `complete_callback` -- called by `GET /oidc/callback` when the
//!     provider redirects back. Validates everything, resolves a principal,
//!     and moves the session to `authenticated`.
//!
//! ## FAIL CLOSED
//! Every function here returns a deny (or an error) unless a specific,
//! positive condition holds. An unconfigured provider never reaches this
//! module at all -- its callers hold an `Option<Arc<OidcProvider>>` and deny
//! on `None`, so there is no code path where "OIDC is not set up" and "the
//! login succeeded" can both be true.
//!
//! ## Why the browser-facing outcomes are so coarse
//! `authorize_redirect` and `complete_callback` return `Invalid` for every
//! failure a client could probe with: unknown login code, unknown `state`,
//! expired session, already-used session, a `state` from a session that is
//! no longer pending. They deliberately do not distinguish, for the same
//! reason `GetAuthSession` does not (see `crate::login`).

use tonic::Status;
use uuid::Uuid;

use crate::db::Db;
use crate::db::principals;
use crate::db::principals::ExternalIdentity;
use crate::db::sessions;
use crate::login;
use crate::login::LoginSettings;
use crate::login::StartedSession;
use crate::oidc::OidcError;
use crate::oidc::OidcProvider;
use crate::secret::random_url_safe_token;
use crate::secret::sha256_b64url;

/// `principals.source` for every identity provisioned through OIDC. The
/// `(source, subject)` pair is unique (see `migrations/0002_...sql`), so an
/// IdP subject can never resolve to two principals.
pub const PRINCIPAL_SOURCE_OIDC: &str = "oidc";

/// Knobs specific to turning a verified OIDC identity into a principal.
#[derive(Debug, Clone)]
pub struct OidcLoginSettings {
    /// Create a principal on first login for an identity that has none.
    ///
    /// Safe to leave ON (the default) because it creates an IDENTITY, never
    /// an AUTHORIZATION: a just-provisioned principal has no role bindings,
    /// so its AuthZ token's `resources` claim is empty and it can see
    /// nothing until an operator grants it something.
    ///
    /// Turn it OFF for a closed deployment where every principal is
    /// pre-provisioned (by an admin, or later by SCIM); a login by an
    /// unknown identity then fails rather than creating a row.
    pub jit_provisioning: bool,
}

impl Default for OidcLoginSettings {
    fn default() -> Self {
        Self {
            jit_provisioning: true,
        }
    }
}

/// What `GET /login/{login_code}` should do.
#[derive(Debug)]
pub enum LoginPageOutcome {
    /// Send the browser to the identity provider.
    Redirect(String),
    /// Unknown, expired, or already-used login code. Deliberately one
    /// outcome, not three.
    Invalid,
    /// The identity provider itself could not be reached or configured.
    /// Distinguished from `Invalid` because it is an OPERATOR problem, not
    /// a user one, and telling a user to retry a broken provider forever is
    /// worse than telling them it is broken.
    ProviderUnavailable,
}

/// What `GET /oidc/callback` should do.
#[derive(Debug)]
pub enum CallbackOutcome {
    /// The session is now `authenticated`; the CLI's next poll will get a
    /// token. The browser gets a "you may close this tab" page.
    Completed,
    /// Anything that must not complete a login. One variant on purpose.
    Invalid,
    ProviderUnavailable,
}

/// Leg 1: mint this session's OIDC transients and persist a pending session.
///
/// `state`, `nonce` and the PKCE verifier are generated HERE, one set per
/// login, from the same CSPRNG as the session codes -- never derived from
/// anything the client sent, which would make them predictable to whoever
/// sent it.
pub async fn start(
    db: &Db,
    settings: &LoginSettings,
    client_state: &str,
) -> Result<StartedSession, Status> {
    let state = random_url_safe_token().map_err(|_| Status::internal("csprng unavailable"))?;
    let nonce = random_url_safe_token().map_err(|_| Status::internal("csprng unavailable"))?;
    // A 43-character base64url string, which is a valid RFC 7636 code
    // verifier as-is (43 to 128 characters from the unreserved set).
    let verifier = random_url_safe_token().map_err(|_| Status::internal("csprng unavailable"))?;

    login::start_session(db, settings, client_state, state, nonce, verifier).await
}

/// Leg 2: the operator's browser arrives with the login code from the URL
/// the CLI printed or opened.
pub async fn authorize_redirect(
    db: &Db,
    provider: &OidcProvider,
    login_code: &str,
) -> Result<LoginPageOutcome, Status> {
    let session = sessions::find_by_login_code_hash(db, &sha256_b64url(login_code))
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "login session lookup failed");
            Status::internal("login session lookup failed")
        })?;

    let Some(session) = session else {
        return Ok(LoginPageOutcome::Invalid);
    };
    if session.is_expired(login::now_ms()) || session.status != sessions::STATUS_PENDING {
        return Ok(LoginPageOutcome::Invalid);
    }

    match provider
        .authorization_url(
            &session.oidc_state,
            &session.oidc_nonce,
            &session.pkce_verifier,
        )
        .await
    {
        Ok(url) => Ok(LoginPageOutcome::Redirect(url)),
        Err(err) => {
            tracing::warn!(error = %err, "building the authorization URL failed");
            Ok(LoginPageOutcome::ProviderUnavailable)
        }
    }
}

/// Leg 3: the identity provider redirects the browser back with a code and
/// the `state` it was given.
///
/// Order of operations matters and is deliberate: `state` is resolved to a
/// session FIRST, so an unrecognized `state` never reaches the token
/// endpoint at all. That keeps this callback from being usable as a way to
/// make this service replay arbitrary authorization codes at the provider.
pub async fn complete_callback(
    db: &Db,
    provider: &OidcProvider,
    settings: &OidcLoginSettings,
    code: &str,
    state: &str,
) -> Result<CallbackOutcome, Status> {
    if code.is_empty() || state.is_empty() {
        return Ok(CallbackOutcome::Invalid);
    }

    // STATE VALIDATION. An unrecognized value finds nothing and stops here.
    let session = sessions::find_by_oidc_state(db, state)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "login session lookup failed");
            Status::internal("login session lookup failed")
        })?;
    let Some(session) = session else {
        tracing::warn!("OIDC callback presented a state that matches no login session");
        return Ok(CallbackOutcome::Invalid);
    };
    let now = login::now_ms();
    if session.is_expired(now) || session.status != sessions::STATUS_PENDING {
        // Covers an expired session AND a replayed callback for a session
        // that is already authenticated or consumed.
        return Ok(CallbackOutcome::Invalid);
    }

    // Signature, iss, aud, exp AND nonce are all verified inside this call;
    // it cannot return an identity with any of them unchecked.
    let identity = match provider
        .exchange_code(code, &session.pkce_verifier, &session.oidc_nonce)
        .await
    {
        Ok(identity) => identity,
        Err(OidcError::Provider | OidcError::Discovery) => {
            return Ok(CallbackOutcome::ProviderUnavailable);
        }
        Err(err) => {
            tracing::warn!(error = %err, "OIDC callback failed validation");
            return Ok(CallbackOutcome::Invalid);
        }
    };

    let external = ExternalIdentity {
        // The provider's `sub`, never the email: an email address can be
        // reassigned to a different human, a `sub` cannot.
        subject: identity.subject,
        source: PRINCIPAL_SOURCE_OIDC.to_string(),
        // The issuer doubles as the `idp` claim value: stable, meaningful to
        // an operator reading a raw token, and needs no extra configuration
        // to keep in sync with the provider it names.
        idp: provider.issuer().to_string(),
        display_name: identity
            .name
            .clone()
            .or_else(|| identity.preferred_username.clone())
            .or_else(|| identity.email.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        preferred_username: identity
            .preferred_username
            .clone()
            .or_else(|| identity.email.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        email: identity.email,
    };

    let Some(principal_id) = resolve_principal(db, &external, settings).await? else {
        // No principal, no login. Covers both "unknown identity and JIT is
        // off" and "known identity, but suspended or deprovisioned".
        return Ok(CallbackOutcome::Invalid);
    };

    // Path A IdP groups support (see tasks.md, docs/configuration.md): a
    // login-time snapshot, re-captured on every login. `identity.groups` was
    // already extracted and filtered by `OidcProvider::verify_id_token`
    // (`crate::oidc::extract_groups`); serializing a `Vec<String>` cannot
    // fail, so `.expect` here documents that rather than threading a
    // never-taken error path through this function.
    let groups_json = identity
        .groups
        .map(|groups| serde_json::to_string(&groups).expect("Vec<String> always serializes"));

    if !sessions::mark_authenticated(db, state, principal_id, groups_json.as_deref(), now)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "completing a login session failed");
            Status::internal("login session update failed")
        })?
    {
        // Lost a race with another callback for the same session, or the
        // session expired in the last few milliseconds. Either way this
        // callback did not complete the login.
        return Ok(CallbackOutcome::Invalid);
    }

    tracing::info!(
        %principal_id,
        idp = %provider.issuer(),
        "login session authenticated by the identity provider"
    );
    Ok(CallbackOutcome::Completed)
}

/// Maps a verified external identity onto a `principals` row.
///
/// Returns `None` -- deny -- for an unknown identity when JIT provisioning
/// is off, and for a known identity whose principal is suspended or
/// deprovisioned. That second case is why this reads the row regardless of
/// status: silently re-provisioning a deprovisioned user would turn
/// offboarding into a no-op.
async fn resolve_principal(
    db: &Db,
    identity: &ExternalIdentity,
    settings: &OidcLoginSettings,
) -> Result<Option<Uuid>, Status> {
    let existing = principals::find_principal_by_subject(db, &identity.source, &identity.subject)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "principal lookup by subject failed");
            Status::internal("principal lookup failed")
        })?;

    if let Some(principal) = existing {
        if principal.status != lore_authz_core::model::PrincipalStatus::Active {
            tracing::warn!(
                principal_id = %principal.id,
                "identity provider authenticated a principal that is not active; denying"
            );
            return Ok(None);
        }
        // Refresh what the provider is authoritative for. Never `status`.
        principals::update_external_identity(db, principal.id, identity)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "refreshing principal identity attributes failed");
                Status::internal("principal update failed")
            })?;
        return Ok(Some(principal.id));
    }

    if !settings.jit_provisioning {
        tracing::warn!(
            "identity provider authenticated an identity with no principal, and JIT provisioning \
             is disabled; denying"
        );
        return Ok(None);
    }

    let id = Uuid::new_v4();
    principals::insert_external_principal(db, id, identity)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "JIT provisioning failed");
            Status::internal("principal provisioning failed")
        })?;

    // Re-read rather than assume `id` won: the insert is
    // `ON CONFLICT (source, subject) DO NOTHING`, so a concurrent first
    // login for the same brand-new identity may have created the row
    // instead. The loser of that race must use the winner's principal, not
    // an id that was never inserted.
    let created = principals::find_principal_by_subject(db, &identity.source, &identity.subject)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "principal lookup after provisioning failed");
            Status::internal("principal lookup failed")
        })?;
    match created {
        Some(principal) if principal.status == lore_authz_core::model::PrincipalStatus::Active => {
            tracing::info!(principal_id = %principal.id, "JIT-provisioned a new principal with no grants");
            Ok(Some(principal.id))
        }
        _ => {
            tracing::warn!("principal was not readable immediately after provisioning; denying");
            Ok(None)
        }
    }
}
