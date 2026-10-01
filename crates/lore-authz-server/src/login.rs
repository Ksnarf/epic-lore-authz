//! The browser login session state machine (PHASE 1b, see tasks.md): the
//! logic behind `StartAuthSession` / `GetAuthSession`, kept out of
//! `crate::grpc` so the rules can be read (and tested) without a gRPC
//! request in the way.
//!
//! Storage lives in `crate::db::sessions`; the identity-provider leg that
//! moves a session from `pending` to `authenticated` lives in
//! `crate::oidc_login`. This module owns what happens either side of it.
//!
//! ## The polling oracle this module refuses to be
//! `GetAuthSession` is an UNAUTHENTICATED endpoint that takes a secret and
//! says whether it worked. That makes it an oracle by default, so every
//! not-yet-a-token outcome collapses to the SAME response: `Ok(None)`,
//! which the CLI reads as "keep polling".
//!
//! Unknown session_code, expired session, wrong client_state, a session
//! still waiting on the browser, a session already consumed, and a session
//! whose principal has since been deprovisioned are therefore
//! indistinguishable to a caller. A probe cannot use this endpoint to
//! enumerate valid session codes, to learn that a code WAS valid and has
//! already been used, or to confirm a guessed client_state. See
//! `PollOutcome` below, whose only two variants are the two things a client
//! is allowed to learn.
//!
//! The one thing deliberately NOT claimed: this equalizes the RESPONSE, and
//! it equalizes the number of database round trips for the unknown/expired/
//! mismatch/pending cases (all exactly one), but it does not claim
//! constant-time behaviour against a determined timing attacker. The
//! session_code is 256 bits of CSPRNG entropy, so there is nothing for a
//! timing oracle to usefully narrow down.
//!
//! ## The 150-second client deadline (documented, not worked around)
//! The lore CLI polls every 5 seconds up to 30 times and then gives up
//! (`POLLING_MAX_RETRIES * POLLING_INTERVAL_SECS` in the CLI's own
//! `auth/login.rs`) -- a hard 150-second budget for the whole browser leg,
//! set client-side, that this service cannot extend. Enterprise MFA (a push
//! notification to a phone that is in another room) routinely exceeds it.
//!
//! What that means in practice, and why the session TTL is deliberately
//! LONGER than 150 seconds (`AUTH_SESSION_TTL_SECS`, default 300): the CLI
//! gives up, but the session stays valid, so the user who completes MFA a
//! minute later still lands on a success page rather than an error, and
//! simply re-runs the login -- which is fast the second time, because the
//! IdP session is now established. Deliberately not "solved" server-side:
//! the only server-side lever would be to hold the poll open (long-polling),
//! which this proto's request/response shape does not support, or to lie
//! about progress, which it must not.

use lore_authz_core::claims::SignedToken;
use tonic::Status;

use crate::db::Db;
use crate::db::principals;
use crate::db::sessions;
use crate::minting::AuthnTokenInput;
use crate::minting::mint_authn_token;
use crate::secret::constant_time_eq;
use crate::secret::sha256_b64url;
use crate::signing::SigningKeyStore;

/// Milliseconds since the UNIX epoch. Sessions store their timestamps in
/// this unit on both database backends (see
/// `migrations/0002_auth_sessions.sql`).
pub fn now_ms() -> i64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the UNIX epoch");
    i64::try_from(since_epoch.as_millis()).unwrap_or(i64::MAX)
}

/// Everything the login/exchange RPCs need that is neither a database
/// handle, a signing key, nor an identity provider. Grouped into one struct
/// rather than eight more fields on `AuthApiService` so adding a knob does
/// not churn every construction site.
#[derive(Debug, Clone)]
pub struct LoginSettings {
    /// `env` claim on every minted token. MANDATORY on both claim shapes --
    /// omitting it fails lore-server's decode loudly (docs/protocol-notes.md
    /// section 2).
    pub token_env: String,
    pub authn_token_ttl_secs: u64,
    pub authz_token_ttl_secs: u64,
    /// How long a login session stays usable. Deliberately longer than the
    /// CLI's own 150-second polling budget -- see the module doc comment.
    pub session_ttl_secs: u64,
    /// Origin (scheme + host + optional port, no trailing slash) this
    /// service is reachable at IN A BROWSER. `StartAuthSession` builds the
    /// `login_url` it hands the CLI from this. Empty means "not configured",
    /// and `StartAuthSession` fails closed rather than handing out a login
    /// URL that goes nowhere.
    pub public_base_url: String,
    /// `idp` claim fallback for principals with no recorded identity
    /// provider (`Principal::idp` is `None`) -- the Phase 1a manual/test
    /// provisioning path. Never empty: an AuthZ token with an absent or
    /// empty `idp` fails SILENTLY at lore-server, dropping `resources` to
    /// `None` (docs/protocol-notes.md section 2).
    pub default_idp: String,
}

impl Default for LoginSettings {
    /// Matches the documented defaults in `.env.example` /
    /// `docs/configuration.md`, EXCEPT `public_base_url`, which has no safe
    /// default and is left empty so `StartAuthSession` denies until an
    /// operator sets it.
    fn default() -> Self {
        Self {
            token_env: "dev".to_string(),
            authn_token_ttl_secs: 36_000,
            authz_token_ttl_secs: 3_600,
            session_ttl_secs: 300,
            public_base_url: String::new(),
            default_idp: "local".to_string(),
        }
    }
}

/// What `StartAuthSession` hands back to the CLI, plus the secrets it must
/// NOT hand back.
#[derive(Debug, Clone)]
pub struct StartedSession {
    /// Returned to the CLI over gRPC. The polling credential.
    pub session_code: String,
    /// Returned to the CLI over gRPC, opened in a browser.
    pub login_url: String,
}

/// The only two things a `GetAuthSession` caller is allowed to learn. Every
/// failure mode -- unknown code, expired session, wrong client_state, still
/// pending, already consumed, principal since deprovisioned -- is
/// `KeepPolling`. See the module doc comment.
#[derive(Debug)]
pub enum PollOutcome {
    KeepPolling,
    Authenticated(AuthenticatedUser),
}

/// A completed login, ready to be shaped into an `epic_urc::UserToken`.
#[derive(Debug)]
pub struct AuthenticatedUser {
    pub token: SignedToken,
    /// Our `principals.id`, which is also the token's `sub` claim.
    pub user_id: String,
    pub user_name: String,
}

/// Creates a pending login session and returns the CLI-facing pair.
///
/// `oidc_state`, `oidc_nonce` and `pkce_verifier` are generated by the
/// caller (`crate::oidc_login::start`) because they belong to the identity
/// provider leg, not to session bookkeeping; this function only persists
/// them alongside the session they belong to.
pub async fn start_session(
    db: &Db,
    settings: &LoginSettings,
    client_state: &str,
    oidc_state: String,
    oidc_nonce: String,
    pkce_verifier: String,
) -> Result<StartedSession, Status> {
    if settings.public_base_url.is_empty() {
        return Err(Status::failed_precondition(
            "PUBLIC_BASE_URL is not configured, so no browser login URL can be issued -- see \
             docs/configuration.md",
        ));
    }
    // The CLI always sends one (a fresh UUID per login attempt). Refusing an
    // empty one is not pedantry: client_state is half of what a poll must
    // present, so accepting an empty value would make every such session
    // pollable by anyone holding only the session_code.
    if client_state.trim().is_empty() {
        return Err(Status::invalid_argument("client_state must not be empty"));
    }

    let now = now_ms();

    // Opportunistic cleanup, best effort: a reaper failure must never fail
    // a login (see db::sessions::delete_expired).
    match sessions::delete_expired(db, now).await {
        Ok(0) => {}
        Ok(removed) => tracing::debug!(removed, "reaped expired auth sessions"),
        Err(err) => tracing::warn!(error = %err, "reaping expired auth sessions failed"),
    }

    let session_code = crate::secret::random_url_safe_token()
        .map_err(|_| Status::internal("session code generation failed"))?;
    let login_code = crate::secret::random_url_safe_token()
        .map_err(|_| Status::internal("session code generation failed"))?;

    let expires_at_ms = now.saturating_add(
        i64::try_from(settings.session_ttl_secs)
            .unwrap_or(300)
            .saturating_mul(1000),
    );

    sessions::insert(
        db,
        &sessions::NewSession {
            session_code_hash: sha256_b64url(&session_code),
            login_code_hash: sha256_b64url(&login_code),
            client_state_hash: sha256_b64url(client_state),
            oidc_state,
            oidc_nonce,
            pkce_verifier,
            created_at_ms: now,
            expires_at_ms,
        },
    )
    .await
    .map_err(|err| {
        tracing::warn!(error = %err, "persisting a new auth session failed");
        Status::internal("starting an auth session failed")
    })?;

    Ok(StartedSession {
        login_url: format!(
            "{}/login/{login_code}",
            settings.public_base_url.trim_end_matches('/')
        ),
        session_code,
    })
}

/// One `GetAuthSession` poll.
///
/// Mints the AuthN token if and only if the database itself confirms this
/// caller is the one that consumed a still-valid, authenticated,
/// not-yet-consumed session (`db::sessions::consume` returning `true`).
/// Everything else is `KeepPolling`.
pub async fn poll_session(
    db: &Db,
    signing_keys: &SigningKeyStore,
    settings: &LoginSettings,
    issuer: &str,
    audience: &[String],
    session_code: &str,
    client_state: &str,
) -> Result<PollOutcome, Status> {
    let now = now_ms();
    let session_code_hash = sha256_b64url(session_code);

    // Exactly one database round trip on every not-yet-a-token path,
    // including the unknown-code path -- see the module doc comment.
    let session = sessions::find_by_session_code_hash(db, &session_code_hash)
        .await
        .map_err(|err| {
            // A real database failure is the ONE case that must not look
            // like "keep polling": failing closed here means an Err, not a
            // response that invites 29 more pointless polls.
            tracing::warn!(error = %err, "auth session lookup failed");
            Status::internal("auth session lookup failed")
        })?;

    let Some(session) = session else {
        return Ok(PollOutcome::KeepPolling);
    };
    if session.is_expired(now) {
        return Ok(PollOutcome::KeepPolling);
    }
    if !constant_time_eq(
        session.client_state_hash.as_bytes(),
        sha256_b64url(client_state).as_bytes(),
    ) {
        return Ok(PollOutcome::KeepPolling);
    }
    if session.status != sessions::STATUS_AUTHENTICATED {
        return Ok(PollOutcome::KeepPolling);
    }
    let Some(principal_id) = session.principal_id else {
        // Defence in depth: the state machine cannot reach `authenticated`
        // without a principal (db::sessions::mark_authenticated binds both
        // in one statement), so this is unreachable unless something wrote
        // the table directly. Deny rather than trust it.
        tracing::warn!("authenticated auth session has no principal_id; denying");
        return Ok(PollOutcome::KeepPolling);
    };

    // THE single-use gate. Claim the session BEFORE minting anything, so a
    // concurrent second poll cannot also mint.
    if !sessions::consume(db, &session_code_hash, now)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "consuming an auth session failed");
            Status::internal("auth session update failed")
        })?
    {
        return Ok(PollOutcome::KeepPolling);
    }

    // Re-checked at token-mint time, not just at login time: a principal
    // suspended or deprovisioned between the browser callback and this poll
    // must not receive a token.
    let principal = principals::find_active_principal(db, principal_id)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "principal lookup failed");
            Status::internal("principal lookup failed")
        })?;
    let Some(principal) = principal else {
        tracing::warn!(
            %principal_id,
            "auth session completed for a principal that is no longer active; denying"
        );
        return Ok(PollOutcome::KeepPolling);
    };

    let token = mint_authn_token(
        signing_keys.active(),
        issuer,
        audience,
        &settings.token_env,
        settings.authn_token_ttl_secs,
        &AuthnTokenInput {
            user_id: principal.id.to_string(),
            name: principal.display_name.clone(),
            preferred_username: principal.preferred_username.clone(),
            is_service_account: principal.is_service_account,
            // Path A IdP groups support: this login's groups snapshot,
            // captured by the OIDC callback (crate::oidc_login::
            // complete_callback) and read back off the session row here --
            // see migrations/0003_auth_session_groups.sql.
            groups: session.groups.clone(),
        },
    )
    .map_err(|err| {
        // Deliberately does NOT include `err` in the client-visible message:
        // jsonwebtoken errors can carry fragments of what was being signed.
        tracing::warn!(error = %err, "minting an AuthN token failed");
        Status::internal("token minting failed")
    })?;

    tracing::info!(
        principal_id = %principal.id,
        "login completed: AuthN token issued and session consumed"
    );

    Ok(PollOutcome::Authenticated(AuthenticatedUser {
        token,
        user_id: principal.id.to_string(),
        user_name: principal.display_name,
    }))
}
