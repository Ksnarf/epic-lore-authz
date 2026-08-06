//! PHASE 1a (see tasks.md) authorization test suite, shared verbatim
//! between BOTH database backends -- not a mock either way. This project
//! has already been burned by mocked tests passing while real integration
//! was broken (see `docs/protocol-notes.md`'s claim-shape-drift discussion
//! and the compat test philosophy in `tests/lore_compat.rs`), so
//! `LookupUserPermissions` and `CheckUserPermission` get the same
//! treatment: exercised against real SQL, a real connection pool, and (for
//! the DB-failure case) a real closed pool, never a stand-in.
//!
//! ## Why this module exists (not just `tests/postgres_backed.rs`)
//! Task 2 of the SQLite backend work requires the SQLite backend to run the
//! IDENTICAL authz test suite as Postgres -- not a subset, not a weaker
//! parallel suite. Every test body below is defined exactly ONCE, taking a
//! `Backend` parameter, and is called from TWO thin wrapper files:
//! `tests/postgres_backed.rs` (`Backend::Postgres`) and
//! `tests/sqlite_backed.rs` (`Backend::Sqlite`). It is structurally
//! impossible to update one backend's coverage without the other, because
//! there is only one copy of each test body to update. This file is
//! `#[path]`-included into both wrapper binaries (see either wrapper file's
//! top), so it is compiled twice -- once per backend's test binary -- which
//! is normal for this pattern and not a bug.
//!
//! ## Running these tests
//! Postgres: requires `TEST_DATABASE_URL` to point at a real, reachable
//! Postgres instance (any throwaway one -- these tests never `CREATE
//! DATABASE`, they only ever create their own schema inside whatever
//! database the URL names). See `docker-compose.test.yml` at the repo root
//! for a documented, reproducible way to provide one. If `TEST_DATABASE_URL`
//! is not set, every Postgres-backed test panics with a message saying so --
//! intentional (fail loudly, not skip silently), not a passing-but-untested
//! green result.
//!
//! SQLite: needs nothing external. Each test gets its own throwaway file
//! under the OS temp directory (`fresh_db`, below), migrated fresh --
//! stronger isolation than Postgres's per-test schema trick, not weaker,
//! since it is a genuinely separate database file, not a shared instance.
//!
//! Each Postgres test connects with its OWN randomly-named schema
//! (`test_<uuid>`) inside the same database, so tests can run concurrently
//! against one shared Postgres instance without seeing each other's data --
//! this is also, incidentally, a live proof that `DB_SCHEMA` isolation
//! actually works, not just something asserted in a doc comment. SQLite has
//! no schema concept (`DB_SCHEMA` is a no-op there -- see `db/mod.rs` and
//! docs/configuration.md), so its per-test isolation comes from the
//! throwaway file instead.
//!
//! ## What each required case proves
//! - `wildcard_grant_allows_any_registered_resource`: a `urc-*` binding
//!   authorizes a specific, real, currently-registered resource.
//! - `specific_repository_grant_does_not_cover_other_repositories`: a
//!   binding scoped to one resource_id does NOT leak into a sibling
//!   resource -- this is the "not over-broad" property in miniature.
//! - `user_with_no_grants_denies_everything`: zero role_bindings at all
//!   denies every check and returns an empty `LookupUserPermissions` set.
//! - `group_inherited_grant`: no DIRECT binding on the user at all -- the
//!   grant only exists on a group the user belongs to.
//! - `service_account_direct_grant`: `principal_kind = 'service_account'`
//!   is exercised for real, not assumed to behave like `'user'`.
//! - `lookup_user_permissions_returns_exact_scoped_set_no_more_no_less` and
//!   `lookup_user_permissions_specific_only_does_not_leak_other_resources`:
//!   `LookupUserPermissions` is lore-server's ONLY candidate list for
//!   `RepositoryList` (see `crates/lore-authz-server/src/grpc.rs`'s
//!   `lookup_user_permissions` doc comment and the fork's
//!   `repository_list::lookup_authorized_repositories`) -- an over-broad
//!   return is a real authorization bug, so these assert the EXACT `Vec`,
//!   not a superset/subset check.
//! - `nonexistent_resource_is_denied_not_errored`: even a wildcard `admin`
//!   grant does not authorize a `resource_id` that was never created via
//!   `RebacApi::CreateResource`.
//! - `unknown_principal_id_denies_check` /
//!   `unknown_principal_id_denies_lookup`: a correctly-signed, unexpired
//!   token whose `sub` does not resolve to any `principals` row.
//! - `missing_bearer_token_is_unauthenticated`: no `authorization` metadata
//!   at all.
//! - `database_failure_denies_rather_than_grants`: the connection pool is
//!   closed out from under an otherwise-valid, otherwise-authorized
//!   request -- proves a real DB error surfaces as `Err`, never as an empty
//!   or partial `Ok` that could be misread as "checked, nothing granted."
//! - `check_user_permission_with_explicit_target_user_token`: the
//!   `target_user.user_token` path (as opposed to the `authorization`
//!   metadata path), which `CheckUserPermissionRequest` supports as an
//!   alternative to the caller's own header.
//! - `create_resource_is_idempotent` /
//!   `delete_resource_revokes_access_and_is_idempotent`: `RebacApi`'s two
//!   RPCs, including that a delete actually revokes access and that both
//!   RPCs tolerate being called twice.
//! - `rebac_create_resource_denies_unauthenticated_caller_against_real_db` /
//!   `rebac_delete_resource_denies_unauthenticated_caller_against_real_db` /
//!   `rebac_create_resource_denies_wrong_service_token_against_real_db` /
//!   `rebac_create_resource_rejects_wildcard_sentinel_against_real_db`: the
//!   `RebacApi` caller-identity gate (security review remediation, see
//!   tasks.md and docs/open-questions.md Q6), proven end to end against a
//!   real database, not just at the grpc.rs unit level with `db: None`.
//! - `migrations_are_idempotent`: re-running a backend's embedded
//!   migrations against an already-migrated database is a no-op, not an
//!   error.
//!
//! ## PHASE 1b cases (login sessions and the AuthZ token exchange)
//! - `poll_returns_an_authn_token_once_the_browser_leg_completes`: the happy
//!   path for everything either side of the identity provider -- a session
//!   is started through the real `login::start_session`, the browser leg
//!   completes through the same `db::sessions::mark_authenticated` the OIDC
//!   callback calls, and the next `GetAuthSession` returns a
//!   signature-verifiable AuthN token. Also asserts `UserToken.expires_at`
//!   is MILLISECONDS and equals the JWT's own seconds-valued `exp` times
//!   1000 (docs/open-questions.md Q1), and that the browser login URL does
//!   not contain the polling secret.
//! - `poll_is_single_use_and_never_reissues`: a replayed `session_code`
//!   never mints a second token.
//! - `poll_with_an_unknown_session_code_is_indistinguishable_from_pending`:
//!   this endpoint is unauthenticated, so an unknown (or empty) code must
//!   produce exactly the same response as a pending one -- no oracle.
//! - `poll_with_a_mismatched_client_state_never_issues_a_token`: the
//!   `session_code` alone is not enough, and a failed attempt does not
//!   consume the session out from under its rightful owner.
//! - `expired_sessions_are_denied_at_both_transitions`: an expired session
//!   can be neither authenticated by the callback nor redeemed by a poll.
//! - `poll_denies_when_the_session_principal_is_not_active`: identity is
//!   re-checked at mint time, not trusted from the session row.
//! - `starting_a_session_without_a_public_base_url_fails_closed` and
//!   `starting_a_session_reaps_expired_ones`: `StartAuthSession` denies
//!   rather than emitting a login URL it cannot build, refuses an empty
//!   `client_state`, and reaps expired rows so the table cannot grow without
//!   bound.
//! - `exchange_mints_an_authz_token_with_resources_idp_and_env`: THE
//!   high-value one -- the exchanged token carries `resources`, a non-empty
//!   `idp` recovered from the PRINCIPAL ROW (the AuthN token it was handed
//!   has no such claim), and `env`. Missing `env` fails loudly at
//!   lore-server; missing `idp` fails silently and looks like a permissions
//!   bug (docs/protocol-notes.md section 2).
//! - `exchange_falls_back_to_the_configured_idp_when_the_principal_has_none`:
//!   an empty `idp` is as broken as an absent one, so there is a fallback
//!   and it is never empty. Also re-proves wildcard expansion.
//! - `exchange_omits_resources_the_caller_has_no_grant_for` and
//!   `exchange_for_a_caller_with_no_grants_yields_an_empty_resources_claim`:
//!   the exchange never widens access, and a caller entitled to nothing gets
//!   a well-formed token that authorizes nothing.
//! - `exchange_denies_every_unauthenticated_caller`: no bearer token, a
//!   garbage bearer token, and a validly-signed token for a principal that
//!   does not exist all deny before anything is minted.

use std::sync::Arc;

use lore_authz_proto::RebacApi as _;
use lore_authz_proto::UrcAuthApi as _;
use lore_authz_proto::epic_urc;
use lore_authz_proto::ucs::auth as rebac;
use lore_authz_server::db::Db;
use lore_authz_server::db::groups;
use lore_authz_server::db::permissions::ROLE_ADMIN;
use lore_authz_server::db::permissions::ROLE_READER;
use lore_authz_server::db::permissions::ROLE_WRITER;
use lore_authz_server::db::permissions::grant;
use lore_authz_server::db::principals::ExternalIdentity;
use lore_authz_server::db::principals::insert_external_principal;
use lore_authz_server::db::principals::insert_principal;
use lore_authz_server::db::sessions;
use lore_authz_server::grpc::AuthApiService;
use lore_authz_server::grpc::RebacApiService;
use lore_authz_server::login;
use lore_authz_server::login::LoginSettings;
use lore_authz_server::minting::AuthnTokenInput;
use lore_authz_server::minting::AuthzTokenInput;
use lore_authz_server::minting::mint_authn_token;
use lore_authz_server::minting::mint_authz_token;
use lore_authz_server::secret::random_url_safe_token;
use lore_authz_server::signing::SigningKeyStore;
use tonic::Code;
use tonic::Request;
use uuid::Uuid;

const ISSUER: &str = "https://authz.example.com";

/// `env` claim on every token these tests mint or assert on. Non-negotiable
/// on both claim shapes -- see docs/protocol-notes.md section 2.
const TOKEN_ENV: &str = "test";

/// `idp` fallback for principals with no recorded identity provider. Used
/// to prove the exchange RPC never emits an empty `idp` even for a
/// principal that never went through an IdP.
const DEFAULT_IDP: &str = "test-default-idp";

/// Browser-facing origin these tests configure. Only its SHAPE matters here
/// (that `login_url` is built from it); nothing dials it.
const PUBLIC_BASE_URL: &str = "https://authz.example.com";

/// Shared secret gating `RebacApi` in these tests -- see
/// `crates/lore-authz-server/src/service_auth.rs` and
/// `docs/open-questions.md` Q6 for why this hop uses a static shared secret
/// rather than the user bearer-JWT path `crate::caller` verifies.
const TEST_REBAC_SERVICE_TOKEN: &str = "test-only-shared-secret-do-not-use-in-prod";

/// Which database backend a given test run is exercising -- see `db/mod.rs`
/// for the production selection mechanism (`DATABASE_URL`'s scheme); tests
/// pick explicitly instead, since a single `cargo test --workspace` run
/// must exercise BOTH.
///
/// `#[allow(dead_code)]`: this module is `#[path]`-included separately into
/// TWO test binaries (`tests/postgres_backed.rs`, `tests/sqlite_backed.rs`),
/// each its own compilation unit. Within any ONE of those binaries, only
/// one variant is ever constructed (that binary's wrappers all pass the
/// same `Backend`), so rustc's per-binary dead-code analysis flags the
/// other variant -- both variants ARE used, just never both in the same
/// binary. Not dead code at the module's actual purpose.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Backend {
    Postgres,
    Sqlite,
}

fn audience() -> Vec<String> {
    vec!["lore.example.com".to_string()]
}

fn test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL").expect(
        "TEST_DATABASE_URL must point at a real, reachable Postgres instance to run these \
         tests -- see docker-compose.test.yml at the repo root for a documented way to provide \
         one. These are real Postgres integration tests, not mocked; there is no fallback.",
    )
}

/// A fresh, isolated, migrated database for one test, on whichever backend
/// `backend` names. Postgres: a uniquely-named throwaway schema inside
/// `TEST_DATABASE_URL` (proves `DB_SCHEMA` isolation for real, and lets
/// tests run concurrently against one shared instance). SQLite: a uniquely
/// named throwaway file under the OS temp directory -- needs nothing
/// external, and gives EVERY test its own database file, not merely its own
/// schema inside a shared one.
async fn fresh_db(backend: Backend) -> Db {
    match backend {
        Backend::Postgres => {
            let schema = format!("test_{}", Uuid::new_v4().simple());
            Db::connect(&test_database_url(), &schema)
                .await
                .expect("connect + migrate a fresh throwaway Postgres schema")
        }
        Backend::Sqlite => {
            let path = std::env::temp_dir()
                .join(format!("epic-lore-authz-test-{}.sqlite3", Uuid::new_v4()));
            let database_url = format!("sqlite://{}", path.display());
            // "loreauth" (the documented DB_SCHEMA default) is passed here
            // purely so this hits Db::connect's informational no-op log
            // path rather than its "you set something non-default" warning
            // -- DB_SCHEMA has no effect on SQLite either way, see
            // db/mod.rs and docs/configuration.md.
            Db::connect(&database_url, "loreauth")
                .await
                .expect("connect + migrate a fresh throwaway sqlite file")
        }
    }
}

/// The base login/token settings every harness uses. `session_ttl_secs` is
/// overridden per test where expiry is the thing under test.
fn login_settings() -> LoginSettings {
    LoginSettings {
        token_env: TOKEN_ENV.to_string(),
        authn_token_ttl_secs: 36_000,
        authz_token_ttl_secs: 3_600,
        session_ttl_secs: 300,
        public_base_url: PUBLIC_BASE_URL.to_string(),
        default_idp: DEFAULT_IDP.to_string(),
    }
}

struct Harness {
    db: Arc<Db>,
    auth_service: AuthApiService,
    rebac_service: RebacApiService,
}

impl Harness {
    async fn new(backend: Backend) -> Self {
        let db = Arc::new(fresh_db(backend).await);
        let signing_keys = Arc::new(
            SigningKeyStore::load("file:///epic-lore-authz-test-fixture-does-not-exist.der")
                .expect("ephemeral signing key for test"),
        );
        let auth_service = AuthApiService {
            db: Some(db.clone()),
            signing_keys,
            jwt_issuer: ISSUER.to_string(),
            jwt_audience: audience(),
            login: login_settings(),
            // These cases exercise everything either side of the identity
            // provider; the provider leg itself has its own suite against a
            // REAL IdP container (tests/oidc_flow.rs). `None` here also
            // means `StartAuthSession` denies, which is asserted directly.
            oidc: None,
        };
        let rebac_service = RebacApiService {
            db: Some(db.clone()),
            rebac_service_token: Some(TEST_REBAC_SERVICE_TOKEN.to_string()),
        };
        Self {
            db,
            auth_service,
            rebac_service,
        }
    }

    /// Mints a real, signed AuthZ token for `user_id` using this harness's
    /// own signing key, and wraps it as a `Bearer` gRPC request -- the same
    /// shape lore-server forwards from the original CLI caller (see
    /// `crates/lore-authz-server/src/caller.rs`'s doc comment on the two
    /// observed `authorization` shapes).
    fn token_for(&self, user_id: Uuid) -> String {
        mint_authz_token(
            self.auth_service.signing_keys.active(),
            ISSUER,
            &audience(),
            "test",
            3600,
            &AuthzTokenInput {
                user_id: user_id.to_string(),
                name: "Test User".to_string(),
                preferred_username: "testuser".to_string(),
                is_service_account: false,
                idp: "test-idp".to_string(),
                groups: None,
                resources: vec![],
            },
        )
        .expect("mint test token")
        .token
    }

    fn request_with_bearer<T>(&self, body: T, user_id: Uuid) -> Request<T> {
        let mut req = Request::new(body);
        let token = self.token_for(user_id);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    /// Wraps a `RebacApi` request with the shared-secret bearer this
    /// harness's `rebac_service` was configured with -- see
    /// `TEST_REBAC_SERVICE_TOKEN` and `crate::service_auth`. Distinct from
    /// `request_with_bearer` above (which mints a user AuthZ/AuthN token):
    /// `RebacApi`'s caller is lore-server itself, not a user, so it is
    /// gated by a different mechanism entirely.
    fn rebac_request<T>(&self, body: T) -> Request<T> {
        let mut req = Request::new(body);
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {TEST_REBAC_SERVICE_TOKEN}")
                .parse()
                .unwrap(),
        );
        req
    }

    async fn create_resource(&self, resource_id: &str) {
        self.rebac_service
            .create_resource(self.rebac_request(rebac::CreateResourceRequest {
                resource_id: resource_id.to_string(),
                resource_name: resource_id.to_string(),
            }))
            .await
            .expect("create_resource");
    }

    /// Mints an AuthN token (identity only, NO `resources` and NO `idp`) and
    /// wraps it as a `Bearer` request -- the exact shape the lore CLI
    /// presents to `ExchangeUserTokenForMultiresourceToken`. Distinct from
    /// `request_with_bearer` above, which mints an AuthZ token: the exchange
    /// RPC is specifically the hop where the caller has only the AuthN
    /// token, which is why it cannot read `idp` off the token it is handed
    /// (docs/protocol-notes.md #7b).
    fn request_with_authn_bearer<T>(
        &self,
        body: T,
        user_id: Uuid,
        display_name: &str,
    ) -> Request<T> {
        let token = mint_authn_token(
            self.auth_service.signing_keys.active(),
            ISSUER,
            &audience(),
            TOKEN_ENV,
            3600,
            &AuthnTokenInput {
                user_id: user_id.to_string(),
                name: display_name.to_string(),
                preferred_username: display_name.to_string(),
                is_service_account: false,
            },
        )
        .expect("mint AuthN test token")
        .token;
        let mut req = Request::new(body);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    /// Starts a real login session through the production code path
    /// (`login::start_session`), returning what the CLI would get plus the
    /// OIDC `state` the browser leg will present -- which in production is
    /// generated by `crate::oidc_login` and handed to the same function.
    async fn start_login(&self, client_state: &str) -> StartedTestSession {
        self.start_login_with_ttl(client_state, 300).await
    }

    async fn start_login_with_ttl(
        &self,
        client_state: &str,
        session_ttl_secs: u64,
    ) -> StartedTestSession {
        let oidc_state = random_url_safe_token().expect("csprng");
        let settings = LoginSettings {
            session_ttl_secs,
            ..login_settings()
        };
        let started = login::start_session(
            &self.db,
            &settings,
            client_state,
            oidc_state.clone(),
            random_url_safe_token().expect("csprng"),
            random_url_safe_token().expect("csprng"),
        )
        .await
        .expect("start_session");
        StartedTestSession {
            session_code: started.session_code,
            login_url: started.login_url,
            oidc_state,
        }
    }

    /// Completes the browser leg the way the real OIDC callback does --
    /// through `db::sessions::mark_authenticated`, the same function
    /// `crate::oidc_login` calls once it has verified an ID token. Returns
    /// whether the transition actually happened.
    async fn complete_login(&self, oidc_state: &str, principal_id: Uuid) -> bool {
        sessions::mark_authenticated(&self.db, oidc_state, principal_id, login::now_ms())
            .await
            .expect("mark_authenticated")
    }

    /// Polls exactly as the CLI does, through the real gRPC handler.
    async fn poll(&self, session_code: &str, client_state: &str) -> Option<epic_urc::UserToken> {
        self.auth_service
            .get_auth_session(Request::new(epic_urc::GetAuthSessionRequest {
                session_code: session_code.to_string(),
                client_state: client_state.to_string(),
            }))
            .await
            .expect("get_auth_session must not error on any keep-polling path")
            .into_inner()
            .user_token
    }

    async fn create_user(&self, id: Uuid, name: &str) {
        insert_principal(&self.db, id, name, false)
            .await
            .expect("insert_principal (user)");
    }

    /// A principal provisioned the way the OIDC login leg provisions one,
    /// with a recorded `idp` -- so the exchange RPC's "recover `idp` from
    /// the principal row" path can be tested for real rather than only its
    /// fallback.
    async fn create_oidc_user(&self, id: Uuid, name: &str, subject: &str, idp: &str) {
        insert_external_principal(
            &self.db,
            id,
            &ExternalIdentity {
                subject: subject.to_string(),
                source: "oidc".to_string(),
                idp: idp.to_string(),
                display_name: name.to_string(),
                preferred_username: name.to_string(),
                email: None,
            },
        )
        .await
        .expect("insert_external_principal");
    }

    async fn create_service_account(&self, id: Uuid, name: &str) {
        insert_principal(&self.db, id, name, true)
            .await
            .expect("insert_principal (service account)");
    }

    async fn create_group(&self, id: Uuid, name: &str) {
        groups::insert_group(&self.db, id, name)
            .await
            .expect("insert_group");
    }

    async fn add_group_member(&self, group_id: Uuid, user_id: Uuid) {
        groups::add_member(&self.db, group_id, user_id)
            .await
            .expect("add_member");
    }

    async fn grant_wildcard(&self, role_id: Uuid, principal_kind: &str, principal_id: Uuid) {
        grant(
            &self.db,
            role_id,
            lore_authz_server::db::permissions::WILDCARD_RESOURCE_PATTERN,
            principal_kind,
            principal_id,
        )
        .await
        .expect("grant wildcard");
    }

    async fn grant_specific(
        &self,
        role_id: Uuid,
        resource_id: &str,
        principal_kind: &str,
        principal_id: Uuid,
    ) {
        grant(&self.db, role_id, resource_id, principal_kind, principal_id)
            .await
            .expect("grant specific");
    }
}

/// What `Harness::start_login` hands back: the CLI-facing pair plus the OIDC
/// `state` that the browser leg needs (and that a test playing the attacker
/// must NOT be able to guess).
struct StartedTestSession {
    session_code: String,
    login_url: String,
    oidc_state: String,
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// Decodes a token this suite's own signing key produced, verifying the
/// SIGNATURE, issuer and audience for real -- these assertions are about
/// what a relying party would accept, so decoding without verification would
/// prove nothing.
fn decode_authz_claims(
    h: &Harness,
    token: &str,
) -> jsonwebtoken::TokenData<lore_authz_core::claims::AuthzClaims> {
    let key = jsonwebtoken::DecodingKey::from_jwk(&h.auth_service.signing_keys.active().public_jwk)
        .expect("our own public JWK");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&audience());
    jsonwebtoken::decode(token, &key, &validation).expect("minted AuthZ token must verify")
}

fn decode_authn_claims(
    h: &Harness,
    token: &str,
) -> jsonwebtoken::TokenData<lore_authz_core::claims::AuthnClaims> {
    let key = jsonwebtoken::DecodingKey::from_jwk(&h.auth_service.signing_keys.active().public_jwk)
        .expect("our own public JWK");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&audience());
    jsonwebtoken::decode(token, &key, &validation).expect("minted AuthN token must verify")
}

pub async fn wildcard_grant_allows_any_registered_resource(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Alice").await;
    h.create_resource("urc-repo1").await;
    h.grant_wildcard(ROLE_READER, "user", user).await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-repo1".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission")
        .into_inner();

    assert_eq!(resp.allowed_resource_permission.len(), 1);
    assert_eq!(resp.allowed_resource_permission[0].resource_id, "urc-repo1");
    assert_eq!(
        resp.allowed_resource_permission[0].permission,
        vec!["read".to_string()]
    );
    assert!(resp.denied_resource_permission.is_empty());
}

pub async fn specific_repository_grant_does_not_cover_other_repositories(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Bob").await;
    h.create_resource("urc-mine").await;
    h.create_resource("urc-not-mine").await;
    h.grant_specific(ROLE_WRITER, "urc-mine", "user", user)
        .await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-mine".to_string(), "urc-not-mine".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission")
        .into_inner();

    assert_eq!(resp.allowed_resource_permission.len(), 1);
    assert_eq!(resp.allowed_resource_permission[0].resource_id, "urc-mine");
    assert_eq!(
        sorted(resp.allowed_resource_permission[0].permission.clone()),
        vec!["read".to_string(), "write".to_string()]
    );
    assert_eq!(resp.denied_resource_permission.len(), 1);
    assert_eq!(
        resp.denied_resource_permission[0].resource_id,
        "urc-not-mine"
    );
    assert!(resp.denied_resource_permission[0].permission.is_empty());
}

pub async fn user_with_no_grants_denies_everything(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Nobody").await;
    h.create_resource("urc-somerepo").await;

    let check_req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-somerepo".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(check_req)
        .await
        .expect("check_user_permission")
        .into_inner();
    assert!(resp.allowed_resource_permission.is_empty());
    assert_eq!(resp.denied_resource_permission.len(), 1);

    let lookup_req = h.request_with_bearer(
        epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        },
        user,
    );
    let resp = h
        .auth_service
        .lookup_user_permissions(lookup_req)
        .await
        .expect("lookup_user_permissions")
        .into_inner();
    assert!(
        resp.resource_permission.is_empty(),
        "a user with zero role_bindings must see zero resources, got {:?}",
        resp.resource_permission
    );
}

pub async fn group_inherited_grant(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    let group = Uuid::new_v4();
    h.create_user(user, "GroupMember").await;
    h.create_group(group, "engineering").await;
    h.add_group_member(group, user).await;
    h.create_resource("urc-teamrepo").await;
    // The grant is on the GROUP, never directly on the user.
    h.grant_specific(ROLE_READER, "urc-teamrepo", "group", group)
        .await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-teamrepo".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission")
        .into_inner();
    assert_eq!(resp.allowed_resource_permission.len(), 1);
    assert_eq!(
        resp.allowed_resource_permission[0].resource_id,
        "urc-teamrepo"
    );
    assert_eq!(
        resp.allowed_resource_permission[0].permission,
        vec!["read".to_string()]
    );
}

pub async fn service_account_direct_grant(backend: Backend) {
    let h = Harness::new(backend).await;
    let sa = Uuid::new_v4();
    h.create_service_account(sa, "ci-bot").await;
    h.create_resource("urc-cirepo").await;
    h.grant_specific(ROLE_WRITER, "urc-cirepo", "service_account", sa)
        .await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-cirepo".to_string()],
            target_user: None,
        },
        sa,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission")
        .into_inner();
    assert_eq!(resp.allowed_resource_permission.len(), 1);
    assert_eq!(
        resp.allowed_resource_permission[0].resource_id,
        "urc-cirepo"
    );
}

pub async fn lookup_user_permissions_returns_exact_scoped_set_no_more_no_less(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Carol").await;

    h.create_resource("urc-a").await;
    h.create_resource("urc-b").await;
    h.create_resource("urc-c").await;
    // Exists, but the user's ONLY relation to it is the wildcard grant below
    // -- proves wildcard expansion enumerates real registered resources,
    // not something invented or stale.
    h.create_resource("urc-d").await;

    h.grant_wildcard(ROLE_READER, "user", user).await; // read on everything
    h.grant_specific(ROLE_ADMIN, "urc-b", "user", user).await; // extra grant on b only

    let req = h.request_with_bearer(
        epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        },
        user,
    );
    let resp = h
        .auth_service
        .lookup_user_permissions(req)
        .await
        .expect("lookup_user_permissions")
        .into_inner();

    let got: std::collections::BTreeMap<String, Vec<String>> = resp
        .resource_permission
        .into_iter()
        .map(|rp| (rp.resource_id, sorted(rp.permission)))
        .collect();

    let mut expected: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    expected.insert("urc-a".to_string(), vec!["read".to_string()]);
    expected.insert(
        "urc-b".to_string(),
        vec!["admin".to_string(), "read".to_string(), "write".to_string()],
    );
    expected.insert("urc-c".to_string(), vec!["read".to_string()]);
    expected.insert("urc-d".to_string(), vec!["read".to_string()]);

    assert_eq!(
        got, expected,
        "LookupUserPermissions must return the EXACT scoped set -- lore-server treats this as \
         the only candidate list for RepositoryList, so an over-broad OR under-broad return is \
         a real authorization bug"
    );
}

pub async fn lookup_user_permissions_specific_only_does_not_leak_other_resources(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Dave").await;
    h.create_resource("urc-onlyme").await;
    h.create_resource("urc-notmine").await;
    h.grant_specific(ROLE_READER, "urc-onlyme", "user", user)
        .await;

    let req = h.request_with_bearer(
        epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        },
        user,
    );
    let resp = h
        .auth_service
        .lookup_user_permissions(req)
        .await
        .expect("lookup_user_permissions")
        .into_inner();

    assert_eq!(resp.resource_permission.len(), 1);
    assert_eq!(resp.resource_permission[0].resource_id, "urc-onlyme");
}

pub async fn nonexistent_resource_is_denied_not_errored(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Eve").await;
    h.grant_wildcard(ROLE_ADMIN, "user", user).await; // wildcard admin grant

    // urc-ghost-repo was never created via RebacApi::CreateResource.
    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-ghost-repo".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission")
        .into_inner();

    assert!(
        resp.allowed_resource_permission.is_empty(),
        "a wildcard admin grant must NOT authorize a resource_id that was never created"
    );
    assert_eq!(resp.denied_resource_permission.len(), 1);
    assert_eq!(
        resp.denied_resource_permission[0].resource_id,
        "urc-ghost-repo"
    );
}

pub async fn unknown_principal_id_denies_check(backend: Backend) {
    let h = Harness::new(backend).await;
    let ghost = Uuid::new_v4(); // a validly-signed token, but never inserted into principals
    h.create_resource("urc-somerepo").await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-somerepo".to_string()],
            target_user: None,
        },
        ghost,
    );
    let status = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect_err("an unknown principal must deny, not panic or silently allow");
    assert_eq!(status.code(), Code::Unauthenticated);
}

pub async fn unknown_principal_id_denies_lookup(backend: Backend) {
    let h = Harness::new(backend).await;
    let ghost = Uuid::new_v4();

    let req = h.request_with_bearer(
        epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        },
        ghost,
    );
    let status = h
        .auth_service
        .lookup_user_permissions(req)
        .await
        .expect_err("an unknown principal must deny, not panic or silently allow");
    assert_eq!(status.code(), Code::Unauthenticated);
}

pub async fn missing_bearer_token_is_unauthenticated(backend: Backend) {
    let h = Harness::new(backend).await;
    let req = Request::new(epic_urc::CheckUserPermissionRequest {
        resource_id: vec!["urc-anything".to_string()],
        target_user: None,
    });
    let status = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect_err("no authorization metadata at all must deny");
    assert_eq!(status.code(), Code::Unauthenticated);
}

pub async fn database_failure_denies_rather_than_grants(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Frank").await;
    h.grant_wildcard(ROLE_ADMIN, "user", user).await;
    h.create_resource("urc-repo").await;

    // Simulate a real DB failure: close the underlying connection pool out
    // from under an otherwise fully-authorized request. Token verification
    // itself does not touch the database (see caller.rs), so this isolates
    // the DB-failure path specifically, rather than an auth failure. Real on
    // both backends: `Db::close` closes whichever pool variant is live.
    h.db.close().await;

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-repo".to_string()],
            target_user: None,
        },
        user,
    );
    let status = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect_err("a real DB failure must surface as Err, never as a permissive Ok");
    assert_eq!(status.code(), Code::Internal);

    let req2 = h.request_with_bearer(
        epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        },
        user,
    );
    let status2 = h
        .auth_service
        .lookup_user_permissions(req2)
        .await
        .expect_err("a real DB failure must surface as Err, never as a permissive Ok");
    assert_eq!(status2.code(), Code::Internal);
}

pub async fn check_user_permission_with_explicit_target_user_token(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Henry").await;
    h.create_resource("urc-explicit").await;
    h.grant_specific(ROLE_READER, "urc-explicit", "user", user)
        .await;

    let token = h.token_for(user);
    // No `authorization` metadata at all -- identity comes from
    // `target_user.user_token` instead, per auth_api.proto's `TargetUser`
    // oneof.
    let req = Request::new(epic_urc::CheckUserPermissionRequest {
        resource_id: vec!["urc-explicit".to_string()],
        target_user: Some(epic_urc::TargetUser {
            user: Some(epic_urc::target_user::User::UserToken(token)),
        }),
    });
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check_user_permission via target_user")
        .into_inner();
    assert_eq!(resp.allowed_resource_permission.len(), 1);
    assert_eq!(
        resp.allowed_resource_permission[0].resource_id,
        "urc-explicit"
    );
}

pub async fn create_resource_is_idempotent(backend: Backend) {
    let h = Harness::new(backend).await;
    h.create_resource("urc-idem").await;
    // A second CreateResource for the same resource_id must not panic or
    // corrupt state, matching lore-server's own AlreadyExists-is-success
    // handling (see grpc.rs's create_resource doc comment). This helper
    // already treats AlreadyExists as an expected outcome via `.expect(...)`
    // succeeding on the underlying Status::already_exists path being
    // handled -- assert directly here instead, to check the actual code.
    let status = h
        .rebac_service
        .create_resource(h.rebac_request(rebac::CreateResourceRequest {
            resource_id: "urc-idem".to_string(),
            resource_name: "urc-idem".to_string(),
        }))
        .await
        .expect_err("second create_resource for the same id returns AlreadyExists");
    assert_eq!(status.code(), Code::AlreadyExists);
}

pub async fn delete_resource_revokes_access_and_is_idempotent(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Grace").await;
    h.create_resource("urc-todelete").await;
    h.grant_specific(ROLE_ADMIN, "urc-todelete", "user", user)
        .await;

    // Sanity: access is granted before deletion.
    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-todelete".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check before delete")
        .into_inner();
    assert_eq!(resp.allowed_resource_permission.len(), 1);

    h.rebac_service
        .delete_resource(h.rebac_request(rebac::DeleteResourceRequest {
            resource_id: "urc-todelete".to_string(),
        }))
        .await
        .expect("delete_resource");
    // Idempotent: deleting again must not error.
    h.rebac_service
        .delete_resource(h.rebac_request(rebac::DeleteResourceRequest {
            resource_id: "urc-todelete".to_string(),
        }))
        .await
        .expect("second delete_resource must not error");

    let req = h.request_with_bearer(
        epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-todelete".to_string()],
            target_user: None,
        },
        user,
    );
    let resp = h
        .auth_service
        .check_user_permission(req)
        .await
        .expect("check after delete")
        .into_inner();
    assert!(
        resp.allowed_resource_permission.is_empty(),
        "a deleted resource must no longer be accessible even to a principal with a standing grant"
    );
    assert_eq!(resp.denied_resource_permission.len(), 1);
}

// --- RebacApi caller-identity gate, end to end against a REAL database-
// backed service (see crates/lore-authz-server/src/service_auth.rs and
// docs/open-questions.md Q6). `create_resource_is_idempotent` and
// `delete_resource_revokes_access_and_is_idempotent` above already prove the
// "valid credential ALLOWED" case for real on both backends (they run
// through `h.rebac_request`, which presents the correct shared secret, and
// succeed all the way through to real database rows). These tests prove the
// deny paths are equally real against the same live service, not just at
// the grpc.rs unit level with db: None.

pub async fn rebac_create_resource_denies_unauthenticated_caller_against_real_db(backend: Backend) {
    let h = Harness::new(backend).await;
    let err = h
        .rebac_service
        .create_resource(Request::new(rebac::CreateResourceRequest {
            resource_id: "urc-noauth".to_string(),
            resource_name: "urc-noauth".to_string(),
        }))
        .await
        .expect_err("no authorization metadata at all must be denied");
    assert_eq!(err.code(), Code::Unauthenticated);
}

pub async fn rebac_delete_resource_denies_unauthenticated_caller_against_real_db(backend: Backend) {
    let h = Harness::new(backend).await;
    h.create_resource("urc-stillthere").await;

    let err = h
        .rebac_service
        .delete_resource(Request::new(rebac::DeleteResourceRequest {
            resource_id: "urc-stillthere".to_string(),
        }))
        .await
        .expect_err("no authorization metadata at all must be denied");
    assert_eq!(err.code(), Code::Unauthenticated);

    // And the resource must genuinely still exist -- the denied delete must
    // not have taken effect.
    let user = Uuid::new_v4();
    h.create_user(user, "Ivan").await;
    h.grant_wildcard(ROLE_READER, "user", user).await;
    let resp = h
        .auth_service
        .check_user_permission(h.request_with_bearer(
            epic_urc::CheckUserPermissionRequest {
                resource_id: vec!["urc-stillthere".to_string()],
                target_user: None,
            },
            user,
        ))
        .await
        .expect("check_user_permission")
        .into_inner();
    assert_eq!(resp.allowed_resource_permission.len(), 1);
}

pub async fn rebac_create_resource_denies_wrong_service_token_against_real_db(backend: Backend) {
    let h = Harness::new(backend).await;
    let mut req = Request::new(rebac::CreateResourceRequest {
        resource_id: "urc-wrongtoken".to_string(),
        resource_name: "urc-wrongtoken".to_string(),
    });
    req.metadata_mut()
        .insert("authorization", "Bearer definitely-wrong".parse().unwrap());

    let err = h
        .rebac_service
        .create_resource(req)
        .await
        .expect_err("a wrong shared secret must be denied");
    assert_eq!(err.code(), Code::Unauthenticated);
}

pub async fn rebac_create_resource_rejects_wildcard_sentinel_against_real_db(backend: Backend) {
    let h = Harness::new(backend).await;
    let err = h
        .rebac_service
        .create_resource(h.rebac_request(rebac::CreateResourceRequest {
            resource_id: lore_authz_server::db::permissions::WILDCARD_RESOURCE_PATTERN.to_string(),
            resource_name: "should-never-be-created".to_string(),
        }))
        .await
        .expect_err("the literal wildcard sentinel must never be creatable as a real resource");
    assert_eq!(err.code(), Code::InvalidArgument);
}

// --- PHASE 1b: login sessions (StartAuthSession / GetAuthSession) --------

/// The happy path for the half of the login flow that does not involve an
/// identity provider: a session is started, the browser leg completes, and
/// the very next poll returns a REAL, signature-verifiable AuthN token whose
/// claims are the ones lore's own client-side decoder requires.
pub async fn poll_returns_an_authn_token_once_the_browser_leg_completes(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Session User").await;

    let client_state = "client-state-happy-path";
    let started = h.start_login(client_state).await;

    // Before the browser leg: keep polling, with no token.
    assert!(
        h.poll(&started.session_code, client_state).await.is_none(),
        "a pending session must never hand out a token"
    );
    // The login URL is built from PUBLIC_BASE_URL and carries a code that is
    // NOT the polling secret -- a leaked login URL must not let its holder
    // poll for the resulting token.
    assert!(started.login_url.starts_with(PUBLIC_BASE_URL));
    assert!(
        !started.login_url.contains(&started.session_code),
        "the session_code must never appear in the browser login URL"
    );

    assert!(h.complete_login(&started.oidc_state, user).await);

    let token = h
        .poll(&started.session_code, client_state)
        .await
        .expect("an authenticated session must issue a token on the next poll");

    assert_eq!(token.user_id, user.to_string());
    assert_eq!(token.user_name, "Session User");
    // MILLISECONDS on the wire, not seconds -- docs/open-questions.md Q1.
    // A seconds value would be ~1.7e9; a milliseconds value ~1.7e12.
    assert!(
        token.expires_at > 1_000_000_000_000,
        "UserToken.expires_at must be epoch milliseconds, not seconds"
    );

    let claims = decode_authn_claims(&h, &token.user_token).claims;
    assert_eq!(claims.user_id, user.to_string());
    assert_eq!(claims.env, TOKEN_ENV, "`env` is mandatory on both shapes");
    assert_eq!(claims.name, "Session User");
    // The JWT `exp` claim is SECONDS and is a different value from
    // UserToken.expires_at above; assert the relationship rather than
    // trusting they happen to agree.
    assert_eq!(token.expires_at, claims.expires_at as i64 * 1000);
    // An AuthN token carries no `resources` at all -- proven structurally by
    // AuthnClaims having no such field, and on the wire by lore_compat.rs.
}

/// A session_code is SINGLE USE. The CLI polls every 5 seconds, so a replay
/// window here would mean a captured code keeps minting fresh tokens for as
/// long as the session lives.
pub async fn poll_is_single_use_and_never_reissues(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Replay User").await;

    let client_state = "client-state-single-use";
    let started = h.start_login(client_state).await;
    assert!(h.complete_login(&started.oidc_state, user).await);

    assert!(
        h.poll(&started.session_code, client_state).await.is_some(),
        "the first poll after authentication must issue a token"
    );
    assert!(
        h.poll(&started.session_code, client_state).await.is_none(),
        "a REUSED session_code must never issue a second token"
    );
    assert!(
        h.poll(&started.session_code, client_state).await.is_none(),
        "and must keep refusing, not merely refuse once"
    );
}

/// An unknown session_code must be indistinguishable from a pending one: no
/// error, no distinct status, no token. Otherwise this unauthenticated
/// endpoint becomes an oracle for enumerating live sessions.
pub async fn poll_with_an_unknown_session_code_is_indistinguishable_from_pending(backend: Backend) {
    let h = Harness::new(backend).await;
    let client_state = "client-state-unknown";

    // A real, pending session, for the response we are comparing against.
    let started = h.start_login(client_state).await;
    let pending = h.poll(&started.session_code, client_state).await;

    let unknown = h
        .poll("this-session-code-was-never-issued", client_state)
        .await;
    let empty = h.poll("", client_state).await;

    assert!(pending.is_none());
    assert!(
        unknown.is_none(),
        "an unknown code must not error or reveal itself"
    );
    assert!(empty.is_none(), "an empty code must be treated as unknown");
}

/// The session_code alone must not be enough: the poll must also present the
/// client_state the CLI generated at StartAuthSession. This is what stops a
/// session_code observed in isolation from being redeemable.
pub async fn poll_with_a_mismatched_client_state_never_issues_a_token(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "State User").await;

    let started = h.start_login("the-real-client-state").await;
    assert!(h.complete_login(&started.oidc_state, user).await);

    assert!(
        h.poll(&started.session_code, "a-different-client-state")
            .await
            .is_none(),
        "a wrong client_state must never redeem a session"
    );
    assert!(
        h.poll(&started.session_code, "").await.is_none(),
        "an empty client_state must never redeem a session"
    );
    // ... and the session is still intact for its rightful owner, i.e. the
    // failed attempts did not consume it.
    assert!(
        h.poll(&started.session_code, "the-real-client-state")
            .await
            .is_some()
    );
}

/// Expiry is enforced at BOTH transitions, not just one: an expired session
/// cannot be authenticated, and an authenticated session that then expires
/// cannot be redeemed.
pub async fn expired_sessions_are_denied_at_both_transitions(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Expiry User").await;

    // Already expired the moment it exists (ttl 0).
    let dead = h.start_login_with_ttl("client-state-dead", 0).await;
    assert!(
        !h.complete_login(&dead.oidc_state, user).await,
        "an expired session must not be authenticatable by the IdP callback"
    );
    assert!(
        h.poll(&dead.session_code, "client-state-dead")
            .await
            .is_none()
    );

    // Authenticated first, expires afterwards -- the case a slow user hits.
    let live = h.start_login_with_ttl("client-state-live", 1).await;
    assert!(h.complete_login(&live.oidc_state, user).await);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert!(
        h.poll(&live.session_code, "client-state-live")
            .await
            .is_none(),
        "an authenticated session that has since expired must not issue a token"
    );
}

/// A session whose principal is deprovisioned (or never existed) between the
/// browser callback and the poll must not produce a token -- the identity is
/// re-checked at mint time, not trusted from the session row.
pub async fn poll_denies_when_the_session_principal_is_not_active(backend: Backend) {
    let h = Harness::new(backend).await;
    // A principal id that resolves to no `principals` row at all.
    let ghost = Uuid::new_v4();

    let client_state = "client-state-ghost";
    let started = h.start_login(client_state).await;
    assert!(h.complete_login(&started.oidc_state, ghost).await);

    assert!(
        h.poll(&started.session_code, client_state).await.is_none(),
        "a session bound to a non-active principal must never issue a token"
    );
}

/// `StartAuthSession` cannot issue a login URL it has no origin for, and
/// must say so rather than emit a broken one.
pub async fn starting_a_session_without_a_public_base_url_fails_closed(backend: Backend) {
    let h = Harness::new(backend).await;
    let settings = LoginSettings {
        public_base_url: String::new(),
        ..login_settings()
    };
    let err = login::start_session(
        &h.db,
        &settings,
        "client-state",
        random_url_safe_token().unwrap(),
        random_url_safe_token().unwrap(),
        random_url_safe_token().unwrap(),
    )
    .await
    .expect_err("no public base URL must deny, not emit a broken login URL");
    assert_eq!(err.code(), Code::FailedPrecondition);

    // An empty client_state is refused for the same reason: it is half of
    // what a poll must present, so accepting it would make the resulting
    // session redeemable by anyone holding only the session_code.
    let err = login::start_session(
        &h.db,
        &login_settings(),
        "   ",
        random_url_safe_token().unwrap(),
        random_url_safe_token().unwrap(),
        random_url_safe_token().unwrap(),
    )
    .await
    .expect_err("an empty client_state must be refused");
    assert_eq!(err.code(), Code::InvalidArgument);
}

/// An unconfigured identity provider must DENY every login attempt through
/// the real RPC, never issue a session_code for a login that could not
/// possibly complete.
pub async fn start_auth_session_without_a_provider_denies_against_real_db(backend: Backend) {
    let h = Harness::new(backend).await; // built with oidc: None
    let err = h
        .auth_service
        .start_auth_session(Request::new(epic_urc::StartAuthSessionRequest {
            client_state: "a-client-state".to_string(),
        }))
        .await
        .expect_err("an unconfigured identity provider must deny");
    assert_eq!(err.code(), Code::FailedPrecondition);
}

/// The opportunistic reaper actually removes expired rows, so the session
/// table does not grow without bound in a long-lived deployment.
pub async fn starting_a_session_reaps_expired_ones(backend: Backend) {
    let h = Harness::new(backend).await;
    let expired = h.start_login_with_ttl("client-state-reap", 0).await;

    // Present before the reaper runs...
    assert!(
        sessions::find_by_session_code_hash(
            &h.db,
            &lore_authz_server::secret::sha256_b64url(&expired.session_code),
        )
        .await
        .expect("lookup")
        .is_some()
    );

    // ... and gone after the next StartAuthSession, which reaps first.
    let _ = h.start_login("client-state-reap-2").await;
    assert!(
        sessions::find_by_session_code_hash(
            &h.db,
            &lore_authz_server::secret::sha256_b64url(&expired.session_code),
        )
        .await
        .expect("lookup")
        .is_none(),
        "an expired session must be reaped by the next StartAuthSession"
    );
}

// --- PHASE 1b: ExchangeUserTokenForMultiresourceToken --------------------

/// The single highest-value assertion in this file: exchanging an AuthN
/// token yields an AuthZ token that carries `resources`, `idp` AND `env`.
/// Missing `env` fails loudly at lore-server; missing `idp` fails SILENTLY,
/// dropping `resources` and surfacing as a permissions bug (see
/// docs/protocol-notes.md section 2).
pub async fn exchange_mints_an_authz_token_with_resources_idp_and_env(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_oidc_user(user, "Exchange User", "idp-subject-1", "example-idp")
        .await;
    h.create_resource("urc-exchange1").await;
    h.grant_specific(ROLE_WRITER, "urc-exchange1", "user", user)
        .await;

    let resp = h
        .auth_service
        .exchange_user_token_for_multiresource_token(h.request_with_authn_bearer(
            epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec!["urc-exchange1".to_string()],
            },
            user,
            "Exchange User",
        ))
        .await
        .expect("exchange")
        .into_inner();

    let token = resp
        .token
        .expect("the exchange response must carry a token");
    assert_eq!(token.user_id, user.to_string());
    assert!(token.expires_at > 1_000_000_000_000, "milliseconds");

    let claims = decode_authz_claims(&h, &token.user_token).claims;
    assert_eq!(
        claims.idp, "example-idp",
        "`idp` must come from the principal row -- the AuthN token has no such claim"
    );
    assert_eq!(claims.env, TOKEN_ENV);
    let resources = claims.resources.expect("`resources` must be present");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].resource_id, "urc-exchange1");
    assert_eq!(
        sorted(resources[0].permission.clone()),
        vec!["read".to_string(), "write".to_string()]
    );
}

/// A principal with no recorded identity provider still gets a NON-EMPTY
/// `idp`, from the configured fallback. An empty `idp` is as silently broken
/// as an absent one.
pub async fn exchange_falls_back_to_the_configured_idp_when_the_principal_has_none(
    backend: Backend,
) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Local User").await; // no idp recorded
    h.create_resource("urc-exchange2").await;
    h.grant_wildcard(ROLE_READER, "user", user).await;

    let resp = h
        .auth_service
        .exchange_user_token_for_multiresource_token(h.request_with_authn_bearer(
            epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec!["urc-exchange2".to_string()],
            },
            user,
            "Local User",
        ))
        .await
        .expect("exchange")
        .into_inner();

    let claims = decode_authz_claims(&h, &resp.token.unwrap().user_token).claims;
    assert_eq!(claims.idp, DEFAULT_IDP);
    assert!(!claims.idp.is_empty());
    // A wildcard grant must be EXPANDED to concrete ids, never emitted as
    // the literal sentinel -- see db/permissions.rs's module doc comment.
    let resources = claims.resources.expect("resources");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].resource_id, "urc-exchange2");
}

/// The exchange must not smuggle in access the caller does not have: an
/// ungranted resource, a never-registered one, and a deleted one are all
/// simply absent from `resources`.
pub async fn exchange_omits_resources_the_caller_has_no_grant_for(backend: Backend) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Scoped User").await;
    h.create_resource("urc-granted").await;
    h.create_resource("urc-notgranted").await;
    h.grant_specific(ROLE_READER, "urc-granted", "user", user)
        .await;

    let resp = h
        .auth_service
        .exchange_user_token_for_multiresource_token(h.request_with_authn_bearer(
            epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec![
                    "urc-granted".to_string(),
                    "urc-notgranted".to_string(),
                    "urc-neverexisted".to_string(),
                ],
            },
            user,
            "Scoped User",
        ))
        .await
        .expect("exchange")
        .into_inner();

    let claims = decode_authz_claims(&h, &resp.token.unwrap().user_token).claims;
    let ids: Vec<String> = claims
        .resources
        .expect("resources")
        .into_iter()
        .map(|r| r.resource_id)
        .collect();
    assert_eq!(ids, vec!["urc-granted".to_string()]);
}

/// A caller entitled to nothing gets a well-formed token that authorizes
/// nothing -- not an error, and never a token with someone else's access.
pub async fn exchange_for_a_caller_with_no_grants_yields_an_empty_resources_claim(
    backend: Backend,
) {
    let h = Harness::new(backend).await;
    let user = Uuid::new_v4();
    h.create_user(user, "Ungranted User").await;
    h.create_resource("urc-somebodyelses").await;

    let resp = h
        .auth_service
        .exchange_user_token_for_multiresource_token(h.request_with_authn_bearer(
            epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
                resource_id: vec!["urc-somebodyelses".to_string()],
            },
            user,
            "Ungranted User",
        ))
        .await
        .expect("exchange")
        .into_inner();

    let claims = decode_authz_claims(&h, &resp.token.unwrap().user_token).claims;
    assert_eq!(claims.resources.expect("resources").len(), 0);
}

/// Every unauthenticated route into the exchange must deny, and must deny
/// BEFORE anything is minted: no bearer token, a garbage bearer token, and a
/// correctly-signed token for a principal that does not exist.
pub async fn exchange_denies_every_unauthenticated_caller(backend: Backend) {
    let h = Harness::new(backend).await;

    let body = || epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
        resource_id: vec!["urc-anything".to_string()],
    };

    let err = h
        .auth_service
        .exchange_user_token_for_multiresource_token(Request::new(body()))
        .await
        .expect_err("no bearer token must deny");
    assert_eq!(err.code(), Code::Unauthenticated);

    let mut garbage = Request::new(body());
    garbage
        .metadata_mut()
        .insert("authorization", "Bearer not-a-jwt".parse().unwrap());
    let err = h
        .auth_service
        .exchange_user_token_for_multiresource_token(garbage)
        .await
        .expect_err("an unparseable bearer token must deny");
    assert_eq!(err.code(), Code::Unauthenticated);

    // Correctly signed by us, unexpired, right issuer and audience -- but
    // its `sub` resolves to no principal.
    let ghost = Uuid::new_v4();
    let err = h
        .auth_service
        .exchange_user_token_for_multiresource_token(h.request_with_authn_bearer(
            body(),
            ghost,
            "Ghost",
        ))
        .await
        .expect_err("a valid token for an unknown principal must deny");
    assert_eq!(err.code(), Code::Unauthenticated);
}

pub async fn migrations_are_idempotent(backend: Backend) {
    // `Db::connect` already ran migrations once (in `fresh_db`); running
    // them again against the SAME database must be a no-op, not an error --
    // this is the actual mechanism (`sqlx::migrate!`'s own history table),
    // not just a claim in a doc comment.
    let db = fresh_db(backend).await;
    db.migrate()
        .await
        .expect("re-running migrations against an already-migrated database");
}
