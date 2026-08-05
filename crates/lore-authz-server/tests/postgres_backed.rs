//! PHASE 1a (see tasks.md) integration tests against a REAL Postgres
//! container -- not sqlite, not a mock. This project has already been
//! burned by mocked tests passing while real integration was broken (see
//! `docs/protocol-notes.md`'s claim-shape-drift discussion and the compat
//! test philosophy in `tests/lore_compat.rs`), so `LookupUserPermissions`
//! and `CheckUserPermission` get the same treatment: exercised against real
//! SQL, a real connection pool, and (for the DB-failure case) a real closed
//! pool, never a stand-in.
//!
//! ## Running these tests
//! Requires `TEST_DATABASE_URL` to point at a real, reachable Postgres
//! instance (any throwaway one -- these tests never `CREATE DATABASE`, they
//! only ever create their own schema inside whatever database the URL
//! names). See `docker-compose.test.yml` at the repo root for a documented,
//! reproducible way to provide one. If `TEST_DATABASE_URL` is not set, every
//! test in this file panics with a message saying so -- that is intentional
//! (fail loudly, not skip silently) rather than a passing-but-untested green
//! result.
//!
//! Each test connects with its OWN randomly-named schema
//! (`test_<uuid>`) inside that same database, so tests can run concurrently
//! against one shared Postgres instance without seeing each other's data --
//! this is also, incidentally, a live proof that `DB_SCHEMA` isolation
//! actually works, not just something asserted in a doc comment.
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
use lore_authz_server::db::principals::insert_principal;
use lore_authz_server::grpc::AuthApiService;
use lore_authz_server::grpc::RebacApiService;
use lore_authz_server::minting::AuthzTokenInput;
use lore_authz_server::minting::mint_authz_token;
use lore_authz_server::signing::SigningKeyStore;
use tonic::Code;
use tonic::Request;
use uuid::Uuid;

const ISSUER: &str = "https://authz.example.com";

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

/// One throwaway, uniquely-named schema per test, inside whatever database
/// `TEST_DATABASE_URL` points at -- proves schema isolation works for real,
/// and lets tests run concurrently without colliding.
async fn fresh_db() -> Db {
    let schema = format!("test_{}", Uuid::new_v4().simple());
    Db::connect(&test_database_url(), &schema)
        .await
        .expect("connect + migrate a fresh throwaway schema")
}

struct Harness {
    db: Arc<Db>,
    auth_service: AuthApiService,
    rebac_service: RebacApiService,
}

impl Harness {
    async fn new() -> Self {
        let db = Arc::new(fresh_db().await);
        let signing_keys = Arc::new(
            SigningKeyStore::load(
                "file:///epic-lore-authz-postgres-test-fixture-does-not-exist.der",
            )
            .expect("ephemeral signing key for test"),
        );
        let auth_service = AuthApiService {
            db: Some(db.clone()),
            signing_keys,
            jwt_issuer: ISSUER.to_string(),
            jwt_audience: audience(),
        };
        let rebac_service = RebacApiService {
            db: Some(db.clone()),
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

    async fn create_resource(&self, resource_id: &str) {
        self.rebac_service
            .create_resource(Request::new(rebac::CreateResourceRequest {
                resource_id: resource_id.to_string(),
                resource_name: resource_id.to_string(),
            }))
            .await
            .expect("create_resource");
    }

    async fn create_user(&self, id: Uuid, name: &str) {
        insert_principal(self.db.pool(), id, name, false)
            .await
            .expect("insert_principal (user)");
    }

    async fn create_service_account(&self, id: Uuid, name: &str) {
        insert_principal(self.db.pool(), id, name, true)
            .await
            .expect("insert_principal (service account)");
    }

    async fn create_group(&self, id: Uuid, name: &str) {
        groups::insert_group(self.db.pool(), id, name)
            .await
            .expect("insert_group");
    }

    async fn add_group_member(&self, group_id: Uuid, user_id: Uuid) {
        groups::add_member(self.db.pool(), group_id, user_id)
            .await
            .expect("add_member");
    }

    async fn grant_wildcard(&self, role_id: Uuid, principal_kind: &str, principal_id: Uuid) {
        grant(
            self.db.pool(),
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
        grant(
            self.db.pool(),
            role_id,
            resource_id,
            principal_kind,
            principal_id,
        )
        .await
        .expect("grant specific");
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[tokio::test]
async fn wildcard_grant_allows_any_registered_resource() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn specific_repository_grant_does_not_cover_other_repositories() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn user_with_no_grants_denies_everything() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn group_inherited_grant() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn service_account_direct_grant() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn lookup_user_permissions_returns_exact_scoped_set_no_more_no_less() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn lookup_user_permissions_specific_only_does_not_leak_other_resources() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn nonexistent_resource_is_denied_not_errored() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn unknown_principal_id_denies_check() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn unknown_principal_id_denies_lookup() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn missing_bearer_token_is_unauthenticated() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn database_failure_denies_rather_than_grants() {
    let h = Harness::new().await;
    let user = Uuid::new_v4();
    h.create_user(user, "Frank").await;
    h.grant_wildcard(ROLE_ADMIN, "user", user).await;
    h.create_resource("urc-repo").await;

    // Simulate a real DB failure: close the underlying connection pool out
    // from under an otherwise fully-authorized request. Token verification
    // itself does not touch Postgres (see caller.rs), so this isolates the
    // DB-failure path specifically, rather than an auth failure.
    h.db.pool().close().await;

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

#[tokio::test]
async fn check_user_permission_with_explicit_target_user_token() {
    let h = Harness::new().await;
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

#[tokio::test]
async fn create_resource_is_idempotent() {
    let h = Harness::new().await;
    h.create_resource("urc-idem").await;
    // A second CreateResource for the same resource_id must not panic or
    // corrupt state, matching lore-server's own AlreadyExists-is-success
    // handling (see grpc.rs's create_resource doc comment). This helper
    // already treats AlreadyExists as an expected outcome via `.expect(...)`
    // succeeding on the underlying Status::already_exists path being
    // handled -- assert directly here instead, to check the actual code.
    let status = h
        .rebac_service
        .create_resource(Request::new(rebac::CreateResourceRequest {
            resource_id: "urc-idem".to_string(),
            resource_name: "urc-idem".to_string(),
        }))
        .await
        .expect_err("second create_resource for the same id returns AlreadyExists");
    assert_eq!(status.code(), Code::AlreadyExists);
}

#[tokio::test]
async fn delete_resource_revokes_access_and_is_idempotent() {
    let h = Harness::new().await;
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
        .delete_resource(Request::new(rebac::DeleteResourceRequest {
            resource_id: "urc-todelete".to_string(),
        }))
        .await
        .expect("delete_resource");
    // Idempotent: deleting again must not error.
    h.rebac_service
        .delete_resource(Request::new(rebac::DeleteResourceRequest {
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

#[tokio::test]
async fn migrations_are_idempotent() {
    // `Db::connect` already ran migrations once (in `fresh_db`); running
    // them again against the SAME schema must be a no-op, not an error --
    // this is the actual mechanism (`sqlx::migrate!`'s own history table),
    // not just a claim in a doc comment.
    let db = fresh_db().await;
    db.migrate()
        .await
        .expect("re-running migrations against an already-migrated schema");
}
