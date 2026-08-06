//! SQLite wrapper around the shared `authz_suite` (see
//! `tests/authz_suite/mod.rs` for the full module doc comment, the "what
//! each case proves" list, and how to run these). Needs nothing external --
//! each test gets its own throwaway SQLite file under the OS temp
//! directory, migrated fresh via `migrations_sqlite/`.
//!
//! Every test here is a one-line call into `authz_suite`'s shared body with
//! `Backend::Sqlite` -- see `tests/postgres_backed.rs` for the IDENTICAL set
//! called with `Backend::Postgres`. This is the parity requirement from
//! tasks.md made structural: the SQLite backend runs every one of the same
//! test bodies as Postgres, not a subset and not a separately-written
//! parallel suite -- there is exactly one copy of each test body
//! (`authz_suite`) for both files to call.

#[path = "authz_suite/mod.rs"]
mod authz_suite;

use authz_suite::Backend;

#[tokio::test]
async fn wildcard_grant_allows_any_registered_resource() {
    authz_suite::wildcard_grant_allows_any_registered_resource(Backend::Sqlite).await
}

#[tokio::test]
async fn specific_repository_grant_does_not_cover_other_repositories() {
    authz_suite::specific_repository_grant_does_not_cover_other_repositories(Backend::Sqlite).await
}

#[tokio::test]
async fn user_with_no_grants_denies_everything() {
    authz_suite::user_with_no_grants_denies_everything(Backend::Sqlite).await
}

#[tokio::test]
async fn group_inherited_grant() {
    authz_suite::group_inherited_grant(Backend::Sqlite).await
}

#[tokio::test]
async fn service_account_direct_grant() {
    authz_suite::service_account_direct_grant(Backend::Sqlite).await
}

#[tokio::test]
async fn lookup_user_permissions_returns_exact_scoped_set_no_more_no_less() {
    authz_suite::lookup_user_permissions_returns_exact_scoped_set_no_more_no_less(Backend::Sqlite)
        .await
}

#[tokio::test]
async fn lookup_user_permissions_specific_only_does_not_leak_other_resources() {
    authz_suite::lookup_user_permissions_specific_only_does_not_leak_other_resources(
        Backend::Sqlite,
    )
    .await
}

#[tokio::test]
async fn nonexistent_resource_is_denied_not_errored() {
    authz_suite::nonexistent_resource_is_denied_not_errored(Backend::Sqlite).await
}

#[tokio::test]
async fn unknown_principal_id_denies_check() {
    authz_suite::unknown_principal_id_denies_check(Backend::Sqlite).await
}

#[tokio::test]
async fn unknown_principal_id_denies_lookup() {
    authz_suite::unknown_principal_id_denies_lookup(Backend::Sqlite).await
}

#[tokio::test]
async fn missing_bearer_token_is_unauthenticated() {
    authz_suite::missing_bearer_token_is_unauthenticated(Backend::Sqlite).await
}

#[tokio::test]
async fn database_failure_denies_rather_than_grants() {
    authz_suite::database_failure_denies_rather_than_grants(Backend::Sqlite).await
}

#[tokio::test]
async fn check_user_permission_with_explicit_target_user_token() {
    authz_suite::check_user_permission_with_explicit_target_user_token(Backend::Sqlite).await
}

#[tokio::test]
async fn create_resource_is_idempotent() {
    authz_suite::create_resource_is_idempotent(Backend::Sqlite).await
}

#[tokio::test]
async fn delete_resource_revokes_access_and_is_idempotent() {
    authz_suite::delete_resource_revokes_access_and_is_idempotent(Backend::Sqlite).await
}

#[tokio::test]
async fn rebac_create_resource_denies_unauthenticated_caller_against_real_db() {
    authz_suite::rebac_create_resource_denies_unauthenticated_caller_against_real_db(
        Backend::Sqlite,
    )
    .await
}

#[tokio::test]
async fn rebac_delete_resource_denies_unauthenticated_caller_against_real_db() {
    authz_suite::rebac_delete_resource_denies_unauthenticated_caller_against_real_db(
        Backend::Sqlite,
    )
    .await
}

#[tokio::test]
async fn rebac_create_resource_denies_wrong_service_token_against_real_db() {
    authz_suite::rebac_create_resource_denies_wrong_service_token_against_real_db(Backend::Sqlite)
        .await
}

#[tokio::test]
async fn rebac_create_resource_rejects_wildcard_sentinel_against_real_db() {
    authz_suite::rebac_create_resource_rejects_wildcard_sentinel_against_real_db(Backend::Sqlite)
        .await
}

#[tokio::test]
async fn migrations_are_idempotent() {
    authz_suite::migrations_are_idempotent(Backend::Sqlite).await
}
