//! Postgres wrapper around the shared `authz_suite` (see
//! `tests/authz_suite/mod.rs` for the full module doc comment, the "what
//! each case proves" list, and how to run these -- `TEST_DATABASE_URL` must
//! point at a real, reachable Postgres instance; see
//! `docker-compose.test.yml`).
//!
//! Every test here is a one-line call into `authz_suite`'s shared body with
//! `Backend::Postgres` -- see `tests/sqlite_backed.rs` for the identical set
//! called with `Backend::Sqlite`. Kept as thin wrappers deliberately: the
//! two files must never drift into testing different things, so there is
//! exactly one place (`authz_suite`) where a test body's logic lives.

#[path = "authz_suite/mod.rs"]
mod authz_suite;

use authz_suite::Backend;

#[tokio::test]
async fn wildcard_grant_allows_any_registered_resource() {
    authz_suite::wildcard_grant_allows_any_registered_resource(Backend::Postgres).await
}

#[tokio::test]
async fn specific_repository_grant_does_not_cover_other_repositories() {
    authz_suite::specific_repository_grant_does_not_cover_other_repositories(Backend::Postgres)
        .await
}

#[tokio::test]
async fn user_with_no_grants_denies_everything() {
    authz_suite::user_with_no_grants_denies_everything(Backend::Postgres).await
}

#[tokio::test]
async fn group_inherited_grant() {
    authz_suite::group_inherited_grant(Backend::Postgres).await
}

#[tokio::test]
async fn service_account_direct_grant() {
    authz_suite::service_account_direct_grant(Backend::Postgres).await
}

#[tokio::test]
async fn lookup_user_permissions_returns_exact_scoped_set_no_more_no_less() {
    authz_suite::lookup_user_permissions_returns_exact_scoped_set_no_more_no_less(Backend::Postgres)
        .await
}

#[tokio::test]
async fn lookup_user_permissions_specific_only_does_not_leak_other_resources() {
    authz_suite::lookup_user_permissions_specific_only_does_not_leak_other_resources(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn nonexistent_resource_is_denied_not_errored() {
    authz_suite::nonexistent_resource_is_denied_not_errored(Backend::Postgres).await
}

#[tokio::test]
async fn unknown_principal_id_denies_check() {
    authz_suite::unknown_principal_id_denies_check(Backend::Postgres).await
}

#[tokio::test]
async fn unknown_principal_id_denies_lookup() {
    authz_suite::unknown_principal_id_denies_lookup(Backend::Postgres).await
}

#[tokio::test]
async fn missing_bearer_token_is_unauthenticated() {
    authz_suite::missing_bearer_token_is_unauthenticated(Backend::Postgres).await
}

#[tokio::test]
async fn database_failure_denies_rather_than_grants() {
    authz_suite::database_failure_denies_rather_than_grants(Backend::Postgres).await
}

#[tokio::test]
async fn check_user_permission_with_explicit_target_user_token() {
    authz_suite::check_user_permission_with_explicit_target_user_token(Backend::Postgres).await
}

#[tokio::test]
async fn create_resource_is_idempotent() {
    authz_suite::create_resource_is_idempotent(Backend::Postgres).await
}

#[tokio::test]
async fn delete_resource_revokes_access_and_is_idempotent() {
    authz_suite::delete_resource_revokes_access_and_is_idempotent(Backend::Postgres).await
}

#[tokio::test]
async fn rebac_create_resource_denies_unauthenticated_caller_against_real_db() {
    authz_suite::rebac_create_resource_denies_unauthenticated_caller_against_real_db(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn rebac_delete_resource_denies_unauthenticated_caller_against_real_db() {
    authz_suite::rebac_delete_resource_denies_unauthenticated_caller_against_real_db(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn rebac_create_resource_denies_wrong_service_token_against_real_db() {
    authz_suite::rebac_create_resource_denies_wrong_service_token_against_real_db(Backend::Postgres)
        .await
}

#[tokio::test]
async fn rebac_create_resource_rejects_wildcard_sentinel_against_real_db() {
    authz_suite::rebac_create_resource_rejects_wildcard_sentinel_against_real_db(Backend::Postgres)
        .await
}

#[tokio::test]
async fn migrations_are_idempotent() {
    authz_suite::migrations_are_idempotent(Backend::Postgres).await
}

// --- PHASE 1b: login sessions and the AuthZ token exchange ---------------
// Same one-line-wrapper rule as above: every body lives exactly once, in
// `authz_suite`, and BOTH backends call all of them.

#[tokio::test]
async fn poll_returns_an_authn_token_once_the_browser_leg_completes() {
    authz_suite::poll_returns_an_authn_token_once_the_browser_leg_completes(Backend::Postgres).await
}

#[tokio::test]
async fn poll_is_single_use_and_never_reissues() {
    authz_suite::poll_is_single_use_and_never_reissues(Backend::Postgres).await
}

#[tokio::test]
async fn poll_with_an_unknown_session_code_is_indistinguishable_from_pending() {
    authz_suite::poll_with_an_unknown_session_code_is_indistinguishable_from_pending(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn poll_with_a_mismatched_client_state_never_issues_a_token() {
    authz_suite::poll_with_a_mismatched_client_state_never_issues_a_token(Backend::Postgres).await
}

#[tokio::test]
async fn expired_sessions_are_denied_at_both_transitions() {
    authz_suite::expired_sessions_are_denied_at_both_transitions(Backend::Postgres).await
}

#[tokio::test]
async fn poll_denies_when_the_session_principal_is_not_active() {
    authz_suite::poll_denies_when_the_session_principal_is_not_active(Backend::Postgres).await
}

#[tokio::test]
async fn starting_a_session_without_a_public_base_url_fails_closed() {
    authz_suite::starting_a_session_without_a_public_base_url_fails_closed(Backend::Postgres).await
}

#[tokio::test]
async fn starting_a_session_reaps_expired_ones() {
    authz_suite::starting_a_session_reaps_expired_ones(Backend::Postgres).await
}

#[tokio::test]
async fn exchange_mints_an_authz_token_with_resources_idp_and_env() {
    authz_suite::exchange_mints_an_authz_token_with_resources_idp_and_env(Backend::Postgres).await
}

#[tokio::test]
async fn exchange_falls_back_to_the_configured_idp_when_the_principal_has_none() {
    authz_suite::exchange_falls_back_to_the_configured_idp_when_the_principal_has_none(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn exchange_omits_resources_the_caller_has_no_grant_for() {
    authz_suite::exchange_omits_resources_the_caller_has_no_grant_for(Backend::Postgres).await
}

#[tokio::test]
async fn exchange_for_a_caller_with_no_grants_yields_an_empty_resources_claim() {
    authz_suite::exchange_for_a_caller_with_no_grants_yields_an_empty_resources_claim(
        Backend::Postgres,
    )
    .await
}

#[tokio::test]
async fn exchange_denies_every_unauthenticated_caller() {
    authz_suite::exchange_denies_every_unauthenticated_caller(Backend::Postgres).await
}

#[tokio::test]
async fn exchange_denies_an_authz_shaped_token_presented_for_renewal() {
    authz_suite::exchange_denies_an_authz_shaped_token_presented_for_renewal(Backend::Postgres)
        .await
}

#[tokio::test]
async fn start_auth_session_without_a_provider_denies_against_real_db() {
    authz_suite::start_auth_session_without_a_provider_denies_against_real_db(Backend::Postgres)
        .await
}
