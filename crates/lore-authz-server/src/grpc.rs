//! Server implementations of `UrcAuthApi` (auth_api.proto) and `RebacApi`
//! (rebac_api.proto). Every method is stubbed with `Status::unimplemented`
//! and a comment naming the RPC's priority and delivery phase, per design
//! plan section B and section E. None of these bodies are real business
//! logic yet -- wiring them up is the content of tasks.md Phase 0 / Phase 1.

use lore_authz_proto::epic_urc;
use lore_authz_proto::ucs::auth as rebac;
use tonic::Request;
use tonic::Response;
use tonic::Status;

pub struct AuthApiService;

#[tonic::async_trait]
impl epic_urc::urc_auth_api_server::UrcAuthApi for AuthApiService {
    // P0. Trivial liveness probe for the gRPC listener; safe to implement
    // for real rather than stub, since it carries no domain logic.
    async fn health_check(
        &self,
        _request: Request<epic_urc::HealthCheckRequest>,
    ) -> Result<Response<epic_urc::HealthCheckResponse>, Status> {
        Ok(Response::new(epic_urc::HealthCheckResponse {
            status: "ok".to_string(),
        }))
    }

    // P0, Phase 0. Creates a pending auth_sessions row and returns
    // {session_code, login_url}. See docs/architecture.md step 5.
    async fn start_auth_session(
        &self,
        _request: Request<epic_urc::StartAuthSessionRequest>,
    ) -> Result<Response<epic_urc::StartAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "start_auth_session: Phase 0 (see tasks.md)",
        ))
    }

    // P0, Phase 0. Polled by the CLI every 5s for up to 150s (lore CLI's own
    // hard deadline -- see docs/protocol-notes.md). Must return
    // {user_token: None} while pending, NOT an error.
    async fn get_auth_session(
        &self,
        _request: Request<epic_urc::GetAuthSessionRequest>,
    ) -> Result<Response<epic_urc::GetAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "get_auth_session: Phase 0 (see tasks.md)",
        ))
    }

    // Dead upstream: RefreshAuthSessionRequest carries no refresh token and
    // the lore CLI's own UcsAuthentication::refresh_authentication returns
    // NotSupported. Intentionally left unimplemented permanently; expiry
    // means re-login. See design plan section A.3.
    async fn refresh_auth_session(
        &self,
        _request: Request<epic_urc::RefreshAuthSessionRequest>,
    ) -> Result<Response<epic_urc::RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "refresh_auth_session: intentionally dead, matches upstream CLI behavior",
        ))
    }

    // P2, Phase 2. UNVERIFIED call sites upstream; implement as identity
    // validation and treat compliance requirements as satisfied unless
    // configured. See design plan Q8.
    async fn verify_user(
        &self,
        _request: Request<epic_urc::VerifyUserRequest>,
    ) -> Result<Response<epic_urc::VerifyUserResponse>, Status> {
        Err(Status::unimplemented("verify_user: Phase 2 (see tasks.md)"))
    }

    // P1, Phase 1. Primary CI path is expected to be token_type "api-key" or
    // a CI OIDC federation type (e.g. "github-actions"). See design plan
    // section A.3.
    async fn exchange_external_token_for_user_token(
        &self,
        _request: Request<epic_urc::ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_external_token_for_user_token: Phase 1 (see tasks.md)",
        ))
    }

    // P2, Phase 1. UNVERIFIED call sites upstream; implement for
    // completeness alongside the external-token path. See design plan A.3.
    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<epic_urc::ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_api_key_for_user_token: Phase 1 (see tasks.md)",
        ))
    }

    // P0, Phase 0. THE core RPC: mints the AuthZ token carrying `resources`.
    // Sizing rule (design plan section C): mint only the requested
    // resource_ids plus urc-* if the principal holds a wildcard binding.
    async fn exchange_user_token_for_multiresource_token(
        &self,
        _request: Request<epic_urc::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_user_token_for_multiresource_token: Phase 0 (see tasks.md)",
        ))
    }

    // P1, Phase 1. UNVERIFIED whether lore-server ever actually calls this
    // (design plan Q4). Implement correctly anyway; do not gate Phase 0 on it.
    async fn check_user_permission(
        &self,
        _request: Request<epic_urc::CheckUserPermissionRequest>,
    ) -> Result<Response<epic_urc::CheckUserPermissionResponse>, Status> {
        Err(Status::unimplemented(
            "check_user_permission: Phase 1 (see tasks.md)",
        ))
    }

    // P1, Phase 1. resource_filter / context_filter semantics are UNVERIFIED
    // (design plan Q5); proposed interpretation: exact match, trailing-*
    // prefix, or urc-* for all. Document the chosen interpretation here once
    // implemented.
    async fn lookup_user_permissions(
        &self,
        _request: Request<epic_urc::LookupUserPermissionsRequest>,
    ) -> Result<Response<epic_urc::LookupUserPermissionsResponse>, Status> {
        Err(Status::unimplemented(
            "lookup_user_permissions: Phase 1 (see tasks.md)",
        ))
    }

    // P1, Phase 1.
    async fn get_user_info(
        &self,
        _request: Request<epic_urc::GetUserInfoRequest>,
    ) -> Result<Response<epic_urc::GetUserInfoResponse>, Status> {
        Err(Status::unimplemented(
            "get_user_info: Phase 1 (see tasks.md)",
        ))
    }

    // P1, Phase 1.
    async fn get_user_id(
        &self,
        _request: Request<epic_urc::GetUserIdRequest>,
    ) -> Result<Response<epic_urc::GetUserIdResponse>, Status> {
        Err(Status::unimplemented("get_user_id: Phase 1 (see tasks.md)"))
    }

    // P2, Phase 1. UNVERIFIED semantics; assumed to map our internal
    // principal id back to the IdP subject (design plan Q9).
    async fn get_provider_user_id(
        &self,
        _request: Request<epic_urc::GetProviderUserIdRequest>,
    ) -> Result<Response<epic_urc::GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "get_provider_user_id: Phase 1 (see tasks.md)",
        ))
    }
}

pub struct RebacApiService;

#[tonic::async_trait]
impl rebac::rebac_api_server::RebacApi for RebacApiService {
    // Phase 0 (in-memory), Phase 1 (persisted). Called by lore-server on
    // repository creation. MUST be idempotent (OK if resource_id already
    // exists) and should establish the creating principal as owner. Design
    // plan Q6: UNVERIFIED whether lore-server sends an authorization header
    // on this call at all -- design the server-to-sidecar auth for this hop
    // assuming it may be absent (mTLS or a shared secret, not a user token).
    async fn create_resource(
        &self,
        _request: Request<rebac::CreateResourceRequest>,
    ) -> Result<Response<rebac::CreateResourceResponse>, Status> {
        Err(Status::unimplemented(
            "create_resource: Phase 0 in-memory, Phase 1 persisted (see tasks.md)",
        ))
    }

    // Phase 0 (in-memory), Phase 1 (persisted).
    async fn delete_resource(
        &self,
        _request: Request<rebac::DeleteResourceRequest>,
    ) -> Result<Response<rebac::DeleteResourceResponse>, Status> {
        Err(Status::unimplemented(
            "delete_resource: Phase 0 in-memory, Phase 1 persisted (see tasks.md)",
        ))
    }
}
