//! Server implementations of `UrcAuthApi` (auth_api.proto) and `RebacApi`
//! (rebac_api.proto).
//!
//! PHASE 1a (see tasks.md) wires up real Postgres-backed logic for exactly
//! four RPCs: `LookupUserPermissions`, `CheckUserPermission`,
//! `RebacApi::CreateResource`, `RebacApi::DeleteResource`. Every other RPC
//! is still a `Status::unimplemented` stub -- see the per-RPC comments below
//! for which phase covers each. `StartAuthSession` / `GetAuthSession` /
//! `ExchangeUserTokenForMultiresourceToken` / OIDC / SAML are explicitly
//! Phase 1b, deliberately untouched by PHASE 1a.

use std::sync::Arc;

use lore_authz_core::policy::PolicyStore;
use lore_authz_proto::epic_urc;
use lore_authz_proto::ucs::auth as rebac;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::caller;
use crate::db::Db;
use crate::db::permissions::PgPolicyStore;
use crate::db::principals;
use crate::db::resources;
use crate::signing::SigningKeyStore;

fn resource_permission_to_wire(
    rp: lore_authz_core::claims::ResourcePermission,
) -> epic_urc::ResourcePermission {
    epic_urc::ResourcePermission {
        resource_id: rp.resource_id,
        permission: rp.permission,
    }
}

/// Extracts the raw `authorization` metadata value from a gRPC request, if
/// present. This is a plain string, not necessarily `"Bearer <token>"`: see
/// `crate::caller`'s doc comment for the two shapes actually observed
/// (lore CLI sends `Bearer <token>`; lore-server's own
/// `create_request_with_authorization` forwards whatever raw value the
/// original caller sent it, including a literal empty string).
fn authorization_header<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

pub struct AuthApiService {
    /// `None` when `DATABASE_URL` is not configured. The four PHASE 1a RPCs
    /// fail closed with `Status::failed_precondition` in that case rather
    /// than panicking -- everything else in this scaffold (HealthCheck,
    /// JWKS, minting) has no Postgres dependency and is unaffected.
    pub db: Option<Arc<Db>>,
    pub signing_keys: Arc<SigningKeyStore>,
    pub jwt_issuer: String,
    pub jwt_audience: Vec<String>,
}

impl AuthApiService {
    fn require_db(&self) -> Result<&Arc<Db>, Status> {
        self.db.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "Postgres not configured (DATABASE_URL unset) -- see docs/configuration.md",
            )
        })
    }

    /// Resolves the calling principal for `CheckUserPermission` /
    /// `LookupUserPermissions`: from the request's own `target_user` token
    /// if one was supplied, otherwise from the caller's `authorization`
    /// metadata. Fails closed (`Status::unauthenticated`) if the token is
    /// missing/invalid, or if it decodes to a `sub` that does not resolve to
    /// an `active` principal (`db::principals::find_active_principal`
    /// returning `None` -- unknown, or suspended/deprovisioned).
    async fn resolve_caller(
        &self,
        db: &Db,
        authorization: Option<&str>,
        target_user_token: Option<&str>,
    ) -> Result<lore_authz_core::model::Principal, Status> {
        let principal_id = caller::caller_principal_id(
            target_user_token.or(authorization),
            &self.signing_keys,
            &self.jwt_issuer,
            &self.jwt_audience,
        )?;

        principals::find_active_principal(db.pool(), principal_id)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, %principal_id, "principal lookup failed");
                Status::internal("principal lookup failed")
            })?
            .ok_or_else(|| Status::unauthenticated("unknown or inactive principal"))
    }
}

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

    // P0, Phase 1b (deliberately untouched by PHASE 1a -- see tasks.md).
    async fn start_auth_session(
        &self,
        _request: Request<epic_urc::StartAuthSessionRequest>,
    ) -> Result<Response<epic_urc::StartAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "start_auth_session: Phase 1b (see tasks.md)",
        ))
    }

    // P0, Phase 1b (deliberately untouched by PHASE 1a -- see tasks.md).
    async fn get_auth_session(
        &self,
        _request: Request<epic_urc::GetAuthSessionRequest>,
    ) -> Result<Response<epic_urc::GetAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "get_auth_session: Phase 1b (see tasks.md)",
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

    // P1, Phase 1b (deliberately untouched by PHASE 1a -- see tasks.md).
    async fn exchange_external_token_for_user_token(
        &self,
        _request: Request<epic_urc::ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_external_token_for_user_token: Phase 1b (see tasks.md)",
        ))
    }

    // P2, Phase 1b. UNVERIFIED call sites upstream; implement for
    // completeness alongside the external-token path. See design plan A.3.
    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<epic_urc::ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_api_key_for_user_token: Phase 1b (see tasks.md)",
        ))
    }

    // P0, Phase 1b (deliberately untouched by PHASE 1a -- see tasks.md). THE
    // core RPC that will mint the AuthZ token carrying `resources`; the
    // policy engine it will read (`PgPolicyStore`, below) already exists as
    // of PHASE 1a.
    async fn exchange_user_token_for_multiresource_token(
        &self,
        _request: Request<epic_urc::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_user_token_for_multiresource_token: Phase 1b (see tasks.md)",
        ))
    }

    // PHASE 1a (see tasks.md). Real logic: resolves the caller (from
    // `target_user` if given, else the request's own `authorization`
    // metadata), then asks `PgPolicyStore` whether they hold a grant
    // (direct, via a group, or via a wildcard, either of those) for each
    // requested `resource_id`. Fails closed: any error resolving the caller
    // or querying Postgres is returned as `Err`, never as an empty allow.
    async fn check_user_permission(
        &self,
        request: Request<epic_urc::CheckUserPermissionRequest>,
    ) -> Result<Response<epic_urc::CheckUserPermissionResponse>, Status> {
        let db = self.require_db()?.clone();
        let authorization = authorization_header(&request);
        let req = request.into_inner();

        let target_user_token = req.target_user.as_ref().and_then(|target| {
            let epic_urc::TargetUser { user } = target;
            user.as_ref()
                .map(|epic_urc::target_user::User::UserToken(token)| token.clone())
        });

        let principal = self
            .resolve_caller(&db, authorization.as_deref(), target_user_token.as_deref())
            .await?;

        let policy = PgPolicyStore::new(db.pool().clone());
        let granted = policy
            .resolve_resource_permissions(&principal, &req.resource_id)
            .await
            .map_err(|err| {
                tracing::warn!(?err, "resolve_resource_permissions failed");
                Status::internal("permission resolution failed")
            })?;

        let granted_by_id: std::collections::HashMap<String, Vec<String>> = granted
            .into_iter()
            .map(|rp| (rp.resource_id, rp.permission))
            .collect();

        let mut allowed_resource_permission = Vec::new();
        let mut denied_resource_permission = Vec::new();
        for resource_id in req.resource_id {
            match granted_by_id.get(&resource_id) {
                Some(permission) => {
                    allowed_resource_permission.push(epic_urc::ResourcePermission {
                        resource_id,
                        permission: permission.clone(),
                    })
                }
                None => denied_resource_permission.push(epic_urc::ResourcePermission {
                    resource_id,
                    permission: vec![],
                }),
            }
        }

        Ok(Response::new(epic_urc::CheckUserPermissionResponse {
            allowed_resource_permission,
            denied_resource_permission,
        }))
    }

    // PHASE 1a (see tasks.md). `resource_filter` semantics (design plan Q5
    // was UNVERIFIED; settled here): a plain prefix match against
    // NOT-deleted `resources.resource_id` (empty filter matches everything).
    // lore-server's real call site sends the literal string `"urc"` (not
    // `"urc-"`, not `"urc-*"`) -- see `repository_list::
    // lookup_authorized_repositories` in the fork this implements against.
    //
    // A wildcard grant is expanded to every currently-existing resource id
    // it matches, NEVER returned as the literal string `"urc-*"` -- see
    // `crate::db::permissions`'s module doc comment for why that distinction
    // is load-bearing, not cosmetic.
    async fn lookup_user_permissions(
        &self,
        request: Request<epic_urc::LookupUserPermissionsRequest>,
    ) -> Result<Response<epic_urc::LookupUserPermissionsResponse>, Status> {
        let db = self.require_db()?.clone();
        let authorization = authorization_header(&request);
        let req = request.into_inner();

        let principal = self
            .resolve_caller(&db, authorization.as_deref(), None)
            .await?;

        let candidates = resources::list_resource_ids_with_prefix(db.pool(), &req.resource_filter)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "resource candidate lookup failed");
                Status::internal("resource lookup failed")
            })?;

        let policy = PgPolicyStore::new(db.pool().clone());
        let resource_permission = policy
            .resolve_resource_permissions(&principal, &candidates)
            .await
            .map_err(|err| {
                tracing::warn!(?err, "resolve_resource_permissions failed");
                Status::internal("permission resolution failed")
            })?;

        // Pagination is applied AFTER permission resolution (over the
        // already-granted set), not over the raw candidate list -- see
        // docs/configuration.md. Not exercised by any real call site today
        // (lore-server never sends page_size/page_token), but the message
        // shape supports it, so it is implemented for real rather than
        // ignored.
        let offset = req
            .page_token
            .as_deref()
            .and_then(|token| token.parse::<usize>().ok())
            .unwrap_or(0);

        let (page, next_page_token) = match req.page_size {
            Some(size) if size > 0 => {
                let size = size as usize;
                let end = offset.saturating_add(size).min(resource_permission.len());
                let page = resource_permission
                    .get(offset.min(resource_permission.len())..end)
                    .unwrap_or_default()
                    .to_vec();
                let next = if end < resource_permission.len() {
                    Some(end.to_string())
                } else {
                    None
                };
                (page, next)
            }
            _ => (resource_permission, None),
        };

        Ok(Response::new(epic_urc::LookupUserPermissionsResponse {
            resource_permission: page.into_iter().map(resource_permission_to_wire).collect(),
            next_page_token,
        }))
    }

    // P1, Phase 1b.
    async fn get_user_info(
        &self,
        _request: Request<epic_urc::GetUserInfoRequest>,
    ) -> Result<Response<epic_urc::GetUserInfoResponse>, Status> {
        Err(Status::unimplemented(
            "get_user_info: Phase 1b (see tasks.md)",
        ))
    }

    // P1, Phase 1b.
    async fn get_user_id(
        &self,
        _request: Request<epic_urc::GetUserIdRequest>,
    ) -> Result<Response<epic_urc::GetUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "get_user_id: Phase 1b (see tasks.md)",
        ))
    }

    // P2, Phase 1b. UNVERIFIED semantics; assumed to map our internal
    // principal id back to the IdP subject (design plan Q9).
    async fn get_provider_user_id(
        &self,
        _request: Request<epic_urc::GetProviderUserIdRequest>,
    ) -> Result<Response<epic_urc::GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "get_provider_user_id: Phase 1b (see tasks.md)",
        ))
    }
}

pub struct RebacApiService {
    /// Same "fail closed with `failed_precondition` when unconfigured" shape
    /// as `AuthApiService::db` above.
    pub db: Option<Arc<Db>>,
}

impl RebacApiService {
    fn require_db(&self) -> Result<&Arc<Db>, Status> {
        self.db.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "Postgres not configured (DATABASE_URL unset) -- see docs/configuration.md",
            )
        })
    }
}

#[tonic::async_trait]
impl rebac::rebac_api_server::RebacApi for RebacApiService {
    // PHASE 1a (see tasks.md). MUST be idempotent: creating a resource that
    // already exists returns `Code::AlreadyExists`, which lore-server's own
    // `repository_create_auth_resource` call site treats as a successful
    // create, not an error (see the fork's `repository_create.rs`).
    //
    // Design plan Q6 (UNVERIFIED whether lore-server sends a meaningful
    // authorization header on this hop at all) is NOT resolved by this
    // pass: no caller-identity check is performed here, matching the design
    // plan's own recommendation to gate this hop at the network layer
    // (mTLS / shared secret) rather than a user token, since there is no
    // evidence lore-server ever sends one worth decoding. This is an
    // explicit, documented gap, not an oversight -- see tasks.md "PHASE 1a".
    async fn create_resource(
        &self,
        request: Request<rebac::CreateResourceRequest>,
    ) -> Result<Response<rebac::CreateResourceResponse>, Status> {
        let db = self.require_db()?;
        let req = request.into_inner();
        if req.resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id must not be empty"));
        }

        match resources::create_resource(db.pool(), &req.resource_id, &req.resource_name).await {
            Ok(resources::CreateResourceOutcome::Created) => {
                Ok(Response::new(rebac::CreateResourceResponse {}))
            }
            Ok(resources::CreateResourceOutcome::AlreadyExists) => Err(Status::already_exists(
                format!("resource {} already exists", req.resource_id),
            )),
            Err(err) => {
                tracing::warn!(error = %err, resource_id = %req.resource_id, "create_resource failed");
                Err(Status::internal("create_resource failed"))
            }
        }
    }

    // PHASE 1a (see tasks.md). Idempotent: deleting a resource that is
    // already deleted, or never existed, is not an error (see
    // `db::resources::delete_resource`'s doc comment). Same
    // no-caller-identity-check gap as `create_resource` above.
    async fn delete_resource(
        &self,
        request: Request<rebac::DeleteResourceRequest>,
    ) -> Result<Response<rebac::DeleteResourceResponse>, Status> {
        let db = self.require_db()?;
        let req = request.into_inner();
        if req.resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id must not be empty"));
        }

        resources::delete_resource(db.pool(), &req.resource_id)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, resource_id = %req.resource_id, "delete_resource failed");
                Status::internal("delete_resource failed")
            })?;

        Ok(Response::new(rebac::DeleteResourceResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tonic::Code;

    use super::*;
    use crate::signing::SigningKeyStore;

    fn service_without_db() -> AuthApiService {
        AuthApiService {
            db: None,
            signing_keys: Arc::new(
                SigningKeyStore::load(
                    "file:///epic-lore-authz-grpc-test-fixture-does-not-exist.der",
                )
                .unwrap(),
            ),
            jwt_issuer: "https://authz.example.com".to_string(),
            jwt_audience: vec!["lore.example.com".to_string()],
        }
    }

    /// Exercises the REAL production early-return path (not a mock): when
    /// `DATABASE_URL` is not configured, the PHASE 1a RPCs must fail closed
    /// with a distinct, clearly-diagnosable status rather than panicking or
    /// silently allowing.
    #[tokio::test]
    async fn lookup_user_permissions_without_configured_postgres_fails_closed() {
        let service = service_without_db();
        let request = Request::new(epic_urc::LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            ..Default::default()
        });

        let err =
            epic_urc::urc_auth_api_server::UrcAuthApi::lookup_user_permissions(&service, request)
                .await
                .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn check_user_permission_without_configured_postgres_fails_closed() {
        let service = service_without_db();
        let request = Request::new(epic_urc::CheckUserPermissionRequest {
            resource_id: vec!["urc-abc".to_string()],
            target_user: None,
        });

        let err =
            epic_urc::urc_auth_api_server::UrcAuthApi::check_user_permission(&service, request)
                .await
                .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn create_resource_without_configured_postgres_fails_closed() {
        let service = RebacApiService { db: None };
        let request = Request::new(rebac::CreateResourceRequest {
            resource_id: "urc-abc".to_string(),
            resource_name: "abc".to_string(),
        });

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn delete_resource_without_configured_postgres_fails_closed() {
        let service = RebacApiService { db: None };
        let request = Request::new(rebac::DeleteResourceRequest {
            resource_id: "urc-abc".to_string(),
        });

        let err = rebac::rebac_api_server::RebacApi::delete_resource(&service, request)
            .await
            .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }
}
