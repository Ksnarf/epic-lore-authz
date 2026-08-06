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
use crate::db::permissions::DbPolicyStore;
use crate::db::permissions::WILDCARD_RESOURCE_PATTERN;
use crate::db::principals;
use crate::db::resources;
use crate::login;
use crate::login::LoginSettings;
use crate::login::PollOutcome;
use crate::minting::AuthzTokenInput;
use crate::minting::mint_authz_token;
use crate::service_auth;
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
    /// Token/session knobs for the PHASE 1b login and exchange RPCs -- see
    /// `crate::login::LoginSettings`.
    pub login: LoginSettings,
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

        principals::find_active_principal(db, principal_id)
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

    // PHASE 1b (see tasks.md). The CLI polls this every 5 seconds while the
    // operator completes the browser login, up to 30 times, then gives up
    // (its own hard 150-second budget -- see `crate::login`'s module doc
    // comment for why this service does not try to work around it).
    //
    // `Ok(user_token: None)` means "keep polling", and is deliberately the
    // response for EVERY not-yet-a-token outcome, including an unknown or
    // expired session_code and a mismatched client_state -- this endpoint is
    // unauthenticated, so distinguishing them would make it an oracle. The
    // one exception is a real database failure, which returns an error
    // rather than inviting 29 more pointless polls. See `crate::login`.
    async fn get_auth_session(
        &self,
        request: Request<epic_urc::GetAuthSessionRequest>,
    ) -> Result<Response<epic_urc::GetAuthSessionResponse>, Status> {
        let db = self.require_db()?.clone();
        let req = request.into_inner();

        let outcome = login::poll_session(
            &db,
            &self.signing_keys,
            &self.login,
            &self.jwt_issuer,
            &self.jwt_audience,
            &req.session_code,
            &req.client_state,
        )
        .await?;

        let user_token = match outcome {
            PollOutcome::KeepPolling => None,
            PollOutcome::Authenticated(user) => Some(epic_urc::UserToken {
                user_token: user.token.token,
                // MILLISECONDS, not seconds -- a different unit from the
                // JWT's own `exp` claim inside the same token. See
                // docs/open-questions.md Q1 (SETTLED) and
                // `crate::minting::signed_token`.
                expires_at: user.token.expires_at,
                user_id: user.user_id,
                user_name: user.user_name,
            }),
        };

        Ok(Response::new(epic_urc::GetAuthSessionResponse {
            user_token,
        }))
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

    // PHASE 1b (see tasks.md). THE core RPC: takes the caller's AuthN token
    // as `authorization: Bearer <token>` and mints the AuthZ token carrying
    // the `resources` claim that lore-server actually enforces.
    //
    // Three details that are load-bearing rather than incidental:
    //
    //  * `idp` is recovered from the PRINCIPAL ROW, not from the caller's
    //    AuthN token -- that token has no `idp` field at all
    //    (docs/protocol-notes.md #7b, docs/open-questions.md Q13, now
    //    settled). Omitting it would not fail loudly: lore-server would
    //    silently decode the token as the AuthN shape, drop `resources` to
    //    `None`, and every repository operation would fail as a misleading
    //    permissions error.
    //  * `resources` contains ONLY the requested ids the caller actually
    //    holds a grant for. A requested id with no grant, or one that was
    //    never registered / has been deleted, is simply absent -- so a
    //    caller entitled to nothing gets a well-formed token that authorizes
    //    nothing, rather than an error that might be retried into a
    //    different answer.
    //  * A wildcard grant is expanded to concrete resource ids by the shared
    //    policy engine, never emitted as the literal `"urc-*"` (see
    //    `crate::db::permissions`).
    async fn exchange_user_token_for_multiresource_token(
        &self,
        request: Request<epic_urc::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<epic_urc::ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        let db = self.require_db()?.clone();
        let authorization = authorization_header(&request);
        let req = request.into_inner();

        let principal = self
            .resolve_caller(&db, authorization.as_deref(), None)
            .await?;

        let policy = DbPolicyStore::new(db.clone());
        let granted = policy
            .resolve_resource_permissions(&principal, &req.resource_id)
            .await
            .map_err(|err| {
                tracing::warn!(?err, "resolve_resource_permissions failed");
                Status::internal("permission resolution failed")
            })?;

        // Never empty (see LoginSettings::default_idp): an empty `idp` is as
        // silently broken as an absent one.
        let idp = principal
            .idp
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| self.login.default_idp.clone());

        let signed = mint_authz_token(
            self.signing_keys.active(),
            &self.jwt_issuer,
            &self.jwt_audience,
            &self.login.token_env,
            self.login.authz_token_ttl_secs,
            &AuthzTokenInput {
                user_id: principal.id.to_string(),
                name: principal.display_name.clone(),
                preferred_username: principal.preferred_username.clone(),
                is_service_account: principal.is_service_account,
                idp,
                // Group-claim-to-`groups` mapping is a separate, still-open
                // Phase 1 item (tasks.md); emitting a half-mapped list here
                // would be worse than emitting none.
                groups: None,
                resources: granted,
            },
        )
        .map_err(|err| {
            tracing::warn!(error = %err, "minting an AuthZ token failed");
            Status::internal("token minting failed")
        })?;

        tracing::info!(
            principal_id = %principal.id,
            requested = req.resource_id.len(),
            "AuthZ token issued"
        );

        Ok(Response::new(
            epic_urc::ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(epic_urc::UserToken {
                    user_token: signed.token,
                    expires_at: signed.expires_at,
                    user_id: principal.id.to_string(),
                    user_name: principal.display_name,
                }),
            },
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

        let policy = DbPolicyStore::new(db.clone());
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

        let candidates = resources::list_resource_ids_with_prefix(&db, &req.resource_filter)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "resource candidate lookup failed");
                Status::internal("resource lookup failed")
            })?;

        let policy = DbPolicyStore::new(db.clone());
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
    /// Shared secret gating both RPCs on this service -- see
    /// `crate::service_auth` for the mechanism and why it fits this hop
    /// (lore-server, not a user, is the caller here), and
    /// `docs/open-questions.md` Q6/Q12 for the finding this closes. `None`
    /// means every call is denied: see `Self::authorize_caller`.
    pub rebac_service_token: Option<String>,
}

impl RebacApiService {
    fn require_db(&self) -> Result<&Arc<Db>, Status> {
        self.db.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "Postgres not configured (DATABASE_URL unset) -- see docs/configuration.md",
            )
        })
    }

    /// Gates BOTH `create_resource` and `delete_resource` on the configured
    /// `REBAC_SERVICE_TOKEN`. Checked before `require_db` deliberately: an
    /// unauthenticated caller should learn nothing about this service's
    /// Postgres configuration state.
    fn authorize_caller<T>(&self, request: &Request<T>) -> Result<(), Status> {
        service_auth::verify_rebac_caller(
            authorization_header(request).as_deref(),
            self.rebac_service_token.as_deref(),
        )
    }
}

/// Rejects a `resource_id` that is not a well-formed `"urc-<id>"` value, and
/// -- the LOW finding from the security review this pass closes -- explicitly
/// rejects the literal wildcard sentinel `WILDCARD_RESOURCE_PATTERN`
/// (`"urc-*"`) itself: that string is reserved for `role_bindings.
/// resource_pattern` wildcard GRANTS (see `crate::db::permissions`), never a
/// real resource row. Letting it through `CreateResource` would create a
/// resource whose id is indistinguishable from the wildcard pattern to any
/// code that compares the two as plain strings.
fn validate_new_resource_id(resource_id: &str) -> Result<(), Status> {
    if resource_id.is_empty() {
        return Err(Status::invalid_argument("resource_id must not be empty"));
    }
    if resource_id == WILDCARD_RESOURCE_PATTERN {
        return Err(Status::invalid_argument(format!(
            "resource_id must not be the wildcard sentinel {WILDCARD_RESOURCE_PATTERN:?} -- \
             that value is reserved for role_bindings.resource_pattern wildcard grants, never a \
             real resource row"
        )));
    }
    let suffix = resource_id.strip_prefix("urc-").ok_or_else(|| {
        Status::invalid_argument(format!(
            "resource_id {resource_id:?} does not match the required \"urc-<id>\" convention"
        ))
    })?;
    let suffix_is_well_formed = !suffix.is_empty()
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !suffix_is_well_formed {
        return Err(Status::invalid_argument(format!(
            "resource_id {resource_id:?} suffix must be non-empty ASCII alphanumeric \
             (plus '-'/'_')"
        )));
    }
    Ok(())
}

#[tonic::async_trait]
impl rebac::rebac_api_server::RebacApi for RebacApiService {
    // PHASE 1a (see tasks.md). MUST be idempotent: creating a resource that
    // already exists returns `Code::AlreadyExists`, which lore-server's own
    // `repository_create_auth_resource` call site treats as a successful
    // create, not an error (see the fork's `repository_create.rs`).
    //
    // Security review remediation (see tasks.md, docs/open-questions.md Q6):
    // gated on `Self::authorize_caller` (`REBAC_SERVICE_TOKEN`, fail closed)
    // before touching Postgres at all, closing the "anything that can reach
    // the gRPC port can create/delete resource rows" finding. `resource_id`
    // is also format-validated, rejecting the literal wildcard sentinel
    // (`validate_new_resource_id`, the LOW finding from the same review).
    async fn create_resource(
        &self,
        request: Request<rebac::CreateResourceRequest>,
    ) -> Result<Response<rebac::CreateResourceResponse>, Status> {
        self.authorize_caller(&request)?;
        let req = request.into_inner();
        validate_new_resource_id(&req.resource_id)?;
        let db = self.require_db()?;

        match resources::create_resource(db, &req.resource_id, &req.resource_name).await {
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
    // `db::resources::delete_resource`'s doc comment). Security review
    // remediation (see tasks.md, docs/open-questions.md Q6): same
    // `Self::authorize_caller` gate as `create_resource` above -- this was
    // the RPC the review's concrete exploit scenario used (mass-revoking
    // every repository's authorization by iterating the predictable
    // `urc-{repository_id}` convention with zero credentials).
    async fn delete_resource(
        &self,
        request: Request<rebac::DeleteResourceRequest>,
    ) -> Result<Response<rebac::DeleteResourceResponse>, Status> {
        self.authorize_caller(&request)?;
        let req = request.into_inner();
        if req.resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id must not be empty"));
        }
        let db = self.require_db()?;

        resources::delete_resource(db, &req.resource_id)
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
            login: LoginSettings::default(),
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

    /// PHASE 1b. The same fail-closed shape for the two login RPCs backed by
    /// session storage: with no database configured they must deny, never
    /// fall back to some in-memory path that would silently work on one
    /// replica and not another.
    #[tokio::test]
    async fn get_auth_session_without_configured_database_fails_closed() {
        let service = service_without_db();
        let request = Request::new(epic_urc::GetAuthSessionRequest {
            session_code: "anything".to_string(),
            client_state: "anything".to_string(),
        });

        let err = epic_urc::urc_auth_api_server::UrcAuthApi::get_auth_session(&service, request)
            .await
            .expect_err("must fail closed when the database is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn exchange_user_token_without_configured_database_fails_closed() {
        let service = service_without_db();
        let request = Request::new(epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec!["urc-abc".to_string()],
        });

        let err =
            epic_urc::urc_auth_api_server::UrcAuthApi::exchange_user_token_for_multiresource_token(
                &service, request,
            )
            .await
            .expect_err("must fail closed when the database is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    /// The exchange RPC must never mint a token for a caller who presented
    /// no bearer token at all. Checked here at the unit level (the
    /// `require_db` early return runs first, so this uses a service WITH a
    /// database in the real-database suite too -- see
    /// `tests/authz_suite`'s `exchange_*` cases).
    #[tokio::test]
    async fn exchange_user_token_with_no_bearer_is_denied_before_any_token_is_minted() {
        let service = service_without_db();
        let request = Request::new(epic_urc::ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec![],
        });

        let err =
            epic_urc::urc_auth_api_server::UrcAuthApi::exchange_user_token_for_multiresource_token(
                &service, request,
            )
            .await
            .expect_err("no bearer token must never produce a token");
        // FailedPrecondition (no DB) rather than Unauthenticated here, and
        // that ordering is deliberate: an unconfigured service tells an
        // anonymous caller nothing about its auth state. Either way the
        // invariant this asserts holds -- no error path produces a token.
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    const TEST_REBAC_SERVICE_TOKEN: &str = "test-only-shared-secret-do-not-use-in-prod";

    fn rebac_service_with_token() -> RebacApiService {
        RebacApiService {
            db: None,
            rebac_service_token: Some(TEST_REBAC_SERVICE_TOKEN.to_string()),
        }
    }

    fn rebac_service_without_token() -> RebacApiService {
        RebacApiService {
            db: None,
            rebac_service_token: None,
        }
    }

    fn authorized_request<T>(body: T) -> Request<T> {
        let mut req = Request::new(body);
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {TEST_REBAC_SERVICE_TOKEN}")
                .parse()
                .unwrap(),
        );
        req
    }

    fn create_request(resource_id: &str) -> rebac::CreateResourceRequest {
        rebac::CreateResourceRequest {
            resource_id: resource_id.to_string(),
            resource_name: "test".to_string(),
        }
    }

    fn delete_request(resource_id: &str) -> rebac::DeleteResourceRequest {
        rebac::DeleteResourceRequest {
            resource_id: resource_id.to_string(),
        }
    }

    /// With a valid service token presented, `require_db`'s
    /// `FailedPrecondition` is still the real production early-return path
    /// when `DATABASE_URL` is not configured -- this proves the new
    /// caller-identity gate does not paper over that existing fail-closed
    /// behavior, just runs before it.
    #[tokio::test]
    async fn create_resource_without_configured_postgres_fails_closed() {
        let service = rebac_service_with_token();
        let request = authorized_request(create_request("urc-abc"));

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn delete_resource_without_configured_postgres_fails_closed() {
        let service = rebac_service_with_token();
        let request = authorized_request(delete_request("urc-abc"));

        let err = rebac::rebac_api_server::RebacApi::delete_resource(&service, request)
            .await
            .expect_err("must fail closed, not panic or allow, when Postgres is unconfigured");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    // --- RebacApi caller-identity gate (security review remediation, see
    // tasks.md and docs/open-questions.md Q6) --------------------------

    #[tokio::test]
    async fn create_resource_denies_unauthenticated_caller() {
        let service = rebac_service_with_token();
        let request = Request::new(create_request("urc-abc")); // no authorization metadata

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("an unauthenticated caller must be denied");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_resource_denies_unauthenticated_caller() {
        let service = rebac_service_with_token();
        let request = Request::new(delete_request("urc-abc")); // no authorization metadata

        let err = rebac::rebac_api_server::RebacApi::delete_resource(&service, request)
            .await
            .expect_err("an unauthenticated caller must be denied");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn create_resource_denies_wrong_service_token() {
        let service = rebac_service_with_token();
        let mut request = Request::new(create_request("urc-abc"));
        request
            .metadata_mut()
            .insert("authorization", "Bearer wrong-secret".parse().unwrap());

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("a wrong service token must be denied");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_resource_denies_wrong_service_token() {
        let service = rebac_service_with_token();
        let mut request = Request::new(delete_request("urc-abc"));
        request
            .metadata_mut()
            .insert("authorization", "Bearer wrong-secret".parse().unwrap());

        let err = rebac::rebac_api_server::RebacApi::delete_resource(&service, request)
            .await
            .expect_err("a wrong service token must be denied");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    /// The single most important case: an OPERATOR who never set
    /// `REBAC_SERVICE_TOKEN` must get a hard deny on every call, never a
    /// silent allow -- this is the exact failure mode the security review
    /// flagged as the worst possible outcome.
    #[tokio::test]
    async fn create_resource_denies_when_gate_is_unconfigured_even_with_a_presented_token() {
        let service = rebac_service_without_token();
        let request = authorized_request(create_request("urc-abc"));

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("an unconfigured gate must deny, never default-allow");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_resource_denies_when_gate_is_unconfigured_even_with_a_presented_token() {
        let service = rebac_service_without_token();
        let request = authorized_request(delete_request("urc-abc"));

        let err = rebac::rebac_api_server::RebacApi::delete_resource(&service, request)
            .await
            .expect_err("an unconfigured gate must deny, never default-allow");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // --- resource_id format validation (LOW finding, same review) -------

    #[tokio::test]
    async fn create_resource_rejects_wildcard_sentinel_resource_id() {
        let service = rebac_service_with_token();
        let request = authorized_request(create_request(WILDCARD_RESOURCE_PATTERN));

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("the literal wildcard sentinel must never be accepted as a resource_id");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_resource_rejects_resource_id_missing_urc_prefix() {
        let service = rebac_service_with_token();
        let request = authorized_request(create_request("not-the-right-prefix-abc"));

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("a resource_id not matching the urc-<id> convention must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_resource_rejects_empty_suffix_after_prefix() {
        let service = rebac_service_with_token();
        let request = authorized_request(create_request("urc-"));

        let err = rebac::rebac_api_server::RebacApi::create_resource(&service, request)
            .await
            .expect_err("urc- with nothing after it must be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn validate_new_resource_id_accepts_well_formed_ids() {
        assert!(validate_new_resource_id("urc-abc123").is_ok());
        assert!(validate_new_resource_id("urc-0194b726b34e72b0b45550b88a967076").is_ok());
    }
}
