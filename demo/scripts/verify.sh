#!/bin/sh
# epic-lore-authz demo: prove the product actually works.
#
# Run this after `docker compose up -d --build`:
#
#   docker compose exec -T tools sh /scripts/verify.sh
#
# It runs INSIDE the demo's own network (the `tools` container), so every
# address below is a container address and nothing depends on which host ports
# you started the demo with.
#
# Each section prints a numbered CLAIM, the raw command output that decides
# it, and a [PASS] or [FAIL] line naming the claim. The script exits non-zero
# if any claim fails. It is re-runnable: it revokes the grant it made last
# time before testing the deny-before/allow-after sequence again.
#
# Nothing here is a secret. The admin token is a published demo value.

set -u

ADMIN_TOKEN="${ADMIN_API_TOKEN:-}"
PANEL_ORIGIN="${PANEL_ORIGIN:-http://localhost:8080}"
PANEL_PORT="${PANEL_PORT:-8080}"

AUTHZ_HTTP="http://authz:8080"
AUTHZ_GRPC="authz:8443"
LORE_GRPC="loreserver:41337"
PANEL_HTTP="http://panel:${PANEL_PORT}"
STARTUP_LOG="/startup/loreserver-startup.log"

# One repository, in the two encodings lore and this service each use for it:
# the same 16 bytes as a base64 id (what lore-server takes) and as the
# lowercase-hex "urc-" resource id (what the authorization service stores).
DEMO_REPO_ID_B64="AZS3JrNOcrC0VVC4ipZwdg=="
DEMO_BRANCH_ID_B64="AZS3JrNOcrC0VVC4ipZwuw=="
DEMO_RESOURCE_ID="urc-0194b726b34e72b0b45550b88a967076"

# An origin that is deliberately not this deployment's, for the CSRF check.
# ".example" is reserved by RFC 2606 and resolves nowhere.
HOSTILE_ORIGIN="http://cross-origin-attacker.example"

PASSES=0
FAILURES=0

say() { printf '%s\n' "$*"; }
rule() { printf '\n================================================================\n'; }

claim() {
    rule
    printf 'CLAIM %s\n  %s\n\n' "$1" "$2"
}

step() { printf '\n-- %s\n' "$*"; }

pass() {
    PASSES=$((PASSES + 1))
    printf '\n[PASS] %s\n' "$1"
}

fail() {
    FAILURES=$((FAILURES + 1))
    printf '\n[FAIL] %s\n' "$1"
}

check() { # check <condition-result> <description>
    if [ "$1" -eq 0 ]; then pass "$2"; else fail "$2"; fi
}

admin_curl() { # admin_curl <curl args...>  -- against the RAW sidecar port
    curl -sS -H "authorization: Bearer ${ADMIN_TOKEN}" "$@"
}

grpc_authz() { # grpc_authz <token-or-empty> <method> <json>
    _tok="$1"
    _method="$2"
    _body="$3"
    if [ -n "$_tok" ]; then
        grpcurl -plaintext -import-path /protos -proto auth_api.proto \
            -H "authorization: Bearer ${_tok}" -d "$_body" \
            "$AUTHZ_GRPC" "$_method"
    else
        grpcurl -plaintext -import-path /protos -proto auth_api.proto \
            -d "$_body" "$AUTHZ_GRPC" "$_method"
    fi
}

grpc_lore() { # grpc_lore <token-or-empty> <method> <json>
    _tok="$1"
    _method="$2"
    _body="$3"
    if [ -n "$_tok" ]; then
        grpcurl -plaintext -import-path /loreprotos \
            -proto lore/repository/v1/repository.proto \
            -H "authorization: Bearer ${_tok}" -d "$_body" \
            "$LORE_GRPC" "$_method"
    else
        grpcurl -plaintext -import-path /loreprotos \
            -proto lore/repository/v1/repository.proto \
            -d "$_body" "$LORE_GRPC" "$_method"
    fi
}

if [ -z "$ADMIN_TOKEN" ]; then
    say "ADMIN_API_TOKEN is not set in this container -- start the stack with docker compose."
    exit 2
fi

rule
say "epic-lore-authz demo verification"
say "  authorization service (raw HTTP) : ${AUTHZ_HTTP}"
say "  authorization service (gRPC)     : ${AUTHZ_GRPC}"
say "  admin panel, behind the proxy    : ${PANEL_HTTP}  (browser: ${PANEL_ORIGIN})"
say "  lore-server (gRPC)               : ${LORE_GRPC}"

# ---------------------------------------------------------------------------
claim 1 "The sidecar serves a JWKS with a kid and an alg, from a key it
  generated at startup. No key material ships with this demo."

step "GET ${AUTHZ_HTTP}/.well-known/jwks.json"
JWKS="$(curl -sS "${AUTHZ_HTTP}/.well-known/jwks.json")"
printf '%s\n' "$JWKS" | jq .
KID="$(printf '%s\n' "$JWKS" | jq -r '.keys[0].kid // empty')"
ALG="$(printf '%s\n' "$JWKS" | jq -r '.keys[0].alg // empty')"
say ""
say "kid = ${KID}"
say "alg = ${ALG}"
if [ -n "$KID" ] && [ "$ALG" = "ES256" ]; then
    pass "1: JWKS published with kid=${KID} alg=${ALG}"
else
    fail "1: JWKS did not carry a kid and alg=ES256"
fi

# ---------------------------------------------------------------------------
claim 2 "lore-server loaded its config and has authentication ENABLED:
  it points at this sidecar's JWKS, expects this sidecar's issuer and
  audience, and holds the service credential for the rebac hop."

step "lore-server's own startup line, filtered to its auth settings"
CONFIG_LINE="$(grep -m1 '^Loaded config:' "$STARTUP_LOG" 2>/dev/null)"
printf '%s\n' "$CONFIG_LINE" \
    | tr ',' '\n' \
    | grep -E 'auth: Some\(AuthSettings|jwt_issuer: Some|jwt_audience: Some|rebac_service_token: Some|endpoint: "http' \
    | sed 's/^ *//'
AUTH_OK=1
if printf '%s' "$CONFIG_LINE" | grep -q 'auth: Some(AuthSettings' \
    && printf '%s' "$CONFIG_LINE" | grep -q "jwt_issuer: Some(\"${PANEL_ORIGIN}\")" \
    && printf '%s' "$CONFIG_LINE" | grep -q 'rebac_service_token: Some' \
    && printf '%s' "$CONFIG_LINE" | grep -q 'jwk: Some(JWKServiceSettings'; then
    AUTH_OK=0
fi
check "$AUTH_OK" "2: lore-server reports auth enabled against this sidecar"

# ---------------------------------------------------------------------------
claim 3 "The admin gate: the sidecar's own port is fail-closed. An
  unauthenticated request gets 401. The same request with the bearer, or
  through the token-injecting proxy, gets 200."

step "GET ${AUTHZ_HTTP}/admin/ui with NO credential (the raw port)"
RAW_ANON="$(curl -sS -o /tmp/anon-body.txt -w '%{http_code}' "${AUTHZ_HTTP}/admin/ui")"
say "HTTP ${RAW_ANON}"
say "body: $(cat /tmp/anon-body.txt)"

step "GET ${AUTHZ_HTTP}/admin/ui presenting the bearer myself"
RAW_AUTH="$(admin_curl -o /dev/null -w '%{http_code}' "${AUTHZ_HTTP}/admin/ui")"
say "HTTP ${RAW_AUTH}"

step "GET ${PANEL_HTTP}/admin/ui with no credential, through the proxy that injects it"
PANEL_ANON="$(curl -sS -o /dev/null -w '%{http_code}' "${PANEL_HTTP}/admin/ui")"
say "HTTP ${PANEL_ANON}"

if [ "$RAW_ANON" = "401" ] && [ "$RAW_AUTH" = "200" ] && [ "$PANEL_ANON" = "200" ]; then
    pass "3: raw port 401 unauthenticated, 200 with the bearer, 200 via the proxy"
else
    fail "3: expected 401/200/200, got ${RAW_ANON}/${RAW_AUTH}/${PANEL_ANON}"
fi

# ---------------------------------------------------------------------------
rule
printf 'SETUP\n  Log in as the mock IdP user by walking the REAL login flow:\n'
printf '  StartAuthSession -> browser leg through the proxy -> GetAuthSession.\n\n'

PANEL_IP="$(getent hosts panel | awk '{print $1}' | head -1)"
CLIENT_STATE="verify-$$"

step "StartAuthSession (gRPC)"
START="$(grpc_authz "" epic_urc.UrcAuthApi/StartAuthSession \
    "{\"client_state\":\"${CLIENT_STATE}\"}")"
printf '%s\n' "$START"
SESSION_CODE="$(printf '%s\n' "$START" | jq -r '.sessionCode // empty')"
LOGIN_URL="$(printf '%s\n' "$START" | jq -r '.loginUrl // empty')"

step "Follow the login URL the way a browser would"
# `localhost:PORT` inside a container is the container itself, so the browser
# leg is pinned to the panel proxy's real address. The URLs stay byte-for-byte
# the ones a browser on the host would follow.
curl -sS -o /dev/null -L --max-redirs 12 \
    --resolve "localhost:${PANEL_PORT}:${PANEL_IP}" "$LOGIN_URL"
say "followed: ${LOGIN_URL}"

step "GetAuthSession (gRPC) -- collect the minted user token"
SESSION="$(grpc_authz "" epic_urc.UrcAuthApi/GetAuthSession \
    "{\"session_code\":\"${SESSION_CODE}\",\"client_state\":\"${CLIENT_STATE}\"}")"
USER_TOKEN="$(printf '%s\n' "$SESSION" | jq -r '.userToken.userToken // empty')"
if [ -z "$USER_TOKEN" ]; then
    printf '%s\n' "$SESSION"
    fail "SETUP: the login flow did not produce a user token"
    say ""
    say "Cannot continue without a token."
    exit 1
fi
say "minted a user token for the mock IdP user (${#USER_TOKEN} chars, not printed)"

step "The principal that login just created (JIT provisioning), via the admin API"
PRINCIPALS="$(admin_curl "${AUTHZ_HTTP}/admin/v1/principals")"
printf '%s\n' "$PRINCIPALS" | jq '.items[] | {id, display_name, source, is_service_account, status}'
PRINCIPAL_ID="$(printf '%s\n' "$PRINCIPALS" \
    | jq -r '[.items[] | select(.source == "oidc")][0].id // empty')"
say "principal id: ${PRINCIPAL_ID}"

step "Revoke any grant left over from a previous run of this script"
LEFTOVER="$(admin_curl "${AUTHZ_HTTP}/admin/v1/grants" \
    | jq -r --arg p "$PRINCIPAL_ID" --arg r "$DEMO_RESOURCE_ID" \
        '.items[] | select(.principal_id == $p and .resource_pattern == $r) | .id')"
if [ -n "$LEFTOVER" ]; then
    for gid in $LEFTOVER; do
        admin_curl -o /dev/null -w 'DELETE /admin/v1/grants/%{http_code}\n' \
            -X DELETE "${AUTHZ_HTTP}/admin/v1/grants/${gid}"
        say "revoked leftover grant ${gid}"
    done
else
    say "none (clean start)"
fi

# ---------------------------------------------------------------------------
claim 4 "BEFORE any grant: CheckUserPermission DENIES this user on
  ${DEMO_RESOURCE_ID}. Logging in creates an identity, never an authorization."

step "CheckUserPermission as the logged-in user"
BEFORE="$(grpc_authz "$USER_TOKEN" epic_urc.UrcAuthApi/CheckUserPermission \
    "{\"resource_id\":[\"${DEMO_RESOURCE_ID}\"]}")"
printf '%s\n' "$BEFORE"
if printf '%s' "$BEFORE" | jq -e --arg r "$DEMO_RESOURCE_ID" \
    '(.deniedResourcePermission // []) | map(.resourceId) | index($r)' >/dev/null \
    && ! printf '%s' "$BEFORE" | jq -e --arg r "$DEMO_RESOURCE_ID" \
        '(.allowedResourcePermission // []) | map(.resourceId) | index($r)' >/dev/null; then
    pass "4: DENIED before the grant (deniedResourcePermission holds the resource)"
else
    fail "4: expected the resource in deniedResourcePermission and nowhere else"
fi

# ---------------------------------------------------------------------------
claim 5 "The admin API provisions: create a principal, create a resource,
  and list the seeded roles a grant can name."

step "POST /admin/v1/principals -- a service-account principal"
NEW_PRINCIPAL="$(admin_curl -w '\nHTTP %{http_code}\n' \
    -H 'content-type: application/json' \
    -d '{"display_name":"demo build robot","preferred_username":"demo-robot","is_service_account":true}' \
    "${AUTHZ_HTTP}/admin/v1/principals")"
printf '%s\n' "$NEW_PRINCIPAL"
NEW_PRINCIPAL_OK=1
printf '%s' "$NEW_PRINCIPAL" | grep -q 'HTTP 201' && NEW_PRINCIPAL_OK=0

step "POST /admin/v1/resources -- register ${DEMO_RESOURCE_ID}"
NEW_RESOURCE="$(admin_curl -w '\nHTTP %{http_code}\n' \
    -H 'content-type: application/json' \
    -d "{\"resource_id\":\"${DEMO_RESOURCE_ID}\",\"resource_name\":\"demo-repository\"}" \
    "${AUTHZ_HTTP}/admin/v1/resources")"
printf '%s\n' "$NEW_RESOURCE"
NEW_RESOURCE_OK=1
# 201 on a clean start; 409 when this script has already run against this
# stack. Both mean the resource is registered.
printf '%s' "$NEW_RESOURCE" | grep -qE 'HTTP (201|409)' && NEW_RESOURCE_OK=0

step "GET /admin/v1/roles -- the three seeded roles"
ROLES="$(admin_curl "${AUTHZ_HTTP}/admin/v1/roles")"
printf '%s\n' "$ROLES" | jq -c '[.[] | {name, permissions}]'
ROLES_OK=1
printf '%s' "$ROLES" | jq -e 'map(.name) | index("admin")' >/dev/null && ROLES_OK=0

if [ "$NEW_PRINCIPAL_OK" -eq 0 ] && [ "$NEW_RESOURCE_OK" -eq 0 ] && [ "$ROLES_OK" -eq 0 ]; then
    pass "5: principal created, resource registered, roles listed"
else
    fail "5: principal=${NEW_PRINCIPAL_OK} resource=${NEW_RESOURCE_OK} roles=${ROLES_OK} (0 = ok)"
fi

# ---------------------------------------------------------------------------
claim 6 "The CSRF gate: the proxy injects the admin bearer, so authority is
  ambient. A cross-origin form POST is refused with 403. The IDENTICAL request
  from this deployment's own origin returns 303 -- and creates the grant."

step "POST ${PANEL_HTTP}/admin/ui/grants with Origin: ${HOSTILE_ORIGIN}"
CROSS_CODE="$(curl -sS -o /tmp/cross-body.txt -w '%{http_code}' \
    -X POST "${PANEL_HTTP}/admin/ui/grants" \
    -H "Origin: ${HOSTILE_ORIGIN}" \
    -d "role=admin&resource_pattern=${DEMO_RESOURCE_ID}&principal_kind=user&principal_id=${PRINCIPAL_ID}")"
say "HTTP ${CROSS_CODE}"
say "body: $(cat /tmp/cross-body.txt)"

step "The same POST with Origin: ${PANEL_ORIGIN} (this deployment's own origin)"
SAME_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "${PANEL_HTTP}/admin/ui/grants" \
    -H "Origin: ${PANEL_ORIGIN}" \
    -d "role=admin&resource_pattern=${DEMO_RESOURCE_ID}&principal_kind=user&principal_id=${PRINCIPAL_ID}")"
say "HTTP ${SAME_CODE}  (303 = the panel redirecting back to itself after the write)"

step "GET /admin/v1/grants -- the grant the same-origin POST created"
admin_curl "${AUTHZ_HTTP}/admin/v1/grants" \
    | jq -c --arg p "$PRINCIPAL_ID" '.items[] | select(.principal_id == $p)'

if [ "$CROSS_CODE" = "403" ] && [ "$SAME_CODE" = "303" ]; then
    pass "6: cross-origin POST refused with 403, same-origin POST accepted with 303"
else
    fail "6: expected 403 then 303, got ${CROSS_CODE} then ${SAME_CODE}"
fi

# ---------------------------------------------------------------------------
claim 7 "AFTER the grant: the SAME CheckUserPermission call with the SAME
  token now ALLOWS, and says which permissions."

step "CheckUserPermission again, unchanged"
AFTER="$(grpc_authz "$USER_TOKEN" epic_urc.UrcAuthApi/CheckUserPermission \
    "{\"resource_id\":[\"${DEMO_RESOURCE_ID}\"]}")"
printf '%s\n' "$AFTER"
if printf '%s' "$AFTER" | jq -e --arg r "$DEMO_RESOURCE_ID" \
    '(.allowedResourcePermission // []) | map(.resourceId) | index($r)' >/dev/null; then
    pass "7: ALLOWED after the grant (same token, same call, opposite answer)"
else
    fail "7: expected the resource in allowedResourcePermission"
fi

# ---------------------------------------------------------------------------
claim 8 "lore-server itself: an unauthenticated gRPC call is rejected, and a
  call carrying a token minted by this service succeeds."

step "Exchange the login token for a multiresource (AuthZ) token"
EXCHANGE="$(grpc_authz "$USER_TOKEN" \
    epic_urc.UrcAuthApi/ExchangeUserTokenForMultiresourceToken \
    "{\"resource_id\":[\"${DEMO_RESOURCE_ID}\"]}")"
AUTHZ_TOKEN="$(printf '%s\n' "$EXCHANGE" | jq -r '.token.userToken // empty')"
if [ -z "$AUTHZ_TOKEN" ]; then
    printf '%s\n' "$EXCHANGE"
    fail "8: could not exchange for a multiresource token"
else
    say "got a multiresource token (${#AUTHZ_TOKEN} chars, not printed)"

    step "RepositoryList with NO credential"
    UNAUTH_OUT="$(grpc_lore "" lore.repository.v1.RepositoryService/RepositoryList '{}' 2>&1)"
    printf '%s\n' "$UNAUTH_OUT"

    step "RepositoryCreate with the token (this also makes lore-server call the
   sidecar's RebacApi with its service credential to register the resource)"
    CREATE_OUT="$(grpc_lore "$AUTHZ_TOKEN" \
        lore.repository.v1.RepositoryService/RepositoryCreate \
        "{\"id\":\"${DEMO_REPO_ID_B64}\",\"name\":\"demo-repository\",\"description\":\"created by the demo verify script\",\"default_branch_id\":\"${DEMO_BRANCH_ID_B64}\",\"default_branch_name\":\"main\"}" 2>&1)"
    printf '%s\n' "$CREATE_OUT"

    step "RepositoryList with the token"
    AUTH_OUT="$(grpc_lore "$AUTHZ_TOKEN" \
        lore.repository.v1.RepositoryService/RepositoryList '{}' 2>&1)"
    printf '%s\n' "$AUTH_OUT"

    UNAUTH_REJECTED=1
    printf '%s' "$UNAUTH_OUT" | grep -qi 'unauthenticated' && UNAUTH_REJECTED=0
    AUTH_ACCEPTED=1
    printf '%s' "$AUTH_OUT" | grep -q 'demo-repository' && AUTH_ACCEPTED=0

    if [ "$UNAUTH_REJECTED" -eq 0 ] && [ "$AUTH_ACCEPTED" -eq 0 ]; then
        pass "8: lore-server rejected the anonymous call and served the authorized one"
    else
        fail "8: unauthenticated_rejected=${UNAUTH_REJECTED} authorized_ok=${AUTH_ACCEPTED} (0 = ok)"
    fi
fi

# ---------------------------------------------------------------------------
rule
say "claims passed: ${PASSES}"
say "claims failed: ${FAILURES}"
rule
if [ "$FAILURES" -ne 0 ]; then
    say "VERIFICATION FAILED"
    exit 1
fi
say "VERIFICATION PASSED"
say ""
say "Open the panel in a browser: ${PANEL_ORIGIN}/admin/ui"
say "Revoke the grant there, re-run this script, and claim 7 flips back to denied."
exit 0
