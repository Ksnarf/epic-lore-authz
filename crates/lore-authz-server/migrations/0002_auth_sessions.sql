-- PHASE 1b (see tasks.md): the browser login session backing
-- StartAuthSession / GetAuthSession, plus the two columns the OIDC login leg
-- needs on `principals`.
--
-- Same schema-qualification rules as 0001: every statement is
-- schema-UNQUALIFIED on purpose, because `Db::connect` points every pooled
-- connection's search_path at the configured DB_SCHEMA before this runs.
--
-- WHY SESSIONS LIVE IN THE DATABASE AND NOT IN PROCESS MEMORY
-- The three legs of one login hit this service at three different times and,
-- behind a load balancer, potentially at three different replicas: the CLI
-- calls StartAuthSession, the operator's BROWSER hits /login/{code} and then
-- the IdP redirects it to /oidc/callback, and the CLI polls GetAuthSession.
-- An in-memory session map would work only for a single-replica deployment
-- and would fail intermittently (not loudly) for any other.

-- WHAT IS STORED HASHED AND WHAT IS STORED RAW -- deliberate, per column:
--
--   HASHED (SHA-256, base64url -- see crate::secret::sha256_b64url):
--     session_code_hash, login_code_hash, client_state_hash. These are the
--     values a CLIENT presents to us to prove it is the right caller. They
--     are looked up / compared, never re-sent by us, so we never need the
--     original -- and storing only a fingerprint means a database read does
--     not hand out usable polling credentials for in-flight logins.
--
--   RAW: oidc_state, oidc_nonce, pkce_verifier. These are the IdP-leg
--     transients, and we must be able to REPRODUCE them, not merely
--     recognize them: `state` and `nonce` go into the authorization-request
--     URL we build when the browser hits /login/{login_code}, and
--     `pkce_verifier` is sent verbatim to the IdP's token endpoint. A hash
--     is unusable for that. They are single-use, expire with the session,
--     and are useless without an IdP authorization code.
--
-- No salt, no password KDF, on any of the hashed columns: the inputs are
-- 256-bit CSPRNG tokens, not user-chosen passwords, so there is no
-- dictionary for a salt or a work factor to defend against.

CREATE TABLE IF NOT EXISTS auth_sessions (
    -- SHA-256 of the session_code returned to the CLI by StartAuthSession
    -- and presented back on every GetAuthSession poll.
    session_code_hash   text PRIMARY KEY,
    -- SHA-256 of the SEPARATE code embedded in the browser login URL. A
    -- distinct secret from session_code on purpose: a login URL leaks
    -- easily (browser history, shoulder-surfing, a pasted link), and
    -- whoever holds it must NOT thereby be able to poll for the resulting
    -- token.
    login_code_hash     text NOT NULL,
    -- SHA-256 of the client_state the CLI generated and sent on
    -- StartAuthSession. Compared (in constant time) against the
    -- client_state sent on each poll, so a session_code alone is not
    -- sufficient to collect the token.
    client_state_hash   text NOT NULL,
    -- OIDC authorization-request transients. See the RAW note above.
    oidc_state          text NOT NULL,
    oidc_nonce          text NOT NULL,
    pkce_verifier       text NOT NULL,
    status              text NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'authenticated', 'consumed')),
    -- NULL until the IdP callback resolves a real principal. A session can
    -- never reach 'authenticated' without one.
    principal_id        uuid,
    -- Epoch MILLISECONDS, as plain integers rather than timestamptz,
    -- deliberately: the SQLite dialect of this migration has no timestamptz
    -- type and no now(), and every comparison this table needs is a plain
    -- integer comparison against "now". Keeping the representation
    -- identical on both backends means the session expiry logic in
    -- crates/lore-authz-server/src/db/sessions.rs has exactly one code path,
    -- not two subtly different ones.
    created_at_ms       bigint NOT NULL,
    expires_at_ms       bigint NOT NULL
);

-- Both are lookup keys for a single session, so both must be unique: a
-- collision would mean one login's browser leg completing another's.
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_login_code_hash_idx
    ON auth_sessions (login_code_hash);

-- The OIDC callback has no session_code and no login_code -- `state` is the
-- ONLY thing tying the IdP's redirect back to the session that started it,
-- which is exactly why it must be validated rather than trusted.
CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_oidc_state_idx
    ON auth_sessions (oidc_state);

-- Supports the opportunistic reaper (db::sessions::delete_expired).
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_ms_idx
    ON auth_sessions (expires_at_ms);

-- The `idp` claim is MANDATORY on every AuthZ token and cannot be recovered
-- from the caller's AuthN token, which has no such field (docs/
-- protocol-notes.md #7b, docs/open-questions.md Q13). This column is where
-- ExchangeUserTokenForMultiresourceToken recovers it: the login leg records
-- which identity provider proved this principal's identity, and the exchange
-- reads it back off the principal row. NULL for principals provisioned
-- without an IdP (the Phase 1a test/manual path), which falls back to the
-- configured TOKEN_IDP.
ALTER TABLE principals ADD COLUMN IF NOT EXISTS idp text;

-- OIDC login looks a principal up by (source, subject) -- the IdP's `sub`
-- claim scoped to where it came from. Unique so a second login can never
-- create a duplicate principal for the same external identity, and so a
-- lookup can never be ambiguous about which principal an IdP subject means.
CREATE UNIQUE INDEX IF NOT EXISTS principals_source_subject_idx
    ON principals (source, subject);
