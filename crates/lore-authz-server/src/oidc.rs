//! A provider-agnostic OIDC relying-party client (PHASE 1b, see tasks.md):
//! discovery, the authorization-code flow with PKCE, and ID token
//! verification.
//!
//! ## Provider-agnostic on purpose
//! Everything this module needs about an identity provider comes from that
//! provider's own `/.well-known/openid-configuration` document -- endpoints,
//! JWKS location, and which client-authentication method to use at the
//! token endpoint. There is no per-vendor branch anywhere in this file, and
//! adding one would be a bug: any IdP implementing OIDC Discovery and the
//! authorization-code grant works, including the ones this project has not
//! been tested against yet.
//!
//! The suite that proves it (`tests/oidc_flow.rs`) drives a REAL identity
//! provider in a container through a REAL browser leg -- a real authorize
//! redirect, a real code, a real token-endpoint exchange, a real ID token
//! signed by a real key fetched from the provider's real JWKS.
//!
//! ## What is validated, and why each one is load-bearing
//! - **`state`**: not validated here but by lookup -- `state` is the ONLY
//!   thing tying the IdP's redirect back to the session that started it, so
//!   an unrecognized value simply finds no session and the callback fails
//!   closed (`crate::oidc_login`). Without it, an attacker could deliver
//!   their own authorization code to a victim's callback (login CSRF).
//! - **`nonce`**: compared, in constant time, against the value bound to the
//!   session when the authorization request was built. Without it, an ID
//!   token obtained elsewhere for the same client could be replayed here.
//! - **PKCE (S256)**: the code verifier never leaves this service, and the
//!   IdP will only exchange the code for a caller that can produce it. This
//!   is what makes an intercepted authorization code useless.
//! - **Signature**: verified against the key the IdP publishes under the ID
//!   token's own `kid`, with the ALGORITHM pinned to what the JWKS declares
//!   (see `algorithm_for`). A JWKS key with no `alg` falls back to the
//!   header's, restricted to an asymmetric allowlist -- accepting `HS*`
//!   there is the classic key-confusion attack, where an attacker signs a
//!   forged token using the provider's PUBLIC key as an HMAC secret.
//! - **`iss` / `aud` / `exp`**: `iss` must equal the configured issuer
//!   exactly, `aud` must contain our client id, and expiry is enforced with
//!   `jsonwebtoken`'s default leeway.
//!
//! ## Logging
//! Nothing in this module ever logs an ID token, an access token, an
//! authorization code, a code verifier, a nonce, or the client secret --
//! at any level. `OidcError`'s `Display` is deliberately coarse for the same
//! reason: it is the text a browser may see. Diagnostic detail goes to
//! `tracing::warn` and still never includes any of the above.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::jwk::KeyAlgorithm;
use reqwest::Url;
use ring::digest::SHA256;
use ring::digest::digest;
use serde::Deserialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;
use tokio::sync::RwLock;

use crate::secret::constant_time_eq;

/// How long a fetched discovery document is reused before being refetched.
/// Endpoints change rarely; an hour keeps a login off the critical path of
/// a provider's availability without pinning stale endpoints for a day.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

/// How long a fetched JWKS is reused. Shorter than discovery because
/// providers rotate signing keys far more often than endpoints -- and a
/// `kid` miss forces an immediate refetch regardless (see `key_for_kid`).
const JWKS_TTL: Duration = Duration::from_secs(300);

/// Every outbound call to the identity provider is bounded. An IdP that
/// accepts a connection and then never answers must not hold a login (or a
/// server thread) open indefinitely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Signature algorithms accepted on an ID token. ASYMMETRIC ONLY, and that
/// is the entire point: allowing an `HS*` algorithm here would let an
/// attacker forge a token by using the provider's PUBLIC signing key (which
/// is, by definition, public) as an HMAC secret.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Deliberately coarse: these strings can reach a browser. The specific
/// reason is logged, never returned.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("the identity provider could not be reached")]
    Provider,
    #[error("the identity provider's configuration is not usable")]
    Discovery,
    #[error("the login could not be completed")]
    CodeExchange,
    #[error("the identity provider's response failed validation")]
    IdToken,
}

/// The relying-party half of an OIDC connection. Every field is operator
/// configuration; nothing here is discovered.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// The issuer identifier, e.g. `https://idp.example.com`. Discovery is
    /// performed against `<issuer>/.well-known/openid-configuration`, and
    /// the document's own `issuer` must match this exactly (OIDC Discovery
    /// section 4.3) -- a mismatch is a provider-substitution attack, not a
    /// configuration nuisance.
    pub issuer: String,
    pub client_id: String,
    /// Read from configuration only. Never defaulted, never committed, never
    /// logged.
    pub client_secret: String,
    /// Must be registered verbatim with the provider, and must be the
    /// `/oidc/callback` route on this service's own public origin.
    pub redirect_url: String,
    /// Space-separated. `openid` is mandatory and is added if absent.
    pub scopes: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// Absent in some providers' documents. OIDC Core section 9 makes
    /// `client_secret_basic` the default when it is, which is what
    /// `client_auth_method` below assumes.
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    /// The ONLY field this flow uses. `access_token` is deliberately not
    /// captured: this service authenticates a user, it does not call the
    /// provider's userinfo or any other resource API, so holding an access
    /// token would be a liability with no purpose.
    id_token: String,
}

#[serde_as]
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    /// A single string OR an array on the wire, same as lore's own tokens.
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(default)]
    #[allow(dead_code)] // validated by jsonwebtoken's own audience check
    aud: Vec<String>,
    nonce: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
}

/// What a successfully verified ID token asserts. Nothing here is trusted
/// beyond "the configured identity provider said so".
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The provider's `sub` claim: opaque, stable, and scoped to the
    /// provider. This -- never the email -- is the identity key, because an
    /// email address can be reassigned to a different human.
    pub subject: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
}

struct Cached<T> {
    value: Arc<T>,
    fetched_at: Instant,
}

/// A live OIDC connection: configuration plus the caches that keep a login
/// from making three extra round trips to the provider.
pub struct OidcProvider {
    config: OidcConfig,
    http: reqwest::Client,
    discovery: RwLock<Option<Cached<DiscoveryDocument>>>,
    jwks: RwLock<Option<Cached<JwkSet>>>,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !config.issuer.is_empty()
                && !config.client_id.is_empty()
                && !config.client_secret.is_empty()
                && !config.redirect_url.is_empty(),
            "an OIDC connection needs all of OIDC_ISSUER_URL, OIDC_CLIENT_ID, \
             OIDC_CLIENT_SECRET and OIDC_REDIRECT_URL -- a partially configured provider is \
             treated as unconfigured and denies every login; see docs/configuration.md"
        );

        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            // The provider is reached directly. Following a redirect from a
            // token or JWKS endpoint would let a compromised (or merely
            // sloppy) provider point key material at an arbitrary host.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            config: OidcConfig {
                issuer: config.issuer.trim_end_matches('/').to_string(),
                scopes: normalize_scopes(&config.scopes),
                ..config
            },
            http,
            discovery: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    async fn discovery(&self) -> Result<Arc<DiscoveryDocument>, OidcError> {
        if let Some(cached) = self.discovery.read().await.as_ref()
            && cached.fetched_at.elapsed() < DISCOVERY_TTL
        {
            return Ok(cached.value.clone());
        }

        let url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        let response = self.http.get(&url).send().await.map_err(|err| {
            tracing::warn!(error = %err, issuer = %self.config.issuer, "OIDC discovery request failed");
            OidcError::Provider
        })?;
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                issuer = %self.config.issuer,
                "OIDC discovery returned a non-success status"
            );
            return Err(OidcError::Provider);
        }
        let document: DiscoveryDocument = response.json().await.map_err(|err| {
            tracing::warn!(error = %err, "OIDC discovery document did not parse");
            OidcError::Discovery
        })?;

        // OIDC Discovery section 4.3: the document's own issuer MUST match
        // the one used to fetch it. Skipping this turns a hijacked discovery
        // URL into a full provider substitution.
        if document.issuer.trim_end_matches('/') != self.config.issuer {
            tracing::warn!(
                configured = %self.config.issuer,
                advertised = %document.issuer,
                "OIDC discovery document advertises a different issuer; refusing it"
            );
            return Err(OidcError::Discovery);
        }

        let document = Arc::new(document);
        *self.discovery.write().await = Some(Cached {
            value: document.clone(),
            fetched_at: Instant::now(),
        });
        Ok(document)
    }

    async fn jwks(&self, force_refresh: bool) -> Result<Arc<JwkSet>, OidcError> {
        if !force_refresh
            && let Some(cached) = self.jwks.read().await.as_ref()
            && cached.fetched_at.elapsed() < JWKS_TTL
        {
            return Ok(cached.value.clone());
        }

        let jwks_uri = self.discovery().await?.jwks_uri.clone();
        let response = self.http.get(&jwks_uri).send().await.map_err(|err| {
            tracing::warn!(error = %err, "OIDC JWKS request failed");
            OidcError::Provider
        })?;
        if !response.status().is_success() {
            tracing::warn!(
                status = response.status().as_u16(),
                "OIDC JWKS returned a non-success status"
            );
            return Err(OidcError::Provider);
        }
        let set: JwkSet = response.json().await.map_err(|err| {
            tracing::warn!(error = %err, "OIDC JWKS did not parse");
            OidcError::Discovery
        })?;

        let set = Arc::new(set);
        *self.jwks.write().await = Some(Cached {
            value: set.clone(),
            fetched_at: Instant::now(),
        });
        Ok(set)
    }

    /// Finds the provider's key for `kid`, refetching the JWKS exactly once
    /// on a miss (providers rotate keys without warning), then giving up.
    /// One retry, not a loop: an unbounded retry on a `kid` an attacker
    /// controls is a request amplifier pointed at the provider.
    async fn key_for_kid(&self, kid: &str) -> Result<Jwk, OidcError> {
        if let Some(jwk) = self.jwks(false).await?.find(kid) {
            return Ok(jwk.clone());
        }
        if let Some(jwk) = self.jwks(true).await?.find(kid) {
            return Ok(jwk.clone());
        }
        tracing::warn!("ID token names a kid the identity provider's JWKS does not publish");
        Err(OidcError::IdToken)
    }

    /// Builds the authorization request URL the browser is redirected to.
    ///
    /// `code_verifier` is NOT sent here -- only its S256 challenge is. That
    /// asymmetry is the whole value of PKCE: an authorization code observed
    /// in transit cannot be redeemed without the verifier, which never
    /// leaves this service.
    pub async fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        code_verifier: &str,
    ) -> Result<String, OidcError> {
        let discovery = self.discovery().await?;
        let mut url = Url::parse(&discovery.authorization_endpoint).map_err(|err| {
            tracing::warn!(error = %err, "authorization_endpoint is not a valid URL");
            OidcError::Discovery
        })?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &pkce_s256_challenge(code_verifier))
            .append_pair("code_challenge_method", "S256");
        Ok(url.to_string())
    }

    /// Exchanges an authorization code for an ID token and verifies it.
    ///
    /// Returns an identity ONLY if every check passes: the exchange
    /// succeeded, the ID token's signature verifies against the provider's
    /// published key under a pinned asymmetric algorithm, `iss`/`aud`/`exp`
    /// are correct, and `nonce` matches the value bound to this session.
    /// There is no path through this function that returns an identity
    /// without all of them.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, OidcError> {
        let discovery = self.discovery().await?;

        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("code_verifier", code_verifier),
        ];

        let mut request = self.http.post(&discovery.token_endpoint);
        if client_auth_is_basic(&discovery) {
            // RFC 6749 section 2.3.1: the client id and secret are
            // form-urlencoded BEFORE being base64'd for HTTP Basic. Skipping
            // that step works right up until a generated secret contains a
            // `+`, `/` or `=`, at which point authentication fails for
            // reasons that look nothing like the cause.
            request = request.basic_auth(
                form_urlencode(&self.config.client_id),
                Some(form_urlencode(&self.config.client_secret)),
            );
        } else {
            form.push(("client_id", self.config.client_id.as_str()));
            form.push(("client_secret", self.config.client_secret.as_str()));
        }

        let response = request.form(&form).send().await.map_err(|err| {
            tracing::warn!(error = %err, "OIDC token request failed");
            OidcError::Provider
        })?;
        if !response.status().is_success() {
            // The body of a failed token response can echo the code back.
            // Log the status only.
            tracing::warn!(
                status = response.status().as_u16(),
                "OIDC token endpoint rejected the authorization code exchange"
            );
            return Err(OidcError::CodeExchange);
        }
        let token: TokenResponse = response.json().await.map_err(|err| {
            tracing::warn!(error = %err, "OIDC token response did not parse");
            OidcError::CodeExchange
        })?;

        self.verify_id_token(&token.id_token, expected_nonce).await
    }

    /// Verifies an ID token: signature against the provider's published key
    /// under a pinned asymmetric algorithm, then `iss`, `aud`, `exp` and
    /// `nonce`.
    ///
    /// `pub` rather than private so `tests/oidc_flow.rs` can present tokens
    /// a real identity provider would never emit -- one with a flipped
    /// signature byte, one signed by a key the provider does not publish,
    /// one carrying the wrong nonce. Those are the cases that matter most
    /// and they cannot be produced through `exchange_code`, because a real
    /// provider only ever returns valid tokens. Nothing in the production
    /// path calls this directly.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, OidcError> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|err| {
            tracing::warn!(error = %err, "ID token header did not parse");
            OidcError::IdToken
        })?;
        let Some(kid) = header.kid.as_deref() else {
            tracing::warn!("ID token carries no kid; cannot select a verification key");
            return Err(OidcError::IdToken);
        };

        let jwk = self.key_for_kid(kid).await?;
        let algorithm = algorithm_for(&jwk, header.alg)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|err| {
            tracing::warn!(error = %err, "identity provider's JWK is not usable as a key");
            OidcError::IdToken
        })?;

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.validate_exp = true;

        let claims = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|err| {
                // `err` here is a jsonwebtoken error kind (InvalidSignature,
                // InvalidIssuer, ExpiredSignature, ...) and carries no token
                // content.
                tracing::warn!(error = %err, "ID token failed signature/claim validation");
                OidcError::IdToken
            })?
            .claims;

        // Replay protection. Constant-time, and REQUIRED: a token with no
        // nonce at all is rejected, not treated as "nothing to compare".
        let presented = claims.nonce.as_deref().unwrap_or_default();
        if presented.is_empty()
            || !constant_time_eq(presented.as_bytes(), expected_nonce.as_bytes())
        {
            tracing::warn!("ID token nonce does not match the one bound to this login session");
            return Err(OidcError::IdToken);
        }

        if claims.sub.is_empty() {
            tracing::warn!("ID token has an empty subject");
            return Err(OidcError::IdToken);
        }

        Ok(VerifiedIdentity {
            subject: claims.sub,
            name: claims.name,
            preferred_username: claims.preferred_username,
            email: claims.email,
        })
    }
}

/// `openid` is mandatory in an OIDC authorization request (OIDC Core section
/// 3.1.2.1); a provider given a scope list without it may return an OAuth2
/// response with no ID token at all, which fails much later and much less
/// clearly than adding it here.
fn normalize_scopes(scopes: &str) -> String {
    let mut parts: Vec<&str> = scopes.split_whitespace().collect();
    if !parts.contains(&"openid") {
        parts.insert(0, "openid");
    }
    parts.join(" ")
}

/// Which client-authentication method to use at the token endpoint, taken
/// from the provider's own discovery document rather than hardcoded.
/// `client_secret_basic` is preferred where supported (it is the OIDC
/// default and the only method some providers accept); `client_secret_post`
/// is the fallback for providers that advertise only that.
fn client_auth_is_basic(discovery: &DiscoveryDocument) -> bool {
    match discovery.token_endpoint_auth_methods_supported.as_ref() {
        // OIDC Core section 9: absent means client_secret_basic.
        None => true,
        Some(methods) => {
            methods.iter().any(|m| m == "client_secret_basic")
                || !methods.iter().any(|m| m == "client_secret_post")
        }
    }
}

/// `application/x-www-form-urlencoded` encoding of one component, per RFC
/// 6749 section 2.3.1's requirement for HTTP Basic client credentials.
/// Hand-rolled rather than pulling in a percent-encoding crate for one
/// eight-line function.
fn form_urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// RFC 7636 section 4.2: `code_challenge = BASE64URL(SHA256(verifier))`.
fn pkce_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}

/// Pins the verification algorithm.
///
/// The JWKS's declared `alg` wins where present, and the token header must
/// agree with it; where the JWKS omits `alg` (permitted by RFC 7517), the
/// header's is used but ONLY from an asymmetric allowlist. Trusting an
/// unrestricted header algorithm is the classic JWT key-confusion attack: an
/// attacker sets `alg: HS256` and signs with the provider's public key,
/// which is published for anyone to read.
fn algorithm_for(jwk: &Jwk, header_alg: Algorithm) -> Result<Algorithm, OidcError> {
    if !ALLOWED_ALGORITHMS.contains(&header_alg) {
        tracing::warn!(
            alg = ?header_alg,
            "ID token uses an algorithm this service refuses (asymmetric algorithms only)"
        );
        return Err(OidcError::IdToken);
    }

    let Some(declared) = jwk.common.key_algorithm else {
        return Ok(header_alg);
    };
    let declared = algorithm_from_key_algorithm(declared).ok_or_else(|| {
        tracing::warn!(
            ?declared,
            "identity provider's JWK declares an unsupported alg"
        );
        OidcError::IdToken
    })?;
    if declared != header_alg {
        tracing::warn!(
            ?declared,
            header = ?header_alg,
            "ID token algorithm does not match the algorithm its key declares"
        );
        return Err(OidcError::IdToken);
    }
    Ok(declared)
}

fn algorithm_from_key_algorithm(value: KeyAlgorithm) -> Option<Algorithm> {
    Some(match value {
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        // Everything else -- notably every HS* variant, and any encryption
        // algorithm -- is refused rather than mapped.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::AlgorithmParameters;
    use jsonwebtoken::jwk::CommonParameters;
    use jsonwebtoken::jwk::EllipticCurve;
    use jsonwebtoken::jwk::EllipticCurveKeyParameters;
    use jsonwebtoken::jwk::EllipticCurveKeyType;

    use super::*;

    fn jwk_with_alg(alg: Option<KeyAlgorithm>) -> Jwk {
        Jwk {
            common: CommonParameters {
                key_algorithm: alg,
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: "x".to_string(),
                y: "y".to_string(),
            }),
        }
    }

    /// The key-confusion guard: an ID token claiming an HMAC algorithm must
    /// be refused outright, because the "secret" would be the provider's
    /// published public key.
    #[test]
    fn symmetric_algorithms_are_refused_even_if_the_key_declares_one() {
        assert!(algorithm_for(&jwk_with_alg(None), Algorithm::HS256).is_err());
        assert!(algorithm_for(&jwk_with_alg(Some(KeyAlgorithm::HS256)), Algorithm::HS256).is_err());
        assert!(algorithm_for(&jwk_with_alg(None), Algorithm::HS512).is_err());
    }

    #[test]
    fn a_header_algorithm_that_disagrees_with_the_key_is_refused() {
        let jwk = jwk_with_alg(Some(KeyAlgorithm::RS256));
        assert!(algorithm_for(&jwk, Algorithm::ES256).is_err());
        assert_eq!(
            algorithm_for(&jwk, Algorithm::RS256).unwrap(),
            Algorithm::RS256
        );
    }

    #[test]
    fn a_key_without_an_alg_falls_back_to_the_header_within_the_allowlist() {
        assert_eq!(
            algorithm_for(&jwk_with_alg(None), Algorithm::ES256).unwrap(),
            Algorithm::ES256
        );
    }

    /// RFC 7636 appendix B's worked example, so the PKCE challenge is pinned
    /// to the specification rather than to this implementation's own output.
    #[test]
    fn pkce_challenge_matches_the_rfc_7636_worked_example() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn openid_scope_is_always_present_and_never_duplicated() {
        assert_eq!(normalize_scopes("profile email"), "openid profile email");
        assert_eq!(normalize_scopes("openid profile"), "openid profile");
        assert_eq!(normalize_scopes(""), "openid");
        assert_eq!(normalize_scopes("   "), "openid");
    }

    #[test]
    fn client_auth_method_follows_the_discovery_document() {
        let with = |methods: Option<Vec<&str>>| DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            jwks_uri: "https://idp.example.com/keys".to_string(),
            token_endpoint_auth_methods_supported: methods
                .map(|m| m.into_iter().map(str::to_string).collect()),
        };
        // OIDC Core section 9: absent means client_secret_basic.
        assert!(client_auth_is_basic(&with(None)));
        assert!(client_auth_is_basic(&with(Some(vec![
            "client_secret_basic"
        ]))));
        assert!(client_auth_is_basic(&with(Some(vec![
            "client_secret_basic",
            "client_secret_post"
        ]))));
        assert!(!client_auth_is_basic(&with(Some(vec![
            "client_secret_post"
        ]))));
    }

    #[test]
    fn form_urlencoding_escapes_what_http_basic_would_otherwise_corrupt() {
        assert_eq!(
            form_urlencode("plain-secret_123~x.y"),
            "plain-secret_123~x.y"
        );
        assert_eq!(form_urlencode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode(":"), "%3A");
    }

    /// A partially configured provider is treated as UNCONFIGURED, and an
    /// unconfigured provider denies -- it never half-works.
    #[test]
    fn a_partially_configured_provider_is_refused_at_construction() {
        let base = OidcConfig {
            issuer: "https://idp.example.com".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://authz.example.com/oidc/callback".to_string(),
            scopes: "openid".to_string(),
        };
        assert!(OidcProvider::new(base.clone()).is_ok());
        for missing in [
            OidcConfig {
                issuer: String::new(),
                ..base.clone()
            },
            OidcConfig {
                client_id: String::new(),
                ..base.clone()
            },
            OidcConfig {
                client_secret: String::new(),
                ..base.clone()
            },
            OidcConfig {
                redirect_url: String::new(),
                ..base.clone()
            },
        ] {
            assert!(OidcProvider::new(missing).is_err());
        }
    }

    #[test]
    fn the_issuer_is_normalized_so_a_trailing_slash_is_not_a_mismatch() {
        let provider = OidcProvider::new(OidcConfig {
            issuer: "https://idp.example.com/".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://authz.example.com/oidc/callback".to_string(),
            scopes: "profile".to_string(),
        })
        .unwrap();
        assert_eq!(provider.issuer(), "https://idp.example.com");
        assert_eq!(provider.config.scopes, "openid profile");
    }
}
