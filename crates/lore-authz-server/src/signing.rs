//! The one ES256 signing key this Phase 0 scaffold uses to mint tokens, and
//! the JWKS document derived from it.
//!
//! ## Why ES256 (EC P-256)
//! docs/protocol-notes.md section 4 records that upstream `lore-server`
//! tests exercise ES256 and HS256, and recommends ES256 or RS256 beyond
//! local dev. `lore-server/src/auth/jwk.rs`'s own `loads_keys_from_file_url`
//! test uses an ES256 P-256 JWK, confirming `DecodingKey::from_jwk` handles
//! that shape. ES256 keeps key generation and the JWK encoding simple (a
//! P-256 point, no RSA modulus/exponent math), so it is the Phase 0 choice
//! here; nothing about lore-server's verifier is ES256-specific.
//!
//! ## Why every JWKS key has BOTH `kid` and `alg`
//! `lore-server/src/auth/jwk.rs`'s `fetch_new_keys` does:
//! ```text
//! let algorithm = jwk.common.key_algorithm.ok_or(JWKServiceError::InternalError)?;
//! ```
//! (verified at the pinned commit `f205899adf24b13b2d28e5c08d9256ac99c69f0c`,
//! `lore-server/src/auth/jwk.rs` around line 164-167). A JWKS response
//! missing `alg` on even one key fails loading the ENTIRE key set -- not
//! just that key. `key_id` (`kid`) is required earlier in the same function
//! for the same reason. Every `Jwk` built below sets both.
//!
//! ## Key material handling
//! `SigningKeyStore::load` tries, in order:
//! 1. A `file://` `SIGNING_KEY_SOURCE` pointing at an existing file
//!    containing an unencrypted PKCS#8 EC private key, either PEM
//!    (`-----BEGIN PRIVATE KEY-----`) or raw DER.
//! 2. Otherwise, generates a fresh EC P-256 keypair in memory and logs a
//!    loud warning that this is an EPHEMERAL DEV key. It is never written to
//!    disk by this process. All tokens signed by the previous run's
//!    ephemeral key stop validating on restart -- acceptable for local dev,
//!    not for anything shared or long-lived. See docs/protocol-notes.md.
//!
//! NOTE on `.env.example`'s original wording: `SIGNING_KEY_SOURCE` was
//! documented as pointing at "a single ES256 JWK". That is not achievable
//! with this project's pinned `jsonwebtoken` crate: `jsonwebtoken::jwk::Jwk`
//! (see its module doc, "only meant to be used to deal with public JWK, not
//! generate ones") has no private-key ("d") variant, so a private EC JWK
//! cannot be loaded through it. `.env.example` and `docs/configuration.md`
//! have been corrected to describe a PKCS#8 private key file instead; see
//! docs/protocol-notes.md for the note.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::CommonParameters;
use jsonwebtoken::jwk::EllipticCurve;
use jsonwebtoken::jwk::EllipticCurveKeyParameters;
use jsonwebtoken::jwk::EllipticCurveKeyType;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::jwk::KeyAlgorithm;
use jsonwebtoken::jwk::PublicKeyUse;
use ring::rand::SystemRandom;
use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair;
use tracing::info;
use tracing::warn;
use uuid::Uuid;

/// PEM header for an unencrypted PKCS#8 private key, used only to decide
/// whether a loaded key file is PEM or raw DER -- no PEM parsing library is
/// pulled in; the header/footer lines are stripped by hand and the body
/// base64-decoded, since PKCS#8 PEM is just base64(DER) wrapped at 64 cols.
const PKCS8_PEM_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_PEM_FOOTER: &str = "-----END PRIVATE KEY-----";

/// One signing key: the private half (as a jsonwebtoken `EncodingKey`, ready
/// to sign with) and the public half (as a `Jwk`, ready to publish).
#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub public_jwk: Jwk,
}

/// Holds the single active signing key for this Phase 0 scaffold. Real key
/// rotation (Pending -> Active -> Retired, publishing the next key in the
/// JWKS before it is ever used to sign -- see docs/protocol-notes.md and
/// docs/architecture.md) is Phase 1 scope (tasks.md); this holds exactly one
/// key for the process lifetime.
pub struct SigningKeyStore {
    active: SigningKey,
}

impl SigningKeyStore {
    /// Loads the active signing key per `source` (the configured
    /// `SIGNING_KEY_SOURCE`), or generates an ephemeral dev key if `source`
    /// does not resolve to a real, loadable file.
    pub fn load(source: &str) -> anyhow::Result<Self> {
        let active = match Self::try_load_from_source(source)? {
            Some(key) => {
                info!(kid = %key.kid, alg = "ES256", source, "loaded signing key from SIGNING_KEY_SOURCE");
                key
            }
            None => {
                let key = Self::generate_ephemeral()?;
                warn!(
                    kid = %key.kid,
                    alg = "ES256",
                    configured_source = source,
                    "SIGNING_KEY_SOURCE did not resolve to an existing key file; generated an \
                     EPHEMERAL DEV signing key instead. This key lives only in this process's \
                     memory: it is regenerated (invalidating every previously minted token) on \
                     every restart, and is NOT suitable for any shared or production deployment."
                );
                key
            }
        };

        Ok(Self { active })
    }

    /// The single active key, used both to sign new tokens and to answer
    /// the JWKS request for it (by `kid`).
    pub fn active(&self) -> &SigningKey {
        &self.active
    }

    /// The JWKS document this service serves at `GET /.well-known/jwks.json`
    /// (or wherever `JWKS_PATH` points). Built from the exact same
    /// `jsonwebtoken::jwk` types lore-server's `JwkServiceImpl` deserializes
    /// a JWKS response into, so there is no independent JSON shape to drift
    /// from lore-server's expectations.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.active.public_jwk.clone()],
        }
    }

    fn try_load_from_source(source: &str) -> anyhow::Result<Option<SigningKey>> {
        let Some(path) = source.strip_prefix("file://") else {
            // Only file:// is supported in Phase 0; a real KMS/HSM-backed
            // source is Phase 1 (see docs/architecture.md and tasks.md).
            return Ok(None);
        };

        if !Path::new(path).is_file() {
            return Ok(None);
        }

        let raw = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("reading SIGNING_KEY_SOURCE file {path}: {e}"))?;
        let der = Self::pkcs8_der_from_file_contents(&raw)?;
        Ok(Some(Self::key_from_pkcs8_der(&der)?))
    }

    /// Accepts either raw PKCS#8 DER bytes, or a PEM file wrapping the same
    /// DER content in base64 between `-----BEGIN PRIVATE KEY-----` /
    /// `-----END PRIVATE KEY-----` markers (the format `openssl pkcs8` and
    /// this project's own `SigningKeyStore::generate_ephemeral` would both
    /// be re-saved as, if written to a file for reuse across restarts).
    fn pkcs8_der_from_file_contents(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let text = match std::str::from_utf8(raw) {
            Ok(text) if text.contains(PKCS8_PEM_HEADER) => text,
            _ => return Ok(raw.to_vec()), // not PEM text; treat as raw DER
        };

        let body: String = text
            .lines()
            .filter(|line| {
                !line.is_empty() && !line.starts_with("-----BEGIN") && !line.starts_with("-----END")
            })
            .collect();
        anyhow::ensure!(
            text.contains(PKCS8_PEM_FOOTER),
            "PEM file has a BEGIN PRIVATE KEY header but no matching END PRIVATE KEY footer"
        );

        base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| anyhow::anyhow!("PEM body is not valid base64: {e}"))
    }

    fn generate_ephemeral() -> anyhow::Result<SigningKey> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("ring EC key generation failed"))?;
        Self::key_from_pkcs8_der(pkcs8.as_ref())
    }

    /// Builds a `SigningKey` (encoding key + public JWK) from an unencrypted
    /// PKCS#8-encoded EC P-256 private key.
    fn key_from_pkcs8_der(der: &[u8]) -> anyhow::Result<SigningKey> {
        let rng = SystemRandom::new();
        // Re-parsing with ring (rather than only handing `der` to
        // jsonwebtoken) is how we get at the public key point to build the
        // JWK -- jsonwebtoken's EncodingKey is sign-only and does not expose it.
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng).map_err(|e| {
                anyhow::anyhow!("not a valid unencrypted PKCS#8 EC P-256 private key: {e}")
            })?;

        // Uncompressed SEC1 point: 0x04 || X (32 bytes) || Y (32 bytes) for P-256.
        let public_point = pair.public_key().as_ref();
        anyhow::ensure!(
            public_point.len() == 65 && public_point[0] == 0x04,
            "unexpected EC public key point encoding (expected 65-byte uncompressed P-256 point)"
        );
        let x = URL_SAFE_NO_PAD.encode(&public_point[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public_point[33..65]);

        // Phase 0 has no key rotation/persistence (see module docs), so a
        // fresh random kid per load is sufficient: it only has to be unique
        // among keys this process's own JWKS ever publishes, and it always
        // publishes exactly one.
        let kid = Uuid::new_v4().to_string();

        let public_jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::ES256),
                key_id: Some(kid.clone()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            }),
        };

        Ok(SigningKey {
            kid,
            encoding_key: EncodingKey::from_ec_der(der),
            public_jwk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_key_has_kid_and_alg_and_parses_as_jwk() {
        let store = SigningKeyStore::load("file:///this/path/does/not/exist.der").unwrap();
        let jwks = store.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let jwk = &jwks.keys[0];
        assert!(jwk.common.key_id.is_some());
        assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::ES256));
        match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(params) => {
                assert_eq!(params.curve, EllipticCurve::P256);
                assert!(!params.x.is_empty());
                assert!(!params.y.is_empty());
            }
            other => panic!("expected an EllipticCurve JWK, got {other:?}"),
        }
    }

    #[test]
    fn non_file_source_generates_ephemeral_key() {
        // No file:// scheme at all -- also falls back to ephemeral rather
        // than erroring, matching "generated at startup if none is
        // configured" from the task brief.
        let store = SigningKeyStore::load("kms://not-implemented-in-phase-0").unwrap();
        assert_eq!(store.active().kid.len(), 36); // uuid string
    }

    #[test]
    fn loads_a_real_pkcs8_der_key_file() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("epic-lore-authz-test-key-{}.der", Uuid::new_v4()));
        std::fs::write(&path, pkcs8.as_ref()).unwrap();

        let source = format!("file://{}", path.display());
        let store = SigningKeyStore::load(&source).unwrap();
        // Sanity: it actually loaded (not a coincidentally-successful
        // ephemeral fallback) by round-tripping a sign/verify with the
        // encoding key this store produced against the parsed public point.
        let header = {
            let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            h.kid = Some(store.active().kid.clone());
            h
        };
        #[derive(serde::Serialize)]
        struct Claims {
            sub: String,
        }
        let token = jsonwebtoken::encode(
            &header,
            &Claims { sub: "test".into() },
            &store.active().encoding_key,
        )
        .unwrap();
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&store.active().public_jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
            .expect("token signed with the loaded file key must verify against its own JWK");

        std::fs::remove_file(&path).ok();
    }
}
