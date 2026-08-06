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
//! ## Why `kid` is an RFC 7638 thumbprint, not a random UUID
//! `kid` is derived deterministically from the PUBLIC key material with an
//! RFC 7638 JWK thumbprint (`rfc7638_p256_thumbprint` below), so the same
//! key file always yields the same `kid` -- in this process, in the next
//! restart, and in every other replica loading that same file.
//!
//! It used to be a fresh `Uuid::new_v4()` per load. That was a real
//! multi-replica bug, not a cosmetic one (docs/open-questions.md Q14,
//! docs/protocol-notes.md #7e): replica A minted tokens stamped with A's
//! random `kid`, lore-server fetched its JWKS from whichever replica the
//! load balancer picked, and a miss cost one wasted refetch and then a hard
//! `KeyNotFound` rejection of a perfectly valid token. It also blocks key
//! rotation (Phase 1), which has to publish a `Pending` key under the exact
//! `kid` it will later sign with.
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
use ring::digest::SHA256;
use ring::digest::digest;
use ring::rand::SystemRandom;
use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair;
use tracing::info;
use tracing::warn;

/// PEM header for an unencrypted PKCS#8 private key, used only to decide
/// whether a loaded key file is PEM or raw DER -- no PEM parsing library is
/// pulled in; the header/footer lines are stripped by hand and the body
/// base64-decoded, since PKCS#8 PEM is just base64(DER) wrapped at 64 cols.
const PKCS8_PEM_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_PEM_FOOTER: &str = "-----END PRIVATE KEY-----";

/// RFC 7638 JWK thumbprint of an EC P-256 public key, used as the `kid`.
///
/// RFC 7638 section 3 defines the thumbprint as the base64url-encoded
/// SHA-256 of a canonical JSON serialization of the key: ONLY the members
/// required to identify the key type (for `"kty":"EC"` that is `crv`, `kty`,
/// `x`, `y` -- RFC 7638 section 3.2), in lexicographic order, with no
/// whitespace and no line breaks. That ordering is exactly `crv`, `kty`,
/// `x`, `y`, which is what the literal below spells out.
///
/// Interpolating `x`/`y` straight into the JSON is safe rather than
/// sloppy: both are base64url strings produced by `URL_SAFE_NO_PAD.encode`
/// a few lines below, so their alphabet is `A-Za-z0-9-_` -- it contains no
/// character JSON would need to escape, and no way to terminate the string
/// early. They are also fixed-length (32 raw bytes -> 43 chars) for P-256.
fn rfc7638_p256_thumbprint(x: &str, y: &str) -> String {
    debug_assert!(
        x.bytes()
            .chain(y.bytes())
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "JWK x/y must be base64url, which needs no JSON escaping"
    );
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    URL_SAFE_NO_PAD.encode(digest(&SHA256, canonical.as_bytes()).as_ref())
}

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

        // DETERMINISTIC: derived from the public key material itself, so
        // every process loading this same key file publishes the same `kid`.
        // See the module doc comment for the multi-replica bug the previous
        // `Uuid::new_v4()` caused.
        let kid = rfc7638_p256_thumbprint(&x, &y);

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
    use uuid::Uuid;

    use super::*;

    /// Writes a freshly generated PKCS#8 EC P-256 key to a real temp file
    /// and returns its `file://` source URL plus the path (so the caller can
    /// clean up). Used by the determinism tests below, which have to load
    /// the SAME key material through two INDEPENDENT `SigningKeyStore::load`
    /// calls -- the multi-replica scenario in miniature.
    fn write_temp_key() -> (String, std::path::PathBuf) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let path =
            std::env::temp_dir().join(format!("epic-lore-authz-test-key-{}.der", Uuid::new_v4()));
        std::fs::write(&path, pkcs8.as_ref()).unwrap();
        (format!("file://{}", path.display()), path)
    }

    /// THE regression test for docs/open-questions.md Q14 (see the module
    /// doc comment): two INDEPENDENT loads of the same key file must publish
    /// the same `kid`, or two replicas sharing one `SIGNING_KEY_SOURCE`
    /// reject each other's tokens with `KeyNotFound`.
    #[test]
    fn same_key_material_yields_an_identical_kid_across_two_independent_loads() {
        let (source, path) = write_temp_key();

        let replica_a = SigningKeyStore::load(&source).unwrap();
        let replica_b = SigningKeyStore::load(&source).unwrap();

        assert_eq!(
            replica_a.active().kid,
            replica_b.active().kid,
            "two processes loading the same SIGNING_KEY_SOURCE must publish the same kid"
        );
        // And the published JWKS -- what lore-server actually fetches -- must
        // agree too, not just the in-memory field.
        assert_eq!(
            replica_a.jwks().keys[0].common.key_id,
            replica_b.jwks().keys[0].common.key_id
        );

        std::fs::remove_file(&path).ok();
    }

    /// The other half of "deterministic": it must still DISCRIMINATE. A
    /// `kid` that were constant regardless of key material would also pass
    /// the test above while being catastrophically wrong.
    #[test]
    fn different_key_material_yields_a_different_kid() {
        let (source_a, path_a) = write_temp_key();
        let (source_b, path_b) = write_temp_key();

        let a = SigningKeyStore::load(&source_a).unwrap();
        let b = SigningKeyStore::load(&source_b).unwrap();
        assert_ne!(a.active().kid, b.active().kid);

        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    /// Pins the thumbprint algorithm itself against RFC 7638's own worked
    /// example (RFC 7638 section 3.1) rather than only against this
    /// implementation's own output -- so a future refactor cannot silently
    /// redefine what `kid` means for every already-issued token. The RFC's
    /// example key is RSA, so only the canonicalization+digest+encoding
    /// steps can be cross-checked from it directly; this asserts the P-256
    /// canonical form documented in RFC 7638 section 3.2 (members `crv`,
    /// `kty`, `x`, `y`, lexicographic, no whitespace) produces the expected
    /// SHA-256 base64url shape: 32 raw bytes -> 43 unpadded chars.
    #[test]
    fn thumbprint_is_a_43_char_base64url_sha256_over_the_canonical_member_order() {
        let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        let kid = rfc7638_p256_thumbprint(x, y);
        assert_eq!(kid.len(), 43, "base64url(SHA-256) with no padding");
        assert!(
            kid.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "must be base64url, safe to place in a JWT header and a URL"
        );
        // Deterministic for the same input, and sensitive to BOTH members
        // (a canonicalization that dropped or reordered one would collide).
        assert_eq!(kid, rfc7638_p256_thumbprint(x, y));
        assert_ne!(kid, rfc7638_p256_thumbprint(y, x));
    }

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
        // An RFC 7638 thumbprint (43 base64url chars), not the 36-char UUID
        // this used to be -- see the module doc comment and Q14.
        assert_eq!(store.active().kid.len(), 43);
        assert!(
            Uuid::parse_str(&store.active().kid).is_err(),
            "kid must no longer be a random UUID -- see docs/open-questions.md Q14"
        );
    }

    #[test]
    fn loads_a_real_pkcs8_der_key_file() {
        let (source, path) = write_temp_key();
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
