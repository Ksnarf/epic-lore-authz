//! The three secret-handling primitives this crate needs in more than one
//! place: generating a high-entropy token, hashing one for storage, and
//! comparing one without a timing side channel.
//!
//! These live in their own module rather than being duplicated per call site
//! deliberately. `crate::service_auth` (the `RebacApi` shared-secret gate)
//! and `crate::sessions` (login session codes) both need constant-time
//! comparison; a security primitive with two copies is a security primitive
//! with two chances to be fixed only once.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::SHA256;
use ring::digest::digest;
use ring::rand::SecureRandom as _;
use ring::rand::SystemRandom;

/// Bytes of CSPRNG entropy behind every generated token. 32 bytes = 256
/// bits, comfortably above the >=128 bits `lore_authz_core::model::
/// AuthSession`'s doc comment requires of a `session_code`, and enough that
/// the birthday bound is irrelevant no matter how many sessions exist.
const TOKEN_ENTROPY_BYTES: usize = 32;

/// A fresh, cryptographically random, URL-safe token: 32 CSPRNG bytes
/// rendered as 43 unpadded base64url characters.
///
/// URL-safe matters concretely here: these values end up in a URL path
/// (`/login/{login_code}`) and in query parameters (the OIDC `state` /
/// `nonce`), where anything needing percent-encoding is a latent
/// double-encoding bug.
///
/// Fails rather than falling back to a weaker source if the system CSPRNG
/// is unavailable -- there is no acceptable degraded mode for this.
pub fn random_url_safe_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// SHA-256 of `value`, base64url-encoded. Used to store a token's
/// FINGERPRINT rather than the token itself, so a database read does not
/// hand out usable credentials.
///
/// No salt and no password-hashing KDF, on purpose: these inputs are 256-bit
/// CSPRNG values, not user-chosen passwords, so there is no dictionary to
/// pre-compute and nothing for a salt or a work factor to defend against.
/// A KDF here would only add latency to every poll.
pub fn sha256_b64url(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()).as_ref())
}

/// Constant-time byte comparison: length is checked up front (not secret --
/// leaking it does not help an attacker guess the token), then every byte
/// pair is compared with no early exit, so a byte-by-byte early-return
/// comparison (`==` on `&str`/`&[u8]`, which DOES short-circuit) cannot leak
/// how many leading bytes of the secret an attacker has guessed correctly
/// via a timing side channel.
///
/// This project already pins `ring` (see workspace `Cargo.toml`) and `ring`
/// does expose `constant_time::verify_slices_are_equal`, but that function
/// is `#[deprecated]` as of the pinned version ("Internal function not
/// intended for external use with no promises regarding side channels") --
/// using it would both fail `cargo clippy -D warnings` and rely on an API
/// its own docs say not to depend on. A small hand-rolled XOR-accumulate
/// comparison is the standard, dependency-free way to do this instead.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_43_char_base64url_and_never_repeat() {
        let a = random_url_safe_token().unwrap();
        let b = random_url_safe_token().unwrap();
        assert_eq!(a.len(), 43, "32 CSPRNG bytes as unpadded base64url");
        assert_ne!(a, b, "a CSPRNG must not hand back the same token twice");
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "must be safe in a URL path and query string with no escaping"
        );
    }

    #[test]
    fn hashing_is_deterministic_and_does_not_reveal_the_input() {
        let token = random_url_safe_token().unwrap();
        assert_eq!(sha256_b64url(&token), sha256_b64url(&token));
        assert_ne!(sha256_b64url(&token), token);
        assert_ne!(sha256_b64url("a"), sha256_b64url("b"));
        assert_eq!(sha256_b64url("").len(), 43);
    }

    #[test]
    fn constant_time_eq_matches_plain_equality_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(constant_time_eq(b"", b""));
    }
}
