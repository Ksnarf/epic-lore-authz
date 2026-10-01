//! DEV-ONLY token minting CLI, used by the Phase 0 integration test to hand
//! a real `lore-server` tokens signed by the same key this sidecar publishes
//! at `/.well-known/jwks.json`.
//!
//! THIS IS NOT A PRODUCTION SURFACE. It reads the private signing key
//! directly off disk and will mint any claims asked of it, with no
//! authentication and no policy check. It must never be copied into a runtime
//! image alongside `lore-authz-server`. It fails closed: it refuses to do
//! anything at all unless `LORE_AUTHZ_DEV_MINT=1` is set in the environment.
//!
//! ## Why a `--kid` argument exists
//! `signing::SigningKeyStore::load` assigns a fresh random `kid` on every
//! load (see the "Phase 0 has no key rotation/persistence" comment in
//! `signing.rs`), so this process loading the same key FILE as the running
//! server still ends up with a DIFFERENT `kid` than the one the server
//! publishes. lore-server looks keys up strictly by `kid`
//! (`lore-server/src/auth/jwk.rs::get_key`), so the caller must pass the
//! `kid` read out of the running server's live JWKS document. See
//! `docs/open-questions.md` Q14 and `docs/protocol-notes.md` #7e for the
//! multi-replica bug this same behaviour would cause in a real deployment.
//!
//! ## Shapes
//! - `authz`         -- full `AuthzClaims`, `resources` + `idp` present.
//! - `authn`         -- `AuthnClaims`, no `resources`, no `idp`.
//! - `authz-no-idp`  -- hand-built claims JSON: every AuthZ field INCLUDING
//!   `resources` but with `idp` omitted. This is the shape
//!   `tests/lore_compat.rs` proves decodes as `JWTUserInfo` (dropping
//!   `resources`) rather than erroring; this binary exists so that failure
//!   mode can be observed against a real running server rather than only
//!   against vendored structs.

use std::process::ExitCode;

use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use lore_authz_core::claims::ResourcePermission;
use lore_authz_server::minting::AuthnTokenInput;
use lore_authz_server::minting::AuthzTokenInput;
use lore_authz_server::minting::mint_authn_token;
use lore_authz_server::minting::mint_authz_token;
use lore_authz_server::signing::SigningKeyStore;

const USAGE: &str = "\
dev-mint-token (DEV ONLY -- requires LORE_AUTHZ_DEV_MINT=1)

  --shape <authz|authn|authz-no-idp>   default: authz
  --kid <kid>                          kid to stamp in the JWT header;
                                       default: this process's own loaded key
  --resource <resource_id>             repeatable, default: urc-*
  --ttl-secs <n>                       default: 3600
  --sub <subject>                      default: dev-user-1
  --idp <idp>                          default: dev-idp
  --wrong-key                          sign with a freshly generated key that
                                       is NOT in the published JWKS (negative
                                       test); the --kid stamped in the header
                                       is unchanged, so lore-server still
                                       finds A key and the SIGNATURE is what
                                       fails

Reads JWT_ISSUER, JWT_AUDIENCE (comma separated), TOKEN_ENV and
SIGNING_KEY_SOURCE from the environment, exactly like the server does.
Prints the encoded JWT to stdout and nothing else.
";

struct Args {
    shape: String,
    kid: Option<String>,
    resources: Vec<String>,
    ttl_secs: u64,
    sub: String,
    idp: String,
    wrong_key: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        shape: "authz".to_string(),
        kid: None,
        resources: Vec::new(),
        ttl_secs: 3600,
        sub: "dev-user-1".to_string(),
        idp: "dev-idp".to_string(),
        wrong_key: false,
    };

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        let mut value = || argv.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--shape" => args.shape = value()?,
            "--kid" => args.kid = Some(value()?),
            "--resource" => args.resources.push(value()?),
            "--ttl-secs" => {
                args.ttl_secs = value()?.parse().map_err(|e| format!("--ttl-secs: {e}"))?
            }
            "--sub" => args.sub = value()?,
            "--idp" => args.idp = value()?,
            "--wrong-key" => args.wrong_key = true,
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    if args.resources.is_empty() {
        args.resources.push("urc-*".to_string());
    }
    Ok(args)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn run() -> Result<String, String> {
    if std::env::var("LORE_AUTHZ_DEV_MINT").as_deref() != Ok("1") {
        return Err(
            "refusing to run: this is a DEV-ONLY minting tool and requires \
             LORE_AUTHZ_DEV_MINT=1"
                .to_string(),
        );
    }

    let args = parse_args()?;

    let issuer = env_or("JWT_ISSUER", "https://authz.example.com");
    let audience: Vec<String> = env_or("JWT_AUDIENCE", "lore.example.com")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let token_env = env_or("TOKEN_ENV", "dev");

    // `--wrong-key` deliberately points the loader at a path that cannot
    // exist, which makes `SigningKeyStore::load` generate a fresh ephemeral
    // key -- a key that is by construction NOT the one the running server
    // publishes in its JWKS.
    let source = if args.wrong_key {
        "file:///nonexistent/wrong-key-for-negative-test.der".to_string()
    } else {
        env_or("SIGNING_KEY_SOURCE", "file:///CHANGE_ME/signing-key.der")
    };
    let store = SigningKeyStore::load(&source).map_err(|e| format!("loading signing key: {e}"))?;
    let signing_key = store.active();
    let kid = args.kid.clone().unwrap_or_else(|| signing_key.kid.clone());

    let resources: Vec<ResourcePermission> = args
        .resources
        .iter()
        .map(|resource_id| ResourcePermission {
            resource_id: resource_id.clone(),
            permission: vec!["read".to_string(), "write".to_string()],
        })
        .collect();

    let token = match args.shape.as_str() {
        "authz" => {
            mint_authz_token(
                signing_key,
                &issuer,
                &audience,
                &token_env,
                args.ttl_secs,
                &AuthzTokenInput {
                    user_id: args.sub.clone(),
                    name: "Dev User".to_string(),
                    preferred_username: "devuser".to_string(),
                    is_service_account: false,
                    idp: args.idp.clone(),
                    groups: None,
                    resources,
                },
            )
            .map_err(|e| format!("minting authz token: {e}"))?
            .token
        }
        "authn" => {
            mint_authn_token(
                signing_key,
                &issuer,
                &audience,
                &token_env,
                args.ttl_secs,
                &AuthnTokenInput {
                    user_id: args.sub.clone(),
                    name: "Dev User".to_string(),
                    preferred_username: "devuser".to_string(),
                    is_service_account: false,
                    groups: None,
                },
            )
            .map_err(|e| format!("minting authn token: {e}"))?
            .token
        }
        // Hand-built because `mint_authz_token` structurally cannot produce
        // this shape: `AuthzTokenInput::idp` is a mandatory `String`. That is
        // the point -- see minting.rs's module doc.
        "authz-no-idp" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock: {e}"))?
                .as_secs();
            let claims = serde_json::json!({
                "sub": args.sub,
                "iss": issuer,
                "iat": now,
                "exp": now + args.ttl_secs,
                "aud": audience,
                "env": token_env,
                "name": "Dev User",
                "preferred_username": "devuser",
                "resources": resources,
                "groups": serde_json::Value::Null,
                "is_service_account": false,
                // "idp" deliberately absent
            });
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(kid.clone());
            return encode(&header, &claims, &signing_key.encoding_key)
                .map_err(|e| format!("minting authz-no-idp token: {e}"));
        }
        other => return Err(format!("unknown --shape: {other}\n\n{USAGE}")),
    };

    // mint_* stamp the loaded store's own kid; re-stamp with the caller's
    // kid by re-signing the same payload rather than string-splicing the
    // header (which would invalidate the signature).
    restamp_kid(&token, &kid, signing_key)
}

/// Re-encodes an already-minted token's payload under a caller-supplied
/// `kid`. Decodes the payload as an untyped `serde_json::Value` so no claim
/// is lost or reordered into a different shape than the minting functions
/// produced.
fn restamp_kid(
    token: &str,
    kid: &str,
    signing_key: &lore_authz_server::signing::SigningKey,
) -> Result<String, String> {
    use base64::Engine as _;

    let payload_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| "minted token is not a well-formed JWT".to_string())?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("decoding minted payload: {e}"))?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|e| format!("parsing minted payload: {e}"))?;

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, &signing_key.encoding_key).map_err(|e| format!("re-encoding: {e}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
