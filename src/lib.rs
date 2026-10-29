//! Fixtures and verifier wrappers for dudect timing tests of HS256 JWT
//! verification.
//!
//! Every wrapper takes a compact JWS string and returns `true` only if the
//! crate accepted the token. The timing classes are built so that both
//! classes are rejected by the same code path and differ only in the
//! position of the first wrong byte of the HMAC tag (last byte vs first
//! byte). An early-exit tag comparison makes the two classes take a
//! different time; a constant-time comparison does not.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Fixed 32-byte HMAC key used by all benches.
pub const KEY: &[u8; 32] = b"ct-verify-jwt fixed bench key 32";

/// Header of every token.
pub const HEADER_JSON: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// Which byte of the 32-byte tag is altered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flip {
    /// No alteration: the token is valid.
    None,
    /// First byte (index 0) altered: an early-exit compare stops at once.
    First,
    /// Last byte (index 31) altered: an early-exit compare scans 31 bytes.
    Last,
}

/// Compact JWS signing input for a payload with the given `sub`.
pub fn signing_input(sub: &str) -> String {
    let payload = serde_json::json!({
        "sub": sub,
        "iat": 1_700_000_000u64,
        "exp": 4_102_444_800u64,
    })
    .to_string();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER_JSON),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

/// HMAC-SHA256 tag of `input` under [`KEY`].
pub fn tag(input: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(KEY).expect("any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

/// Alter one byte of a tag.
pub fn flip(mut t: [u8; 32], f: Flip) -> [u8; 32] {
    match f {
        Flip::None => {}
        Flip::First => t[0] ^= 0x01,
        Flip::Last => t[31] ^= 0x01,
    }
    t
}

/// Full compact token for `sub` with the tag altered by `f`.
pub fn token(sub: &str, f: Flip) -> String {
    let si = signing_input(sub);
    let t = flip(tag(si.as_bytes()), f);
    format!("{}.{}", si, URL_SAFE_NO_PAD.encode(t))
}

/// jsonwebtoken (Keats), `decode` with `Validation::new(HS256)`.
pub fn verify_jsonwebtoken(tok: &str) -> bool {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    let key = DecodingKey::from_secret(KEY);
    let v = Validation::new(Algorithm::HS256);
    decode::<serde_json::Value>(tok, &key, &v).is_ok()
}

/// jwt-simple (jedisct1), `HS256Key::verify_token` with default options.
pub fn verify_jwt_simple(tok: &str) -> bool {
    use jwt_simple::prelude::*;
    let key = HS256Key::from_bytes(KEY);
    key.verify_token::<NoCustomClaims>(tok, None).is_ok()
}

/// jwt (mikkyang), `VerifyWithKey` with an `Hmac<Sha256>` key.
pub fn verify_jwt(tok: &str) -> bool {
    use jwt::VerifyWithKey;
    use std::collections::BTreeMap;
    let key = HmacSha256::new_from_slice(KEY).expect("any key length");
    let r: Result<BTreeMap<String, serde_json::Value>, _> = tok.verify_with_key(&key);
    r.is_ok()
}

fn split(tok: &str) -> Option<(&str, Vec<u8>)> {
    let (si, sig) = tok.rsplit_once('.')?;
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    Some((si, sig))
}

/// Positive control at JWT level: same parse + HMAC work, naive `==` on the tag.
pub fn verify_ctrl_naive_eq(tok: &str) -> bool {
    match split(tok) {
        Some((si, sig)) => tag(si.as_bytes())[..] == sig[..],
        None => false,
    }
}

/// Positive control at JWT level: same work, explicit early-exit byte loop.
pub fn verify_ctrl_early_exit(tok: &str) -> bool {
    match split(tok) {
        Some((si, sig)) => early_exit_eq(&tag(si.as_bytes()), &sig),
        None => false,
    }
}

/// Negative control at JWT level: same work, `subtle::ConstantTimeEq`.
pub fn verify_ctrl_subtle(tok: &str) -> bool {
    match split(tok) {
        Some((si, sig)) => bool::from(tag(si.as_bytes())[..].ct_eq(&sig[..])),
        None => false,
    }
}

/// Byte-by-byte comparison that returns at the first difference.
#[inline(never)]
pub fn early_exit_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if std::hint::black_box(a[i]) != std::hint::black_box(b[i]) {
            return false;
        }
    }
    true
}

/// One parsed dudect-bencher result line.
#[derive(Clone, Debug, PartialEq)]
pub struct BenchResult {
    pub name: String,
    pub n: f64,
    pub max_t: f64,
    pub max_tau: f64,
}

/// Threshold fixed in PREREGISTRO.md: |t| > 4.5 means a timing leak.
pub const T_THRESHOLD: f64 = 4.5;

/// Parse lines like
/// `bench crate_jwt ... : n == +0.100M, max t = +1.23, max tau = +0.0039, (5/tau)^2 = 1640000`.
pub fn parse_dudect(out: &str) -> Vec<BenchResult> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("bench ") else {
            continue;
        };
        let Some((name, stats)) = rest.split_once(" ... : ") else {
            continue;
        };
        let num = |key: &str| -> Option<f64> {
            let s = stats.split(key).nth(1)?;
            let s = s.trim_start();
            let end = s.find([',', ' ']).unwrap_or(s.len());
            let tok = &s[..end];
            let (tok, mult) = match tok.strip_suffix('M') {
                Some(t) => (t, 1e6),
                None => (tok, 1.0),
            };
            tok.parse::<f64>().ok().map(|x| x * mult)
        };
        if let (Some(n), Some(t), Some(tau)) = (num("n =="), num("max t ="), num("max tau =")) {
            v.push(BenchResult {
                name: name.trim().to_string(),
                n,
                max_t: t,
                max_tau: tau,
            });
        }
    }
    v
}

/// Verdict for one result under the pre-registered threshold.
pub fn leaks(r: &BenchResult) -> bool {
    r.max_t.abs() > T_THRESHOLD
}
