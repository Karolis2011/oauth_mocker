use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn b64url(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Opaque random token with a recognizable prefix, e.g. `at_3f2a…`.
pub fn new_token(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// `at_hash`: base64url of the left half of the SHA-256 of the access token.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    b64url(&digest[..digest.len() / 2])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    Plain,
    S256,
}

impl PkceMethod {
    pub fn parse(method: &str) -> Option<PkceMethod> {
        match method {
            "plain" => Some(PkceMethod::Plain),
            "S256" => Some(PkceMethod::S256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pkce {
    pub challenge: String,
    pub method: PkceMethod,
}

/// RFC 7636 section 4.1: 43 to 128 characters of `[A-Za-z0-9-._~]`.
pub fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

impl Pkce {
    pub fn verify(&self, verifier: &str) -> bool {
        match self.method {
            PkceMethod::Plain => self.challenge == verifier,
            PkceMethod::S256 => self.challenge == b64url(&Sha256::digest(verifier.as_bytes())),
        }
    }
}
