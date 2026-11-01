use jsonwebtoken::{EncodingKey, Header};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use serde::Serialize;

use crate::config::{KeyConfig, KeyKind};
use crate::crypto::b64url;
use crate::error::OAuthError;

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    kid: String,
    kty: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    n: String,
    e: String,
}

/// Parsed signing material, built once at startup.
pub struct Keys {
    encoding_key: EncodingKey,
    header: Header,
    jwks: Vec<Jwk>,
}

fn encode_uint(value: &BigUint) -> String {
    b64url(&value.to_bytes_be())
}

impl Keys {
    /// Every configured key is published in the JWKS, the first active one signs.
    pub fn from_config(keys: &[KeyConfig]) -> Result<Keys, String> {
        let mut jwks = Vec::new();
        for key in keys {
            let KeyKind::PemRs256 = key.kind;
            let private = RsaPrivateKey::from_pkcs8_pem(&key.key)
                .map_err(|e| format!("key `{}` is not a valid PKCS#8 PEM RSA key: {e}", key.kid))?;
            jwks.push(Jwk {
                kid: key.kid.clone(),
                kty: "RSA",
                alg: "RS256",
                use_: "sig",
                n: encode_uint(private.n()),
                e: encode_uint(private.e()),
            });
        }
        let active = keys
            .iter()
            .find(|k| k.active)
            .ok_or("no key is marked `active = true`")?;
        let encoding_key = EncodingKey::from_rsa_pem(active.key.as_bytes())
            .map_err(|e| format!("key `{}` cannot be used for signing: {e}", active.kid))?;
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(active.kid.clone());
        Ok(Keys {
            encoding_key,
            header,
            jwks,
        })
    }

    pub fn jwks(&self) -> &[Jwk] {
        &self.jwks
    }

    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, OAuthError> {
        jsonwebtoken::encode(&self.header, claims, &self.encoding_key)
            .map_err(|e| OAuthError::server_error(format!("failed to sign token: {e}")))
    }
}
