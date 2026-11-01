use std::collections::HashSet;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::config::{Config, User};
use crate::crypto::at_hash;
use crate::util::now;

/// Splits a space-delimited scope string, dropping duplicates and keeping order.
pub fn parse_scopes(scope: &str) -> Vec<String> {
    let mut scopes: Vec<String> = Vec::new();
    for scope in scope.split_whitespace() {
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_string());
        }
    }
    scopes
}

/// The claims `user` releases for `scopes`.
///
/// A claim named by at least one scope is released only when one of those scopes
/// is granted. A claim named by no scope is always released.
pub fn user_claims(config: &Config, user: &User, scopes: &[String]) -> Map<String, Value> {
    let scoped: HashSet<&str> = config
        .scope_map
        .values()
        .flatten()
        .map(String::as_str)
        .collect();
    let granted: HashSet<&str> = scopes
        .iter()
        .filter_map(|scope| config.scope_map.get(scope))
        .flatten()
        .map(String::as_str)
        .collect();
    user.all_claims()
        .into_iter()
        .filter(|(name, _)| granted.contains(name.as_str()) || !scoped.contains(name.as_str()))
        .collect()
}

pub struct IdTokenInput<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub user: &'a User,
    pub scopes: &'a [String],
    pub nonce: Option<&'a str>,
    pub auth_time: i64,
    pub access_token: &'a str,
    pub ttl: Duration,
}

/// ID token payload. Registered claims are inserted last so user claims cannot override them.
pub fn id_token_claims(config: &Config, input: &IdTokenInput) -> Map<String, Value> {
    let iat = now();
    let mut claims = user_claims(config, input.user, input.scopes);
    claims.insert("iss".into(), input.issuer.into());
    claims.insert("sub".into(), input.user.id.clone().into());
    claims.insert("aud".into(), input.client_id.into());
    claims.insert("iat".into(), iat.into());
    claims.insert("exp".into(), (iat + input.ttl.as_secs() as i64).into());
    claims.insert("auth_time".into(), input.auth_time.into());
    claims.insert("at_hash".into(), at_hash(input.access_token).into());
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".into(), nonce.into());
    }
    claims
}
