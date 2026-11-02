use std::collections::HashSet;
use std::time::Duration;

use serde_json::{Map, Value};
use uuid::Uuid;

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

/// What placeholders in configured claims are filled from.
pub struct ClaimContext<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub user: &'a User,
    pub scopes: &'a [String],
}

/// Fills placeholders in a configured claim value. A string that is exactly `{scopes}` becomes
/// the granted scopes as an array. In other strings `{client_id}`, `{user_id}`, `{email}`,
/// `{name}`, `{issuer}` and `{scope}` (space-separated scopes) are replaced.
pub fn expand(value: &Value, ctx: &ClaimContext) -> Value {
    match value {
        Value::String(s) if s == "{scopes}" => ctx.scopes.to_vec().into(),
        Value::String(s) => s
            .replace("{client_id}", ctx.client_id)
            .replace("{user_id}", &ctx.user.id)
            .replace("{email}", &ctx.user.email)
            .replace("{name}", &ctx.user.name)
            .replace("{issuer}", ctx.issuer)
            .replace("{scope}", &ctx.scopes.join(" "))
            .into(),
        Value::Array(items) => items.iter().map(|v| expand(v, ctx)).collect(),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| (k.clone(), expand(v, ctx)))
            .collect::<Map<_, _>>()
            .into(),
        other => other.clone(),
    }
}

fn expand_all(claims: &Map<String, Value>, ctx: &ClaimContext) -> Map<String, Value> {
    claims.iter().map(|(k, v)| (k.clone(), expand(v, ctx))).collect()
}

/// JWT access token payload. Configured claims may set `sub` and `aud`, but not `iss`,
/// `iat`, `exp` or `jti`.
pub fn access_token_claims(config: &Config, ctx: &ClaimContext, ttl: Duration) -> Map<String, Value> {
    let iat = now();
    let mut claims = match &config.tokens.access_claims {
        Some(template) => expand_all(template, ctx),
        None => {
            let mut claims = Map::new();
            claims.insert("sub".into(), ctx.user.id.clone().into());
            claims.insert("aud".into(), ctx.client_id.into());
            claims.insert("client_id".into(), ctx.client_id.into());
            claims.insert("scope".into(), ctx.scopes.join(" ").into());
            claims
        }
    };
    claims.insert("iss".into(), ctx.issuer.into());
    claims.insert("iat".into(), iat.into());
    claims.insert("exp".into(), (iat + ttl.as_secs() as i64).into());
    claims.insert("jti".into(), Uuid::new_v4().to_string().into());
    claims
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
    let ctx = ClaimContext {
        issuer: input.issuer,
        client_id: input.client_id,
        user: input.user,
        scopes: input.scopes,
    };
    claims.extend(expand_all(&config.tokens.id_claims, &ctx));
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
