use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::response::Response;

use crate::app::AppState;
use crate::claims::user_claims;
use crate::error::OAuthError;
use crate::util::no_store;

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
}

/// RFC 6750 section 2.2: `access_token` in a form-encoded request body.
fn form_token(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let is_form = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return None;
    }
    url::form_urlencoded::parse(body)
        .find(|(key, value)| key == "access_token" && !value.is_empty())
        .map(|(_, value)| value.into_owned())
}

pub async fn userinfo(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, OAuthError> {
    let token = bearer_token(&headers)
        .map(String::from)
        .or_else(|| form_token(&headers, &body))
        .ok_or_else(|| OAuthError::invalid_token("A bearer access token is required"))?;
    let grant = app
        .stores
        .access_tokens
        .get(&token)
        .ok_or_else(|| OAuthError::invalid_token("Invalid or expired access token"))?;

    if let Some(client) = app.config.client(&grant.client_id)
        && let Some(code) = &client.simulate.userinfo_error {
            return Err(OAuthError::simulated(code));
        }
    if !grant.scopes.iter().any(|s| s == "openid") {
        return Err(OAuthError::insufficient_scope(
            "The access token was not issued for the openid scope",
        ));
    }

    let user = app
        .config
        .user(&grant.user_id)
        .ok_or_else(|| OAuthError::server_error("The user no longer exists"))?;
    let mut claims = user_claims(&app.config, user, &grant.scopes);
    claims.insert("sub".into(), user.id.clone().into());
    Ok(no_store(Json(claims)))
}
