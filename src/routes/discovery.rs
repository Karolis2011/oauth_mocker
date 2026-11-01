use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use serde_json::{Value, json};

use crate::app::AppState;
use crate::error::render;
use crate::templates::{ClientView, IndexTemplate, PageCtx};
use crate::util::issuer;

pub async fn index(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let issuer = issuer(&app.config, &headers);
    let endpoints = vec![
        ("Discovery", format!("{issuer}/.well-known/openid-configuration")),
        ("JWKS", format!("{issuer}/.well-known/jwks.json")),
        ("Authorization", format!("{issuer}/oauth2/authorize")),
        ("Token", format!("{issuer}/oauth2/token")),
        ("UserInfo", format!("{issuer}/userinfo")),
        ("Users", format!("{issuer}/users")),
    ];
    let clients = app
        .config
        .clients
        .iter()
        .map(|c| ClientView {
            id: c.client_id.clone(),
            name: c.display_name().to_string(),
            public: c.is_public(),
        })
        .collect();
    render(&IndexTemplate {
        page: PageCtx::new(&app.config),
        issuer,
        endpoints,
        clients,
        user_count: app.config.users.len(),
    })
}

pub async fn users(State(app): State<AppState>) -> Json<Value> {
    Json(json!(app.config.users))
}

pub async fn openid_config(State(app): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let issuer = issuer(&app.config, &headers);
    let mut scopes: Vec<&String> = app.config.scope_map.keys().collect();
    scopes.sort();
    let mut claims: Vec<&str> = vec!["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash"];
    claims.extend(
        app.config
            .scope_map
            .values()
            .flatten()
            .map(String::as_str),
    );
    claims.sort();
    claims.dedup();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": scopes,
        "claims_supported": claims,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
    }))
}

pub async fn jwks(State(app): State<AppState>) -> Json<Value> {
    Json(json!({ "keys": app.keys.jwks() }))
}
