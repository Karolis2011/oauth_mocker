use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use serde_json::{Value, json};

use crate::app::AppState;
use crate::error::render;
use crate::templates::{ClientView, IndexTemplate, PageCtx};
use crate::util::{base_url, issuer};

pub async fn index(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let config = &app.config;
    let base = base_url(config, &headers);
    let paths = &config.endpoints;
    let endpoints = vec![
        ("Discovery", format!("{base}{}", config.discovery_path())),
        ("JWKS", format!("{base}{}", paths.jwks)),
        ("Authorization", format!("{base}{}", paths.authorize)),
        ("Token", format!("{base}{}", paths.token)),
        ("UserInfo", format!("{base}{}", paths.userinfo)),
        ("Users", format!("{base}/users")),
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
        issuer: issuer(config, &headers),
        preset: config.preset.clone(),
        endpoints,
        clients,
        user_count: app.config.users.len(),
    })
}

pub async fn users(State(app): State<AppState>) -> Json<Value> {
    Json(json!(app.config.users))
}

pub async fn openid_config(State(app): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let config = &app.config;
    let base = base_url(config, &headers);
    let paths = &config.endpoints;
    let mut scopes: Vec<&String> = config.scope_map.keys().collect();
    scopes.sort();
    let mut claims: Vec<&str> = vec!["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash"];
    claims.extend(config.scope_map.values().flatten().map(String::as_str));
    claims.extend(config.tokens.id_claims.keys().map(String::as_str));
    claims.sort();
    claims.dedup();
    Json(json!({
        "issuer": issuer(config, &headers),
        "authorization_endpoint": format!("{base}{}", paths.authorize),
        "token_endpoint": format!("{base}{}", paths.token),
        "userinfo_endpoint": format!("{base}{}", paths.userinfo),
        "jwks_uri": format!("{base}{}", paths.jwks),
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
