use std::time::Duration;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Response;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::claims::{ClaimContext, IdTokenInput, access_token_claims, id_token_claims, parse_scopes};
use crate::config::{AccessFormat, Client};
use crate::crypto::{is_valid_verifier, new_token};
use crate::error::OAuthError;
use crate::store::{AccessGrant, RefreshGrant};
use crate::util::{issuer, no_store};

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// What a token request was authorized for, whichever grant it came through.
struct Grant {
    user_id: String,
    /// Scopes of the tokens issued now, possibly narrowed by a refresh request.
    scopes: Vec<String>,
    /// Scopes the user originally granted, what a refresh token must keep.
    granted: Vec<String>,
    auth_time: i64,
    nonce: Option<String>,
    /// Whether a refresh token may be returned.
    refresh: bool,
}

pub async fn token(
    State(app): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(req) = form.map_err(|e| OAuthError::invalid_request(e.to_string()))?;
    let client = authenticate(&app, &headers, &req)?;

    // Reject malformed requests before simulating a failure, like a real server would.
    let grant_type = match req.grant_type.as_deref() {
        Some(grant_type @ ("authorization_code" | "refresh_token")) => grant_type,
        Some(other) => {
            return Err(OAuthError::unsupported_grant_type(format!(
                "grant_type `{other}` is not supported"
            )));
        }
        None => return Err(OAuthError::invalid_request("grant_type is required")),
    };
    match grant_type {
        "authorization_code" if req.code.is_none() => {
            return Err(OAuthError::invalid_request("code is required"));
        }
        "refresh_token" if req.refresh_token.is_none() => {
            return Err(OAuthError::invalid_request("refresh_token is required"));
        }
        _ => {}
    }

    if let Some(ms) = client.simulate.token_delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    let simulated = match grant_type {
        "refresh_token" => client
            .simulate
            .refresh_error
            .as_ref()
            .or(client.simulate.token_error.as_ref()),
        _ => client.simulate.token_error.as_ref(),
    };
    if let Some(code) = simulated {
        return Err(OAuthError::simulated(code));
    }

    let issuer = issuer(&app.config, &headers);
    let response = match grant_type {
        "authorization_code" => code_grant(&app, client, &req, &issuer)?,
        _ => refresh_grant(&app, client, &req, &issuer)?,
    };
    Ok(no_store(Json(response)))
}

/// Decodes one half of HTTP Basic credentials, which RFC 6749 says are form-urlencoded.
/// Decoded by hand so a raw `&` or `=` in a secret cannot be mistaken for form syntax.
fn decode_basic_part(part: &str) -> String {
    percent_encoding::percent_decode_str(&part.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let malformed = || OAuthError::invalid_client("malformed Basic credentials");
    let decoded = BASE64_STANDARD
        .decode(encoded.trim())
        .map_err(|_| malformed())?;
    let decoded = String::from_utf8(decoded).map_err(|_| malformed())?;
    let (id, secret) = decoded.split_once(':').ok_or_else(malformed)?;
    Ok(Some((decode_basic_part(id), decode_basic_part(secret))))
}

/// Accepts `client_secret_basic` and `client_secret_post`. Public clients only send their id.
fn authenticate<'a>(
    app: &'a AppState,
    headers: &HeaderMap,
    req: &TokenRequest,
) -> Result<&'a Client, OAuthError> {
    let (client_id, secret) = match basic_credentials(headers)? {
        Some((id, secret)) => {
            if req.client_secret.is_some() {
                return Err(OAuthError::invalid_request(
                    "client credentials sent with more than one method",
                ));
            }
            if req.client_id.as_deref().is_some_and(|form_id| form_id != id) {
                return Err(OAuthError::invalid_request(
                    "client_id does not match the Authorization header",
                ));
            }
            (id, Some(secret))
        }
        None => {
            let id = req
                .client_id
                .clone()
                .ok_or_else(|| OAuthError::invalid_client("client authentication is missing"))?;
            (id, req.client_secret.clone())
        }
    };
    let client = app
        .config
        .client(&client_id)
        .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;
    if let Some(expected) = &client.client_secret
        && secret.as_deref() != Some(expected.as_str()) {
            return Err(OAuthError::invalid_client("invalid client secret"));
        }
    Ok(client)
}

fn code_grant(
    app: &AppState,
    client: &Client,
    req: &TokenRequest,
    issuer: &str,
) -> Result<TokenResponse, OAuthError> {
    let code = req
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let invalid = || OAuthError::invalid_grant("Invalid or expired authorization code");

    // Check everything against a peek, so a request that fails (another client, a wrong
    // redirect_uri) does not burn the code of the legitimate client.
    let peeked = app.stores.codes.get(code).ok_or_else(invalid)?;
    if peeked.client_id != client.client_id {
        return Err(OAuthError::invalid_grant("The code was issued to another client"));
    }
    if app.config.strict_redirect_uri(client) {
        // RFC 6749 section 4.1.3: required, and identical, because authorize always had one.
        let redirect_uri = req
            .redirect_uri
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
        if redirect_uri != peeked.redirect_uri {
            return Err(OAuthError::invalid_grant(
                "redirect_uri does not match the authorization request",
            ));
        }
    }
    if let Some(pkce) = &peeked.pkce {
        let verifier = req
            .code_verifier
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_grant("code_verifier is required"))?;
        if !is_valid_verifier(verifier) || !pkce.verify(verifier) {
            return Err(OAuthError::invalid_grant("PKCE verification failed"));
        }
    }

    // `take` decides who redeems the code if two requests race.
    let grant = app.stores.codes.take(code).ok_or_else(invalid)?;
    issue_tokens(
        app,
        client,
        issuer,
        &Grant {
            user_id: grant.user_id,
            granted: grant.scopes.clone(),
            scopes: grant.scopes,
            auth_time: grant.auth_time,
            nonce: grant.nonce,
            refresh: grant.refresh,
        },
        None,
    )
}

fn refresh_grant(
    app: &AppState,
    client: &Client,
    req: &TokenRequest,
    issuer: &str,
) -> Result<TokenResponse, OAuthError> {
    let token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let invalid = || OAuthError::invalid_grant("Invalid or expired refresh token");
    let stored: RefreshGrant = app.stores.refresh_tokens.get(token).ok_or_else(invalid)?;
    if stored.client_id != client.client_id {
        return Err(OAuthError::invalid_grant(
            "The refresh token was issued to another client",
        ));
    }
    let scopes = match req.scope.as_deref().filter(|s| !s.is_empty()) {
        None => stored.scopes.clone(),
        Some(scope) => {
            let requested = parse_scopes(scope);
            if let Some(extra) = requested.iter().find(|s| !stored.scopes.contains(s)) {
                return Err(OAuthError::invalid_scope(format!(
                    "Scope `{extra}` was not granted originally"
                )));
            }
            requested
        }
    };

    let tokens = &app.config.tokens;
    let (refresh, reuse) = if tokens.rotate_refresh {
        app.stores.refresh_tokens.take(token).ok_or_else(invalid)?;
        (true, None)
    } else if tokens.echo_refresh {
        (true, Some(token.to_string()))
    } else {
        (false, None)
    };
    issue_tokens(
        app,
        client,
        issuer,
        &Grant {
            user_id: stored.user_id,
            scopes,
            granted: stored.scopes,
            auth_time: stored.auth_time,
            nonce: None,
            refresh,
        },
        reuse,
    )
}

/// Mints and stores the tokens for `grant`. `reuse_refresh` is returned as the refresh
/// token instead of minting a new one, for refreshes without rotation. No refresh token
/// is returned when the grant does not allow one.
fn issue_tokens(
    app: &AppState,
    client: &Client,
    issuer: &str,
    grant: &Grant,
    reuse_refresh: Option<String>,
) -> Result<TokenResponse, OAuthError> {
    let config = &app.config;
    let user = config
        .user(&grant.user_id)
        .ok_or_else(|| OAuthError::server_error("The user no longer exists"))?;
    let ttls = config.ttls(client);

    let access_token = match config.tokens.access_format {
        AccessFormat::Opaque => new_token("at"),
        AccessFormat::Jwt => {
            let ctx = ClaimContext {
                issuer,
                client_id: &client.client_id,
                user,
                scopes: &grant.scopes,
            };
            app.keys.sign(&access_token_claims(config, &ctx, ttls.access))?
        }
    };
    app.stores.access_tokens.insert(
        access_token.clone(),
        AccessGrant {
            client_id: client.client_id.clone(),
            user_id: user.id.clone(),
            scopes: grant.scopes.clone(),
        },
        ttls.access,
    );

    let id_token = if grant.scopes.iter().any(|s| s == "openid") {
        let claims = id_token_claims(
            config,
            &IdTokenInput {
                issuer,
                client_id: &client.client_id,
                user,
                scopes: &grant.scopes,
                nonce: grant.nonce.as_deref(),
                auth_time: grant.auth_time,
                access_token: &access_token,
                ttl: ttls.id,
            },
        );
        Some(app.keys.sign(&claims)?)
    } else {
        None
    };

    let refresh_token = match (ttls.refresh, reuse_refresh) {
        _ if !grant.refresh => None,
        (None, _) => None,
        (Some(_), Some(token)) => Some(token),
        (Some(ttl), None) => {
            let token = new_token("rt");
            app.stores.refresh_tokens.insert(
                token.clone(),
                RefreshGrant {
                    client_id: client.client_id.clone(),
                    user_id: user.id.clone(),
                    scopes: grant.granted.clone(),
                    auth_time: grant.auth_time,
                },
                ttl,
            );
            Some(token)
        }
    };

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ttls.access.as_secs(),
        scope: grant.scopes.join(" "),
        id_token,
        refresh_token,
    })
}
