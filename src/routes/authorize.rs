use std::time::Duration;

use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::claims::parse_scopes;
use crate::config::{Client, Config, LoginHintMode, RefreshWhen, User};
use crate::crypto::{Pkce, PkceMethod, new_token};
use crate::error::{PageError, page_error, render};
use crate::store::{AuthCode, LoginSession};
use crate::templates::{LoginTemplate, PageCtx, UserView};
use crate::util::{ResponseMode, client_redirect, now, validate_redirect_uri};

/// How long the user has to pick an account.
const SESSION_TTL: Duration = Duration::from_secs(600);

/// Errors the login page can answer an authorization request with, for testing client error handling.
const SIMULATED_ERRORS: &[(&str, &str)] = &[
    ("access_denied", "Deny access"),
    ("server_error", "Server error"),
    ("temporarily_unavailable", "Temporarily unavailable"),
    ("interaction_required", "Interaction required"),
    ("consent_required", "Consent required"),
];

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    response_mode: Option<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    access_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// A problem that is reported to the client by redirecting back to it.
struct FlowError {
    code: &'static str,
    description: String,
    mode: ResponseMode,
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

pub async fn authorize(
    State(app): State<AppState>,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Result<Redirect, PageError> {
    let config = &app.config;
    let bad_request = |title: &str, message: String| {
        page_error(config, StatusCode::BAD_REQUEST, title, message)
    };
    let Query(q) = query.map_err(|e| bad_request("Invalid request", e.to_string()))?;

    // Until the client and redirect URI are trusted, problems must not redirect.
    let client_id = non_empty(&q.client_id)
        .ok_or_else(|| bad_request("Missing client_id", "The request has no client_id.".into()))?;
    let client = config.client(client_id).ok_or_else(|| {
        bad_request(
            "Unknown client",
            format!("No client with id \u{201c}{client_id}\u{201d} is configured."),
        )
    })?;
    let redirect_uri = non_empty(&q.redirect_uri)
        .ok_or_else(|| bad_request("Missing redirect_uri", "The request has no redirect_uri.".into()))?;
    validate_redirect_uri(redirect_uri)
        .map_err(|e| bad_request("Invalid redirect_uri", format!("The redirect_uri {e}.")))?;

    if let Some(allowed) = &client.redirect_uris
        && !allowed.iter().any(|uri| uri == redirect_uri)
    {
        return Err(bad_request(
            "Unregistered redirect_uri",
            format!("This client has not registered the redirect_uri {redirect_uri}."),
        ));
    }

    match start_session(&app, &q, client, redirect_uri) {
        Ok(session_id) => {
            // `auto` skips the picker when the hint names exactly one account.
            if config.login_hint == LoginHintMode::Auto
                && let Some(hint) = non_empty(&q.login_hint)
                && let [user] = config.users_matching(hint).as_slice()
                && let Some(session) = app.stores.sessions.take(&session_id)
            {
                let params = vec![issue_code(&app, &session, user, client)];
                return finish_redirect(config, &session, params);
            }
            Ok(Redirect::to(&format!("/login?session={session_id}")))
        }
        Err(e) => {
            let mut params = vec![
                ("error", e.code.to_string()),
                ("error_description", e.description),
            ];
            if let Some(state) = non_empty(&q.state) {
                params.push(("state", state.to_string()));
            }
            client_redirect(config, redirect_uri, e.mode, params)
        }
    }
}

fn start_session(
    app: &AppState,
    q: &AuthorizeQuery,
    client: &Client,
    redirect_uri: &str,
) -> Result<String, FlowError> {
    let config = &app.config;
    let fail = |code: &'static str, description: &str, mode| FlowError {
        code,
        description: description.to_string(),
        mode,
    };

    let mode = match non_empty(&q.response_mode) {
        None => ResponseMode::Query,
        Some(mode) => ResponseMode::parse(mode).ok_or_else(|| {
            fail("invalid_request", "Unsupported response_mode.", ResponseMode::Query)
        })?,
    };
    if q.response_type.as_deref() != Some("code") {
        return Err(fail(
            "unsupported_response_type",
            "Only response_type=code is supported.",
            mode,
        ));
    }

    let scopes = parse_scopes(non_empty(&q.scope).unwrap_or(&config.default_scope));
    if let Some(allowed) = &client.scopes
        && let Some(denied) = scopes.iter().find(|s| !allowed.contains(s)) {
            return Err(FlowError {
                code: "invalid_scope",
                description: format!("Scope `{denied}` is not allowed for this client."),
                mode,
            });
        }

    let pkce = match non_empty(&q.code_challenge) {
        Some(challenge) => {
            let method = match non_empty(&q.code_challenge_method) {
                None => PkceMethod::Plain,
                Some(m) => PkceMethod::parse(m).ok_or_else(|| {
                    fail("invalid_request", "Unsupported code_challenge_method.", mode)
                })?,
            };
            Some(Pkce {
                challenge: challenge.to_string(),
                method,
            })
        }
        None if client.is_public() => {
            return Err(fail(
                "invalid_request",
                "Public clients must use PKCE (code_challenge is missing).",
                mode,
            ));
        }
        None => None,
    };

    let prompts: Vec<&str> = non_empty(&q.prompt)
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();
    // The mock has no existing login to reuse, so silent authentication cannot succeed.
    if prompts.contains(&"none") {
        return Err(fail("login_required", "prompt=none cannot be satisfied.", mode));
    }

    let offline = match non_empty(&q.access_type) {
        Some("offline") => true,
        None | Some("online") => false,
        // Only a provider that defines access_type rejects other values.
        Some(_) if config.tokens.refresh_when == RefreshWhen::AccessTypeOffline => {
            return Err(fail("invalid_request", "access_type must be online or offline.", mode));
        }
        Some(_) => false,
    };

    let session_id = new_token("ls");
    app.stores.sessions.insert(
        session_id.clone(),
        LoginSession {
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scopes,
            state: non_empty(&q.state).map(String::from),
            nonce: non_empty(&q.nonce).map(String::from),
            pkce,
            response_mode: mode,
            login_hint: non_empty(&q.login_hint)
                .filter(|_| config.login_hint != LoginHintMode::Ignore)
                .map(String::from),
            offline,
            prompt_consent: prompts.contains(&"consent"),
        },
        SESSION_TTL,
    );
    Ok(session_id)
}

#[derive(Deserialize)]
pub struct LoginQuery {
    session: Option<String>,
}

fn expired_session(config: &Config) -> PageError {
    page_error(
        config,
        StatusCode::BAD_REQUEST,
        "Login session expired",
        "This login session is unknown, expired or was already used. Start the sign-in again from your application.",
    )
}

pub async fn login_page(
    State(app): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, PageError> {
    let config = &app.config;
    let session = query
        .session
        .as_deref()
        .and_then(|id| app.stores.sessions.get(id))
        .ok_or_else(|| expired_session(config))?;
    let client = config.client(&session.client_id).ok_or_else(|| {
        page_error(
            config,
            StatusCode::BAD_REQUEST,
            "Unknown client",
            "The client of this login session is no longer configured.",
        )
    })?;
    // Suggested accounts first, otherwise in configured order.
    let suggested: Vec<&User> = session
        .login_hint
        .as_deref()
        .map(|hint| config.users_matching(hint))
        .unwrap_or_default();
    let hint_matched = !suggested.is_empty();
    let mut users: Vec<UserView> = config
        .users
        .iter()
        .map(|u| UserView::new(u, suggested.iter().any(|s| s.id == u.id)))
        .collect();
    users.sort_by_key(|u| !u.suggested);
    Ok(render(&LoginTemplate {
        page: PageCtx::new(config),
        session: query.session.unwrap_or_default(),
        client_name: client.display_name().to_string(),
        client_id: client.client_id.clone(),
        redirect_uri: session.redirect_uri,
        scopes: session.scopes,
        users,
        login_hint: session.login_hint,
        hint_matched,
        simulated_errors: SIMULATED_ERRORS
            .iter()
            .copied()
            .filter(|(code, _)| *code != "access_denied")
            .collect(),
    }))
}

#[derive(Deserialize)]
pub struct LoginForm {
    session: String,
    user: Option<String>,
    error: Option<String>,
}

pub async fn login_submit(
    State(app): State<AppState>,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Result<impl IntoResponse, PageError> {
    let config = &app.config;
    let bad_request = |title: &str, message: String| {
        page_error(config, StatusCode::BAD_REQUEST, title, message)
    };
    let Form(form) = form.map_err(|e| bad_request("Invalid request", e.to_string()))?;

    // Validate against a peek first, so a bad choice leaves the session usable for a retry.
    let peeked = app
        .stores
        .sessions
        .get(&form.session)
        .ok_or_else(|| expired_session(config))?;
    let outcome = if let Some(code) = non_empty(&form.error) {
        let (_, label) = SIMULATED_ERRORS
            .iter()
            .find(|(c, _)| *c == code)
            .ok_or_else(|| bad_request("Unknown error", format!("`{code}` cannot be simulated.")))?;
        Outcome::Error(code, label)
    } else {
        let user_id = non_empty(&form.user)
            .ok_or_else(|| bad_request("No account selected", "Pick an account to continue.".into()))?;
        let user = config
            .user(user_id)
            .ok_or_else(|| bad_request("Unknown user", format!("No user with id `{user_id}`.")))?;
        let client = config
            .client(&peeked.client_id)
            .ok_or_else(|| bad_request("Unknown client", "The client is no longer configured.".into()))?;
        Outcome::Login(user, client)
    };

    // `take` is the single point that decides who owns the session, so a double
    // submit cannot mint two codes from it.
    let session = app
        .stores
        .sessions
        .take(&form.session)
        .ok_or_else(|| expired_session(config))?;

    let mut params: Vec<(&str, String)> = Vec::new();
    match outcome {
        Outcome::Error(code, label) => {
            params.push(("error", code.to_string()));
            params.push((
                "error_description",
                format!("Simulated by the mock login page ({label})."),
            ));
        }
        Outcome::Login(user, client) => params.push(issue_code(&app, &session, user, client)),
    }
    finish_redirect(config, &session, params)
}

/// Mints an authorization code for `user` and returns it as a redirect parameter.
fn issue_code(
    app: &AppState,
    session: &LoginSession,
    user: &User,
    client: &Client,
) -> (&'static str, String) {
    let code = new_token("code");
    app.stores.codes.insert(
        code.clone(),
        AuthCode {
            client_id: session.client_id.clone(),
            user_id: user.id.clone(),
            redirect_uri: session.redirect_uri.clone(),
            scopes: session.scopes.clone(),
            nonce: session.nonce.clone(),
            pkce: session.pkce.clone(),
            auth_time: now(),
            refresh: refresh_allowed(app, session, user),
        },
        app.config.ttls(client).code,
    );
    ("code", code)
}

/// Whether the code for this login may be exchanged for a refresh token too.
fn refresh_allowed(app: &AppState, session: &LoginSession, user: &User) -> bool {
    let tokens = &app.config.tokens;
    let requested = match tokens.refresh_when {
        RefreshWhen::Always => true,
        RefreshWhen::OfflineAccess => session.scopes.iter().any(|s| s == "offline_access"),
        RefreshWhen::AccessTypeOffline => session.offline,
    };
    if !requested {
        return false;
    }
    let first = app.stores.consents.insert(&session.client_id, &user.id);
    first || session.prompt_consent || !tokens.refresh_on_first_consent_only
}

/// Sends the user back to the client, adding `state` to `params`.
fn finish_redirect(
    config: &Config,
    session: &LoginSession,
    mut params: Vec<(&str, String)>,
) -> Result<Redirect, PageError> {
    if let Some(state) = &session.state {
        params.push(("state", state.clone()));
    }
    client_redirect(config, &session.redirect_uri, session.response_mode, params)
}

/// What the user chose on the login page, already validated.
enum Outcome<'a> {
    Error(&'a str, &'a str),
    Login(&'a User, &'a Client),
}
