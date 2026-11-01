use askama::Template;
use axum::Json;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde_json::json;

use crate::config::Config;
use crate::templates::{ErrorTemplate, PageCtx};
use crate::util::no_store;

/// RFC 6749 section 5.2 error response, rendered as JSON.
#[derive(Debug)]
pub struct OAuthError {
    pub code: String,
    pub description: Option<String>,
    pub status: StatusCode,
}

fn status_for(code: &str) -> StatusCode {
    match code {
        "invalid_client" | "invalid_token" => StatusCode::UNAUTHORIZED,
        "insufficient_scope" => StatusCode::FORBIDDEN,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        "temporarily_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

impl OAuthError {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        let code = code.into();
        OAuthError {
            status: status_for(&code),
            code,
            description: Some(description.into()),
        }
    }

    /// An error requested through the client's `simulate` settings.
    pub fn simulated(code: &str) -> Self {
        OAuthError::new(code, "Simulated by the mock server configuration")
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        OAuthError::new("invalid_request", description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        OAuthError::new("invalid_client", description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        OAuthError::new("invalid_grant", description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        OAuthError::new("invalid_scope", description)
    }

    pub fn invalid_token(description: impl Into<String>) -> Self {
        OAuthError::new("invalid_token", description)
    }

    pub fn insufficient_scope(description: impl Into<String>) -> Self {
        OAuthError::new("insufficient_scope", description)
    }

    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        OAuthError::new("unsupported_grant_type", description)
    }

    pub fn server_error(description: impl Into<String>) -> Self {
        OAuthError::new("server_error", description)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code });
        if let Some(description) = &self.description {
            body["error_description"] = description.clone().into();
        }
        let mut response = no_store((self.status, Json(body)));
        let challenge = match self.code.as_str() {
            "invalid_client" => Some(r#"Basic realm="oauth_mocker""#),
            "invalid_token" => Some(r#"Bearer error="invalid_token""#),
            _ => None,
        };
        if let Some(challenge) = challenge {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        response
    }
}

/// Router fallback, keeps unknown paths in the same JSON shape as other errors.
pub async fn not_found() -> OAuthError {
    OAuthError {
        code: "not_found".into(),
        description: Some("No such endpoint".into()),
        status: StatusCode::NOT_FOUND,
    }
}

/// An HTML error page, for failures where redirecting back to the client is not safe.
pub struct PageError {
    status: StatusCode,
    template: ErrorTemplate,
}

pub fn page_error(
    config: &Config,
    status: StatusCode,
    title: impl Into<String>,
    message: impl Into<String>,
) -> PageError {
    PageError {
        status,
        template: ErrorTemplate {
            page: PageCtx::new(config),
            status: status.as_u16(),
            heading: title.into(),
            message: message.into(),
        },
    }
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        (self.status, render(&self.template)).into_response()
    }
}

/// Renders a template, falling back to a plain 500 if rendering fails.
pub fn render<T: Template>(template: &T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template error: {e}"),
        )
            .into_response(),
    }
}
