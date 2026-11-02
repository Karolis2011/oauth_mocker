use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::header::{CACHE_CONTROL, HOST, PRAGMA};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use url::Url;

use crate::config::Config;
use crate::error::{PageError, page_error};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// How the authorization response is delivered to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    Fragment,
}

impl ResponseMode {
    pub fn parse(mode: &str) -> Option<ResponseMode> {
        match mode {
            "query" => Some(ResponseMode::Query),
            "fragment" => Some(ResponseMode::Fragment),
            _ => None,
        }
    }
}

/// Base URL the endpoints live under: the configured `issuer`, or scheme plus `Host` header.
pub fn base_url(config: &Config, headers: &HeaderMap) -> String {
    if let Some(issuer) = &config.issuer {
        return issuer.trim_end_matches('/').to_string();
    }
    let scheme = if config.use_tls { "https" } else { "http" };
    let host = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    format!("{scheme}://{host}")
}

/// The issuer: the base URL plus `issuer_path`.
pub fn issuer(config: &Config, headers: &HeaderMap) -> String {
    format!("{}{}", base_url(config, headers), config.issuer_path)
}

/// A redirect URI must be absolute and must not carry a fragment (RFC 6749 section 3.1.2).
pub fn validate_redirect_uri(redirect_uri: &str) -> Result<(), String> {
    let url = Url::parse(redirect_uri).map_err(|e| format!("not a valid absolute URI: {e}"))?;
    if url.fragment().is_some() {
        return Err("must not contain a fragment".into());
    }
    // Redirecting a browser to these would run or render attacker-controlled content.
    if matches!(url.scheme(), "javascript" | "data" | "vbscript") {
        return Err(format!("must not use the `{}` scheme", url.scheme()));
    }
    Ok(())
}

/// Redirects back to the client, adding `params` to the query or the fragment.
pub fn client_redirect(
    config: &Config,
    redirect_uri: &str,
    mode: ResponseMode,
    params: Vec<(&str, String)>,
) -> Result<Redirect, PageError> {
    let mut url = Url::parse(redirect_uri).map_err(|e| {
        page_error(
            config,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid redirect URI",
            e.to_string(),
        )
    })?;
    match mode {
        ResponseMode::Query => {
            url.query_pairs_mut().extend_pairs(params);
        }
        ResponseMode::Fragment => {
            let fragment = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish();
            url.set_fragment(Some(&fragment));
        }
    }
    Ok(Redirect::to(url.as_str()))
}

/// Marks a token-bearing response as uncacheable (RFC 6749 section 5.1).
pub fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
