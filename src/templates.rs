use askama::Template;
use serde_json::Value;

use crate::config::{Config, User};

/// Fields every page needs, read by `base.html`.
pub struct PageCtx {
    pub title: String,
    pub custom_css: String,
}

impl PageCtx {
    pub fn new(config: &Config) -> Self {
        PageCtx {
            title: config.ui.title.clone(),
            custom_css: config.ui.custom_css.clone(),
        }
    }
}

pub struct UserView {
    pub id: String,
    pub name: String,
    pub email: String,
    pub initial: String,
    /// Matches the `login_hint` of the request.
    pub suggested: bool,
    pub claims: Vec<(String, String)>,
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(display_value).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

impl UserView {
    pub fn new(user: &User, suggested: bool) -> Self {
        UserView {
            suggested,
            id: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            initial: user
                .name
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".into()),
            claims: user
                .claims
                .iter()
                .map(|(k, v)| (k.clone(), display_value(v)))
                .collect(),
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub page: PageCtx,
    pub session: String,
    pub client_name: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub users: Vec<UserView>,
    pub login_hint: Option<String>,
    pub hint_matched: bool,
    pub simulated_errors: Vec<(&'static str, &'static str)>,
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub page: PageCtx,
    pub status: u16,
    pub heading: String,
    pub message: String,
}

pub struct ClientView {
    pub id: String,
    pub name: String,
    pub public: bool,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub page: PageCtx,
    pub issuer: String,
    pub endpoints: Vec<(&'static str, String)>,
    pub clients: Vec<ClientView>,
    pub user_count: usize,
}
