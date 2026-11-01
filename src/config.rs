use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Longest lifetime we accept, keeps `Instant + Duration` far away from overflow.
const MAX_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Determines if OIDC responds with http or https URLs.
    #[serde(default)]
    pub use_tls: bool,
    /// Fixed issuer URL. When unset it is derived from the `Host` header.
    pub issuer: Option<String>,
    /// Scope used when an authorization request does not ask for any.
    #[serde(default = "default_scope")]
    pub default_scope: String,
    /// What to do with a `login_hint` in the authorization request.
    #[serde(default)]
    pub login_hint: LoginHintMode,
    /// Make the token endpoint require a `redirect_uri` identical to the authorize request
    /// (RFC 6749 section 4.1.3). Off by default, clients can override it.
    #[serde(default)]
    pub strict_redirect_uri: bool,
    #[serde(default)]
    pub tokens: TokenConfig,
    #[serde(default)]
    pub ui: UiConfig,
    /// Custom scopes (and overrides of the built-in ones), by scope name.
    #[serde(default)]
    pub scopes: BTreeMap<String, ScopeConfig>,
    pub keys: Vec<KeyConfig>,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub users: Vec<User>,
    /// Built-in plus configured scopes, filled in by `finalize`.
    #[serde(skip)]
    pub scope_map: BTreeMap<String, Vec<String>>,
}

fn default_scope() -> String {
    "openid profile email".to_string()
}

/// How `login_hint` is treated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginHintMode {
    /// Show the matching account first, marked as suggested.
    #[default]
    Highlight,
    /// Skip the account picker when exactly one account matches.
    Auto,
    /// Do not look at the hint.
    Ignore,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TokenConfig {
    /// Authorization code lifetime in seconds.
    pub code_ttl: u64,
    /// Access token lifetime in seconds.
    pub access_ttl: u64,
    /// ID token lifetime in seconds.
    pub id_ttl: u64,
    /// Refresh token lifetime in seconds, 0 disables refresh tokens.
    pub refresh_ttl: u64,
    /// Issue a new refresh token on every refresh and invalidate the old one.
    pub rotate_refresh: bool,
}

impl Default for TokenConfig {
    fn default() -> Self {
        TokenConfig {
            code_ttl: 60,
            access_ttl: 3600,
            id_ttl: 3600,
            refresh_ttl: 24 * 3600,
            rotate_refresh: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    pub title: String,
    /// CSS appended after the built-in stylesheet.
    pub custom_css: String,
    /// File whose contents are appended to `custom_css` at startup.
    pub custom_css_file: Option<PathBuf>,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            title: "Mock Login".to_string(),
            custom_css: String::new(),
            custom_css_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum KeyKind {
    #[serde(rename = "PEM_RS256")]
    PemRs256,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Determines if the key is used for signing JWT tokens.
    #[serde(default)]
    pub active: bool,
    pub kind: KeyKind,
    /// Key ID, ends up in the `kid` header of signed tokens and in the JWKS.
    pub kid: String,
    /// Private key in PEM PKCS#8 format.
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub client_id: String,
    /// Clients without a secret are public clients and must use PKCE.
    pub client_secret: Option<String>,
    /// Display name for the login page.
    pub name: Option<String>,
    /// Exact redirect URIs the client may use, any URI when unset.
    pub redirect_uris: Option<Vec<String>>,
    /// Overrides the global `strict_redirect_uri` for this client.
    pub strict_redirect_uri: Option<bool>,
    /// Scopes this client may request, any scope when unset.
    pub scopes: Option<Vec<String>>,
    pub access_ttl: Option<u64>,
    pub id_ttl: Option<u64>,
    pub refresh_ttl: Option<u64>,
    #[serde(default)]
    pub simulate: Simulate,
}

impl Client {
    pub fn is_public(&self) -> bool {
        self.client_secret.is_none()
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.client_id)
    }
}

/// Failure injection for a client, for testing how an app copes with a misbehaving provider.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Simulate {
    /// OAuth error code every token request fails with, e.g. `invalid_grant`.
    pub token_error: Option<String>,
    /// Same, but only for `refresh_token` grants. Takes precedence over `token_error` there.
    pub refresh_error: Option<String>,
    /// Delay added to every token request.
    pub token_delay_ms: Option<u64>,
    /// OAuth error code every userinfo request fails with, e.g. `invalid_token`.
    pub userinfo_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    /// Extra claims, any JSON-compatible value.
    #[serde(default)]
    pub claims: Map<String, Value>,
}

impl User {
    /// Every claim the user can release, `name` and `email` included.
    pub fn all_claims(&self) -> Map<String, Value> {
        let mut all = Map::new();
        all.insert("name".into(), self.name.clone().into());
        all.insert("email".into(), self.email.clone().into());
        all.extend(self.claims.clone());
        all
    }
}

/// Resolved token lifetimes for one client.
#[derive(Debug, Clone, Copy)]
pub struct Ttls {
    pub code: Duration,
    pub access: Duration,
    pub id: Duration,
    /// `None` when refresh tokens are disabled.
    pub refresh: Option<Duration>,
}

pub fn ttl(secs: u64) -> Duration {
    Duration::from_secs(secs.min(MAX_TTL_SECS))
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file `{path}`: {e}"))?;
        Config::from_toml(&text).map_err(|e| format!("invalid config `{path}`: {e}"))
    }

    pub fn from_toml(text: &str) -> Result<Config, String> {
        let mut config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        config.finalize()?;
        config.validate()?;
        Ok(config)
    }

    fn finalize(&mut self) -> Result<(), String> {
        if let Some(path) = &self.ui.custom_css_file {
            let css = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read ui.custom_css_file `{}`: {e}", path.display()))?;
            self.ui.custom_css.push('\n');
            self.ui.custom_css.push_str(&css);
        }
        let mut scope_map: BTreeMap<String, Vec<String>> = [
            ("openid", vec![]),
            ("profile", vec!["name"]),
            ("email", vec!["email", "email_verified"]),
            ("offline_access", vec![]),
        ]
        .into_iter()
        .map(|(name, claims)| {
            (
                name.to_string(),
                claims.into_iter().map(String::from).collect(),
            )
        })
        .collect();
        for (name, scope) in &self.scopes {
            scope_map.insert(name.clone(), scope.claims.clone());
        }
        self.scope_map = scope_map;
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if !self.keys.iter().any(|k| k.active) {
            return Err("no key is marked `active = true`".into());
        }
        unique("client_id", self.clients.iter().map(|c| c.client_id.as_str()))?;
        unique("user id", self.users.iter().map(|u| u.id.as_str()))?;
        unique("kid", self.keys.iter().map(|k| k.kid.as_str()))?;
        for client in &self.clients {
            for uri in client.redirect_uris.iter().flatten() {
                crate::util::validate_redirect_uri(uri).map_err(|e| {
                    format!("client `{}`: redirect URI `{uri}` {e}", client.client_id)
                })?;
            }
        }
        for name in self.scopes.keys() {
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(format!("invalid scope name `{name}`"));
            }
        }
        Ok(())
    }

    pub fn client(&self, client_id: &str) -> Option<&Client> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }

    pub fn user(&self, id: &str) -> Option<&User> {
        self.users.iter().find(|u| u.id == id)
    }

    /// Users whose id, name or email equals `hint`, ignoring case and surrounding spaces.
    pub fn users_matching(&self, hint: &str) -> Vec<&User> {
        let hint = hint.trim().to_lowercase();
        if hint.is_empty() {
            return Vec::new();
        }
        self.users
            .iter()
            .filter(|u| {
                [&u.id, &u.name, &u.email]
                    .iter()
                    .any(|field| field.to_lowercase() == hint)
            })
            .collect()
    }

    pub fn strict_redirect_uri(&self, client: &Client) -> bool {
        client.strict_redirect_uri.unwrap_or(self.strict_redirect_uri)
    }

    pub fn ttls(&self, client: &Client) -> Ttls {
        let refresh = client.refresh_ttl.unwrap_or(self.tokens.refresh_ttl);
        Ttls {
            code: ttl(self.tokens.code_ttl),
            access: ttl(client.access_ttl.unwrap_or(self.tokens.access_ttl)),
            id: ttl(client.id_ttl.unwrap_or(self.tokens.id_ttl)),
            refresh: (refresh > 0).then(|| ttl(refresh)),
        }
    }
}

fn unique<'a>(what: &str, values: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("duplicate {what} `{value}`"));
        }
    }
    Ok(())
}
