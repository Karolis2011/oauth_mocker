use std::ops::Deref;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::config::Config;
use crate::error::not_found;
use crate::keys::Keys;
use crate::routes::{authorize, discovery, token, userinfo};
use crate::store::Stores;

pub struct AppInner {
    pub config: Config,
    pub keys: Keys,
    pub stores: Stores,
}

/// Cheaply cloneable handle to everything the handlers share.
#[derive(Clone)]
pub struct AppState(Arc<AppInner>);

impl AppState {
    pub fn new(config: Config) -> Result<AppState, String> {
        let keys = Keys::from_config(&config.keys)?;
        Ok(AppState(Arc::new(AppInner {
            config,
            keys,
            stores: Stores::default(),
        })))
    }
}

impl Deref for AppState {
    type Target = AppInner;

    fn deref(&self) -> &AppInner {
        &self.0
    }
}

pub fn build_router(app: AppState) -> Router {
    Router::new()
        .route("/", get(discovery::index))
        .route("/users", get(discovery::users))
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_config),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .route("/oauth2/authorize", get(authorize::authorize))
        .route(
            "/login",
            get(authorize::login_page).post(authorize::login_submit),
        )
        .route("/oauth2/token", post(token::token))
        .route(
            "/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .fallback(not_found)
        .with_state(app)
}
