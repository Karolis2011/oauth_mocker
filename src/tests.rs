//! End-to-end tests that drive the router in-process.

use axum::Router;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, LOCATION};
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::Url;

use crate::app::{AppState, build_router};
use crate::config::Config;
use crate::crypto::at_hash;

const REDIRECT: &str = "http://localhost:3000/callback";
const REDIRECT_ENC: &str = "http%3A%2F%2Flocalhost%3A3000%2Fcallback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Example config with `overrides` merged in, tables are merged one level deep.
fn router_with(overrides: &str) -> Router {
    let mut config: toml::Table = include_str!("../config.example.toml").parse().unwrap();
    let overrides: toml::Table = overrides.parse().expect("valid override TOML");
    for (key, value) in overrides {
        match (config.get_mut(&key), value) {
            (Some(toml::Value::Table(base)), toml::Value::Table(extra)) => base.extend(extra),
            (_, value) => {
                config.insert(key, value);
            }
        }
    }
    let config = Config::from_toml(&config.to_string()).expect("example config is valid");
    build_router(AppState::new(config).expect("keys are valid"))
}

/// Example config with one piece of text replaced.
fn router_replacing(from: &str, to: &str) -> Router {
    let text = include_str!("../config.example.toml");
    assert!(text.contains(from), "example config no longer contains {from:?}");
    let config = Config::from_toml(&text.replace(from, to)).expect("valid config");
    build_router(AppState::new(config).expect("keys are valid"))
}

const SIMULATE_BLOCK: &str = "# [clients.simulate]";

fn router() -> Router {
    router_with("")
}

struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }

    fn location(&self) -> Url {
        Url::parse("http://localhost")
            .unwrap()
            .join(self.location.as_deref().expect("a Location header"))
            .unwrap()
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(LOCATION)
        .map(|v| v.to_str().unwrap().to_string());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        location,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

async fn get(app: &Router, uri: &str) -> Reply {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

async fn post_form(app: &Router, uri: &str, body: &str, auth: Option<&str>) -> Reply {
    let mut request = Request::post(uri).header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        request = request.header(AUTHORIZATION, auth);
    }
    send(app, request.body(Body::from(body.to_string())).unwrap()).await
}

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", BASE64_STANDARD.encode(format!("{id}:{secret}")))
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn jwt_payload(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Starts an authorization request and returns the login session id.
async fn authorize(app: &Router, extra: &str) -> String {
    let reply = get(
        app,
        &format!(
            "/oauth2/authorize?response_type=code&redirect_uri={}&{extra}",
            encode(REDIRECT)
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let location = reply.location();
    assert_eq!(location.path(), "/login", "unexpected redirect: {location}");
    query(&location, "session").expect("a session id")
}

/// Picks `user` on the login page and returns the authorization code.
async fn login(app: &Router, session: &str, user: &str) -> String {
    let reply = post_form(app, "/login", &format!("session={session}&user={user}"), None).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    query(&reply.location(), "code").expect("a code")
}

async fn exchange(app: &Router, code: &str) -> Value {
    let reply = post_form(
        app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={}", encode(REDIRECT)),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply.json()
}

async fn tokens_for(app: &Router, scope: &str) -> Value {
    let session = authorize(app, &format!("client_id=my-client&scope={}", encode(scope))).await;
    let code = login(app, &session, "1").await;
    exchange(app, &code).await
}

async fn userinfo(app: &Router, access_token: &str) -> Reply {
    send(
        app,
        Request::get("/userinfo")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn discovery_is_truthful() {
    let app = router();
    let reply = send(
        &app,
        Request::get("/.well-known/openid-configuration")
            .header("host", "idp.test:9000")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let doc = reply.json();
    assert_eq!(doc["issuer"], "http://idp.test:9000");
    assert_eq!(doc["token_endpoint"], "http://idp.test:9000/oauth2/token");
    assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
    assert!(doc["grant_types_supported"].as_array().unwrap().contains(&"refresh_token".into()));

    let jwks = get(&app, "/.well-known/jwks.json").await.json();
    assert_eq!(jwks["keys"][0]["kty"], "RSA");
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn full_code_flow_issues_a_complete_id_token() {
    let app = router();
    let session = authorize(&app, "client_id=my-client&state=xyz&nonce=n-0S6_WzA2Mj&scope=openid+profile+email+groups").await;

    let page = get(&app, &format!("/login?session={session}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Alice") && page.body.contains("My App"));

    let reply = post_form(&app, "/login", &format!("session={session}&user=1"), None).await;
    let location = reply.location();
    assert!(location.as_str().starts_with(REDIRECT));
    assert_eq!(query(&location, "state").as_deref(), Some("xyz"));
    let code = query(&location, "code").unwrap();

    let tokens = exchange(&app, &code).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);
    let claims = jwt_payload(tokens["id_token"].as_str().unwrap());
    assert_eq!(claims["iss"], "http://localhost");
    assert_eq!(claims["sub"], "1");
    assert_eq!(claims["aud"], "my-client");
    assert_eq!(claims["nonce"], "n-0S6_WzA2Mj");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["groups"], serde_json::json!(["admin", "user"]));
    assert_eq!(claims["at_hash"], at_hash(tokens["access_token"].as_str().unwrap()));
    assert!(claims["auth_time"].is_i64() && claims["exp"].as_i64() > claims["iat"].as_i64());

    let info = userinfo(&app, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.json()["sub"], "1");

    // Codes are single use, and a session is consumed by the login.
    let replay = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}"),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");
    let again = post_form(&app, "/login", &format!("session={session}&user=1"), None).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn concurrent_flows_do_not_interfere() {
    let app = router();
    let first = authorize(&app, "client_id=my-client&state=one").await;
    let second = authorize(&app, "client_id=my-client&state=two").await;
    let a = post_form(&app, "/login", &format!("session={first}&user=1"), None).await;
    let b = post_form(&app, "/login", &format!("session={second}&user=2"), None).await;
    assert_eq!(query(&a.location(), "state").as_deref(), Some("one"));
    assert_eq!(query(&b.location(), "state").as_deref(), Some("two"));
}

#[tokio::test]
async fn scopes_filter_claims() {
    let app = router();
    let narrow = tokens_for(&app, "openid").await;
    let info = userinfo(&app, narrow["access_token"].as_str().unwrap()).await.json();
    assert!(info.get("email").is_none() && info.get("name").is_none(), "{info}");
    assert_eq!(info["sub"], "1");
    // `groups` is a custom scope in the example config, so it needs the scope too.
    assert!(info.get("groups").is_none());

    let wide = tokens_for(&app, "openid email groups").await;
    let info = userinfo(&app, wide["access_token"].as_str().unwrap()).await.json();
    assert_eq!(info["email"], "alice@example.com");
    assert_eq!(info["email_verified"], true);
    assert!(info.get("groups").is_some() && info.get("name").is_none());
}

#[tokio::test]
async fn id_token_requires_openid_scope() {
    let app = router();
    let tokens = tokens_for(&app, "email").await;
    assert!(tokens.get("id_token").is_none());
    let info = userinfo(&app, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info.status, StatusCode::FORBIDDEN);
    assert_eq!(info.json()["error"], "insufficient_scope");
}

#[tokio::test]
async fn refresh_rotates_tokens() {
    let app = router();
    let tokens = tokens_for(&app, "openid email offline_access").await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    let reply = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=refresh_token&refresh_token={refresh}&scope=openid"),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let refreshed = reply.json();
    assert_eq!(refreshed["scope"], "openid");
    assert_ne!(refreshed["refresh_token"], tokens["refresh_token"]);
    assert!(refreshed["id_token"].is_string());
    assert!(jwt_payload(refreshed["id_token"].as_str().unwrap()).get("email").is_none());

    let reuse = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=refresh_token&refresh_token={refresh}"),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(reuse.json()["error"], "invalid_grant");

    let widen = post_form(
        &app,
        "/oauth2/token",
        &format!(
            "grant_type=refresh_token&refresh_token={}&scope=openid+groups",
            refreshed["refresh_token"].as_str().unwrap()
        ),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(widen.json()["error"], "invalid_scope");
}

#[tokio::test]
async fn refresh_tokens_can_be_disabled() {
    let app = router_with("[tokens]\nrefresh_ttl = 0");
    let tokens = tokens_for(&app, "openid").await;
    assert!(tokens.get("refresh_token").is_none());
}

#[tokio::test]
async fn access_tokens_expire() {
    let app = router_with("[tokens]\naccess_ttl = 0");
    let tokens = tokens_for(&app, "openid").await;
    assert_eq!(tokens["expires_in"], 0);
    let info = userinfo(&app, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info.status, StatusCode::UNAUTHORIZED);
    assert_eq!(info.json()["error"], "invalid_token");
}

#[tokio::test]
async fn pkce_s256_is_enforced() {
    let app = router();
    let challenge = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let start = format!("client_id=my-spa&code_challenge={challenge}&code_challenge_method=S256");

    let session = authorize(&app, &start).await;
    let code = login(&app, &session, "1").await;
    let wrong = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&client_id=my-spa&code={code}&redirect_uri={REDIRECT_ENC}&code_verifier={}", "a".repeat(43)),
        None,
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.json()["error"], "invalid_grant");

    let session = authorize(&app, &start).await;
    let code = login(&app, &session, "1").await;
    let missing = post_form(&app, "/oauth2/token", &format!("grant_type=authorization_code&client_id=my-spa&code={code}&redirect_uri={REDIRECT_ENC}"), None).await;
    assert_eq!(missing.json()["error"], "invalid_grant");

    let session = authorize(&app, &start).await;
    let code = login(&app, &session, "1").await;
    let ok = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&client_id=my-spa&code={code}&redirect_uri={REDIRECT_ENC}&code_verifier={VERIFIER}"),
        None,
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

#[tokio::test]
async fn public_clients_must_use_pkce() {
    let app = router();
    let reply = get(
        &app,
        &format!("/oauth2/authorize?response_type=code&client_id=my-spa&state=s&redirect_uri={}", encode(REDIRECT)),
    )
    .await;
    let location = reply.location();
    assert_eq!(query(&location, "error").as_deref(), Some("invalid_request"));
    assert_eq!(query(&location, "state").as_deref(), Some("s"));
}

#[tokio::test]
async fn authorize_errors_redirect_only_for_trusted_requests() {
    let app = router();
    let unknown = get(&app, &format!("/oauth2/authorize?response_type=code&client_id=nope&redirect_uri={}", encode(REDIRECT))).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert!(unknown.location.is_none() && unknown.body.contains("Unknown client"));

    let no_uri = get(&app, "/oauth2/authorize?response_type=code&client_id=my-client").await;
    assert_eq!(no_uri.status, StatusCode::BAD_REQUEST);

    let reply = get(
        &app,
        &format!("/oauth2/authorize?response_type=token&client_id=my-client&state=s&redirect_uri={}", encode(REDIRECT)),
    )
    .await;
    assert_eq!(query(&reply.location(), "error").as_deref(), Some("unsupported_response_type"));

    let reply = get(
        &app,
        &format!("/oauth2/authorize?response_type=code&client_id=my-client&prompt=none&redirect_uri={}", encode(REDIRECT)),
    )
    .await;
    assert_eq!(query(&reply.location(), "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn fragment_response_mode_and_redirect_encoding() {
    let app = router();
    let uri = "http://localhost:3000/cb?existing=1";
    let reply = get(
        &app,
        &format!(
            "/oauth2/authorize?response_type=code&client_id=my-client&response_mode=fragment&state={}&redirect_uri={}",
            encode("a b&c"),
            encode(uri)
        ),
    )
    .await;
    let session = query(&reply.location(), "session").unwrap();
    let done = post_form(&app, "/login", &format!("session={session}&user=1"), None).await;
    let location = done.location();
    assert_eq!(query(&location, "existing").as_deref(), Some("1"));
    assert!(query(&location, "code").is_none(), "code must travel in the fragment");
    let fragment = location.fragment().unwrap();
    assert!(fragment.starts_with("code=") && fragment.contains("state=a+b%26c"), "{fragment}");
}

#[tokio::test]
async fn token_endpoint_errors_are_oauth_shaped() {
    let app = router();

    let bad_secret = post_form(&app, "/oauth2/token", "grant_type=authorization_code&code=x", Some(&basic("my-client", "wrong"))).await;
    assert_eq!(bad_secret.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad_secret.json()["error"], "invalid_client");

    let auth = basic("my-client", "my-secret");
    let bad_grant = post_form(&app, "/oauth2/token", "grant_type=password", Some(&auth)).await;
    assert_eq!(bad_grant.json()["error"], "unsupported_grant_type");

    let none = post_form(&app, "/oauth2/token", "code=x", Some(&auth)).await;
    assert_eq!(none.json()["error"], "invalid_request");

    let both = post_form(&app, "/oauth2/token", "grant_type=authorization_code&code=x&client_secret=my-secret", Some(&auth)).await;
    assert_eq!(both.json()["error"], "invalid_request");

    let unknown_route = get(&app, "/nope").await;
    assert_eq!(unknown_route.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_route.json()["error"], "not_found");
}

#[tokio::test]
async fn client_credentials_in_the_form_body_work() {
    let app = router();
    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "2").await;
    let reply = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_ENC}&client_id=my-client&client_secret=my-secret"),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
async fn code_is_bound_to_redirect_uri() {
    let app = router_with("strict_redirect_uri = true");
    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "1").await;
    let reply = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={}", encode("http://evil.test/cb")),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(reply.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn login_page_can_simulate_errors() {
    let app = router();
    let session = authorize(&app, "client_id=my-client&state=keep").await;
    let reply = post_form(&app, "/login", &format!("session={session}&error=access_denied"), None).await;
    let location = reply.location();
    assert_eq!(query(&location, "error").as_deref(), Some("access_denied"));
    assert_eq!(query(&location, "state").as_deref(), Some("keep"));
    assert!(query(&location, "code").is_none());

    let session = authorize(&app, "client_id=my-client").await;
    let bogus = post_form(&app, "/login", &format!("session={session}&error=made_up"), None).await;
    assert_eq!(bogus.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn clients_can_simulate_token_and_userinfo_failures() {
    let config = include_str!("../config.example.toml").replace(
        SIMULATE_BLOCK,
        "[clients.simulate]\ntoken_error = \"temporarily_unavailable\"",
    );
    assert!(config.contains("temporarily_unavailable"), "example config changed shape");
    let app = build_router(AppState::new(Config::from_toml(&config).unwrap()).unwrap());
    let reply = post_form(&app, "/oauth2/token", "grant_type=authorization_code&code=x", Some(&basic("my-client", "my-secret"))).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.json()["error"], "temporarily_unavailable");

    let config = include_str!("../config.example.toml").replace(
        SIMULATE_BLOCK,
        "[clients.simulate]\nuserinfo_error = \"server_error\"",
    );
    let app = build_router(AppState::new(Config::from_toml(&config).unwrap()).unwrap());
    let tokens = tokens_for(&app, "openid").await;
    let info = userinfo(&app, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn custom_css_reaches_the_login_page() {
    let app = router_with("[ui]\ntitle = \"Acme Login\"\ncustom_css = \"body { outline: 1px solid red; }\"");
    let session = authorize(&app, "client_id=my-client").await;
    let page = get(&app, &format!("/login?session={session}")).await;
    assert!(page.body.contains("<title>Acme Login</title>"));
    assert!(page.body.contains("outline: 1px solid red"));
    assert!(!page.body.contains("unpkg.com"), "the page must not need the network");
}

#[test]
fn config_problems_are_reported() {
    let example = include_str!("../config.example.toml");
    assert!(Config::from_toml(&example.replace("active = true", "active = false")).is_err());
    assert!(Config::from_toml(&format!("use_tsl = true\n{example}")).is_err(), "typos are rejected");
    let duplicate = format!("{example}\n[[users]]\nid = \"1\"\nname = \"Eve\"\nemail = \"eve@example.com\"\n");
    assert!(Config::from_toml(&duplicate).unwrap_err().contains("duplicate"));
}

#[tokio::test]
async fn token_request_must_repeat_the_redirect_uri() {
    let app = router_with("strict_redirect_uri = true");
    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "1").await;
    let auth = basic("my-client", "my-secret");

    let missing = post_form(&app, "/oauth2/token", &format!("grant_type=authorization_code&code={code}"), Some(&auth)).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing.json()["error"], "invalid_request");

    // The failed attempt must not have burned the code.
    let ok = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_ENC}"),
        Some(&auth),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

#[tokio::test]
async fn failed_exchanges_do_not_burn_the_code() {
    let app = router_with("strict_redirect_uri = true");
    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "1").await;

    // Another client presents the code.
    let other = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&client_id=my-spa&code={code}&redirect_uri={REDIRECT_ENC}"),
        None,
    )
    .await;
    assert_eq!(other.json()["error"], "invalid_grant");

    // Wrong redirect_uri.
    let wrong = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={}", encode("http://evil.test/cb")),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(wrong.json()["error"], "invalid_grant");

    let ok = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_ENC}"),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

#[tokio::test]
async fn basic_credentials_are_decoded_without_form_parsing() {
    let app = router_replacing("client_secret = \"my-secret\"", "client_secret = \"ab&c+d=e\"");
    let attempt = |header: String| {
        let app = app.clone();
        async move {
            post_form(&app, "/oauth2/token", "grant_type=authorization_code&code=x", Some(&header)).await
        }
    };
    // A raw `&` and `=` must not truncate the secret (any error other than invalid_client is a pass).
    let raw = attempt(format!("Basic {}", BASE64_STANDARD.encode("my-client:ab&c%2Bd=e"))).await;
    assert_eq!(raw.json()["error"], "invalid_grant", "{}", raw.body);
    // The RFC form-encoded variant of the same secret.
    let encoded = attempt(format!("Basic {}", BASE64_STANDARD.encode("my-client:ab%26c%2Bd%3De"))).await;
    assert_eq!(encoded.json()["error"], "invalid_grant", "{}", encoded.body);
    let wrong = attempt(basic("my-client", "ab")).await;
    assert_eq!(wrong.json()["error"], "invalid_client");
}

#[tokio::test]
async fn narrowed_refresh_keeps_the_original_grant() {
    let app = router();
    let tokens = tokens_for(&app, "openid profile email").await;
    let auth = basic("my-client", "my-secret");

    let narrowed = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=refresh_token&refresh_token={}&scope=openid", tokens["refresh_token"].as_str().unwrap()),
        Some(&auth),
    )
    .await
    .json();
    assert_eq!(narrowed["scope"], "openid");

    // Asking for more than the narrowed token, but within the original grant, must work.
    let widened = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=refresh_token&refresh_token={}&scope=openid+email", narrowed["refresh_token"].as_str().unwrap()),
        Some(&auth),
    )
    .await;
    assert_eq!(widened.status, StatusCode::OK, "{}", widened.body);
    assert_eq!(widened.json()["scope"], "openid email");
}

#[tokio::test]
async fn a_session_yields_one_code_even_when_submitted_twice() {
    let app = router();
    let session = authorize(&app, "client_id=my-client").await;
    let form = format!("session={session}&user=1");
    let (a, b) = tokio::join!(
        post_form(&app, "/login", &form, None),
        post_form(&app, "/login", &form, None),
    );
    let successes = [&a, &b].iter().filter(|r| r.status == StatusCode::SEE_OTHER).count();
    assert_eq!(successes, 1, "a: {} b: {}", a.status, b.status);
}

#[tokio::test]
async fn a_bad_login_choice_keeps_the_session() {
    let app = router();
    let session = authorize(&app, "client_id=my-client").await;
    let bad = post_form(&app, "/login", &format!("session={session}&user=nobody"), None).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let retry = post_form(&app, "/login", &format!("session={session}&user=1"), None).await;
    assert_eq!(retry.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn dangerous_redirect_schemes_are_rejected() {
    let app = router();
    for uri in ["javascript:alert(1)", "data:text/html,hi", "JaVaScRiPt:alert(1)"] {
        let reply = get(&app, &format!("/oauth2/authorize?response_type=code&client_id=my-client&redirect_uri={}", encode(uri))).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(reply.location.is_none(), "{uri} must not redirect");
    }
}

#[tokio::test]
async fn registered_redirect_uris_are_enforced() {
    let app = router_replacing("name = \"My App\"", "name = \"My App\"\nredirect_uris = [\"http://localhost:3000/callback\"]");
    let ok = get(&app, &format!("/oauth2/authorize?response_type=code&client_id=my-client&redirect_uri={REDIRECT_ENC}")).await;
    assert_eq!(ok.location().path(), "/login");
    let other = get(&app, &format!("/oauth2/authorize?response_type=code&client_id=my-client&redirect_uri={}", encode("http://localhost:3000/other"))).await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    assert!(other.location.is_none() && other.body.contains("Unregistered redirect_uri"));

    let example = include_str!("../config.example.toml");
    let bad = example.replace("name = \"My App\"", "name = \"My App\"\nredirect_uris = [\"javascript:alert(1)\"]");
    assert!(Config::from_toml(&bad).unwrap_err().contains("redirect URI"));
}

#[tokio::test]
async fn userinfo_accepts_the_token_in_a_post_body() {
    let app = router();
    let tokens = tokens_for(&app, "openid").await;
    let token = tokens["access_token"].as_str().unwrap();
    let reply = post_form(&app, "/userinfo", &format!("access_token={token}"), None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json()["sub"], "1");
    let none = post_form(&app, "/userinfo", "other=1", None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn simulated_failures_come_after_request_validation() {
    let app = router_replacing(SIMULATE_BLOCK, "[clients.simulate]\ntoken_error = \"invalid_grant\"");
    let auth = basic("my-client", "my-secret");
    let malformed = post_form(&app, "/oauth2/token", "code=x", Some(&auth)).await;
    assert_eq!(malformed.json()["error"], "invalid_request");
    let no_code = post_form(&app, "/oauth2/token", "grant_type=authorization_code", Some(&auth)).await;
    assert_eq!(no_code.json()["error"], "invalid_request");
    let simulated = post_form(&app, "/oauth2/token", "grant_type=authorization_code&code=x", Some(&auth)).await;
    assert_eq!(simulated.json()["error_description"], "Simulated by the mock server configuration");
}

#[tokio::test]
async fn refresh_failures_can_be_simulated_alone() {
    let app = router_replacing(SIMULATE_BLOCK, "[clients.simulate]\nrefresh_error = \"server_error\"");
    let tokens = tokens_for(&app, "openid").await;
    let refresh = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=refresh_token&refresh_token={}", tokens["refresh_token"].as_str().unwrap()),
        Some(&basic("my-client", "my-secret")),
    )
    .await;
    assert_eq!(refresh.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn redirect_uri_is_not_checked_at_the_token_endpoint_by_default() {
    let app = router();
    let auth = basic("my-client", "my-secret");

    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "1").await;
    let missing = post_form(&app, "/oauth2/token", &format!("grant_type=authorization_code&code={code}"), Some(&auth)).await;
    assert_eq!(missing.status, StatusCode::OK, "{}", missing.body);

    let session = authorize(&app, "client_id=my-client").await;
    let code = login(&app, &session, "1").await;
    let other = post_form(
        &app,
        "/oauth2/token",
        &format!("grant_type=authorization_code&code={code}&redirect_uri={}", encode("http://elsewhere.test/cb")),
        Some(&auth),
    )
    .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.body);
}

#[tokio::test]
async fn strict_redirect_uri_can_be_set_per_client() {
    let auth = basic("my-client", "my-secret");
    let exchange_without_redirect_uri = |app: Router| {
        let auth = auth.clone();
        async move {
            let session = authorize(&app, "client_id=my-client").await;
            let code = login(&app, &session, "1").await;
            post_form(&app, "/oauth2/token", &format!("grant_type=authorization_code&code={code}"), Some(&auth)).await
        }
    };

    // Global on, the client opts out.
    let text = include_str!("../config.example.toml")
        .replacen("strict_redirect_uri = false", "strict_redirect_uri = true", 1)
        .replace("name = \"My App\"", "name = \"My App\"\nstrict_redirect_uri = false");
    let config = Config::from_toml(&text).unwrap();
    let opted_out = build_router(AppState::new(config).unwrap());
    assert_eq!(exchange_without_redirect_uri(opted_out).await.status, StatusCode::OK);

    // Global on, no override.
    let global = exchange_without_redirect_uri(router_with("strict_redirect_uri = true")).await;
    assert_eq!(global.status, StatusCode::BAD_REQUEST);

    // Global off, the client opts in.
    let strict = router_replacing("name = \"My App\"", "name = \"My App\"\nstrict_redirect_uri = true");
    let reply = exchange_without_redirect_uri(strict).await;
    assert_eq!(reply.json()["error"], "invalid_request");
}

/// Position of `needle` in `haystack`, panicking with the page if it is missing.
fn pos(haystack: &str, needle: &str) -> usize {
    haystack.find(needle).unwrap_or_else(|| panic!("{needle:?} not in page:\n{haystack}"))
}

async fn login_page_for(app: &Router, extra: &str) -> String {
    let session = authorize(app, &format!("client_id=my-client&{extra}")).await;
    get(app, &format!("/login?session={session}")).await.body
}

#[tokio::test]
async fn login_hint_highlights_the_matching_account() {
    let app = router();

    let plain = login_page_for(&app, "").await;
    assert!(pos(&plain, "Alice") < pos(&plain, "Bob"));
    assert!(!plain.contains("Suggested") && !plain.contains("Login hint"));

    // Matches by email, id and name, ignoring case and surrounding spaces.
    for hint in ["bob@example.com", "BOB@Example.com", "2", "bob", "%20bob%20"] {
        let page = login_page_for(&app, &format!("login_hint={hint}")).await;
        assert!(pos(&page, "Bob") < pos(&page, "Alice"), "hint {hint}: Bob should come first");
        assert!(page.contains("Suggested"), "hint {hint}");
        assert!(page.contains("Login hint") && !page.contains("no account matches"), "hint {hint}");
    }

    let none = login_page_for(&app, "login_hint=nobody%40example.com").await;
    assert!(pos(&none, "Alice") < pos(&none, "Bob"));
    assert!(none.contains("nobody@example.com") && none.contains("no account matches"));
    assert!(!none.contains("Suggested"));
}

#[tokio::test]
async fn login_hint_is_escaped_on_the_page() {
    let app = router();
    let page = login_page_for(&app, "login_hint=%3Cscript%3Ealert(1)%3C%2Fscript%3E").await;
    assert!(!page.contains("<script>alert(1)"), "the hint must be HTML-escaped");
    // askama escapes with numeric entities.
    assert!(page.contains("&#60;script&#62;"), "{page}");
}

#[tokio::test]
async fn login_hint_auto_mode_skips_the_picker() {
    let app = router_with("login_hint = \"auto\"");

    let reply = get(
        &app,
        &format!("/oauth2/authorize?response_type=code&client_id=my-client&state=st&scope=openid&login_hint=bob%40example.com&redirect_uri={REDIRECT_ENC}"),
    )
    .await;
    let location = reply.location();
    assert!(location.as_str().starts_with(REDIRECT), "should go straight back: {location}");
    assert_eq!(query(&location, "state").as_deref(), Some("st"));
    let tokens = exchange(&app, &query(&location, "code").unwrap()).await;
    assert_eq!(jwt_payload(tokens["id_token"].as_str().unwrap())["sub"], "2");

    // No match, or no hint, still shows the picker.
    for extra in ["login_hint=nobody", ""] {
        let reply = get(
            &app,
            &format!("/oauth2/authorize?response_type=code&client_id=my-client&{extra}&redirect_uri={REDIRECT_ENC}"),
        )
        .await;
        assert_eq!(reply.location().path(), "/login", "{extra:?}");
    }
}

#[tokio::test]
async fn login_hint_auto_mode_needs_exactly_one_match() {
    let dup = format!(
        "{}\n[[users]]\nid = \"3\"\nname = \"Bob\"\nemail = \"bob2@example.com\"\n",
        include_str!("../config.example.toml")
    )
    .replacen("login_hint = \"highlight\"", "login_hint = \"auto\"", 1);
    let app = build_router(AppState::new(Config::from_toml(&dup).unwrap()).unwrap());
    let reply = get(
        &app,
        &format!("/oauth2/authorize?response_type=code&client_id=my-client&login_hint=bob&redirect_uri={REDIRECT_ENC}"),
    )
    .await;
    assert_eq!(reply.location().path(), "/login", "two accounts named Bob are ambiguous");
}

#[tokio::test]
async fn login_hint_can_be_ignored() {
    let app = router_with("login_hint = \"ignore\"");
    let page = login_page_for(&app, "login_hint=bob%40example.com").await;
    assert!(pos(&page, "Alice") < pos(&page, "Bob"));
    assert!(!page.contains("Suggested") && !page.contains("Login hint"));
}
