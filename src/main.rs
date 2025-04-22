use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use jsonwebtoken::{EncodingKey, Header};
use rocket::form::Form;
use rocket::request::FromRequest;
use rocket::{Request, State};
use rocket::serde::json::Json;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use askama_rocket::Template; // Correct import for Askama Rocket integration
use uuid::Uuid;
#[macro_use]
extern crate rocket;

pub struct AuthCodeStore {
    store: Mutex<HashMap<String, (String, String, Option<String>)>>, // Updated to store client_id and nonce
}

impl AuthCodeStore {
    pub fn new() -> Self {
        AuthCodeStore {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, code: String, client_id: String, user_id: String, nonce: Option<String>) {
        if let Ok(mut store) = self.store.lock() {
            store.insert(code, (client_id, user_id, nonce));
        } else {
            eprintln!("Failed to acquire lock for AuthCodeStore");
        }
    }

    pub fn remove(&self, code: &str) -> Option<(String, String, Option<String>)> {
        match self.store.lock() {
            Ok(mut store) => store.remove(code),
            Err(_) => {
                eprintln!("Failed to acquire lock for AuthCodeStore");
                None
            }
        }
    }
}

pub struct AccessTokenStore {
    store: Mutex<HashMap<String, (String, String)>>,
}

impl AccessTokenStore {
    pub fn new() -> Self {
        AccessTokenStore {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, token: String, client_id: String, user_id: String) {
        if let Ok(mut store) = self.store.lock() {
            store.insert(token, (client_id, user_id));
        } else {
            eprintln!("Failed to acquire lock for AccessTokenStore");
        }
    }

    pub fn get(&self, token: &str) -> Option<(String, String)> {
        match self.store.lock() {
            Ok(store) => store.get(token).cloned(),
            Err(_) => {
                eprintln!("Failed to acquire lock for AccessTokenStore");
                None
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Client {
    client_id: String,
    client_secret: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct OAuthConfig {
    use_tls: Option<bool>,
    keys: Vec<JwtKey>,
    users: Vec<User>,
    clients: Vec<Client>,
}

// Updated User struct to handle claims as a HashMap
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct User {
    id: String,
    name: String,
    email: String,
    claims: HashMap<String, String>, // Changed back to HashMap to match the TOML structure
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct JwtKey {
    active: Option<bool>,
    kind: String,
    key: String,
    kid: String,
}

impl JwtKey {
    fn is_public(&self) -> bool {
        match self.kind.as_str() {
            "PEM_RS256" => true,
            _ => false,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct JwtPublicKey {
    kid: String,
    kty: String,
    e: String,
    n: String,
    alg: String,
    #[serde(rename = "use")]
    use_: String,
}

impl JwtPublicKey {
    fn encode_base64url(b: &rsa::BigUint) -> String {
        let bytes = b.to_bytes_be();
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }
    fn from_jwt_key(key: &JwtKey) -> Self {
        match key.kind.as_str() {
            "PEM_RS256" => {
                let private_key =
                    RsaPrivateKey::from_pkcs8_pem(&key.key).expect("Failed to parse PEM key");
                JwtPublicKey {
                    kid: key.kid.clone(),
                    kty: "RSA".to_string(),
                    e: JwtPublicKey::encode_base64url(&private_key.e()),
                    n: JwtPublicKey::encode_base64url(&private_key.n()),
                    alg: "RS256".to_string(),
                    use_: "sig".to_string(),
                }
            }
            _ => panic!("Unsupported key type"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct JwtBodyClaims {
    sub: String,
    name: String,
    email: String,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    aud: Option<String>,
    nonce: Option<String>,
    #[serde(flatten)]
    other_claims: Option<HashMap<String, String>>,
}

struct ActiveJwtKey {
    encoding_key: EncodingKey,
    header: Header,
}


impl ActiveJwtKey {
    fn new(key: &JwtKey) -> Self {
        let encoding_key = match key.kind.as_str() {
            "PEM_RS256" => {
                let pem = key.key.as_bytes();
                EncodingKey::from_rsa_pem(pem).expect("Failed to create RSA PEM key")
            }
            _ => panic!("Unsupported key type"),
        };
        let mut header = match key.kind.as_str() {
            "PEM_RS256" => Header::new(jsonwebtoken::Algorithm::RS256),
            _ => panic!("Unsupported key type"),
        };
        header.kid = Some(key.kid.clone());
        ActiveJwtKey {
            encoding_key,
            header,
        }
    }

    fn generate_id_token(&self, user: &User, client_id: &str, nonce: Option<&str>) -> Result<String, &'static str> {
        let claims = JwtBodyClaims {
            sub: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            iat: chrono::Utc::now().timestamp(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(3600)).timestamp(),
            nbf: None,
            aud: client_id.to_string().into(),
            nonce: nonce.map(|n| n.to_string()),
            other_claims: Some(user.claims.clone().into_iter().collect()),
        };
        jsonwebtoken::encode(
            &self.header.clone(),
            &claims,
            &self.encoding_key,
        )
        .map_err(|_| "Failed to generate ID token")
    }
}

#[launch]
fn rocket() -> _ {
    // Read and deserialize the 'users.toml' file
    let config: OAuthConfig =
        toml::from_str(&std::fs::read_to_string("config.toml").expect("Unable to read file"))
            .expect("Unable to parse TOML");
    // Create currently active key
    let active_key = config
        .keys
        .iter()
        .filter(|key| key.active.unwrap_or(false))
        .map(ActiveJwtKey::new)
        .next()
        .expect("No active key found");
    rocket::build()
        .manage(config)
        .manage(active_key)
        .manage(AuthCodeStore::new())
        .manage(AccessTokenStore::new())
        .mount(
            "/",
            routes![
                test,
                get_users,
                openid_config,
                jwks,
                login_ui,
                authorize_code_flow,
                token_code_grant,
                finish_login,
                userinfo // Add the userinfo route
            ],
        )
}

#[get("/")]
fn test() -> &'static str {
    "Hello, world!"
}

#[get("/users")]
fn get_users(users: &State<OAuthConfig>) -> Json<Vec<User>> {
    let users = users.inner().users.clone();
    Json(users)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct OpenIdConfig {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
}

#[get("/.well-known/openid-configuration")]
fn openid_config(
    host: &rocket::http::uri::Host,
    config: &State<OAuthConfig>,
) -> Json<OpenIdConfig> {
    let protocol = if config.inner().use_tls.unwrap_or(false) {
        "https"
    } else {
        "http"
    };
    let oid_config = OpenIdConfig {
        issuer: format!("{}://{}", protocol, host),
        authorization_endpoint: format!("{}://{}/oauth2/authorize", protocol, host),
        token_endpoint: format!("{}://{}/oauth2/token", protocol, host),
        userinfo_endpoint: format!("{}://{}/userinfo", protocol, host),
        jwks_uri: format!("{}://{}/.well-known/jwks.json", protocol, host),
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        response_types_supported: vec!["code".to_string(), "id_token".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
    };
    Json(oid_config)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct JwksResponse {
    keys: Vec<JwtPublicKey>,
}

#[get("/.well-known/jwks.json")]
fn jwks(config: &State<OAuthConfig>) -> Json<JwksResponse> {
    let keys = config
        .inner()
        .keys
        .iter()
        .filter(|key| key.is_public())
        .map(JwtPublicKey::from_jwt_key)
        .collect::<Vec<_>>();
    Json(JwksResponse { keys })
}

// Updated LoginCookies to use Vec<(String, String)> instead of HashMap
struct LoginCookies {
    client_id: String,
    redirect_uri: String,
    state: String, // Changed from Option<String> to String
}

// Updated LoginTemplate to transform Vec<(String, String)> into a renderable format
#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    users: Vec<User>,
    cookies: LoginCookies, // Updated cookies field
}

impl LoginTemplate {
    fn new(users: Vec<User>, cookies: LoginCookies) -> Self {
        LoginTemplate {
            users,
            cookies,
        }
    }
}

#[get("/login")] // Updated route for user login
fn login_ui(cookies: &rocket::http::CookieJar<'_>, config: &State<OAuthConfig>) -> LoginTemplate {
    let users = config.inner().users.clone();
    let login_cookies = LoginCookies {
        client_id: cookies.get("client_id").map(|c| c.value().to_string()).unwrap_or_default(),
        redirect_uri: cookies.get("redirect_uri").map(|c| c.value().to_string()).unwrap_or_default(),
        state: cookies.get("state").map(|c| c.value().to_string()).unwrap_or_default(), // Default to empty string
    };
    LoginTemplate::new(users, login_cookies)
}

// Updated the authorize endpoint to handle response_mode and nonce
#[get("/oauth2/authorize?response_type=code&<client_id>&<redirect_uri>&<scope>&<state>&<response_mode>&<nonce>")]
fn authorize_code_flow(
    client_id: &str,
    redirect_uri: Option<&str>,
    scope: Option<&str>,
    state: Option<&str>,
    response_mode: Option<&str>,
    nonce: Option<&str>,
    cookies: &rocket::http::CookieJar<'_>,
    config: &State<OAuthConfig>,
) -> Result<rocket::response::Redirect, &'static str> {
    // Validate client_id
    if !config.inner().clients.iter().any(|client| client.client_id == client_id) {
        return Err("Invalid client_id");
    }

    // Validate redirect_uri (mock validation for now)
    if client_id.is_empty() || redirect_uri.is_none() {
        return Err("Invalid client_id or redirect_uri");
    }

    // Store the necessary state in cookies
    cookies.add(rocket::http::Cookie::new("client_id", client_id.to_string()));
    if let Some(redirect_uri) = redirect_uri {
        cookies.add(rocket::http::Cookie::new("redirect_uri", redirect_uri.to_string()));
    }
    if let Some(scope) = scope {
        cookies.add(rocket::http::Cookie::new("scope", scope.to_string()));
    }
    if let Some(state) = state {
        cookies.add(rocket::http::Cookie::new("state", state.to_string()));
    }
    if let Some(nonce) = nonce {
        cookies.add(rocket::http::Cookie::new("nonce", nonce.to_string()));
    }

    // Redirect to the login UI for user selection
    Ok(rocket::response::Redirect::to("/login"))
}

// Suppressed unused variable warnings
#[get("/finish_login?<user>")]
fn finish_login(
    user: &str,
    cookies: &rocket::http::CookieJar<'_>,
    auth_code_store: &State<AuthCodeStore>,
    _config: &State<OAuthConfig>, // Prefixed with underscore
) -> Result<rocket::response::Redirect, &'static str> {
    // Retrieve stored state from cookies
    let client_id = cookies.get("client_id").map(|c| c.value()).ok_or("Missing client_id")?;
    let redirect_uri = cookies.get("redirect_uri").map(|c| c.value()).ok_or("Missing redirect_uri")?;
    let state = cookies.get("state").map(|c| c.value());
    let nonce = cookies.get("nonce").map(|c| c.value());

    // Validate user
    if !_config.inner().users.iter().any(|u| u.id == user) {
        return Err("Invalid user");
    }

    // Generate an authorization code
    let auth_code = Uuid::new_v4().to_string();

    // Store the authorization code with the client_id
    auth_code_store.insert(auth_code.clone(), client_id.to_string(), user.to_string(), nonce.map(|n| n.to_string()));

    // Redirect to the redirect_uri with the authorization code and state
    let mut redirect_url = format!("{}?code={}", redirect_uri, auth_code);
    if let Some(state) = state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Ok(rocket::response::Redirect::to(redirect_url))
}

use serde::Serialize;

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    id_token: String,
}

#[derive(FromForm)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
}

#[post("/oauth2/token", data = "<form>", format = "application/x-www-form-urlencoded")]
fn token_code_grant(
    form: Form<TokenRequest>,
    auth_code_store: &State<AuthCodeStore>,
    access_token_store: &State<AccessTokenStore>,
    active_key: &State<ActiveJwtKey>,
    config: &State<OAuthConfig>,
) -> Result<Json<TokenResponse>, &'static str> {
    let form = form.into_inner();

    if form.grant_type != "authorization_code" {
        return Err("Unsupported grant type");
    }

    // Validate client_id and client_secret
    if !config.inner().clients.iter().any(|client| client.client_id == form.client_id && client.client_secret == form.client_secret) {
        return Err("Invalid client_id or client_secret");
    }

    // Validate the authorization code
    if let Some((stored_client_id, user_id, nonce)) = auth_code_store.remove(&form.code) {
        if stored_client_id != form.client_id {
            return Err("Invalid client_id for the provided code");
        }

        // Generate an access token
        let access_token = Uuid::new_v4().to_string();
        
        // Generate an ID token using ActiveJwtKey
        let user = config
        .users
        .iter()
        .find(|u| u.id == user_id)
        .ok_or("User not found")?;

        // Store the access token
        access_token_store.insert(access_token.clone(), form.client_id.clone(), user_id.clone());

        let id_token = active_key.generate_id_token(user, &form.client_id, nonce.as_deref())?;

        // Return the response
        let response = TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            id_token,
        };

        Ok(Json(response))
    } else {
        Err("Invalid or expired authorization code")
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct UserInfoResponse {
    sub: String,
    name: String,
    email: String,
    #[serde(flatten)]
    other_claims: HashMap<String, String>,
}

// Custom request guard to extract the Authorization header
struct Authorization(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorization {
    
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> rocket::request::Outcome<Self,Self::Error>   {
        use rocket::outcome::Outcome;
        match req.headers().get_one("Authorization") {
            Some(header) if header.starts_with("Bearer ") => {
                Outcome::Success(Authorization(header[7..].to_string()))
            }
            _ => Outcome::Error((rocket::http::Status::Unauthorized, ()))
        }
    }
}

#[get("/userinfo")]
fn userinfo(
    auth: Authorization,
    access_token_store: &State<AccessTokenStore>,
    config: &State<OAuthConfig>,
) -> Result<Json<UserInfoResponse>, &'static str> {
    // Extract the token from the Authorization header
    let token = auth.0;

    // Validate the access token
    let (_, user_id) = access_token_store
        .get(&token)
        .ok_or("Invalid or expired access token")?;

    // Find the user associated with the client_id
    let user = config
        .users
        .iter()
        .find(|u| u.id == user_id)
        .ok_or("User not found")?;

    // Construct the userinfo response
    let response = UserInfoResponse {
        sub: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
        other_claims: user.claims.clone(),
    };

    Ok(Json(response))
}
