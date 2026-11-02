# OAuth Mocker v0.2.0 design

Status: draft, written before the v0.2.0 rewrite. Update it when the code diverges.

## Goals

OAuth Mocker is a stand-in identity provider for local development and CI. It should behave like a
real OIDC provider closely enough that client libraries accept it, and be easy to break on purpose
so client error handling can be tested.

v0.2.0 goals:

- Spec-correct core: OAuth-shaped errors, a complete ID token, a truthful discovery document.
- Server-side login sessions instead of global cookies.
- Refresh tokens, PKCE, access-token expiry.
- Configurable scopes and claims, per-client token lifetimes.
- Error simulation for token, userinfo and authorize responses.
- A nicer login UI that works offline and can be restyled from `config.toml`.
- Move from Rocket to axum and split the single `main.rs` into modules.

## Non-goals

- Production use. There is no persistence, rate limiting or hardening.
- `/users` stays unauthenticated on purpose, it is a convenience for tests.
- Deferred, not rejected: CORS headers, `response_mode=form_post`, token introspection and revocation,
  dynamic client registration.

## Stack

| Concern    | Choice                                   | Why |
|------------|------------------------------------------|-----|
| HTTP       | axum 0.7 on tokio                        | Plain handlers and extractors, easy to test with `tower::ServiceExt::oneshot`, no macro-generated routes. |
| Templates  | askama 0.12, rendered to `Html<String>`  | No framework integration crate to keep in sync with axum versions. |
| JWT        | jsonwebtoken, RS256 only                 | Unchanged. Keys are parsed once at startup. |
| Hashing    | sha2                                     | `at_hash` and PKCE `S256`. |
| URLs       | url                                      | Correct query and fragment encoding for redirects. |

The Docker build image is `rust:1.86`, so code must not use language features newer than that
(for example let-chains).

## Module layout

```
src/
  main.rs        startup: load config, build router, serve
  app.rs         AppState, build_router()
  config.rs      config types, parsing, preset layering, validation, TTL resolution
  presets.rs     built-in presets (compiled in from presets/*.toml) and the TOML merge
  keys.rs        signing key, JWKS
  crypto.rs      token generation, at_hash, PKCE
  store.rs       TtlMap, the four in-memory stores, offline-access consents
  claims.rs      scope parsing, claim filtering, placeholders, ID and access token claims
  error.rs       OAuthError (JSON) and PageError (HTML)
  util.rs        base URL and issuer derivation, client redirects, response modes
  templates.rs   askama structs
  routes/
    discovery.rs   /, /users, /.well-known/*
    authorize.rs   /oauth2/authorize, /login (GET and POST)
    token.rs       /oauth2/token
    userinfo.rs    /userinfo
  tests.rs       end-to-end tests against the router
templates/       base.html, style.css, index.html, login.html, error.html
presets/         google.toml, okta.toml
examples/        a full config per preset, with realistic users
docs/DESIGN.md   this file
```

`AppState` is one `Arc` holding `Config`, `Keys` and `Stores`. Handlers are plain async functions
taking `State<AppState>`.

## Flows

### Authorization code flow

1. `GET /oauth2/authorize` validates the request.
   - Unknown `client_id`, or a missing, malformed or unregistered `redirect_uri`: render an HTML error
     page with status 400. Never redirect, as the target cannot be trusted. A `redirect_uri` must be
     absolute, without a fragment, and not use the `javascript`, `data` or `vbscript` scheme. A client
     may list exact `redirect_uris`, otherwise any URI is accepted.
   - Any other problem: redirect to the client with `error`, `error_description` and `state`.
     Covers `unsupported_response_type`, `invalid_scope`, `invalid_request`, and `login_required`
     for `prompt=none`.
   - On success, store a `LoginSession` (client, redirect URI, scopes, state, nonce, PKCE challenge,
     response mode) under a random id and redirect to `/login?session=<id>`. Sessions live 10 minutes.
2. `GET /login?session=<id>` shows the account picker and the simulate-error controls.
   With a `login_hint`, see Login hint below.
3. `POST /login` (form: `session`, and either `user` or `error`) consumes the session. The choice is
   validated against a peek, so a bad choice can be retried, and the session is then taken in one atomic
   step, so a double submit mints one code only.
   - `user`: create an `AuthCode` and redirect to the client with `code` and `state`.
   - `error`: redirect with that error code, to simulate a failing login.
4. `POST /oauth2/token` with `grant_type=authorization_code` checks the client, the PKCE verifier and,
   when `strict_redirect_uri` is on, the `redirect_uri` against a peek, then consumes the code and returns
   tokens. A request that fails those checks does not burn the code.

`strict_redirect_uri` (global, with a per-client override, default **off**) makes the token endpoint require
a `redirect_uri` identical to the one used at authorize, as RFC 6749 section 4.1.3 does. Off means the token
endpoint ignores `redirect_uri`, as v0.1 did. Turn it on to catch clients that would fail a real provider.
It is separate from a client's `redirect_uris` allow-list, which applies at authorize and is on only for
clients that list URIs.

Because the login state lives server-side under an unguessable session id, concurrent flows in one
browser no longer overwrite each other.

### Refresh

`grant_type=refresh_token` looks up the refresh token, checks the client, optionally narrows `scope`
to a subset, and returns fresh tokens. A narrowed `scope` applies to the new access and ID tokens only,
the rotated refresh token keeps the originally granted scopes (RFC 6749 section 6). With `tokens.rotate_refresh = true` (default) the old refresh
token is consumed and a new one returned. Without rotation the same token stays valid, and the
response repeats it unless `tokens.echo_refresh = false` (Google omits it). Refresh tokens are disabled
when the resolved `refresh_ttl` is 0.

Whether the code exchange returns a refresh token at all is decided when the code is issued:

- `tokens.refresh_when`: `always` (default), `offline_access` (the scope was granted) or
  `access_type_offline` (the authorize request had `access_type=offline`). In that last mode
  `access_type` must be `online` or `offline`, otherwise it is ignored.
- `tokens.refresh_on_first_consent_only`: a refresh token only the first time a user consents to a
  client, or when the request has `prompt=consent`. Consents live in memory until restart, and are
  only recorded for requests that asked for offline access.

### PKCE

- `code_challenge_method` is `plain` or `S256` and defaults to `plain`, as in RFC 7636.
- A challenge given at authorize requires a matching `code_verifier` at the token endpoint.
- Public clients (no `client_secret`) must send a challenge.

### Tokens

- Access and refresh tokens are opaque random strings with a prefix (`at_`, `rt_`), kept in memory
  with an expiry. Expired entries are never returned, and are freed by a sweep at most every 30 seconds. After `access_ttl`, `/userinfo` answers `401 invalid_token`.
- With `tokens.access_format = "jwt"` access tokens are JWTs signed like ID tokens, and still stored
  so `/userinfo` and expiry work the same. Claims come from `[tokens.access_claims]`, or by default
  `sub`, `aud` and `client_id` (the client id) and `scope`, as in RFC 9068. `iss`, `iat`, `exp` and `jti`
  are always set by the server. Configured claims may override `sub` and `aud`, Okta needs both.
- `[tokens.access_claims]` and `[tokens.id_claims]` string values take placeholders: `{client_id}`,
  `{user_id}`, `{email}`, `{name}`, `{issuer}` and `{scope}` (space separated). A value of exactly
  `"{scopes}"` becomes an array. `id_claims` are added after user claims and before registered claims,
  so they override user claims but never `iss`, `sub`, `aud` and the like.
- The ID token is issued only when the granted scopes include `openid`. Claims: `iss`, `sub`, `aud`,
  `exp`, `iat`, `auth_time`, `nonce` (when sent), `at_hash`, plus the scope-filtered user claims.
  Registered claims always win over user claims of the same name.
- With no `scope` parameter, `default_scope` applies (`openid profile email`).

### Issuer

The base URL is `issuer` from config if set, otherwise `<scheme>://<Host header>` where the scheme comes
from `use_tls`. The issuer is the base URL plus `issuer_path` (default empty, Okta uses `/oauth2/default`).
Endpoint URLs are the base URL plus their path from `[endpoints]`, and discovery is served at
`<issuer_path>/.well-known/openid-configuration`, as OIDC Discovery requires. Endpoint paths must start
with `/`, must not use axum's `{}` or `*` syntax, and must not collide with each other, with discovery
or with `/`, `/login` and `/users`.

## Presets

`preset = "<name>"` layers `presets/<name>.toml`, compiled into the binary, under the user's config.
Tables merge key by key and any other value from the user's file replaces the preset's, arrays included.
A preset sets behavior only, never `keys`, `clients`, `users` or `issuer`. The user's file is first parsed
on its own, so errors in it keep their line numbers. `oauth_mocker --print-preset <name>` prints one.

A preset turns on the provider's quirks by default, and each is a plain option the user can switch
back. Shipped: `google` and `okta`, see the comment at the top of each file. Planned, one preset per
process: Entra, Discord, Apple, Steam.

## Login hint

The authorize endpoint accepts `login_hint` (OIDC Core 3.1.2.1). A hint matches a user whose `id`, `name`
or `email` equals it, ignoring case and surrounding spaces. The top-level `login_hint` option picks the
behavior:

- `highlight` (default): the login page lists matching accounts first with a "Suggested" badge, and shows
  the hint. A hint that matches nobody is shown with "no account matches", and the picker is unchanged.
- `auto`: when exactly one account matches, the picker is skipped and the client gets its code straight
  away. No match, several matches or no hint show the picker. Useful for automated tests.
- `ignore`: the hint is not looked at.

`prompt=none` still answers `login_required` in every mode, the mock has no existing login to reuse.

## Scopes and claims

A user's releasable claims are `name`, `email` and everything under `[users.claims]`.

- Built-in scopes: `profile` releases `name`, `email` releases `email` and `email_verified`,
  `openid` and `offline_access` release nothing extra.
- `[scopes.<name>] claims = [...]` adds scopes or overrides built-in ones.
- A claim listed by at least one scope is released only when one of those scopes is granted.
  A claim listed by no scope is always released. This keeps old configs working, where every claim was
  always released.
- Clients may restrict requestable scopes with `scopes = [...]`. Unlisted scopes fail with `invalid_scope`.

## Errors

Token, userinfo and error-catcher responses use the RFC 6749 shape:
`{"error": "invalid_grant", "error_description": "..."}`, with `Cache-Control: no-store`.

| Code | Status |
|------|--------|
| `invalid_client`, `invalid_token` | 401, with a `WWW-Authenticate` header |
| `insufficient_scope` | 403 |
| `server_error` | 500 |
| `temporarily_unavailable` | 503 |
| everything else | 400 |

Client authentication accepts HTTP Basic (`client_secret_basic`) and form fields
(`client_secret_post`). Sending both is `invalid_request`. Basic credentials are percent-decoded, so a
raw `&` or `=` in a secret is safe.

`/userinfo` accepts `GET` and `POST`, with the token in a `Bearer` header or, for `POST`, an
`access_token` form field.

## Error simulation

Two mechanisms, both off by default:

- **Login page**: buttons to answer the authorization request with `access_denied` (prominent),
  `server_error`, `temporarily_unavailable`, `interaction_required` or `consent_required`.
- **Per client**, in `config.toml`. Malformed requests (no `grant_type`, no `code`) still get their real
  `invalid_request`, a simulated failure only replaces the outcome of an otherwise valid request:
  ```toml
  [clients.simulate]
  token_error = "invalid_grant"   # every token request fails with this code
  refresh_error = "server_error"  # refresh_token grants only, wins over token_error there
  token_delay_ms = 1500           # delay every token request
  userinfo_error = "invalid_token"
  ```

## UI

- Self-contained: the stylesheet is compiled into the binary, with no CDN requests.
- Light and dark themes through `prefers-color-scheme`. Colors, radii and fonts are CSS variables.
- Login page: request summary (client, redirect URI, login hint, requested scopes as chips), one card per
  user with avatar initial, email and claim badges, and a footer with deny and simulate controls.
  Accounts matching the `login_hint` come first, marked as suggested.
- Custom styling: `ui.title`, `ui.custom_css` (inline) and `ui.custom_css_file` are appended after the
  built-in stylesheet, so overriding the variables is usually enough.

## Configuration

Existing v0.1 files keep working, with one exception: an unknown key is now a startup error, which
catches typos. `OAUTH_MOCKER_CONFIG` selects the path, default `config.toml`. Problems print a message
and exit 1, there are no panics.

```toml
use_tls = false
preset = "google"                       # optional, see Presets
issuer = "http://localhost:8080"        # optional
issuer_path = ""                        # e.g. "/oauth2/default"
default_scope = "openid profile email"
strict_redirect_uri = false             # true: token endpoint requires a matching redirect_uri
login_hint = "highlight"                # "highlight", "auto" (skip the picker on one match) or "ignore"

[tokens]
code_ttl = 60
access_ttl = 3600
id_ttl = 3600
refresh_ttl = 86400                     # 0 disables refresh tokens
rotate_refresh = true
echo_refresh = true
refresh_when = "always"                 # "offline_access" or "access_type_offline"
refresh_on_first_consent_only = false
access_format = "opaque"                # or "jwt"
[tokens.access_claims]                  # optional, JWT access token claims
scp = "{scopes}"
[tokens.id_claims]                      # optional, extra ID token claims
azp = "{client_id}"

[endpoints]
authorize = "/oauth2/authorize"
token = "/oauth2/token"
userinfo = "/userinfo"
jwks = "/.well-known/jwks.json"

[ui]
title = "Mock Login"
custom_css = ":root { --accent: #d6336c; }"
custom_css_file = "theme.css"

[scopes.groups]
claims = ["groups"]

[[clients]]
client_id = "my-client"
client_secret = "my-secret"             # omit for a public client
name = "My App"
redirect_uris = ["http://localhost:3000/callback"]   # exact match, any URI when omitted
strict_redirect_uri = true              # per-client override of the global option
scopes = ["openid", "profile", "email", "groups"]
access_ttl = 600                        # per-client overrides: access_ttl, id_ttl, refresh_ttl

[[users]]
id = "1"
name = "Alice"
email = "alice@example.com"
[users.claims]
groups = ["admin", "user"]              # any JSON-compatible value
```

## Testing

`src/tests.rs` drives the router in-process with `tower::ServiceExt::oneshot`, no sockets.
Covered paths: discovery, the full code flow with ID token checks, PKCE success and failure,
refresh with rotation, access-token expiry, scope filtering, client authentication variants,
OAuth error shapes, simulated errors, and each preset through its example config. Running `cargo test` and `cargo clippy` is part of done.

## Migration notes for v0.1 users

- `/finish_login` (GET) is replaced by `POST /login`. It was an internal step, not a client-facing endpoint.
- The `login_*` cookies are gone.
- Error bodies are JSON instead of plain text.
- `id_token` is issued only with the `openid` scope, and `default_scope` applies when none is sent.
- Claims named by a scope are filtered by the granted scopes, see Scopes and claims.
- The token endpoint still ignores `redirect_uri` by default. Set `strict_redirect_uri = true` to enforce it.
- `client_secret` may be omitted, which makes the client public and PKCE mandatory.
- The listen address is no longer set through `ROCKET_ADDRESS` and `ROCKET_PORT`. Use
  `OAUTH_MOCKER_BIND` (`host:port`, default `127.0.0.1:8000`). The Docker image sets it to `0.0.0.0:8080`.

## Open questions

- Whether to add CORS headers, which browser-based public clients need to call the token and userinfo endpoints.
