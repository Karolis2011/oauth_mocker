# OAuth Mocker

OAuth Mocker is a lightweight mock server for simulating OAuth 2.0 and OpenID Connect flows. It is designed for testing and development purposes, allowing developers to emulate authentication and authorization flows without relying on external services.

> Not for production use: everything lives in memory and nothing is hardened.

## Features

- OAuth 2.0 authorization code flow with refresh tokens and PKCE (`S256` and `plain`), including public clients.
- OpenID Connect: ID tokens (`iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash`), discovery document, JWKS and UserInfo.
- Scopes with configurable claims, custom scopes, per-client allowed scopes.
- Access, ID and refresh token lifetimes, globally or per client. Access tokens really expire.
- Spec-shaped JSON errors (`{"error": "invalid_grant", ...}`) and error redirects.
- Error simulation: deny or fail a login from the login page, or make a client's token and userinfo requests fail or stall.
- `login_hint` support: highlight the matching account, or skip the picker entirely.
- Account picker login page that works offline, follows the system light or dark theme, and can be restyled from `config.toml`.
- Everything configured in one `config.toml`: users, clients, keys, scopes, tokens, UI.

## Getting started

You need a recent stable Rust toolchain, or Docker.

1. Create a config. The example is ready to run and includes a test signing key:
   ```bash
   cp config.example.toml config.toml
   ```
2. Run the server:
   ```bash
   cargo run
   ```
3. Open `http://localhost:8000`. The start page lists the endpoints and configured clients.

Point your application at `http://localhost:8000/.well-known/openid-configuration`.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `OAUTH_MOCKER_CONFIG` | `config.toml` | Path of the configuration file |
| `OAUTH_MOCKER_BIND` | `127.0.0.1:8000` | Address to listen on, `host:port` |

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/` | Start page with endpoints and clients |
| `/users` | The configured users as JSON (intentionally unauthenticated) |
| `/.well-known/openid-configuration` | OpenID Connect discovery |
| `/.well-known/jwks.json` | Public signing keys |
| `/oauth2/authorize` | Authorization endpoint (`response_type=code`) |
| `/login` | Account picker the authorize endpoint redirects to |
| `/oauth2/token` | Token endpoint: `authorization_code` and `refresh_token` grants |
| `/userinfo` | Claims for an access token with the `openid` scope |

Clients authenticate with HTTP Basic or with `client_id` and `client_secret` in the form body.
A client without a `client_secret` is public and must send a PKCE `code_challenge`.

## Configuration

See [config.example.toml](config.example.toml) for every option with its default, and
[docs/DESIGN.md](docs/DESIGN.md) for how the server behaves. The essentials:

```toml
[tokens]
access_ttl = 3600
refresh_ttl = 86400            # 0 disables refresh tokens

[ui]
title = "Acme Login"
custom_css = ":root { --accent: #d6336c; }"   # or custom_css_file = "theme.css"

[scopes.groups]                # a claim named by a scope is only released when it is granted
claims = ["groups"]

[[clients]]
client_id = "my-client"
client_secret = "my-secret"

[[users]]
id = "1"
name = "Alice"
email = "alice@example.com"
[users.claims]
groups = ["admin", "user"]
```

### Strict `redirect_uri`

By default the token endpoint ignores `redirect_uri`. Set `strict_redirect_uri = true` (globally, or per
client) to require one identical to the authorize request, as RFC 6749 does. A client can also list
exact `redirect_uris`, which the authorize endpoint then enforces for that client.

### Login hint

`login_hint` on the authorize request (matched against a user's id, name or email, ignoring case) puts the
matching account first on the login page, marked as suggested. Set `login_hint = "auto"` to skip the
picker when exactly one account matches, handy for automated tests, or `"ignore"` to turn it off.

### Simulating failures

On the login page, **Deny access** answers the authorization request with `access_denied`, and
*Simulate another error response* offers `server_error`, `temporarily_unavailable` and more.
For the token and userinfo endpoints, set this on a client:

```toml
[clients.simulate]
token_error = "invalid_grant"
refresh_error = "server_error"   # refresh grants only
token_delay_ms = 1500
userinfo_error = "invalid_token"
```

### Restyling

The login page colors, radius and fonts are CSS variables (`--accent`, `--bg`, `--surface`, ...).
Set `ui.custom_css` or `ui.custom_css_file` to override them, see the top of
[templates/style.css](templates/style.css) for the list.

## Docker

Use the prebuilt image from GitHub Container Registry. It listens on port 8080.

```bash
docker pull ghcr.io/karolis2011/oauth-mocker:latest
docker run -it -v ./config.toml:/app/config.toml -p 8080:8080 ghcr.io/karolis2011/oauth-mocker:latest
```

When the mock is reachable under a different name than the one your app sees (a container network
alias, a TLS proxy), set `issuer` in `config.toml`, or `use_tls = true` to make generated URLs `https`.

## Development

```bash
cargo test      # end-to-end tests that drive the router in-process
cargo clippy --all-targets
```

## Upgrading from 0.1

See the migration notes in [docs/DESIGN.md](docs/DESIGN.md#migration-notes-for-v01-users).

## License

This project is licensed under the MIT License.
