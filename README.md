# OAuth Mocker

OAuth Mocker is a lightweight mock server for simulating OAuth 2.0 and OpenID Connect flows. It is designed for testing and development purposes, allowing developers to emulate authentication and authorization flows without relying on external services.

## Features

- Supports OAuth 2.0 Authorization Code Flow.
- OpenID Connect (OIDC) support with ID tokens.
- Configurable users, clients, and keys via `config.toml`.
- JWKS endpoint for public key discovery.
- Login UI for user selection.
- UserInfo endpoint for retrieving user claims.

## Prerequisites

- Rust (latest stable version)
- Docker (optional, for containerized deployment)

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd oauth_mocker
   ```

2. Configure the server:
   - Edit the `config.toml` file to define users, clients, and keys.

3. Run the server:
   ```bash
   cargo run
   ```

4. Access the server:
   - Open your browser and navigate to `http://localhost:8000`.

## Endpoints

- `/`: Test endpoint.
- `/users`: Returns the list of configured users.
- `/.well-known/openid-configuration`: OpenID Connect configuration.
- `/.well-known/jwks.json`: JWKS endpoint for public key discovery.
- `/login`: Login UI for user selection.
- `/oauth2/authorize`: OAuth 2.0 authorization endpoint.
- `/oauth2/token`: OAuth 2.0 token endpoint.
- `/userinfo`: Returns user claims based on the provided access token.

## Docker Deployment

To run the server in a Docker container, use the prebuilt image from GitHub Container Registry.

1. Pull the Docker image:
   ```bash
   docker pull ghcr.io/karolis2011/oauth-mocker:latest
   ```

2. Run the container:
   ```bash
   docker run -it -v ./config.toml:/app/config.toml -p 8080:8080 ghcr.io/karolis2011/oauth-mocker:latest
   ```

## License

This project is licensed under the MIT License.
