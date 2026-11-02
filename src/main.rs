mod app;
mod claims;
mod config;
mod crypto;
mod error;
mod keys;
mod presets;
mod routes;
mod store;
mod templates;
mod util;

#[cfg(test)]
mod tests;

use app::{AppState, build_router};
use config::Config;

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, name] = args.as_slice()
        && flag == "--print-preset"
    {
        match presets::get(name) {
            Some(text) => print!("{text}"),
            None => fail(format!(
                "unknown preset `{name}`, known presets: {}",
                presets::names().join(", ")
            )),
        }
        return;
    }
    let path = std::env::var("OAUTH_MOCKER_CONFIG").unwrap_or_else(|_| "config.toml".into());
    let bind = std::env::var("OAUTH_MOCKER_BIND").unwrap_or_else(|_| "127.0.0.1:8000".into());

    let config = Config::load(&path).unwrap_or_else(|e| fail(e));
    let app = AppState::new(config).unwrap_or_else(|e| fail(e));
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| fail(format!("cannot bind {bind}: {e}")));

    println!("oauth_mocker listening on http://{bind} (config: {path})");
    axum::serve(listener, build_router(app))
        .await
        .unwrap_or_else(|e| fail(e));
}
