use crate::{
    config::SecurityConfig,
    types::Envelope,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir};
use tracing::{error, info};

pub struct Channels {
    tx: mpsc::Sender<Envelope>,
    security: SecurityConfig,
}

impl Channels {
    pub fn new(tx: mpsc::Sender<Envelope>, security: SecurityConfig) -> Self {
        Self { tx, security }
    }

    pub async fn run_repl(&self) {
        let mut reader = BufReader::new(io::stdin()).lines();
        info!("REPL started. Type messages to ingest.");

        while let Ok(Some(line)) = reader.next_line().await {
            let env = Envelope::new("repl", line);
            if let Err(e) = self.tx.send(env).await {
                error!("Failed to enqueue REPL message: {}", e);
                break;
            }
        }
    }

    pub async fn run_http_server(self: Arc<Self>, addr: &str) {
        let max_bytes = self.security.max_body_bytes;
        let assets_service = ServeDir::new("assets");
        let app = Router::new()
            .route("/ingest", post(ingest_handler))
            .route("/healthz", get(healthz_handler))
            .nest_service("/assets", assets_service)
            .layer(RequestBodyLimitLayer::new(max_bytes))
            .with_state(self);

        info!("HTTP Ingest server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

async fn healthz_handler() -> (StatusCode, Bytes) {
    (StatusCode::OK, Bytes::from_static(b"ok"))
}

fn check_ingest_auth(headers: &HeaderMap, sec: &SecurityConfig) -> Result<(), (StatusCode, String)> {
    if !sec.ingest_auth_enabled {
        return Ok(());
    }

    let expected = std::env::var(&sec.ingest_token_env)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Missing env {}", sec.ingest_token_env)))?;

    if expected.trim().is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Ingest token is empty".to_string()));
    }

    let header_name = sec.ingest_auth_header.to_ascii_lowercase();
    let provided = headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(&header_name))
        .and_then(|(_, v)| v.to_str().ok())
        .unwrap_or("");

    if provided != expected {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    Ok(())
}

async fn ingest_handler(
    State(state): State<Arc<Channels>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Envelope>, (StatusCode, String)> {
    check_ingest_auth(&headers, &state.security)?;

    let content = payload
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'content' field".to_string()))?;

    let env = Envelope::new("http", content);
    state
        .tx
        .send(env.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(env))
}
