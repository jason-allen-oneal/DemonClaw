use crate::{
    config::SecurityConfig, evidence::EvidenceLocker, memory::MemoryManager,
    security::SecurityPolicy, types::Envelope,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, Sse},
    routing::{get, post},
};
use futures::Stream;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::{broadcast, mpsc};
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir};
use tracing::{error, info, warn};

/// Simple fixed-window rate limiter state.
struct RateLimiter {
    max_requests: u64,
    window: Duration,
    window_start: Mutex<Instant>,
    count: AtomicU64,
}

impl RateLimiter {
    fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            window_start: Mutex::new(Instant::now()),
            count: AtomicU64::new(0),
        }
    }

    fn check(&self) -> bool {
        let mut start = self.window_start.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*start) >= self.window {
            *start = now;
            self.count.store(1, Ordering::SeqCst);
            true
        } else {
            let current = self.count.fetch_add(1, Ordering::SeqCst);
            current < self.max_requests
        }
    }
}

pub struct Channels {
    tx: mpsc::Sender<Envelope>,
    security: SecurityConfig,
    rate_limiter: Arc<RateLimiter>,
    evidence: EvidenceLocker,
    policy: SecurityPolicy,
    templates: tera::Tera,
    memory: Option<MemoryManager>,
    /// Event broadcaster: sends evidence events to all SSE subscribers.
    event_tx: broadcast::Sender<serde_json::Value>,
}

impl Channels {
    pub fn new(
        tx: mpsc::Sender<Envelope>,
        security: SecurityConfig,
        evidence: EvidenceLocker,
        policy: SecurityPolicy,
        memory: Option<MemoryManager>,
    ) -> Self {
        // Load templates from the templates/ directory relative to the working dir.
        let template_dir = std::env::var("DEMONCLAW_TEMPLATE_DIR")
            .map(|p| format!("{}/templates", p))
            .unwrap_or_else(|_| "templates".to_string());

        let templates = match tera::Tera::new(&format!("{}/*.html", template_dir)) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "Failed to load templates from {}: {}. Dashboard will be unavailable.",
                    template_dir, e
                );
                tera::Tera::default()
            }
        };

        // Event broadcast channel for SSE subscribers.
        let (event_tx, _event_rx) = broadcast::channel::<serde_json::Value>(256);

        Self {
            tx,
            security,
            rate_limiter: Arc::new(RateLimiter::new(60, 60)),
            evidence,
            policy,
            templates,
            memory,
            event_tx,
        }
    }

    /// Clone the event sender for publishing events from the agent loop.
    pub fn event_publisher(&self) -> broadcast::Sender<serde_json::Value> {
        self.event_tx.clone()
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
            .route("/dashboard/", get(dashboard_handler))
            .route("/dashboard/evidence", get(evidence_handler))
            .route("/dashboard/policy", get(policy_handler))
            .route("/dashboard/memory", get(memory_handler))
            .route("/dashboard/payloads", get(payloads_handler))
            .route("/api/status", get(api_status))
            .route("/api/evidence", get(api_evidence))
            .route("/api/evidence/verify", get(api_evidence_verify))
            .route("/api/policy", get(api_policy))
            .route("/api/events/stream", get(sse_events_handler))
            .route("/api/memory/search", get(api_memory_search))
            .nest_service("/assets", assets_service)
            .layer(RequestBodyLimitLayer::new(max_bytes))
            .with_state(self);

        info!("HTTP server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        if let Err(e) = axum::serve(listener, app).await {
            error!("HTTP server error: {}", e);
        }
    }
}

// --- Template rendering helper ---

fn render_template(
    templates: &tera::Tera,
    name: &str,
    ctx: &tera::Context,
) -> Result<String, (StatusCode, String)> {
    templates.render(name, ctx).map_err(|e| {
        error!("Template render error for '{}': {}", name, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
    })
}

// --- SSE event stream ---

async fn sse_events_handler(
    State(state): State<Arc<Channels>>,
) -> Sse<impl Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    let mut broadcast_rx = state.event_tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match broadcast_rx.recv().await {
                Ok(event) => {
                    yield Ok(axum::response::sse::Event::default()
                        .data(serde_json::to_string(&event).unwrap_or_default()));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Client is slow, continue receiving
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream)
}

// --- Dashboard page handlers ---

async fn dashboard_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let evidence_count = state
        .evidence
        .count()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let events = state
        .evidence
        .query_all(10)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verify = state
        .evidence
        .verify_chain()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut ctx = tera::Context::new();
    ctx.insert("page", &"dashboard");
    ctx.insert("evidence_count", &evidence_count);
    ctx.insert("events", &events);
    ctx.insert("chain_valid", &verify.is_valid);
    ctx.insert("tool_level", &format!("{:?}", state.policy.max_tool_level));
    ctx.insert("engagement_id", &state.policy.engagement_id);

    let html = render_template(&state.templates, "dashboard.html", &ctx)?;
    Ok(Html(html))
}

async fn evidence_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let events = state
        .evidence
        .query_all(100)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verify = state
        .evidence
        .verify_chain()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut ctx = tera::Context::new();
    ctx.insert("page", &"evidence");
    ctx.insert("events", &events);
    ctx.insert("verify", &verify);

    let html = render_template(&state.templates, "evidence.html", &ctx)?;
    Ok(Html(html))
}

async fn policy_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let pol = &state.policy;
    let mut ctx = tera::Context::new();
    ctx.insert("page", &"policy");

    // Build a serializable policy map for the template
    let policy_map: HashMap<&str, serde_json::Value> = {
        let mut m = HashMap::new();
        m.insert("engagement_id", serde_json::json!(&pol.engagement_id));
        m.insert(
            "require_engagement_context",
            serde_json::json!(pol.require_engagement_context),
        );
        m.insert(
            "allow_private_only",
            serde_json::json!(pol.allow_private_only),
        );
        m.insert(
            "max_tool_level",
            serde_json::json!(format!("{:?}", pol.max_tool_level)),
        );
        m.insert(
            "max_ports_per_scan",
            serde_json::json!(pol.max_ports_per_scan),
        );
        m.insert(
            "blocked_ports",
            serde_json::json!(pol.blocked_ports.iter().collect::<Vec<_>>()),
        );
        m.insert("allowed_cidrs", serde_json::json!(&pol.allowed_cidrs));
        m.insert(
            "allowed_domains",
            serde_json::json!(pol.allowed_domains.iter().collect::<Vec<_>>()),
        );
        m
    };
    ctx.insert("policy", &policy_map);

    let html = render_template(&state.templates, "policy.html", &ctx)?;
    Ok(Html(html))
}

async fn memory_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let mut ctx = tera::Context::new();
    ctx.insert("page", &"memory");
    ctx.insert("chunks", &Vec::<serde_json::Value>::new());
    ctx.insert("query", &"");
    ctx.insert("result_count", &0);

    let html = render_template(&state.templates, "memory.html", &ctx)?;
    Ok(Html(html))
}

async fn payloads_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let mut ctx = tera::Context::new();
    ctx.insert("page", &"payloads");

    // Discover available payloads from the payloads/ directory
    let payloads = discover_payloads();
    ctx.insert("payloads", &payloads);

    let html = render_template(&state.templates, "payloads.html", &ctx)?;
    Ok(Html(html))
}

/// Discover available WASM payloads from the payloads/ directory.
fn discover_payloads() -> Vec<serde_json::Value> {
    let payload_dir = std::path::Path::new("payloads");
    if !payload_dir.is_dir() {
        return Vec::new();
    }

    let mut payloads = Vec::new();
    if let Ok(entries) = std::fs::read_dir(payload_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let wasm_path = path
                .join("target/wasm32-wasip1/release")
                .join(format!("{}.wasm", name));
            let exists = wasm_path.exists();
            let size = if exists {
                std::fs::metadata(&wasm_path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
            payloads.push(serde_json::json!({
                "name": name,
                "wasm_exists": exists,
                "wasm_size": size,
            }));
        }
    }
    payloads.sort_by(|a, b| {
        let a_name = a["name"].as_str().unwrap_or("");
        let b_name = b["name"].as_str().unwrap_or("");
        a_name.cmp(b_name)
    });
    payloads
}

// --- JSON API handlers ---

async fn healthz_handler() -> (StatusCode, Bytes) {
    (StatusCode::OK, Bytes::from_static(b"ok"))
}

fn check_ingest_auth(
    headers: &HeaderMap,
    sec: &SecurityConfig,
) -> Result<(), (StatusCode, String)> {
    if !sec.ingest_auth_enabled {
        return Ok(());
    }

    let expected = std::env::var(&sec.ingest_token_env).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Missing env {}", sec.ingest_token_env),
        )
    })?;

    if expected.trim().is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Ingest token is empty".to_string(),
        ));
    }

    let header_name = sec.ingest_auth_header.to_ascii_lowercase();
    let provided = headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(&header_name))
        .and_then(|(_, v)| v.to_str().ok())
        .unwrap_or("");

    // Constant-time comparison to prevent timing attacks
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    Ok(())
}

/// Constant-time byte comparison to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

async fn ingest_handler(
    State(state): State<Arc<Channels>>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Envelope>, (StatusCode, String)> {
    // Rate limit check
    if !state.rate_limiter.check() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded".to_string(),
        ));
    }

    check_ingest_auth(&headers, &state.security)?;

    let content = payload
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing 'content' field".to_string(),
            )
        })?;

    let env = Envelope::new("http", content);
    state
        .tx
        .send(env.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Broadcast the ingest event to SSE subscribers
    let _ = state.event_tx.send(serde_json::json!({
        "type": "envelope.received",
        "id": env.id.to_string(),
        "source": env.source,
        "content": env.content,
        "timestamp": env.received_at.to_rfc3339(),
    }));

    Ok(Json(env))
}

async fn api_status(
    State(state): State<Arc<Channels>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let evidence_count = state
        .evidence
        .count()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let latest_events = state
        .evidence
        .query_all(5)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "operational",
        "evidence_count": evidence_count,
        "latest_events": latest_events,
        "policy": {
            "engagement_id": state.policy.engagement_id,
            "max_tool_level": format!("{:?}", state.policy.max_tool_level),
            "allow_private_only": state.policy.allow_private_only,
        }
    })))
}

async fn api_evidence(
    State(state): State<Arc<Channels>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let events = state
        .evidence
        .query_all(50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "events": events })))
}

async fn api_evidence_verify(
    State(state): State<Arc<Channels>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let verify = state
        .evidence
        .verify_chain()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "is_valid": verify.is_valid,
        "total_events": verify.total_events,
        "valid_events": verify.valid_events,
        "broken_links": verify.broken_links,
        "hash_mismatches": verify.hash_mismatches,
    })))
}

async fn api_policy(
    State(state): State<Arc<Channels>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let pol = &state.policy;
    Ok(Json(serde_json::json!({
        "engagement_id": pol.engagement_id,
        "require_engagement_context": pol.require_engagement_context,
        "allow_private_only": pol.allow_private_only,
        "max_tool_level": format!("{:?}", pol.max_tool_level),
        "max_ports_per_scan": pol.max_ports_per_scan,
        "blocked_ports": pol.blocked_ports.iter().collect::<Vec<_>>(),
        "allowed_cidrs": pol.allowed_cidrs,
        "allowed_domains": pol.allowed_domains.iter().collect::<Vec<_>>(),
    })))
}

async fn api_memory_search(
    State(state): State<Arc<Channels>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let query = params.get("q").map(|s| s.as_str()).unwrap_or("");
    if query.is_empty() {
        return Ok(Json(serde_json::json!({
            "query": "",
            "chunks": [],
            "count": 0,
        })));
    }

    let Some(ref memory) = state.memory else {
        return Ok(Json(serde_json::json!({
            "query": query,
            "chunks": [],
            "count": 0,
            "error": "Memory manager not available (no database connection)",
        })));
    };

    match memory.hybrid_retrieve(query, 10).await {
        Ok(matches) => {
            let chunks: Vec<serde_json::Value> = matches
                .into_iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.id.to_string(),
                        "content": m.content,
                        "metadata": m.metadata,
                        "similarity": m.similarity,
                    })
                })
                .collect();
            Ok(Json(serde_json::json!({
                "query": query,
                "chunks": chunks,
                "count": chunks.len(),
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({
            "query": query,
            "chunks": [],
            "count": 0,
            "error": e.to_string(),
        }))),
    }
}
