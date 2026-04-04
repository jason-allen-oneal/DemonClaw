use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemonClawConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

impl Default for DemonClawConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_bind")]
    pub http_bind: String,
}

fn default_http_bind() -> String {
    "0.0.0.0:3000".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind: default_http_bind(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub ingest_auth_enabled: bool,
    #[serde(default = "default_ingest_header")]
    pub ingest_auth_header: String,
    #[serde(default = "default_ingest_token_env")]
    pub ingest_token_env: String,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

fn default_ingest_header() -> String {
    "x-demonclaw-token".to_string()
}

fn default_ingest_token_env() -> String {
    "DEMONCLAW_TOKEN".to_string()
}

fn default_max_body_bytes() -> usize {
    1_000_000
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            ingest_auth_enabled: false,
            ingest_auth_header: default_ingest_header(),
            ingest_token_env: default_ingest_token_env(),
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

impl DemonClawConfig {
    pub fn load_from_env() -> Self {
        // Minimal env-only config for now. We can add file-based config next.
        let mut cfg = Self::default();

        if let Ok(v) = std::env::var("DEMONCLAW_HTTP_BIND") {
            if !v.trim().is_empty() {
                cfg.server.http_bind = v;
            }
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_AUTH_ENABLED") {
            cfg.security.ingest_auth_enabled = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_AUTH_HEADER") {
            if !v.trim().is_empty() {
                cfg.security.ingest_auth_header = v.trim().to_ascii_lowercase();
            }
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_TOKEN_ENV") {
            if !v.trim().is_empty() {
                cfg.security.ingest_token_env = v;
            }
        }

        if let Ok(v) = std::env::var("DEMONCLAW_MAX_BODY_BYTES") {
            if let Ok(n) = v.trim().parse::<usize>() {
                cfg.security.max_body_bytes = n;
            }
        }

        cfg
    }
}
