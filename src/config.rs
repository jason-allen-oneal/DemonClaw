use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::{
    security::{SecurityPolicy, ToolLevel},
    signalgate::{SignalGateConfig, UserForwardMode},
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DemonClawConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub signalgate: SignalGateSettings,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub ghostmcp: GhostMcpConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalGateSettings {
    #[serde(default = "default_signalgate_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_signalgate_model")]
    pub model: String,
    #[serde(default)]
    pub upstream_allowlist: String,
    #[serde(default)]
    pub upstream_allow_http: bool,
    #[serde(default = "default_user_forward_mode")]
    pub user_forward_mode: String,
    #[serde(default)]
    pub user_hash_salt: String,
}

fn default_signalgate_base_url() -> String {
    "https://api.openai.com/v1".to_string()
}

fn default_signalgate_model() -> String {
    "gpt-4o".to_string()
}

fn default_user_forward_mode() -> String {
    "hash".to_string()
}

impl Default for SignalGateSettings {
    fn default() -> Self {
        Self {
            base_url: default_signalgate_base_url(),
            api_key: String::new(),
            model: default_signalgate_model(),
            upstream_allowlist: String::new(),
            upstream_allow_http: false,
            user_forward_mode: default_user_forward_mode(),
            user_hash_salt: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    #[serde(default)]
    pub scheduler_jobs: Vec<ScheduledJobConfig>,
    #[serde(default = "default_event_buffer")]
    pub event_buffer: usize,
    #[serde(default = "default_max_concurrent_payloads")]
    pub max_concurrent_payloads: usize,
}

fn default_database_url() -> String {
    "postgres://localhost/demonclaw".to_string()
}

fn default_scheduler_interval_secs() -> u64 {
    60
}

fn default_event_buffer() -> usize {
    256
}

fn default_max_concurrent_payloads() -> usize {
    4
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            database_url: default_database_url(),
            scheduler_interval_secs: default_scheduler_interval_secs(),
            scheduler_jobs: Vec::new(),
            event_buffer: default_event_buffer(),
            max_concurrent_payloads: default_max_concurrent_payloads(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJobConfig {
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub interval_secs: Option<u64>,
    #[serde(default)]
    pub cron: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub include_request_spans: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            include_request_spans: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GhostMcpConfig {
    #[serde(default)]
    pub auto_approve: bool,
}

impl DemonClawConfig {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::load_from_file_if_present()?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn load_from_file_if_present() -> Result<Self> {
        let path = std::env::var("DEMONCLAW_CONFIG")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "demonclaw.json".to_string());

        let path_ref = Path::new(&path);
        if !path_ref.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path_ref)
            .with_context(|| format!("failed to read config file {}", path_ref.display()))?;
        let cfg = serde_json::from_str::<Self>(&raw)
            .with_context(|| format!("failed to parse config file {}", path_ref.display()))?;
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("DEMONCLAW_HTTP_BIND")
            && !v.trim().is_empty()
        {
            self.server.http_bind = v;
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_AUTH_ENABLED") {
            self.security.ingest_auth_enabled = parse_bool(&v);
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_AUTH_HEADER")
            && !v.trim().is_empty()
        {
            self.security.ingest_auth_header = v.trim().to_ascii_lowercase();
        }

        if let Ok(v) = std::env::var("DEMONCLAW_INGEST_TOKEN_ENV")
            && !v.trim().is_empty()
        {
            self.security.ingest_token_env = v;
        }

        if let Ok(v) = std::env::var("DEMONCLAW_MAX_BODY_BYTES")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            self.security.max_body_bytes = n;
        }

        if let Ok(v) = std::env::var("DATABASE_URL")
            && !v.trim().is_empty()
        {
            self.runtime.database_url = v;
        }

        if let Ok(v) = std::env::var("DEMONCLAW_SCHEDULER_INTERVAL_SECS")
            && let Ok(n) = v.trim().parse::<u64>()
        {
            self.runtime.scheduler_interval_secs = n;
        }

        if let Ok(v) = std::env::var("DEMONCLAW_EVENT_BUFFER")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            self.runtime.event_buffer = n;
        }

        if let Ok(v) = std::env::var("DEMONCLAW_MAX_CONCURRENT_PAYLOADS")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            self.runtime.max_concurrent_payloads = n.max(1);
        }

        if let Ok(v) = std::env::var("DEMONCLAW_LOG_LEVEL")
            && !v.trim().is_empty()
        {
            self.logging.level = v.trim().to_ascii_lowercase();
        }

        if let Ok(v) = std::env::var("SIGNALGATE_BASE_URL") {
            self.signalgate.base_url = v;
        }
        if let Ok(v) = std::env::var("SIGNALGATE_API_KEY") {
            self.signalgate.api_key = v;
        }
        if let Ok(v) = std::env::var("SIGNALGATE_MODEL") {
            self.signalgate.model = v;
        }
        if let Ok(v) = std::env::var("SIGNALGATE_UPSTREAM_ALLOW_HTTP") {
            self.signalgate.upstream_allow_http = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("SIGNALGATE_UPSTREAM_ALLOWLIST") {
            self.signalgate.upstream_allowlist = v;
        }
        if let Ok(v) = std::env::var("SIGNALGATE_USER_FORWARD_MODE") {
            self.signalgate.user_forward_mode = v;
        }
        if let Ok(v) = std::env::var("SIGNALGATE_USER_SALT") {
            self.signalgate.user_hash_salt = v;
        }

        if let Ok(v) = std::env::var("GHOSTMCP_AUTO_APPROVE") {
            self.ghostmcp.auto_approve = parse_bool(&v);
        }
    }

    pub fn signalgate_config(&self) -> SignalGateConfig {
        let mut cfg = SignalGateConfig {
            llm_base_url: self.signalgate.base_url.clone(),
            llm_api_key: self.signalgate.api_key.clone(),
            model: self.signalgate.model.clone(),
            upstream_allow_http: self.signalgate.upstream_allow_http,
            user_forward_mode: UserForwardMode::parse(&self.signalgate.user_forward_mode),
            user_hash_salt: self.signalgate.user_hash_salt.clone(),
            ..SignalGateConfig::default()
        };

        for entry in self.signalgate.upstream_allowlist.split(';') {
            let mut parts = entry.split('=');
            if let Some(provider) = parts.next() {
                let urls: Vec<String> = parts
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !urls.is_empty() {
                    cfg.upstream_allowlist
                        .insert(provider.trim().to_string(), urls);
                }
            }
        }

        cfg
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        let mut policy = SecurityPolicy::load_from_env();
        if let Ok(v) = std::env::var("DEMONCLAW_MAX_TOOL_LEVEL") {
            policy.max_tool_level = ToolLevel::parse(&v);
        }
        policy
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
