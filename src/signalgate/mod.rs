//! SignalGate - Semantic routing with upstream security
//! Ported from SignalGate Python repo - upstream allowlist, user forwarding, security gates

use anyhow::{Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct SignalGate {
    config: SignalGateConfig,
    client: Client,
}

#[derive(Debug, Clone)]
pub struct SignalGateConfig {
    pub llm_base_url: String,
    pub llm_api_key: String,
    pub model: String,
    pub upstream_allowlist: HashMap<String, Vec<String>>,
    pub upstream_allow_http: bool,
    pub user_forward_mode: UserForwardMode,
    pub user_hash_salt: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum UserForwardMode {
    Drop,
    #[default]
    Hash,
    Passthrough,
}

impl UserForwardMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "drop" => UserForwardMode::Drop,
            "passthrough" => UserForwardMode::Passthrough,
            _ => UserForwardMode::Hash,
        }
    }

    pub fn forward_user(&self, user: Option<&str>, salt: &str) -> Option<String> {
        let user = user?;
        match self {
            UserForwardMode::Drop => None,
            UserForwardMode::Passthrough => Some(user.to_string()),
            UserForwardMode::Hash => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(format!("{}:{}", salt, user).as_bytes());
                Some(format!("{:x}", hasher.finalize()))
            }
        }
    }
}

impl Default for SignalGateConfig {
    fn default() -> Self {
        Self {
            llm_base_url: "https://api.openai.com/v1".to_string(),
            llm_api_key: String::new(),
            model: "gpt-4o".to_string(),
            upstream_allowlist: HashMap::new(),
            upstream_allow_http: false,
            user_forward_mode: UserForwardMode::Hash,
            user_hash_salt: String::new(),
        }
    }
}

impl SignalGateConfig {
    pub fn load_from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(v) = std::env::var("SIGNALGATE_BASE_URL") {
            cfg.llm_base_url = v;
        }

        if let Ok(v) = std::env::var("SIGNALGATE_API_KEY") {
            cfg.llm_api_key = v;
        }

        if let Ok(v) = std::env::var("SIGNALGATE_MODEL") {
            cfg.model = v;
        }

        if let Ok(v) = std::env::var("SIGNALGATE_UPSTREAM_ALLOW_HTTP") {
            cfg.upstream_allow_http =
                matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        if let Ok(v) = std::env::var("SIGNALGATE_UPSTREAM_ALLOWLIST") {
            // Format: provider1=url1,url2;provider2=url3
            for entry in v.split(';') {
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
        }

        if let Ok(v) = std::env::var("SIGNALGATE_USER_FORWARD_MODE") {
            cfg.user_forward_mode = UserForwardMode::parse(&v);
        }

        if let Ok(v) = std::env::var("SIGNALGATE_USER_SALT") {
            cfg.user_hash_salt = v;
        }

        info!(
            "SignalGate config loaded: base_url={} model={} allow_http={}",
            cfg.llm_base_url, cfg.model, cfg.upstream_allow_http
        );

        cfg
    }

    fn validate_upstream_url(&self, url: &str, provider: &str) -> Result<()> {
        let parsed = Url::parse(url)?;

        if parsed.scheme() != "https" && !self.upstream_allow_http {
            bail!(
                "Insecure upstream scheme for {}: {}",
                provider,
                parsed.scheme()
            );
        }

        if let Some(allowed) = self.upstream_allowlist.get(provider)
            && let Some(host) = parsed.host_str()
            && !allowed.iter().any(|a| a == host || url.starts_with(a))
        {
            bail!("Upstream host not allowlisted for {}: {}", provider, host);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Intent {
    Query,
    Command,
    AttackPayload,
    Unknown,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Deserialize)]
struct ChatMessageResponse {
    content: String,
}

impl SignalGate {
    pub fn new(config: SignalGateConfig) -> Result<Self> {
        config.validate_upstream_url(&config.llm_base_url, "default")?;

        crate::tls::ensure_crypto_provider_installed();

        info!("SignalGate semantic routing proxy initialized.");
        Ok(Self {
            config,
            client: Client::new(),
        })
    }

    /// Fast, lightweight intent classification via LLM
    pub async fn classify_intent(&self, input: &str, user: Option<&str>) -> Result<Intent> {
        info!("SignalGate classifying intent for: {}", input);

        if let Some(local) = classify_locally(input) {
            return Ok(local);
        }

        // If no upstream key is configured, fall back to query semantics.
        // (Keeps DemonClaw usable offline while still allowing deterministic command routing.)
        if self.config.llm_api_key.trim().is_empty() {
            return Ok(Intent::Query);
        }

        // Apply user forwarding policy
        let forwarded_user = self
            .config
            .user_forward_mode
            .forward_user(user, &self.config.user_hash_salt);

        if let Some(ref u) = forwarded_user {
            info!("SignalGate: user forwarded as hash={}", &u[..16]);
        }

        let prompt = format!(
            "Classify the following user input into one of these intents: Query, Command, AttackPayload. \
            Only respond with the exact word of the intent. \
            Input: '{}'",
            input
        );

        let req = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            temperature: 0.0,
        };

        let res = self
            .client
            .post(format!("{}/chat/completions", self.config.llm_base_url))
            .bearer_auth(&self.config.llm_api_key)
            .json(&req)
            .send()
            .await?;

        if res.status().is_success() {
            let chat_res: ChatResponse = res.json().await?;
            if let Some(choice) = chat_res.choices.first() {
                let content = choice.message.content.trim();
                return Ok(match content {
                    "Query" => Intent::Query,
                    "Command" => Intent::Command,
                    "AttackPayload" => Intent::AttackPayload,
                    _ => Intent::Unknown,
                });
            }
        } else {
            warn!(
                "Failed to classify intent, LLM returned status: {}",
                res.status()
            );
        }

        Ok(Intent::Unknown)
    }

    /// Get the validated upstream base URL
    pub fn upstream_url(&self) -> &str {
        &self.config.llm_base_url
    }

    /// Check if a provider URL is allowlisted
    pub fn is_provider_allowed(&self, provider: &str, url: &str) -> bool {
        self.config.validate_upstream_url(url, provider).is_ok()
    }
}

fn classify_locally(input: &str) -> Option<Intent> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(Intent::Unknown);
    }
    if trimmed.starts_with("payload:") {
        return Some(Intent::AttackPayload);
    }
    if matches!(trimmed, "memory:compact" | "HEARTBEAT") {
        return Some(Intent::Command);
    }

    // Active defense commands (local deterministic parsing).
    if trimmed.starts_with("scan:")
        || trimmed.starts_with("remediate:")
        || trimmed.starts_with("verify")
        || trimmed.starts_with("intrusion:")
    {
        return Some(Intent::Command);
    }

    None
}
