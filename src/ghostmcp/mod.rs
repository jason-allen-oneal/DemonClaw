use std::{
    collections::{HashMap, HashSet},
    env,
    sync::Arc,
};

use anyhow::{Result, bail};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Default)]
pub struct OutboundRequest {
    pub destination: String,
    pub action_desc: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// The Model Context Protocol server, embedded as the secure human-AI handshake.
pub struct GhostMcp {
    approved_actions: Arc<RwLock<HashSet<String>>>,
    secret_store: Arc<RwLock<HashMap<String, String>>>,
}

impl Default for GhostMcp {
    fn default() -> Self {
        Self::new()
    }
}

impl GhostMcp {
    pub fn new() -> Self {
        info!("GhostMCP (Authorization Boundary) initialized.");
        Self {
            approved_actions: Arc::new(RwLock::new(HashSet::new())),
            secret_store: Arc::new(RwLock::new(load_secrets_from_env())),
        }
    }

    /// Triggers the human-AI handshake for destructive tests or state-altering scans.
    pub async fn authorize_action(&self, action_desc: &str) -> Result<bool> {
        info!("GhostMCP Requesting authorization for: {}", action_desc);

        if !requires_human_approval(action_desc) {
            self.approved_actions
                .write()
                .await
                .insert(action_desc.to_string());
            return Ok(true);
        }

        let auto_approve = env::var("GHOSTMCP_AUTO_APPROVE")
            .map(|val| val.eq_ignore_ascii_case("true") || val == "1")
            .unwrap_or(false);

        let token_match = match (
            env::var("GHOSTMCP_APPROVAL_TOKEN"),
            env::var("GHOSTMCP_HUMAN_TOKEN"),
        ) {
            (Ok(expected), Ok(provided)) => !expected.trim().is_empty() && expected == provided,
            _ => false,
        };

        let action_allowlisted = env::var("GHOSTMCP_ALLOWED_ACTIONS")
            .ok()
            .map(|actions| {
                actions
                    .split(',')
                    .map(str::trim)
                    .filter(|action| !action.is_empty())
                    .any(|action| action == action_desc)
            })
            .unwrap_or(false);

        if auto_approve || token_match || action_allowlisted {
            self.approved_actions
                .write()
                .await
                .insert(action_desc.to_string());
            info!("GhostMCP authorization granted: {}", action_desc);
            return Ok(true);
        }

        warn!(
            "GhostMCP authorization denied. Provide human approval via GHOSTMCP_HUMAN_TOKEN or allowlist."
        );
        Ok(false)
    }

    /// Convenience: payload execution authorization.
    pub async fn approve_payload(&self, payload_name: &str) -> Result<bool> {
        // For now, treat payload runs as an "execute" action.
        self.authorize_action(&format!("execute:payload:{}", payload_name))
            .await
    }

    /// Injects secret into an outbound WASM request boundary.
    pub async fn inject_credential(
        &self,
        request: &mut OutboundRequest,
        secret_key: &str,
    ) -> Result<()> {
        if !self
            .approved_actions
            .read()
            .await
            .contains(&request.action_desc)
        {
            bail!(
                "GhostMCP blocked credential injection: action '{}' is not authorized",
                request.action_desc
            );
        }

        self.detect_secret_leak(request).await?;

        let secret = self.lookup_secret(secret_key).await?;
        request.headers.insert(
            format!("x-ghostmcp-secret-{}", secret_key.to_ascii_lowercase()),
            secret,
        );

        info!(
            "GhostMCP injected credential '{}' at outbound boundary for {}",
            secret_key, request.destination
        );

        Ok(())
    }

    async fn detect_secret_leak(&self, request: &OutboundRequest) -> Result<()> {
        let body = String::from_utf8_lossy(&request.body);
        let mut outbound_content = String::new();
        outbound_content.push_str(&body);

        for header in request.headers.values() {
            outbound_content.push('\n');
            outbound_content.push_str(header);
        }

        let secret_store = self.secret_store.read().await;
        for (secret_name, secret_value) in secret_store.iter() {
            if !secret_value.is_empty() && outbound_content.contains(secret_value) {
                bail!(
                    "GhostMCP leak detection blocked outbound request: content matches managed secret '{}'",
                    secret_name
                );
            }
        }

        Ok(())
    }

    async fn lookup_secret(&self, secret_key: &str) -> Result<String> {
        let normalized_key = secret_key.to_ascii_uppercase();

        if let Some(secret) = self.secret_store.read().await.get(&normalized_key).cloned() {
            return Ok(secret);
        }

        let env_key = format!("DC_SECRET_{}", normalized_key);
        let secret = env::var(&env_key)
            .map_err(|_| anyhow::anyhow!("Secret '{}' not found in GhostMCP store", env_key))?;

        self.secret_store
            .write()
            .await
            .insert(normalized_key, secret.clone());

        Ok(secret)
    }
}

fn load_secrets_from_env() -> HashMap<String, String> {
    env::vars()
        .filter_map(|(key, value)| {
            key.strip_prefix("DC_SECRET_")
                .map(|name| (name.to_ascii_uppercase(), value))
        })
        .collect()
}

fn requires_human_approval(action_desc: &str) -> bool {
    let normalized = action_desc.to_ascii_lowercase();
    [
        "delete",
        "destroy",
        "drop",
        "write",
        "modify",
        "execute",
        "exploit",
        "remediation",
    ]
    .iter()
    .any(|keyword| normalized.contains(keyword))
}
