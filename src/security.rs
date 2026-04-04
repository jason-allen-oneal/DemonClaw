//! DemonClaw Security Policy
//! Ported from GhostMCP security.py - engagement context, CIDR/domain/port validation

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Require engagement context for sensitive operations
    #[serde(default)]
    pub require_engagement_context: bool,

    /// Current engagement ID (optional)
    #[serde(default)]
    pub engagement_id: Option<String>,

    /// Allow only private IP addresses (RFC1918)
    #[serde(default = "default_true")]
    pub allow_private_only: bool,

    /// Allowed CIDR blocks (empty = no restriction beyond allow_private_only)
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    /// Blocked ports (always blocked regardless of other settings)
    #[serde(default = "default_blocked_ports")]
    pub blocked_ports: HashSet<u16>,

    /// Maximum ports per scan operation
    #[serde(default = "default_max_ports")]
    pub max_ports_per_scan: u16,

    /// Allowed domains (empty = no domain restriction)
    #[serde(default)]
    pub allowed_domains: HashSet<String>,

    /// Maximum tool execution level: passive | active | intrusive
    #[serde(default)]
    pub max_tool_level: ToolLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolLevel {
    Passive,
    Active,
    #[default]
    Intrusive,
}

impl ToolLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "passive" => ToolLevel::Passive,
            "active" => ToolLevel::Active,
            _ => ToolLevel::Intrusive,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_blocked_ports() -> HashSet<u16> {
    [22, 2375, 2376, 3389].iter().cloned().collect()
}

fn default_max_ports() -> u16 {
    256
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_engagement_context: false,
            engagement_id: None,
            allow_private_only: true,
            allowed_cidrs: Vec::new(),
            blocked_ports: default_blocked_ports(),
            max_ports_per_scan: 256,
            allowed_domains: HashSet::new(),
            max_tool_level: ToolLevel::Intrusive,
        }
    }
}

impl SecurityPolicy {
    pub fn load_from_env() -> Self {
        let mut policy = Self::default();

        if let Ok(v) = std::env::var("DEMONCLAW_REQUIRE_ENGAGEMENT") {
            policy.require_engagement_context = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        if let Ok(v) = std::env::var("DEMONCLAW_ENGAGEMENT_ID") {
            if !v.trim().is_empty() {
                policy.engagement_id = Some(v.trim().to_string());
            }
        }

        if let Ok(v) = std::env::var("DEMONCLAW_ALLOW_PRIVATE_ONLY") {
            policy.allow_private_only = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        if let Ok(v) = std::env::var("DEMONCLAW_ALLOWED_CIDRS") {
            policy.allowed_cidrs = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }

        if let Ok(v) = std::env::var("DEMONCLAW_BLOCKED_PORTS") {
            policy.blocked_ports = v
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
        }

        if let Ok(v) = std::env::var("DEMONCLAW_ALLOWED_DOMAINS") {
            policy.allowed_domains = v.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
        }

        if let Ok(v) = std::env::var("DEMONCLAW_MAX_TOOL_LEVEL") {
            policy.max_tool_level = ToolLevel::from_str(&v);
        }

        info!("SecurityPolicy loaded: engagement={:?}, private_only={}, tool_level={:?}",
              policy.engagement_id, policy.allow_private_only, policy.max_tool_level);

        policy
    }

    /// Validate a target host/IP against policy
    pub fn validate_target(&self, host: &str) -> Result<Vec<IpAddr>> {
        let candidate = host.trim();
        if candidate.is_empty() {
            bail!("Target host is required");
        }

        // Resolve to IPs
        let ips: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(candidate, 0))?
            .map(|sockaddr| sockaddr.ip())
            .collect();

        if ips.is_empty() {
            bail!("Unable to resolve target host: {}", candidate);
        }

        // Validate each resolved IP
        for ip in &ips {
            if self.allow_private_only && !is_private_ip(ip) {
                bail!("Target policy violation: only private addresses are allowed (got {})", ip);
            }

            if !self.allowed_cidrs.is_empty() {
                let in_allowlist = self.allowed_cidrs.iter().any(|cidr| {
                    ip_in_cidr(ip, cidr).unwrap_or(false)
                });
                if !in_allowlist {
                    bail!("Target policy violation: {} not in allowed CIDRs", ip);
                }
            }
        }

        Ok(ips)
    }

    /// Validate a list of ports against policy
    pub fn validate_ports(&self, ports: &[u16]) -> Result<Vec<u16>> {
        if ports.is_empty() {
            bail!("At least one port is required");
        }

        if ports.len() > self.max_ports_per_scan as usize {
            bail!("Port list too large: {} > {}", ports.len(), self.max_ports_per_scan);
        }

        let mut validated = Vec::new();
        for port in ports {
            if *port == 0 {
                bail!("Invalid port: 0");
            }
            if self.blocked_ports.contains(port) {
                bail!("Port is blocked by policy: {}", port);
            }
            validated.push(*port);
        }

        validated.sort();
        validated.dedup();
        Ok(validated)
    }

    /// Validate a domain name against allowed domains
    pub fn validate_domain(&self, domain: &str) -> Result<String> {
        let candidate = domain.trim().to_lowercase();
        if candidate.is_empty() || candidate.len() > 253 {
            bail!("Invalid domain name");
        }

        // Basic domain regex check
        static DOMAIN_RE: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$").unwrap());

        if !DOMAIN_RE.is_match(&candidate) {
            bail!("Invalid domain name format");
        }

        let candidate = candidate.strip_suffix('.').unwrap_or(&candidate).to_string();

        // Check against allowed domains
        if !self.allowed_domains.is_empty() {
            let in_scope = self.allowed_domains.iter().any(|allowed| {
                &candidate == allowed || candidate.ends_with(&format!(".{}", allowed))
            });
            if !in_scope {
                bail!("Domain policy violation: {} not in allowed domains", domain);
            }
        }

        Ok(candidate)
    }

    /// Check if engagement context is required and present
    pub fn check_engagement_context(&self, operation: &str) -> Result<()> {
        if self.require_engagement_context && self.engagement_id.is_none() {
            bail!("Engagement context required for '{}' but no engagement_id set", operation);
        }
        Ok(())
    }

    /// Check if a tool level is permitted
    pub fn check_tool_level(&self, requested: ToolLevel) -> Result<()> {
        if !tool_level_permitted(self.max_tool_level, requested) {
            bail!("Tool level {:?} exceeds maximum allowed level {:?}", requested, self.max_tool_level);
        }
        Ok(())
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> Result<bool> {
    let cidr: ipnetwork::IpNetwork = cidr.parse()?;
    Ok(cidr.contains(*ip))
}

pub fn tool_level_permitted(max: ToolLevel, requested: ToolLevel) -> bool {
    // Intrusive > Active > Passive
    match (max, requested) {
        (ToolLevel::Intrusive, _) => true,
        (ToolLevel::Active, ToolLevel::Intrusive) => false,
        (ToolLevel::Active, _) => true,
        (ToolLevel::Passive, ToolLevel::Passive) => true,
        (ToolLevel::Passive, _) => false,
    }
}
