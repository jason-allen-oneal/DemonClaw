use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Local,
    /// SSH destination in the form `user@host` or `host`.
    Ssh { destination: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    ListeningPorts,
    PackageInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub target: Target,
    pub probe: ProbeKind,
    /// Human-readable summary.
    pub summary: String,
    /// Raw stdout (may be truncated by callers).
    #[serde(default)]
    pub stdout: String,
    /// Raw stderr (may be truncated by callers).
    #[serde(default)]
    pub stderr: String,
    pub exit_code: i32,
    pub skipped: bool,
    #[serde(default)]
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Vuln,
    Intrusion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub kind: ScanKind,
    pub target: Target,
}
