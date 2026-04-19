use serde::{Deserialize, Serialize};

use super::types::Target;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    pub target: Target,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub finding_kind: String,
    pub target: Target,
    pub method: String,
    pub result: VerificationResult,
    #[serde(default)]
    pub notes: String,
}
