use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: Uuid,
    pub source: String,
    pub content: String,
    #[serde(default)]
    pub metadata: Value,
    pub received_at: DateTime<Utc>,
}

impl Envelope {
    pub fn new(source: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            source: source.into(),
            content: content.into(),
            metadata: Value::Null,
            received_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub id: Uuid,
    pub envelope_id: Option<Uuid>,
    pub kind: String,
    #[serde(default)]
    pub detail: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Received,
    Classified,
    Running,
    Completed,
    Failed,
    Denied,
    Ignored,
}
