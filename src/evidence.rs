//! Evidence Locker - Tamper-evident audit chain
//! Each event is hashed and linked to the previous event for integrity verification

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;
use tracing::{info, warn};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub id: Uuid,
    pub prev_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub detail: Value,
    pub envelope_id: Option<Uuid>,
    pub hash: String,
}

impl EvidenceEvent {
    pub fn new(
        id: Uuid,
        prev_hash: Option<String>,
        kind: impl Into<String>,
        detail: Value,
        envelope_id: Option<Uuid>,
    ) -> Self {
        let timestamp = Utc::now();
        let kind_str = kind.into();
        let hash = Self::compute_hash(id, &prev_hash, &timestamp, &kind_str, &detail, &envelope_id);
        
        Self {
            id,
            prev_hash,
            timestamp,
            kind: kind_str,
            detail,
            envelope_id,
            hash,
        }
    }

    fn compute_hash(
        id: Uuid,
        prev_hash: &Option<String>,
        timestamp: &DateTime<Utc>,
        kind: &str,
        detail: &Value,
        envelope_id: &Option<Uuid>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        if let Some(ph) = prev_hash {
            hasher.update(ph.as_bytes());
        }
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(kind.as_bytes());
        hasher.update(serde_json::to_string(detail).unwrap_or_default().as_bytes());
        if let Some(eid) = envelope_id {
            hasher.update(eid.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            self.id,
            &self.prev_hash,
            &self.timestamp,
            &self.kind,
            &self.detail,
            &self.envelope_id,
        );
        computed == self.hash
    }
}

pub struct EvidenceLocker {
    pool: Pool<Postgres>,
}

impl EvidenceLocker {
    pub fn new(pool: Pool<Postgres>) -> Self {
        info!("Evidence Locker initialized.");
        Self { pool }
    }

    pub async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS evidence_chain (
                id UUID PRIMARY KEY,
                prev_hash TEXT,
                timestamp TIMESTAMPTZ NOT NULL,
                kind TEXT NOT NULL,
                detail JSONB NOT NULL,
                envelope_id UUID,
                hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence_chain(timestamp);
            CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence_chain(kind);
            CREATE INDEX IF NOT EXISTS idx_evidence_envelope ON evidence_chain(envelope_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        info!("Evidence Locker schema initialized.");
        Ok(())
    }

    /// Get the latest hash in the chain (for linking next event)
    pub async fn get_latest_hash(&self) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT hash FROM evidence_chain ORDER BY timestamp DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.try_get("hash").ok()))
    }

    /// Append a new event to the chain
    pub async fn append(&self, event: &EvidenceEvent) -> Result<()> {
        // Verify the event's hash is valid before storing
        if !event.verify_hash() {
            bail!("Evidence event hash verification failed");
        }

        // Verify the prev_hash matches the actual latest hash
        let latest = self.get_latest_hash().await?;
        if latest != event.prev_hash {
            warn!(
                "Evidence chain fork detected: expected prev_hash={:?}, got prev_hash={:?}",
                latest, event.prev_hash
            );
            // Still append but log the warning - could be concurrent writes
        }

        sqlx::query(
            r#"
            INSERT INTO evidence_chain (id, prev_hash, timestamp, kind, detail, envelope_id, hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(event.id)
        .bind(&event.prev_hash)
        .bind(event.timestamp)
        .bind(&event.kind)
        .bind(&event.detail)
        .bind(event.envelope_id)
        .bind(&event.hash)
        .execute(&self.pool)
        .await?;

        info!(
            "Evidence appended: id={} kind={} hash={}",
            event.id, event.kind, &event.hash[..16]
        );

        Ok(())
    }

    /// Create and append an event in one call
    pub async fn record(
        &self,
        kind: impl Into<String>,
        detail: Value,
        envelope_id: Option<Uuid>,
    ) -> Result<EvidenceEvent> {
        let prev_hash = self.get_latest_hash().await?;
        let event = EvidenceEvent::new(Uuid::new_v4(), prev_hash, kind, detail, envelope_id);
        self.append(&event).await?;
        Ok(event)
    }

    /// Verify the entire chain integrity
    pub async fn verify_chain(&self) -> Result<ChainVerification> {
        let rows = sqlx::query(
            "SELECT id, prev_hash, timestamp, kind, detail, envelope_id, hash 
             FROM evidence_chain ORDER BY timestamp ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut verification = ChainVerification {
            total_events: rows.len(),
            valid_events: 0,
            broken_links: Vec::new(),
            hash_mismatches: Vec::new(),
            is_valid: true,
        };

        let mut expected_next_hash: Option<String> = None;

        for row in rows {
            let id: Uuid = row.get("id");
            let prev_hash: Option<String> = row.get("prev_hash");
            let hash: String = row.get("hash");

            // Check link integrity
            if expected_next_hash.is_some() && expected_next_hash != prev_hash {
                verification.broken_links.push(id);
                verification.is_valid = false;
            }

            // Reconstruct and verify hash
            let timestamp: DateTime<Utc> = row.get("timestamp");
            let kind: String = row.get("kind");
            let detail: Value = row.get("detail");
            let envelope_id: Option<Uuid> = row.get("envelope_id");

            let computed = EvidenceEvent::compute_hash(
                id, &prev_hash, &timestamp, &kind, &detail, &envelope_id,
            );

            if computed != hash {
                verification.hash_mismatches.push(id);
                verification.is_valid = false;
            } else {
                verification.valid_events += 1;
            }

            expected_next_hash = Some(hash);
        }

        Ok(verification)
    }

    /// Query events by kind
    pub async fn query_by_kind(&self, kind: &str, limit: i64) -> Result<Vec<EvidenceEvent>> {
        let rows = sqlx::query(
            "SELECT id, prev_hash, timestamp, kind, detail, envelope_id, hash 
             FROM evidence_chain WHERE kind = $1 ORDER BY timestamp DESC LIMIT $2",
        )
        .bind(kind)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EvidenceEvent {
                id: row.get("id"),
                prev_hash: row.get("prev_hash"),
                timestamp: row.get("timestamp"),
                kind: row.get("kind"),
                detail: row.get("detail"),
                envelope_id: row.get("envelope_id"),
                hash: row.get("hash"),
            })
            .collect())
    }

    /// Export evidence chain as JSON report
    pub async fn export_json(&self, limit: i64) -> Result<String> {
        let rows = sqlx::query(
            "SELECT id, prev_hash, timestamp, kind, detail, envelope_id, hash 
             FROM evidence_chain ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let events: Vec<EvidenceEvent> = rows
            .into_iter()
            .map(|row| EvidenceEvent {
                id: row.get("id"),
                prev_hash: row.get("prev_hash"),
                timestamp: row.get("timestamp"),
                kind: row.get("kind"),
                detail: row.get("detail"),
                envelope_id: row.get("envelope_id"),
                hash: row.get("hash"),
            })
            .collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "exported_at": chrono::Utc::now(),
            "total_events": events.len(),
            "events": events
        }))?)
    }

    /// Export evidence chain as Markdown report
    pub async fn export_markdown(&self, limit: i64) -> Result<String> {
        let events = self.query_by_kind("envelope.received", limit).await?;
        let verification = self.verify_chain().await?;

        let mut md = String::new();
        md.push_str("# DemonClaw Evidence Report\n\n");
        md.push_str(&format!("**Exported:** {}\n\n", chrono::Utc::now()));
        md.push_str("## Chain Verification\n\n");
        md.push_str(&format!("- **Status:** {}\n", if verification.is_valid { "✅ VALID" } else { "❌ BROKEN" }));
        md.push_str(&format!("- **Total Events:** {}\n", verification.total_events));
        md.push_str(&format!("- **Valid Events:** {}\n", verification.valid_events));
        
        if !verification.broken_links.is_empty() {
            md.push_str(&format!("- **Broken Links:** {}\n", verification.broken_links.len()));
        }
        if !verification.hash_mismatches.is_empty() {
            md.push_str(&format!("- **Hash Mismatches:** {}\n", verification.hash_mismatches.len()));
        }
        
        md.push_str("\n## Event Log\n\n");
        md.push_str("| Timestamp | Kind | ID | Details |\n");
        md.push_str("|-----------|------|-----|---------|\n");
        
        for event in events.iter().rev() {
            let detail_summary = match &event.detail {
                serde_json::Value::Object(obj) => {
                    obj.get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}")
                        .chars()
                        .take(50)
                        .collect::<String>()
                }
                _ => "{}".to_string(),
            };
            md.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                event.kind,
                event.id,
                detail_summary
            ));
        }

        Ok(md)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub total_events: usize,
    pub valid_events: usize,
    pub broken_links: Vec<Uuid>,
    pub hash_mismatches: Vec<Uuid>,
    pub is_valid: bool,
}
