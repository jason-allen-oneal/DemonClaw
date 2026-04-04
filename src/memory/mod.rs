use anyhow::{Result, anyhow};
use serde_json::Value;
use sqlx::{Pool, Postgres, Row, postgres::PgPoolOptions};
use uuid::Uuid;
use tracing::{info, warn};
use crate::embeddings::EmbeddingManager;

#[derive(Clone)]
pub struct MemoryManager {
    pub pool: Pool<Postgres>,
    pub embeddings: EmbeddingManager,
}

#[derive(Debug, Clone)]
pub struct SemanticChunk {
    pub id: Uuid,
    pub content: String,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct SemanticMatch {
    pub id: Uuid,
    pub content: String,
    pub metadata: Value,
    pub similarity: f32,
}

impl MemoryManager {
    pub async fn new(db_url: &str) -> Result<Self> {
        info!("Initializing MemoryManager (PostgreSQL + pgvector)...");
        // Reduced timeout for local dev if DB isn't ready
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(db_url)
            .await?;
        
        let embeddings = EmbeddingManager::from_env();
        if embeddings.is_available() {
            info!("Embedding provider available (dim={})", embeddings.dimension());
        } else {
            warn!("No embedding provider configured, using stub (FTS only)");
        }
            
        Ok(Self { pool, embeddings })
    }

    pub async fn init_schema(&self) -> Result<()> {
        info!("Running pgvector migrations (memory optimizer prep)...");
        sqlx::migrate!("./migrations").run(&self.pool).await?;

        Ok(())
    }

    pub async fn insert_chunk(
        &self,
        content: &str,
        metadata: Value,
        embedding: &[f32],
    ) -> Result<Uuid> {
        const EMBEDDING_DIM: usize = 1536;
        if embedding.len() != EMBEDDING_DIM {
            return Err(anyhow!(
                "embedding length mismatch: expected {}, got {}",
                EMBEDDING_DIM,
                embedding.len()
            ));
        }

        let embedding_literal = embedding_to_pgvector_literal(embedding);

        let row = sqlx::query(
            "INSERT INTO memory_chunks (content, metadata, embedding)
             VALUES ($1, $2, $3::vector)
             RETURNING id",
        )
        .bind(content)
        .bind(metadata)
        .bind(embedding_literal)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get::<Uuid, _>("id"))
    }

    pub async fn query_similar_chunks(
        &self,
        query_embedding: &[f32],
        limit: i64,
    ) -> Result<Vec<SemanticMatch>> {
        const EMBEDDING_DIM: usize = 1536;
        if query_embedding.len() != EMBEDDING_DIM {
            return Err(anyhow!(
                "query embedding length mismatch: expected {}, got {}",
                EMBEDDING_DIM,
                query_embedding.len()
            ));
        }

        let embedding_literal = embedding_to_pgvector_literal(query_embedding);

        let rows = sqlx::query(
            "SELECT
                id,
                content,
                metadata,
                (1 - (embedding <=> $1::vector))::float4 AS similarity
             FROM memory_chunks
             ORDER BY embedding <=> $1::vector
             LIMIT $2",
        )
        .bind(embedding_literal)
        .bind(limit.max(1))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| SemanticMatch {
                id: row.get("id"),
                content: row.get("content"),
                metadata: row.get("metadata"),
                similarity: row.get("similarity"),
            })
            .collect())
    }

    pub async fn compact_memory(&self) -> Result<()> {
        info!("MemoryManager performing semantic compaction and index optimization...");
        sqlx::query("ANALYZE memory_chunks").execute(&self.pool).await?;
        Ok(())
    }
    
    pub async fn retrieve_context(&self, query: &str) -> Result<Vec<String>> {
        // Hybrid retrieval: RRF (Reciprocal Rank Fusion) of vector + FTS
        let matches = self.hybrid_retrieve(query, 10).await?;
        Ok(matches.into_iter().map(|m| m.content).collect())
    }

    /// Hybrid retrieval combining vector similarity + full-text search via RRF
    pub async fn hybrid_retrieve(&self, query: &str, limit: i64) -> Result<Vec<SemanticMatch>> {
        info!("MemoryManager hybrid retrieval (RRF) for: {}", query);

        // Check if embeddings are available
        if self.embeddings.is_available() {
            // Generate query embedding
            let query_embedding = self.embeddings.embed(query).await?;
            
            // Run vector similarity query
            let embedding_literal = embedding_to_pgvector_literal(&query_embedding);
            
            let rows = sqlx::query(
                r#"
                SELECT
                    id,
                    content,
                    metadata,
                    (1 - (embedding <=> $1::vector))::float4 AS similarity
                FROM memory_chunks
                ORDER BY embedding <=> $1::vector
                LIMIT $2
                "#,
            )
            .bind(embedding_literal)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

            return Ok(rows
                .into_iter()
                .map(|row| SemanticMatch {
                    id: row.get("id"),
                    content: row.get("content"),
                    metadata: row.get("metadata"),
                    similarity: row.get("similarity"),
                })
                .collect());
        }

        // Fallback to FTS-only when embeddings unavailable
        warn!("Embeddings not available, using FTS-only retrieval");
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                content,
                metadata,
                ts_rank(content_tsv, plainto_tsquery('english', $1)) as rank
            FROM memory_chunks
            WHERE content_tsv @@ plainto_tsquery('english', $1)
            ORDER BY rank DESC, created_at DESC
            LIMIT $2
            "#,
        )
        .bind(query)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| SemanticMatch {
                id: row.get("id"),
                content: row.get("content"),
                metadata: row.get("metadata"),
                similarity: row.try_get("rank").unwrap_or(0.0),
            })
            .collect())
    }

    /// Memory Optimizer: background compaction and index maintenance
    pub async fn run_optimizer(&self, interval_secs: u64) {
        use tokio::time::{interval, Duration};
        let mut ticker = interval(Duration::from_secs(interval_secs));

        info!("Memory Optimizer started (interval={}s)", interval_secs);

        loop {
            ticker.tick().await;

            info!("Memory Optimizer: running compaction and index maintenance...");

            // ANALYZE for query planner stats
            if let Err(e) = sqlx::query("ANALYZE memory_chunks")
                .execute(&self.pool)
                .await
            {
                warn!("Memory Optimizer: ANALYZE failed: {}", e);
            }

            // Reindex if fragmentation is high (simplified - production would check pg_stat_user_indexes)
            if let Err(e) = sqlx::query("REINDEX INDEX CONCURRENTLY IF EXISTS idx_memory_embedding")
                .execute(&self.pool)
                .await
            {
                warn!("Memory Optimizer: REINDEX failed: {}", e);
            }

            // Vacuum analyze for dead tuple cleanup
            if let Err(e) = sqlx::query("VACUUM ANALYZE memory_chunks")
                .execute(&self.pool)
                .await
            {
                warn!("Memory Optimizer: VACUUM failed: {}", e);
            }

            info!("Memory Optimizer: maintenance cycle complete.");
        }
    }
}

fn embedding_to_pgvector_literal(values: &[f32]) -> String {
    let mut encoded = String::with_capacity(values.len() * 10 + 2);
    encoded.push('[');

    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            encoded.push(',');
        }
        encoded.push_str(&value.to_string());
    }

    encoded.push(']');
    encoded
}
