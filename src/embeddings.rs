//! Embedding Provider Interface
//! For generating vector embeddings for semantic memory

use anyhow::{Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Embedding provider trait
#[async_trait::async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Generate embedding for text (returns vector of floats)
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;

    /// Get embedding dimension
    fn dimension(&self) -> usize;
}

/// OpenAI-compatible embedding provider
pub struct OpenAIEmbeddings {
    client: Client,
    base_url: String,
    api_key: String,
    model: String,
    dimension: usize,
}

#[derive(Serialize)]
struct EmbeddingRequest {
    model: String,
    input: Vec<String>,
    encoding_format: String,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

impl OpenAIEmbeddings {
    pub fn new(base_url: String, api_key: String, model: String, dimension: usize) -> Self {
        crate::tls::ensure_crypto_provider_installed();
        info!(
            "OpenAI Embeddings provider initialized: base_url={} model={} dim={}",
            base_url, model, dimension
        );
        Self {
            client: Client::new(),
            base_url,
            api_key,
            model,
            dimension,
        }
    }

    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("EMBEDDING_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
        let api_key = std::env::var("EMBEDDING_API_KEY").ok()?;
        let model = std::env::var("EMBEDDING_MODEL")
            .unwrap_or_else(|_| "text-embedding-3-small".to_string());
        let dimension = std::env::var("EMBEDDING_DIMENSION")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1536); // text-embedding-3-small default

        if api_key.is_empty() {
            warn!("EMBEDDING_API_KEY not set, embeddings disabled");
            return None;
        }

        Some(Self::new(base_url, api_key, model, dimension))
    }
}

#[async_trait::async_trait]
impl EmbeddingProvider for OpenAIEmbeddings {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let request = EmbeddingRequest {
            model: self.model.clone(),
            input: vec![text.to_string()],
            encoding_format: "float".to_string(),
        };

        let url = format!("{}/embeddings", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("Embedding API error ({}): {}", status, body);
        }

        let embedding_response: EmbeddingResponse = response.json().await?;

        if embedding_response.data.is_empty() {
            bail!("Embedding API returned no results");
        }

        let embedding = embedding_response.data[0].embedding.clone();

        if embedding.len() != self.dimension {
            warn!(
                "Embedding dimension mismatch: expected {}, got {}",
                self.dimension,
                embedding.len()
            );
        }

        Ok(embedding)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Stub provider for testing (returns zero vectors)
#[derive(Clone)]
pub struct StubEmbeddings {
    dimension: usize,
}

impl StubEmbeddings {
    pub fn new(dimension: usize) -> Self {
        Self { dimension }
    }
}

#[async_trait::async_trait]
impl EmbeddingProvider for StubEmbeddings {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>> {
        // Return zero vector for testing
        Ok(vec![0.0f32; self.dimension])
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

/// Hybrid embedding manager (tries provider, falls back to stub)
#[derive(Clone)]
pub struct EmbeddingManager {
    provider: Option<std::sync::Arc<dyn EmbeddingProvider>>,
    fallback: StubEmbeddings,
}

impl EmbeddingManager {
    pub fn new(
        provider: Option<std::sync::Arc<dyn EmbeddingProvider>>,
        fallback_dim: usize,
    ) -> Self {
        Self {
            provider,
            fallback: StubEmbeddings::new(fallback_dim),
        }
    }

    pub fn from_env() -> Self {
        let provider = OpenAIEmbeddings::from_env()
            .map(|p| std::sync::Arc::new(p) as std::sync::Arc<dyn EmbeddingProvider>);
        let fallback_dim = provider.as_ref().map(|p| p.dimension()).unwrap_or(1536);
        Self::new(provider, fallback_dim)
    }

    pub async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        if let Some(ref provider) = self.provider {
            match provider.embed(text).await {
                Ok(embedding) => return Ok(embedding),
                Err(e) => {
                    warn!("Embedding provider failed, using stub: {}", e);
                }
            }
        }
        self.fallback.embed(text).await
    }

    pub fn dimension(&self) -> usize {
        self.provider
            .as_ref()
            .map(|p| p.dimension())
            .unwrap_or(self.fallback.dimension())
    }

    pub fn is_available(&self) -> bool {
        self.provider.is_some()
    }
}
