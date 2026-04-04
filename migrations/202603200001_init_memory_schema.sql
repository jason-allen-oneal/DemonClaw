CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS memory_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    embedding vector(1536) NOT NULL,
    content_tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS memory_chunks_embedding_idx
    ON memory_chunks USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

CREATE INDEX IF NOT EXISTS memory_chunks_content_tsv_idx
    ON memory_chunks USING GIN (content_tsv);

CREATE INDEX IF NOT EXISTS memory_chunks_created_at_idx
    ON memory_chunks (created_at DESC);

CREATE OR REPLACE FUNCTION set_memory_chunks_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_memory_chunks_updated_at ON memory_chunks;
CREATE TRIGGER trg_memory_chunks_updated_at
BEFORE UPDATE ON memory_chunks
FOR EACH ROW
EXECUTE FUNCTION set_memory_chunks_updated_at();
