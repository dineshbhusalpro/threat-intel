-- PostgreSQL initialization script for Threat Intelligence Pipeline
-- This script sets up the database schema with pgvector support

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create custom types
DO $$ BEGIN
    CREATE TYPE indicator_type AS ENUM (
        'domain', 'url', 'ip_address', 'email', 'phone',
        'md5', 'sha1', 'sha256',
        'facebook', 'twitter', 'instagram', 'youtube', 'linkedin',
        'tiktok', 'telegram', 'reddit', 'vk', 'truth_social', 'parler',
        'google_analytics', 'adsense',
        'bitcoin', 'ethereum'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Function to update last_seen timestamp
CREATE OR REPLACE FUNCTION update_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic timestamp updates
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_indicators_last_seen') THEN
        CREATE TRIGGER update_indicators_last_seen
        BEFORE UPDATE ON indicators
        FOR EACH ROW
        EXECUTE FUNCTION update_last_seen();
    END IF;
END
$$;

-- Create materialized view for indicator statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS indicator_statistics AS
SELECT 
    i.type,
    COUNT(*) as total_count,
    COUNT(DISTINCT im.document_id) as document_count,
    AVG(im.confidence) as avg_confidence,
    MAX(i.last_seen) as most_recent
FROM indicators i
LEFT JOIN indicator_mentions im ON i.indicator_id = im.indicator_id
GROUP BY i.type;

-- Create index on materialized view
CREATE INDEX IF NOT EXISTS idx_indicator_statistics_type 
ON indicator_statistics(type);

-- Function to refresh statistics
CREATE OR REPLACE FUNCTION refresh_indicator_statistics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY indicator_statistics;
END;
$$ LANGUAGE plpgsql;

-- Create search function for full-text search
CREATE OR REPLACE FUNCTION search_documents(
    search_query TEXT,
    result_limit INT DEFAULT 10
)
RETURNS TABLE(
    doc_id VARCHAR(255),
    title TEXT,
    source TEXT,
    rank REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.doc_id,
        d.title,
        d.source,
        ts_rank(
            to_tsvector('english', COALESCE(d.title, '') || ' ' || COALESCE(d.source, '')),
            plainto_tsquery('english', search_query)
        ) as rank
    FROM documents d
    WHERE to_tsvector('english', COALESCE(d.title, '') || ' ' || COALESCE(d.source, ''))
          @@ plainto_tsquery('english', search_query)
    ORDER BY rank DESC
    LIMIT result_limit;
END;
$$ LANGUAGE plpgsql;

-- Function to find similar indicators
CREATE OR REPLACE FUNCTION find_similar_indicators(
    target_indicator_id VARCHAR(255),
    similarity_threshold FLOAT DEFAULT 0.5,
    result_limit INT DEFAULT 10
)
RETURNS TABLE(
    indicator_id VARCHAR(255),
    type VARCHAR(50),
    value TEXT,
    similarity_score FLOAT
) AS $$
BEGIN
    RETURN QUERY
    WITH target AS (
        SELECT * FROM indicators WHERE indicator_id = target_indicator_id
    ),
    mentions AS (
        SELECT 
            im2.indicator_id,
            COUNT(*) as common_documents
        FROM indicator_mentions im1
        JOIN indicator_mentions im2 ON im1.document_id = im2.document_id
        WHERE im1.indicator_id = target_indicator_id
          AND im2.indicator_id != target_indicator_id
        GROUP BY im2.indicator_id
    )
    SELECT 
        i.indicator_id,
        i.type,
        i.value,
        CAST(m.common_documents::FLOAT / 
             (SELECT COUNT(*) FROM indicator_mentions WHERE indicator_id = target_indicator_id) 
             AS FLOAT) as similarity_score
    FROM indicators i
    JOIN mentions m ON i.indicator_id = m.indicator_id
    WHERE CAST(m.common_documents::FLOAT / 
               (SELECT COUNT(*) FROM indicator_mentions WHERE indicator_id = target_indicator_id) 
               AS FLOAT) >= similarity_threshold
    ORDER BY similarity_score DESC
    LIMIT result_limit;
END;
$ LANGUAGE plpgsql;

-- Function to get indicator timeline
CREATE OR REPLACE FUNCTION get_indicator_timeline(
    target_indicator_id VARCHAR(255),
    days_back INT DEFAULT 30
)
RETURNS TABLE(
    date DATE,
    mention_count BIGINT,
    unique_documents BIGINT
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        DATE(im.created_at) as date,
        COUNT(*) as mention_count,
        COUNT(DISTINCT im.document_id) as unique_documents
    FROM indicator_mentions im
    WHERE im.indicator_id = target_indicator_id
      AND im.created_at >= CURRENT_DATE - INTERVAL '1 day' * days_back
    GROUP BY DATE(im.created_at)
    ORDER BY date DESC;
END;
$ LANGUAGE plpgsql;

-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_mentions_created_at ON indicator_mentions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chunks_language ON document_chunks(language);

-- Create GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_documents_metadata_gin ON documents USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_indicators_metadata_gin ON indicators USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_chunks_metadata_gin ON document_chunks USING GIN (metadata);

-- Create text search indexes
CREATE INDEX IF NOT EXISTS idx_documents_title_trgm ON documents USING GIN (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_indicators_value_trgm ON indicators USING GIN (value gin_trgm_ops);

-- Grant permissions (adjust as needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO threat_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO threat_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO threat_user;

-- Initial data for testing (optional)
INSERT INTO campaigns (name, description, metadata)
VALUES 
    ('Doppelgänger', 'Russian disinformation campaign targeting Western audiences', '{"active": true, "region": "Europe"}'),
    ('Storm-1516', 'Advanced persistent threat group', '{"active": true, "sophistication": "high"}'),
    ('Operation Overload', 'Large-scale phishing campaign', '{"active": false, "targets": ["financial", "government"]}')
ON CONFLICT (name) DO NOTHING;

INSERT INTO threat_actors (name, aliases, country, description)
VALUES
    ('APT28', ARRAY['Fancy Bear', 'Sofacy Group'], 'Russia', 'Russian military intelligence'),
    ('APT29', ARRAY['Cozy Bear', 'The Dukes'], 'Russia', 'Russian foreign intelligence'),
    ('Lazarus Group', ARRAY['Hidden Cobra'], 'North Korea', 'North Korean state-sponsored')
ON CONFLICT (name) DO NOTHING;

-- Vacuum and analyze for optimal performance
VACUUM ANALYZE;