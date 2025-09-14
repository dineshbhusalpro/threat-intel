"""
PostgreSQL Client with pgvector for Threat Intelligence Pipeline
Handles structured data and vector similarity search
"""

import logging
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from psycopg2.pool import SimpleConnectionPool
import numpy as np
from contextlib import contextmanager
import hashlib

logger = logging.getLogger(__name__)


class PostgreSQLClient:
    """PostgreSQL client with pgvector support"""
    
    def __init__(self,
                 host: str,
                 port: int,
                 database: str,
                 user: str,
                 password: str,
                 min_connections: int = 2,
                 max_connections: int = 10):
        """
        Initialize PostgreSQL client
        
        Args:
            host: Database host
            port: Database port
            database: Database name
            user: Username
            password: Password
            min_connections: Minimum pool connections
            max_connections: Maximum pool connections
        """
        self.connection_params = {
            'host': host,
            'port': port,
            'database': database,
            'user': user,
            'password': password
        }
        
        try:
            # Create connection pool
            self.pool = SimpleConnectionPool(
                min_connections,
                max_connections,
                **self.connection_params
            )
            
            logger.info(f"Connected to PostgreSQL at {host}:{port}/{database}")
            
            # Initialize database schema
            self._init_schema()
            
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get connection from pool"""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.pool.putconn(conn)
    
    def _init_schema(self):
        """Initialize database schema"""
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Enable pgvector extension
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                
                # Create tables
                queries = [
                    """
                    CREATE TABLE IF NOT EXISTS documents (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        doc_id VARCHAR(255) UNIQUE NOT NULL,
                        title TEXT,
                        source TEXT,
                        file_hash VARCHAR(64),
                        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        total_pages INTEGER,
                        languages TEXT[],
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS indicators (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        indicator_id VARCHAR(255) UNIQUE NOT NULL,
                        type VARCHAR(50) NOT NULL,
                        value TEXT NOT NULL,
                        normalized_value TEXT NOT NULL,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        occurrence_count INTEGER DEFAULT 1,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS indicator_mentions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        indicator_id VARCHAR(255) REFERENCES indicators(indicator_id),
                        document_id VARCHAR(255) REFERENCES documents(doc_id),
                        context TEXT,
                        confidence FLOAT DEFAULT 1.0,
                        page_number INTEGER,
                        position INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(indicator_id, document_id, position)
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS document_chunks (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        chunk_id VARCHAR(255) UNIQUE NOT NULL,
                        document_id VARCHAR(255) REFERENCES documents(doc_id),
                        content TEXT NOT NULL,
                        chunk_index INTEGER,
                        start_position INTEGER,
                        end_position INTEGER,
                        page_numbers INTEGER[],
                        language VARCHAR(10),
                        embedding vector(384),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS campaigns (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        name VARCHAR(255) UNIQUE NOT NULL,
                        description TEXT,
                        start_date DATE,
                        end_date DATE,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS threat_actors (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        name VARCHAR(255) UNIQUE NOT NULL,
                        aliases TEXT[],
                        description TEXT,
                        country VARCHAR(100),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS indicator_relationships (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        source_indicator_id VARCHAR(255) REFERENCES indicators(indicator_id),
                        target_indicator_id VARCHAR(255) REFERENCES indicators(indicator_id),
                        relationship_type VARCHAR(50),
                        correlation_score FLOAT DEFAULT 1.0,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(source_indicator_id, target_indicator_id, relationship_type)
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS campaign_indicators (
                        campaign_name VARCHAR(255) REFERENCES campaigns(name),
                        indicator_id VARCHAR(255) REFERENCES indicators(indicator_id),
                        confidence FLOAT DEFAULT 1.0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (campaign_name, indicator_id)
                    )
                    """,
                    
                    """
                    CREATE TABLE IF NOT EXISTS campaign_attributions (
                        campaign_name VARCHAR(255) REFERENCES campaigns(name),
                        actor_name VARCHAR(255) REFERENCES threat_actors(name),
                        confidence FLOAT DEFAULT 1.0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (campaign_name, actor_name)
                    )
                    """
                ]
                
                # Create indexes
                indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_normalized ON indicators(normalized_value)",
                    "CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(file_hash)",
                    "CREATE INDEX IF NOT EXISTS idx_mentions_confidence ON indicator_mentions(confidence)",
                    "CREATE INDEX IF NOT EXISTS idx_chunks_embedding ON document_chunks USING ivfflat (embedding vector_cosine_ops)",
                    "CREATE INDEX IF NOT EXISTS idx_chunks_document ON document_chunks(document_id)",
                    "CREATE INDEX IF NOT EXISTS idx_relationships_score ON indicator_relationships(correlation_score)"
                ]
                
                # Execute schema creation
                for query in queries:
                    cur.execute(query)
                    
                for index in indexes:
                    cur.execute(index)
                
                logger.info("Database schema initialized")
    
    def insert_document(self,
                       doc_id: str,
                       title: str,
                       source: str,
                       file_hash: str,
                       total_pages: int = None,
                       languages: List[str] = None,
                       metadata: Dict = None) -> str:
        """Insert document into database"""
        
        query = """
        INSERT INTO documents (doc_id, title, source, file_hash, total_pages, languages, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (doc_id) DO UPDATE
        SET title = EXCLUDED.title,
            source = EXCLUDED.source,
            file_hash = EXCLUDED.file_hash,
            total_pages = EXCLUDED.total_pages,
            languages = EXCLUDED.languages,
            metadata = EXCLUDED.metadata,
            processed_at = CURRENT_TIMESTAMP
        RETURNING doc_id
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (
                    doc_id,
                    title,
                    source,
                    file_hash,
                    total_pages,
                    languages or [],
                    Json(metadata or {})
                ))
                
                result = cur.fetchone()
                return result[0] if result else None
    
    def insert_indicator(self,
                        indicator_type: str,
                        value: str,
                        normalized_value: str,
                        metadata: Dict = None) -> str:
        """Insert indicator into database"""
        
        # Generate indicator ID
        indicator_id = hashlib.md5(f"{indicator_type}:{normalized_value}".encode()).hexdigest()
        
        query = """
        INSERT INTO indicators (indicator_id, type, value, normalized_value, metadata)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (indicator_id) DO UPDATE
        SET last_seen = CURRENT_TIMESTAMP,
            occurrence_count = indicators.occurrence_count + 1
        RETURNING indicator_id
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (
                    indicator_id,
                    indicator_type,
                    value,
                    normalized_value,
                    Json(metadata or {})
                ))
                
                result = cur.fetchone()
                return result[0] if result else None
    
    def insert_indicator_mention(self,
                                 indicator_id: str,
                                 document_id: str,
                                 context: str,
                                 confidence: float = 1.0,
                                 page_number: int = None,
                                 position: int = None):
        """Insert indicator mention"""
        
        query = """
        INSERT INTO indicator_mentions 
        (indicator_id, document_id, context, confidence, page_number, position)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (indicator_id, document_id, position) DO UPDATE
        SET context = EXCLUDED.context,
            confidence = EXCLUDED.confidence,
            page_number = EXCLUDED.page_number
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (
                    indicator_id,
                    document_id,
                    context,
                    confidence,
                    page_number,
                    position
                ))
    
    def insert_chunk(self,
                    chunk_id: str,
                    document_id: str,
                    content: str,
                    chunk_index: int,
                    embedding: np.ndarray = None,
                    start_position: int = None,
                    end_position: int = None,
                    page_numbers: List[int] = None,
                    language: str = None,
                    metadata: Dict = None):
        """Insert document chunk with embedding"""
        
        query = """
        INSERT INTO document_chunks 
        (chunk_id, document_id, content, chunk_index, embedding, 
         start_position, end_position, page_numbers, language, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (chunk_id) DO UPDATE
        SET content = EXCLUDED.content,
            embedding = EXCLUDED.embedding,
            metadata = EXCLUDED.metadata
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Convert numpy array to list for pgvector
                embedding_list = embedding.tolist() if embedding is not None else None
                
                cur.execute(query, (
                    chunk_id,
                    document_id,
                    content,
                    chunk_index,
                    embedding_list,
                    start_position,
                    end_position,
                    page_numbers or [],
                    language,
                    Json(metadata or {})
                ))
    
    def vector_search(self,
                     query_embedding: np.ndarray,
                     limit: int = 10,
                     threshold: float = 0.0) -> List[Dict]:
        """Perform vector similarity search"""
        
        query = """
        SELECT 
            chunk_id,
            document_id,
            content,
            chunk_index,
            page_numbers,
            1 - (embedding <=> %s::vector) as similarity
        FROM document_chunks
        WHERE embedding IS NOT NULL
            AND 1 - (embedding <=> %s::vector) > %s
        ORDER BY embedding <=> %s::vector
        LIMIT %s
        """
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                embedding_list = query_embedding.tolist()
                cur.execute(query, (
                    embedding_list,
                    embedding_list,
                    threshold,
                    embedding_list,
                    limit
                ))
                
                return cur.fetchall()
    
    def search_indicators(self,
                         indicator_type: str = None,
                         value_pattern: str = None,
                         limit: int = 100) -> List[Dict]:
        """Search for indicators"""
        
        conditions = []
        params = []
        
        if indicator_type:
            conditions.append("type = %s")
            params.append(indicator_type)
        
        if value_pattern:
            conditions.append("(value ILIKE %s OR normalized_value ILIKE %s)")
            params.extend([f"%{value_pattern}%", f"%{value_pattern}%"])
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f"""
        SELECT 
            indicator_id,
            type,
            value,
            normalized_value,
            occurrence_count,
            first_seen,
            last_seen,
            metadata
        FROM indicators
        {where_clause}
        ORDER BY occurrence_count DESC
        LIMIT %s
        """
        
        params.append(limit)
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchall()
    
    def get_indicator_context(self, indicator_id: str) -> Dict:
        """Get full context for an indicator"""
        
        result = {
            'indicator': None,
            'mentions': [],
            'related_indicators': []
        }
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get indicator details
                cur.execute(
                    "SELECT * FROM indicators WHERE indicator_id = %s",
                    (indicator_id,)
                )
                result['indicator'] = cur.fetchone()
                
                # Get mentions
                cur.execute("""
                    SELECT 
                        m.*,
                        d.title as document_title,
                        d.source as document_source
                    FROM indicator_mentions m
                    JOIN documents d ON m.document_id = d.doc_id
                    WHERE m.indicator_id = %s
                    ORDER BY m.confidence DESC
                """, (indicator_id,))
                result['mentions'] = cur.fetchall()
                
                # Get related indicators
                cur.execute("""
                    SELECT 
                        i.*,
                        r.relationship_type,
                        r.correlation_score
                    FROM indicator_relationships r
                    JOIN indicators i ON i.indicator_id = r.target_indicator_id
                    WHERE r.source_indicator_id = %s
                    ORDER BY r.correlation_score DESC
                    LIMIT 20
                """, (indicator_id,))
                result['related_indicators'] = cur.fetchall()
        
        return result
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        
        stats = {}
        
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                queries = {
                    'total_documents': "SELECT COUNT(*) FROM documents",
                    'total_indicators': "SELECT COUNT(*) FROM indicators",
                    'total_chunks': "SELECT COUNT(*) FROM document_chunks",
                    'total_mentions': "SELECT COUNT(*) FROM indicator_mentions",
                    'indicator_types': """
                        SELECT type, COUNT(*) as count 
                        FROM indicators 
                        GROUP BY type
                    """
                }
                
                for key, query in queries.items():
                    cur.execute(query)
                    if key == 'indicator_types':
                        stats[key] = dict(cur.fetchall())
                    else:
                        stats[key] = cur.fetchone()[0]
        
        return stats
    
    def close(self):
        """Close all connections"""
        if self.pool:
            self.pool.closeall()
            logger.info("Closed PostgreSQL connections")