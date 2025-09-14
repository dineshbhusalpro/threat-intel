"""
Vector Store Module for Threat Intelligence Pipeline
Manages vector embeddings and similarity search
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class VectorSearchResult:
    """Result from vector similarity search"""
    chunk_id: str
    document_id: str
    content: str
    similarity: float
    metadata: Dict[str, Any]


class VectorStore:
    """Vector store with multiple backend support"""
    
    def __init__(self,
                 postgres_client=None,
                 chroma_client=None,
                 qdrant_client=None,
                 embedding_dimension: int = 384):
        """
        Initialize vector store
        
        Args:
            postgres_client: PostgreSQL client with pgvector
            chroma_client: ChromaDB client (optional)
            qdrant_client: Qdrant client (optional)
            embedding_dimension: Dimension of embeddings
        """
        self.postgres = postgres_client
        self.chroma = chroma_client
        self.qdrant = qdrant_client
        self.dimension = embedding_dimension
        
        # Use PostgreSQL as primary if available
        self.primary_store = "postgres" if postgres_client else None
        
        if not self.primary_store:
            raise ValueError("At least one vector store backend must be provided")
        
        logger.info(f"Vector store initialized with {self.primary_store} backend")
    
    def add_documents(self,
                     documents: List[Dict],
                     embeddings: List[np.ndarray],
                     metadata: List[Dict] = None) -> bool:
        """
        Add documents with embeddings to vector store
        
        Args:
            documents: List of document dictionaries
            embeddings: List of embedding vectors
            metadata: Optional metadata for each document
            
        Returns:
            Success status
        """
        if not documents or not embeddings:
            return False
        
        if len(documents) != len(embeddings):
            raise ValueError("Documents and embeddings must have same length")
        
        metadata = metadata or [{}] * len(documents)
        
        try:
            if self.primary_store == "postgres":
                return self._add_to_postgres(documents, embeddings, metadata)
            elif self.primary_store == "chroma":
                return self._add_to_chroma(documents, embeddings, metadata)
            elif self.primary_store == "qdrant":
                return self._add_to_qdrant(documents, embeddings, metadata)
            
        except Exception as e:
            logger.error(f"Error adding documents to vector store: {e}")
            return False
    
    def search(self,
              query_embedding: np.ndarray,
              k: int = 10,
              filters: Dict = None,
              threshold: float = 0.0) -> List[VectorSearchResult]:
        """
        Search for similar documents
        
        Args:
            query_embedding: Query embedding vector
            k: Number of results
            filters: Optional filters
            threshold: Minimum similarity threshold
            
        Returns:
            List of search results
        """
        try:
            if self.primary_store == "postgres":
                return self._search_postgres(query_embedding, k, filters, threshold)
            elif self.primary_store == "chroma":
                return self._search_chroma(query_embedding, k, filters, threshold)
            elif self.primary_store == "qdrant":
                return self._search_qdrant(query_embedding, k, filters, threshold)
            
        except Exception as e:
            logger.error(f"Vector search error: {e}")
            return []
    
    def _add_to_postgres(self,
                        documents: List[Dict],
                        embeddings: List[np.ndarray],
                        metadata: List[Dict]) -> bool:
        """Add documents to PostgreSQL with pgvector"""
        
        for doc, embedding, meta in zip(documents, embeddings, metadata):
            self.postgres.insert_chunk(
                chunk_id=doc.get("chunk_id"),
                document_id=doc.get("document_id"),
                content=doc.get("content"),
                chunk_index=doc.get("chunk_index", 0),
                embedding=embedding,
                start_position=doc.get("start_position"),
                end_position=doc.get("end_position"),
                page_numbers=doc.get("page_numbers"),
                language=doc.get("language"),
                metadata=meta
            )
        
        return True
    
    def _search_postgres(self,
                        query_embedding: np.ndarray,
                        k: int,
                        filters: Dict,
                        threshold: float) -> List[VectorSearchResult]:
        """Search PostgreSQL vector store"""
        
        results = self.postgres.vector_search(
            query_embedding=query_embedding,
            limit=k,
            threshold=threshold
        )
        
        search_results = []
        for result in results:
            search_results.append(VectorSearchResult(
                chunk_id=result.get("chunk_id"),
                document_id=result.get("document_id"),
                content=result.get("content"),
                similarity=result.get("similarity", 0.0),
                metadata={
                    "chunk_index": result.get("chunk_index"),
                    "page_numbers": result.get("page_numbers")
                }
            ))
        
        return search_results
    
    def _add_to_chroma(self,
                      documents: List[Dict],
                      embeddings: List[np.ndarray],
                      metadata: List[Dict]) -> bool:
        """Add documents to ChromaDB"""
        
        if not self.chroma:
            return False
        
        # ChromaDB implementation would go here
        # This is a placeholder
        logger.warning("ChromaDB backend not fully implemented")
        return False
    
    def _search_chroma(self,
                      query_embedding: np.ndarray,
                      k: int,
                      filters: Dict,
                      threshold: float) -> List[VectorSearchResult]:
        """Search ChromaDB"""
        
        if not self.chroma:
            return []
        
        # ChromaDB search implementation would go here
        logger.warning("ChromaDB search not fully implemented")
        return []
    
    def _add_to_qdrant(self,
                      documents: List[Dict],
                      embeddings: List[np.ndarray],
                      metadata: List[Dict]) -> bool:
        """Add documents to Qdrant"""
        
        if not self.qdrant:
            return False
        
        # Qdrant implementation would go here
        logger.warning("Qdrant backend not fully implemented")
        return False
    
    def _search_qdrant(self,
                      query_embedding: np.ndarray,
                      k: int,
                      filters: Dict,
                      threshold: float) -> List[VectorSearchResult]:
        """Search Qdrant"""
        
        if not self.qdrant:
            return []
        
        # Qdrant search implementation would go here
        logger.warning("Qdrant search not fully implemented")
        return []
    
    def delete_document(self, document_id: str) -> bool:
        """Delete all chunks for a document"""
        
        try:
            if self.primary_store == "postgres":
                query = "DELETE FROM document_chunks WHERE document_id = %s"
                with self.postgres.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(query, (document_id,))
                return True
            
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            return False
    
    def update_metadata(self,
                       chunk_id: str,
                       metadata: Dict) -> bool:
        """Update metadata for a chunk"""
        
        try:
            if self.primary_store == "postgres":
                query = """
                UPDATE document_chunks 
                SET metadata = %s 
                WHERE chunk_id = %s
                """
                with self.postgres.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(query, (json.dumps(metadata), chunk_id))
                return True
            
        except Exception as e:
            logger.error(f"Error updating metadata: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get vector store statistics"""
        
        stats = {
            "backend": self.primary_store,
            "dimension": self.dimension
        }
        
        try:
            if self.primary_store == "postgres":
                query = """
                SELECT 
                    COUNT(*) as total_chunks,
                    COUNT(DISTINCT document_id) as total_documents,
                    COUNT(embedding) as chunks_with_embeddings
                FROM document_chunks
                """
                with self.postgres.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(query)
                        result = cur.fetchone()
                        stats.update({
                            "total_chunks": result[0],
                            "total_documents": result[1],
                            "chunks_with_embeddings": result[2]
                        })
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
        
        return stats