"""
Main API Module for Threat Intelligence Pipeline
FastAPI application with LangGraph integration for intelligent routing
"""

import logging
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Body, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from ..storage.neo4j_client import Neo4jClient
from ..storage.postgres_client import PostgreSQLClient
from ..storage.vector_store import VectorStore
from ..pipeline.indicators import IndicatorExtractor

from ..pipeline.extractor_simple import PDFExtractor

from ..pipeline.chunker import SemanticChunker
from ..pipeline.embedder import MultilingualEmbedder
from .langgraph_agent import ThreatIntelligenceAgent
from .models import *

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
neo4j_client = None
postgres_client = None
vector_store = None
agent = None
indicator_extractor = None
pdf_extractor = None
chunker = None
embedder = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global neo4j_client, postgres_client, vector_store, agent
    global indicator_extractor, pdf_extractor, chunker, embedder
    
    # Startup
    logger.info("Starting Threat Intelligence API...")
    
    # Initialize database clients
    neo4j_client = Neo4jClient(
        uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        user=os.getenv("NEO4J_USER", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", "password")
    )
    
    postgres_client = PostgreSQLClient(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", 5432)),
        database=os.getenv("POSTGRES_DB", "threat_intel"),
        user=os.getenv("POSTGRES_USER", "user"),
        password=os.getenv("POSTGRES_PASSWORD", "password")
    )
    
    # Initialize vector store
    vector_store = VectorStore(
        postgres_client=postgres_client,
        embedding_dimension=384
    )
    
    # Initialize pipeline components
    indicator_extractor = IndicatorExtractor()
    pdf_extractor = PDFExtractor()
    chunker = SemanticChunker()
    embedder = MultilingualEmbedder(model_name='multilingual')
    
    # Initialize LangGraph agent
    agent = ThreatIntelligenceAgent(
        neo4j_client=neo4j_client,
        postgres_client=postgres_client,
        vector_store=vector_store,
        embedder=embedder
    )
    
    logger.info("API initialization complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Threat Intelligence API...")
    
    if neo4j_client:
        neo4j_client.close()
    if postgres_client:
        postgres_client.close()
    
    logger.info("API shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="Threat Intelligence Pipeline API",
    description="Advanced threat intelligence extraction and analysis system",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Check API health status"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "neo4j": neo4j_client is not None,
            "postgres": postgres_client is not None,
            "vector_store": vector_store is not None,
            "agent": agent is not None
        }
    }


# Document processing endpoints
@app.post("/documents/process", response_model=ProcessDocumentResponse)
async def process_document(
    request: ProcessDocumentRequest,
    background_tasks: BackgroundTasks
):
    """Process a PDF document and extract indicators"""
    try:
        # Extract document content
        logger.info(f"Processing document: {request.file_path}")
        document = pdf_extractor.extract_document(request.file_path)
        
        # Store document in database
        doc_id = postgres_client.insert_document(
            doc_id=document.file_hash,
            title=document.title,
            source=request.file_path,
            file_hash=document.file_hash,
            total_pages=document.total_pages,
            languages=document.languages_detected,
            metadata=document.metadata
        )
        
        neo4j_client.create_document(
            doc_id=doc_id,
            title=document.title,
            source=request.file_path,
            metadata=document.metadata
        )
        
        # Extract and store indicators
        all_indicators = []
        for page in document.pages:
            indicators = indicator_extractor.extract_all(
                page.text,
                source_doc=doc_id
            )
            
            for indicator in indicators:
                # Store in both databases
                ind_id = postgres_client.insert_indicator(
                    indicator_type=indicator.type.value,
                    value=indicator.value,
                    normalized_value=indicator.normalized_value,
                    metadata=indicator.metadata
                )
                
                neo4j_ind_id = neo4j_client.create_indicator(
                    indicator_type=indicator.type.value,
                    value=indicator.value,
                    normalized_value=indicator.normalized_value,
                    metadata=indicator.metadata
                )
                
                # Create mention relationship
                postgres_client.insert_indicator_mention(
                    indicator_id=ind_id,
                    document_id=doc_id,
                    context=indicator.context,
                    confidence=indicator.confidence,
                    page_number=page.page_number,
                    position=indicator.source_position
                )
                
                neo4j_client.create_indicator_mention(
                    indicator_id=neo4j_ind_id,
                    document_id=doc_id,
                    context=indicator.context,
                    confidence=indicator.confidence,
                    page_number=page.page_number
                )
                
                all_indicators.append(indicator)
        
        # Create chunks and embeddings in background
        if request.create_embeddings:
            background_tasks.add_task(
                create_document_embeddings,
                document,
                doc_id
            )
        
        # Generate statistics
        stats = indicator_extractor.get_statistics(all_indicators)
        
        return ProcessDocumentResponse(
            document_id=doc_id,
            title=document.title,
            total_pages=document.total_pages,
            languages_detected=document.languages_detected,
            indicators_extracted=stats['total'],
            indicator_breakdown=stats['by_type'],
            processing_time=0.0,  # Would need to track actual time
            status="completed"
        )
        
    except Exception as e:
        logger.error(f"Error processing document: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def create_document_embeddings(document, doc_id):
    """Background task to create embeddings for document chunks"""
    try:
        # Create chunks
        pages_data = [(p.page_number, p.text) for p in document.pages]
        chunks = chunker.chunk_pages(pages_data, doc_id)
        
        # Generate embeddings
        embeddings = embedder.embed_chunks(chunks)
        
        # Store chunks with embeddings
        for chunk, embedding in zip(chunks, embeddings):
            postgres_client.insert_chunk(
                chunk_id=chunk.chunk_id,
                document_id=doc_id,
                content=chunk.content,
                chunk_index=chunk.chunk_index,
                embedding=embedding,
                start_position=chunk.start_position,
                end_position=chunk.end_position,
                page_numbers=chunk.page_numbers,
                language=chunk.language,
                metadata=chunk.metadata
            )
        
        logger.info(f"Created {len(chunks)} chunks with embeddings for document {doc_id}")
        
    except Exception as e:
        logger.error(f"Error creating embeddings: {e}")


# Search endpoints
@app.post("/search", response_model=SearchResponse)
async def hybrid_search(request: SearchRequest):
    """Perform hybrid search combining vector similarity and structured queries"""
    try:
        results = await agent.search(
            query=request.query,
            search_type=request.search_type,
            filters=request.filters,
            limit=request.limit
        )
        
        return SearchResponse(
            query=request.query,
            results=results['results'],
            total_results=results['total'],
            search_type=results['search_type'],
            processing_time=results['processing_time']
        )
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Indicator endpoints
@app.get("/indicators/{indicator_type}", response_model=List[IndicatorResponse])
async def get_indicators_by_type(
    indicator_type: str,
    limit: int = Query(100, ge=1, le=1000)
):
    """Retrieve indicators of a specific type"""
    try:
        indicators = neo4j_client.find_indicators_by_type(
            indicator_type=indicator_type,
            limit=limit
        )
        
        return [IndicatorResponse(**ind) for ind in indicators]
        
    except Exception as e:
        logger.error(f"Error retrieving indicators: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/context/{indicator_id}", response_model=IndicatorContextResponse)
async def get_indicator_context(indicator_id: str):
    """Get full context for an indicator including documents and relationships"""
    try:
        context = neo4j_client.get_indicator_context(indicator_id)
        
        if not context:
            raise HTTPException(status_code=404, detail="Indicator not found")
        
        return IndicatorContextResponse(
            indicator=context['indicator'],
            documents=context['documents'],
            campaigns=context['campaigns'],
            related_indicators=context['related_indicators']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting indicator context: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/relationships/{indicator_id}")
async def get_indicator_relationships(
    indicator_id: str,
    max_hops: int = Query(2, ge=1, le=5)
):
    """Get graph traversal for connected entities"""
    try:
        related = neo4j_client.find_related_indicators(
            indicator_id=indicator_id,
            max_hops=max_hops
        )
        
        return {
            "indicator_id": indicator_id,
            "max_hops": max_hops,
            "related_indicators": related,
            "total_related": len(related)
        }
        
    except Exception as e:
        logger.error(f"Error getting relationships: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/network/{node_id}")
async def get_network_visualization(
    node_id: str,
    max_hops: int = Query(2, ge=1, le=3),
    limit: int = Query(100, ge=10, le=500)
):
    """Get network visualization data for an indicator or campaign"""
    try:
        network_data = neo4j_client.get_network_graph(
            center_node_id=node_id,
            max_hops=max_hops,
            limit=limit
        )
        
        return {
            "center_node": node_id,
            "graph": network_data,
            "node_count": len(network_data['nodes']),
            "edge_count": len(network_data['edges'])
        }
        
    except Exception as e:
        logger.error(f"Error getting network data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Campaign endpoints
@app.post("/campaigns", response_model=CampaignResponse)
async def create_campaign(request: CreateCampaignRequest):
    """Create a new campaign"""
    try:
        campaign_id = neo4j_client.create_campaign(
            name=request.name,
            description=request.description,
            metadata=request.metadata
        )
        
        # Link indicators if provided
        if request.indicator_ids:
            for ind_id in request.indicator_ids:
                neo4j_client.link_indicator_to_campaign(
                    indicator_id=ind_id,
                    campaign_name=request.name,
                    confidence=request.confidence
                )
        
        return CampaignResponse(
            name=request.name,
            description=request.description,
            indicator_count=len(request.indicator_ids) if request.indicator_ids else 0,
            metadata=request.metadata
        )
        
    except Exception as e:
        logger.error(f"Error creating campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/campaigns/{campaign_name}/indicators")
async def get_campaign_indicators(campaign_name: str):
    """Get all indicators associated with a campaign"""
    try:
        query = f"""
        MATCH (i:Indicator)-[:PART_OF_CAMPAIGN]->(c:Campaign {{name: $name}})
        RETURN i
        """
        
        with neo4j_client.driver.session() as session:
            result = session.run(query, name=campaign_name)
            indicators = [dict(record['i']) for record in result]
        
        return {
            "campaign": campaign_name,
            "indicators": indicators,
            "total": len(indicators)
        }
        
    except Exception as e:
        logger.error(f"Error getting campaign indicators: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Analysis endpoints
@app.get("/analysis/clusters")
async def find_indicator_clusters(
    min_cluster_size: int = Query(3, ge=2, le=20)
):
    """Find clusters of related indicators"""
    try:
        clusters = neo4j_client.find_indicator_clusters(
            min_cluster_size=min_cluster_size
        )
        
        return {
            "clusters": clusters,
            "total_clusters": len(clusters),
            "min_cluster_size": min_cluster_size
        }
        
    except Exception as e:
        logger.error(f"Error finding clusters: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analysis/patterns")
async def detect_patterns():
    """Detect patterns across campaigns and indicators"""
    try:
        patterns = await agent.detect_patterns()
        
        return {
            "patterns": patterns,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error detecting patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Statistics endpoint
@app.get("/statistics")
async def get_statistics():
    """Get system-wide statistics"""
    try:
        neo4j_stats = neo4j_client.get_statistics()
        postgres_stats = postgres_client.get_statistics()
        
        return {
            "graph_database": neo4j_stats,
            "relational_database": postgres_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Test queries endpoint
@app.post("/test/queries")
async def run_test_queries():
    """Run predefined test queries to validate system"""
    try:
        test_results = []
        
        # Test Query 1: Semantic search
        result1 = await agent.search(
            query="What Russian disinformation campaigns target France?",
            search_type="semantic"
        )
        test_results.append({
            "query": "Russian disinformation campaigns targeting France",
            "type": "semantic",
            "results_found": len(result1['results'])
        })
        
        # Test Query 2: Indicator lookup
        doppelganger_domains = neo4j_client.find_indicators_by_type("domain", limit=100)
        test_results.append({
            "query": "Find all domains associated with Doppelgänger",
            "type": "indicator_lookup",
            "results_found": len(doppelganger_domains)
        })
        
        # Test Query 3: Graph traversal
        if doppelganger_domains:
            first_domain = doppelganger_domains[0]['id']
            related = neo4j_client.find_related_indicators(first_domain, max_hops=2)
            test_results.append({
                "query": f"Indicators within 2 hops of {first_domain}",
                "type": "graph_traversal",
                "results_found": len(related)
            })
        
        # Test Query 4: Pattern detection
        clusters = neo4j_client.find_indicator_clusters(min_cluster_size=2)
        test_results.append({
            "query": "Find clusters of related social media accounts",
            "type": "pattern_detection",
            "results_found": len(clusters)
        })
        
        return {
            "test_results": test_results,
            "all_tests_passed": all(r['results_found'] > 0 for r in test_results),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error running test queries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )