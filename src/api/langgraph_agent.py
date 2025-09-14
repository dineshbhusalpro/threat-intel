"""
LangGraph Agent for Intelligent Query Routing
Manages complex search and analysis operations across multiple data stores
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import asyncio
from enum import Enum

from langgraph.graph import StateGraph, END
from langchain.schema import Document
from langchain.callbacks.manager import CallbackManagerForRetrieverRun
import numpy as np

logger = logging.getLogger(__name__)


class QueryIntent(Enum):
    """Query intent classification"""
    INDICATOR_LOOKUP = "indicator_lookup"
    SEMANTIC_SEARCH = "semantic_search"
    GRAPH_TRAVERSAL = "graph_traversal"
    PATTERN_ANALYSIS = "pattern_analysis"
    CAMPAIGN_ANALYSIS = "campaign_analysis"
    TIMELINE_QUERY = "timeline_query"
    UNKNOWN = "unknown"


class AgentState(Dict):
    """State management for LangGraph agent"""
    query: str
    intent: QueryIntent
    results: List[Any]
    metadata: Dict[str, Any]
    error: Optional[str]
    processing_time: float


class ThreatIntelligenceAgent:
    """Intelligent agent for threat intelligence queries"""
    
    def __init__(self,
                 neo4j_client,
                 postgres_client,
                 vector_store,
                 embedder):
        """
        Initialize the agent
        
        Args:
            neo4j_client: Neo4j database client
            postgres_client: PostgreSQL database client
            vector_store: Vector store for similarity search
            embedder: Embedding model
        """
        self.neo4j = neo4j_client
        self.postgres = postgres_client
        self.vector_store = vector_store
        self.embedder = embedder
        
        # Build the state graph
        self.graph = self._build_graph()
        self.app = self.graph.compile()
        
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine"""
        
        # Create the graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("classify_intent", self.classify_intent)
        workflow.add_node("route_query", self.route_query)
        workflow.add_node("indicator_search", self.indicator_search)
        workflow.add_node("semantic_search", self.semantic_search)
        workflow.add_node("graph_search", self.graph_search)
        workflow.add_node("pattern_search", self.pattern_search)
        workflow.add_node("synthesize_results", self.synthesize_results)
        
        # Set entry point
        workflow.set_entry_point("classify_intent")
        
        # Add edges
        workflow.add_edge("classify_intent", "route_query")
        
        # Add conditional edges based on intent
        workflow.add_conditional_edges(
            "route_query",
            self.determine_search_path,
            {
                "indicator": "indicator_search",
                "semantic": "semantic_search",
                "graph": "graph_search",
                "pattern": "pattern_search",
                "synthesize": "synthesize_results"
            }
        )
        
        # All search nodes lead to synthesis
        workflow.add_edge("indicator_search", "synthesize_results")
        workflow.add_edge("semantic_search", "synthesize_results")
        workflow.add_edge("graph_search", "synthesize_results")
        workflow.add_edge("pattern_search", "synthesize_results")
        
        # Synthesis leads to end
        workflow.add_edge("synthesize_results", END)
        
        return workflow
    
    async def search(self,
                    query: str,
                    search_type: str = "hybrid",
                    filters: Dict = None,
                    limit: int = 10) -> Dict:
        """
        Execute a search query
        
        Args:
            query: Search query
            search_type: Type of search
            filters: Search filters
            limit: Maximum results
            
        Returns:
            Search results dictionary
        """
        start_time = datetime.utcnow()
        
        # Initialize state
        initial_state = AgentState(
            query=query,
            intent=QueryIntent.UNKNOWN,
            results=[],
            metadata={
                "search_type": search_type,
                "filters": filters or {},
                "limit": limit
            },
            error=None,
            processing_time=0.0
        )
        
        try:
            # Run the graph
            final_state = await self.app.ainvoke(initial_state)
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "results": final_state["results"],
                "total": len(final_state["results"]),
                "search_type": search_type,
                "intent": final_state["intent"].value,
                "processing_time": processing_time,
                "metadata": final_state["metadata"]
            }
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {
                "results": [],
                "total": 0,
                "search_type": search_type,
                "error": str(e),
                "processing_time": (datetime.utcnow() - start_time).total_seconds()
            }
    
    def classify_intent(self, state: AgentState) -> AgentState:
        """Classify the intent of the query"""
        query = state["query"].lower()
        
        # Simple rule-based classification (could be replaced with ML model)
        if any(keyword in query for keyword in ["find", "get", "show", "list"]):
            if any(word in query for word in ["domain", "ip", "url", "email", "indicator"]):
                state["intent"] = QueryIntent.INDICATOR_LOOKUP
            elif any(word in query for word in ["related", "connected", "hops", "graph"]):
                state["intent"] = QueryIntent.GRAPH_TRAVERSAL
            elif any(word in query for word in ["campaign", "actor", "threat"]):
                state["intent"] = QueryIntent.CAMPAIGN_ANALYSIS
            else:
                state["intent"] = QueryIntent.SEMANTIC_SEARCH
        elif any(keyword in query for keyword in ["pattern", "cluster", "group"]):
            state["intent"] = QueryIntent.PATTERN_ANALYSIS
        elif any(keyword in query for keyword in ["timeline", "when", "history"]):
            state["intent"] = QueryIntent.TIMELINE_QUERY
        else:
            state["intent"] = QueryIntent.SEMANTIC_SEARCH
        
        logger.info(f"Classified intent: {state['intent'].value}")
        return state
    
    def route_query(self, state: AgentState) -> AgentState:
        """Route query to appropriate search methods"""
        # This node prepares the query for routing
        state["metadata"]["routed"] = True
        return state
    
    def determine_search_path(self, state: AgentState) -> str:
        """Determine which search path to take"""
        intent = state["intent"]
        
        if intent == QueryIntent.INDICATOR_LOOKUP:
            return "indicator"
        elif intent == QueryIntent.SEMANTIC_SEARCH:
            return "semantic"
        elif intent == QueryIntent.GRAPH_TRAVERSAL:
            return "graph"
        elif intent == QueryIntent.PATTERN_ANALYSIS:
            return "pattern"
        else:
            return "semantic"  # Default to semantic search
    
    def indicator_search(self, state: AgentState) -> AgentState:
        """Perform indicator-specific search"""
        query = state["query"]
        filters = state["metadata"].get("filters", {})
        limit = state["metadata"].get("limit", 10)
        
        try:
            # Extract indicator type from query if possible
            indicator_type = self._extract_indicator_type(query)
            
            if indicator_type:
                # Search for specific indicator type
                indicators = self.neo4j.find_indicators_by_type(
                    indicator_type=indicator_type,
                    limit=limit
                )
            else:
                # General indicator search
                indicators = self.postgres.search_indicators(
                    value_pattern=query,
                    limit=limit
                )
            
            # Format results
            results = []
            for ind in indicators:
                results.append({
                    "score": 1.0,
                    "type": "indicator",
                    "content": ind.get("value", ""),
                    "metadata": {
                        "indicator_type": ind.get("type"),
                        "normalized_value": ind.get("normalized_value"),
                        "occurrence_count": ind.get("occurrence_count", 0),
                        "first_seen": str(ind.get("first_seen", "")),
                        "last_seen": str(ind.get("last_seen", ""))
                    }
                })
            
            state["results"] = results
            
        except Exception as e:
            logger.error(f"Indicator search error: {e}")
            state["error"] = str(e)
        
        return state
    
    def semantic_search(self, state: AgentState) -> AgentState:
        """Perform semantic similarity search"""
        query = state["query"]
        limit = state["metadata"].get("limit", 10)
        
        try:
            # Generate query embedding
            query_embedding = self.embedder.embed_text(query)
            
            # Search vector store
            results = self.postgres.vector_search(
                query_embedding=query_embedding,
                limit=limit,
                threshold=0.5
            )
            
            # Format results
            formatted_results = []
            for result in results:
                formatted_results.append({
                    "score": result.get("similarity", 0.0),
                    "type": "semantic",
                    "content": result.get("content", ""),
                    "source": result.get("document_id"),
                    "metadata": {
                        "chunk_id": result.get("chunk_id"),
                        "page_numbers": result.get("page_numbers", [])
                    }
                })
            
            state["results"] = formatted_results
            
        except Exception as e:
            logger.error(f"Semantic search error: {e}")
            state["error"] = str(e)
        
        return state
    
    def graph_search(self, state: AgentState) -> AgentState:
        """Perform graph traversal search"""
        query = state["query"]
        limit = state["metadata"].get("limit", 10)
        
        try:
            # Extract node ID from query
            node_id = self._extract_node_id(query)
            
            if node_id:
                # Get related indicators
                max_hops = self._extract_max_hops(query)
                related = self.neo4j.find_related_indicators(
                    indicator_id=node_id,
                    max_hops=max_hops,
                    limit=limit
                )
                
                # Format results
                results = []
                for item in related:
                    results.append({
                        "score": 1.0 / (item.get("distance", 1) + 1),
                        "type": "graph",
                        "content": item.get("value", ""),
                        "metadata": {
                            "indicator_type": item.get("type"),
                            "distance": item.get("distance"),
                            "normalized_value": item.get("normalized_value")
                        }
                    })
                
                state["results"] = results
            
        except Exception as e:
            logger.error(f"Graph search error: {e}")
            state["error"] = str(e)
        
        return state
    
    def pattern_search(self, state: AgentState) -> AgentState:
        """Perform pattern analysis search"""
        query = state["query"]
        
        try:
            # Find indicator clusters
            clusters = self.neo4j.find_indicator_clusters(min_cluster_size=3)
            
            # Format results
            results = []
            for cluster in clusters[:10]:  # Limit to top 10 clusters
                results.append({
                    "score": cluster.get("size", 0) / 100.0,
                    "type": "pattern",
                    "content": f"Cluster {cluster.get('cluster_id')} with {cluster.get('size')} indicators",
                    "metadata": {
                        "cluster_id": cluster.get("cluster_id"),
                        "size": cluster.get("size"),
                        "indicators": cluster.get("indicators", [])[:5]  # Sample of indicators
                    }
                })
            
            state["results"] = results
            
        except Exception as e:
            logger.error(f"Pattern search error: {e}")
            state["error"] = str(e)
        
        return state
    
    def synthesize_results(self, state: AgentState) -> AgentState:
        """Synthesize and rank final results"""
        results = state.get("results", [])
        
        if not results:
            return state
        
        # Sort by score
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        # Limit results
        limit = state["metadata"].get("limit", 10)
        state["results"] = results[:limit]
        
        # Add summary metadata
        state["metadata"]["result_summary"] = {
            "total_found": len(results),
            "returned": len(state["results"]),
            "top_score": results[0].get("score", 0) if results else 0,
            "result_types": list(set(r.get("type") for r in state["results"]))
        }
        
        return state
    
    async def detect_patterns(self) -> List[Dict]:
        """Detect patterns across the threat intelligence data"""
        patterns = []

        # Use the current event loop for async operations
        loop = asyncio.get_event_loop()
        
        try:
            # Pattern 1: Common indicators across campaigns
            campaign_query = """
            MATCH (i:Indicator)-[:PART_OF_CAMPAIGN]->(c:Campaign)
            WITH i, COLLECT(c.name) as campaign_names
            WHERE size(campaign_names) > 1
            RETURN i.type as indicator_type,
                i.value as indicator_value,
                size(campaign_names) as campaign_count,
                campaign_names as campaigns
            ORDER BY campaign_count DESC
            LIMIT 10
            """
            
            # Run the synchronous database query in a separate thread
            def run_campaign_query():
                with self.neo4j.driver.session() as session:
                    return [dict(record) for record in session.run(campaign_query)]
            
            campaign_results = await loop.run_in_executor(None, run_campaign_query)
            
            for record in campaign_results:
                patterns.append({
                    "pattern_type": "cross_campaign_indicator",
                    "description": f"Indicator {record['indicator_value']} appears in {record['campaign_count']} campaigns",
                    "confidence": min(record['campaign_count'] / 10.0, 1.0),
                    "indicators_involved": [record['indicator_value']],
                    "campaigns_involved": record['campaigns']
                })
            
            # Pattern 2: Indicator type distribution (already fixed in previous response)
            type_query = """
            MATCH (i:Indicator)
            RETURN i.type as type, COUNT(*) as count
            ORDER BY count DESC
            """
            
            def run_type_query():
                with self.neo4j.driver.session() as session:
                    return {record['type']: record['count'] for record in session.run(type_query)}

            type_distribution = await loop.run_in_executor(None, run_type_query)
            
            # Find anomalies in distribution
            total = sum(type_distribution.values())
            if total > 0:
                for ind_type, count in type_distribution.items():
                    ratio = count / total
                    if ratio > 0.3:  # If one type dominates
                        patterns.append({
                            "pattern_type": "dominant_indicator_type",
                            "description": f"{ind_type} indicators make up {ratio:.1%} of all indicators",
                            "confidence": ratio,
                            "indicators_involved": [],
                            "metadata": {"type": ind_type, "count": count}
                        })
        
        except Exception as e:
            logger.error(f"Pattern detection error: {e}")
            # The API endpoint's try-except block will handle raising HTTPException
            raise
        
        return patterns
    
    def _extract_indicator_type(self, query: str) -> Optional[str]:
        """Extract indicator type from query"""
        query_lower = query.lower()
        
        type_keywords = {
            "domain": ["domain", "domains"],
            "url": ["url", "urls", "link", "links"],
            "ip_address": ["ip", "ips", "address", "addresses"],
            "email": ["email", "emails"],
            "phone": ["phone", "phones", "number"],
            "md5": ["md5"],
            "sha1": ["sha1"],
            "sha256": ["sha256"]
        }
        
        for ind_type, keywords in type_keywords.items():
            if any(keyword in query_lower for keyword in keywords):
                return ind_type
        
        return None
    
    def _extract_node_id(self, query: str) -> Optional[str]:
        """Extract node ID from query"""
        # Simple extraction - look for MD5 hash pattern
        import re
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        match = re.search(md5_pattern, query)
        return match.group() if match else None
    
    def _extract_max_hops(self, query: str) -> int:
        """Extract max hops from query"""
        import re
        # Look for patterns like "2 hops", "within 3 hops"
        hop_pattern = r'(\d+)\s*hop'
        match = re.search(hop_pattern, query.lower())
        if match:
            return min(int(match.group(1)), 5)  # Cap at 5 hops
        return 2  # Default to 2 hops