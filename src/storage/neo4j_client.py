"""
Neo4j Graph Database Client for Threat Intelligence Pipeline
Manages graph relationships between indicators, documents, and campaigns
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import json
from neo4j import GraphDatabase, Transaction
from neo4j.exceptions import Neo4jError
import hashlib
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the graph"""
    label: str
    properties: Dict[str, Any]
    node_id: Optional[str] = None


@dataclass 
class GraphRelationship:
    """Represents a relationship in the graph"""
    source_id: str
    target_id: str
    relationship_type: str
    properties: Dict[str, Any] = None


class Neo4jClient:
    """Neo4j database client for threat intelligence graph"""
    
    # Node labels
    LABELS = {
        'document': 'Document',
        'indicator': 'Indicator', 
        'campaign': 'Campaign',
        'threat_actor': 'ThreatActor',
        'chunk': 'TextChunk',
        'report': 'Report'
    }
    
    # Relationship types
    RELATIONSHIPS = {
        'mentioned_in': 'MENTIONED_IN',
        'related_to': 'RELATED_TO',
        'part_of': 'PART_OF_CAMPAIGN',
        'attributed_to': 'ATTRIBUTED_TO',
        'contains': 'CONTAINS',
        'extracted_from': 'EXTRACTED_FROM',
        'targets': 'TARGETS',
        'uses': 'USES'
    }
    
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        """
        Initialize Neo4j client
        
        Args:
            uri: Neo4j connection URI
            user: Username
            password: Password
            database: Database name
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {uri}")
            
            # Create indexes and constraints
            self._create_schema()
            
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def _create_schema(self):
        """Create indexes and constraints for optimal performance"""
        with self.driver.session(database=self.database) as session:
            # Create unique constraints
            constraints = [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Document) REQUIRE d.doc_id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (i:Indicator) REQUIRE i.value IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatActor) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (ch:TextChunk) REQUIRE ch.chunk_id IS UNIQUE"
            ]
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS FOR (i:Indicator) ON (i.type)",
                "CREATE INDEX IF NOT EXISTS FOR (i:Indicator) ON (i.normalized_value)",
                "CREATE INDEX IF NOT EXISTS FOR (d:Document) ON (d.hash)",
                "CREATE INDEX IF NOT EXISTS FOR (d:Document) ON (d.source)",
                "CREATE INDEX IF NOT EXISTS FOR (r:MENTIONED_IN) ON (r.confidence)",
                "CREATE INDEX IF NOT EXISTS FOR (r:RELATED_TO) ON (r.correlation_score)"
            ]
            
            # Execute schema creation
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.debug(f"Created constraint: {constraint[:50]}...")
                except Neo4jError as e:
                    if "already exists" not in str(e):
                        logger.warning(f"Constraint creation failed: {e}")
            
            for index in indexes:
                try:
                    session.run(index)
                    logger.debug(f"Created index: {index[:50]}...")
                except Neo4jError as e:
                    if "already exists" not in str(e):
                        logger.warning(f"Index creation failed: {e}")
    
    def create_document(self, 
                       doc_id: str,
                       title: str,
                       source: str,
                       metadata: Dict = None) -> str:
        """Create a document node"""
        
        query = """
        MERGE (d:Document {doc_id: $doc_id})
        SET d.title = $title,
            d.source = $source,
            d.created_at = datetime(),
            d.metadata = $metadata
        RETURN d.doc_id as id
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, 
                               doc_id=doc_id,
                               title=title,
                               source=source,
                               metadata=json.dumps(metadata or {}))
            
            record = result.single()
            return record['id'] if record else None
    
    def create_indicator(self,
                        indicator_type: str,
                        value: str,
                        normalized_value: str,
                        metadata: Dict = None) -> str:
        """Create an indicator node"""
        
        # Generate unique ID
        indicator_id = hashlib.md5(f"{indicator_type}:{normalized_value}".encode()).hexdigest()
        
        query = """
        MERGE (i:Indicator {value: $value})
        SET i.type = $type,
            i.normalized_value = $normalized_value,
            i.indicator_id = $indicator_id,
            i.first_seen = coalesce(i.first_seen, datetime()),
            i.last_seen = datetime(),
            i.metadata = $metadata,
            i.occurrence_count = coalesce(i.occurrence_count, 0) + 1
        RETURN i.indicator_id as id
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               type=indicator_type,
                               value=value,
                               normalized_value=normalized_value,
                               indicator_id=indicator_id,
                               metadata=json.dumps(metadata or {}))
            
            record = result.single()
            return record['id'] if record else None
    
    def create_indicator_mention(self,
                                 indicator_id: str,
                                 document_id: str,
                                 context: str,
                                 confidence: float = 1.0,
                                 page_number: int = None):
        """Create MENTIONED_IN relationship between indicator and document"""
        
        query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})
        MATCH (d:Document {doc_id: $document_id})
        MERGE (i)-[r:MENTIONED_IN]->(d)
        SET r.context = $context,
            r.confidence = $confidence,
            r.page_number = $page_number,
            r.created_at = datetime()
        RETURN r
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               indicator_id=indicator_id,
                               document_id=document_id,
                               context=context,
                               confidence=confidence,
                               page_number=page_number)
            return result.single() is not None
    
    def create_campaign(self,
                       name: str,
                       description: str = None,
                       metadata: Dict = None) -> str:
        """Create a campaign node"""
        
        query = """
        MERGE (c:Campaign {name: $name})
        SET c.description = $description,
            c.created_at = datetime(),
            c.metadata = $metadata
        RETURN c.name as id
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               name=name,
                               description=description,
                               metadata=json.dumps(metadata or {}))
            
            record = result.single()
            return record['id'] if record else None
    
    def create_threat_actor(self,
                           name: str,
                           aliases: List[str] = None,
                           metadata: Dict = None) -> str:
        """Create a threat actor node"""
        
        query = """
        MERGE (t:ThreatActor {name: $name})
        SET t.aliases = $aliases,
            t.created_at = datetime(),
            t.metadata = $metadata
        RETURN t.name as id
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               name=name,
                               aliases=aliases or [],
                               metadata=json.dumps(metadata or {}))
            
            record = result.single()
            return record['id'] if record else None
    
    def link_indicator_to_campaign(self,
                                   indicator_id: str,
                                   campaign_name: str,
                                   confidence: float = 1.0):
        """Link indicator to campaign"""
        
        query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})
        MATCH (c:Campaign {name: $campaign_name})
        MERGE (i)-[r:PART_OF_CAMPAIGN]->(c)
        SET r.confidence = $confidence,
            r.created_at = datetime()
        RETURN r
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               indicator_id=indicator_id,
                               campaign_name=campaign_name,
                               confidence=confidence)
            return result.single() is not None
    
    def link_campaign_to_actor(self,
                               campaign_name: str,
                               actor_name: str,
                               confidence: float = 1.0):
        """Link campaign to threat actor"""
        
        query = """
        MATCH (c:Campaign {name: $campaign_name})
        MATCH (t:ThreatActor {name: $actor_name})
        MERGE (c)-[r:ATTRIBUTED_TO]->(t)
        SET r.confidence = $confidence,
            r.created_at = datetime()
        RETURN r
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               campaign_name=campaign_name,
                               actor_name=actor_name,
                               confidence=confidence)
            return result.single() is not None
    
    def create_indicator_relationship(self,
                                     source_id: str,
                                     target_id: str,
                                     correlation_score: float = 1.0,
                                     relationship_type: str = "RELATED_TO"):
        """Create relationship between two indicators"""
        
        query = f"""
        MATCH (source:Indicator {{indicator_id: $source_id}})
        MATCH (target:Indicator {{indicator_id: $target_id}})
        MERGE (source)-[r:{relationship_type}]->(target)
        SET r.correlation_score = $correlation_score,
            r.created_at = datetime()
        RETURN r
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               source_id=source_id,
                               target_id=target_id,
                               correlation_score=correlation_score)
            return result.single() is not None
    
    def find_indicators_by_type(self, indicator_type: str, limit: int = 100) -> List[Dict]:
        """Find all indicators of a specific type"""
        
        query = """
        MATCH (i:Indicator {type: $type})
        RETURN i.indicator_id as id,
               i.type as type,
               i.value as value,
               i.normalized_value as normalized_value,
               i.occurrence_count as count,
               i.first_seen as first_seen,
               i.last_seen as last_seen,
               i.metadata as metadata
        ORDER BY i.occurrence_count DESC
        LIMIT $limit
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, type=indicator_type, limit=limit)
            
            indicators = []
            for record in result:
                indicator = dict(record)
                # Convert Neo4j DateTime objects to Python datetime objects
                if 'first_seen' in indicator and indicator['first_seen'] is not None:
                    indicator['first_seen'] = indicator['first_seen'].to_native()
                if 'last_seen' in indicator and indicator['last_seen'] is not None:
                    indicator['last_seen'] = indicator['last_seen'].to_native()
                    
                if indicator['metadata']:
                    indicator['metadata'] = json.loads(indicator['metadata'])
                indicators.append(indicator)
            
            return indicators
    
    def find_related_indicators(self,
                                indicator_id: str,
                                max_hops: int = 2,
                                limit: int = 50) -> List[Dict]:
        """Find indicators related within N hops"""
        
        query = f"""
        MATCH path = (start:Indicator {{indicator_id: $indicator_id}})-[*1..{max_hops}]-(related:Indicator)
        WHERE start <> related
        // Add related.occurrence_count to the WITH clause so it's available for ORDER BY
        WITH related, min(length(path)) as distance, related.occurrence_count as occurrence_count
        ORDER BY distance, occurrence_count DESC
        RETURN DISTINCT
            related.indicator_id as id,
            related.type as type,
            related.value as value,
            related.normalized_value as normalized_value,
            distance
        LIMIT $limit
        """

        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                               indicator_id=indicator_id,
                               limit=limit)
            
            return [dict(record) for record in result]
    
    def get_indicator_context(self, indicator_id: str) -> Dict:
        """Get full context for an indicator"""
        
        # Get indicator details
        indicator_query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})
        RETURN i.indicator_id as indicator_id,
               i.type as type,
               i.value as value,
               i.normalized_value as normalized_value,
               i.occurrence_count as occurrence_count,
               toString(i.first_seen) as first_seen,
               toString(i.last_seen) as last_seen,
               i.metadata as metadata
        """
        
        # Get documents mentioning the indicator
        docs_query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})-[r:MENTIONED_IN]->(d:Document)
        RETURN d.doc_id as doc_id,
               d.title as title,
               d.source as source,
               r.context as context,
               r.confidence as confidence,
               r.page_number as page_number
        ORDER BY r.confidence DESC
        """
        
        # Get related campaigns
        campaigns_query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})-[:PART_OF_CAMPAIGN]->(c:Campaign)
        OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(t:ThreatActor)
        RETURN c.name as name,
               c.description as description,
               collect(DISTINCT t.name) as threat_actors
        """
        
        # Get related indicators
        related_query = """
        MATCH (i:Indicator {indicator_id: $indicator_id})-[r:RELATED_TO]-(related:Indicator)
        RETURN related.type as type,
               related.value as value,
               r.correlation_score as score
        ORDER BY r.correlation_score DESC
        LIMIT 10
        """
        
        with self.driver.session(database=self.database) as session:
            # Get indicator
            result = session.run(indicator_query, indicator_id=indicator_id)
            indicator = result.single()
            
            if not indicator:
                return None
            
            # Build context with converted indicator data
            context = {
                'indicator': dict(indicator),
                'documents': [],
                'campaigns': [],
                'related_indicators': []
            }
            
            # Parse metadata if it exists
            if context['indicator'].get('metadata'):
                try:
                    context['indicator']['metadata'] = json.loads(context['indicator']['metadata'])
                except:
                    pass
            
            # Get documents
            result = session.run(docs_query, indicator_id=indicator_id)
            context['documents'] = [dict(record) for record in result]
            
            # Get campaigns
            result = session.run(campaigns_query, indicator_id=indicator_id)
            context['campaigns'] = [dict(record) for record in result]
            
            # Get related indicators
            result = session.run(related_query, indicator_id=indicator_id)
            context['related_indicators'] = [dict(record) for record in result]
            
            return context
    
    def get_network_graph(self,
                         center_node_id: str,
                         max_hops: int = 2,
                         limit: int = 100) -> Dict:
        """Get network graph data for visualization"""
        
        query = f"""
        MATCH path = (center)-[*0..{max_hops}]-(connected)
        WHERE 
            (
                (center:Indicator AND center.indicator_id = $node_id) OR
                (center:Campaign AND center.name = $node_id) OR
                (center:ThreatActor AND center.name = $node_id)
            )
        WITH center, connected, path
        LIMIT $limit
        
        // Collect and flatten nodes and relationships
        WITH collect(DISTINCT center) + collect(DISTINCT connected) as nodes,
            [rel IN relationships(path) | rel] as all_rels
        
        UNWIND all_rels as rel_to_unwind
        
        WITH nodes, collect(DISTINCT rel_to_unwind) as relationships
        
        UNWIND nodes as node
        WITH collect(DISTINCT {{
            id: CASE 
                WHEN node:Indicator THEN node.indicator_id
                WHEN node:Campaign THEN node.name
                WHEN node:ThreatActor THEN node.name
                ELSE toString(id(node))
            END,
            label: labels(node)[0],
            properties: properties(node)
        }}) as nodes, relationships
        
        UNWIND relationships as rel
        WITH nodes, collect(DISTINCT {{
            source: CASE
                WHEN startNode(rel):Indicator THEN startNode(rel).indicator_id
                WHEN startNode(rel):Campaign THEN startNode(rel).name
                WHEN startNode(rel):ThreatActor THEN startNode(rel).name
                ELSE toString(id(startNode(rel)))
            END,
            target: CASE
                WHEN endNode(rel):Indicator THEN endNode(rel).indicator_id
                WHEN endNode(rel):Campaign THEN endNode(rel).name
                WHEN endNode(rel):ThreatActor THEN endNode(rel).name
                ELSE toString(id(endNode(rel)))
            END,
            type: type(rel),
            properties: properties(rel)
        }}) as relationships
        RETURN nodes, relationships
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, node_id=center_node_id, limit=limit)
            record = result.single()
            
            if record:
                return {
                    'nodes': record['nodes'],
                    'edges': record['relationships']
                }
            return {'nodes': [], 'edges': []}
    
    def find_indicator_clusters(self, min_cluster_size: int = 3) -> List[Dict]:
        """Find clusters of related indicators"""
        
        # First check if GDS is available
        try:
            with self.driver.session(database=self.database) as session:
                # Check if GDS plugin is installed
                result = session.run("CALL gds.version()")
                gds_version = result.single()
                logger.info(f"GDS version: {gds_version}")
        except Neo4jError:
            logger.warning("GDS plugin not available, using alternative clustering method")
            return self._find_clusters_without_gds(min_cluster_size)
        
        # GDS-based clustering
        try:
            # First ensure we have RELATED_TO relationships
            with self.driver.session(database=self.database) as session:
                # Create some RELATED_TO relationships based on co-occurrence
                session.run("""
                    MATCH (i1:Indicator)-[:MENTIONED_IN]->(d:Document)<-[:MENTIONED_IN]-(i2:Indicator)
                    WHERE i1 <> i2
                    MERGE (i1)-[r:RELATED_TO]->(i2)
                    SET r.correlation_score = 1.0
                """)
                
                # Now try GDS clustering
                query = """
                CALL gds.graph.project.cypher(
                    'indicator-graph',
                    'MATCH (n:Indicator) RETURN id(n) AS id',
                    'MATCH (i1:Indicator)-[r:RELATED_TO]-(i2:Indicator) 
                     RETURN id(i1) AS source, id(i2) AS target, 
                     coalesce(r.correlation_score, 1.0) AS weight'
                ) YIELD graphName
                
                CALL gds.louvain.stream('indicator-graph', {
                    relationshipWeightProperty: 'weight'
                }) YIELD nodeId, communityId
                
                WITH communityId, collect(gds.util.asNode(nodeId)) as indicators
                WHERE size(indicators) >= $min_size
                
                CALL gds.graph.drop('indicator-graph', false) YIELD graphName as dropped
                
                RETURN communityId as cluster_id,
                       size(indicators) as size,
                       [i in indicators | {
                           id: i.indicator_id,
                           type: i.type,
                           value: i.value
                       }] as indicators
                ORDER BY size DESC
                """
                
                result = session.run(query, min_size=min_cluster_size)
                return [dict(record) for record in result]
                
        except Neo4jError as e:
            logger.warning(f"GDS clustering failed: {e}")
            return self._find_clusters_without_gds(min_cluster_size)
    
    def _find_clusters_without_gds(self, min_cluster_size: int = 3) -> List[Dict]:
        """Find clusters without using GDS plugin"""
        
        query = """
        // Find indicators that appear together in documents
        MATCH (i1:Indicator)-[:MENTIONED_IN]->(d:Document)<-[:MENTIONED_IN]-(i2:Indicator)
        WHERE i1.indicator_id < i2.indicator_id
        WITH i1, i2, count(distinct d) as co_occurrences
        WHERE co_occurrences >= 2
        
        // Create temporary relationships for clustering
        WITH collect({source: i1, target: i2, weight: co_occurrences}) as relationships
        
        // Simple clustering based on connected components
        UNWIND relationships as rel
        WITH rel.source as indicator
        MATCH (indicator)-[:MENTIONED_IN]->(d:Document)<-[:MENTIONED_IN]-(related:Indicator)
        WHERE indicator <> related
        WITH indicator, collect(DISTINCT related) as cluster_members
        WHERE size(cluster_members) >= $min_size - 1
        
        RETURN indicator.indicator_id as cluster_center,
               size(cluster_members) + 1 as size,
               [{
                   id: indicator.indicator_id,
                   type: indicator.type,
                   value: indicator.value
               }] + [m in cluster_members | {
                   id: m.indicator_id,
                   type: m.type,
                   value: m.value
               }] as indicators
        ORDER BY size DESC
        LIMIT 10
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, min_size=min_cluster_size)
                
                clusters = []
                cluster_id = 0
                for record in result:
                    clusters.append({
                        'cluster_id': cluster_id,
                        'size': record['size'],
                        'indicators': record['indicators']
                    })
                    cluster_id += 1
                
                return clusters
                
        except Neo4jError as e:
            logger.error(f"Clustering without GDS failed: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        
        query = """
        CALL { MATCH (d:Document) RETURN count(d) as doc_count }
        CALL { MATCH (i:Indicator) RETURN count(i) as indicator_count, collect(DISTINCT i.type) as types }
        CALL { MATCH ()-[r:MENTIONED_IN]->() RETURN count(r) as mention_count }
        CALL { MATCH (c:Campaign) RETURN count(c) as campaign_count }
        CALL { MATCH (t:ThreatActor) RETURN count(t) as actor_count }
        
        RETURN {
            documents: doc_count,
            indicators: indicator_count,
            indicator_types: types,
            mentions: mention_count,
            campaigns: campaign_count,
            threat_actors: actor_count
        } as stats
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            record = result.single()
            return record['stats'] if record else {}
    
    def clear_database(self):
        """Clear all data from database (use with caution!)"""
        
        query = "MATCH (n) DETACH DELETE n"
        
        with self.driver.session(database=self.database) as session:
            session.run(query)
            logger.warning("Cleared all data from Neo4j database")
    
    def close(self):
        """Close database connection"""
        if self.driver:
            self.driver.close()
            logger.info("Closed Neo4j connection")