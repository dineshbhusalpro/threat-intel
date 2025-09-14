"""
Pydantic Models for Threat Intelligence API
Data validation and serialization models
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum


class SearchType(str, Enum):
    """Search type enumeration"""
    SEMANTIC = "semantic"
    STRUCTURED = "structured"
    HYBRID = "hybrid"
    GRAPH = "graph"


class IndicatorTypeEnum(str, Enum):
    """Indicator type enumeration"""
    DOMAIN = "domain"
    URL = "url"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE = "phone"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    INSTAGRAM = "instagram"
    YOUTUBE = "youtube"
    LINKEDIN = "linkedin"
    TIKTOK = "tiktok"
    TELEGRAM = "telegram"
    REDDIT = "reddit"
    VK = "vk"
    TRUTH_SOCIAL = "truth_social"
    PARLER = "parler"
    GOOGLE_ANALYTICS = "google_analytics"
    ADSENSE = "adsense"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"


# Request Models
class ProcessDocumentRequest(BaseModel):
    """Request model for document processing"""
    file_path: str = Field(..., description="Path to PDF file")
    create_embeddings: bool = Field(True, description="Generate embeddings for chunks")
    extract_images: bool = Field(True, description="Extract images from PDF")
    extract_tables: bool = Field(True, description="Extract tables from PDF")
    languages: List[str] = Field(
        default=["en", "fr", "de"],
        description="Languages for OCR and processing"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class SearchRequest(BaseModel):
    """Request model for search operations"""
    query: str = Field(..., description="Search query")
    search_type: SearchType = Field(
        SearchType.HYBRID,
        description="Type of search to perform"
    )
    filters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Search filters"
    )
    limit: int = Field(10, ge=1, le=100, description="Maximum results")
    include_context: bool = Field(True, description="Include context in results")


class CreateCampaignRequest(BaseModel):
    """Request model for creating campaigns"""
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    indicator_ids: Optional[List[str]] = Field(
        default=None,
        description="Initial indicators to link"
    )
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for indicator links"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class CreateThreatActorRequest(BaseModel):
    """Request model for creating threat actors"""
    name: str = Field(..., description="Threat actor name")
    aliases: List[str] = Field(
        default_factory=list,
        description="Known aliases"
    )
    country: Optional[str] = Field(None, description="Country of origin")
    description: Optional[str] = Field(None, description="Description")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class LinkIndicatorRequest(BaseModel):
    """Request model for linking indicators"""
    source_indicator_id: str = Field(..., description="Source indicator ID")
    target_indicator_id: str = Field(..., description="Target indicator ID")
    relationship_type: str = Field(
        "RELATED_TO",
        description="Type of relationship"
    )
    correlation_score: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Correlation strength"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Relationship metadata"
    )


# Response Models
class ProcessDocumentResponse(BaseModel):
    """Response model for document processing"""
    document_id: str
    title: str
    total_pages: int
    languages_detected: List[str]
    indicators_extracted: int
    indicator_breakdown: Dict[str, int]
    processing_time: float
    status: str
    

class IndicatorResponse(BaseModel):
    """Response model for indicator data"""
    id: str = Field(..., alias="indicator_id")
    type: str
    value: str
    normalized_value: str
    occurrence_count: int = Field(1, alias="count")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        populate_by_name = True


class DocumentResponse(BaseModel):
    """Response model for document data"""
    doc_id: str
    title: str
    source: str
    context: Optional[str] = None
    confidence: Optional[float] = None
    page_number: Optional[int] = None


class CampaignResponse(BaseModel):
    """Response model for campaign data"""
    name: str
    description: Optional[str] = None
    threat_actors: List[str] = Field(default_factory=list)
    indicator_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RelatedIndicatorResponse(BaseModel):
    """Response model for related indicators"""
    type: str
    value: str
    score: float = Field(..., alias="correlation_score")
    distance: Optional[int] = None
    
    class Config:
        populate_by_name = True


class IndicatorContextResponse(BaseModel):
    """Response model for indicator context"""
    indicator: Dict[str, Any]
    documents: List[DocumentResponse]
    campaigns: List[CampaignResponse]
    related_indicators: List[RelatedIndicatorResponse]


class SearchResult(BaseModel):
    """Individual search result"""
    score: float
    type: str
    content: str
    source: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    highlights: List[str] = Field(default_factory=list)


class SearchResponse(BaseModel):
    """Response model for search operations"""
    query: str
    results: List[SearchResult]
    total_results: int
    search_type: str
    processing_time: float
    suggestions: List[str] = Field(default_factory=list)


class NetworkNode(BaseModel):
    """Network visualization node"""
    id: str
    label: str
    type: str
    properties: Dict[str, Any]
    size: Optional[float] = None
    color: Optional[str] = None


class NetworkEdge(BaseModel):
    """Network visualization edge"""
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    weight: Optional[float] = None


class NetworkGraphResponse(BaseModel):
    """Response model for network visualization"""
    center_node: str
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]
    node_count: int
    edge_count: int


class ClusterResponse(BaseModel):
    """Response model for indicator clusters"""
    cluster_id: int
    size: int
    indicators: List[Dict[str, Any]]
    central_indicator: Optional[Dict[str, Any]] = None


class PatternResponse(BaseModel):
    """Response model for pattern detection"""
    pattern_type: str
    description: str
    confidence: float
    indicators_involved: List[str]
    campaigns_involved: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StatisticsResponse(BaseModel):
    """Response model for system statistics"""
    graph_database: Dict[str, Any]
    relational_database: Dict[str, Any]
    timestamp: datetime
    processing_metrics: Optional[Dict[str, Any]] = None


class TestQueryResult(BaseModel):
    """Result of a test query"""
    query: str
    type: str
    results_found: int
    execution_time: Optional[float] = None
    success: bool = True
    error: Optional[str] = None


class TestQueriesResponse(BaseModel):
    """Response model for test queries"""
    test_results: List[TestQueryResult]
    all_tests_passed: bool
    timestamp: datetime
    summary: Optional[str] = None


# Validation helpers
class QueryValidator:
    """Validate and sanitize search queries"""
    
    @staticmethod
    def validate_query(query: str) -> str:
        """Validate and clean search query"""
        # Remove excessive whitespace
        query = ' '.join(query.split())
        
        # Check minimum length
        if len(query) < 2:
            raise ValueError("Query too short")
        
        # Check maximum length
        if len(query) > 1000:
            raise ValueError("Query too long")
        
        return query
    
    @staticmethod
    def validate_indicator_id(indicator_id: str) -> str:
        """Validate indicator ID format"""
        if not indicator_id or len(indicator_id) != 32:
            raise ValueError("Invalid indicator ID format")
        return indicator_id


class FilterBuilder:
    """Build filters for database queries"""
    
    @staticmethod
    def build_indicator_filters(filters: Dict[str, Any]) -> Dict[str, Any]:
        """Build filters for indicator queries"""
        valid_filters = {}
        
        if 'type' in filters and filters['type'] in IndicatorTypeEnum.__members__.values():
            valid_filters['type'] = filters['type']
        
        if 'confidence_min' in filters:
            valid_filters['confidence_min'] = max(0.0, min(1.0, float(filters['confidence_min'])))
        
        if 'date_from' in filters:
            valid_filters['date_from'] = filters['date_from']
        
        if 'date_to' in filters:
            valid_filters['date_to'] = filters['date_to']
        
        return valid_filters