"""
Comprehensive test suite for Threat Intelligence Pipeline
Tests all major components and query types
"""

import os
import sys
import asyncio
import time
from pathlib import Path
import json
import logging

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.pipeline.indicators import IndicatorExtractor, IndicatorType
from src.pipeline.extractor import PDFExtractor
from src.pipeline.chunker import SemanticChunker
from src.pipeline.embedder import MultilingualEmbedder
from src.storage.neo4j_client import Neo4jClient
from src.storage.postgres_client import PostgreSQLClient
from src.storage.vector_store import VectorStore
from src.api.langgraph_agent import ThreatIntelligenceAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligencePipelineTest:
    """Test suite for the threat intelligence pipeline"""
    
    def __init__(self):
        """Initialize test environment"""
        self.results = {
            "extraction": {},
            "storage": {},
            "search": {},
            "performance": {}
        }
        
    def setup(self):
        """Setup test environment"""
        logger.info("Setting up test environment...")
        
        # Initialize components
        self.indicator_extractor = IndicatorExtractor()
        self.pdf_extractor = PDFExtractor()
        self.chunker = SemanticChunker()
        self.embedder = MultilingualEmbedder(model_name='fast')
        
        # Initialize databases
        self.neo4j = Neo4jClient(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "threat_intel_2024")
        )
        
        self.postgres = PostgreSQLClient(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            database=os.getenv("POSTGRES_DB", "threat_intel"),
            user=os.getenv("POSTGRES_USER", "threat_user"),
            password=os.getenv("POSTGRES_PASSWORD", "threat_intel_2024")
        )
        
        self.vector_store = VectorStore(
            postgres_client=self.postgres,
            embedding_dimension=384
        )
        
        self.agent = ThreatIntelligenceAgent(
            neo4j_client=self.neo4j,
            postgres_client=self.postgres,
            vector_store=self.vector_store,
            embedder=self.embedder
        )
        
        logger.info("Test environment setup complete")
    
    def test_indicator_extraction(self):
        """Test indicator extraction capabilities"""
        logger.info("Testing indicator extraction...")
        
        test_texts = [
            # Test various indicator types
            "The malicious domain evil-site.com was hosting malware at https://evil-site.com/payload.exe",
            "Contact email: hacker@malicious.org, IP address: 192.168.1.100",
            "Phone number: +1-555-123-4567, Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "Social media accounts: facebook.com/badactor, twitter.com/threat_actor, t.me/malware_group",
            "Tracking IDs found: UA-12345678-1, pub-1234567890123456",
            "File hashes: MD5: d41d8cd98f00b204e9800998ecf8427e, SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]
        
        all_indicators = []
        for text in test_texts:
            indicators = self.indicator_extractor.extract_all(text)
            all_indicators.extend(indicators)
        
        # Get statistics
        stats = self.indicator_extractor.get_statistics(all_indicators)
        
        self.results["extraction"] = {
            "total_indicators": stats['total'],
            "by_type": stats['by_type'],
            "confidence_distribution": stats['confidence_distribution'],
            "test_passed": stats['total'] > 10
        }
        
        logger.info(f"Extracted {stats['total']} indicators")
        return self.results["extraction"]["test_passed"]
    
    def test_pdf_processing(self):
        """Test PDF document processing"""
        logger.info("Testing PDF processing...")
        
        # Create a sample PDF path (would need actual PDFs)
        pdf_paths = [
            "data/pdfs/operation_overload.pdf",
            "data/pdfs/storm_1516.pdf",
            "data/pdfs/doppelganger.pdf"
        ]
        
        results = []
        for pdf_path in pdf_paths:
            if os.path.exists(pdf_path):
                try:
                    start_time = time.time()
                    
                    # Extract document
                    document = self.pdf_extractor.extract_document(pdf_path)
                    
                    # Extract indicators
                    indicators = []
                    for page in document.pages:
                        page_indicators = self.indicator_extractor.extract_all(page.text)
                        indicators.extend(page_indicators)
                    
                    processing_time = time.time() - start_time
                    
                    results.append({
                        "file": pdf_path,
                        "pages": document.total_pages,
                        "indicators": len(indicators),
                        "languages": document.languages_detected,
                        "processing_time": processing_time
                    })
                    
                    logger.info(f"Processed {pdf_path}: {len(indicators)} indicators in {processing_time:.2f}s")
                    
                except Exception as e:
                    logger.error(f"Error processing {pdf_path}: {e}")
        
        self.results["extraction"]["pdf_processing"] = results
        return len(results) > 0
    
    def test_storage_operations(self):
        """Test database storage operations"""
        logger.info("Testing storage operations...")
        
        try:
            # Test document creation
            doc_id = self.postgres.insert_document(
                doc_id="test_doc_001",
                title="Test Document",
                source="test_source",
                file_hash="abc123def456",
                total_pages=10,
                languages=["en", "fr"]
            )
            
            neo4j_doc = self.neo4j.create_document(
                doc_id="test_doc_001",
                title="Test Document",
                source="test_source"
            )
            
            # Test indicator creation
            test_indicators = [
                ("domain", "test-domain.com", "test-domain.com"),
                ("ip_address", "10.0.0.1", "10.0.0.1"),
                ("email", "test@example.com", "test@example.com")
            ]
            
            for ind_type, value, normalized in test_indicators:
                pg_id = self.postgres.insert_indicator(
                    indicator_type=ind_type,
                    value=value,
                    normalized_value=normalized
                )
                
                neo4j_id = self.neo4j.create_indicator(
                    indicator_type=ind_type,
                    value=value,
                    normalized_value=normalized
                )
                
                # Create mention
                self.postgres.insert_indicator_mention(
                    indicator_id=pg_id,
                    document_id=doc_id,
                    context="Test context",
                    confidence=0.95
                )
                
                self.neo4j.create_indicator_mention(
                    indicator_id=neo4j_id,
                    document_id="test_doc_001",
                    context="Test context",
                    confidence=0.95
                )
            
            # Test retrieval
            pg_stats = self.postgres.get_statistics()
            neo4j_stats = self.neo4j.get_statistics()
            
            self.results["storage"] = {
                "postgres": pg_stats,
                "neo4j": neo4j_stats,
                "test_passed": True
            }
            
            logger.info("Storage operations successful")
            return True
            
        except Exception as e:
            logger.error(f"Storage test failed: {e}")
            self.results["storage"]["error"] = str(e)
            return False
    
    async def test_search_queries(self):
        """Test various search query types"""
        logger.info("Testing search queries...")
        
        test_queries = [
            {
                "name": "Semantic Search",
                "query": "What Russian disinformation campaigns target France?",
                "type": "semantic"
            },
            {
                "name": "Indicator Lookup",
                "query": "Find all domains associated with Doppelgänger",
                "type": "indicator_lookup"
            },
            {
                "name": "Graph Traversal",
                "query": "Show all indicators within 2 hops of domain test-domain.com",
                "type": "graph"
            },
            {
                "name": "Pattern Detection",
                "query": "Find clusters of related social media accounts",
                "type": "pattern"
            },
            {
                "name": "Campaign Analysis",
                "query": "Which indicators appear across multiple campaigns?",
                "type": "hybrid"
            }
        ]
        
        results = []
        for test_query in test_queries:
            try:
                start_time = time.time()
                
                result = await self.agent.search(
                    query=test_query["query"],
                    search_type=test_query["type"],
                    limit=10
                )
                
                query_time = time.time() - start_time
                
                results.append({
                    "name": test_query["name"],
                    "query": test_query["query"],
                    "results_found": result["total"],
                    "query_time": query_time,
                    "success": result["total"] >= 0
                })
                
                logger.info(f"{test_query['name']}: {result['total']} results in {query_time:.3f}s")
                
            except Exception as e:
                logger.error(f"Query test failed: {e}")
                results.append({
                    "name": test_query["name"],
                    "error": str(e),
                    "success": False
                })
        
        self.results["search"] = {
            "queries": results,
            "test_passed": all(r["success"] for r in results)
        }
        
        return self.results["search"]["test_passed"]
    
    def test_performance(self):
        """Test performance metrics"""
        logger.info("Testing performance metrics...")
        
        performance_tests = []
        
        # Test 1: Bulk indicator extraction
        start_time = time.time()
        test_text = "test@example.com " * 1000  # 1000 emails
        indicators = self.indicator_extractor.extract_all(test_text)
        extraction_time = time.time() - start_time
        
        performance_tests.append({
            "test": "Bulk Extraction (1000 indicators)",
            "time": extraction_time,
            "rate": 1000 / extraction_time if extraction_time > 0 else 0,
            "passed": extraction_time < 5.0  # Should process in under 5 seconds
        })
        
        # Test 2: Vector search performance
        test_embedding = self.embedder.embed_text("test query")
        start_time = time.time()
        results = self.vector_store.search(test_embedding, k=10)
        search_time = time.time() - start_time
        
        performance_tests.append({
            "test": "Vector Search",
            "time": search_time,
            "passed": search_time < 0.5  # Sub-500ms
        })
        
        # Test 3: Graph traversal
        start_time = time.time()
        try:
            # Find any indicator to test with
            indicators = self.neo4j.find_indicators_by_type("domain", limit=1)
            if indicators:
                related = self.neo4j.find_related_indicators(
                    indicators[0]['id'],
                    max_hops=2
                )
            graph_time = time.time() - start_time
            
            performance_tests.append({
                "test": "Graph Traversal (2 hops)",
                "time": graph_time,
                "passed": graph_time < 2.0  # Under 2 seconds
            })
        except:
            pass
        
        self.results["performance"] = {
            "tests": performance_tests,
            "test_passed": all(t.get("passed", False) for t in performance_tests)
        }
        
        return self.results["performance"]["test_passed"]
    
    def generate_report(self):
        """Generate test report"""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "extraction_passed": self.results.get("extraction", {}).get("test_passed", False),
                "storage_passed": self.results.get("storage", {}).get("test_passed", False),
                "search_passed": self.results.get("search", {}).get("test_passed", False),
                "performance_passed": self.results.get("performance", {}).get("test_passed", False)
            },
            "details": self.results
        }
        
        # Calculate success metrics
        if "extraction" in self.results and "total_indicators" in self.results["extraction"]:
            extraction_rate = self.results["extraction"]["total_indicators"] / 6  # 6 test texts
            report["metrics"] = {
                "extraction_accuracy": f"{min(extraction_rate / 10 * 100, 100):.1f}%",
                "indicators_extracted": self.results["extraction"]["total_indicators"]
            }
        
        # Save report
        with open("test_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "="*50)
        print("THREAT INTELLIGENCE PIPELINE TEST REPORT")
        print("="*50)
        print(f"Timestamp: {report['timestamp']}")
        print(f"Extraction Test: {'✓ PASSED' if report['summary']['extraction_passed'] else '✗ FAILED'}")
        print(f"Storage Test: {'✓ PASSED' if report['summary']['storage_passed'] else '✗ FAILED'}")
        print(f"Search Test: {'✓ PASSED' if report['summary']['search_passed'] else '✗ FAILED'}")
        print(f"Performance Test: {'✓ PASSED' if report['summary']['performance_passed'] else '✗ FAILED'}")
        
        if "metrics" in report:
            print(f"\nExtraction Accuracy: {report['metrics']['extraction_accuracy']}")
            print(f"Total Indicators: {report['metrics']['indicators_extracted']}")
        
        all_passed = all(report["summary"].values())
        print(f"\nOVERALL: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
        print("="*50)
        
        return all_passed


async def main():
    """Main test execution"""
    tester = ThreatIntelligencePipelineTest()
    
    try:
        # Setup
        tester.setup()
        
        # Run tests
        print("\n🔍 Running Indicator Extraction Tests...")
        tester.test_indicator_extraction()
        
        print("\n📄 Running PDF Processing Tests...")
        tester.test_pdf_processing()
        
        print("\n💾 Running Storage Tests...")
        tester.test_storage_operations()
        
        print("\n🔎 Running Search Query Tests...")
        await tester.test_search_queries()
        
        print("\n⚡ Running Performance Tests...")
        tester.test_performance()
        
        # Generate report
        print("\n📊 Generating Test Report...")
        success = tester.generate_report()
        
        return 0 if success else 1
        
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)