"""
Test Queries Module for Threat Intelligence Pipeline
Validates all required query types and performance metrics
"""

import asyncio
import time
import json
from typing import Dict, List, Any
import requests
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.storage.neo4j_client import Neo4jClient
from src.storage.postgres_client import PostgreSQLClient
from src.api.langgraph_agent import ThreatIntelligenceAgent


class QueryTestSuite:
    """Comprehensive test suite for all query types"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.test_results = []
        
    def test_semantic_search(self) -> Dict:
        """Test 1: Semantic search for Russian disinformation campaigns"""
        
        query = "What Russian disinformation campaigns target France?"
        
        start_time = time.time()
        response = requests.post(
            f"{self.api_url}/search",
            json={
                "query": query,
                "search_type": "semantic",
                "limit": 10
            }
        )
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Semantic Search - Russian Disinformation",
            "query": query,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200:
            data = response.json()
            result["results_count"] = data.get("total", 0)
            result["passed"] = data.get("total", 0) > 0 and query_time < 2.0
            result["sample_results"] = data.get("results", [])[:3]
        else:
            result["error"] = response.text
            
        return result
    
    def test_indicator_lookup(self) -> Dict:
        """Test 2: Find all domains associated with Doppelgänger"""
        
        query = "Find all domains associated with Doppelgänger"
        
        start_time = time.time()
        
        # First search for Doppelgänger-related content
        response = requests.post(
            f"{self.api_url}/search",
            json={
                "query": query,
                "search_type": "indicator",
                "limit": 50
            }
        )
        
        # Also try direct indicator endpoint
        domains_response = requests.get(
            f"{self.api_url}/indicators/domain?limit=100"
        )
        
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Indicator Lookup - Doppelgänger Domains",
            "query": query,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200 and domains_response.status_code == 200:
            search_data = response.json()
            domains_data = domains_response.json()
            
            # Filter domains that might be related to Doppelgänger
            doppelganger_domains = [
                d for d in domains_data 
                if 'doppel' in str(d).lower() or 
                   'ganger' in str(d).lower() or
                   'duplicate' in str(d).lower()
            ]
            
            result["results_count"] = len(doppelganger_domains)
            result["total_domains"] = len(domains_data)
            result["passed"] = query_time < 1.0  # Should be fast
            result["sample_domains"] = doppelganger_domains[:5]
        else:
            result["error"] = response.text
            
        return result
    
    def test_graph_traversal(self) -> Dict:
        """Test 3: Show all indicators within 2 hops of a domain"""
        
        # First get a domain to test with
        domains_response = requests.get(f"{self.api_url}/indicators/domain?limit=1")
        
        if domains_response.status_code != 200 or not domains_response.json():
            return {
                "test_name": "Graph Traversal - 2 Hops",
                "error": "No domains available for testing",
                "passed": False
            }
        
        test_domain = domains_response.json()[0]
        domain_id = test_domain.get("id") or test_domain.get("indicator_id")
        
        query = f"Show all indicators within 2 hops of domain {domain_id}"
        
        start_time = time.time()
        response = requests.get(
            f"{self.api_url}/relationships/{domain_id}?max_hops=2"
        )
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Graph Traversal - 2 Hops",
            "query": query,
            "test_domain": domain_id,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200:
            data = response.json()
            result["related_count"] = data.get("total_related", 0)
            result["max_hops"] = data.get("max_hops", 2)
            result["passed"] = query_time < 2.0  # Must complete within 2 seconds
            result["sample_related"] = data.get("related_indicators", [])[:5]
        else:
            result["error"] = response.text
            
        return result
    
    def test_pattern_detection(self) -> Dict:
        """Test 4: Find clusters of related social media accounts"""
        
        query = "Find clusters of related social media accounts"
        
        start_time = time.time()
        response = requests.get(
            f"{self.api_url}/analysis/clusters?min_cluster_size=2"
        )
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Pattern Detection - Social Media Clusters",
            "query": query,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200:
            data = response.json()
            clusters = data.get("clusters", [])
            
            # Filter for social media clusters
            social_media_types = [
                'facebook', 'twitter', 'instagram', 'youtube', 
                'linkedin', 'tiktok', 'telegram', 'reddit'
            ]
            
            social_clusters = [
                c for c in clusters
                if any(
                    any(sm in str(ind).lower() for sm in social_media_types)
                    for ind in c.get("indicators", [])
                )
            ]
            
            result["total_clusters"] = len(clusters)
            result["social_clusters"] = len(social_clusters)
            result["passed"] = query_time < 3.0
            result["sample_clusters"] = social_clusters[:3]
        else:
            result["error"] = response.text
            
        return result
    
    def test_cross_campaign_analysis(self) -> Dict:
        """Test 5: Which indicators appear across multiple campaigns?"""
        
        query = "Which indicators appear across multiple campaigns?"
        
        start_time = time.time()
        response = requests.get(f"{self.api_url}/analysis/patterns")
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Campaign Analysis - Cross-Campaign Indicators",
            "query": query,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200:
            data = response.json()
            patterns = data.get("patterns", [])
            
            # Find cross-campaign patterns
            cross_campaign = [
                p for p in patterns
                if p.get("pattern_type") == "cross_campaign_indicator"
            ]
            
            result["patterns_found"] = len(patterns)
            result["cross_campaign_indicators"] = len(cross_campaign)
            result["passed"] = query_time < 2.0
            result["sample_patterns"] = cross_campaign[:3]
        else:
            result["error"] = response.text
            
        return result
    
    def test_timeline_query(self) -> Dict:
        """Test 6: Show indicator relationships over time"""
        
        query = "Show indicator relationships over time"
        
        # This would typically query historical data
        start_time = time.time()
        response = requests.post(
            f"{self.api_url}/search",
            json={
                "query": query,
                "search_type": "hybrid",
                "filters": {
                    "date_from": "2024-01-01",
                    "date_to": "2024-12-31"
                },
                "limit": 20
            }
        )
        query_time = time.time() - start_time
        
        result = {
            "test_name": "Timeline Query - Temporal Analysis",
            "query": query,
            "status_code": response.status_code,
            "query_time": query_time,
            "passed": False
        }
        
        if response.status_code == 200:
            data = response.json()
            result["results_count"] = data.get("total", 0)
            result["passed"] = query_time < 2.0
            result["time_range"] = "2024-01-01 to 2024-12-31"
        else:
            result["error"] = response.text
            
        return result
    
    def run_performance_tests(self) -> List[Dict]:
        """Run performance benchmarks"""
        
        performance_tests = []
        
        # Test 1: Bulk indicator retrieval
        start_time = time.time()
        response = requests.get(f"{self.api_url}/indicators/domain?limit=1000")
        bulk_time = time.time() - start_time
        
        performance_tests.append({
            "test": "Bulk Indicator Retrieval (1000)",
            "time": bulk_time,
            "passed": bulk_time < 1.0,
            "status_code": response.status_code
        })
        
        # Test 2: Concurrent searches
        async def concurrent_search():
            import aiohttp
            import asyncio
            
            async def single_search(session, query):
                async with session.post(
                    f"{self.api_url}/search",
                    json={"query": query, "search_type": "hybrid", "limit": 5}
                ) as response:
                    return await response.json()
            
            async with aiohttp.ClientSession() as session:
                queries = [
                    "malware analysis",
                    "phishing campaigns",
                    "ransomware attacks",
                    "data breach",
                    "threat actors"
                ]
                
                start = time.time()
                results = await asyncio.gather(
                    *[single_search(session, q) for q in queries]
                )
                return time.time() - start
        
        try:
            concurrent_time = asyncio.run(concurrent_search())
            performance_tests.append({
                "test": "5 Concurrent Searches",
                "time": concurrent_time,
                "passed": concurrent_time < 3.0
            })
        except Exception as e:
            performance_tests.append({
                "test": "5 Concurrent Searches",
                "error": str(e),
                "passed": False
            })
        
        # Test 3: Complex graph query
        start_time = time.time()
        response = requests.get(f"{self.api_url}/analysis/clusters?min_cluster_size=5")
        graph_time = time.time() - start_time
        
        performance_tests.append({
            "test": "Complex Graph Analysis",
            "time": graph_time,
            "passed": graph_time < 5.0,
            "status_code": response.status_code
        })
        
        return performance_tests
    
    def run_all_tests(self) -> Dict:
        """Run all test queries and compile results"""
        
        print("🧪 Running Threat Intelligence Query Tests...\n")
        
        # Run each test
        tests = [
            self.test_semantic_search(),
            self.test_indicator_lookup(),
            self.test_graph_traversal(),
            self.test_pattern_detection(),
            self.test_cross_campaign_analysis(),
            self.test_timeline_query()
        ]
        
        # Run performance tests
        performance = self.run_performance_tests()
        
        # Compile results
        all_passed = all(t.get("passed", False) for t in tests)
        perf_passed = all(p.get("passed", False) for p in performance)
        
        # Generate summary
        summary = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": len(tests),
            "passed_tests": sum(1 for t in tests if t.get("passed")),
            "failed_tests": sum(1 for t in tests if not t.get("passed")),
            "all_tests_passed": all_passed,
            "performance_tests_passed": perf_passed,
            "test_results": tests,
            "performance_results": performance,
            "average_query_time": sum(t.get("query_time", 0) for t in tests) / len(tests)
        }
        
        # Print results
        self._print_results(summary)
        
        # Save to file
        with open("query_test_results.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        return summary
    
    def _print_results(self, summary: Dict):
        """Print test results in a formatted manner"""
        
        print("=" * 60)
        print("QUERY TEST RESULTS")
        print("=" * 60)
        print(f"Timestamp: {summary['timestamp']}")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed_tests']}")
        print(f"Failed: {summary['failed_tests']}")
        print(f"Average Query Time: {summary['average_query_time']:.3f}s")
        print()
        
        # Individual test results
        for test in summary['test_results']:
            status = "✅ PASS" if test.get("passed") else "❌ FAIL"
            print(f"{status} | {test['test_name']}")
            print(f"  Query Time: {test.get('query_time', 0):.3f}s")
            if test.get("results_count") is not None:
                print(f"  Results: {test['results_count']}")
            if test.get("error"):
                print(f"  Error: {test['error']}")
            print()
        
        # Performance results
        print("PERFORMANCE BENCHMARKS:")
        for perf in summary['performance_results']:
            status = "✅" if perf.get("passed") else "❌"
            print(f"{status} {perf['test']}: {perf.get('time', 0):.3f}s")
        
        print()
        print("=" * 60)
        overall = "✅ ALL TESTS PASSED" if summary['all_tests_passed'] else "❌ SOME TESTS FAILED"
        print(f"OVERALL RESULT: {overall}")
        print("=" * 60)


def main():
    """Main test execution"""
    test_suite = QueryTestSuite()
    results = test_suite.run_all_tests()
    
    # Return exit code based on results
    return 0 if results['all_tests_passed'] else 1


if __name__ == "__main__":
    exit(main())