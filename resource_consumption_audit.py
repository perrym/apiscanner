# resource_consumption_audit.py
# Updated with debug logging, lower thresholds, and parameter extraction
import logging
import requests
import time
import json
from datetime import datetime
from urllib.parse import urljoin

# Configure debug logging
logging.basicConfig(level=logging.DEBUG, format='[RC DEBUG] %(message)s')

class ResourceConsumptionAuditor:
    """Test Unrestricted Resource Consumption (API4:2023)"""
    
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        # Lower thresholds for quicker feedback
        self.thresholds = {
            'response_size': 10_000,   # 10 KB
            'response_time': 0.5,       # 0.5 seconds
            'rate_limit': 50            # 50 requests/minute
        }
        self.issues = []
        logging.debug(f"Initialized ResourceConsumptionAuditor with thresholds: {self.thresholds}")
    
    def test_resource_consumption(self, endpoints):
        """
        Test endpoints for resource consumption issues.
        :param endpoints: List of dicts with keys:
            - url: path or full URL
            - method: HTTP method
            - (optional) parameters: dict of query parameters
        """
        for endpoint in endpoints:
            logging.debug(f"Starting tests for endpoint: {endpoint.get('method', 'GET')} {endpoint['url']}")
            # Extract parameters from provided dict or empty
            params = endpoint.get('parameters', {})
            endpoint['parameters'] = params
            self._test_endpoint(endpoint)
        return self.issues
    
    def _test_endpoint(self, endpoint):
        logging.debug(f"-- Running all resource consumption checks on {endpoint['url']}")
        self._test_large_payloads(endpoint)
        self._test_computational_complexity(endpoint)
        self._test_rate_limiting(endpoint)
        self._test_batch_operations(endpoint)
    
    def _build_url(self, path):
        return urljoin(self.base_url, path)
    
    def _format_bytes(self, size):
        for unit in ['B','KB','MB','GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def _log_issue(self, endpoint, issue_type, description, severity, data=None):
        entry = {
            'endpoint': endpoint,
            'type': issue_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self.issues.append(entry)
        logging.debug(f"Logged issue: {entry}")
    
    def _test_large_payloads(self, endpoint):
        """Test how the API handles large payload sizes via query params"""
        test_cases = [
            ('small', {'limit': 10}),
            ('medium', {'limit': 1000}),
            ('large', {'limit': 10000}),
            ('huge', {'limit': 100000}),
        ]
        logging.debug(f"  → Large payload tests with params: {test_cases}")
        for size_name, params in test_cases:
            try:
                start = time.time()
                response = self.session.request(
                    method=endpoint.get('method','GET'),
                    url=self._build_url(endpoint['url']),
                    params=params,
                    timeout=30
                )
                rt = time.time() - start
                rs = len(response.content)
                logging.debug(f"    • {size_name}: status={response.status_code}, size={rs} bytes, time={rt:.2f}s")
                if rs > self.thresholds['response_size']:
                    self._log_issue(endpoint['url'],
                                    "Large Response Size",
                                    f"{size_name} request returned {self._format_bytes(rs)}",
                                    "Medium",
                                    {'params': params, 'size': rs, 'time': rt})
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'],
                                    "Slow Response",
                                    f"{size_name} request took {rt:.2f}s",
                                    "Medium",
                                    {'params': params, 'time': rt})
            except Exception as e:
                logging.debug(f"    ! Error during {size_name} payload test: {e}")
                self._log_issue(endpoint['url'], "Test Error", str(e), "Low")
    
    def _test_computational_complexity(self, endpoint):
        """Test CPU-intensive operations via crafted queries"""
        queries = [
            {'search': 'a'*1000},
            {'filter': ' OR '.join(['1=1']*100)},
            {'sort': ','.join(['field']*20)},
        ]
        logging.debug(f"  → Computational complexity tests with queries: {queries}")
        for query in queries:
            try:
                start = time.time()
                response = self.session.request(
                    method=endpoint.get('method','GET'),
                    url=self._build_url(endpoint['url']),
                    params=query,
                    timeout=30
                )
                rt = time.time() - start
                logging.debug(f"    • complexity {query}: status={response.status_code}, time={rt:.2f}s")
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'],
                                    "Computational Complexity",
                                    f"Complex query took {rt:.2f}s",
                                    "High",
                                    {'query': query, 'time': rt})
            except Exception as e:
                logging.debug(f"    ! Error during complexity test: {e}")
                self._log_issue(endpoint['url'], "Test Error", str(e), "Low")
    
    def _test_rate_limiting(self, endpoint):
        """Test if rate limiting is implemented"""
        limit = self.thresholds['rate_limit']
        logging.debug(f"  → Rate limit test: up to {limit+5} requests")
        successes = 0
        start = time.time()
        for i in range(limit+5):
            try:
                response = self.session.request(
                    method=endpoint.get('method','GET'),
                    url=self._build_url(endpoint['url']),
                    timeout=5
                )
                if response.status_code == 200:
                    successes += 1
                elif response.status_code == 429:
                    logging.debug(f"    • rate limited at request #{i+1}")
                    break
            except Exception as e:
                logging.debug(f"    ! Error during rate-limit test: {e}")
                break
        elapsed = time.time() - start
        rpm = successes / elapsed * 60 if elapsed>0 else successes
        logging.debug(f"    • achieved ~{rpm:.1f} requests/minute")
        if rpm > limit:
            self._log_issue(endpoint['url'],
                            "Missing Rate Limiting",
                            f"Achieved {rpm:.1f} r/min (no throttling)",
                            "High",
                            {'sent': limit+5, 'successes': successes, 'rpm': rpm})
    
    def _test_batch_operations(self, endpoint):
        """Test batch operations for resource consumption"""
        method = endpoint.get('method','GET')
        if method not in ['POST','PUT']:
            return
        sizes = [1,10,100,1000]
        logging.debug(f"  → Batch operations tests with sizes: {sizes}")
        for size in sizes:
            try:
                payload = {'items': [{'id': i} for i in range(size)]}
                start = time.time()
                response = self.session.request(
                    method=method,
                    url=self._build_url(endpoint['url']),
                    json=payload,
                    timeout=60
                )
                rt = time.time() - start
                logging.debug(f"    • batch {size}: status={response.status_code}, time={rt:.2f}s")
                if rt > self.thresholds['response_time'] * size:
                    self._log_issue(endpoint['url'],
                                    "Batch Operation Scaling",
                                    f"Batch of {size} items took {rt:.2f}s",
                                    "Medium",
                                    {'batch_size': size, 'time': rt})
            except Exception as e:
                logging.debug(f"    ! Error during batch test size {size}: {e}")
                self._log_issue(endpoint['url'], "Test Error", str(e), "Low")

    def generate_report(self, format='markdown'):
        """Generate security report in Markdown or JSON"""
        if format == 'json':
            return json.dumps(self.issues, indent=2)
        report = [
            "# API Security Audit - Unrestricted Resource Consumption (API4:2023)",
            f"## Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"## Target: {self.base_url}",
            "## Findings"
        ]
        by_sev = {'Critical':[], 'High':[], 'Medium':[], 'Low':[]}
        for issue in self.issues:
            by_sev.setdefault(issue['severity'],[]).append(issue)
        for sev, items in by_sev.items():
            if not items: continue
            report.append(f"\n### {sev} risks ({len(items)})")
            for i in items:
                report.append(f"- [{i['severity']}] {i['type']} @ {i['endpoint']}")
                report.append(f"  • {i['description']}")
                if i.get('data'):
                    report.append(f"    ```json\n{json.dumps(i['data'],indent=2)}\n```")
        return "\n".join(report)

# Example usage
if __name__ == "__main__":
    API_URL = "https://api.example.com"
    TEST_ENDPOINTS = [
        {'url': '/api/data', 'method': 'GET', 'parameters': {'limit':100}},
        {'url': '/api/search', 'method': 'GET'},
        {'url': '/api/batch', 'method': 'POST'}
    ]
    auditor = ResourceConsumptionAuditor(API_URL)
    issues = auditor.test_resource_consumption(TEST_ENDPOINTS)
    print(auditor.generate_report())
