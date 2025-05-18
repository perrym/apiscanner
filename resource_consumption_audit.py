#
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
# resource_consumption_audit.py
# Updated with debug logging, lower thresholds, and parameter extraction
import logging
import requests
import time
import json
from datetime import datetime
from urllib.parse import urljoin
from report_utils import ReportGenerator

# Configure debug logging
logging.basicConfig(level=logging.DEBUG, format='[RC DEBUG] %(message)s')

class ResourceConsumptionAuditor:
    """Test Unrestricted Resource Consumption (API4:2023)"""
    
    def __init__(self, base_url, session=None, thresholds=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.thresholds = thresholds or {
            'response_size': 10_000,   # 10 KB
            'response_time': 0.5,      # 0.5 seconds
            'rate_limit': 50,          # 50 requests/minute
            'batch_sizes': [1, 10, 100, 500]  # Configurable batch sizes
        }
        self.issues = []
        self.retry_config = {
            'max_retries': 3,
            'backoff_factor': 0.3
        }
        logging.debug(f"Initialized with thresholds: {self.thresholds}")
    
    def _log_request_error(self, endpoint, size, exception):
        """Handle request errors with detailed diagnostics"""
        error_type = exception.__class__.__name__
        error_details = {
            'batch_size': size,
            'error_type': error_type,
            'message': str(exception)
        }

        if isinstance(exception, requests.exceptions.Timeout):
            description = f"Timeout during batch test ({size} items)"
            severity = "High"
        elif isinstance(exception, requests.exceptions.ConnectionError):
            description = f"Connection failed during batch test ({size} items)"
            severity = "Medium"
        else:
            description = f"Request error during batch test ({size} items)"
            severity = "Medium"

        self._log_issue(endpoint['url'], 
                        "Batch Request Failure",
                        description,
                        severity,
                        error_details)

    
    
    def test_resource_consumption(self, endpoints):
        """
        Test endpoints for resource consumption issues.
        :param endpoints: List of dicts with keys:
            - url: path or full URL
            - method: HTTP method
            - (optional) parameters: dict of query parameters
        """
        self.endpoints = endpoints
    
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
    
    def _analyze_batch_response(self, endpoint, size, response, response_time):
        """Analyze batch operation responses with detailed validation"""
        logging.debug(f"    • batch {size}: status={response.status_code}, time={response_time:.2f}s")
        
        # Check for validation errors
        if response.status_code == 400:
            error_data = response.json()
            self._log_issue(endpoint['url'],
                            "Batch Validation Failure",
                            f"Batch of {size} failed validation",
                            "Medium",
                            {'errors': error_data, 'batch_size': size})
            return

        # Check performance thresholds with non-linear scaling
        expected_time = self.thresholds['response_time'] * (size ** 0.8)
        if response_time > expected_time:
            self._log_issue(endpoint['url'],
                            "Batch Performance Issue",
                            f"Batch of {size} took {response_time:.2f}s (expected ≤{expected_time:.2f}s)",
                            "High",
                            {'batch_size': size, 
                             'response_time': response_time,
                             'threshold': expected_time})
            
    
    def _test_batch_operations(self, endpoint):
        """Test batch operations with proper payload validation"""
        method = endpoint.get('method', 'GET').upper()
        if method not in ['POST', 'PUT']:
            return

        # Enhanced payload template with required fields
        base_payload = endpoint.get('json', {
            'items': [{
                'id': 1,
                'name': 'Test User',
                'email': 'test@example.com',
                'phone': '+1234567890',
                'password': 'ValidPassword1!',
                'mechanic_code': 'CODE123'
            }]
        })

        for size in self.thresholds['batch_sizes']:
            try:
                # Generate valid payload for each item
                payload = {'items': []}
                for i in range(size):
                    item = base_payload['items'][0].copy()
                    item.update({
                        'id': i,
                        'email': f'user{i}@example.com',
                        'phone': f'+123456{i:04}'
                    })
                    payload['items'].append(item)

                # Add retry logic for transient errors
                adapter = requests.adapters.HTTPAdapter(
                    max_retries=self.retry_config['max_retries'],
                    backoff_factor=self.retry_config['backoff_factor']
                )
                self.session.mount('http://', adapter)
                self.session.mount('https://', adapter)

                start = time.time()
                response = self.session.request(
                    method=method,
                    url=self._build_url(endpoint['url']),
                    json=payload,
                    timeout=60
                )
                rt = time.time() - start

                # Enhanced result analysis
                self._analyze_batch_response(endpoint, size, response, rt)

            except requests.exceptions.RequestException as e:
                self._log_request_error(endpoint, size, e)
            except Exception as e:
                logging.error(f"Critical error testing batch {size}: {str(e)}", exc_info=True)
                self._log_issue(endpoint['url'], "System Error", f"Critical failure: {str(e)}", "High")

    def generate_report(self, fmt='markdown'):
        return ReportGenerator(
            issues=self.issues,
            scanner="ResourceConsumption (API04)",
            base_url=self.base_url
        ).generate_markdown() if fmt == "markdown" else ReportGenerator(
            issues=self.issues,
            scanner="ResourceConsumption (API04)",
            base_url=self.base_url
        ).generate_json()

    def save_report(self, path: str, fmt: str = 'markdown'):
        ReportGenerator(self.issues, scanner="ResourceConsumption (API04)", base_url=self.base_url).save(path, fmt=fmt)


   

# Example usage
if __name__ == "__main__":
    API_URL = "https://api.example.com"
    TESTendpoints = [
        {'url': '/api/data', 'method': 'GET', 'parameters': {'limit':100}},
        {'url': '/api/search', 'method': 'GET'},
        {'url': '/api/batch', 'method': 'POST'}
    ]
    auditor = ResourceConsumptionAuditor(API_URL)
    issues = auditor.test_resource_consumption(TESTendpoints)
    print(auditor.generate_report())