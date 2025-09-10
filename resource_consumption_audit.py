# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
import logging
import time
import json
from datetime import datetime
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Union
import concurrent.futures
from tqdm import tqdm
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from report_utils import ReportGenerator
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='[RC DEBUG] %(message)s')
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])

def _headers_to_list(headerobj):
    if hasattr(headerobj, 'getlist'):
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())

class ResourceConsumptionAuditor:

    def __init__(self, base_url: str, session, *, thresholds: dict | None=None, show_progress: bool=True) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.show_progress = show_progress
        self.thresholds = thresholds or {'response_time_ms': 2000, 'payload_kb_warn': 512, 'payload_kb_high': 2048, 'records_warn': 1000, 'records_high': 10000}
        self.issues: list[dict] = []

    def test_resource_consumption(self, endpoints):
        logger.info(f'Starting resource consumption test on {len(endpoints)} endpoints')
        issues = []
        FALSE_POSITIVE_STATUSES = {401, 403, 404, 405}
        it = tqdm(endpoints, desc='API4 resource endpoints', unit='endpoint') if self.show_progress else endpoints
        for ep in it:
            path = ep.get('path', '')
            method = ep.get('method', 'get').upper()
            url = urljoin(self.base_url + '/', path.lstrip('/'))
            if self.show_progress:
                it.write(f'-> Testing {method} {url}')
            headers = self.session.headers.copy()
            request_payload = {}
            try:
                start_time = datetime.utcnow()
                if method == 'GET':
                    resp = self.session.get(url)
                elif method == 'POST':
                    request_payload = {'test': 'value'}
                    resp = self.session.post(url, json=request_payload)
                elif method == 'PUT':
                    request_payload = {'update': 'value'}
                    resp = self.session.put(url, json=request_payload)
                elif method == 'DELETE':
                    resp = self.session.delete(url)
                else:
                    logger.warning(f'Unsupported method {method} for {url}')
                    continue
                end_time = datetime.utcnow()
                elapsed = (end_time - start_time).total_seconds()
                resp_size = len(resp.content)
                status = resp.status_code
                if status in FALSE_POSITIVE_STATUSES:
                    logger.debug(f'Skipping {url} due to likely false positive (status {status})')
                    continue
                if status == 501 or status == 503:
                    severity = 'Medium'
                elif resp_size > self.thresholds.get('response_size', 1000000):
                    severity = 'Critical'
                elif elapsed > self.thresholds.get('response_time', 2.0):
                    severity = 'High'
                elif status == 200:
                    severity = 'Medium'
                else:
                    severity = 'Info'
                issue = {'severity': severity, 'category': 'Resource Consumption', 'endpoint': url, 'method': method, 'status_code': status, 'response_time': elapsed, 'response_size': resp_size, 'description': f'{severity} - Resource Consumption at {url}', 'request_body': json.dumps(request_payload), 'response_body': resp.text[:2000], 'timestamp': str(datetime.utcnow()), 'request_headers': _headers_to_list(resp.request.headers), 'response_headers': _headers_to_list(resp.raw.headers)}
                issues.append(issue)
                logger.info(f'ISSUE FOUND: {severity} - Resource Consumption at {url}')
            except Exception as e:
                logger.warning(f'Exception while testing {url}: {str(e)}')
        return issues

    def _test_endpoint(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        url = endpoint.get('url', '')
        logging.debug(f'-- Running all resource consumption checks on {method} {url}')
        self._test_large_payloads(endpoint)
        self._test_computational_complexity(endpoint)
        self._test_rate_limiting(endpoint)
        self._test_batch_operations(endpoint)
        self._test_concurrent_flood(endpoint)

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} PB'

    def _build_url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    def _generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        payload = {}
        current = payload
        for i in range(depth):
            current['nested'] = {}
            current = current['nested']
            if i % 10 == 0:
                current[f'key_{i}'] = 'A' * 100
        return payload

    def _log_issue(self, endpoint: str, issue_type: str, description: str, severity: str, data: Optional[Dict[str, Any]]=None) -> None:
        status_code = data.get('status_code', 1) if data else 1
        if 500 <= status_code < 600:
            severity = 'Critical'
        elif status_code == 0 and severity == 'Medium':
            severity = 'High'
        entry = {'endpoint': endpoint, 'type': issue_type, 'description': description, 'severity': severity, 'status_code': status_code, 'timestamp': datetime.now().isoformat(), 'request_headers': _headers_to_list(self.session.headers), 'response_headers': _headers_to_list(data.get('headers') or {}), 'response_body': data.get('body') if data else None, 'request_body': data.get('request_body'), 'request_cookies': self.session.cookies.get_dict(), 'response_cookies': resp.cookies.get_dict() if 'resp' in locals() else {}, 'data': data, 'metrics': {'response_size': data.get('size'), 'response_time': data.get('time'), 'rpm': data.get('rpm'), 'batch_size': data.get('batch_size')} if data else None}
        self.issues.append(entry)
        logging.info(f"ISSUE FOUND: {severity} - {entry['type']} at {endpoint}")

    def _test_large_payloads(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        test_cases = [('small', {'limit': 10}, 'Low'), ('medium', {'limit': 1000}, 'Low'), ('large', {'limit': 10000}, 'Medium'), ('huge', {'limit': 100000}, 'High'), ('massive', {'limit': 1000000}, 'High')]
        if self.show_progress:
            test_iter = tqdm(test_cases, desc='Testing payload sizes', leave=False)
        else:
            test_iter = test_cases
        for size_name, params, severity in test_iter:
            if self.show_progress:
                test_iter.write(f"   -> {size_name} payload on {endpoint['url']}")
        malicious_payloads = [('10MB_string', 'A' * 10000000, 'High'), ('deep_json_100', self._generate_deep_nested_json(100), 'High'), ('zip_bomb', b'PK\x05\x06' + b'\x00' * 18, 'Critical')]
        logging.debug('  - Large payload tests')
        for size_name, params, severity in test_iter:
            try:
                start = time.time()
                resp = self.session.request(method, self._build_url(endpoint['url']), params=params, timeout=30)
                rt = time.time() - start
                rs = len(resp.content)
                logging.debug(f'    - {size_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                if rs > self.thresholds['response_size']:
                    self._log_issue(endpoint['url'], 'Large Response Size', f'{size_name} request returned {self._format_bytes(rs)}', severity, {'params': params, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Slow Response', f'{size_name} request took {rt:.2f}s', severity, {'params': params, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during {size_name} test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'Medium' if 'timeout' in str(exc).lower() else 'Low', {'status_code': 0})
        if method in ['POST', 'PUT', 'PATCH']:
            if self.show_progress:
                malicious_iter = tqdm(malicious_payloads, desc='Testing malicious payloads', leave=False)
            else:
                malicious_iter = malicious_payloads
            for payload_name, payload, severity in malicious_iter:
                try:
                    start = time.time()
                    headers = {'Content-Type': 'application/json'} if isinstance(payload, dict) else None
                    resp = self.session.request(method, self._build_url(endpoint['url']), json=payload if isinstance(payload, dict) else None, data=payload if isinstance(payload, bytes) else None, headers=headers, timeout=30)
                    rt = time.time() - start
                    rs = len(resp.content)
                    logging.debug(f'    - {payload_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                    if rs > self.thresholds['response_size']:
                        self._log_issue(endpoint['url'], 'Large Response Size', f"Malicious payload '{payload_name}' returned {self._format_bytes(rs)}", severity, {'payload_type': payload_name, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                    if rt > self.thresholds['response_time']:
                        self._log_issue(endpoint['url'], 'Slow Response', f"Malicious payload '{payload_name}' took {rt:.2f}s", severity, {'payload_type': payload_name, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                except requests.RequestException as exc:
                    logging.debug(f'    ! Error during {payload_name} test: {exc}')
                    self._log_issue(endpoint['url'], 'Request Error', f'{payload_name}: {exc}', 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'request_body': str(payload)[:1024]})

    def _test_computational_complexity(self, endpoint: Dict[str, Any]) -> None:
        queries = [{'search': 'a' * 10000, 'severity': 'Medium'}, {'filter': ' OR '.join(['1=1'] * 500), 'severity': 'High'}, {'sort': ','.join(['field'] * 100), 'severity': 'Medium'}, {'id': '123 AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)', 'severity': 'Critical'}, {'query': "' OR 1=1; WAITFOR DELAY '0:0:5'--", 'severity': 'Critical'}, {'q': '{"$where": "sleep(5000)"}', 'severity': 'Critical'}]
        if self.show_progress:
            query_iter = tqdm(queries, desc='Testing complex queries', leave=False)
        else:
            query_iter = queries
        logging.debug('  - Computational complexity tests')
        for query in query_iter:
            severity = query.pop('severity')
            try:
                start = time.time()
                resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), params=query, timeout=35)
                rt = time.time() - start
                logging.debug(f'    - query {list(query.keys())[0]}: status={resp.status_code}, time={rt:.2f}s')
                if rt > 5.0 and any((keyword in str(query).lower() for keyword in ['sleep', 'waitfor', 'delay'])):
                    self._log_issue(endpoint['url'], 'Time-Based Vulnerability', f'Time-based test detected ({rt:.2f}s response)', 'Critical', {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                elif rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Computational Complexity', f'Complex query took {rt:.2f}s', severity, {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during complexity test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'query': query})

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        limit = self.thresholds['rate_limit']
        logging.debug(f'  - Rate limit test (sustained traffic for 30 seconds, target - {limit} req/min)')
        successes = 0
        start_time = time.time()
        last_resp = None
        request_count = 0
        if self.show_progress:
            pbar = tqdm(total=30, desc='Rate limit test', unit='s')
        while time.time() - start_time < 30:
            try:
                last_resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), timeout=5)
                request_count += 1
                if last_resp.status_code == 200:
                    successes += 1
                elif last_resp.status_code == 429:
                    logging.debug(f'    - rate limited at request #{request_count}')
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during ratelimit request #{request_count}: {exc}')
                last_resp = None
            if self.show_progress:
                pbar.update(1)
                pbar.set_postfix({'requests': request_count, 'successes': successes})
        if self.show_progress:
            pbar.close()
        elapsed = time.time() - start_time
        rpm = successes / elapsed * 60 if elapsed > 0 else 0
        logging.debug(f'    - sent {request_count} requests, {successes} succeeded (~{rpm:.1f} req/min)')
        if rpm > limit:
            self._log_issue(endpoint['url'], 'Missing Rate Limiting', f'Achieved {rpm:.1f} req/min (no throttling)', 'High', {'sent': request_count, 'successes': successes, 'rpm': rpm, 'status_code': getattr(last_resp, 'status_code', 0) if last_resp else 0})
        elif successes == request_count:
            self._log_issue(endpoint['url'], 'Rate Limit Too High', f'No throttling detected at {rpm:.1f} req/min', 'Medium', {'sent': request_count, 'successes': successes, 'rpm': rpm})

    def _analyze_batch_response(self, endpoint: Dict[str, Any], size: int, resp: requests.Response, rt: float) -> None:
        logging.debug(f'    - batch {size}: status={resp.status_code}, time={rt:.2f}s')
        if resp.status_code == 207:
            try:
                responses = resp.json()
                failures = [r for r in responses if 400 <= r.get('status', 200) < 600]
                if failures:
                    self._log_issue(endpoint['url'], 'Partial Batch Failure', f'{len(failures)}/{size} items failed in batch', 'Medium', {'batch_size': size, 'failures': len(failures), 'status_code': 207, 'body': resp.text[:2048]})
            except json.JSONDecodeError:
                pass
        expected_time = self.thresholds['response_time'] * size ** 0.8
        if rt > expected_time * 2:
            severity = 'High' if size > 100 else 'Medium'
            self._log_issue(endpoint['url'], 'Batch Performance Issue', f'Batch of {size} took {rt:.2f}s (expected -{expected_time:.2f}s)', severity, {'batch_size': size, 'response_time': rt, 'threshold': expected_time, 'status_code': resp.status_code, 'body': resp.text[:2048]})

    def _test_batch_operations(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            return
        base_payload = endpoint.get('json', {'items': [{'id': 1, 'name': 'Test User', 'email': 'test@example.com', 'phone': '+1234567890', 'password': 'ValidPassword1!'}]})
        malicious_patterns = [('duplicate_ids', lambda i: {'id': 1}, 'Medium'), ('null_values', lambda i: {'id': i, 'value': None}, 'Low'), ('sql_injection', lambda i: {'id': i, 'filter': f"' OR 1=1 -- {i}"}, 'Critical')]
        if self.show_progress:
            batch_iter = tqdm(self.thresholds['batch_sizes'], desc='Testing batch sizes', leave=False)
        else:
            batch_iter = self.thresholds['batch_sizes']
        for size in batch_iter:
            try:
                payload = {'items': []}
                for i in range(size):
                    item = base_payload['items'][0].copy()
                    item.update({'id': i, 'email': f'user{i}@example.com'})
                    payload['items'].append(item)
                self._execute_batch_request(endpoint, size, method, payload, 'normal', 'Medium')
            except Exception as exc:
                logging.error(f'Critical error testing batch {size}: {exc}', exc_info=True)
                self._log_issue(endpoint['url'], 'Batch Request Failure', str(exc), 'High', {'batch_size': size, 'status_code': 0})
            if self.show_progress:
                pattern_iter = tqdm(malicious_patterns, desc='Testing malicious patterns', leave=False)
            else:
                pattern_iter = malicious_patterns
            for pattern_name, item_generator, severity in pattern_iter:
                try:
                    payload = {'items': [item_generator(i) for i in range(size)]}
                    self._execute_batch_request(endpoint, size, method, payload, pattern_name, severity)
                except Exception:
                    continue

    def _execute_batch_request(self, endpoint: Dict[str, Any], size: int, method: str, payload: Dict[str, Any], pattern_name: str, severity: str) -> None:
        adapter = HTTPAdapter(max_retries=self.retry_config['max_retries'], backoff_factor=self.retry_config['backoff_factor'])
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        start = time.time()
        resp = self.session.request(method, self._build_url(endpoint['url']), json=payload, timeout=60)
        rt = time.time() - start
        if resp.status_code == 400:
            self._log_issue(endpoint['url'], 'Batch Validation Failure', f'{pattern_name} batch of {size} failed validation', severity, {'pattern': pattern_name, 'batch_size': size, 'status_code': 400, 'body': resp.text[:2048]})
        else:
            self._analyze_batch_response(endpoint, size, resp, rt)

    def _test_concurrent_flood(self, endpoint: Dict[str, Any]) -> None:
        logging.debug(f"  - Concurrent flood test ({self.thresholds['concurrent_workers']} workers)")
        method = endpoint.get('method', 'GET')
        url = self._build_url(endpoint['url'])
        params = endpoint.get('parameters', {})
        successes = 0
        errors = 0
        timeouts = 0
        start_time = time.time()

        def send_request():
            try:
                resp = self.session.request(method, url, params=params, timeout=5)
                return resp.status_code
            except requests.exceptions.Timeout:
                return 'timeout'
            except requests.exceptions.RequestException:
                return 'error'
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thresholds['concurrent_workers']) as executor:
            futures = [executor.submit(send_request) for _ in range(self.thresholds['concurrent_requests'])]
            if self.show_progress:
                pbar = tqdm(total=len(futures), desc='Concurrent requests', unit='req')
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result == 200:
                    successes += 1
                elif result == 'timeout':
                    timeouts += 1
                else:
                    errors += 1
                if self.show_progress:
                    pbar.update(1)
                    pbar.set_postfix({'success': successes, 'errors': errors, 'timeouts': timeouts})
            if self.show_progress:
                pbar.close()
        elapsed = time.time() - start_time
        total_requests = self.thresholds['concurrent_requests']
        logging.debug(f'    - Completed {total_requests} requests in {elapsed:.2f}s: {successes} succeeded, {errors} errors, {timeouts} timeouts')
        if timeouts > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'Critical', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        elif timeouts > total_requests * 0.2:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'High', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        if errors > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'Critical', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})
        elif errors > total_requests * 0.3:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'High', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return [i for i in self.issues if i.get('status_code', 1) != 0]

    def generate_report(self, fmt: str='markdown') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url)
        if fmt == 'markdown':
            return gen.generate_markdown()
        if fmt == 'html':
            return gen.generate_html()
        return gen.generate_html()

    def save_report(self, path: str, fmt: str='markdown') -> None:
        ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url).save(path, fmt=fmt)
import logging
import time
import json
from datetime import datetime
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Union
import concurrent.futures
from tqdm import tqdm
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from report_utils import ReportGenerator
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='[RC DEBUG] %(message)s')
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])

def _headers_to_list(headerobj):
    if hasattr(headerobj, 'getlist'):
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())

class ResourceConsumptionAuditor:

    def __init__(self, base_url: str, session, *, thresholds: dict | None=None, show_progress: bool=True) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.show_progress = show_progress
        self.thresholds = thresholds or {'response_time_ms': 2000, 'payload_kb_warn': 512, 'payload_kb_high': 2048, 'records_warn': 1000, 'records_high': 10000}
        self.issues: list[dict] = []

    def test_resource_consumption(self, endpoints):
        logger.info(f'Starting resource consumption test on {len(endpoints)} endpoints')
        issues = []
        FALSE_POSITIVE_STATUSES = {401, 403, 404, 405}
        it = tqdm(endpoints, desc='API4 resource endpoints', unit='endpoint') if self.show_progress else endpoints
        for ep in it:
            path = ep.get('path', '')
            method = ep.get('method', 'get').upper()
            url = urljoin(self.base_url + '/', path.lstrip('/'))
            if self.show_progress:
                it.write(f'-> Testing {method} {url}')
            headers = self.session.headers.copy()
            request_payload = {}
            try:
                start_time = datetime.utcnow()
                if method == 'GET':
                    resp = self.session.get(url)
                elif method == 'POST':
                    request_payload = {'test': 'value'}
                    resp = self.session.post(url, json=request_payload)
                elif method == 'PUT':
                    request_payload = {'update': 'value'}
                    resp = self.session.put(url, json=request_payload)
                elif method == 'DELETE':
                    resp = self.session.delete(url)
                else:
                    logger.warning(f'Unsupported method {method} for {url}')
                    continue
                end_time = datetime.utcnow()
                elapsed = (end_time - start_time).total_seconds()
                resp_size = len(resp.content)
                status = resp.status_code
                if status in FALSE_POSITIVE_STATUSES:
                    logger.debug(f'Skipping {url} due to likely false positive (status {status})')
                    continue
                if status == 501 or status == 503:
                    severity = 'Medium'
                elif resp_size > self.thresholds.get('response_size', 1000000):
                    severity = 'Critical'
                elif elapsed > self.thresholds.get('response_time', 2.0):
                    severity = 'High'
                elif status == 200:
                    severity = 'Medium'
                else:
                    severity = 'Info'
                issue = {'severity': severity, 'category': 'Resource Consumption', 'endpoint': url, 'method': method, 'status_code': status, 'response_time': elapsed, 'response_size': resp_size, 'description': f'{severity} - Resource Consumption at {url}', 'request_body': json.dumps(request_payload), 'response_body': resp.text[:2000], 'timestamp': str(datetime.utcnow()), 'request_headers': _headers_to_list(resp.request.headers), 'response_headers': _headers_to_list(resp.raw.headers)}
                issues.append(issue)
                logger.info(f'ISSUE FOUND: {severity} - Resource Consumption at {url}')
            except Exception as e:
                logger.warning(f'Exception while testing {url}: {str(e)}')
        return issues

    def _test_endpoint(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        url = endpoint.get('url', '')
        logging.debug(f'-- Running all resource consumption checks on {method} {url}')
        self._test_large_payloads(endpoint)
        self._test_computational_complexity(endpoint)
        self._test_rate_limiting(endpoint)
        self._test_batch_operations(endpoint)
        self._test_concurrent_flood(endpoint)

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} PB'

    def _build_url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    def _generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        payload = {}
        current = payload
        for i in range(depth):
            current['nested'] = {}
            current = current['nested']
            if i % 10 == 0:
                current[f'key_{i}'] = 'A' * 100
        return payload

    def _log_issue(self, endpoint: str, issue_type: str, description: str, severity: str, data: Optional[Dict[str, Any]]=None) -> None:
        status_code = data.get('status_code', 1) if data else 1
        if 500 <= status_code < 600:
            severity = 'Critical'
        elif status_code == 0 and severity == 'Medium':
            severity = 'High'
        entry = {'endpoint': endpoint, 'type': issue_type, 'description': description, 'severity': severity, 'status_code': status_code, 'timestamp': datetime.now().isoformat(), 'request_headers': _headers_to_list(self.session.headers), 'response_headers': _headers_to_list(data.get('headers') or {}), 'response_body': data.get('body') if data else None, 'request_body': data.get('request_body'), 'request_cookies': self.session.cookies.get_dict(), 'response_cookies': resp.cookies.get_dict() if 'resp' in locals() else {}, 'data': data, 'metrics': {'response_size': data.get('size'), 'response_time': data.get('time'), 'rpm': data.get('rpm'), 'batch_size': data.get('batch_size')} if data else None}
        self.issues.append(entry)
        logging.info(f"ISSUE FOUND: {severity} - {entry['type']} at {endpoint}")

    def _test_large_payloads(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        test_cases = [('small', {'limit': 10}, 'Low'), ('medium', {'limit': 1000}, 'Low'), ('large', {'limit': 10000}, 'Medium'), ('huge', {'limit': 100000}, 'High'), ('massive', {'limit': 1000000}, 'High')]
        if self.show_progress:
            test_iter = tqdm(test_cases, desc='Testing payload sizes', leave=False)
        else:
            test_iter = test_cases
        for size_name, params, severity in test_iter:
            if self.show_progress:
                test_iter.write(f"   -> {size_name} payload on {endpoint['url']}")
        malicious_payloads = [('10MB_string', 'A' * 10000000, 'High'), ('deep_json_100', self._generate_deep_nested_json(100), 'High'), ('zip_bomb', b'PK\x05\x06' + b'\x00' * 18, 'Critical')]
        logging.debug('  - Large payload tests')
        for size_name, params, severity in test_iter:
            try:
                start = time.time()
                resp = self.session.request(method, self._build_url(endpoint['url']), params=params, timeout=30)
                rt = time.time() - start
                rs = len(resp.content)
                logging.debug(f'    - {size_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                if rs > self.thresholds['response_size']:
                    self._log_issue(endpoint['url'], 'Large Response Size', f'{size_name} request returned {self._format_bytes(rs)}', severity, {'params': params, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Slow Response', f'{size_name} request took {rt:.2f}s', severity, {'params': params, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during {size_name} test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'Medium' if 'timeout' in str(exc).lower() else 'Low', {'status_code': 0})
        if method in ['POST', 'PUT', 'PATCH']:
            if self.show_progress:
                malicious_iter = tqdm(malicious_payloads, desc='Testing malicious payloads', leave=False)
            else:
                malicious_iter = malicious_payloads
            for payload_name, payload, severity in malicious_iter:
                try:
                    start = time.time()
                    headers = {'Content-Type': 'application/json'} if isinstance(payload, dict) else None
                    resp = self.session.request(method, self._build_url(endpoint['url']), json=payload if isinstance(payload, dict) else None, data=payload if isinstance(payload, bytes) else None, headers=headers, timeout=30)
                    rt = time.time() - start
                    rs = len(resp.content)
                    logging.debug(f'    - {payload_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                    if rs > self.thresholds['response_size']:
                        self._log_issue(endpoint['url'], 'Large Response Size', f"Malicious payload '{payload_name}' returned {self._format_bytes(rs)}", severity, {'payload_type': payload_name, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                    if rt > self.thresholds['response_time']:
                        self._log_issue(endpoint['url'], 'Slow Response', f"Malicious payload '{payload_name}' took {rt:.2f}s", severity, {'payload_type': payload_name, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                except requests.RequestException as exc:
                    logging.debug(f'    ! Error during {payload_name} test: {exc}')
                    self._log_issue(endpoint['url'], 'Request Error', f'{payload_name}: {exc}', 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'request_body': str(payload)[:1024]})

    def _test_computational_complexity(self, endpoint: Dict[str, Any]) -> None:
        queries = [{'search': 'a' * 10000, 'severity': 'Medium'}, {'filter': ' OR '.join(['1=1'] * 500), 'severity': 'High'}, {'sort': ','.join(['field'] * 100), 'severity': 'Medium'}, {'id': '123 AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)', 'severity': 'Critical'}, {'query': "' OR 1=1; WAITFOR DELAY '0:0:5'--", 'severity': 'Critical'}, {'q': '{"$where": "sleep(5000)"}', 'severity': 'Critical'}]
        if self.show_progress:
            query_iter = tqdm(queries, desc='Testing complex queries', leave=False)
        else:
            query_iter = queries
        logging.debug('  - Computational complexity tests')
        for query in query_iter:
            severity = query.pop('severity')
            try:
                start = time.time()
                resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), params=query, timeout=35)
                rt = time.time() - start
                logging.debug(f'    - query {list(query.keys())[0]}: status={resp.status_code}, time={rt:.2f}s')
                if rt > 5.0 and any((keyword in str(query).lower() for keyword in ['sleep', 'waitfor', 'delay'])):
                    self._log_issue(endpoint['url'], 'Time-Based Vulnerability', f'Time-based test detected ({rt:.2f}s response)', 'Critical', {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                elif rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Computational Complexity', f'Complex query took {rt:.2f}s', severity, {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during complexity test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'query': query})

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        limit = self.thresholds['rate_limit']
        logging.debug(f'  - Rate limit test (sustained traffic for 30 seconds, target - {limit} req/min)')
        successes = 0
        start_time = time.time()
        last_resp = None
        request_count = 0
        if self.show_progress:
            pbar = tqdm(total=30, desc='Rate limit test', unit='s')
        while time.time() - start_time < 30:
            try:
                last_resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), timeout=5)
                request_count += 1
                if last_resp.status_code == 200:
                    successes += 1
                elif last_resp.status_code == 429:
                    logging.debug(f'    - rate limited at request #{request_count}')
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during ratelimit request #{request_count}: {exc}')
                last_resp = None
            if self.show_progress:
                pbar.update(1)
                pbar.set_postfix({'requests': request_count, 'successes': successes})
        if self.show_progress:
            pbar.close()
        elapsed = time.time() - start_time
        rpm = successes / elapsed * 60 if elapsed > 0 else 0
        logging.debug(f'    - sent {request_count} requests, {successes} succeeded (~{rpm:.1f} req/min)')
        if rpm > limit:
            self._log_issue(endpoint['url'], 'Missing Rate Limiting', f'Achieved {rpm:.1f} req/min (no throttling)', 'High', {'sent': request_count, 'successes': successes, 'rpm': rpm, 'status_code': getattr(last_resp, 'status_code', 0) if last_resp else 0})
        elif successes == request_count:
            self._log_issue(endpoint['url'], 'Rate Limit Too High', f'No throttling detected at {rpm:.1f} req/min', 'Medium', {'sent': request_count, 'successes': successes, 'rpm': rpm})

    def _analyze_batch_response(self, endpoint: Dict[str, Any], size: int, resp: requests.Response, rt: float) -> None:
        logging.debug(f'    - batch {size}: status={resp.status_code}, time={rt:.2f}s')
        if resp.status_code == 207:
            try:
                responses = resp.json()
                failures = [r for r in responses if 400 <= r.get('status', 200) < 600]
                if failures:
                    self._log_issue(endpoint['url'], 'Partial Batch Failure', f'{len(failures)}/{size} items failed in batch', 'Medium', {'batch_size': size, 'failures': len(failures), 'status_code': 207, 'body': resp.text[:2048]})
            except json.JSONDecodeError:
                pass
        expected_time = self.thresholds['response_time'] * size ** 0.8
        if rt > expected_time * 2:
            severity = 'High' if size > 100 else 'Medium'
            self._log_issue(endpoint['url'], 'Batch Performance Issue', f'Batch of {size} took {rt:.2f}s (expected -{expected_time:.2f}s)', severity, {'batch_size': size, 'response_time': rt, 'threshold': expected_time, 'status_code': resp.status_code, 'body': resp.text[:2048]})

    def _test_batch_operations(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            return
        base_payload = endpoint.get('json', {'items': [{'id': 1, 'name': 'Test User', 'email': 'test@example.com', 'phone': '+1234567890', 'password': 'ValidPassword1!'}]})
        malicious_patterns = [('duplicate_ids', lambda i: {'id': 1}, 'Medium'), ('null_values', lambda i: {'id': i, 'value': None}, 'Low'), ('sql_injection', lambda i: {'id': i, 'filter': f"' OR 1=1 -- {i}"}, 'Critical')]
        if self.show_progress:
            batch_iter = tqdm(self.thresholds['batch_sizes'], desc='Testing batch sizes', leave=False)
        else:
            batch_iter = self.thresholds['batch_sizes']
        for size in batch_iter:
            try:
                payload = {'items': []}
                for i in range(size):
                    item = base_payload['items'][0].copy()
                    item.update({'id': i, 'email': f'user{i}@example.com'})
                    payload['items'].append(item)
                self._execute_batch_request(endpoint, size, method, payload, 'normal', 'Medium')
            except Exception as exc:
                logging.error(f'Critical error testing batch {size}: {exc}', exc_info=True)
                self._log_issue(endpoint['url'], 'Batch Request Failure', str(exc), 'High', {'batch_size': size, 'status_code': 0})
            if self.show_progress:
                pattern_iter = tqdm(malicious_patterns, desc='Testing malicious patterns', leave=False)
            else:
                pattern_iter = malicious_patterns
            for pattern_name, item_generator, severity in pattern_iter:
                try:
                    payload = {'items': [item_generator(i) for i in range(size)]}
                    self._execute_batch_request(endpoint, size, method, payload, pattern_name, severity)
                except Exception:
                    continue

    def _execute_batch_request(self, endpoint: Dict[str, Any], size: int, method: str, payload: Dict[str, Any], pattern_name: str, severity: str) -> None:
        adapter = HTTPAdapter(max_retries=self.retry_config['max_retries'], backoff_factor=self.retry_config['backoff_factor'])
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        start = time.time()
        resp = self.session.request(method, self._build_url(endpoint['url']), json=payload, timeout=60)
        rt = time.time() - start
        if resp.status_code == 400:
            self._log_issue(endpoint['url'], 'Batch Validation Failure', f'{pattern_name} batch of {size} failed validation', severity, {'pattern': pattern_name, 'batch_size': size, 'status_code': 400, 'body': resp.text[:2048]})
        else:
            self._analyze_batch_response(endpoint, size, resp, rt)

    def _test_concurrent_flood(self, endpoint: Dict[str, Any]) -> None:
        logging.debug(f"  - Concurrent flood test ({self.thresholds['concurrent_workers']} workers)")
        method = endpoint.get('method', 'GET')
        url = self._build_url(endpoint['url'])
        params = endpoint.get('parameters', {})
        successes = 0
        errors = 0
        timeouts = 0
        start_time = time.time()

        def send_request():
            try:
                resp = self.session.request(method, url, params=params, timeout=5)
                return resp.status_code
            except requests.exceptions.Timeout:
                return 'timeout'
            except requests.exceptions.RequestException:
                return 'error'
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thresholds['concurrent_workers']) as executor:
            futures = [executor.submit(send_request) for _ in range(self.thresholds['concurrent_requests'])]
            if self.show_progress:
                pbar = tqdm(total=len(futures), desc='Concurrent requests', unit='req')
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result == 200:
                    successes += 1
                elif result == 'timeout':
                    timeouts += 1
                else:
                    errors += 1
                if self.show_progress:
                    pbar.update(1)
                    pbar.set_postfix({'success': successes, 'errors': errors, 'timeouts': timeouts})
            if self.show_progress:
                pbar.close()
        elapsed = time.time() - start_time
        total_requests = self.thresholds['concurrent_requests']
        logging.debug(f'    - Completed {total_requests} requests in {elapsed:.2f}s: {successes} succeeded, {errors} errors, {timeouts} timeouts')
        if timeouts > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'Critical', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        elif timeouts > total_requests * 0.2:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'High', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        if errors > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'Critical', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})
        elif errors > total_requests * 0.3:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'High', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return [i for i in self.issues if i.get('status_code', 1) != 0]

    def generate_report(self, fmt: str='markdown') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url)
        if fmt == 'markdown':
            return gen.generate_markdown()
        if fmt == 'html':
            return gen.generate_html()
        return gen.generate_html()

    def save_report(self, path: str, fmt: str='markdown') -> None:
        ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url).save(path, fmt=fmt)
import logging
import time
import json
from datetime import datetime
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Union
import concurrent.futures
from tqdm import tqdm
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from report_utils import ReportGenerator
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='[RC DEBUG] %(message)s')
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])

def _headers_to_list(headerobj):
    if hasattr(headerobj, 'getlist'):
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())

class ResourceConsumptionAuditor:

    def __init__(self, base_url: str, session, *, thresholds: dict | None=None, show_progress: bool=True) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.show_progress = show_progress
        self.thresholds = thresholds or {'response_time_ms': 2000, 'payload_kb_warn': 512, 'payload_kb_high': 2048, 'records_warn': 1000, 'records_high': 10000}
        self.issues: list[dict] = []

    def test_resource_consumption(self, endpoints):
        logger.info(f'Starting resource consumption test on {len(endpoints)} endpoints')
        issues = []
        FALSE_POSITIVE_STATUSES = {401, 403, 404, 405}
        it = tqdm(endpoints, desc='API4 resource endpoints', unit='endpoint') if self.show_progress else endpoints
        for ep in it:
            path = ep.get('path', '')
            method = ep.get('method', 'get').upper()
            url = urljoin(self.base_url + '/', path.lstrip('/'))
            if self.show_progress:
                it.write(f'-> Testing {method} {url}')
            headers = self.session.headers.copy()
            request_payload = {}
            try:
                start_time = datetime.utcnow()
                if method == 'GET':
                    resp = self.session.get(url)
                elif method == 'POST':
                    request_payload = {'test': 'value'}
                    resp = self.session.post(url, json=request_payload)
                elif method == 'PUT':
                    request_payload = {'update': 'value'}
                    resp = self.session.put(url, json=request_payload)
                elif method == 'DELETE':
                    resp = self.session.delete(url)
                else:
                    logger.warning(f'Unsupported method {method} for {url}')
                    continue
                end_time = datetime.utcnow()
                elapsed = (end_time - start_time).total_seconds()
                resp_size = len(resp.content)
                status = resp.status_code
                if status in FALSE_POSITIVE_STATUSES:
                    logger.debug(f'Skipping {url} due to likely false positive (status {status})')
                    continue
                if status == 501 or status == 503:
                    severity = 'Medium'
                elif resp_size > self.thresholds.get('response_size', 1000000):
                    severity = 'Critical'
                elif elapsed > self.thresholds.get('response_time', 2.0):
                    severity = 'High'
                elif status == 200:
                    severity = 'Medium'
                else:
                    severity = 'Info'
                issue = {'severity': severity, 'category': 'Resource Consumption', 'endpoint': url, 'method': method, 'status_code': status, 'response_time': elapsed, 'response_size': resp_size, 'description': f'{severity} - Resource Consumption at {url}', 'request_body': json.dumps(request_payload), 'response_body': resp.text[:2000], 'timestamp': str(datetime.utcnow()), 'request_headers': _headers_to_list(resp.request.headers), 'response_headers': _headers_to_list(resp.raw.headers)}
                issues.append(issue)
                logger.info(f'ISSUE FOUND: {severity} - Resource Consumption at {url}')
            except Exception as e:
                logger.warning(f'Exception while testing {url}: {str(e)}')
        return issues

    def _test_endpoint(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        url = endpoint.get('url', '')
        logging.debug(f'-- Running all resource consumption checks on {method} {url}')
        self._test_large_payloads(endpoint)
        self._test_computational_complexity(endpoint)
        self._test_rate_limiting(endpoint)
        self._test_batch_operations(endpoint)
        self._test_concurrent_flood(endpoint)

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} PB'

    def _build_url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    def _generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        payload = {}
        current = payload
        for i in range(depth):
            current['nested'] = {}
            current = current['nested']
            if i % 10 == 0:
                current[f'key_{i}'] = 'A' * 100
        return payload

    def _log_issue(self, endpoint: str, issue_type: str, description: str, severity: str, data: Optional[Dict[str, Any]]=None) -> None:
        status_code = data.get('status_code', 1) if data else 1
        if 500 <= status_code < 600:
            severity = 'Critical'
        elif status_code == 0 and severity == 'Medium':
            severity = 'High'
        entry = {'endpoint': endpoint, 'type': issue_type, 'description': description, 'severity': severity, 'status_code': status_code, 'timestamp': datetime.now().isoformat(), 'request_headers': _headers_to_list(self.session.headers), 'response_headers': _headers_to_list(data.get('headers') or {}), 'response_body': data.get('body') if data else None, 'request_body': data.get('request_body'), 'request_cookies': self.session.cookies.get_dict(), 'response_cookies': resp.cookies.get_dict() if 'resp' in locals() else {}, 'data': data, 'metrics': {'response_size': data.get('size'), 'response_time': data.get('time'), 'rpm': data.get('rpm'), 'batch_size': data.get('batch_size')} if data else None}
        self.issues.append(entry)
        logging.info(f"ISSUE FOUND: {severity} - {entry['type']} at {endpoint}")

    def _test_large_payloads(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        test_cases = [('small', {'limit': 10}, 'Low'), ('medium', {'limit': 1000}, 'Low'), ('large', {'limit': 10000}, 'Medium'), ('huge', {'limit': 100000}, 'High'), ('massive', {'limit': 1000000}, 'High')]
        if self.show_progress:
            test_iter = tqdm(test_cases, desc='Testing payload sizes', leave=False)
        else:
            test_iter = test_cases
        for size_name, params, severity in test_iter:
            if self.show_progress:
                test_iter.write(f"   -> {size_name} payload on {endpoint['url']}")
        malicious_payloads = [('10MB_string', 'A' * 10000000, 'High'), ('deep_json_100', self._generate_deep_nested_json(100), 'High'), ('zip_bomb', b'PK\x05\x06' + b'\x00' * 18, 'Critical')]
        logging.debug('  - Large payload tests')
        for size_name, params, severity in test_iter:
            try:
                start = time.time()
                resp = self.session.request(method, self._build_url(endpoint['url']), params=params, timeout=30)
                rt = time.time() - start
                rs = len(resp.content)
                logging.debug(f'    - {size_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                if rs > self.thresholds['response_size']:
                    self._log_issue(endpoint['url'], 'Large Response Size', f'{size_name} request returned {self._format_bytes(rs)}', severity, {'params': params, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Slow Response', f'{size_name} request took {rt:.2f}s', severity, {'params': params, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during {size_name} test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'Medium' if 'timeout' in str(exc).lower() else 'Low', {'status_code': 0})
        if method in ['POST', 'PUT', 'PATCH']:
            if self.show_progress:
                malicious_iter = tqdm(malicious_payloads, desc='Testing malicious payloads', leave=False)
            else:
                malicious_iter = malicious_payloads
            for payload_name, payload, severity in malicious_iter:
                try:
                    start = time.time()
                    headers = {'Content-Type': 'application/json'} if isinstance(payload, dict) else None
                    resp = self.session.request(method, self._build_url(endpoint['url']), json=payload if isinstance(payload, dict) else None, data=payload if isinstance(payload, bytes) else None, headers=headers, timeout=30)
                    rt = time.time() - start
                    rs = len(resp.content)
                    logging.debug(f'    - {payload_name}: status={resp.status_code}, size={self._format_bytes(rs)}, time={rt:.2f}s')
                    if rs > self.thresholds['response_size']:
                        self._log_issue(endpoint['url'], 'Large Response Size', f"Malicious payload '{payload_name}' returned {self._format_bytes(rs)}", severity, {'payload_type': payload_name, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                    if rt > self.thresholds['response_time']:
                        self._log_issue(endpoint['url'], 'Slow Response', f"Malicious payload '{payload_name}' took {rt:.2f}s", severity, {'payload_type': payload_name, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048], 'request_body': str(payload)[:1024]})
                except requests.RequestException as exc:
                    logging.debug(f'    ! Error during {payload_name} test: {exc}')
                    self._log_issue(endpoint['url'], 'Request Error', f'{payload_name}: {exc}', 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'request_body': str(payload)[:1024]})

    def _test_computational_complexity(self, endpoint: Dict[str, Any]) -> None:
        queries = [{'search': 'a' * 10000, 'severity': 'Medium'}, {'filter': ' OR '.join(['1=1'] * 500), 'severity': 'High'}, {'sort': ','.join(['field'] * 100), 'severity': 'Medium'}, {'id': '123 AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)', 'severity': 'Critical'}, {'query': "' OR 1=1; WAITFOR DELAY '0:0:5'--", 'severity': 'Critical'}, {'q': '{"$where": "sleep(5000)"}', 'severity': 'Critical'}]
        if self.show_progress:
            query_iter = tqdm(queries, desc='Testing complex queries', leave=False)
        else:
            query_iter = queries
        logging.debug('  - Computational complexity tests')
        for query in query_iter:
            severity = query.pop('severity')
            try:
                start = time.time()
                resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), params=query, timeout=35)
                rt = time.time() - start
                logging.debug(f'    - query {list(query.keys())[0]}: status={resp.status_code}, time={rt:.2f}s')
                if rt > 5.0 and any((keyword in str(query).lower() for keyword in ['sleep', 'waitfor', 'delay'])):
                    self._log_issue(endpoint['url'], 'Time-Based Vulnerability', f'Time-based test detected ({rt:.2f}s response)', 'Critical', {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
                elif rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Computational Complexity', f'Complex query took {rt:.2f}s', severity, {'query': query, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': resp.text[:2048]})
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during complexity test: {exc}')
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0, 'query': query})

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        limit = self.thresholds['rate_limit']
        logging.debug(f'  - Rate limit test (sustained traffic for 30 seconds, target - {limit} req/min)')
        successes = 0
        start_time = time.time()
        last_resp = None
        request_count = 0
        if self.show_progress:
            pbar = tqdm(total=30, desc='Rate limit test', unit='s')
        while time.time() - start_time < 30:
            try:
                last_resp = self.session.request(endpoint.get('method', 'GET'), self._build_url(endpoint['url']), timeout=5)
                request_count += 1
                if last_resp.status_code == 200:
                    successes += 1
                elif last_resp.status_code == 429:
                    logging.debug(f'    - rate limited at request #{request_count}')
            except requests.RequestException as exc:
                logging.debug(f'    ! Error during ratelimit request #{request_count}: {exc}')
                last_resp = None
            if self.show_progress:
                pbar.update(1)
                pbar.set_postfix({'requests': request_count, 'successes': successes})
        if self.show_progress:
            pbar.close()
        elapsed = time.time() - start_time
        rpm = successes / elapsed * 60 if elapsed > 0 else 0
        logging.debug(f'    - sent {request_count} requests, {successes} succeeded (~{rpm:.1f} req/min)')
        if rpm > limit:
            self._log_issue(endpoint['url'], 'Missing Rate Limiting', f'Achieved {rpm:.1f} req/min (no throttling)', 'High', {'sent': request_count, 'successes': successes, 'rpm': rpm, 'status_code': getattr(last_resp, 'status_code', 0) if last_resp else 0})
        elif successes == request_count:
            self._log_issue(endpoint['url'], 'Rate Limit Too High', f'No throttling detected at {rpm:.1f} req/min', 'Medium', {'sent': request_count, 'successes': successes, 'rpm': rpm})

    def _analyze_batch_response(self, endpoint: Dict[str, Any], size: int, resp: requests.Response, rt: float) -> None:
        logging.debug(f'    - batch {size}: status={resp.status_code}, time={rt:.2f}s')
        if resp.status_code == 207:
            try:
                responses = resp.json()
                failures = [r for r in responses if 400 <= r.get('status', 200) < 600]
                if failures:
                    self._log_issue(endpoint['url'], 'Partial Batch Failure', f'{len(failures)}/{size} items failed in batch', 'Medium', {'batch_size': size, 'failures': len(failures), 'status_code': 207, 'body': resp.text[:2048]})
            except json.JSONDecodeError:
                pass
        expected_time = self.thresholds['response_time'] * size ** 0.8
        if rt > expected_time * 2:
            severity = 'High' if size > 100 else 'Medium'
            self._log_issue(endpoint['url'], 'Batch Performance Issue', f'Batch of {size} took {rt:.2f}s (expected -{expected_time:.2f}s)', severity, {'batch_size': size, 'response_time': rt, 'threshold': expected_time, 'status_code': resp.status_code, 'body': resp.text[:2048]})

    def _test_batch_operations(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            return
        base_payload = endpoint.get('json', {'items': [{'id': 1, 'name': 'Test User', 'email': 'test@example.com', 'phone': '+1234567890', 'password': 'ValidPassword1!'}]})
        malicious_patterns = [('duplicate_ids', lambda i: {'id': 1}, 'Medium'), ('null_values', lambda i: {'id': i, 'value': None}, 'Low'), ('sql_injection', lambda i: {'id': i, 'filter': f"' OR 1=1 -- {i}"}, 'Critical')]
        if self.show_progress:
            batch_iter = tqdm(self.thresholds['batch_sizes'], desc='Testing batch sizes', leave=False)
        else:
            batch_iter = self.thresholds['batch_sizes']
        for size in batch_iter:
            try:
                payload = {'items': []}
                for i in range(size):
                    item = base_payload['items'][0].copy()
                    item.update({'id': i, 'email': f'user{i}@example.com'})
                    payload['items'].append(item)
                self._execute_batch_request(endpoint, size, method, payload, 'normal', 'Medium')
            except Exception as exc:
                logging.error(f'Critical error testing batch {size}: {exc}', exc_info=True)
                self._log_issue(endpoint['url'], 'Batch Request Failure', str(exc), 'High', {'batch_size': size, 'status_code': 0})
            if self.show_progress:
                pattern_iter = tqdm(malicious_patterns, desc='Testing malicious patterns', leave=False)
            else:
                pattern_iter = malicious_patterns
            for pattern_name, item_generator, severity in pattern_iter:
                try:
                    payload = {'items': [item_generator(i) for i in range(size)]}
                    self._execute_batch_request(endpoint, size, method, payload, pattern_name, severity)
                except Exception:
                    continue

    def _execute_batch_request(self, endpoint: Dict[str, Any], size: int, method: str, payload: Dict[str, Any], pattern_name: str, severity: str) -> None:
        adapter = HTTPAdapter(max_retries=self.retry_config['max_retries'], backoff_factor=self.retry_config['backoff_factor'])
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        start = time.time()
        resp = self.session.request(method, self._build_url(endpoint['url']), json=payload, timeout=60)
        rt = time.time() - start
        if resp.status_code == 400:
            self._log_issue(endpoint['url'], 'Batch Validation Failure', f'{pattern_name} batch of {size} failed validation', severity, {'pattern': pattern_name, 'batch_size': size, 'status_code': 400, 'body': resp.text[:2048]})
        else:
            self._analyze_batch_response(endpoint, size, resp, rt)

    def _test_concurrent_flood(self, endpoint: Dict[str, Any]) -> None:
        logging.debug(f"  - Concurrent flood test ({self.thresholds['concurrent_workers']} workers)")
        method = endpoint.get('method', 'GET')
        url = self._build_url(endpoint['url'])
        params = endpoint.get('parameters', {})
        successes = 0
        errors = 0
        timeouts = 0
        start_time = time.time()

        def send_request():
            try:
                resp = self.session.request(method, url, params=params, timeout=5)
                return resp.status_code
            except requests.exceptions.Timeout:
                return 'timeout'
            except requests.exceptions.RequestException:
                return 'error'
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thresholds['concurrent_workers']) as executor:
            futures = [executor.submit(send_request) for _ in range(self.thresholds['concurrent_requests'])]
            if self.show_progress:
                pbar = tqdm(total=len(futures), desc='Concurrent requests', unit='req')
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result == 200:
                    successes += 1
                elif result == 'timeout':
                    timeouts += 1
                else:
                    errors += 1
                if self.show_progress:
                    pbar.update(1)
                    pbar.set_postfix({'success': successes, 'errors': errors, 'timeouts': timeouts})
            if self.show_progress:
                pbar.close()
        elapsed = time.time() - start_time
        total_requests = self.thresholds['concurrent_requests']
        logging.debug(f'    - Completed {total_requests} requests in {elapsed:.2f}s: {successes} succeeded, {errors} errors, {timeouts} timeouts')
        if timeouts > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'Critical', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        elif timeouts > total_requests * 0.2:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total_requests} requests timed out under load', 'High', {'total_requests': total_requests, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        if errors > total_requests * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'Critical', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})
        elif errors > total_requests * 0.3:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total_requests} requests failed under load', 'High', {'total_requests': total_requests, 'errors': errors, 'timeouts': timeouts, 'successes': successes})

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return [i for i in self.issues if i.get('status_code', 1) != 0]

    def generate_report(self, fmt: str='markdown') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url)
        if fmt == 'markdown':
            return gen.generate_markdown()
        if fmt == 'html':
            return gen.generate_html()
        return gen.generate_html()

    def save_report(self, path: str, fmt: str='markdown') -> None:
        ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url).save(path, fmt=fmt)
