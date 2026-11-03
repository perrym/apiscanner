########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 24-06-2026                               #
########################################################
from __future__ import annotations
import re
import concurrent.futures
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry
from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig as OASSecurityConfig
from report_utils import ReportGenerator
logger = logging.getLogger(__name__)

#================funtion _headers_to_list _headers_to_list =============
def _headers_to_list(headerobj) -> List[tuple[str, str]]:
    try:
        if hasattr(headerobj, 'getlist'):
            out = []
            for k in headerobj:
                for v in headerobj.getlist(k):
                    out.append((str(k), str(v)))
            return out
        return [(str(k), str(v)) for k, v in (headerobj.items() if hasattr(headerobj, 'items') else [])]
    except Exception:
        return []

class ResourceConsumptionAuditor:

    #================funtion _slice_body _slice_body =============
    def _slice_body(self, resp, limit=2048):
        try:
            return (resp.text or '')[:limit]
        except Exception:
            return ''

    def _safe_body_sample(self, body, limit: int = 2048) -> str:
        if body is None:
            return ''
        if isinstance(body, bytes):
            try:
                return body.decode('utf-8', 'replace')[:limit]
            except Exception:
                return f'<{len(body)} bytes>'
        if isinstance(body, str):
            return body[:limit]
        try:
            return json.dumps(body, ensure_ascii=False)[:limit]
        except Exception:
            return str(body)[:limit]

    def _install_retry_adapter(self) -> None:
        try:
            adapter = HTTPAdapter(max_retries=self.retry)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
        except Exception:
            pass
    _FP_BODY_PATTERNS = re.compile("(not\\s+a\\s+multipart\\s+request|token\\s+didn'?t\\s+match|no\\s+documents\\s+in\\s+result|validation\\s+error|unsupported\\s+media\\s+type|csrf|missing\\s+required\\s+parameter|boundary\\s+not\\s+found)", re.IGNORECASE)

    @staticmethod
    #================funtion _looks_like_upload_path _looks_like_upload_path =============
    def _looks_like_upload_path(url: str) -> bool:
        p = url.lower()
        return any((x in p for x in ['/upload', '/uploads', '/pictures', '/videos', '/media', '/file', '/files']))

    #================funtion __init__ __init__ =============
    def __init__(self, session: requests.Session, *, base_url: str, swagger_spec: Optional[Dict[str, Any]]=None, timeout: float=10.0, thresholds: Optional[Dict[str, Any]]=None, show_progress: bool=True, logger: Optional[logging.Logger]=None) -> None:
        if session is None:
            raise ValueError('Session is required; pass an authenticated requests.Session.')
        if not base_url or not isinstance(base_url, str):
            raise ValueError('base_url is required')
        self.session = session
        self.base_url = base_url.rstrip('/') + '/'
        self.timeout = timeout
        self.logger = logger or logging.getLogger(__name__)
        self.spec: Dict[str, Any] = swagger_spec or {}
        self.show_progress = show_progress
        self.thresholds: Dict[str, Any] = {'response_time': 2.0, 'response_time_ms': 2000, 'response_size': 1000000, 'payload_kb_warn': 512, 'payload_kb_high': 2048, 'records_warn': 1000, 'records_high': 10000, 'rate_limit': 120.0, 'batch_sizes': [10, 50, 100], 'concurrent_workers': 4, 'concurrent_requests': 20, 'rate_probe_requests': 20, 'rate_probe_seconds': 5, 'rate_probe_interval': 0.1, 'ignore_nonstress_5xx': True, 'nonstress_5xx_max_size': 131072, 'nonstress_5xx_max_time': 2.0, 'skip_upload_like_endpoints_without_body': True}
        if thresholds:
            self.thresholds.update(thresholds)
        self.retry = Retry(total=1, connect=1, read=0, status=0, backoff_factor=0.4, status_forcelist=[], allowed_methods=['GET','HEAD','OPTIONS'], raise_on_status=False)
        self._install_retry_adapter()
        self.issues: List[Dict[str, Any]] = []

    #================funtion _build_url _build_url =============
    def _build_url(self, path_or_url: str) -> str:
        if not path_or_url:
            return self.base_url
        if path_or_url.startswith(('http://', 'https://')):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip('/'))

    @staticmethod
    #================funtion _format_bytes _format_bytes =============
    def _format_bytes(size: int) -> str:
        units = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB')
        s = float(size)
        for u in units:
            if s < 1024.0:
                return f'{s:.1f} {u}'
            s /= 1024.0
        return f'{s:.1f} ZB'

    #================funtion _generate_deep_nested_json _generate_deep_nested_json =============
    def _generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        cur = payload
        for i in range(depth):
            cur['nested'] = {}
            cur = cur['nested']
            if i % 10 == 0:
                cur[f'key_{i}'] = 'A' * 100
        return payload

    #================funtion _log_issue _log_issue =============
    def _log_issue(self, endpoint_url: str, issue_type: str, description: str, severity: str, data: Optional[Dict[str, Any]]=None) -> None:
        # Skip internal Python errors accidentally caught and logged as findings
        desc_low = (description or '').lower()
        if any(p in desc_low for p in ('nonetype', 'not subscriptable', 'keyerror', 'attributeerror', 'typeerror')):
            return
        data = data or {}
        status_code = int(data.get('status_code', 0))
        if issue_type in ('Concurrent Request Failures', 'Concurrent Request Timeouts'):
            description = 'Observation: ' + description + '; baseline availability and abuse impact unverified'
            severity = 'Info'
        elif status_code == 0:
            severity = 'Info' 
        if str(severity).lower() in ('high','critical'):
            description = 'Observation: '+description+'; configured limit and sustained availability impact unverified'
            severity = 'Info'
        entry = {'endpoint': endpoint_url, 'method': data.get('method') if data else None, 'type': issue_type, 'description': description, 'severity': severity, 'status_code': status_code, 'timestamp': datetime.utcnow().isoformat(), 'request_headers': _headers_to_list(self.session.headers), 'response_headers': _headers_to_list(data.get('headers') or {}), 'response_body': data.get('body'), 'request_body': data.get('request_body'), 'request_cookies': getattr(self.session.cookies, 'get_dict', lambda: {})(), 'response_cookies': data.get('resp_cookies', {}), 'data': data, 'metrics': {'response_size': data.get('size'), 'response_time': data.get('time'), 'rpm': data.get('rpm'), 'batch_size': data.get('batch_size')} if data else None}
        self.issues.append(entry)
        self.logger.info('ISSUE: %s - %s at %s', severity, issue_type, endpoint_url)

    #================funtion _endpoints_from_spec _endpoints_from_spec =============
    def _endpoints_from_spec(self) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        try:
            sec = OASSecurityConfig()
            for op in oas_iter_ops(self.spec or {}):
                try:
                    req = oas_build_request(self.spec, self.base_url, op, sec)
                except ValueError:
                    continue
                headers = {k: v for k, v in (req.get('headers') or {}).items() if k.lower() != 'authorization'}
                endpoints.append({'method': (req['method'] or 'GET').upper(), 'url': req['url'], 'headers': headers, 'json': req.get('json'), 'data': req.get('data'), 'params': req.get('params'), 'cookies': req.get('cookies'), 'files': req.get('files'), 'parameters': {}})
        except Exception as e:
            self.logger.debug('Universal builder failed: %s', e)
        return endpoints

    #================funtion test_resource_consumption test_resource_consumption =============
    def test_resource_consumption(self, endpoints: Optional[List[Dict[str, Any]]]=None) -> List[Dict[str, Any]]:
        from probe_policy import ProbePolicySession
        original = self.session
        policy = ProbePolicySession(original, self.spec, self.base_url)
        self.session = policy
        self.diagnostics = []
        try:
            return self._test_resource_consumption(endpoints)
        finally:
            self.session = original
            self.diagnostics.extend(policy.diagnostics('API4'))
            self.coverage = {'audit':'API4','state':'incomplete' if self.diagnostics else 'completed_unmeasured',
                             'scope_limited':True,'probe_policy':policy.summary(),
                             'note':'Only operations with successful baselines are eligible for sampled load probes. Task completeness is not established.'}

    def _test_resource_consumption(self, endpoints: Optional[List[Dict[str, Any]]]=None) -> List[Dict[str, Any]]:
        if endpoints is None or len(endpoints) == 0:
            if self.spec:
                endpoints = self._endpoints_from_spec()
            else:
                endpoints = []
        it = tqdm(endpoints, desc='API4 resource endpoints', unit='endpoint') if self.show_progress else endpoints
        start_count = len(self.issues)
        skip_status = {401, 403, 404, 405}
        eligible = []
        for ep in it:
            method = (ep.get('method') or 'GET').upper()
            url = self._build_url(ep.get('url') or ep.get('path', '/'))
            json_body = ep.get('json')
            data_body = ep.get('data')
            if self.thresholds.get('skip_upload_like_endpoints_without_body', True):
                if method in ('POST', 'PUT', 'PATCH') and (json_body is None and data_body is None and not ep.get('files')) and self._looks_like_upload_path(url):
                    if self.show_progress:
                        try:
                            it.write(f'   ~ Skipped (upload endpoint without body): {url}')
                        except Exception:
                            pass
                    continue
            headers = dict(ep.get('headers') or {})
            headers.pop('Authorization', None)
            if self.show_progress:
                try:
                    it.write(f'-> Testing {method} {url}')
                except Exception:
                    pass
            t0 = time.time()
            try:
                if method in ('POST', 'PUT', 'PATCH'):
                    resp = self.session.request(method, url, headers=headers, json=json_body, data=data_body, files=ep.get('files'), params=ep.get('params'), cookies=ep.get('cookies'), timeout=self.timeout)
                else:
                    resp = self.session.request(method, url, headers=headers, params=ep.get('params'), cookies=ep.get('cookies'), timeout=self.timeout)
                elapsed = time.time() - t0
                size = len(resp.content or b'')
                status = resp.status_code
                body_text = self._slice_body(resp, 2000)
                content_type = str(resp.headers.get('Content-Type', '')).lower()
                nonstress = elapsed <= float(self.thresholds.get('nonstress_5xx_max_time', self.thresholds['response_time'])) and size <= int(self.thresholds.get('nonstress_5xx_max_size', 131072))
                if not 200 <= status < 300:
                    self.diagnostics.append(dict(audit='API4',method=method,url=url,status=status,response_body=self._slice_body(resp,20000),response_content_type=content_type,error='Baseline unsuitable for load probes',execution_status='skipped'))
                    continue
                eligible.append(ep)
                if status in (501, 503):
                    severity = 'Medium'
                elif size > float(self.thresholds['response_size']):
                    severity = 'Critical'
                elif elapsed > float(self.thresholds['response_time']):
                    severity = 'High'
                else:
                    severity = 'Info'
                triggered = False
                if 500 <= status < 600:
                    if self.thresholds.get('ignore_nonstress_5xx', True):
                        if nonstress or self._FP_BODY_PATTERNS.search(body_text):
                            if self.show_progress:
                                try:
                                    it.write(f'   ~ Ignored non-stress 5xx: {status} {url}')
                                except Exception:
                                    pass
                            continue
                    sev = 'Critical' if elapsed > float(self.thresholds['response_time']) or size > float(self.thresholds['response_size']) else 'High'
                    self._log_issue(url, 'Server Error', f'Server error under load: {status}', sev, {'method': method, 'status_code': status, 'time': elapsed, 'size': size, 'headers': dict(resp.headers), 'body': body_text})
                    continue
                if size > float(self.thresholds['response_size']):
                    self._log_issue(url, 'Large Response Size', f'Body: {self._format_bytes(size)}', 'Critical', {'method': method, 'status_code': status, 'size': size, 'time': elapsed, 'headers': dict(resp.headers), 'body': body_text})
                    triggered = True
                if elapsed > float(self.thresholds['response_time']):
                    self._log_issue(url, 'Response Time Observation', f'Observation: single response took {elapsed:.2f}s; no resource exhaustion demonstrated', 'Info', {'method': method, 'status_code': status, 'time': elapsed, 'size': size, 'headers': dict(resp.headers), 'body': body_text})
                    triggered = True
                if not triggered and status == 200:
                    try:
                        if 'application/json' not in content_type:
                            raise ValueError('skip non-JSON body for large record count check')
                        data = resp.json()
                        total_records = 0
                        if isinstance(data, list):
                            total_records = len(data)
                        elif isinstance(data, dict):
                            for v in data.values():
                                if isinstance(v, list):
                                    total_records = max(total_records, len(v))
                        warn = int(self.thresholds.get('records_warn', 1000))
                        high = int(self.thresholds.get('records_high', 10000))
                        if total_records >= high:
                            self._log_issue(url, 'Large Record Set', f'{total_records} records', 'High', {'method': method, 'status_code': status, 'records': total_records, 'time': elapsed, 'size': size, 'headers': dict(resp.headers)})
                            triggered = True
                        elif total_records >= warn:
                            self._log_issue(url, 'Large Record Set', f'{total_records} records', 'Medium', {'method': method, 'status_code': status, 'records': total_records, 'time': elapsed, 'size': size, 'headers': dict(resp.headers)})
                            triggered = True
                    except Exception:
                        pass
                if not triggered:
                    continue
            except requests.RequestException as exc:
                elapsed = time.time() - t0
                self.diagnostics.append(dict(audit='API4',method=method,url=url,error=type(exc).__name__,execution_status='failed'))
                self._log_issue(url, 'Request Error', str(exc), 'Medium' if 'timeout' in str(exc).lower() else 'Low', {'method': method, 'status_code': 0, 'time': elapsed})

        # ── Advanced resource consumption tests on sampled endpoints ──
        # Run heavy tests only on a subset to avoid overloading the target.
        if eligible:
            # Payload size tests (query params) — sample first 3 GET endpoints
            get_eps = [e for e in eligible if (e.get('method') or 'GET').upper() == 'GET'][:3]
            for ep in get_eps:
                try:
                    self._test_large_payloads(ep)
                except Exception:
                    pass

            # Batch / computational / rate-limit / concurrent tests — sample 1 endpoint each
            write_eps = [e for e in eligible if (e.get('method') or 'GET').upper() in ('POST', 'PUT', 'PATCH')]
            for ep in write_eps[:1]:
                try:
                    self._test_batch_operations(ep)
                except Exception:
                    pass
            for ep in [e for e in eligible if (e.get('method') or 'GET').upper()=='GET'][:1]:
                try:
                    self._test_computational_complexity(ep)
                    self._test_rate_limiting(ep)
                    self._test_concurrent_flood(ep)
                except Exception:
                    pass

        # ── Data exfiltration risk assessment (Salesforce Data Loader pattern) ──
        # Detect endpoints vulnerable to bulk data theft: large records + no
        # pagination + rapid repeatable queries.  Based on Mitiga/UNC6040 TTPs.
        try:
            self._test_data_exfiltration_risk(eligible)
        except Exception:
            pass

        return self.issues[start_count:]

    #================funtion _test_data_exfiltration_risk detect bulk exfiltration vulnerability ##########
    def _test_data_exfiltration_risk(self, endpoints: List[Dict[str, Any]]) -> None:
        """Detect endpoints vulnerable to bulk data exfiltration (Salesforce Data Loader pattern).

        Threat actors use legitimate API tokens to pull large record sets in rapid bursts,
        each request returning mid-sized chunks (1-6 MB / 1000+ records) to stay under
        per-request limits while exfiltrating millions of records total.

        Indicators (from Mitiga UNC6040 / CVE-2023-44487 IOAs):
        - GET endpoint returns 1000+ records or 1MB+ per request without pagination
        - Rapid repeatable queries — 5 requests in quick succession all succeed
        - Missing pagination headers (Link, X-Total-Count, Content-Range)
        - No rate limiting detected (checked separately by _test_rate_limiting)
        """
        candidates = []
        for ep in (endpoints or [])[:10]:  # sample first 10 to keep test fast
            method = (ep.get('method') or 'GET').upper()
            if method != 'GET':
                continue
            url = self._build_url(ep.get('url') or ep.get('path', '/'))
            try:
                resp = self.session.request(method, url, timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                size = len(resp.content or b'')
                ct = (resp.headers.get('Content-Type', '') or '').lower()
                if 'application/json' not in ct:
                    continue
                data = resp.json()
                total_records = 0
                if isinstance(data, list):
                    total_records = len(data)
                elif isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            total_records = max(total_records, len(v))
                # Only test endpoints that already show large data potential
                if total_records < int(self.thresholds.get('records_warn', 1000)) and size < int(self.thresholds.get('response_size', 1000000)):
                    continue
                candidates.append((ep, url, total_records, size))
            except Exception:
                continue

        for ep, url, records, first_size in candidates[:3]:
            # Rapid burst: 5 identical requests in quick succession
            sizes = [first_size]
            all_ok = True
            for _ in range(4):
                try:
                    r = self.session.request('GET', url, timeout=self.timeout)
                    if r.status_code == 200:
                        sizes.append(len(r.content or b''))
                    else:
                        all_ok = False
                        break
                except Exception:
                    all_ok = False
                    break

            if not all_ok:
                continue

            avg_size = sum(sizes) / len(sizes)
            consistent = all(abs(s - avg_size) < avg_size * 0.3 for s in sizes)  # within 30%

            # Check for pagination enforcement
            hdrs_lower = {k.lower(): v for k, v in (getattr(self.session, 'headers', {}) or {}).items()}
            has_pagination = any(
                h in hdrs_lower for h in ('link', 'x-total-count', 'x-total', 'content-range')
            )

            if consistent and not has_pagination:
                desc = (
                    f'{records} records / {self._format_bytes(int(avg_size))} per request × 5 rapid GETs '
                    f'— no pagination headers. Vulnerable to bulk data exfiltration '
                    f'(Salesforce Data Loader / UNC6040 TTP).'
                )
                self._log_issue(url, 'Data Exfiltration Risk', desc, 'Critical',
                    {'method': 'GET', 'records_per_request': records, 'avg_size': int(avg_size),
                     'burst_size': len(sizes), 'consistent': consistent, 'has_pagination': has_pagination,
                     'note': 'Mid-sized chunk exfiltration — each request is moderate but cumulative theft is massive'})
            elif consistent:
                self._log_issue(url, 'Data Exfiltration Risk',
                    f'{records} records / {self._format_bytes(int(avg_size))} per request × 5 rapid GETs '
                    f'— pagination present but consistent large chunks still exfiltratable',
                    'Medium',
                    {'method': 'GET', 'records_per_request': records, 'avg_size': int(avg_size),
                     'burst_size': len(sizes), 'has_pagination': has_pagination})

    #================funtion _test_large_payloads _test_large_payloads =============
    def _test_large_payloads(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get('method', 'GET') or 'GET').upper()
        if 'limit' not in (endpoint.get('params') or {}): return
        test_cases = [('small', {'limit': 10}, 'Low'), ('medium', {'limit': 1000}, 'Low'), ('large', {'limit': 10000}, 'Medium'), ('huge', {'limit': 100000}, 'High'), ('massive', {'limit': 1000000}, 'High')]
        it = tqdm(test_cases, desc='Testing payload sizes', leave=False) if self.show_progress else test_cases
        for size_name, params, sev in it:
            try:
                start = time.time()
                resp = self.session.request(method, self._build_url(endpoint['url']), params=params, timeout=30)
                rt = time.time() - start
                rs = len(resp.content or b'')
                if rs > self.thresholds['response_size']:
                    self._log_issue(endpoint['url'], 'Large Response Size', f'{size_name} -> {self._format_bytes(rs)}', sev, {'method': method, 'params': params, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
                if rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Slow Response', f'{size_name} took {rt:.2f}s', sev, {'method': method, 'params': params, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
            except requests.RequestException as exc:
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'Medium' if 'timeout' in str(exc).lower() else 'Low', {'method': method, 'status_code': 0})
        if method in ['POST', 'PUT', 'PATCH']:
            malicious_payloads = [('10MB_string', 'A' * 10000000, 'High'), ('deep_json_100', self._generate_deep_nested_json(100), 'High'), ('zip_stub', b'PK\x05\x06' + b'\x00' * 18, 'Critical')]
            it2 = tqdm(malicious_payloads, desc='Testing malicious payloads', leave=False) if self.show_progress else malicious_payloads
            for payload_name, payload, sev in it2:
                try:
                    start = time.time()
                    headers = {'Content-Type': 'application/json'} if isinstance(payload, dict) else None
                    resp = self.session.request(method, self._build_url(endpoint['url']), json=payload if isinstance(payload, dict) else None, data=payload if isinstance(payload, (bytes, str)) and (not isinstance(payload, dict)) else None, headers=headers, timeout=30)
                    rt = time.time() - start
                    rs = len(resp.content or b'')
                    if rs > self.thresholds['response_size']:
                        self._log_issue(endpoint['url'], 'Large Response Size', f'{payload_name} -> {self._format_bytes(rs)}', sev, {'method': method, 'payload_type': payload_name, 'size': rs, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
                    if rt > self.thresholds['response_time']:
                        self._log_issue(endpoint['url'], 'Slow Response', f'{payload_name} took {rt:.2f}s', sev, {'method': method, 'payload_type': payload_name, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
                except requests.RequestException as exc:
                    self._log_issue(endpoint['url'], 'Request Error', f'{payload_name}: {exc}', 'High' if 'timeout' in str(exc).lower() else 'Medium', {'status_code': 0})

    #================funtion _test_computational_complexity _test_computational_complexity =============
    def _test_computational_complexity(self, endpoint: Dict[str, Any]) -> None:
        # Sane payload sizes: avoid DoS-ing the target with absurd 10KB strings
        # and 500-repetition filters that cause cascading 500 errors.
        queries = [
            {'search': 'a' * 256, 'severity': 'Low'},
            {'filter': ' OR '.join(['1=1'] * 20), 'severity': 'Medium'},
            {'sort': ','.join(['field'] * 20), 'severity': 'Low'},
            {'id': '123 AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)', 'severity': 'Critical'},
            {'query': "' OR 1=1; WAITFOR DELAY '0:0:5'--", 'severity': 'Critical'},
            {'q': '{"$where": "sleep(5000)"}', 'severity': 'Critical'},
        ]
        it = tqdm(queries, desc='Testing complex queries', leave=False) if self.show_progress else queries
        for q in it:
            sev = q.pop('severity')
            q = {key:value for key,value in q.items() if key in (endpoint.get('params') or {})}
            if not q: continue
            try:
                start = time.time()
                resp = self.session.request((endpoint.get('method', 'GET') or 'GET').upper(), self._build_url(endpoint['url']), params=q, timeout=35)
                rt = time.time() - start
                if rt > 5.0 and any((k in str(q).lower() for k in ['sleep', 'waitfor', 'delay'])):
                    self._log_issue(endpoint['url'], 'Time-Based Vulnerability', f'Time-based test: {rt:.2f}s', 'Critical', {'method': endpoint.get('method', 'GET'), 'query': q, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
                elif rt > self.thresholds['response_time']:
                    self._log_issue(endpoint['url'], 'Computational Complexity', f'Complex query took {rt:.2f}s', sev, {'method': endpoint.get('method', 'GET'), 'query': q, 'time': rt, 'status_code': resp.status_code, 'headers': dict(resp.headers), 'body': (resp.text or '')[:2048]})
            except requests.RequestException as exc:
                # Don't log connection-pool errors as findings — if we overload
                # the server, that's our fault, not a security issue.
                exc_str = str(exc).lower()
                if 'connectionpool' in exc_str or 'max retries' in exc_str:
                    continue
                self._log_issue(endpoint['url'], 'Request Error', str(exc), 'High' if 'timeout' in str(exc).lower() else 'Medium', {'method': endpoint.get('method', 'GET'), 'status_code': 0, 'query': q})

    #================funtion _test_rate_limiting _test_rate_limiting =============
    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        limit = float(self.thresholds['rate_limit'])
        successes = 0
        start_time = time.time()
        last_resp = None
        request_count = 0
        if self.show_progress:
            pbar = tqdm(total=30, desc='Rate limit test', unit='s')
        last_sec = 0
        while time.time() - start_time < float(self.thresholds.get('rate_probe_seconds',5)) and request_count < int(self.thresholds.get('rate_probe_requests',20)):
            try:
                last_resp = self.session.request((endpoint.get('method', 'GET') or 'GET').upper(), self._build_url(endpoint['url']), timeout=5)
                request_count += 1
                if last_resp.status_code in (400,401,403,404,405,415,422,429): break
                if last_resp.status_code == 200:
                    successes += 1
            except requests.RequestException:
                last_resp = None
                break
            time.sleep(float(self.thresholds.get('rate_probe_interval',0.1)))
            if self.show_progress:
                sec = int(time.time() - start_time)
                if sec > last_sec:
                    pbar.update(sec - last_sec)
                    last_sec = sec
        if self.show_progress:
            pbar.close()
        elapsed = time.time() - start_time
        rpm = successes / elapsed * 60 if elapsed > 0 else 0.0
        if rpm > limit:
            self._log_issue(endpoint['url'], 'Rate Limit Observation', f'Observation: ~{rpm:.1f} req/min accepted during this probe; configured limit and impact unknown', 'Info', {'method': endpoint.get('method', 'GET'), 'sent': request_count, 'successes': successes, 'rpm': rpm, 'status_code': getattr(last_resp, 'status_code', 0) if last_resp else 0})

    #================funtion _analyze_batch_response _analyze_batch_response =============
    def _analyze_batch_response(self, endpoint: Dict[str, Any], size: int, resp: requests.Response, rt: float) -> None:
        if resp.status_code == 207:
            try:
                responses = resp.json()
                failures = [r for r in responses if 400 <= r.get('status', 200) < 600]
                if failures:
                    self._log_issue(endpoint['url'], 'Partial Batch Failure', f'{len(failures)}/{size} items failed in batch', 'Medium', {'method': endpoint.get('method', 'GET'), 'batch_size': size, 'failures': len(failures), 'status_code': 207, 'body': (resp.text or '')[:2048]})
            except json.JSONDecodeError:
                pass
        expected_time = float(self.thresholds['response_time']) * size ** 0.8
        if rt > expected_time * 2:
            severity = 'High' if size > 100 else 'Medium'
            self._log_issue(endpoint['url'], 'Batch Performance Issue', f'Batch of {size} took {rt:.2f}s', severity, {'method': endpoint.get('method', 'GET'), 'batch_size': size, 'response_time': rt, 'threshold': expected_time, 'status_code': resp.status_code, 'body': (resp.text or '')[:2048]})

    #================funtion _test_batch_operations _test_batch_operations =============
    def _test_batch_operations(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get('method', 'GET') or 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            return
        from copy import deepcopy
        base_payload = endpoint.get('json')
        if not isinstance(base_payload,dict): return
        array_key = next((key for key,value in base_payload.items() if isinstance(value,list) and value),None)
        if array_key is None: return
        template = base_payload[array_key][0]
        for size in self.thresholds.get('batch_sizes',[10,50,100]):
            payload = deepcopy(base_payload)
            payload[array_key] = [deepcopy(template) for _ in range(size)]
            try: self._execute_batch_request(endpoint,size,method,payload,'schema-array','Info')
            except requests.RequestException: return

    #================funtion _execute_batch_request _execute_batch_request =============
    def _execute_batch_request(self, endpoint: Dict[str, Any], size: int, method: str, payload: Dict[str, Any], pattern_name: str, severity: str) -> None:
        start = time.time()
        resp = self.session.request(method, self._build_url(endpoint['url']), json=payload, timeout=60)
        rt = time.time() - start
        if resp.status_code == 400:
            # Only flag if the 400 reveals stack traces or verbose errors —
            # a plain "validation failed" on an invalid batch is expected behavior.
            # Spring's BeanPropertyBindingResult is normal validation, NOT a verbose error.
            body_text = (resp.text or '').lower()
            verbose_indicators = (
                'stack trace', 'traceback', 'exception', 'sqlstate',
                'java.lang.', 'at com.', 'at org.',
                'sql syntax', 'column.*not found', 'unclosed quotation',
                'org.springframework.dao', 'org.springframework.jdbc',
                'org.springframework.orm', 'org.hibernate',
                'org.postgresql', 'com.mysql', 'java.sql',
                'nullpointerexception', 'illegalargumentexception',
                'illegalstateexception', 'classcastexception', 'arrayindexoutofbounds',
                'indexoutofbounds', 'numberformatexception', 'concurrentmodification',
            )
            # Exclude normal Spring validation — BeanPropertyBindingResult is expected
            is_spring_validation = 'beanpropertybindingresult' in body_text
            has_real_verbose = any(ind in body_text for ind in verbose_indicators)
            if has_real_verbose and not is_spring_validation:
                self._log_issue(endpoint['url'], 'Batch Request Error',
                    f'{pattern_name} batch of {size} caused verbose server error',
                    severity, {'method': method, 'pattern': pattern_name, 'batch_size': size,
                    'status_code': 400, 'body': body_text[:2048]})
            # Normal validation rejections are not security findings — skip.
        else:
            self._analyze_batch_response(endpoint, size, resp, rt)

    #================funtion _test_concurrent_flood _test_concurrent_flood =============
    def _test_concurrent_flood(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get('method', 'GET') or 'GET').upper()
        url = self._build_url(endpoint.get('url') or endpoint.get('path', '/'))

        # Quick probe — skip endpoints that don't exist
        try:
            probe = self.session.request(method, url, timeout=5)
            if not 200 <= probe.status_code < 300:
                return  # endpoint doesn't exist or requires auth
        except Exception:
            return  # can't reach endpoint, skip

        params = endpoint.get('parameters', {})
        successes = 0
        errors = 0
        timeouts = 0

        #================funtion send_request send_request =============
        def send_request():
            try:
                resp = self.session.request(method, url, params=params, timeout=5)
                return resp.status_code
            except requests.exceptions.Timeout:
                return 'timeout'
            except requests.exceptions.RequestException:
                return 'error'
        max_workers = int(self.thresholds.get('concurrent_workers', 8))
        total = int(self.thresholds.get('concurrent_requests', 100))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(send_request) for _ in range(total)]
            bar = tqdm(total=len(futures), desc='Concurrent requests', unit='req') if self.show_progress else None
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result == 200:
                    successes += 1
                elif result == 'timeout':
                    timeouts += 1
                else:
                    errors += 1
                if bar:
                    bar.update(1)
            if bar:
                bar.close()
        # When ALL requests fail (errors+timeouts=total), we overloaded the server
        # ourselves — this is self-DoS, not a vulnerability. Downgrade to Info.
        if timeouts + errors >= total:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total} timed out, {errors} errors; cause unverified', 'Info', {'method': method, 'total_requests': total, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        elif timeouts > total * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total} timed out', 'High', {'method': method, 'total_requests': total, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        elif timeouts > total * 0.2:
            self._log_issue(endpoint['url'], 'Concurrent Request Timeouts', f'{timeouts}/{total} timed out', 'Medium', {'method': method, 'total_requests': total, 'timeouts': timeouts, 'errors': errors, 'successes': successes})
        if errors > total * 0.5:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total} failed', 'High', {'method': method, 'total_requests': total, 'errors': errors, 'timeouts': timeouts, 'successes': successes})
        elif errors > total * 0.3:
            self._log_issue(endpoint['url'], 'Concurrent Request Failures', f'{errors}/{total} failed', 'Medium', {'method': method, 'total_requests': total, 'errors': errors, 'timeouts': timeouts, 'successes': successes})

    #================funtion _filtered_issues _filtered_issues =============
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        ERROR_PATTERNS = (
            'nonetype', 'not subscriptable', 'keyerror', 'attributeerror',
            'typeerror', "'none'", 'connectionpool', 'max retries',
        )
        for it in self.issues:
            code = int(it.get('status_code', 0) or 0)
            desc = (it.get('description') or '').lower()
            # Skip known uninteresting HTTP status codes
            if code in (400, 404, 405):
                continue
            # Filter out Python crash messages logged as findings
            if any(p in desc for p in ERROR_PATTERNS):
                continue
            # Skip concurrent flood results for endpoints that don't exist
            if 'failed' in desc and code == 0:
                continue
            key = (
                it.get('endpoint'),
                it.get('method'),
                it.get('type'),
                it.get('severity'),
                code,
                (it.get('description') or '')[:256],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    #================funtion generate_report generate_report =============
    def generate_report(self, fmt: str='markdown') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url)
        if fmt == 'markdown':
            return gen.generate_markdown()
        if fmt == 'html':
            return gen.generate_html()
        return gen.generate_html()

    #================funtion save_report save_report =============
    def save_report(self, path: str, fmt: str='markdown') -> None:
        ReportGenerator(self._filtered_issues(), scanner='ResourceConsumption (API04)', base_url=self.base_url).save(path, fmt=fmt)
