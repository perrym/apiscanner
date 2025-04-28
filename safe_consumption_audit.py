# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
"""safe_consumption_audit.py – Enhanced OWASP API10:2023 Auditor
=================================================
Veilige versie met:
* Uitgebreide injectiepayloads (SQL, XSS, Path, NoSQL, SSTI, LDAP, XXE)
* CRLF / Header Injection tests
* HTTP Parameter Pollution (HPP)
* SSRF Vector tests
* Docker Remote API exposure tests
* Kubernetes API exposure tests
* GraphQL Introspection tests
* Rate limiting en whitelist-ondersteuning
* Verbeterde error handling
* INFO logging voor voortgangsweergave
"""
from __future__ import annotations
import json
import ssl
import socket
import urllib.parse as urlparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import re
import time
import requests

Issue = Dict[str, Any]

class SafeConsumptionAuditor:
    """Veilige auditor voor OWASP API10 met uitgebreide tests en INFO-logging"""
    INJECTION_PAYLOADS = {
        'sql': ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT null,null--", "1; show tables--", "' AND SLEEP(5)--", "'||(SELECT version())||'"],
        #'xss': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<body onload=alert(1)>'],
        #'path': ['../../../etc/passwd', '%2e%2e%2fetc%2fpasswd', '..%2f..%2f..%2fetc%2fpasswd'],
        #'nosql': ['{"$gt":""}', '{"$ne":null}', '{"$where":"sleep(5)"}'],
        #'ssti': ['{{7*7}}', '${{7*7}}', '<%= 7*7 %>'],
        #'ldap': ['*)(uid=*))(|(uid=*)', '*))%00'],
        #'xxe': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    }
    CRLF_PAYLOADS = ['%0d%0aX-Evil: test', '\r\nSet-Cookie: evil=1']
    HPP_PARAMS = ['id', 'q']
    SSRF_PAYLOADS = ['http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd', 'gopher://127.0.0.1:6379/_PING']
    GRAPHQL_INTROSPECTION_QUERY = '{ __schema { types { name } } }'

    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 8):
        self.session = session or self._create_secure_session()
        self.timeout = timeout
        self.issues: List[Issue] = []
        self.rate_limit = 0.5  # seconden tussen requests

    def _create_secure_session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers.update({'User-Agent': 'SafeAPIAuditor/2.0', 'Accept': 'application/json'})
        sess.verify = True
        return sess

    @staticmethod
    def third_party_hosts_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding='utf-8'))
        hosts: Set[str] = set()
        for srv in spec.get('servers', []):
            url = srv.get('url')
            if url:
                parsed = urlparse.urlparse(url)
                if parsed.netloc:
                    hosts.add(parsed.netloc.split(':')[0])
        def walk(node: Any):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == '$ref' and isinstance(v, str) and v.startswith('http'):
                        hosts.add(urlparse.urlparse(v).netloc.split(':')[0])
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(spec)
        return sorted(hosts)

    @staticmethod
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding='utf-8'))
        servers = [srv.get('url').rstrip('/') for srv in spec.get('servers', []) if srv.get('url')]
        paths = spec.get('paths', {})
        endpoints: List[str] = []
        for server in servers:
            for path in paths:
                endpoints.append(server + path)
        return endpoints

    def _log(self,
             issue: str,
             target: str,
             severity: str,
             payload: Optional[str] = None,
             response_sample: Optional[str] = None):
        entry = {
            'issue':      issue,
            'target':     target,
            'severity':   severity,
            'timestamp':  datetime.now().isoformat(),
            'scanner':    'SafeAPI-Auditor-2.0'
        }
        if payload:
            entry['payload'] = payload
        if response_sample:
            entry['response_sample'] = response_sample[:200]
        self.issues.append(entry)

    def _is_injection_successful(self, response: requests.Response, attack_type: str) -> bool:
        if response.status_code >= 500:
            return True
        content = response.text.lower()
        if attack_type == 'sql' and any(term in content for term in ['sql', 'syntax', 'error', 'unclosed']):
            return True
        return False

    def _test_basic_security(self, host: str):
        print(f"[INFO] Basic security test for {host}")
        try:
            url = f"https://{host}"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code >= 400:
                self._log('Basic security fail', url, 'Medium', response_sample=r.text)
        except Exception as e:
            self._log('Basic security error', host, 'Medium')

    def _test_crlf_injection(self, host: str):
        print(f"[INFO] CRLF Injection tests for {host}")
        for payload in self.CRLF_PAYLOADS:
            try:
                url = f"https://{host}/?q={payload}"
                r = self.session.get(url, timeout=self.timeout)
                if 'evil' in r.text.lower():
                    self._log('CRLF Injection', url, 'High', payload=payload, response_sample=r.text)
            except:
                pass

    def _test_hpp(self, host: str):
        print(f"[INFO] HTTP Parameter Pollution tests for {host}")
        for param in self.HPP_PARAMS:
            try:
                url = f"https://{host}/?{param}=1&{param}=2"
                r = self.session.get(url, timeout=self.timeout)
                if ',' in r.text:
                    self._log('HPP detected', url, 'Medium', response_sample=r.text)
            except:
                pass

    def _test_ssrf(self, host: str):
        print(f"[INFO] SSRF tests for {host}")
        for payload in self.SSRF_PAYLOADS:
            try:
                url = payload
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code < 400:
                    self._log('SSRF endpoint accessible', payload, 'High', response_sample=r.text)
            except:
                pass

    def _test_docker_api(self, host: str):
        print(f"[INFO] Docker API test for {host}")
        try:
            r = self.session.get(f"http://{host}:2375/version", timeout=self.timeout)
            if r.status_code == 200:
                self._log('Docker Remote API open', host, 'High', response_sample=r.text)
        except:
            pass

    def _test_kubernetes_api(self, host: str):
        print(f"[INFO] Kubernetes API test for {host}")
        try:
            for port in [6443, 2379]:
                r = self.session.get(f"https://{host}:{port}/version", timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    self._log('Kubernetes API open', f"{host}:{port}", 'High', response_sample=r.text)
        except:
            pass

    def _test_graphql_introspection(self, host: str):
        print(f"[INFO] GraphQL introspection test for {host}")
        try:
            url = f"https://{host}/graphql"
            r = self.session.post(url, json={'query': self.GRAPHQL_INTROSPECTION_QUERY}, timeout=self.timeout)
            if 'data' in r.json():
                self._log('GraphQL introspection available', url, 'Medium', response_sample=str(r.json()))
        except:
            pass

    def _test_sensitive_data_exposure(self, host: str):
        print(f"[INFO] Sensitive data exposure test for {host}")
        try:
            url = f"https://{host}/api/v1/config"
            r = self.session.get(url, timeout=self.timeout)
            for term in ['password', 'secret', 'token']:
                if term in r.text.lower():
                    self._log('Sensitive data exposure', url, 'High', response_sample=r.text)
        except:
            pass

    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        for url in endpoints:
            print(f"[INFO] Testing endpoint: {url}")
            host = urlparse.urlparse(url).netloc
            try:
                self._test_basic_security(host)
                for t, payloads in self.INJECTION_PAYLOADS.items():
                    for p in payloads:
                        test_url = f"{url}?input={urlparse.quote(p)}"
                        print(f"[INFO] Injection test on {test_url}")
                        time.sleep(self.rate_limit)
                        r = self.session.get(test_url, timeout=self.timeout/2, allow_redirects=False)
                        if self._is_injection_successful(r, t):
                            self._log(
                                issue=f'Possible {t.upper()} injection',
                                target=test_url,
                                severity='Critical',
                                payload=p,
                                response_sample=r.text
                            )
                self._test_crlf_injection(host)
                self._test_hpp(host)
                self._test_ssrf(host)
                self._test_docker_api(host)
                self._test_kubernetes_api(host)
                self._test_graphql_introspection(host)
                self._test_sensitive_data_exposure(host)
            except Exception as e:
                self._log('Endpoint testing failed', f'{url} - {e}', 'Medium')
        return self.issues

    def generate_report(self, fmt: str = 'markdown') -> str:
        if not self.issues:
            return 'No issues found.'
        if fmt == 'json':
            return json.dumps({'meta': {'date': datetime.now().isoformat()}, 'findings': self.issues}, indent=2)
        lines = ['# Safe Consumption Report', f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
        for entry in self.issues:
            line = f"- [{entry['severity']}] {entry['issue']} @ {entry['target']}"
            if 'payload' in entry:
                line += f" | payload: {entry['payload']}"
            if 'response_sample' in entry:
                line += f" | response: {entry['response_sample']!r}"
            lines.append(line)
        return '\n'.join(lines)
