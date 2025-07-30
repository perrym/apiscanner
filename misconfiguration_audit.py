##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################

from __future__ import annotations
import argparse
import json
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, quote_plus
from report_utils import ReportGenerator
import requests

def _headers_to_list(hdrs):
    # Set-Cookie"""
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())

Endpoint = Dict[str, Any]
Finding = Dict[str, Any]

class MisconfigurationAuditorPro:
    DEFAULT_CONCURRENCY = 12
    DEFAULT_TIMEOUT = 8
    DEFAULT_REQUESTS_PER_SECOND = 10
    RATE_LIMIT_AFTER_ERRORS = 10
    RANDOM_SLEEP_AFTER_REQUESTS = 50

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, 
                 concurrency: int = DEFAULT_CONCURRENCY, 
                 timeout: int = DEFAULT_TIMEOUT,
                 requests_per_second: int = DEFAULT_REQUESTS_PER_SECOND,
                 debug: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.concurrency = concurrency
        self.timeout = timeout
        self.requests_per_second = requests_per_second
        self.debug = debug
        self._findings: List[Finding] = []
        self._lock = threading.Lock()
        self._last_request_time = 0
        self._response_analyzers = [
            self._too_permissive_analyzer,
            self._security_header_analyzer,
            self._cors_analyzer,
            self._reflected_ssrf_analyzer,
            self._blind_ssrf_analyzer,
            self._server_error_analyzer,
            self._verbose_error_analyzer,
            self._http_method_analyzer
        ]
        self._error_count = 0
        self._request_counter = 0
        self._tested_payloads = set()

    def _log(self, message: str, level: str = "info"):
        if self.debug or level in ("error", "warn"):
            prefix = {
                "debug": "[DEBUG]",
                "info": "[INFO]",
                "warn": "[WARNING]",
                "error": "[ERROR]"
            }.get(level, "[INFO]")
            print(f"{prefix} {message}")

    @classmethod
    def endpoints_from_swagger(cls, swagger_path: str) -> List[Endpoint]:
        try:
            spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
            server = spec.get("servers", [{}])[0].get("url", "")
            eps: List[Endpoint] = []
            
            for path, item in spec.get("paths", {}).items():
                for method in ("get", "post", "put", "patch", "delete", "options", "head", "trace"):
                    if method in item:
                        eps.append({
                            "base": server,
                            "path": path,
                            "method": method.upper(),
                            "operationId": item[method].get("operationId", ""),
                            "parameters": item[method].get("parameters", [])
                        })
            return eps
        except Exception as e:
            raise ValueError(f"Failed to parse Swagger file: {str(e)}")

    def _default_payloads(self) -> Iterable[str]:
        base = [
            "http://127.0.0.1/", 
            "http://localhost/", 
            "http://0.0.0.0/",
            "http://169.254.169.254/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://metadata.azure.microsoft.com/",  # Azure metadata
            "http://metadata.nomadproject.com/"  # Nomad metadata
        ]
        
        fancy = [
            "http://127.0.0.1@evil.com/",
            "http://evil.com@127.0.0.1/",
            "http://127%2e0%2e0%2e1/",
            "http://127-0-0-1/",
            "http://[::1]/",  # IPv6 localhost
            "http://2130706433/",  # Decimal IP
            "http://0x7f000001/",  # Hex IP
            "http://127.1/",  # Shortened IP
            "file:///etc/passwd",
            "ftp://evil.com",
            "ldap://evil.com",
            "gopher://evil.com:70/_test",
            "dict://evil.com:1337/",
            "sftp://evil.com",
            "tftp://evil.com",
            "///etc/passwd",
            "../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd"
        ]
        
        all_payloads = base + fancy
        random.shuffle(all_payloads)
        return all_payloads

    def _build_finding(
        self,
        endpoint: Endpoint,
        payload: str,
        response: requests.Response,
        duration: float,
        description: str,
        severity: str
    ) -> Finding:
        return {
            "name":           f"{endpoint['method']} {endpoint['path']}",
            "endpoint":       f"{endpoint['method']} {endpoint['path']}",
            "operation_id":   endpoint.get("operationId", ""),
            "payload":        payload,
            "status_code":    response.status_code,
            "response_time":  duration,
            "description":    description,
            "severity":       severity,

            # -- response context ------------------------------------------
            "response_headers": _headers_to_list(response.raw.headers),
            "response_body":    response.text[:2048] if response.text else "",
            "response_body_sample": response.text[:500] if response.text else None,
            "response_cookies": response.cookies.get_dict(),

            # -- request context -------------------------------------------
            "request_headers": _headers_to_list(response.request.headers)
                            if response.request else [],
            "request_body":    getattr(response.request, "body", None)
                            if response.request else None,
            "request_cookies": self.session.cookies.get_dict(),

            # -- meta ------------------------------------------------------
            "timestamp": datetime.now().isoformat(),
        }


    def _enforce_rate_limit(self):
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < 1.0 / self.requests_per_second:
            sleep_time = (1.0 / self.requests_per_second) - elapsed
            self._log(f"Rate limiting: sleeping for {sleep_time:.2f}s", "debug")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _is_cloud_service(self) -> bool:
        """Check if target has cloud metadata endpoints"""
        test_url = urljoin(self.base_url, "/latest/meta-data/")
        try:
            resp = self.session.get(test_url, timeout=2)
            return resp.status_code < 400
        except:
            return False

    def _is_real_ssrf(self, response, payload) -> bool:
        """Advanced verification if SSRF actually occurred"""
        # 1. Check for unusual response times
        if response.elapsed.total_seconds() > 3.0:
            return True
            
        # 2. Check for typical SSRF response headers
        ssrf_headers = {"Server", "Via", "X-Azure-Ref", "X-Amz-Cf-Id"}
        if any(h in response.headers for h in ssrf_headers):
            return True
            
        # 3. Content analysis
        body = response.text.lower()
        if any(p in body for p in ["connection refused", "could not connect", "internal service"]):
            return True
            
        return False

    def _test_single_endpoint(self, ep: Endpoint):
        try:
            self._log(f"\nTesting {ep['method']} {ep['path']}", "info")
            full_url = urljoin(ep.get("base") or self.base_url, ep["path"].lstrip("/"))
            
            # First do a normal request to check baseline
            try:
                self._enforce_rate_limit()
                baseline_resp = self.session.request(
                    ep["method"], 
                    full_url, 
                    timeout=self.timeout
                )
                self._log(f"Baseline response: {baseline_resp.status_code}", "debug")
            except requests.RequestException as e:
                self._log(f"Baseline request failed: {str(e)}", "error")
                return
                
            # Test with payloads
            for payload in list(self._default_payloads()):
                if payload in self._tested_payloads:
                    continue
                self._tested_payloads.add(payload)
                
                # Skip cloud metadata checks if target isn't a cloud service
                if any(cloud in payload for cloud in ["169.254.169.254", "metadata"]) and not self._is_cloud_service():
                    continue
                
                self._log(f"Trying payload: {payload}", "debug")
                
                # JSON SSRF for POST/PUT/PATCH
                if ep["method"] in ["POST", "PUT", "PATCH"]:
                    json_payload = {"url": payload, "target": payload}
                    try:
                        self._enforce_rate_limit()
                        start = time.time()
                        resp = self.session.request(
                            ep["method"], 
                            full_url, 
                            json=json_payload, 
                            timeout=self.timeout
                        )
                        dur = time.time() - start
                        self._request_counter += 1

                        for analyzer in self._response_analyzers:
                            finding = analyzer(ep, str(json_payload), resp, dur)
                            if finding:
                                self._record_finding(finding)
                    except requests.RequestException as e:
                        self._error_count += 1
                        self._log(f"JSON request failed: {str(e)}", "error")
                        continue

                # Query param SSRF testing
                ssrf_params = ["q", "url", "uri", "path", "next", "redirect", "return", "returnUrl"]
                for param in ssrf_params:
                    crafted_url = full_url + f"?{param}={quote_plus(payload)}"
                    try:
                        self._enforce_rate_limit()
                        start = time.time()
                        resp = self.session.request(
                            ep["method"], 
                            crafted_url, 
                            timeout=self.timeout, 
                            allow_redirects=True
                        )
                        dur = time.time() - start
                        self._request_counter += 1

                        for analyzer in self._response_analyzers:
                            finding = analyzer(ep, payload, resp, dur)
                            if finding:
                                self._record_finding(finding)

                        if self._request_counter % self.RANDOM_SLEEP_AFTER_REQUESTS == 0:
                            sleep_time = random.uniform(0.1, 0.3)
                            self._log(f"Random sleep: {sleep_time:.2f}s", "debug")
                            time.sleep(sleep_time)

                    except requests.RequestException as e:
                        self._error_count += 1
                        self._log(f"Query param request failed: {str(e)}", "error")
                        if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                            self._log("Too many errors, sleeping for 1s", "warn")
                            time.sleep(1)
                            self._error_count = 0
                        continue

        except Exception as e:
            self._log(f"Unexpected error testing endpoint: {str(e)}", "error")
            raise

    # Improved analyzers
    def _too_permissive_analyzer(self, ep, payload, resp, dur):
        if resp.status_code == 200 and any(ip in payload for ip in ["127.0.0.1", "localhost"]):
            if self._is_real_ssrf(resp, payload):
                return self._build_finding(
                    ep, payload, resp, dur, 
                    "Probable SSRF - Local network behavior detected", 
                    "High"
                )

    def _reflected_ssrf_analyzer(self, ep, payload, resp, dur):
        body_lower = resp.text.lower()
        
        sensitive_patterns = {
            r"aws-metadata": "AWS metadata exposure",
            r"gcp-metadata": "GCP metadata exposure",
            r"azure-metadata": "Azure metadata exposure",
            r"local(file|host|net)": "Local system access"
        }
        
        for pattern, description in sensitive_patterns.items():
            if re.search(pattern, body_lower):
                # Ignore reflections in error messages
                if not re.search(r"(invalid|illegal|not allowed).*" + pattern, body_lower):
                    return self._build_finding(
                        ep, payload, resp, dur,
                        f"Reflected SSRF pattern: {description}",
                        "High"
                    )

    def _blind_ssrf_analyzer(self, ep, payload, resp, dur):
        if resp.status_code == 504 or "timeout" in resp.text.lower():
            if dur > 5.0:  # Only consider real timeouts
                return self._build_finding(
                    ep, payload, resp, dur, 
                    "Possible blind SSRF (timeout detected)", 
                    "Medium"
                )

    def _security_header_analyzer(self, ep, payload, resp, dur):
        headers = resp.headers
        findings = []
        
        required_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": None,
            "Referrer-Policy": "no-referrer"
        }
        
        for header, expected_value in required_headers.items():
            if header not in headers:
                findings.append(f"Missing security header: {header}")
            elif expected_value and headers[header].lower() != expected_value.lower():
                findings.append(f"Insecure {header} value: {headers[header]}")
        
        insecure_headers = {
            "Server": "Server header exposes technology",
            "X-Powered-By": "Exposes technology stack",
            "X-AspNet-Version": "Exposes ASP.NET version",
            "X-Runtime": "Exposes backend runtime"
        }
        
        for header, description in insecure_headers.items():
            if header in headers:
                findings.append(f"{description}: {headers[header]}")
        
        if findings:
            return self._build_finding(
                ep, payload, resp, dur, 
                " | ".join(findings), 
                "Medium"
            )

    def _cors_analyzer(self, ep, payload, resp, dur):
        headers = resp.headers
        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] == "*":
                return self._build_finding(
                    ep, payload, resp, dur,
                    "Overly permissive CORS policy (Allow-Origin: *)",
                    "High"
                )
            
            if ("Access-Control-Allow-Credentials" in headers and 
                headers["Access-Control-Allow-Credentials"].lower() == "true" and
                headers["Access-Control-Allow-Origin"] == "*"):
                return self._build_finding(
                    ep, payload, resp, dur,
                    "Insecure CORS: Credentials allowed with wildcard origin",
                    "Critical"
                )

    def _server_error_analyzer(self, ep, payload, resp, dur):
        if str(resp.status_code).startswith("5"):
            return self._build_finding(
                ep, payload, resp, dur, 
                f"Unexpected server error ({resp.status_code})", 
                "Medium"
            )

    def _verbose_error_analyzer(self, ep, payload, resp, dur):
        error_patterns = [
            r"<b>.*error</b>",
            r"stack trace:",
            r"at \w+\.\w+",
            r"line \d+",
            r"exception:",
            r"sql.*error",
            r"syntax error",
            r"database error"
        ]
        
        body = resp.text.lower()
        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return self._build_finding(
                    ep, payload, resp, dur, 
                    "Verbose error message detected", 
                    "Medium"
                )

    def _http_method_analyzer(self, ep, payload, resp, dur):
        insecure_methods = {
            "TRACE": "Cross-Site Tracing vulnerability",
            "OPTIONS": "Overly revealing options",
            "PUT": "Possible file upload",
            "DELETE": "Data deletion risk"
        }
        
        if ep["method"] in insecure_methods and resp.status_code == 200:
            if "Authorization" not in ep.get("parameters", []):
                return self._build_finding(
                    ep, payload, resp, dur,
                    f"Potentially dangerous HTTP method {ep['method']} enabled without auth",
                    "Medium"
                )

    def _record_finding(self, finding: Finding) -> None:
        with self._lock:
            key = (finding["endpoint"], finding["description"])
            self._finding_count = getattr(self, "_finding_count", {})
            self._finding_count[key] = self._finding_count.get(key, 0) + 1

            #  Maximaal 3 findings per groep
            if self._finding_count[key] > 3:
                return

            duplicate = any(
                f['endpoint'] == finding['endpoint'] and 
                f['description'] == finding['description'] and
                f['status_code'] == finding['status_code']
                for f in self._findings
            )

            if not duplicate:
                self._findings.append(finding)
                self._log(f"Found issue: {finding['description']}", "info")


    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        self._log(f"Starting audit of {len(endpoints)} endpoints", "info")
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            for _ in as_completed(futures):
                pass
        self._log(f"Audit complete. Found {len(self._findings)} issues", "info")
        return self._findings

    def generate_report(self, fmt: str = "markdown") -> str:
        return ReportGenerator(
            issues=self._findings,
            scanner="Enhanced Misconfiguration Auditor (API08)",
            base_url=self.base_url
        ).generate_markdown() if fmt == "markdown" else ReportGenerator(
            issues=self._findings,
            scanner="Enhanced Misconfiguration Auditor (API08)",
            base_url=self.base_url
        ).generate_json()
        
    def save_report(self, path: str, fmt: str = "markdown"):
        ReportGenerator(
            self._findings, 
            scanner="Enhanced Misconfiguration Auditor (API08)", 
            base_url=self.base_url
        ).save(path, fmt=fmt)
