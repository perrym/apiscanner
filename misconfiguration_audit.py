##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
from __future__ import annotations
import json
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, quote_plus, urlparse

import requests
from tqdm import tqdm

from report_utils import ReportGenerator

Endpoint = Dict[str, Any]
Finding  = Dict[str, Any]

def _headers_to_list(hdrs):
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    try:
        return list(hdrs.items())
    except Exception:
        return []

class MisconfigurationAuditorPro:
    DEFAULT_CONCURRENCY = 12
    DEFAULT_TIMEOUT = 8
    DEFAULT_REQUESTS_PER_SECOND = 10
    RATE_LIMIT_AFTER_ERRORS = 10
    RANDOM_SLEEP_AFTER_REQUESTS = 50

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        requests_per_second: int = DEFAULT_REQUESTS_PER_SECOND,
        debug: bool = False,
        show_progress: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.concurrency = concurrency
        self.timeout = timeout
        self.requests_per_second = requests_per_second
        self.debug = debug
        self.show_progress = show_progress

        self._findings: List[Finding] = []
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._error_count = 0
        self._request_counter = 0
        self._tested_payloads = set()
        self._finding_count: Dict[Tuple[str, str], int] = {}

        # Dedup sets
        self._reported_header_issues = set()   # per endpoint
        self._reported_header_hosts  = set()   # per host

        self._response_analyzers = [
            self._too_permissive_analyzer,
            self._security_header_analyzer,
            self._cors_analyzer,
            self._reflected_ssrf_analyzer,
            self._blind_ssrf_analyzer,
            self._server_error_analyzer,
            self._verbose_error_analyzer,
            self._http_method_analyzer,
        ]

    # -------------------------- helpers / logging -------------------------- #
    def _tw(self, msg: str, level: str = "info"):
        if self.show_progress:
            if self.debug or level in ("error", "warn"):
                tqdm.write(msg)
        else:
            if self.debug or level in ("error", "warn"):
                print(msg)

    @classmethod
    def endpoints_from_swagger(cls, swagger_path: str) -> List[Endpoint]:
        try:
            spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
            server = spec.get("servers", [{}])[0].get("url", "")
            eps: List[Endpoint] = []
            for path, item in (spec.get("paths") or {}).items():
                for method in ("get", "post", "put", "patch", "delete", "options", "head", "trace"):
                    if method in item:
                        meta = item[method] or {}
                        params = []
                        if isinstance(item.get("parameters"), list):
                            params.extend(item["parameters"])
                        if isinstance(meta.get("parameters"), list):
                            params.extend(meta["parameters"])
                        eps.append({
                            "base": server,
                            "path": path,
                            "method": method.upper(),
                            "operationId": meta.get("operationId", ""),
                            "parameters": params,
                        })
            return eps
        except Exception as e:
            raise ValueError(f"Failed to parse Swagger file: {str(e)}")

    def _default_payloads(self) -> Iterable[str]:
        base = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://169.254.169.254/",
            "http://metadata.google.internal/",
            "http://metadata.azure.microsoft.com/",
            "http://metadata.nomadproject.com/",
        ]
        fancy = [
            "http://127.0.0.1@evil.com/",
            "http://evil.com@127.0.0.1/",
            "http://127%2e0%2e0%2e1/",
            "http://127-0-0-1/",
            "http://[::1]/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://127.1/",
            "file:///etc/passwd",
            "ftp://evil.com",
            "ldap://evil.com",
            "gopher://evil.com:70/_test",
            "dict://evil.com:1337/",
            "sftp://evil.com",
            "tftp://evil.com",
            "///etc/passwd",
            "../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
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
        severity: str,
    ) -> Finding:
        return {
            "name":         f"{endpoint['method']} {endpoint['path']}",
            "endpoint":     f"{endpoint['method']} {endpoint['path']}",
            "operation_id": endpoint.get("operationId", ""),
            "payload":      payload,
            "status_code":  response.status_code,
            "response_time": duration,
            "description":  description,
            "severity":     severity,
            "response_headers": _headers_to_list(getattr(response.raw, "headers", {})) or _headers_to_list(response.headers),
            "response_body":    (response.text[:2048] if getattr(response, "text", None) else ""),
            "response_body_sample": (response.text[:500] if getattr(response, "text", None) else None),
            "response_cookies": response.cookies.get_dict(),
            "request_headers":  _headers_to_list(getattr(getattr(response, "request", None), "headers", {})) if getattr(response, "request", None) else [],
            "request_body":     getattr(getattr(response, "request", None), "body", None),
            "request_cookies":  self.session.cookies.get_dict(),
            "timestamp":        datetime.now().isoformat(),
        }

    def _enforce_rate_limit(self):
        now = time.time()
        elapsed = now - self._last_request_time
        gap = 1.0 / float(self.requests_per_second)
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last_request_time = time.time()

    # ------------------------------ single endpoint ------------------------ #
    def _test_single_endpoint(self, ep: Endpoint, pbar: Optional[tqdm] = None):
        """
        Performs misconfiguration/SSRF-related checks on a single endpoint.
        - Quiet UI: nested tqdm bars only with --debug
        - Rate limiting per request
        - Deduplicate 'missing security headers' per host (once per host)
        """
        # Reset tested payloads for each endpoint
        tested_payloads = set()
        
        try:
            method = ep["method"]
            path   = ep["path"]
            base   = ep.get("base") or self.base_url
            full_url = urljoin(base, path.lstrip("/"))
            host_key = urlparse(full_url).netloc.lower()

            # --- rustige logging ---
            self._tw(f"Testing {method} {path}", level="debug")

            # --- baseline request ---
            try:
                self._enforce_rate_limit()
                start = time.time()
                baseline_resp = self.session.request(method, full_url, timeout=self.timeout, allow_redirects=True)
                dur = time.time() - start
                self._request_counter += 1
            except requests.RequestException as e:
                self._error_count += 1
                self._tw(f"[ERROR] Baseline failed for {method} {path}: {e}", "error")
                if pbar:
                    pbar.update(1)
                return

            # --- 1x per host: security-header analyse ---
            with self._lock:
                # Check if we've already reported header issues for this host
                host_already_reported = (host_key in self._reported_header_hosts)
                
            if not host_already_reported:
                finding = self._security_header_analyzer(ep, "<baseline>", baseline_resp, dur)
                if finding:
                    self._record_finding(finding)
                    with self._lock:
                        # Mark this host as reported so we don't check headers again
                        self._reported_header_hosts.add(host_key)
                        # Skip header checks for all future requests to this host
                        host_already_reported = True

            # --- payloads / params (nested tqdm alleen met --debug) ---
            show_inner = (self.show_progress and self.debug)

            payloads = list(self._default_payloads())
            pbar_payload = tqdm(
                payloads, desc="payloads", unit="payload",
                leave=False, disable=not show_inner, position=1, dynamic_ncols=True
            ) if show_inner else payloads

            for payload in pbar_payload:
                # local deduplication of payloads
                if payload in tested_payloads:
                    continue
                tested_payloads.add(payload)

                # write methods: JSON body with url/target
                if method in ("POST", "PUT", "PATCH"):
                    json_payload = {"url": payload, "target": payload}
                    try:
                        self._enforce_rate_limit()
                        start = time.time()
                        resp = self.session.request(method, full_url, json=json_payload, timeout=self.timeout, allow_redirects=True)
                        dur = time.time() - start
                        self._request_counter += 1

                        # run analyzers (skip security header analyzer if host already reported)
                        for analyzer in self._response_analyzers:
                            # Skip security header checks if we've already reported issues for this host
                            if host_already_reported and analyzer == self._security_header_analyzer:
                                continue
                            f = analyzer(ep, str(json_payload), resp, dur)
                            if f:
                                self._record_finding(f)
                    except requests.RequestException as e:
                        self._error_count += 1
                        self._tw(f"[ERROR] JSON request failed: {e}", "error")

                # query-param variants (typical SSRF/misconfig keywords)
                ssrf_params = ["q", "url", "uri", "path", "next", "redirect", "return", "returnUrl"]
                pbar_params = tqdm(
                    ssrf_params, desc="params", unit="param",
                    leave=False, disable=not show_inner, position=2, dynamic_ncols=True
                ) if show_inner else ssrf_params

                for param in pbar_params:
                    crafted = f"{full_url}?{param}={quote_plus(payload)}"
                    try:
                        self._enforce_rate_limit()
                        start = time.time()
                        resp = self.session.request(method, crafted, timeout=self.timeout, allow_redirects=True)
                        dur = time.time() - start
                        self._request_counter += 1

                        # run analyzers (skip security header analyzer if host already reported)
                        for analyzer in self._response_analyzers:
                            # Skip security header checks if we've already reported issues for this host
                            if host_already_reported and analyzer == self._security_header_analyzer:
                                continue
                            f = analyzer(ep, payload, resp, dur)
                            if f:
                                self._record_finding(f)

                        # simple jitter to keep output/ratelimit stable
                        if self._request_counter % self.RANDOM_SLEEP_AFTER_REQUESTS == 0:
                            time.sleep(random.uniform(0.1, 0.3))

                    except requests.RequestException as e:
                        self._error_count += 1
                        self._tw(f"[ERROR] Query request failed: {e}", "error")
                        if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                            self._tw("[WARN] Many errors, cooling down 1s", "warn")
                            time.sleep(1.0)
                            self._error_count = 0

        except Exception as e:
            self._tw(f"[ERROR] Unexpected test error at {ep.get('method')} {ep.get('path')}: {e}", "error")
        finally:
            if pbar:
                pbar.update(1)
        # ------------------------------ analyzers ------------------------------ #
    def _too_permissive_analyzer(self, ep, payload, resp, dur):
        if resp.status_code == 200 and any(lp in (payload or "").lower() for lp in ("127.0.0.1", "localhost")):
            return self._build_finding(ep, payload, resp, dur, "Probable SSRF - Local network behavior detected", "High")

    def _reflected_ssrf_analyzer(self, ep, payload, resp, dur):
        body_lower = (resp.text or "").lower()
        sensitive_patterns = {
            r"aws-metadata": "AWS metadata exposure",
            r"gcp-metadata": "GCP metadata exposure",
            r"azure-metadata": "Azure metadata exposure",
            r"local(file|host|net)": "Local system access",
        }
        for pattern, description in sensitive_patterns.items():
            if re.search(pattern, body_lower) and not re.search(r"(invalid|illegal|not allowed).*" + pattern, body_lower):
                return self._build_finding(ep, payload, resp, dur, f"Reflected SSRF pattern: {description}", "High")

    def _blind_ssrf_analyzer(self, ep, payload, resp, dur):
        if resp.status_code == 504 or "timeout" in (resp.text or "").lower():
            if dur > 5.0:
                return self._build_finding(ep, payload, resp, dur, "Possible blind SSRF (timeout detected)", "Medium")

    def _security_header_analyzer(self, ep, payload, resp, dur):
        headers = resp.headers
        findings = []
        required_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": None,
            "Referrer-Policy": "no-referrer",
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
            "X-Runtime": "Exposes backend runtime",
        }
        for header, description in insecure_headers.items():
            if header in headers:
                findings.append(f"{description}: {headers[header]}")
        if findings:
            return self._build_finding(ep, payload, resp, dur, " | ".join(findings), "Medium")

    def _cors_analyzer(self, ep, payload, resp, dur):
        headers = resp.headers
        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] == "*":
                return self._build_finding(ep, payload, resp, dur, "Overly permissive CORS policy (Allow-Origin: *)", "High")
            if (headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                and headers["Access-Control-Allow-Origin"] == "*"):
                return self._build_finding(ep, payload, resp, dur, "Insecure CORS: Credentials allowed with wildcard origin", "Critical")

    def _server_error_analyzer(self, ep, payload, resp, dur):
        if str(resp.status_code).startswith("5"):
            return self._build_finding(ep, payload, resp, dur, f"Unexpected server error ({resp.status_code})", "Medium")

    def _verbose_error_analyzer(self, ep, payload, resp, dur):
        error_patterns = [
            r"<b>.*error</b>",
            r"stack trace:",
            r"at \w+\.\w+",
            r"line \d+",
            r"exception:",
            r"sql.*error",
            r"syntax error",
            r"database error",
        ]
        body = (resp.text or "").lower()
        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return self._build_finding(ep, payload, resp, dur, "Verbose error message detected", "Medium")

    def _http_method_analyzer(self, ep, payload, resp, dur):
        risky = {"TRACE": "Cross-Site Tracing vulnerability", "OPTIONS": "Overly revealing options", "PUT": "Possible file upload", "DELETE": "Data deletion risk"}
        if ep["method"] in risky and resp.status_code == 200:
            # Check if there is an Authorization header param in swagger
            header_names = { (p.get("name") or "").lower()
                             for p in ep.get("parameters", []) if (p.get("in") == "header") }
            if "authorization" not in header_names:
                return self._build_finding(ep, payload, resp, dur, f"Potentially dangerous HTTP method {ep['method']} enabled without auth header", "Medium")

    # ------------------------------ record/report -------------------------- #
    def _record_finding(self, finding: Finding) -> None:
        with self._lock:
            key = (finding["endpoint"], finding["description"])
            self._finding_count[key] = self._finding_count.get(key, 0) + 1
            if self._finding_count[key] > 3:
                return
            duplicate = any(
                f['endpoint'] == finding['endpoint']
                and f['description'] == finding['description']
                and f['status_code'] == finding['status_code']
                for f in self._findings
            )
            if not duplicate:
                self._findings.append(finding)
                if self.show_progress:
                    tqdm.write(f"[ISSUE] {finding['severity']}: {finding['description']} @ {finding['endpoint']}")

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        self._tw(f"[INFO] Auditing {len(endpoints)} endpoints", "info")
        if not endpoints:
            return self._findings

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            if self.show_progress:
                for _ in tqdm(as_completed(futures), total=len(futures), desc="API8 misconfig endpoints", unit="endpoint", dynamic_ncols=True):
                    pass
            else:
                for _ in as_completed(futures):
                    pass

        self._tw(f"[INFO] Audit complete, findings: {len(self._findings)}", "info")
        return self._findings

    def generate_report(self, fmt: str = "markdown") -> str:
        scanner = "Enhanced Misconfiguration Auditor (API08)"
        gen = ReportGenerator(self._findings, scanner=scanner, base_url=self.base_url)
        return gen.generate_markdown() if fmt == "markdown" else gen.generate_json()

    def save_report(self, path: str, fmt: str = "markdown"):
        scanner = "Enhanced Misconfiguration Auditor (API08)"
        ReportGenerator(self._findings, scanner=scanner, base_url=self.base_url).save(path, fmt=fmt)
