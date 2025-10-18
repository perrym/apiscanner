##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
                                
from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

import requests
from tqdm import tqdm

from report_utils import ReportGenerator

try:
    from openapi_universal import (
        iter_operations as oas_iter_ops,
        build_request as oas_build_request,
        SecurityConfig as OASSecurityConfig,
    )
except Exception:
    oas_iter_ops = None
    oas_build_request = None
    OASSecurityConfig = None


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
        *args,
        base_url: Optional[str] = None,
        session: Optional[requests.Session] = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        requests_per_second: int = DEFAULT_REQUESTS_PER_SECOND,
        debug: bool = False,
        show_progress: bool = True,
        swagger_spec: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        if (session is None or base_url is None) and len(args) >= 2:
            if isinstance(args[1], requests.Session):
                base_url, session = args[0], args[1]
            elif isinstance(args[0], requests.Session):
                session, base_url = args[0], args[1]

        if not session or not base_url:
            raise ValueError("session and base_url are required")
        if "://" not in str(base_url):
            base_url = "http://" + str(base_url)

        self.base_url = str(base_url).rstrip("/")
        self.session = session
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

        self._reported_header_hosts  = set()

        self._response_analyzers = [
            self._security_header_analyzer,
            self._cors_analyzer,
            self._server_error_analyzer,
            self._verbose_error_analyzer,
            self._http_method_analyzer,
        ]

        self.spec: Dict[str, Any] = swagger_spec or kwargs.get("spec") or {}

                                                                               
    # ----------------------- Funtion endpoints_from_spec_universal ----------------------------#
    def endpoints_from_spec_universal(self) -> List[Endpoint]:
        if not self.spec or not (oas_iter_ops and oas_build_request):
            return []
        endpoints: List[Endpoint] = []
        sec = OASSecurityConfig() if OASSecurityConfig else None
        try:
            for op in oas_iter_ops(self.spec):
                req = oas_build_request(self.spec, self.base_url + "/", op, sec)
                endpoints.append({
                    "base": self.base_url,
                    "path": op.get("path", ""),
                    "method": (req.get("method") or "GET").upper(),
                    "operationId": op.get("operationId", ""),
                    "parameters": op.get("parameters", []),
                })
        except Exception:
            return []
        return endpoints

    # ----------------------- Funtion endpoints_from_swagger ----------------------------#
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

    # ----------------------- Funtion _build_finding ----------------------------#
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

                                                                               
    # ----------------------- Funtion _test_single_endpoint ----------------------------#
    def _test_single_endpoint(self, ep: Endpoint, pbar: Optional[tqdm] = None) -> None:
        try:
            method = ep["method"]
            path   = ep["path"]
            base   = ep.get("base") or self.base_url
            full_url = urljoin(base, path.lstrip("/"))
            if "{" in path and "}" in path:
                path = re.sub(r"\{[^}]+\}", "123", path)
                full_url = urljoin(base, path.lstrip("/"))
            host_key = urlparse(full_url).netloc.lower()
            if self.debug:
                self._tw(f"Testing {method} {path}", level="debug")
            seq = []
            if method != "HEAD":
                seq.append("HEAD")
            if method not in ("HEAD", "OPTIONS"):
                seq.append("OPTIONS")
            seq.append(method)
            seen = set()
            seq = [m for m in seq if not (m in seen or seen.add(m))]

            with self._lock:
                host_already_reported = (host_key in self._reported_header_hosts)

            for m in seq:
                try:
                    self._enforce_rate_limit()
                    start = time.time()
                    headers = dict(getattr(self.session, "headers", {}) or {})
                    if m in ("HEAD", "OPTIONS"):
                        headers.pop("Authorization", None)
                    resp = self.session.request(m, full_url, headers=headers, timeout=self.timeout, allow_redirects=True)
                    dur = time.time() - start
                    self._request_counter += 1
                except requests.RequestException as e:
                    self._error_count += 1
                    self._tw(f"[ERROR] {m} failed for {method} {path}: {e}", "error")
                    continue

                if not host_already_reported:
                    f = self._security_header_analyzer(ep, f"<{m}>", resp, dur)
                    if f:
                        self._record_finding(f)
                    with self._lock:
                        self._reported_header_hosts.add(host_key)
                        host_already_reported = True

                for analyzer in self._response_analyzers:
                    if host_already_reported and analyzer == self._security_header_analyzer:
                        continue
                    try:
                        f = analyzer(ep, f"<{m}>", resp, dur)
                        if f:
                            self._record_finding(f)
                    except Exception as ex:
                        self._tw(f"[ERROR] Analyzer {analyzer.__name__} on {m} {path}: {ex}", "error")

            if method not in ("HEAD", "OPTIONS"):
                probe_names = getattr(self, "PARAM_PROBE_NAMES", [
                    "probe", "debug", "verbose", "pretty", "format", "fields",
                    "sort", "expand", "include", "lang", "locale", "cache",
                    "nocache", "trace", "test"
                ])
                probe_vals = getattr(self, "PARAM_PROBE_VALUES", ["1", "true", "*"])

                for name in probe_names:
                    for val in probe_vals:
                        try:
                            self._enforce_rate_limit()
                            u = urlparse(full_url)
                            q = dict(parse_qsl(u.query, keep_blank_values=True))
                            q[name] = val
                            crafted = u._replace(query=urlencode(q, doseq=True)).geturl()
                            start = time.time()
                            resp = self.session.request(method, crafted, timeout=self.timeout, allow_redirects=True)
                            dur = time.time() - start
                            self._request_counter += 1

                            for analyzer in self._response_analyzers:
                                if host_already_reported and analyzer == self._security_header_analyzer:
                                    continue
                                f = analyzer(ep, f"{name}={val}", resp, dur)
                                if f:
                                    self._record_finding(f)

                            if self._request_counter % self.RANDOM_SLEEP_AFTER_REQUESTS == 0:
                                time.sleep(random.uniform(0.1, 0.3))

                        except requests.RequestException as e:
                            self._error_count += 1
                            self._tw(f"[ERROR] Param probe failed ({name}={val}) on {method} {path}: {e}", "error")
                            if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                                self._tw("[WARN] Many errors, cooling down 1s", "warn")
                                time.sleep(1.0)
                                self._error_count = 0

        except Exception as e:
            self._tw(f"[ERROR] Unexpected test error at {ep.get('method')} {ep.get('path')}: {e}", "error")
        finally:
            if pbar:
                pbar.update(1)

                                                                               
    # ----------------------- Funtion _security_header_analyzer ----------------------------#
    def _security_header_analyzer(self, ep, payload, resp, dur):
                                                                
        if self._is_api_json(resp):
            return None

                                                   
        path = (ep.get("path") if isinstance(ep, dict) else str(ep) or "").lower()
        if re.search(r"/auth|/login|/signup|check-otp|verify-email-token", path):
            return None

                                                     
        if str(self.base_url).lower().startswith("http://"):
            return None

        hdrs = resp.headers or {}
        missing = []
        low_keys = {k.lower(): v for k, v in hdrs.items()}

        if "strict-transport-security" not in low_keys:
            missing.append("HSTS")
        if str(hdrs.get("X-Content-Type-Options", "")).lower() != "nosniff":
            missing.append("X-Content-Type-Options")
        if "X-Frame-Options" not in hdrs:
            missing.append("X-Frame-Options")
        if "Content-Security-Policy" not in hdrs:
            missing.append("CSP")

        if not missing:
            return None

        return self._build_finding(
            ep, payload, resp, dur,
            "Missing: " + ", ".join(missing),
            "Low",
        )

    # ----------------------- Funtion _cors_analyzer ----------------------------#
    def _cors_analyzer(self, ep, payload, resp, dur):
        hdrs = resp.headers or {}
        acao = (hdrs.get("Access-Control-Allow-Origin", "") or "").strip()
        acac = (hdrs.get("Access-Control-Allow-Credentials", "") or "").strip().lower()
        if not acao:
            return None
        method = getattr(getattr(resp, "request", None), "method", "GET").upper()

        if acao == "*" and acac == "true":
            sev = "High"
        elif acao == "*" and acac != "true":
            sev = "Info" if method == "OPTIONS" else "Low"
        else:
            sev = "Info"

        desc = f"ACAO={acao}, ACAC={acac or 'false'}"
        return self._build_finding(ep, payload, resp, dur, desc, sev)

    # ----------------------- Funtion _server_error_analyzer ----------------------------#
    def _server_error_analyzer(self, ep, payload, resp, dur):
        if 500 <= resp.status_code < 600:
            return self._build_finding(ep, payload, resp, dur, f"{resp.status_code} on baseline/probe", "Medium")

    # ----------------------- Funtion _verbose_error_analyzer ----------------------------#
    def _verbose_error_analyzer(self, ep, payload, resp, dur):
        body = (resp.text or "")
        low = body.lower()
        markers = ("exception", "stack trace", "traceback", "sqlstate", "nullreferenceexception")
        if any(m in low for m in markers):
            return self._build_finding(ep, payload, resp, dur, "Response body contains implementation stack/error markers", "High")

    def _http_method_analyzer(self, ep, payload, resp, dur):
        return None

                                                                               
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

    
    def _title_for(self, ep: Dict[str, Any], resp: requests.Response) -> str:
        ep_method = str(ep.get("method", "GET")).upper()
        path = ep.get("path") or ""
        return f"{ep_method} {path}"

            
    # ----------------------- Funtion _filter_issues ----------------------------#
    def _filter_issues(self) -> list[dict]:
        cleaned, seen = ([], set())

        NOISE_4XX = {404, 405}
        NOISE_4XX_BODY_MARKERS = (
            "not found", "no static resource", "method not allowed",
            "bad request", "invalid request", "unexpected end of json input",
            "missing", "invalid parameter", "validation failed"
        )

        NOISE_5XX_BODY_MARKERS = (
            "current request is not a multipart request",
            "missingservletrequestpartexception",
            "no multipart boundary",
            "unsupported media type",
            "required request part",
            "illegalargumentexception: content-type",
            "whitelabel error page",
        )

        VERBOSE_5XX_KEEP = (
            "exception", "stack trace", "traceback", "sqlstate",
            "nullreferenceexception", "at com.", "internal server error"
        )

        items = getattr(self, "_findings", []) or getattr(self, "issues", [])
        for i in items:
            body = (i.get("response_body") or "")
            body_low = body.lower()
            payload = str(i.get("payload") or "").lower()
            try:
                status = int(i.get("status_code") or 0)
            except Exception:
                status = 0

                                                
            if status in NOISE_4XX and not any(m in body_low for m in NOISE_4XX_BODY_MARKERS):
                continue

                                    
            if status == 400 and any(m in body_low for m in NOISE_4XX_BODY_MARKERS):
                continue

                                                                                 
            if status >= 500:
                if payload in ("<head>", "<options>"):
                    continue
                if any(m in body_low for m in NOISE_5XX_BODY_MARKERS):
                    continue
                if not any(m in body_low for m in VERBOSE_5XX_KEEP):
                    i["severity"] = "Info"

            key = (
                i.get("endpoint"),
                i.get("issue"),
                str(status),
                str(i.get("description") or "")[:120],
            )
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(i)

                                                              
        if hasattr(self, "_findings"):
            self._findings = cleaned
            return self._findings
        self.issues = cleaned
        return self.issues
     
   
    # ----------------------- Funtion test_endpoints ----------------------------#
    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        if not endpoints and getattr(self, "spec", None):
            endpoints = self.endpoints_from_spec_universal()
        if not endpoints:
            return []

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            if self.show_progress:
                for _ in tqdm(as_completed(futures), total=len(futures), desc="API8 misconfig endpoints", unit="endpoint", dynamic_ncols=True):
                    pass
            else:
                for _ in as_completed(futures):
                    pass

        return self._filter_issues()

    # ----------------------- Funtion generate_report ----------------------------#
    def generate_report(self, fmt: str = "markdown") -> str:
        scanner = "Enhanced Misconfiguration Auditor (API08)"
        filtered = self._filter_findings()
        gen = ReportGenerator(filtered, scanner=scanner, base_url=self.base_url)
        return gen.generate_markdown() if fmt == "markdown" else gen.generate_json()

    # ----------------------- Funtion save_report ----------------------------#
    def save_report(self, path: str, fmt: str = "markdown"):
        scanner = "Enhanced Misconfiguration Auditor (API08)"
        filtered = self._filter_findings()
        ReportGenerator(filtered, scanner=scanner, base_url=self.base_url).save(path, fmt=fmt)
