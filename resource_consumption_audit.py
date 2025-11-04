########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the MIT License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.2  2-11--2025                              #
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

from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig as OASSecurityConfig,
)
from report_utils import ReportGenerator

logger = logging.getLogger(__name__)


def _headers_to_list(headerobj) -> List[tuple[str, str]]:
    try:
        if hasattr(headerobj, "getlist"):
            out = []
            for k in headerobj:
                for v in headerobj.getlist(k):
                    out.append((str(k), str(v)))
            return out
        return [(str(k), str(v)) for k, v in (headerobj.items() if hasattr(headerobj, "items") else [])]
    except Exception:
        return []


class ResourceConsumptionAuditor:
    def _slice_body(self, resp, limit=2048):
        try:
            return (resp.text or "")[:limit]
        except Exception:
            return ""


    # Heuristic patterns that commonly indicate functional/validation errors, not resource-consumption
    _FP_BODY_PATTERNS = re.compile(
        r"(not\s+a\s+multipart\s+request|token\s+didn'?t\s+match|no\s+documents\s+in\s+result|validation\s+error|unsupported\s+media\s+type|csrf|missing\s+required\s+parameter|boundary\s+not\s+found)",
        re.IGNORECASE,
    )

    @staticmethod
    def _looks_like_upload_path(url: str) -> bool:
        p = url.lower()
        return any(x in p for x in ["/upload", "/uploads", "/pictures", "/videos", "/media", "/file", "/files"])
    
    # ----------------------- Function __init__ ----------------------------#
    def __init__(
        self,
        session: requests.Session,
        *,
        base_url: str,
        swagger_spec: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
        thresholds: Optional[Dict[str, Any]] = None,
        show_progress: bool = True,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        if session is None:
            raise ValueError("Session is required; pass an authenticated requests.Session.")
        if not base_url or not isinstance(base_url, str):
            raise ValueError("base_url is required")

        self.session = session
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.logger = logger or logging.getLogger(__name__)
        self.spec: Dict[str, Any] = swagger_spec or {}
        self.show_progress = show_progress

                                                       
        self.thresholds: Dict[str, Any] = {
            "response_time": 2.0,                     
            "response_time_ms": 2000,                                   
            "response_size": 1_000_000,             
            "payload_kb_warn": 512,
            "payload_kb_high": 2048,
            "records_warn": 1000,
            "records_high": 10000,
            "rate_limit": 120.0,                      
            "batch_sizes": [10, 50, 100],
            "concurrent_workers": 8,
            "concurrent_requests": 100,
            "ignore_nonstress_5xx": True,
            "nonstress_5xx_max_size": 131072,
            "nonstress_5xx_max_time": 2.0,
            "skip_upload_like_endpoints_without_body": True,

        }
        if thresholds:
            self.thresholds.update(thresholds)

                                              
        self.retry = Retry(total=2, backoff_factor=0.4, status_forcelist=[429, 500, 502, 503, 504])
        self.issues: List[Dict[str, Any]] = []

                                   
    def _build_url(self, path_or_url: str) -> str:
        if not path_or_url:
            return self.base_url
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    @staticmethod
    def _format_bytes(size: int) -> str:
        units = ("B", "KB", "MB", "GB", "TB", "PB", "EB")
        s = float(size)
        for u in units:
            if s < 1024.0:
                return f"{s:.1f} {u}"
            s /= 1024.0
        return f"{s:.1f} ZB"

    def _generate_deep_nested_json(self, depth: int) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        cur = payload
        for i in range(depth):
            cur["nested"] = {}
            cur = cur["nested"]
            if i % 10 == 0:
                cur[f"key_{i}"] = "A" * 100
        return payload

    # ----------------------- Function _log_issue ----------------------------#
    def _log_issue(
        self,
        endpoint_url: str,
        issue_type: str,
        description: str,
        severity: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        data = data or {}
        status_code = int(data.get("status_code", 0))
        if 500 <= status_code < 600:
            severity = "Critical"
        elif status_code == 0 and severity == "Medium":
            severity = "High"

        entry = {
            "endpoint": endpoint_url,
            "method": data.get("method") if data else None,
            "type": issue_type,
            "description": description,
            "severity": severity,
            "status_code": status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": _headers_to_list(self.session.headers),
            "response_headers": _headers_to_list(data.get("headers") or {}),
            "response_body": data.get("body"),
            "request_body": data.get("request_body"),
            "request_cookies": getattr(self.session.cookies, "get_dict", lambda: {})(),
            "response_cookies": data.get("resp_cookies", {}),
            "data": data,
            "metrics": {
                "response_size": data.get("size"),
                "response_time": data.get("time"),
                "rpm": data.get("rpm"),
                "batch_size": data.get("batch_size"),
            }
            if data
            else None,
        }
        self.issues.append(entry)
        self.logger.info("ISSUE: %s - %s at %s", severity, issue_type, endpoint_url)

                                                                     
    # ----------------------- Function _endpoints_from_spec ----------------------------#
    def _endpoints_from_spec(self) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        try:
            sec = OASSecurityConfig()
            for op in oas_iter_ops(self.spec or {}):
                req = oas_build_request(self.spec, self.base_url, op, sec)
                headers = {k: v for k, v in (req.get("headers") or {}).items() if k.lower() != "authorization"}
                endpoints.append(
                    {
                        "method": (req["method"] or "GET").upper(),
                        "url": req["url"],
                        "headers": headers,
                        "json": req.get("json"),
                        "data": req.get("data"),
                        "parameters": {},
                    }
                )
        except Exception as e:
            self.logger.debug("Universal builder failed: %s", e)
        return endpoints

                                             
    # ----------------------- Function test_resource_consumption ----------------------------#
    def test_resource_consumption(self, endpoints: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        if endpoints is None or len(endpoints) == 0:
            if self.spec:
                endpoints = self._endpoints_from_spec()
            else:
                endpoints = []

        it = tqdm(endpoints, desc="API4 resource endpoints", unit="endpoint") if self.show_progress else endpoints
        start_count = len(self.issues)
        skip_status = {401, 403, 404, 405}

        for ep in it:
            method = (ep.get("method") or "GET").upper()
            url = self._build_url(ep.get("url") or ep.get("path", "/"))
            json_body = ep.get("json")
            data_body = ep.get("data")
            if self.thresholds.get("skip_upload_like_endpoints_without_body", True):
                if method in ("POST", "PUT", "PATCH") and (json_body is None and data_body is None) and self._looks_like_upload_path(url):
                    # Skip: very likely requires multipart/form-data or binary
                    if self.show_progress:
                        try: it.write(f"   ~ Skipped (upload endpoint without body): {url}")
                        except Exception: pass
                    continue
            headers = dict(ep.get("headers") or {})
            headers.pop("Authorization", None)

            if self.show_progress:
                try:
                    it.write(f"-> Testing {method} {url}")
                except Exception:
                    pass

            t0 = time.time()
            try:
                if method in ("POST", "PUT", "PATCH"):
                    resp = self.session.request(method, url, headers=headers, json=json_body, data=data_body, timeout=self.timeout)
                else:
                    resp = self.session.request(method, url, headers=headers, timeout=self.timeout)
                elapsed = time.time() - t0
                size = len(resp.content or b"")
                status = resp.status_code
                body_text = self._slice_body(resp, 2000)
                body_text = body_text
                content_type = str(resp.headers.get("Content-Type", "")).lower()
                nonstress = (
                    elapsed <= float(self.thresholds.get("nonstress_5xx_max_time", self.thresholds["response_time"]))
                    and size <= int(self.thresholds.get("nonstress_5xx_max_size", 131072))
                )

                if status in skip_status:
                    continue

                if status in (501, 503):
                    severity = "Medium"
                elif size > float(self.thresholds["response_size"]):
                    severity = "Critical"
                elif elapsed > float(self.thresholds["response_time"]):
                    severity = "High"
                else:
                    severity = "Info"

                triggered = False
                if 500 <= status < 600:
                    if self.thresholds.get("ignore_nonstress_5xx", True):
                        if nonstress or self._FP_BODY_PATTERNS.search(body_text):
                            # Ignore or downgrade noisy 5xx that look like validation/functional errors
                            # We'll treat it as Info only when progress is enabled, otherwise drop it
                            if self.show_progress:
                                try: it.write(f"   ~ Ignored non-stress 5xx: {status} {url}")
                                except Exception: pass
                            continue
                    sev = "Critical" if (elapsed > float(self.thresholds["response_time"]) or size > float(self.thresholds["response_size"])) else "High"
                    self._log_issue(url, "Server Error", f"Server error under load: {status}", sev, {"method": method, "status_code": status, "time": elapsed, "size": size, "headers": dict(resp.headers), "body": body_text})
                    continue
                if size > float(self.thresholds["response_size"]):
                    self._log_issue(url, "Large Response Size", f"Body: {self._format_bytes(size)}", "Critical", {"method": method, "status_code": status, "size": size, "time": elapsed, "headers": dict(resp.headers), "body": body_text})
                    triggered = True
                if elapsed > float(self.thresholds["response_time"]):
                    self._log_issue(url, "Slow Response", f"{elapsed:.2f}s", "High", {"method": method, "status_code": status, "time": elapsed, "size": size, "headers": dict(resp.headers), "body": body_text})
                    triggered = True
                if not triggered and status == 200:
                    try:
                        if not content_type.startswith("application/json"):
                            raise ValueError("skip non-JSON body for large record count check")
                        data = resp.json()
                        total_records = 0
                        if isinstance(data, list):
                            total_records = len(data)
                        elif isinstance(data, dict):
                            for v in data.values():
                                if isinstance(v, list):
                                    total_records = max(total_records, len(v))
                        warn = int(self.thresholds.get("records_warn", 1000))
                        high = int(self.thresholds.get("records_high", 10000))
                        if total_records >= high:
                            self._log_issue(url, "Large Record Set", f"{total_records} records", "High", {"method": method, "status_code": status, "records": total_records, "time": elapsed, "size": size, "headers": dict(resp.headers)})
                            triggered = True
                        elif total_records >= warn:
                            self._log_issue(url, "Large Record Set", f"{total_records} records", "Medium", {"method": method, "status_code": status, "records": total_records, "time": elapsed, "size": size, "headers": dict(resp.headers)})
                            triggered = True
                    except Exception:
                        pass
                if not triggered:
                    continue
            except requests.RequestException as exc:
                elapsed = time.time() - t0
                self._log_issue(
                    url,
                    "Request Error",
                    str(exc),
                    "Medium" if "timeout" in str(exc).lower() else "Low",
                    {"method": method, "status_code": 0, "time": elapsed},
                )

        return self.issues[start_count:]

                                                    
    # ----------------------- Function _test_large_payloads ----------------------------#
    def _test_large_payloads(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get("method", "GET") or "GET").upper().upper()
        test_cases = [
            ("small", {"limit": 10}, "Low"),
            ("medium", {"limit": 1_000}, "Low"),
            ("large", {"limit": 10_000}, "Medium"),
            ("huge", {"limit": 100_000}, "High"),
            ("massive", {"limit": 1_000_000}, "High"),
        ]
        it = tqdm(test_cases, desc="Testing payload sizes", leave=False) if self.show_progress else test_cases
        for size_name, params, sev in it:
            try:
                start = time.time()
                resp = self.session.request(method, self._build_url(endpoint["url"]), params=params, timeout=30)
                rt = time.time() - start
                rs = len(resp.content or b"")
                if rs > self.thresholds["response_size"]:
                    self._log_issue(endpoint["url"], "Large Response Size", f"{size_name} -> {self._format_bytes(rs)}", sev, {"method": method, "params": params, "size": rs, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
                if rt > self.thresholds["response_time"]:
                    self._log_issue(endpoint["url"], "Slow Response", f"{size_name} took {rt:.2f}s", sev, {"method": method, "params": params, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
            except requests.RequestException as exc:
                self._log_issue(endpoint["url"], "Request Error", str(exc), "Medium" if "timeout" in str(exc).lower() else "Low", {"method": method, "status_code": 0})

        if method in ["POST", "PUT", "PATCH"]:
            malicious_payloads = [
                ("10MB_string", "A" * 10_000_000, "High"),
                ("deep_json_100", self._generate_deep_nested_json(100), "High"),
                ("zip_stub", b"PK\x05\x06" + b"\x00" * 18, "Critical"),
            ]
            it2 = tqdm(malicious_payloads, desc="Testing malicious payloads", leave=False) if self.show_progress else malicious_payloads
            for payload_name, payload, sev in it2:
                try:
                    start = time.time()
                    headers = {"Content-Type": "application/json"} if isinstance(payload, dict) else None
                    resp = self.session.request(
                        method,
                        self._build_url(endpoint["url"]),
                        json=payload if isinstance(payload, dict) else None,
                        data=payload if isinstance(payload, (bytes, str)) and not isinstance(payload, dict) else None,
                        headers=headers,
                        timeout=30,
                    )
                    rt = time.time() - start
                    rs = len(resp.content or b"")
                    if rs > self.thresholds["response_size"]:
                        self._log_issue(endpoint["url"], "Large Response Size", f"{payload_name} -> {self._format_bytes(rs)}", sev, {"method": method, "payload_type": payload_name, "size": rs, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
                    if rt > self.thresholds["response_time"]:
                        self._log_issue(endpoint["url"], "Slow Response", f"{payload_name} took {rt:.2f}s", sev, {"method": method, "payload_type": payload_name, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
                except requests.RequestException as exc:
                    self._log_issue(endpoint["url"], "Request Error", f"{payload_name}: {exc}", "High" if "timeout" in str(exc).lower() else "Medium", {"status_code": 0})

    # ----------------------- Function _test_computational_complexity ----------------------------#
    def _test_computational_complexity(self, endpoint: Dict[str, Any]) -> None:
        queries = [
            {"search": "a" * 10000, "severity": "Medium"},
            {"filter": " OR ".join(["1=1"] * 500), "severity": "High"},
            {"sort": ",".join(["field"] * 100), "severity": "Medium"},
            {"id": "123 AND (SELECT * FROM (SELECT(SLEEP(5)))xyz)", "severity": "Critical"},
            {"query": "' OR 1=1; WAITFOR DELAY '0:0:5'--", "severity": "Critical"},
            {"q": '{"$where": "sleep(5000)"}', "severity": "Critical"},
        ]
        it = tqdm(queries, desc="Testing complex queries", leave=False) if self.show_progress else queries
        for q in it:
            sev = q.pop("severity")
            try:
                start = time.time()
                resp = self.session.request((endpoint.get("method", "GET") or "GET").upper(), self._build_url(endpoint["url"]), params=q, timeout=35)
                rt = time.time() - start
                if rt > 5.0 and any(k in str(q).lower() for k in ["sleep", "waitfor", "delay"]):
                    self._log_issue(endpoint["url"], "Time-Based Vulnerability", f"Time-based test: {rt:.2f}s", "Critical", {"method": endpoint.get("method", "GET"), "query": q, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
                elif rt > self.thresholds["response_time"]:
                    self._log_issue(endpoint["url"], "Computational Complexity", f"Complex query took {rt:.2f}s", sev, {"method": endpoint.get("method", "GET"), "query": q, "time": rt, "status_code": resp.status_code, "headers": dict(resp.headers), "body": (resp.text or "")[:2048]})
            except requests.RequestException as exc:
                self._log_issue(endpoint["url"], "Request Error", str(exc), "High" if "timeout" in str(exc).lower() else "Medium", {"method": endpoint.get("method", "GET"), "status_code": 0, "query": q})

    # ----------------------- Function _test_rate_limiting ----------------------------#
    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        limit = float(self.thresholds["rate_limit"])
        successes = 0
        start_time = time.time()
        last_resp = None
        request_count = 0
        if self.show_progress:
            pbar = tqdm(total=30, desc="Rate limit test", unit="s")
        last_sec = 0
        while time.time() - start_time < 30:
            try:
                last_resp = self.session.request((endpoint.get("method", "GET") or "GET").upper(), self._build_url(endpoint["url"]), timeout=5)
                request_count += 1
                if last_resp.status_code == 200:
                    successes += 1
            except requests.RequestException:
                last_resp = None
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
            self._log_issue(endpoint["url"], "Missing Rate Limiting", f"~{rpm:.1f} req/min (no throttling)", "High", {"method": endpoint.get("method", "GET"), "sent": request_count, "successes": successes, "rpm": rpm, "status_code": getattr(last_resp, "status_code", 0) if last_resp else 0})

    # ----------------------- Function _analyze_batch_response ----------------------------#
    def _analyze_batch_response(self, endpoint: Dict[str, Any], size: int, resp: requests.Response, rt: float) -> None:
        if resp.status_code == 207:
            try:
                responses = resp.json()
                failures = [r for r in responses if 400 <= r.get("status", 200) < 600]
                if failures:
                    self._log_issue(endpoint["url"], "Partial Batch Failure", f"{len(failures)}/{size} items failed in batch", "Medium", {"method": endpoint.get("method", "GET"), "batch_size": size, "failures": len(failures), "status_code": 207, "body": (resp.text or "")[:2048]})
            except json.JSONDecodeError:
                pass
        expected_time = float(self.thresholds["response_time"]) * (size ** 0.8)
        if rt > expected_time * 2:
            severity = "High" if size > 100 else "Medium"
            self._log_issue(endpoint["url"], "Batch Performance Issue", f"Batch of {size} took {rt:.2f}s", severity, {"method": endpoint.get("method", "GET"), "batch_size": size, "response_time": rt, "threshold": expected_time, "status_code": resp.status_code, "body": (resp.text or "")[:2048]})

    # ----------------------- Function _test_batch_operations ----------------------------#
    def _test_batch_operations(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get("method", "GET") or "GET").upper().upper()
        if method not in ("POST", "PUT", "PATCH"):
            return
        base_payload = endpoint.get("json", {"items": [{"id": 1, "name": "Test User", "email": "test@example.com"}]})
        patterns = [
            ("duplicate_ids", lambda i: {"id": 1}, "Medium"),
            ("null_values", lambda i: {"id": i, "value": None}, "Low"),
            ("sql_injection", lambda i: {"id": i, "filter": f"' OR 1=1 -- {i}"}, "Critical"),
        ]
        sizes = self.thresholds.get("batch_sizes", [10, 50, 100])
        for size in (tqdm(sizes, desc="Testing batch sizes", leave=False) if self.show_progress else sizes):
            try:
                payload = {"items": []}
                for i in range(size):
                    item = dict(base_payload["items"][0])
                    item.update({"id": i, "email": f"user{i}@example.com"})
                    payload["items"].append(item)
                self._execute_batch_request(endpoint, size, method, payload, "normal", "Medium")
            except Exception as exc:
                self._log_issue(endpoint["url"], "Batch Request Failure", str(exc), "High", {"batch_size": size, "status_code": 0})
            for pattern_name, gen, sev in (tqdm(patterns, desc="Testing malicious patterns", leave=False) if self.show_progress else patterns):
                try:
                    payload = {"items": [gen(i) for i in range(size)]}
                    self._execute_batch_request(endpoint, size, method, payload, pattern_name, sev)
                except Exception:
                    continue

    # ----------------------- Function _execute_batch_request ----------------------------#
    def _execute_batch_request(self, endpoint: Dict[str, Any], size: int, method: str, payload: Dict[str, Any], pattern_name: str, severity: str) -> None:
        start = time.time()
        resp = self.session.request(method, self._build_url(endpoint["url"]), json=payload, timeout=60)
        rt = time.time() - start
        if resp.status_code == 400:
            self._log_issue(endpoint["url"], "Batch Validation Failure", f"{pattern_name} batch of {size} failed validation", severity, {"method": method, "pattern": pattern_name, "batch_size": size, "status_code": 400, "body": (resp.text or "")[:2048]})
        else:
            self._analyze_batch_response(endpoint, size, resp, rt)

    # ----------------------- Function _test_concurrent_flood ----------------------------#
    def _test_concurrent_flood(self, endpoint: Dict[str, Any]) -> None:
        method = (endpoint.get("method", "GET") or "GET").upper()
        url = self._build_url(endpoint["url"])
        params = endpoint.get("parameters", {})
        successes = 0
        errors = 0
        timeouts = 0

        def send_request():
            try:
                resp = self.session.request(method, url, params=params, timeout=5)
                return resp.status_code
            except requests.exceptions.Timeout:
                return "timeout"
            except requests.exceptions.RequestException:
                return "error"

        max_workers = int(self.thresholds.get("concurrent_workers", 8))
        total = int(self.thresholds.get("concurrent_requests", 100))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(send_request) for _ in range(total)]
            bar = tqdm(total=len(futures), desc="Concurrent requests", unit="req") if self.show_progress else None
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result == 200:
                    successes += 1
                elif result == "timeout":
                    timeouts += 1
                else:
                    errors += 1
                if bar:
                    bar.update(1)
            if bar:
                bar.close()

        if timeouts > total * 0.5:
            self._log_issue(endpoint["url"], "Concurrent Request Timeouts", f"{timeouts}/{total} timed out", "Critical", {"method": method, "total_requests": total, "timeouts": timeouts, "errors": errors, "successes": successes})
        elif timeouts > total * 0.2:
            self._log_issue(endpoint["url"], "Concurrent Request Timeouts", f"{timeouts}/{total} timed out", "High", {"method": method, "total_requests": total, "timeouts": timeouts, "errors": errors, "successes": successes})
        if errors > total * 0.5:
            self._log_issue(endpoint["url"], "Concurrent Request Failures", f"{errors}/{total} failed", "Critical", {"method": method, "total_requests": total, "errors": errors, "timeouts": timeouts, "successes": successes})
        elif errors > total * 0.3:
            self._log_issue(endpoint["url"], "Concurrent Request Failures", f"{errors}/{total} failed", "High", {"method": method, "total_requests": total, "errors": errors, "timeouts": timeouts, "successes": successes})

                                     
    # ----------------------- Function _filtered_issues ----------------------------#
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for it in self.issues:
            code = int(it.get('status_code', 0) or 0)
            if code in (0, 400, 404, 405):
                continue
            desc = (it.get('description') or '')
            if 200 <= code < 300 and desc.startswith('Medium - Resource Consumption'):
                continue
            key = (it.get('endpoint'), it.get('method'), code, desc)
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    # ----------------------- Function generate_report ----------------------------#
    def generate_report(self, fmt: str = "markdown") -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner="ResourceConsumption (API04)", base_url=self.base_url)
        if fmt == "markdown":
            return gen.generate_markdown()
        if fmt == "html":
            return gen.generate_html()
        return gen.generate_html()

    # ----------------------- Function save_report ----------------------------#
    def save_report(self, path: str, fmt: str = "markdown") -> None:
        ReportGenerator(self._filtered_issues(), scanner="ResourceConsumption (API04)", base_url=self.base_url).save(path, fmt=fmt)
