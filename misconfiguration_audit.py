########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.2 1-4-2026                                 #
########################################################                                             
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


#================funtion _headers_to_list normalize headers mapping to list of tuples ##########
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

    #================funtion __init__ initialize configuration and state ##########
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
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        
        # Error suppressie attributen
        self._endpoint_error_counts = {}
        self._param_error_logged = set()

    #================funtion _tw logging wrapper ##########
    def _tw(self, message: str, level: str = "info") -> None:
        if self.show_progress:
            tqdm.write(f"[{level.upper()}] {message}")
        else:
            if level == "error":
                self.logger.error(message)
            elif level == "warn":
                self.logger.warning(message)
            elif level == "debug":
                self.logger.debug(message)
            else:
                self.logger.info(message)

    #================funtion _is_api_json check if response is API JSON ##########
      
    def _is_api_json(self, response) -> bool:
        try:
            ctype = (response.headers.get("Content-Type", "") or "").lower()
        except Exception:
            ctype = ""
        if "application/json" in ctype or "problem+json" in ctype:
            return True
        try:
            txt = getattr(response, "text", "") or ""
            if not txt or len(txt) > 4096:
                return False
            import json as _json
            _json.loads(txt)
            return True
        except Exception:
            return False

    #================funtion _stringify_body safe body extraction/pretty-print ##########
    def _stringify_body(self, response) -> str:
        try:
            ctype = (response.headers.get("Content-Type", "") or "").lower()
        except Exception:
            ctype = ""

        try:
            txt = getattr(response, "text", None)
        except Exception:
            txt = None

        if txt:
            if "application/json" in ctype:
                try:
                    import json as _json
                    return _json.dumps(_json.loads(txt), indent=2, ensure_ascii=False)[:4096]
                except Exception:
                    return txt[:4096]
            return txt[:4096]

        try:
            data = getattr(response, "content", b"") or b""
        except Exception:
            data = b""

        if not data:
            return "[empty body]"

        try:
            return data[:512].decode("utf-8", errors="replace")
        except Exception:
            return f"[binary {len(data)} bytes]"


    #================funtion _filter_findings filter findings ##########
    def _filter_findings(self) -> List[Finding]:
        return self._filter_issues()
                                                                               
                                                                                                 
    #================funtion endpoints_from_spec_universal build endpoints from OpenAPI (universal) ##########
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
        except Exception as e:
            self._tw(f"Error building endpoints from spec: {e}", "error")
            return []
        return endpoints

                                                                                          
    @classmethod
    #================funtion endpoints_from_swagger parse Swagger/OpenAPI file to endpoints ##########
    def endpoints_from_swagger(cls, swagger_path: str) -> List[Endpoint]:
        try:
            spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
            server = str((spec.get("servers", [{}]) or [{}])[0].get("url", "") or "")
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

    #================funtion _default_payloads return shuffled misconfiguration probe payloads ##########
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

                                                                                  
    #================funtion _build_finding construct a finding dict from response ##########
  
    def _build_finding(
        self,
        endpoint: Endpoint,
        payload: str,
        response: requests.Response,
        duration: float,
        description: str,
        severity: str,
    ) -> Finding:
        method_used = str(
            getattr(getattr(response, "request", None), "method", endpoint.get("method", "GET"))
        ).upper()

        ctype = (response.headers.get("Content-Type", "") or "").lower()
        clen = response.headers.get("Content-Length")

        try:
            body_bytes = bytes(getattr(response, "content", b"") or b"")
        except Exception:
            txt = getattr(response, "text", "")
            enc = getattr(response, "encoding", None) or "utf-8"
            body_bytes = txt.encode(enc, errors="replace")
  
        if not body_bytes:
            if method_used in ("HEAD", "OPTIONS") or response.status_code in (204, 304) or (
                clen is not None and str(clen).strip() == "0"
            ):
                body_display = f"<no body> ({method_used} {response.status_code}; Content-Length={clen or 0})"
            else:
                body_display = "<empty response body>"
        else:
            if ("application/json" in ctype) or ("text/" in ctype) or ("xml" in ctype) or ("javascript" in ctype):
                if "json" in ctype:
                    try:
                        body_display = json.dumps(response.json(), indent=2)[:8192]
                    except Exception:
                        enc = getattr(response, "encoding", None) or "utf-8"
                        body_display = (getattr(response, "text", "") or body_bytes.decode(enc, errors="replace"))[:8192]
                else:
                    enc = getattr(response, "encoding", None) or "utf-8"
                    body_display = (getattr(response, "text", "") or body_bytes.decode(enc, errors="replace"))[:8192]
            else:
                hex_preview = body_bytes[:64].hex()
                body_display = f"[binary {len(body_bytes)} bytes, content-type={ctype}]\nhex-preview: {hex_preview}"

        sample_display = body_display[:500] if body_display is not None else None

        return {
            "name": f"{endpoint['method']} {endpoint['path']}",
            "endpoint": f"{endpoint['method']} {endpoint['path']}",
            "operation_id": endpoint.get("operationId", ""),
            "payload": payload,
            "status_code": response.status_code,
            "response_time": duration,
            "description": description,
            "severity": severity,
            "response_headers": _headers_to_list(getattr(response.raw, "headers", {})) or _headers_to_list(response.headers),
            "response_body": body_display,
            "response_body_sample": sample_display,
            "response_cookies": response.cookies.get_dict(),
            "request_headers": _headers_to_list(getattr(getattr(response, "request", None), "headers", {})) if getattr(response, "request", None) else [],
            "request_body": getattr(getattr(response, "request", None), "body", None),
            "request_cookies": self.session.cookies.get_dict(),
            "timestamp": datetime.now().isoformat(),
        }


    #================funtion _enforce_rate_limit throttle outbound requests ##########
    def _enforce_rate_limit(self) -> None:
        now = time.time()
        gap = 1.0 / float(self.requests_per_second)
        with self._lock:
            elapsed = now - self._last_request_time
            wait = max(0.0, gap - elapsed)
        if wait > 0:
            time.sleep(wait)
        with self._lock:
            self._last_request_time = time.time()

                                                                               
    #================funtion _suppress_excessive_errors prevent error spam ##########
    def _suppress_excessive_errors(self, endpoint_method, endpoint_path):
        """Suppress error logging after too many consecutive errors on same endpoint"""
        with self._lock:
            key = f"{endpoint_method} {endpoint_path}"
            self._endpoint_error_counts[key] = self._endpoint_error_counts.get(key, 0) + 1
            
            # Als we meer dan 3 errors hebben op hetzelfde endpoint, log minder
            if self._endpoint_error_counts[key] > 3:
                return self._endpoint_error_counts[key] % 10 == 0  # Log elke 10e error
            return True  # Log alle errors
                                                                                         
    #================funtion _test_single_endpoint probe one endpoint and run analyzers ##########
    def _test_single_endpoint(self, ep: Endpoint, pbar: Optional[tqdm] = None) -> None:
        try:
            method = ep["method"]
            path   = ep["path"]
            base   = ep.get("base") or self.base_url
            
            error_key = f"{method} {path}"
            with self._lock:
                if self._endpoint_error_counts.get(error_key, 0) >= 5:
                    if pbar:
                        pbar.update(1)
                    return
            
            full_url = urljoin(base, path.lstrip("/"))
            
            if "{" in path and "}" in path:
                path = re.sub(r"\{[^}]+\}", "123", path)
                full_url = urljoin(base, path.lstrip("/"))
            
            host_key = urlparse(full_url).netloc.lower()
            
            if self.debug:
                self._tw(f"Testing {method} {path}", level="debug")

            seq = []
            if method == "GET":
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
                        headers.pop("X-API-Key", None)
                        headers.pop("X-Auth-Token", None)
                    resp = self.session.request(
                        m, 
                        full_url, 
                        headers=headers, 
                        timeout=self.timeout, 
                        allow_redirects=True
                    )
                    dur = time.time() - start
                    self._request_counter += 1
                    
                    with self._lock:
                        if error_key in self._endpoint_error_counts:
                            del self._endpoint_error_counts[error_key]
                    
                except requests.RequestException as e:
                    self._error_count += 1
                    with self._lock:
                        self._endpoint_error_counts[error_key] = \
                            self._endpoint_error_counts.get(error_key, 0) + 1
                    if self._suppress_excessive_errors(method, path):
                        error_msg = str(e)
                        if "500" in error_msg or "Internal Server Error" in error_msg:
                            self._tw(f"{m} 500 error for {method} {path}", "warn")
                        else:
                            self._tw(f"{m} failed for {method} {path}: {e}", "error")
                    if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                        self._tw("Many errors, cooling down 1s", "warn")
                        time.sleep(1.0)
                        self._error_count = 0
                    if m == "OPTIONS" and self._endpoint_error_counts.get(error_key, 0) >= 2:
                        continue
                    if m == method and self._endpoint_error_counts.get(error_key, 0) >= 5:
                        break
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
                        self._tw(f"Analyzer {analyzer.__name__} on {m} {path}: {ex}", "debug")
            if method not in ("HEAD", "OPTIONS"):
                with self._lock:
                    if self._endpoint_error_counts.get(error_key, 0) >= 3:
                        if pbar:
                            pbar.update(1)
                        return
                
                probe_names = getattr(self, "PARAM_PROBE_NAMES", [
                    "probe", "debug", "verbose", "pretty", "format", "fields",
                    "sort", "expand", "include", "lang", "locale", "cache",
                    "nocache", "trace", "test"
                ])
                probe_vals = getattr(self, "PARAM_PROBE_VALUES", ["1", "true", "*"])
                
                max_probes = 3 if self._error_count > 0 else len(probe_names)
                
                for i, name in enumerate(probe_names[:max_probes]):
                    with self._lock:
                        if self._endpoint_error_counts.get(error_key, 0) >= 3:
                            break
                    
                    for val in probe_vals[:2]:
                        try:
                            self._enforce_rate_limit()
                            
                            u = urlparse(full_url)
                            q = dict(parse_qsl(u.query, keep_blank_values=True))
                            q[name] = val
                            crafted = u._replace(query=urlencode(q, doseq=True)).geturl()
                            
                            start = time.time()
                            resp = self.session.request(
                                method, 
                                crafted, 
                                timeout=self.timeout, 
                                allow_redirects=True
                            )
                            dur = time.time() - start
                            self._request_counter += 1
                            
                            with self._lock:
                                if error_key in self._endpoint_error_counts:
                                    del self._endpoint_error_counts[error_key]
                            
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
                            
                            with self._lock:
                                self._endpoint_error_counts[error_key] = \
                                    self._endpoint_error_counts.get(error_key, 0) + 1
                            
                            param_error_key = f"param-{method}-{path}"
                            with self._lock:
                                if param_error_key not in self._param_error_logged:
                                    error_msg = str(e)
                                    if "500" in error_msg or "Internal Server Error" in error_msg:
                                        try:
                                            mock_resp = type('MockResponse', (), {
                                                'status_code': 500,
                                                'headers': {},
                                                'text': str(e),
                                                'request': type('MockRequest', (), {
                                                    'method': method,
                                                    'url': crafted
                                                })()
                                            })()
                                            
                                            finding = self._build_finding(
                                                ep,
                                                f"{name}={val}",
                                                mock_resp,
                                                0.0,
                                                f"500 error on parameter probe: {name}={val}",
                                                "Medium"
                                            )
                                            self._record_finding(finding)
                                        except Exception:
                                            pass
                                        
                                        self._tw(f"Param probe 500 error on {method} {path} ({name}={val})", "warn")
                                    else:
                                        self._tw(f"Param probe failing on {method} {path}: {e}", "error")
                                    self._param_error_logged.add(param_error_key)
                            
                            if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                                self._tw("Many errors, cooling down 1s", "warn")
                                time.sleep(1.0)
                                self._error_count = 0
                            
                            with self._lock:
                                if self._endpoint_error_counts.get(error_key, 0) >= 3:
                                    break
                        
        except Exception as e:
            if self._suppress_excessive_errors(method, path):
                self._tw(f"Unexpected test error at {method} {path}: {e}", "error")
        finally:
            if pbar:
                pbar.update(1)                              
                                                                                                
    #================funtion _security_header_analyzer detect missing security headers ##########
    def _security_header_analyzer(self, ep, payload, resp, dur):
        if self._is_api_json(resp):
            return None
            
        path = (ep.get("path") if isinstance(ep, dict) else str(ep) or "").lower()
        if re.search(r"/auth|/login|/signup|check-otp|verify-email-token", path):
            return None
            
        if str(self.base_url).lower().startswith("http://"):
            return None
        
        hdrs = resp.headers or {}
        low_keys = {k.lower(): v for k, v in hdrs.items()}
        missing = []

        if "strict-transport-security" not in low_keys:
            missing.append("HSTS")
        if low_keys.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in low_keys:
            missing.append("X-Frame-Options")
        if "content-security-policy" not in low_keys:
            missing.append("CSP")

        if not missing:
            return None

        return self._build_finding(
            ep, payload, resp, dur,
            "Missing: " + ", ".join(missing),
            "Low",
        )
                                                                                  
    #================funtion _cors_analyzer analyze CORS exposure ##########
    def _cors_analyzer(self, ep, payload, resp, dur):
        hdrs = resp.headers or {}
        acao = (hdrs.get("Access-Control-Allow-Origin", "") or "").strip()
        acac = (hdrs.get("Access-Control-Allow-Credentials", "") or "").strip().lower()
        vary = (hdrs.get("Vary", "") or "").lower()

        if not acao:
            return None

        req_origin = ""
        try:
            req_origin = (getattr(getattr(resp, "request", None), "headers", {}) or {}).get("Origin", "") or ""
        except Exception:
            req_origin = ""

        method = getattr(getattr(resp, "request", None), "method", "GET").upper()

        # Default severity
        sev = "Info"
        desc_parts = [f"ACAO={acao}", f"ACAC={acac or 'false'}"]
        
        if "," in acao:
            sev = "Medium"
            desc_parts.append("Multiple origins in ACAO")
        elif acao == "*" and acac == "true":
            sev = "High"
            desc_parts.append("Wildcard with credentials")
        elif req_origin and acao == req_origin:
            sev = "Medium" if "origin" not in vary else "Low"
            desc_parts.append("ACAO reflects request Origin")
        elif acao == "*":
            sev = "Low" if method != "OPTIONS" else "Info"
            desc_parts.append("Wildcard CORS")

        return self._build_finding(ep, payload, resp, dur, ", ".join(desc_parts), sev)

    #================funtion _server_error_analyzer flag 5xx server errors ########## flag 5xx server errors ##########
    def _server_error_analyzer(self, ep, payload, resp, dur):
        if 500 <= resp.status_code < 600:
            return self._build_finding(ep, payload, resp, dur, f"{resp.status_code} on baseline/probe", "Medium")

                                                                                           
    #================funtion _verbose_error_analyzer detect verbose error disclosures ##########
    def _verbose_error_analyzer(self, ep, payload, resp, dur):
        body = (resp.text or "")
        low = body.lower()
        markers = ("exception", "stack trace", "traceback", "sqlstate", "nullreferenceexception")
        if any(m in low for m in markers):
            p = (ep.get("path") or "").lower()
            if any(x in p for x in ("/swagger", "/openapi", "/api-docs", "/docs")):
                return None
            return self._build_finding(ep, payload, resp, dur, "Response body contains implementation stack/error markers", "High")

    #================funtion _http_method_analyzer detect risky HTTP methods / Allow header ##########
    def _http_method_analyzer(self, ep, payload, resp, dur):
        allow = (resp.headers.get("Allow", "") or "").upper()
        if not allow:
            return None
        risky = []
        for m in ("TRACE", "TRACK", "CONNECT"):
            if m in allow:
                risky.append(m)
        if not risky:
            return None
        return self._build_finding(
            ep,
            payload,
            resp,
            dur,
            f"Potentially risky HTTP methods enabled via Allow header: {', '.join(risky)}",
            "Medium",
        )

                                                                               
    #================funtion _record_finding deduplicate and record finding ##########
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

    
    #================funtion _title_for compose display title for endpoint ##########
    def _title_for(self, ep: Dict[str, Any], resp: requests.Response) -> str:
        ep_method = str(ep.get("method", "GET")).upper()
        path = ep.get("path") or ""
        return f"{ep_method} {path}"

            
                                                                                  
    #================funtion _filter_issues filter noise and deduplicate issues ##########
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

            key = (i.get("endpoint"), i.get("description"), str(status), str(i.get("description") or "")[:120],)
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(i)

                                                              
        if hasattr(self, "_findings"):
            self._findings = cleaned
            return self._findings
        self.issues = cleaned
        return self.issues
     
   
                                                                                  
    #================funtion test_endpoints run scan across endpoints with concurrency ##########
    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        if not endpoints and getattr(self, "spec", None):
            endpoints = self.endpoints_from_spec_universal()
        if not endpoints:
            return []

        # Reset error tracking voor nieuwe scan
        self._endpoint_error_counts = {}
        self._param_error_logged = set()

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            if self.show_progress:
                for _ in tqdm(as_completed(futures), total=len(futures), desc="API8 misconfiguration endpoints", unit="endpoint", dynamic_ncols=True):
                    pass
            else:
                for _ in as_completed(futures):
                    pass

        return self._filter_issues()

                                                                                   
    #================funtion generate_report render report via ReportGenerator ##########
    def generate_report(self, fmt: str = "markdown") -> str:
        scanner = "Enhanced Misconfiguration Auditor (API8)"
        filtered = self._filter_issues()  # Fixed: was _filter_findings
        gen = ReportGenerator(filtered, scanner=scanner, base_url=self.base_url)
        return gen.generate_markdown() if fmt == "markdown" else gen.generate_json()

                                                                               
    #================funtion save_report persist report to disk ##########
    def save_report(self, path: str, fmt: str = "markdown"):
        scanner = "Enhanced Misconfiguration Auditor (API8)"
        filtered = self._filter_issues()
        ReportGenerator(filtered, scanner=scanner, base_url=self.base_url).save(path, fmt=fmt)