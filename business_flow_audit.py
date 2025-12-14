########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the MIT License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.1 14-12-2025                               #
########################################################  
                                                      
from __future__ import annotations

import json
import random
import re
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Set
from urllib.parse import urljoin, urlparse

import requests

try:
    from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig                
except Exception:
    oas_iter_ops = None
    oas_build_request = None

try:
    from report_utils import ReportGenerator  
except Exception:
    ReportGenerator = None  

class Flow(TypedDict, total=False):
    name: str
    method: str
    url: str
    path: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    body: Dict[str, Any]
    json: Any
    data: Any
    files: Any
    sensitive: bool

class Issue(TypedDict, total=False):
    url: str
    endpoint: str
    method: str
    description: str
    severity: str
    status_code: int
    timestamp: str
    request_headers: Dict[str, Any]
    request_body: Any
    request_cookies: Dict[str, Any]
    response_headers: Dict[str, Any]
    response_body: str
    response_cookies: Dict[str, Any]
    request: Dict[str, Any]
    details: Dict[str, Any]
    fingerprint: str
    duplicate_count: int
    variants: List[str]

@dataclass(frozen=True)
class _OpRef:
    method: str
    path: str
    op: Any

class BusinessFlowAuditor:
    
    PRICE_KEYS: Set[str] = {
        "price", "amount", "total", "total_amount", "totalprice", "unit_price", "unitprice",
        "cost", "value", "balance", "quantity", "qty", "count"
    }
    COUPON_KEYS: Set[str] = {"coupon", "coupon_code", "promo", "promo_code", "discount_code"}

    AUTH_PATH_RE = re.compile(r"(login|signup|register|token|oauth|auth|reset-password|verify-email|forgot)", re.I)

    #================funtion __init__ description =============
    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        swagger_spec: dict,
        flow: str = "none",
        *,
        timeout: int = 12,
        concurrency: int = 8,
        logger: Any = None,
        enable_stress: bool = False,
        coupon_attempts: int = 20,
        sequential_rate_limit_requests: int = 25,
    ) -> None:
        self.session = session
        self.base_url = base_url.rstrip("/") + "/"
        self.spec = swagger_spec
        self.flow = flow or "none"
        self.timeout = int(timeout)
        self.concurrency = max(1, int(concurrency))
        self.enable_stress = bool(enable_stress)
        self.coupon_attempts = max(1, int(coupon_attempts))
        self.sequential_rate_limit_requests = max(5, int(sequential_rate_limit_requests))
        self.logger = logger

        self._issues: List[Issue] = []
        self._lock = threading.Lock()
        self._tested_coupons: Set[str] = set()

        self._op_index: Dict[Tuple[str, str], Any] = {}
        self._op_shape_index: Dict[Tuple[str, str], Any] = {}
        self._index_openapi_ops()

                                                                       
    #================funtion _tw description =============
    def _tw(self, msg: str) -> None:
        try:
            from tqdm import tqdm
            tqdm.write(msg)
        except Exception:
            print(msg)

                                                                                      
    #================funtion _index_openapi_ops description =============
    def _index_openapi_ops(self) -> None:
        if oas_iter_ops is None:
            return
        try:
            for op in oas_iter_ops(self.spec):
                m = (op.get("method") or "").upper()
                p = op.get("path") or ""
                if not m or not p:
                    continue
                p = "/" + p.lstrip("/")
                self._op_index[(m, p)] = op
                self._op_shape_index[(m, self._canonical_path(p))] = op
        except Exception:
            return

                                                                                   
    #================funtion _canonical_path description =============
    def _canonical_path(self, p: str) -> str:
        p = "/" + (p or "").lstrip("/")
        return re.sub(r"\{[^}]+\}", "{}", p)

                                                                            
    #================funtion _abs_url description =============
    def _abs_url(self, path_or_url: str) -> str:
        s = path_or_url or ""
        if s.startswith(("http://", "https://")):
            return s
        return urljoin(self.base_url, s.lstrip("/"))

                                                                          
    #================funtion _nonce description =============
    def _nonce(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

                                                                                     
    #================funtion _safe_body_sample description =============
    def _safe_body_sample(self, body: Any, limit: int = 2048) -> str:
        if body is None:
            return ""
        if isinstance(body, bytes):
            try:
                return body.decode("utf-8", "replace")[:limit]
            except Exception:
                return f"<{len(body)} bytes>"
        if isinstance(body, str):
            return body[:limit]
        try:
            return json.dumps(body, ensure_ascii=False)[:limit]
        except Exception:
            return str(body)[:limit]

                                                                                             
    #================funtion _looks_like_auth_endpoint description =============
    def _looks_like_auth_endpoint(self, path: str) -> bool:
        return bool(self.AUTH_PATH_RE.search(path or ""))

                                                                                 
    #================funtion _is_processed description =============
    def _is_processed(self, resp: requests.Response) -> bool:
        if resp is None:
            return False
        code = int(getattr(resp, "status_code", 0) or 0)
        if not (200 <= code < 300):
            return False

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" not in ctype:
            return True

        try:
            data = resp.json()
        except Exception:
            return True

        if isinstance(data, dict):
            keys = {str(k).lower() for k in data.keys()}
            if "error" in keys or "errors" in keys:
                return False
            if keys.issubset({"message", "status", "detail"}) and all(not isinstance(v, (dict, list)) for v in data.values()):
                txt = (data.get("message") or data.get("detail") or "").lower()
                if any(w in txt for w in ("error", "failed", "invalid", "denied", "unauthorized", "forbidden")):
                    return False
        return True

                                                                          
    #================funtion _shape description =============
    def _shape(self, text: str) -> str:
        if not text:
            return ""
        try:
            data = json.loads(text)
        except Exception:
            return re.sub(r"\s+", " ", text).strip()[:4096]

        #================funtion norm description =============
        def norm(v: Any):
            if isinstance(v, dict):
                return {k: norm(val) for k, val in sorted(v.items(), key=lambda x: x[0]) if str(k).lower() not in {
                    "timestamp", "time", "date", "requestid", "request_id", "traceid", "trace_id"
                }}
            if isinstance(v, list):
                return [norm(v[0])] if v else []
            if isinstance(v, str):
                return "S"
            if isinstance(v, (int, float)):
                return "N"
            if isinstance(v, bool):
                return "B"
            if v is None:
                return "null"
            return "X"

        try:
            shaped = norm(data)
            return json.dumps(shaped, separators=(",", ":"), ensure_ascii=False)[:8192]
        except Exception:
            return re.sub(r"\s+", " ", text).strip()[:4096]

                                                                                
    #================funtion _fingerprint description =============
    def _fingerprint(self, method: str, path: str, status_code: int, desc: str, resp_text: str) -> str:
        canon = self._canonical_path(path)
        shp = self._shape(resp_text)
        base = f"{method.upper()}|{canon}|{status_code}|{desc[:120]}|{shp[:512]}"
        import hashlib
        return hashlib.sha1(base.encode("utf-8", "ignore")).hexdigest()

                                                                                   
    #================funtion _get_smart_body description =============
    def _get_smart_body(self, original_body: Optional[dict]) -> dict:
        if original_body:
            return dict(original_body)
        return {
            "email": f"user{self._nonce()}@example.com",
            "amount": 100,
            "quantity": 1,
            "product_id": "prod_" + self._nonce(),
            "user_id": "user_" + self._nonce(),
            "card_number": "4242424242424242",
            "name": "Test User",
            "description": "Security test transaction",
            "coupon": "TEST" + self._nonce(4).upper(),
        }

                                                                               
    #================funtion _extract_id description =============
    def _extract_id(self, resp: Optional[requests.Response]) -> Optional[str]:
        if not resp:
            return None
        try:
            data = resp.json()
        except Exception:
            return None

        keys = ("id", "order_id", "ticket_id", "transaction_id", "payment_id", "uuid", "reference")
        if isinstance(data, dict):
            for k in keys:
                if k in data and data[k] is not None:
                    return str(data[k])
            for container_key in ("order", "data", "result"):
                v = data.get(container_key)
                if isinstance(v, dict):
                    for k in keys:
                        if k in v and v[k] is not None:
                            return str(v[k])
        return None

                                                                                
    #================funtion _op_for_flow description =============
    def _op_for_flow(self, method: str, path: str) -> Optional[Any]:
        method = (method or "").upper()
        path = "/" + (path or "").lstrip("/")
        op = self._op_index.get((method, path))
        if not op:
            op = self._op_shape_index.get((method, self._canonical_path(path)))
        return op

                                                                                  
    #================funtion _build_request description =============
    def _build_request(self, flow: Flow, *, override_method: Optional[str] = None, body: Optional[dict] = None) -> Dict[str, Any]:
        method = (override_method or flow.get("method") or "POST").upper()
        path = flow.get("path") or urlparse(flow.get("url", "")).path or flow.get("url", "/")
        path = "/" + str(path).lstrip("/")

        op = self._op_for_flow(method, path)
        if op is not None and oas_build_request is not None:
            try:
                req = oas_build_request(self.spec, self.base_url, op, None)
            except Exception:
                req = {"method": method, "url": self._abs_url(path), "headers": {}}
        else:
            req = {"method": method, "url": self._abs_url(path), "headers": {}}

        hdrs: Dict[str, str] = {}
        hdrs.update(getattr(self.session, "headers", {}) or {})
        hdrs.update(flow.get("headers") or {})
        hdrs.setdefault("Accept", "application/json")
        hdrs.setdefault("User-Agent", "APISCAN/3.0 (API6)")
        req["headers"] = hdrs

        params = dict(flow.get("params") or {})
        if params:
            req["params"] = params

        payload = body if body is not None else flow.get("body")
        if payload is None:
            payload = flow.get("json")

        if method not in {"GET", "HEAD", "OPTIONS"} and payload is not None:
            req["json"] = payload

        return req

                                                                         
    #================funtion _send description =============
    def _send(
        self,
        flow: Flow,
        *,
        body: Optional[dict] = None,
        override_method: Optional[str] = None,
        anonymous: bool = False,
    ) -> Optional[requests.Response]:
        req = self._build_request(flow, override_method=override_method, body=body)
        url = req.get("url") or self._abs_url(flow.get("url", "/"))

        if anonymous:
            req_headers = dict(req.get("headers") or {})
            req_headers.pop("Authorization", None)
            req["headers"] = req_headers

            tmp = requests.Session()
            tmp.verify = getattr(self.session, "verify", True)
            tmp.trust_env = getattr(self.session, "trust_env", True)
            tmp.proxies = getattr(self.session, "proxies", {})
            ses = tmp
        else:
            ses = self.session

        try:
            return ses.request(timeout=self.timeout, **req)
        except Exception:
            return None

                                                                        
    #================funtion _log description =============
    def _log(self, flow: Flow, desc: str, sev: str, req: Optional[dict] = None, resp: Optional[requests.Response] = None, details: Optional[dict] = None) -> None:
        if resp is None:
            return
        sc = int(getattr(resp, "status_code", 0) or 0)
        if sc in (0, 400, 404, 405):
            return

        eff_url = getattr(getattr(resp, "request", None), "url", None) or self._abs_url(flow.get("url", "/"))
        endpoint_path = urlparse(eff_url).path or "/"

        entry: Issue = {
            "url": eff_url,
            "endpoint": endpoint_path,
            "method": (flow.get("method") or "GET").upper(),
            "description": desc,
            "severity": str(sev).capitalize(),
            "status_code": sc,
            "timestamp": datetime.now().isoformat(),
            "request_headers": {},
            "request_body": None,
            "request_cookies": {},
            "response_headers": {},
            "response_body": "",
            "response_cookies": {},
            "details": details or {},
        }

        try:
            entry["response_headers"] = dict(resp.headers)
            entry["response_body"] = (resp.text or "")[:2048]
            entry["response_cookies"] = resp.cookies.get_dict()
        except Exception:
            pass

        try:
            if resp.request is not None:
                entry["request_headers"] = dict(resp.request.headers)
                entry["request_body"] = self._safe_body_sample(resp.request.body, limit=1024)
                entry["request_cookies"] = self.session.cookies.get_dict()
        except Exception:
            pass

        if req:
            entry["request"] = req

        entry["fingerprint"] = self._fingerprint(entry["method"], endpoint_path, sc, desc, entry.get("response_body") or "")

        with self._lock:
            self._issues.append(entry)
            self._tw(f"[ISSUE] {entry['method']} {endpoint_path} - {desc} (Severity: {entry['severity']})")

                                                                                    
    #================funtion _filtered_issues description =============
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        if not self._issues:
            return []
        sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        dedup: Dict[str, Issue] = {}

        for it in self._issues:
            fp = it.get("fingerprint") or ""
            if not fp:
                continue
            if fp in dedup:
                cur = dedup[fp]
                cur["duplicate_count"] = cur.get("duplicate_count", 1) + 1
                variants = cur.setdefault("variants", [])
                d = it.get("description", "")
                if d and d not in variants:
                    variants.append(d)
                if sev_rank.get(it.get("severity", "Info"), 0) > sev_rank.get(cur.get("severity", "Info"), 0):
                    cur["severity"] = it.get("severity", cur.get("severity", "Info"))
            else:
                it.setdefault("duplicate_count", 1)
                it.setdefault("variants", [it.get("description", "")])
                dedup[fp] = it

        return list(dedup.values())

                                                                                       
    #================funtion test_business_flows description =============
    def test_business_flows(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flows: List[Flow] = []
        for ep in endpoints:
            method = (ep.get("method") or ep.get("http_method") or "POST").upper()
            if method not in {"POST", "PUT", "PATCH"}:
                continue

            raw = ep.get("path") or ep.get("url") or ""
            if not raw:
                continue

            if raw.startswith(("http://", "https://")):
                path_only = urlparse(raw).path or "/"
            else:
                path_only = "/" + str(raw).lstrip("/")

            if self._looks_like_auth_endpoint(path_only):
                continue

            flow: Flow = {
                "name": ep.get("name") or ep.get("operationId") or f"{method} {path_only}",
                "method": method,
                "url": path_only,
                "path": path_only,
                "headers": dict(ep.get("headers") or {}),
                "params": dict(ep.get("params") or {}),
                "body": dict(ep.get("body") or {}),
                "sensitive": bool(ep.get("sensitive", False)),
            }
            flows.append(flow)

        for fl in flows:
            self._run_tests_for_flow(fl)

        return self._filtered_issues()

                                                                                       
    #================funtion _run_tests_for_flow description =============
    def _run_tests_for_flow(self, flow: Flow) -> None:
        tests = (
            self._test_auth_bypass,
            self._test_replay_attack,
            self._test_duplicate_submission,
            self._test_price_manipulation,
            self._test_coupon_bruteforce,
            self._test_method_override,
            self._test_rate_limit_sequential,
            self._test_concurrency,
            self._test_field_pollution,
        )
        for test in tests:
            try:
                test(flow)
            except Exception as exc:
                self._log(flow, f"Test error: {exc}", "Low")

                                                                                     
    #================funtion _test_auth_bypass description =============
    def _test_auth_bypass(self, flow: Flow) -> None:
        sess_auth = "Authorization" in getattr(self.session, "headers", {}) or bool(getattr(self.session, "cookies", {}).get_dict())
        if not sess_auth:
            return

        r = self._send(flow, anonymous=True)
        if r is not None and self._is_processed(r):
            self._log(flow, "Authentication bypass possible (anonymous request processed)", "High", resp=r)

                                                                                       
    #================funtion _test_replay_attack description =============
    def _test_replay_attack(self, flow: Flow) -> None:
        idem = "idem-" + self._nonce(12)
        hdr = dict(flow.get("headers") or {})
        hdr["Idempotency-Key"] = idem
        tmp = dict(flow)
        tmp["headers"] = hdr

        r1 = self._send(tmp)
        time.sleep(0.2)
        r2 = self._send(tmp)
        if r1 is None or r2 is None:
            return
        if not (self._is_processed(r1) and self._is_processed(r2)):
            return

        id1 = self._extract_id(r1)
        id2 = self._extract_id(r2)

        if id1 and id2 and id1 == id2:
            return

        sev = "High"
        p = (flow.get("path") or flow.get("url") or "").lower()
        if any(k in p for k in ("payment", "checkout", "order", "transaction", "transfer")):
            sev = "Critical"

        self._log(flow, "Replay/duplicate processing possible (same request processed twice)", sev, resp=r2, details={"id1": id1, "id2": id2, "idempotency_key": idem})

                                                                                              
    #================funtion _test_duplicate_submission description =============
    def _test_duplicate_submission(self, flow: Flow) -> None:
        r1 = self._send(flow)
        time.sleep(0.3)
        r2 = self._send(flow)
        if r1 is None or r2 is None:
            return
        if not (self._is_processed(r1) and self._is_processed(r2)):
            return

        id1 = self._extract_id(r1)
        id2 = self._extract_id(r2)
        if id1 and id2 and id1 != id2:
            self._log(flow, "Duplicate submission accepted (missing idempotency)", "Medium", resp=r2, details={"id1": id1, "id2": id2})

                                                                                            
    #================funtion _test_price_manipulation description =============
    def _test_price_manipulation(self, flow: Flow) -> None:
        payload = self._get_smart_body(flow.get("body"))
        keys = set(payload.keys())
        if not (keys & self.PRICE_KEYS):
            return

        for value in (0, -1, 0.01, 999999999):
            manipulated = dict(payload)
            for k in (keys & self.PRICE_KEYS):
                manipulated[k] = value

            r = self._send(flow, body=manipulated)
            if r is not None and self._is_processed(r):
                sev = "Critical" if value <= 0 else "High"
                self._log(flow, f"Price manipulation accepted (value={value})", sev, resp=r, details={"payload": manipulated})

                                                                                           
    #================funtion _test_coupon_bruteforce description =============
    def _test_coupon_bruteforce(self, flow: Flow) -> None:
        payload = self._get_smart_body(flow.get("body"))
        keys = set(payload.keys())
        coupon_key = next(iter(keys & self.COUPON_KEYS), None)
        if not coupon_key:
            return

        for _ in range(self.coupon_attempts):
            coupon = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if coupon in self._tested_coupons:
                continue
            self._tested_coupons.add(coupon)
            attempt = dict(payload)
            attempt[coupon_key] = coupon

            r = self._send(flow, body=attempt)
            if r is not None and self._is_processed(r):
                self._log(flow, f"Coupon brute-force succeeded ({coupon_key}={coupon})", "High", resp=r, details={"payload": attempt})
                break

                                                                                               
    #================funtion _test_rate_limit_sequential description =============
    def _test_rate_limit_sequential(self, flow: Flow) -> None:
        processed_seen = 0
        last: Optional[requests.Response] = None
        for _ in range(self.sequential_rate_limit_requests):
            r = self._send(flow)
            last = r
            if r is None:
                continue
            sc = int(getattr(r, "status_code", 0) or 0)
            if sc in {429, 503}:
                return
            if self._is_processed(r):
                processed_seen += 1
            else:
                return

        if processed_seen >= self.sequential_rate_limit_requests and last is not None:
            self._log(flow, f"No rate-limiting after {self.sequential_rate_limit_requests} rapid processed requests", "Medium", resp=last)

                                                                                     
    #================funtion _test_concurrency description =============
    def _test_concurrency(self, flow: Flow) -> None:

        #================funtion _invoke description =============
        def _invoke() -> Optional[requests.Response]:
            return self._send(flow)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(_invoke) for _ in range(self.concurrency)]
            responses = [f.result() for f in as_completed(futures)]

        ok = [r for r in responses if (r is not None and self._is_processed(r))]
        if len(ok) == self.concurrency:
            self._log(flow, f"No throttling at {self.concurrency} parallel processed requests", "High", resp=ok[0])

                                                                                         
    #================funtion _test_method_override description =============
    def _test_method_override(self, flow: Flow) -> None:
        for verb in ("PUT", "DELETE", "PATCH"):
            r = self._send(flow, override_method=verb)
            if r is not None and self._is_processed(r):
                self._log(flow, f"Method override to {verb} processed", "Medium", resp=r)

                                                                                         
    #================funtion _test_field_pollution description =============
    def _test_field_pollution(self, flow: Flow) -> None:
        payload = self._get_smart_body(flow.get("body"))
        extra = {
            "role": "admin",
            "isAdmin": True,
            "permissions": ["*"],
            "price": -1,
            "discount": 999999,
            "owner_id": "user_" + self._nonce(),
        }
        attempt = dict(payload)
        attempt.update(extra)
        r = self._send(flow, body=attempt)
        if r is None:
            return
        if self._is_processed(r):
            body = (r.text or "")[:4096]
            if any(k in body for k in ("isAdmin", "permissions", "owner_id", "role")):
                self._log(flow, "Field pollution / mass-assignment suspicion (extra privileged fields accepted)", "High", resp=r, details={"payload": attempt})
            else:
                self._log(flow, "Field pollution accepted (extra fields did not error)", "Low", resp=r, details={"payload": attempt})

                                                                                   
    #================funtion generate_report description =============
    def generate_report(self, fmt: str = "html") -> str:
        issues = self._filtered_issues()
        if ReportGenerator is None:
            return json.dumps(issues, indent=2, ensure_ascii=False)
        gen = ReportGenerator(issues, scanner="BusinessFlows", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

                                                                               
    #================funtion save_report description =============
    def save_report(self, path: str, fmt: str = "html") -> None:
        out = self.generate_report(fmt=fmt)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
