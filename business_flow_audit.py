##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
from __future__ import annotations
import argparse
import json
import random
import string
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from report_utils import ReportGenerator

import requests

Flow = Dict[str, Any]
Issue = Dict[str, Any]
SideEffectChecker = Callable[[requests.Response], bool]


class BusinessFlowAuditor:
    DEFAULT_HEADERS = {"User-Agent": "BusinessFlowAuditor/2.2"}
    AUTH_HEADERS = {"authorization", "x-api-key", "token", "x-auth-token"}
    PRICE_KEYS = {"price", "amount", "total", "cost", "value", "sum"}
    SENSITIVE_PARAMS = {"password", "secret", "token", "creditcard", "cvv"}

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, 
                 concurrency: int = 3, timeout: int = 6, 
                 swagger_spec: Optional[dict] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)
        self.timeout = timeout
        self.concurrency = concurrency
        self._issues: List[Issue] = []
        self._lock = threading.Lock()
        self._tested_coupons: Set[str] = set()
        self.swagger_spec = swagger_spec
        self._endpoint_cache: Dict[Tuple[str, str], dict] = {}
        self.db_errors_detected = False

    def _abs_url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def check_db_health(self):
        try:
            # Eenvoudige database health check
            r = self.session.get(f"{self.base_url}/health/db", timeout=2)
            if r.status_code != 200:
                self.db_errors_detected = True
        except Exception:
            self.db_errors_detected = True

    def _nonce(self) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=8))

    def load_swagger(self, swagger_url: str) -> List[Flow]:
        try:
            resp = self.session.get(swagger_url, timeout=10)
            resp.raise_for_status()
            self.swagger_spec = spec = resp.json()
            
            flows = []
            base_path = spec.get('basePath', '')
            paths = spec.get("paths", {})
            
            for path, methods in paths.items():
                full_path = f"{base_path}{path}"
                for method, details in methods.items():
                    method = method.upper()
                    if method in {"POST", "PUT", "PATCH"}:
                        flow = {
                            "name": details.get("operationId", f"{method}_{path.strip('/').replace('/', '_')}").lower(),
                            "url": full_path,
                            "method": method,
                            "body": self._generate_body_from_schema(details),
                            "headers": self._get_auth_headers(details),
                            "params": self._generate_params_from_schema(details),
                            "metadata": details
                        }
                        flows.append(flow)
                        self._endpoint_cache[(method, full_path)] = details
            return flows
        except Exception as e:
            print(f" Error loading Swagger: {e}")
            return []

    def _generate_body_from_schema(self, endpoint_spec: dict) -> dict:
        """Generate example body from Swagger schema"""
        body = {}
        if 'parameters' in endpoint_spec:
            for param in endpoint_spec['parameters']:
                if param.get('in') == 'body' and 'schema' in param:
                    schema = param['schema']
                    if 'example' in schema:
                        return schema['example']
                    if 'properties' in schema:
                        for prop, prop_schema in schema['properties'].items():
                            body[prop] = self._generate_example_value(prop_schema)
        return body

    def _generate_params_from_schema(self, endpoint_spec: dict) -> dict:
        """Generate example query parameters from Swagger schema"""
        params = {}
        if 'parameters' in endpoint_spec:
            for param in endpoint_spec['parameters']:
                if param.get('in') == 'query' and 'name' in param:
                    params[param['name']] = self._generate_example_value(param)
        return params

    def _generate_example_value(self, schema: dict) -> Any:
        """Generate example value based on Swagger schema"""
        if 'example' in schema:
            return schema['example']
        if 'enum' in schema and schema['enum']:
            return random.choice(schema['enum'])
        
        type_ = schema.get('type', 'string')
        if type_ == 'integer':
            return random.randint(1, 100)
        elif type_ == 'number':
            return round(random.uniform(1, 100), 2)
        elif type_ == 'boolean':
            return random.choice([True, False])
        else:  # string
            if 'format' in schema:
                if schema['format'] == 'email':
                    return f"user{self._nonce()}@example.com"
                elif schema['format'] == 'date-time':
                    return datetime.now().isoformat()
            return "example_" + self._nonce()

    def _get_auth_headers(self, endpoint_spec: dict) -> dict:
        """Extract required auth headers from Swagger"""
        headers = {}
        if 'security' in endpoint_spec and self.swagger_spec:
            for sec_req in endpoint_spec['security']:
                for scheme_name in sec_req.keys():
                    if 'securityDefinitions' in self.swagger_spec and scheme_name in self.swagger_spec['securityDefinitions']:
                        scheme = self.swagger_spec['securityDefinitions'][scheme_name]
                        if scheme['type'] == 'apiKey' and scheme['in'] == 'header':
                            headers[scheme['name']] = f"Bearer {self._nonce()}"
        return headers

    def load_flows_file(self, path: str) -> List[Flow]:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f"Flows file not found: {path}")
        if p.suffix.lower() in {".yml", ".yaml"}:
            import yaml
            return yaml.safe_load(p.read_text(encoding="utf-8"))
        else:
            return json.loads(p.read_text(encoding="utf-8"))

    def discover_business_flows(self) -> List[Flow]:
        candidates = [
            ("ticket_purchase", "/tickets/buy", "POST"),
            ("order_checkout", "/checkout", "POST"),
            ("comment_post", "/comments", "POST"),
            ("subscription", "/subscribe", "POST"),
            ("payment", "/payments", "POST"),
            ("transfer", "/transfer", "POST"),
        ]
        flows: List[Flow] = []
        for name, path, method in candidates:
            url = self._abs_url(path)
            try:
                r = self.session.options(url, timeout=3)
                if r.status_code < 500:
                    flows.append({
                        "name": name,
                        "url": path,
                        "method": method,
                        "body": self._get_smart_body({}),
                        "headers": {}
                    })
            except Exception:
                continue
        return flows

    def test_business_flows(self, flows: List[Flow]) -> List[Issue]:
        """Main entry point for testing business flows. Compatible with apiscan.py"""
        self._issues.clear()  # Reset issues for each test run

        # Skip-login/auth related endpoints
        SKIP_KEYWORDS = [
            "/login", "/signup", "/sign-in", "/sign_in", "/signin",
            "/auth", "/oauth", "/token", "/check-otp", "/verify", "/session",
            "/forget-password", "/forgot-password", "/reset-password",
            "/microsoft", "/azure", "/aws", "/cognito", "/okta", "/sso", "/idp",
            "/google", "/apple", "/login.microsoftonline.com", "/accounts.google.com"
        ]
        
        for flow in flows:
            try:
                # Skip flow if URL contains auth/cloud keywords
                url = flow.get("url", "").lower()
                if any(keyword in url for keyword in SKIP_KEYWORDS):
                    print(f"[SKIPPED] Skipping auth/cloud-related endpoint: {url}")
                    continue

                # Ensure flow has minimum required fields
                if not all(k in flow for k in ['url', 'method']):
                    continue

                self._run_tests_for_flow({
                    'name': flow.get('name', f"{flow['method']}_{flow['url']}"),
                    'url': flow['url'],
                    'method': flow['method'],
                    'body': flow.get('body', {}),
                    'headers': flow.get('headers', {}),
                    'params': flow.get('params', {})
                })
            except Exception as e:
                print(f"Error testing flow {flow.get('name')}: {e}")

        return self._issues



    def _filtered_issues(self) -> List[Issue]:
        uniq = {}
        for it in self._issues:
            sc = it.get("status_code")
            if not self._is_processed(type("Resp", (), {"status_code": sc})):
                continue  # skip 404/422/500 noise
            key = (it["endpoint"], it["description"], sc)
            uniq.setdefault(key, it)
        return list(uniq.values())

        
    def _log(self,flow: Flow,desc: str,sev: str,req: Optional[dict] = None,resp: Optional[requests.Response] = None,) -> None:
        """Voeg --n bevinding toe; sla over bij ontbrekend HTTP-antwoord."""
        # Skip wanneer er geen of een -0--response is
        if resp is None or getattr(resp, "status_code", 0) in (0, None):
            return

        url = self._abs_url(flow["url"])

        entry: Issue = {
            "url": url,
            "endpoint": url,
            "method": flow.get("method", "POST"),
            "description": desc,
            "severity": sev,
            "status_code": getattr(resp, "status_code", None),
            "timestamp": datetime.now().isoformat(),
            "request_headers": {},
            "request_body": None,
            "response_headers": {},
            "response_body": "",
            "request_cookies": {},
            "response_cookies": {},
        }

        # Vul request/response-velden als die aanwezig zijn
        if resp is not None:
            entry["response_headers"] = dict(resp.headers)
            entry["response_body"] = resp.text[:2048]
            entry["response_cookies"] = resp.cookies.get_dict()
            if resp.request is not None:
                entry["request_headers"] = dict(resp.request.headers)
                entry["request_body"] = resp.request.body
                entry["request_cookies"] = self.session.cookies.get_dict()
                
        if req:
            entry["request"] = req

        # Thread-safe toevoegen
        with self._lock:
            self._issues.append(entry)
            print(f"[ISSUE] {entry['method']} {entry['url']} - {entry['description']} (Severity: {entry['severity']})")


    def _run_tests_for_flow(self, flow: Flow):
        print(f"[FLOW] Executing tests for: {flow['method']} {flow['url']}")
        for test in (
            self._test_auth_bypass,
            self._test_replay_attack,
            self._test_csrf_protection,
            self._test_concurrency,
            self._test_duplicate_submission,
            self._test_price_manipulation,
            self._test_coupon_bruteforce,
            self._test_rate_limit_sequential,
            self._test_method_override,
            self._test_field_pollution,
        ):
            try:
                test(flow)
            except Exception as exc:
                self._log(flow, f"Test error: {exc}", "Medium")

    def _get_smart_body(self, original_body: dict) -> dict:
        """Generate realistic test values for common fields."""
        if original_body:
            return original_body
        
        smart_defaults = {
            "email": f"user{self._nonce()}@example.com",
            "amount": 100,
            "quantity": 1,
            "product_id": "prod_" + self._nonce(),
            "user_id": "user_" + self._nonce(),
            "card_number": "4242424242424242",
            "name": "Test User",
            "description": "Security test transaction"
        }
        
        return smart_defaults

    def _send(self, flow: Flow, *, body: Optional[Dict[str, Any]] = None, override_method: Optional[str] = None) -> Optional[requests.Response]:
        url = self._abs_url(flow["url"])
        method = (override_method or flow.get("method", "POST")).upper()
        headers = {**flow.get("headers", {}), "X-Audit-Nonce": self._nonce()}
        params = flow.get("params", {})
        
        # Merge generated body with test body
        final_body = {**self._get_smart_body(flow.get("body", {})), **(body or {})}

        # Define sensitive endpoints that need special handling
        sensitive_keywords = {"signup", "register", "payment", "transfer", "buy", "checkout", "subscribe"}
        
        # Adjust timeout and concurrency for sensitive endpoints
        current_timeout = self.timeout
        if self.db_errors_detected:
            print(f"[SKIPPED] {url} -  database issues")
            return None
            
        
        if any(kw in url.lower() for kw in sensitive_keywords):
            current_timeout = 10  # Longer timeout for sensitive endpoints

        try:
            # Add small jitter to prevent synchronized bursts
            time.sleep(random.uniform(0.01, 0.1))

            if method == "GET":
                return self.session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=current_timeout
                )

            return self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=final_body,
                timeout=current_timeout,
            )

        except requests.exceptions.ReadTimeout:
            print(f"[TIMEOUT] No response from {url} after {current_timeout} seconds.")
            return None

        except requests.exceptions.ConnectionError:
            print(f"[CONNECTION ERROR] Failed to connect to {url}")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed for {url}: {e}")
            return None


    def _extract_id(self, resp: Optional[requests.Response]) -> Optional[str]:
        if not resp:
            return None
        try:
            data = resp.json()
            for k in ("id", "order_id", "ticket_id", "transaction_id", "payment_id"):
                if k in data:
                    return str(data[k])
        except Exception:
            pass
        return None

    def _test_auth_bypass(self, flow: Flow):
        """Test if the endpoint works without authentication headers."""
        original_headers = flow.get("headers", {})
        
        clean_headers = {k: v for k, v in original_headers.items() 
                        if k.lower() not in self.AUTH_HEADERS}
        
        modified_flow = {**flow, "headers": clean_headers}
        r = self._send(modified_flow)
        
        if r and r.status_code == 200:
            self._log(flow, "Authentication bypass possible - request succeeded without auth headers", "Critical", resp=r)

    def _test_replay_attack(self, flow: Flow):
        """Test if the same request can be replayed with identical results."""
        r1 = self._send(flow)
        if not r1 or r1.status_code != 200:
            return
        
        # Clone the original request including headers/body
        cloned_flow = {**flow, "headers": {**flow.get("headers", {})}}
        r2 = self._send(cloned_flow)
        
        if r2 and r2.status_code == 200:
            id1 = self._extract_id(r1)
            id2 = self._extract_id(r2)
            if id1 and id2 and id1 == id2:
                self._log(flow, "Replay attack possible - identical transaction ID", "Critical", resp=r2)
            elif id2:
                self._log(flow, "Replay attack possible - new transaction created", "High", resp=r2)

    def _test_csrf_protection(self, flow: Flow):
        """Check if endpoint is vulnerable to CSRF by testing without referer/origin."""
        original_headers = flow.get("headers", {})
        modified_headers = {k: v for k, v in original_headers.items()
                          if k.lower() not in {"origin", "referer"}}
        modified_flow = {**flow, "headers": modified_headers}
        r = self._send(modified_flow)
        if r and r.status_code == 200:
            self._log(flow, "Missing CSRF protection - request succeeded without Origin/Referer", "High", resp=r)

    def _test_concurrency(self, flow: Flow):
        def _invoke():
            return self._send(flow)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            responses = [f.result() for f in as_completed(pool.submit(_invoke) for _ in range(self.concurrency))]

        processed = [r for r in responses if self._is_processed(r)]
        if processed and len(processed) == self.concurrency:
            self._log(flow, f"No throttling at {self.concurrency} parallel *processed* requests", "High", resp=processed[0])


    def _test_duplicate_submission(self, flow: Flow):
        r1 = self._send(flow)
        time.sleep(0.5)
        r2 = self._send(flow)

        ids = {self._extract_id(r) for r in (r1, r2) if r}
        if len(ids) == 2:
            self._log(flow, "Duplicate submission accepted (missing idempotency)", "Medium", resp=r2)

    def _test_price_manipulation(self, flow: Flow):
        payload = flow.get("body", {})
        if not (self.PRICE_KEYS & payload.keys()):
            payload = self._get_smart_body(payload)
            
        for value in [0, -1, 0.01, 999999999]:
            manipulated = {**payload}
            for k in self.PRICE_KEYS & manipulated.keys():
                manipulated[k] = value
            r = self._send(flow, body=manipulated)
            if r and r.status_code == 200:
                self._log(flow, f"Price manipulation: {value} accepted", 
                        "Critical" if value <= 0 else "High", 
                        manipulated, r)

    def _test_coupon_bruteforce(self, flow: Flow):
        body = flow.get("body", {})
        if "coupon" not in body:
            body = self._get_smart_body(body)
            
        for _ in range(20):
            coupon = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if coupon in self._tested_coupons:
                continue
                
            self._tested_coupons.add(coupon)
            attempt = {**body, "coupon": coupon}
            r = self._send(flow, body=attempt)
            if r and r.status_code == 200:
                self._log(flow, f"Coupon brute-force succeeded: {coupon}", "High", attempt, r)
                break

    def _test_rate_limit_sequential(self, flow: Flow):
        """
        Max 25 opeenvolgende verzoeken:
        * Stop zodra we een 429/503 zien  - goed afgebroken
        * Stop zodra we een niet-verwerkte fout zien (404/422/5xx) - test niet relevant
        * Log pas een issue wanneer er minstens --n _verwerkt_ antwoord was
            en we t-ch geen 429/503 kregen.
        """
        processed_seen = False
        for _ in range(25):
            r = self._send(flow)
            if not r:
                continue

            if r.status_code in {429, 503}:
                return  # rate-limiting aanwezig

            if not self._is_processed(r):
                # Endpoint werd niet echt uitgevoerd; test ongeldig
                return

            processed_seen = True

        if processed_seen:
            self._log(
                flow,
                "No rate-limiting after 25 rapid *processed* requests",
                "Medium",
                resp=r,
            )


    def _test_method_override(self, flow: Flow):
        for verb in ("PUT", "DELETE", "PATCH"):
            r = self._send(flow, override_method=verb)
            if r and r.status_code == 200:
                self._log(flow, f"Method override to {verb} allowed", "Medium", resp=r)
                break

    def _test_field_pollution(self, flow: Flow):
        body = self._get_smart_body(flow.get("body", {}))
        noisy = {**body, "__polluted": "yes", "polluted_field": True}
        r = self._send(flow, body=noisy)
        if r and r.status_code == 200:
            self._log(flow, "Unexpected field accepted", "Low", noisy, r)


    def generate_report(self, fmt: str = "html") -> str:
            gen = ReportGenerator(
                self._filtered_issues(),
                scanner="API6:2023 - Sensitive Business Flows",   # titel in header
                base_url=self.base_url,
            )
            return gen.generate_html() if fmt == "html" else gen.generate_markdown()
        
    
    
    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(
            self._filtered_issues(),
            scanner="API6:2023 - Sensitive Business Flows",
            base_url=self.base_url,
        ).save(path, fmt=fmt)