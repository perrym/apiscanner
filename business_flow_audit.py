########################################################
# APISCAN - API Security Scanner                       #
# Licensed under AGPL-V3.0                             #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.0  26-11--2025                             #
########################################################                                
from __future__ import annotations
import argparse
import json
import random
import string
import threading
import time
import re
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from tqdm import tqdm
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
from report_utils import ReportGenerator
import requests

from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig,
)
Flow = Dict[str, Any]
Issue = Dict[str, Any]
SideEffectChecker = Callable[[requests.Response], bool]



class BusinessFlowAuditor:
    DEFAULT_HEADERS = {'User-Agent': 'BusinessFlowAuditor/2.2'}
    AUTH_HEADERS = {'authorization', 'x-api-key', 'token', 'x-auth-token'}
    PRICE_KEYS = {'price', 'amount', 'total', 'cost', 'value', 'sum'}
    SENSITIVE_PARAMS = {'password', 'secret', 'token', 'creditcard', 'cvv'}

    # ----------------------- Funtion __init__ ----------------------------#
    def __init__(
        self,
        session: requests.Session,
        *,
        base_url: str,
        concurrency: int = 3,
        timeout: int = 6,
        swagger_spec: Optional[dict] = None,
        show_progress: bool = True,
        default_headers: Optional[Dict[str, str]] = None,
        flow: Optional[str] = None,
    ) -> None:
        if session is None:
            raise ValueError("Session is required")
        if not base_url or not isinstance(base_url, str):
            raise ValueError("base_url is required")

        self.session = session
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.concurrency = concurrency
        self.show_progress = show_progress
        self.flow = (flow or "none").lower()

        hdrs = dict(default_headers or getattr(self, "DEFAULT_HEADERS", {}))
        hdrs.pop("Authorization", None)
        if hdrs:
            self.session.headers.update(hdrs)

        self._issues: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._tested_coupons: Set[str] = set()
        self.swagger_spec = swagger_spec
        self._endpoint_cache: Dict[Tuple[str, str], dict] = {}
        self.db_errors_detected = False

        self._respect_session_auth = True
        self._forbid_local_auth_headers = True

        self.spec: Dict[str, Any] = self.swagger_spec or {}

        self._op_index: Dict[Tuple[str, str], dict] = {}
        for _op in oas_iter_ops(self.spec):
            self._op_index[(_op["method"], _op["path"])] = _op

        self._op_shape_index: Dict[Tuple[str, str], dict] = {}
        for (m, p), op in self._op_index.items():
            self._op_shape_index[(m, self._canonical_path(p))] = op


    def _canonical_path(self, p: str) -> str:
        p = "/" + (p or "").lstrip("/")
        return re.sub(r"\{[^}]+\}", "{}", p)


    def _tw(self, msg: str) -> None:
        try:
            if getattr(self, "show_progress", False):
                tqdm.write(msg)
            else:
                print(msg)
        except Exception:
            print(msg)


    def _abs_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    def check_db_health(self) -> None:
        try:
            r = self.session.get(f"{self.base_url}health/db", timeout=2)
            if r.status_code != 200:
                self.db_errors_detected = True
        except Exception:
            self.db_errors_detected = True


    def _nonce(self) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    # ----------------------- Funtion load_swagger ----------------------------#
    def load_swagger(self, swagger_url: str) -> List[Flow]:
        try:
            resp = self.session.get(swagger_url, timeout=10)
            resp.raise_for_status()
            self.swagger_spec = spec = resp.json()
            flows = []
            base_path = spec.get('basePath', '')
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                full_path = f'{base_path}{path}'
                for method, details in methods.items():
                    method = method.upper()
                    if method in {'POST', 'PUT', 'PATCH'}:
                        flow = {'name': details.get('operationId', f"{method}_{path.strip('/').replace('/', '_')}").lower(), 'url': full_path, 'method': method, 'body': self._generate_body_from_schema(details), 'headers': self._get_auth_headers(details), 'params': self._generate_params_from_schema(details), 'metadata': details}
                        flows.append(flow)
                        self._endpoint_cache[method, full_path] = details
            return flows
        except Exception as e:
            self._tw(f'[ERR] Swagger load: {e}')
            return []

    def _generate_body_from_schema(self, endpoint_spec: dict) -> dict:
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
        params = {}
        if 'parameters' in endpoint_spec:
            for param in endpoint_spec['parameters']:
                if param.get('in') == 'query' and 'name' in param:
                    params[param['name']] = self._generate_example_value(param)
        return params

    def _generate_example_value(self, schema: dict) -> Any:
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
        else:
            if 'format' in schema:
                if schema['format'] == 'email':
                    return f'user{self._nonce()}@example.com'
                elif schema['format'] == 'date-time':
                    return datetime.now().isoformat()
            return 'example_' + self._nonce()

    def _get_auth_headers(self, endpoint_spec: dict) -> dict:
        headers = {}
        if 'security' in endpoint_spec and self.swagger_spec:
            for sec_req in endpoint_spec['security']:
                for scheme_name in sec_req.keys():
                    if 'securityDefinitions' in self.swagger_spec and scheme_name in self.swagger_spec['securityDefinitions']:
                        scheme = self.swagger_spec['securityDefinitions'][scheme_name]
                        if scheme['type'] == 'apiKey' and scheme['in'] == 'header':
                            headers[scheme['name']] = f'Bearer {self._nonce()}'
        return headers

    def load_flows_file(self, path: str) -> List[Flow]:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f'Flows file not found: {path}')
        if p.suffix.lower() in {'.yml', '.yaml'}:
            import yaml
            return yaml.safe_load(p.read_text(encoding='utf-8'))
        else:
            return json.loads(p.read_text(encoding='utf-8'))

    # ----------------------- Funtion discover_business_flows ----------------------------#
    def discover_business_flows(self) -> List[Flow]:
        candidates = [('ticket_purchase', '/tickets/buy', 'POST'), ('order_checkout', '/checkout', 'POST'), ('comment_post', '/comments', 'POST'), ('subscription', '/subscribe', 'POST'), ('payment', '/payments', 'POST'), ('transfer', '/transfer', 'POST')]
        flows: List[Flow] = []
        for name, path, method in candidates:
            url = self._abs_url(path)
            try:
                r = self.session.options(url, timeout=3)
                if r.status_code < 500:
                    flows.append({'name': name, 'url': path, 'method': method, 'body': self._get_smart_body({}), 'headers': {}})
            except Exception:
                continue
        return flows

    # ----------------------- Funtion test_business_flows ----------------------------#
    def test_business_flows(self, flows: List[Flow]) -> List[Issue]:
        self._issues.clear()
        SKIP_KEYWORDS = ['/login', '/signup', '/sign-in', '/sign_in', '/signin', '/auth', '/oauth', '/token', '/check-otp', '/verify', '/session', '/forget-password', '/forgot-password', '/reset-password', '/microsoft', '/azure', '/aws', '/cognito', '/okta', '/sso', '/idp', '/google', '/apple', '/login.microsoftonline.com', '/accounts.google.com']
        iterator = tqdm(flows, desc='API6 flows', unit='flow') if self.show_progress else flows
        for flow in iterator:
            try:
                url = flow.get('url', '').lower()
                if any((keyword in url for keyword in SKIP_KEYWORDS)):
                    self._tw(f'[SKIPPED] Auth/cloud endpoint: {url}')
                    continue
                if not all((k in flow for k in ['url', 'method'])):
                    continue
                self._run_tests_for_flow({'name': flow.get('name', f"{flow['method']}_{flow['url']}"), 'url': flow['url'], 'method': flow['method'], 'body': flow.get('body', {}), 'headers': flow.get('headers', {}), 'params': flow.get('params', {})})
            except Exception as e:
                self._tw(f"[ERR] Flow {flow.get('name')}: {e}")
        return self._issues

    # ----------------------- Funtion _filtered_issues ----------------------------#
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        uniq: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        for it in self._issues:
            sc = it.get("status_code")
            try:
                code = int(sc)
            except Exception:
                continue
            if code in (0, 400, 404, 405) or (500 <= code < 600):
                continue
            if not (200 <= code < 300):
                continue
            key = (it.get("endpoint"), it.get("description"), code)
            uniq.setdefault(key, it)
        return list(uniq.values())

    def _log(self, flow: Flow, desc: str, sev: str, req: Optional[dict]=None, resp: Optional[requests.Response]=None) -> None:
        if resp is None or getattr(resp, 'status_code', 0) in (0, None):
            return
        url = self._abs_url(flow['url'])
        entry: Issue = {'url': url, 'endpoint': url, 'method': flow.get('method', 'POST'), 'description': desc, 'severity': sev, 'status_code': getattr(resp, 'status_code', None), 'timestamp': datetime.now().isoformat(), 'request_headers': {}, 'request_body': None, 'response_headers': {}, 'response_body': '', 'request_cookies': {}, 'response_cookies': {}}
        if resp is not None:
            entry['response_headers'] = dict(resp.headers)
            entry['response_body'] = resp.text[:2048]
            entry['response_cookies'] = resp.cookies.get_dict()
            if resp.request is not None:
                entry['request_headers'] = dict(resp.request.headers)
                entry['request_body'] = resp.request.body
                entry['request_cookies'] = self.session.cookies.get_dict()
        if req:
            entry['request'] = req
        with self._lock:
            self._issues.append(entry)
            self._tw(f"[ISSUE] {entry['method']} {entry['url']} - {entry['description']} (Severity: {entry['severity']})")
    # ----------------------- Funtion _run_tests_for_flow ----------------------------#
    def _run_tests_for_flow(self, flow: Flow):
        for test in (self._test_auth_bypass, self._test_replay_attack, self._test_csrf_protection, self._test_concurrency, self._test_duplicate_submission, self._test_price_manipulation, self._test_coupon_bruteforce, self._test_rate_limit_sequential, self._test_method_override, self._test_field_pollution):
            try:
                test(flow)
            except Exception as exc:
                self._log(flow, f'Test error: {exc}', 'Medium')

    def _get_smart_body(self, original_body: dict) -> dict:
        if original_body:
            return original_body
        smart_defaults = {'email': f'user{self._nonce()}@example.com', 'amount': 100, 'quantity': 1, 'product_id': 'prod_' + self._nonce(), 'user_id': 'user_' + self._nonce(), 'card_number': '4242424242424242', 'name': 'Test User', 'description': 'Security test transaction'}
        return smart_defaults
    

    def _extract_id(self, resp: Optional[requests.Response]) -> Optional[str]:
        if not resp:
            return None
        try:
            data = resp.json()
            for k in ('id', 'order_id', 'ticket_id', 'transaction_id', 'payment_id'):
                if k in data:
                    return str(data[k])
        except Exception:
            pass
        return None

    # ----------------------- Funtion _send ----------------------------#
    def _send(
        self,
        flow_or_method,
        path_template: Optional[str] = None,
        *,
        body: Optional[dict] = None,
        override_method: Optional[str] = None,
        cfg: Optional[SecurityConfig] = None,
    ) -> Optional[requests.Response]:
        import requests
        from urllib.parse import urlparse, urljoin

        if getattr(self, "db_errors_detected", False):
            self._tw("Database issue detected earlier; proceeding cautiously.")

        if isinstance(flow_or_method, dict):
            flow = flow_or_method
            method = (override_method or flow.get("method") or "POST").upper()
            raw = flow.get("url") or ""
            path = urlparse(raw).path if raw.startswith(("http://", "https://")) else raw
            path = "/" + path.lstrip("/")

            hdrs = dict(flow.get("headers") or {})
            params = flow.get("params") or {}
            json_body = body if body is not None else (flow.get("json") or flow.get("body"))
            files = flow.get("files")

            op = self._op_index.get((method, path))
            if not op:
                op = self._op_shape_index.get((method, self._canonical_path(path)))

            if op:
                req = oas_build_request(self.spec, self.base_url, op, cfg)
                if hdrs:
                    req["headers"].update({k: v for k, v in hdrs.items() if k.lower() != "authorization"})
                if params:
                    req["params"].update(params)
                if json_body is not None:
                    req["json"] = json_body
                if files is not None:
                    req["files"] = files
            else:
                req = {
                    "method": method,
                    "url": self._abs_url(path),
                    "headers": {k: v for k, v in hdrs.items() if k.lower() != "authorization"},
                    "params": params,
                    "json": json_body,
                    "files": files,
                }
        else:
            method = (override_method or str(flow_or_method)).upper()
            path = path_template or ""
            req = self._req_from_spec(method, path, cfg=cfg)
            if body is not None:
                req["json"] = body

        try:
            self._tw(f"[FLOW] {req.get('method')} {req.get('url')}")
        except Exception:
            pass

        try:
            return self.session.request(**req, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            self._tw(f"[ERROR] Request failed for {req.get('url')}: {e}")
            return None


    # ----------------------- Funtion _test_auth_bypass ----------------------------#
    def _test_auth_bypass(self, flow: Flow):
        original_headers = flow.get('headers', {})
        clean_headers = {k: v for k, v in original_headers.items() if k.lower() not in self.AUTH_HEADERS}
        modified_flow = {**flow, 'headers': clean_headers}
        r = self._send(modified_flow)
        if r and r.status_code == 200:
            self._log(flow, 'Authentication bypass possible - request succeeded without auth headers', 'Critical', resp=r)

    # ----------------------- Funtion _test_replay_attack ----------------------------#
    def _test_replay_attack(self, flow: Flow):
        r1 = self._send(flow)
        if not r1 or r1.status_code != 200:
            return
        cloned_flow = {**flow, 'headers': {**flow.get('headers', {})}}
        r2 = self._send(cloned_flow)
        if r2 and r2.status_code == 200:
            id1 = self._extract_id(r1)
            id2 = self._extract_id(r2)
            if id1 and id2 and (id1 == id2):
                self._log(flow, 'Replay attack possible - identical transaction ID', 'Critical', resp=r2)
            elif id2:
                self._log(flow, 'Replay attack possible - new transaction created', 'High', resp=r2)

    # ----------------------- Funtion _test_csrf_protection ----------------------------#
    def _test_csrf_protection(self, flow: Flow):
        original_headers = flow.get('headers', {})
        modified_headers = {k: v for k, v in original_headers.items() if k.lower() not in {'origin', 'referer'}}
        modified_flow = {**flow, 'headers': modified_headers}
        r = self._send(modified_flow)
        if r and r.status_code == 200:
            self._log(flow, 'Missing CSRF protection - request succeeded without Origin/Referer', 'High', resp=r)

    # ----------------------- Funtion _test_concurrency ----------------------------#
    def _test_concurrency(self, flow: Flow):

        def _invoke():
            return self._send(flow)
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            responses = [f.result() for f in as_completed((pool.submit(_invoke) for _ in range(self.concurrency)))]
        ok = [r for r in responses if (r is not None and 200 <= getattr(r, 'status_code', 0) < 300)]
        if len(ok) == self.concurrency:
            self._log(flow, f'No throttling at {self.concurrency} parallel *processed* requests', 'High', resp=ok[0])

    # ----------------------- Funtion _test_duplicate_submission ----------------------------#
    def _test_duplicate_submission(self, flow: Flow):
        r1 = self._send(flow)
        time.sleep(0.5)
        r2 = self._send(flow)
        ids = {self._extract_id(r) for r in (r1, r2) if r}
        if len(ids) == 2:
            self._log(flow, 'Duplicate submission accepted (missing idempotency)', 'Medium', resp=r2)

    # ----------------------- Funtion _test_price_manipulation ----------------------------#
    def _test_price_manipulation(self, flow: Flow):
        payload = flow.get('body', {})
        if not self.PRICE_KEYS & payload.keys():
            payload = self._get_smart_body(payload)
        for value in [0, -1, 0.01, 999999999]:
            manipulated = {**payload}
            for k in self.PRICE_KEYS & manipulated.keys():
                manipulated[k] = value
            r = self._send(flow, body=manipulated)
            if r and r.status_code == 200:
                self._log(flow, f'Price manipulation: {value} accepted', 'Critical' if value <= 0 else 'High', manipulated, r)

    # ----------------------- Funtion _test_coupon_bruteforce ----------------------------#
    def _test_coupon_bruteforce(self, flow: Flow):
        body = flow.get('body', {})
        if 'coupon' not in body:
            body = self._get_smart_body(body)
        for _ in range(20):
            coupon = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if coupon in self._tested_coupons:
                continue
            self._tested_coupons.add(coupon)
            attempt = {**body, 'coupon': coupon}
            r = self._send(flow, body=attempt)
            if r and r.status_code == 200:
                self._log(flow, f'Coupon brute-force succeeded: {coupon}', 'High', attempt, r)
                break

    # ----------------------- Funtion _test_rate_limit_sequential ----------------------------#
    def _test_rate_limit_sequential(self, flow: Flow):
        processed_seen = False
        for _ in range(25):
            r = self._send(flow)
            if not r:
                continue
            if r.status_code in {429, 503}:
                return
            if not self._is_processed(r):
                return
            processed_seen = True
        if processed_seen:
            self._log(flow, 'No rate-limiting after 25 rapid *processed* requests', 'Medium', resp=r)

    # ----------------------- Funtion _test_method_override ----------------------------#
    def _test_method_override(self, flow: Flow):
        for verb in ('PUT', 'DELETE', 'PATCH'):
            r = self._send(flow, override_method=verb)
            if r and r.status_code == 200:
                self._log(flow, f'Method override to {verb} allowed', 'Medium', resp=r)
                break

    # ----------------------- Funtion _test_field_pollution ----------------------------#
    def _test_field_pollution(self, flow: Flow):
        body = self._get_smart_body(flow.get('body', {}))
        noisy = {**body, '__polluted': 'yes', 'polluted_field': True}
        r = self._send(flow, body=noisy)
        if r and r.status_code == 200:
            self._log(flow, 'Unexpected field accepted', 'Low', noisy, r)

    # ----------------------- Funtion generate_report ----------------------------#
    def generate_report(self, fmt: str='html') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='API6:2023 - Sensitive Business Flows', base_url=self.base_url)
        return gen.generate_html() if fmt == 'html' else gen.generate_markdown()

    # ----------------------- Funtion _req_from_spec ----------------------------#
    def _req_from_spec(self, method: str, path_template: str, cfg: Optional[SecurityConfig] = None) -> Dict[str, Any]:
        key = (method.upper(), path_template)
        op = self._op_index.get(key)
        if not op:
            shape = self._canonical_path(path_template)
            op = self._op_shape_index.get((method.upper(), shape))
        if not op:
            raise KeyError(f"Operation not found: {method} {path_template}")
        return oas_build_request(self.spec, self.base_url, op, cfg)


    # ----------------------- Funtion _is_processed ----------------------------#
    def _is_processed(self, resp: Optional[requests.Response]) -> bool:
        if resp is None:
            return False
        sc = getattr(resp, "status_code", None)
        return isinstance(sc, int) and 200 <= sc < 300


    # ----------------------- Funtion save_report ----------------------------#
    def save_report(self, path: str, fmt: str='html') -> None:
        ReportGenerator(self._filtered_issues(), scanner='API6:2023 - Sensitive Business Flows', base_url=self.base_url).save(path, fmt=fmt)
