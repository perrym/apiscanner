##############################################
# APISCAN - API Security Scanner             #
# Licensed under the MIT License             #
# Author: Perry Mertens (2025)               #
##############################################

import json
import re
import requests
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from requests import Request, exceptions as req_exc
from tqdm import tqdm

from report_utils import ReportGenerator

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- Helpers ------------------
def _is_real_issue(issue: dict) -> bool:
    try:
        return int(issue.get("status_code", 0)) != 0
    except (ValueError, TypeError):
        return False

def _headers_to_list(hdrs):
    if hasattr(hdrs, "getlist"):
        out = []
        for k in hdrs:
            for v in hdrs.getlist(k):
                out.append((k, v))
        return out
    return list(hdrs.items())

def classify_risk(status_code: int, response_body: str = "", sensitive: bool = False, size_alert: bool = False, cross_user: bool = False) -> str:
    if status_code == 200 and (sensitive or cross_user or size_alert):
        return "High"
    if status_code == 200:
        return "Medium"
    if status_code == 403:
        return "Low"
    if 500 <= status_code < 600:
        return "Low"
    if status_code == 0:
        return "Ignore"
    return "Low"

# ---------------- Data Classes -------------
@dataclass
class TestResult:
    test_case: str = ""
    method: str = ""
    url: str = ""
    status_code: int = 0
    response_time: float = 0.0
    is_vulnerable: bool = False
    response_sample: str = ""
    request_sample: str = ""
    params: dict = field(default_factory=dict)
    headers: list = field(default_factory=list)
    response_headers: list = field(default_factory=list)
    request_cookies: dict = field(default_factory=dict)
    response_cookies: dict = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: str = ""
    request_body: str = ""
    sensitive_hit: bool = False
    size_alert: bool = False
    cross_user: bool = False

    def to_dict(self):
        return {
            "method": self.method,
            "url": self.url,
            "endpoint": self.url,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "description": self.test_case,
            "severity": classify_risk(
                self.status_code,
                self.response_sample,
                sensitive=self.sensitive_hit,
                size_alert=self.size_alert,
                cross_user=self.cross_user
            ),
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "request_parameters": self.params or {},
            "request_headers": self.headers or [],
            "request_cookies": self.request_cookies or {},
            "request_body": self.request_sample,
            "response_headers": self.response_headers or [],
            "response_cookies": self.response_cookies or {},
            "response_body": (str(self.response_sample) if self.response_sample else "")
        }

# ---------------- Auditor ------------------
class BOLAAuditor:
    def __init__(self, session, test_delay=0.2, max_retries=1, show_subbars=True):
        self.session = session
        self.issues: List[dict] = []
        self.object_key_patterns = [
            r'(?:^|_)id$', r'uuid$', r'_id$', r'key$',
            r'email$', r'token$', r'slug$',
            r'user', r'account', r'profile'
        ]
        self.sensitive_data_patterns = [
            r'email', r'password', r'token',
            r'auth', r'admin', r'credit.?card', r'phone',
            r'secret', r'private', r'personal'
        ]
        self.test_delay = test_delay
        self.max_retries = max_retries
        self.base_url = ""
        self.show_subbars = show_subbars

    def load_swagger(self, swagger_path: str) -> Optional[Dict]:
        try:
            path = Path(swagger_path)
            if not path.exists():
                logger.error(f"Swagger file not found: {swagger_path}")
                return None
            spec = json.loads(path.read_text(encoding="utf-8"))
            logger.info(f"Swagger loaded: {len(spec.get('paths', {}))} endpoints found")
            return spec
        except Exception as e:
            logger.error(f"Error loading Swagger: {e}", exc_info=True)
            return None

    def get_object_endpoints(self, swagger_spec: Dict) -> List[Dict]:
        endpoints: List[Dict] = []
        paths = swagger_spec.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_params = path_item.get("parameters", [])
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"] or not isinstance(operation, dict):
                    continue
                all_params = path_params + operation.get("parameters", [])
                object_params = self._find_object_params(all_params)
                rb = operation.get("requestBody", {})
                content = rb.get("content", {})
                if "application/json" in content:
                    schema = content["application/json"].get("schema", {}) or {}
                    for prop, prop_schema in (schema.get("properties", {}) or {}).items():
                        if any(re.search(pat, prop.lower()) for pat in self.object_key_patterns):
                            object_params.append({
                                "name": prop,
                                "in": "body",
                                "required": prop in (schema.get("required", []) or []),
                                "type": prop_schema.get("type", "string"),
                                "format": prop_schema.get("format", ""),
                                "description": prop_schema.get("description", "")
                            })
                if object_params:
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "parameters": object_params,
                        "operation_id": operation.get("operationId", ""),
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", ""),
                        "security": operation.get("security", [])
                    })
        logger.info(f"Object endpoints detected: {len(endpoints)}")
        return endpoints

    def _find_object_params(self, parameters: List[Dict]) -> List[Dict]:
        obj = []
        for param in parameters or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").lower()
            if any(re.search(pat, name) for pat in self.object_key_patterns):
                schema = param.get("schema", {}) or {}
                obj.append({
                    "name": param.get("name", ""),
                    "in": param.get("in", ""),
                    "required": param.get("required", False),
                    "type": schema.get("type", "string"),
                    "format": schema.get("format", ""),
                    "description": param.get("description", "")
                })
        return obj

    def _generate_test_values(self, parameters: List[Dict]) -> Dict[str, Dict]:
        base_values = {
            "valid": "1",
            "other_user": "2",
            "string": "testuser",
            "empty": "",
            "null": "null",
            "urlenc_null": "%00",
            "urlenc_dotdot": "%2e%2e%2f",
            "unicode_homoglyph": "\u13B0\u13B1",
            "sqlish": '" OR "1"="1"--',
            "non_existent": "99999",
            "random_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "admin_user": "admin",
            "high_value": "1000000"
        }
        type_vals = {
            "integer": {"negative": "-1", "zero": "0", "large": "2147483647"},
            "string": {"long": "A" * 1000, "special_chars": "!@#$%^&*()"}
        }
        cases: Dict[str, Dict] = {}
        for n, v in base_values.items():
            cases[n] = {p["name"]: v for p in parameters}
        for p in parameters:
            ptype = p.get("type", "string")
            if ptype in type_vals:
                for n, v in type_vals[ptype].items():
                    cname = f"{ptype}_{n}"
                    cases[cname] = {
                        q["name"]: (v if q.get("type") == ptype else base_values["valid"])
                        for q in parameters
                    }
        return cases

    def test_endpoint(self, base_url: str, endpoint: Dict, *, progress_position: int | None = None) -> List[TestResult]:
        results: List[TestResult] = []
        if not endpoint.get("parameters"):
            return results
        cases = self._generate_test_values(endpoint["parameters"])
        desc = f"{endpoint['method']} {endpoint['path']}"
        it = cases.items()
        if self.show_subbars:
            it = tqdm(
                it,
                desc=desc,
                unit="case",
                leave=False,
                position=(progress_position if progress_position is not None else 1),
                dynamic_ncols=True,
            )
        for name, vals in it:
            time.sleep(self.test_delay)
            results.append(self._test_object_access(base_url, endpoint, name, vals))
        return results

    def _send_with_retry(self, prepared: requests.PreparedRequest) -> tuple[Optional[requests.Response], float, Optional[str]]:
        attempts = 0
        start = time.time()
        while True:
            try:
                resp = self.session.send(prepared, timeout=10, allow_redirects=False)
                return resp, (time.time() - start), None
            except (req_exc.Timeout, req_exc.ConnectionError) as exc:
                attempts += 1
                if attempts > self.max_retries:
                    return None, (time.time() - start), str(exc)
                time.sleep(0.5 * attempts)
            except Exception as exc:
                return None, (time.time() - start), str(exc)

    def _test_object_access(self, base_url: str, endpoint: dict, name: str, vals: dict) -> TestResult:
        url = urljoin(base_url, endpoint["path"])
        query_params: dict[str, str] = {}
        json_body: dict[str, str] = {}
        headers: dict[str, str] = {"User-Agent": "APISecurityScanner/1.0"}

        for prm in endpoint.get("parameters", []):
            pname = prm["name"]
            loc = prm.get("in", "query")
            value = vals.get(pname, "1")
            if loc == "path":
                url = url.replace(f"{{{pname}}}", str(value))
            elif loc == "query":
                query_params[pname] = value
            elif loc == "header":
                headers[pname] = value
            else:
                json_body[pname] = value

        req = Request(method=endpoint["method"], url=url, headers=headers, params=query_params, json=json_body or None)
        prepared = self.session.prepare_request(req)
        resp, resp_time, error_msg = self._send_with_retry(prepared)
        status_code = resp.status_code if resp else 0
        body_text = resp.text if resp else ""
        sample = self._sanitize_response(body_text)
        contains_sensitive = any(re.search(pat, body_text or "", re.I) for pat in self.sensitive_data_patterns)
        large_body = len(body_text or "") > 10000
        cross_user = ("other_user" in name)
        is_vuln = status_code == 200 and (contains_sensitive or large_body or cross_user) if status_code != 0 else False

        return TestResult(
            test_case=name,
            method=prepared.method or "",
            url=prepared.url or url,
            status_code=status_code,
            response_time=resp_time,
            is_vulnerable=is_vuln,
            response_sample=sample,
            request_sample=(prepared.body.decode() if isinstance(prepared.body, (bytes, bytearray)) else (prepared.body or "")),
            params=query_params,
            headers=_headers_to_list(prepared.headers),
            response_headers=_headers_to_list(resp.headers) if resp else [],
            request_cookies=self.session.cookies.get_dict(),
            response_cookies=resp.cookies.get_dict() if resp else {},
            error=error_msg,
            timestamp=datetime.now().isoformat(),
            request_body=(prepared.body.decode() if isinstance(prepared.body, (bytes, bytearray)) else prepared.body or ""),
            sensitive_hit=contains_sensitive,
            size_alert=large_body,
            cross_user=cross_user
        )

    def _sanitize_response(self, text: str, max_length: int = 200) -> str:
        if not text:
            return ""
        sanitized = re.sub(r'(password|token|secret|authorization)"?\s*:\s*"[^"]+"', r'\1":"*****"', text, flags=re.I)
        return (sanitized[:max_length] + "...") if len(sanitized) > max_length else sanitized

    def generate_report(self, fmt: str = "markdown") -> str:
        clean_issues = [i for i in self.issues if _is_real_issue(i)]
        return ReportGenerator(clean_issues, scanner="Bola", base_url=self.base_url).generate_html()

    def _get_base_url(self, results: List[TestResult]):
        if not results:
            return "N/A"
        parsed = urlparse(results[0].url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def save_report(self, path: str, fmt: str = "markdown"):
        clean_issues = [i for i in self.issues if _is_real_issue(i)]
        ReportGenerator(clean_issues, scanner="Bola", base_url=self.base_url).save(path, fmt="html")
