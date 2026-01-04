########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0 License                 #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 3.2 1-4-2026                                 #
########################################################

from __future__ import annotations

import json
import re
import time
import logging
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Iterable
from urllib.parse import urljoin, urlparse, parse_qsl
import requests
from requests import exceptions as req_exc
from tqdm import tqdm
from report_utils import ReportGenerator
from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig as OASSecurityConfig,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#================funtion classify_risk derive risk level from HTTP result and context ##########
def classify_risk(status_code: int, response_body: str = "", sensitive: bool = False, size_alert: bool = False, cross_user: bool = False) -> str:
    if status_code in (0, 400, 404, 405):
        return "Ignore"
    if 500 <= status_code < 600:
        return "Ignore"
    if status_code == 200 and (sensitive or cross_user or size_alert):
        return "High"
    if status_code == 200:
        return "Medium"
    if status_code == 403:
        return "Low"
    return "Low"

#================funtion _is_real_issue basic sanity check for a recorded issue ##########
def _is_real_issue(issue: dict) -> bool:
    try:
        return int(issue.get("status_code", 0)) != 0
    except (ValueError, TypeError):
        return False

#================funtion _headers_to_list normalize headers to list of tuples ##########
def _headers_to_list(hdrs) -> List[Tuple[str, str]]:
    if hasattr(hdrs, "getlist"):
        out = []
        for k in hdrs:
            for v in hdrs.getlist(k):
                out.append((k, v))
        return out
    return list(hdrs.items()) if hdrs else []

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

    true_positive: bool = False
    fingerprint: str = ""
    duplicate_of: Optional[str] = None
    duplicate_count: int = 1

    #================funtion to_dict convert TestResult to serializable dict ##########
    def to_dict(self):

        cross_for_risk = bool(self.cross_user and self.method.upper() in {"GET", "PUT", "DELETE"})
        sens_for_risk = bool(self.sensitive_hit or self.true_positive)
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
                sensitive=sens_for_risk,
                size_alert=self.size_alert,
                cross_user=cross_for_risk,
            ),
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "request_parameters": self.params or {},
            "request_headers": self.headers or [],
            "request_cookies": self.request_cookies or {},
            "request_body": self.request_sample,
            "response_headers": self.response_headers or [],
            "response_cookies": self.response_cookies or {},
            "response_body": (str(self.response_sample) if self.response_sample else ""),
            "true_positive": self.true_positive,
            "cross_user": self.cross_user,
            "sensitive_hit": self.sensitive_hit,
            "fingerprint": self.fingerprint,
            "duplicate_of": self.duplicate_of,
            "duplicate_count": self.duplicate_count,
            "variants": getattr(self, "variants", [self.test_case]),
        }


class BOLAAuditor:
    #================funtion __init__ initialize BOLAAuditor and OpenAPI indexes ##########
    def __init__(
        self,
        *args,
        session: Optional[requests.Session] = None,
        base_url: Optional[str] = None,
        swagger_spec: Optional[Dict[str, Any]] = None,
        test_delay: float = 0.2,
        max_retries: int = 1,
        show_subbars: bool = True,
        timeout: float = 10.0,
        ignore_http_statuses: Optional[Iterable[int]] = None,
        ignore_http_5xx: bool = True,
    ) -> None:
        sess_arg: Optional[requests.Session] = session
        base_arg: Optional[str] = base_url

        if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], requests.Session):
            base_arg = args[0]
            sess_arg = args[1]
        elif len(args) == 1 and isinstance(args[0], requests.Session):
            sess_arg = args[0]
        elif len(args) == 1 and isinstance(args[0], str):
            base_arg = args[0]

        if base_arg and "://" not in base_arg:
            base_arg = "http://" + base_arg

        if sess_arg is None:
            raise ValueError("Session is required")
        if not base_arg or not isinstance(base_arg, str):
            raise ValueError("base_url is required")

        self.session = sess_arg
        self.base_url = base_arg.rstrip("/") + "/"
        self.timeout = timeout

        self.ignore_statuses = set(ignore_http_statuses or (0, 400, 404, 405))
        self.ignore_http_5xx = bool(ignore_http_5xx)

        self.issues: List[dict] = []
        self.test_delay = test_delay
        self.max_retries = max_retries
        self.show_subbars = show_subbars

        self.swagger_spec = swagger_spec or {}
        self._op_index: Dict[Tuple[str, str], dict] = {}
        for _op in oas_iter_ops(self.swagger_spec or {}):
            self._op_index[(_op["method"], _op["path"])] = _op
        self._op_shape_index: Dict[Tuple[str, str], dict] = {}
        for (m, p), op in self._op_index.items():
            self._op_shape_index[(m, self._canonical_path(p))] = op

        self._endpoints_cache: Optional[List[Dict[str, Any]]] = None
        self._baseline_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    #================funtion _safe_body_sample make request body JSON-serializable for logging ##########
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

    #================funtion _canonical_path description =============
    def _canonical_path(self, p: str) -> str:
        p = "/" + (p or "").lstrip("/")
        return re.sub(r"\{[^}]+\}", "{}", p)

    #================funtion _abs_url resolve relative path to absolute URL ##########
    def _abs_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    #================funtion _canonicalize_url normalize URL for fingerprinting ##########
    def _canonicalize_url(self, url: str) -> str:
        try:
            u = urlparse(url)

            keys = sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)})
            qs = "&".join(keys)
            return f"{u.scheme}://{u.netloc}{u.path}?{qs}" if qs else f"{u.scheme}://{u.netloc}{u.path}"
        except Exception:
            return url

    #================funtion _json_shape reduce JSON to structural signature ##########
    def _json_shape(self, text: str) -> str:
        if not text:
            return ""
        try:
            data = json.loads(text)
        except Exception:
            return re.sub(r"\s+", " ", text).strip()[:4096]

        def normalize(val):
            if isinstance(val, dict):
                return {k: normalize(v) for k, v in sorted(val.items(), key=lambda x: x[0]) if k not in {"timestamp","time","date","requestId","request_id"}}
            if isinstance(val, list):
                return [normalize(val[0])] if val else []
            if isinstance(val, str):
                return "S"
            if isinstance(val, (int, float)):
                return "N"
            if val is None:
                return "null"
            if isinstance(val, bool):
                return "B"
            return "X"
        try:
            shaped = normalize(data)
            return json.dumps(shaped, separators=(",", ":"), ensure_ascii=False)[:8192]
        except Exception:
            return re.sub(r"\s+", " ", text).strip()[:4096]

    #================funtion _baseline_key build a stable key for endpoint baselines ##########
    def _baseline_key(self, endpoint: Dict[str, Any]) -> Tuple[str, str]:
        method = (endpoint.get("method") or "GET").upper()
        path = endpoint.get("path") or endpoint.get("url") or "/"
        canon = self._canonicalize_url(path)
        return (method, canon)

    #================funtion _extract_id_candidates_from_json recursively find ID-like values ##########
    def _extract_id_candidates_from_json(self, data: Any) -> List[str]:
        keys_id_like = ("id", "_id", "uuid", "guid", "userId", "accountId", "orderId", "customerId", "tenantId")
        out: List[str] = []

        def is_id_key(k: str) -> bool:
            kl = (k or "").lower()
            if kl in {x.lower() for x in keys_id_like}:
                return True
            return any(t in kl for t in ("id", "uuid", "guid"))

        def add_val(v: Any) -> None:
            if v is None:
                return
            if isinstance(v, bool):
                return
            if isinstance(v, (int, float)):
                out.append(str(int(v)) if isinstance(v, int) or float(v).is_integer() else str(v))
                return
            if isinstance(v, str):
                v2 = v.strip()
                if 0 < len(v2) <= 128:
                    out.append(v2)

        def walk(x: Any) -> None:
            if isinstance(x, dict):
                for k, v in x.items():
                    if is_id_key(str(k)):
                        add_val(v)
                    walk(v)
            elif isinstance(x, list):
                for i in x:
                    walk(i)

        walk(data)
        seen = set()
        res: List[str] = []
        for v in out:
            if v not in seen:
                res.append(v)
                seen.add(v)
        return res[:50]

    #================funtion _store_baseline record baseline response and harvested IDs ##########
    def _store_baseline(self, key: Tuple[str, str], endpoint: Dict[str, Any], resp: Optional[requests.Response], req: Dict[str, Any]) -> None:
        if resp is None:
            return
        try:
            code = int(getattr(resp, "status_code", 0) or 0)
        except Exception:
            code = 0
        if code not in (200, 206):
            return

        body_text = getattr(resp, "text", "") or ""
        shape = self._json_shape(body_text)
        ids: List[str] = []
        try:
            data = resp.json()
            ids = self._extract_id_candidates_from_json(data)
        except Exception:
            ids = []

        self._baseline_cache[key] = {
            "status_code": code,
            "shape": shape,
            "fingerprint": self._fingerprint(req.get("method", ""), req.get("url", ""), code, body_text[:2048]),
            "ids": ids,
            "captured_at": time.time(),
        }

    #================funtion _pick_other_id choose an alternative ID candidate ##########
    def _pick_other_id(self, key: Tuple[str, str], current: str) -> Optional[str]:
        base = self._baseline_cache.get(key) or {}
        candidates = base.get("ids") or []
        for c in candidates:
            if str(c) != str(current):
                return str(c)
        return None

    #================funtion _determine_cross_user decide if response indicates cross-user access ##########
    def _determine_cross_user(self, key: Tuple[str, str], name: str, status_code: int, body_text: str, resp: Optional[requests.Response]) -> bool:
        if "other_user" not in (name or ""):
            return False
        if status_code not in (200, 206, 302):
            return False

        base = self._baseline_cache.get(key)
        if not base:
            return False

        if status_code == 302 and resp is not None:
            loc = (resp.headers.get("Location") or "").strip()
            if loc and loc != (resp.request.url if resp.request else ""):
                return True
            return False

        other_shape = self._json_shape(body_text or "")
        if other_shape and base.get("shape") and other_shape != base.get("shape"):
            return True

        try:
            data = resp.json() if resp is not None else None
            other_ids = self._extract_id_candidates_from_json(data) if data is not None else []
        except Exception:
            other_ids = []
        base_ids = base.get("ids") or []
        if base_ids and other_ids:
            for oid in other_ids[:5]:
                if oid and oid not in base_ids:
                    return True

        if not self._is_generic_success(body_text or ""):
            other_fp = self._fingerprint("", "", status_code, (body_text or "")[:2048])
            if other_fp and other_fp != base.get("fingerprint"):
                return True
        return False

    @staticmethod
    #================funtion _looks_like_server_error_leak description =============
    def _looks_like_server_error_leak(text: str) -> bool:
        t = (text or "").lower()
        markers = (
            "traceback", "stack trace", "exception", "nullreference", "sqlstate", "syntax error",
            "at ", "org.springframework", "java.lang.", "system.nullreferenceexception",
            "pdoexception", "fatal error", "warning: mysql", "unhandled exception"
        )
        return any(m in t for m in markers)

    #================funtion _fingerprint description =============
    def _fingerprint(self, method: str, url: str, status: int, body_text: str) -> str:
        canon = self._canonicalize_url(url)
        shape = self._json_shape(body_text or "")
        h = hashlib.sha1(f"{method}|{canon}|{status}|{shape}".encode("utf-8", "ignore")).hexdigest()
        return f"{method}|{canon}|{status}|{h}"

    #================funtion _detect_sensitive detect tokens/emails and sensitive fields ##########
    def _detect_sensitive(self, body_text: str) -> bool:
        if not body_text:
            return False
        text = (body_text or "").strip()
        try:
            data = json.loads(text)
            seen_keys = set()
            def walk(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        kl = str(k).lower()
                        if kl in {"email", "access_token", "refresh_token", "token"}:
                            if isinstance(v, str) and v.strip():
                                seen_keys.add(kl)
                        if kl in {"message", "status", "detail", "error"}:
                            continue
                        walk(v)
                elif isinstance(obj, list):
                    for it in obj:
                        walk(it)
            walk(data)
            if seen_keys:
                return True
        except Exception:
            pass
        if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, flags=re.I):
            return True
        if re.search(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", text):
            return True
        return False

    #================funtion _is_true_positive determine if result is a true BOLA hit ##########

    def _is_true_positive(self, method: str, status_code: int, cross_user: bool, contains_sensitive: bool) -> bool:
        if status_code not in (200, 206, 302):
            return False
        if method.upper() in {"GET", "PUT", "DELETE"} and cross_user and status_code in (200, 206, 302):
            return True
        if contains_sensitive and status_code in (200, 206):
            return True
        return False

    #================funtion _is_generic_success description =============
    def _is_generic_success(self, body_text: str) -> bool:
        if not body_text:
            return True
        try:
            data = json.loads(body_text)
            if isinstance(data, dict):
                allowed = {"message", "status", "detail", "error"}
                keys = set(map(lambda k: str(k).lower(), data.keys()))
                if keys and keys.issubset(allowed):
                    return all(not isinstance(v, (dict, list)) for v in data.values())
        except Exception:
            pass
        trimmed = body_text.strip().lower()
        if len(trimmed) <= 64 and trimmed in {"ok", "success", "done", "created", "updated", "deleted"}:
            return True
        return False

    #================funtion load_swagger load and index OpenAPI/Swagger spec ##########
    def load_swagger(self, swagger_path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(swagger_path, "r", encoding="utf-8") as f:
                spec = json.loads(f.read())
            self.swagger_spec = spec
            self._op_index.clear()
            for _op in oas_iter_ops(self.swagger_spec or {}):
                self._op_index[(_op["method"], _op["path"])] = _op
            self._op_shape_index.clear()
            for (m, p), op in self._op_index.items():
                self._op_shape_index[(m, self._canonical_path(p))] = op
            self._endpoints_cache = None
            return spec
        except Exception as e:
            logger.error(f"Error loading Swagger: {e}", exc_info=True)
            return None

    #================funtion get_object_endpoints collect endpoints with object identifiers ##########
    def get_object_endpoints(self, swagger_spec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        spec = swagger_spec or self.swagger_spec or {}
        if self._endpoints_cache is not None:
            return self._endpoints_cache

        endpoints: List[Dict[str, Any]] = []
        for op in oas_iter_ops(spec or {}):
            path = op["path"]
            method = op["method"]
            meta = op.get("raw", {})

            path_params = (meta.get("parameters") or []) if isinstance(meta, dict) else []
            op_params = op.get("parameters") or []
            all_params = list(path_params) + list(op_params)

            object_params = self._find_object_params(all_params)

            rb = (op.get("requestBody") or meta.get("requestBody")) if isinstance(meta, dict) else op.get("requestBody")
            content = (rb or {}).get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {}) or {}
                for prop, prop_schema in (schema.get("properties", {}) or {}).items():
                    if any(re.search(pat, str(prop).lower()) for pat in [r'(?:^|_)id$', r'uuid$', r'_id$', r'key$', r'email$', r'token$', r'slug$', r'user', r'account', r'profile']):
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
                    "method": method,
                    "parameters": object_params,
                    "operation_id": op.get("operationId", ""),
                    "summary": op.get("summary", ""),
                    "description": op.get("description", ""),
                    "security": op.get("security", []),
                    "request_body": rb or None,
                })

        logger.info(f"Object endpoints detected: {len(endpoints)}")
        self._endpoints_cache = endpoints
        return endpoints

    #================funtion _find_object_params extract likely object-identifying params ##########
    def _find_object_params(self, parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        obj = []
        for param in parameters or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").lower()
            if any(re.search(pat, name) for pat in [r'(?:^|_)id$', r'uuid$', r'_id$', r'key$', r'email$', r'token$', r'slug$', r'user', r'account', r'profile']):
                schema = param.get("schema", {}) or {}
                obj.append({
                    "name": param.get("name", ""),
                    "in": param.get("in", "query"),
                    "required": param.get("required", False),
                    "type": schema.get("type", "string"),
                    "format": schema.get("format", ""),
                    "description": param.get("description", "")
                })
        return obj

    #================funtion _generate_test_values generate test cases for parameters ##########
    def _generate_test_values(self, parameters: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
        seeds = getattr(self, "param_seeds", {}) or {}

        def is_id_like(n: str) -> bool:
            n = (n or "").lower()
            return any(k in n for k in ("id", "_id", "uuid", "key", "account", "user", "order"))

        def pick_valid_for(p: dict) -> str:
            name = p.get("name", "")
            schema = p.get("schema", {}) or {}
            fmt = (schema.get("format") or "").lower()
            ptype = (schema.get("type") or "string").lower()
            if seeds.get(name):
                return str(seeds[name][0])
            for k in ("example", "default"):
                if schema.get(k) not in (None, ""):
                    return str(schema[k])
            if schema.get("enum"):
                return str(schema["enum"][0])
            if fmt == "uuid":
                return "550e8400-e29b-41d4-a716-446655440000"
            if ptype == "integer":
                return "1"

            return "testuser"
        per_param_valid = {p["name"]: pick_valid_for(p) for p in (parameters or [])}

        def as_int(s: str) -> Optional[int]:
            try:
                return int(s)
            except Exception:
                return None

        cases: Dict[str, Dict[str, str]] = {}
        cases["valid"] = dict(per_param_valid)
        other = {}
        for p in parameters or []:
            name = p["name"]
            val = per_param_valid[name]
            if as_int(val) is not None:
                other[name] = str(as_int(val) + 1)
            elif is_id_like(name):
                other[name] = "other-user"
            else:
                other[name] = "testuser2"
        cases["other_user"] = other
        nonexist = {}
        for p in parameters or []:
            name = p["name"]
            schema = p.get("schema", {}) or {}
            fmt = (schema.get("format") or "").lower()
            if (schema.get("type") or "").lower() == "integer":
                nonexist[name] = "99999999"
            elif fmt == "uuid":
                nonexist[name] = "00000000-0000-0000-0000-000000000000"
            else:
                nonexist[name] = "does-not-exist"
        cases["non_existent"] = nonexist
        for p in parameters or []:
            name = p["name"]
            ptype = (p.get("schema", {}) or {}).get("type", "string").lower()
            if ptype == "integer":
                for key, v in {"integer_negative": "-1", "integer_zero": "0", "integer_large": "2147483647"}.items():
                    c = dict(per_param_valid); c[name] = v; cases[key] = c
            else:
                for key, v in {"string_long": "A" * 1000, "string_special": "!@#$%^&*()"}.items():
                    c = dict(per_param_valid); c[name] = v; cases[key] = c
        inj_vals = [
            ("urlenc_null", "%00"),
            ("urlenc_dotdot", "%2e%2e%2f"),
            ("unicode_homoglyph", "\\u13B0\\u13B1"),
            ("sqlish", "\" OR \"1\"=\"1\"--"),
        ]
        for label, val in inj_vals:
            c = dict(per_param_valid)
            for p in parameters or []:
                schema = p.get("schema", {}) or {}
                ptype = (schema.get("type") or "string").lower()
                if ptype != "integer" and is_id_like(p.get("name","")):
                    c[p["name"]] = val
            cases[label] = c

        return cases

    #================funtion _build_req_from_op construct request from OpenAPI operation ##########
    def _build_req_from_op(self, method: str, path_template: str) -> Dict[str, Any]:
        key = (method.upper(), path_template)
        op = self._op_index.get(key) or self._op_shape_index.get((method.upper(), self._canonical_path(path_template)))
        if not op:
            raise KeyError(f"Operation not found: {method} {path_template}")
        try:
            return oas_build_request(self.swagger_spec, self.base_url, op, None)
        except TypeError:
            try:
                return oas_build_request(self.base_url, op, OASSecurityConfig())
            except Exception:
                return {"method": method.upper(), "url": self._abs_url(path_template), "headers": {"User-Agent": "APISecurityScanner/2.1"}}

    #================funtion _apply_param_values apply parameter values into request ##########

    def _apply_param_values(self, req: Dict[str, Any], endpoint: Dict[str, Any], values: Dict[str, str]) -> Dict[str, Any]:
        out = dict(req)
        out.setdefault("headers", {})
        out.setdefault("params", {})
        url = out.get("url") or self._abs_url(endpoint["path"])

        for prm in endpoint.get("parameters", []):
            pname = prm.get("name")
            loc = prm.get("in", "query")
            val = values.get(pname, "1")
            if loc == "path":
                url = url.replace(f"{{{pname}}}", str(val))

        out["url"] = url

        ctype = (str(out.get("headers", {}).get("Content-Type", "")) or "").lower()
        prefers_form = ("application/x-www-form-urlencoded" in ctype) or ("multipart/form-data" in ctype)
        prefers_json = ("application/json" in ctype) or (not prefers_form)

        for prm in endpoint.get("parameters", []):
            pname = prm.get("name")
            loc = prm.get("in", "query")
            val = values.get(pname, "1")
            if loc == "query":
                out["params"][pname] = val
            elif loc == "header":
                out["headers"][pname] = val
            elif loc == "path":
                continue
            else:
                if prefers_form or ("data" in out and out.get("data") is not None):
                    base = dict(out.get("data") or {})
                    base[pname] = val
                    out["data"] = base
                else:
                    base = dict(out.get("json") or {})
                    base[pname] = val
                    out["json"] = base

        return out

    #================funtion _send_with_retry description =============
    def _send_with_retry(self, req: Dict[str, Any]) -> tuple[Optional[requests.Response], float, Optional[str]]:
        attempts = 0
        start = time.time()
        while True:
            try:
                resp = self.session.request(**req, timeout=self.timeout, allow_redirects=False)
                return resp, (time.time() - start), None
            except (req_exc.Timeout, req_exc.ConnectionError) as exc:
                attempts += 1
                if attempts > self.max_retries:
                    return None, (time.time() - start), str(exc)
                time.sleep(0.5 * attempts)
            except Exception as exc:
                return None, (time.time() - start), str(exc)

    #================funtion test_endpoint run BOLA tests for one endpoint ##########

    def test_endpoint(self, base_url: str, endpoint: Dict[str, Any], *, progress_position: int | None = None) -> List[TestResult]:
        results: List[TestResult] = []
        if not endpoint.get("parameters"):
            return results

        cases = self._generate_test_values(endpoint["parameters"])

        key = self._baseline_key(endpoint)
        if "valid" in cases:
            time.sleep(self.test_delay)
            tr_valid = self._test_object_access(endpoint, "valid", cases["valid"], store_baseline=True)
            results.append(tr_valid)

        desc = f"{endpoint['method']} {endpoint['path']}"
        other_cases = [(k, v) for k, v in cases.items() if k != "valid"]
        it = other_cases
        if self.show_subbars:
            it = tqdm(other_cases, desc=desc, unit="case", leave=False, position=(progress_position if progress_position is not None else 1), dynamic_ncols=True)

        for name, vals in it:
            time.sleep(self.test_delay)
            results.append(self._test_object_access(endpoint, name, vals, store_baseline=False))

        return results

    #================funtion _test_object_access description =============
    def _test_object_access(self, endpoint: dict, name: str, vals: dict, *, store_baseline: bool = False) -> TestResult:
        method = endpoint["method"]
        key = self._baseline_key(endpoint)

        if "other_user" in (name or ""):
            try:
                adjusted = dict(vals or {})
                for prm in endpoint.get("parameters", []):
                    pname = prm.get("name") or ""
                    schema = prm.get("schema", {}) or {}
                    fmt = (schema.get("format") or "").lower()
                    ptype = (schema.get("type") or "string").lower()
                    is_id_like = ("id" in pname.lower()) or (fmt == "uuid") or (ptype in ("integer", "number") and "id" in pname.lower())
                    if is_id_like and pname in adjusted:
                        alt = self._pick_other_id(key, str(adjusted[pname]))
                        if alt is not None:
                            adjusted[pname] = alt
                vals = adjusted
            except Exception:
                pass

        try:
            req = self._build_req_from_op(method, endpoint["path"])
        except KeyError:
            req = {
                "method": method.upper(),
                "url": self._abs_url(endpoint["path"]),
                "headers": {"User-Agent": "APISecurityScanner/2.1"},
            }

        req = self._apply_param_values(req, endpoint, vals)

        resp, resp_time, error_msg = self._send_with_retry(req)

        status_code = 0
        code = 0
        body_text = ""
        sample = ""
        if resp is not None:
            status_code = int(getattr(resp, "status_code", 0) or 0)
            code = status_code
            body_text = getattr(resp, "text", "") or ""
            sample = self._sanitize_response(body_text)

        contains_sensitive = self._detect_sensitive(body_text)
        large_body = len(body_text or "") > 10000

        if store_baseline:
            self._store_baseline(key, endpoint, resp, req)

        cross_user = self._determine_cross_user(key, name, status_code, body_text, resp)

        true_pos = self._is_true_positive(method, status_code, cross_user, contains_sensitive)

        successful = status_code in (200, 206, 302)
        non_generic = not self._is_generic_success(body_text or "")
        is_vuln = bool(successful and (true_pos or contains_sensitive or (cross_user and non_generic) or (large_body and non_generic)))

        effective_url = getattr(getattr(resp, "request", None), "url", req.get("url"))
        req_headers = (
            dict(getattr(getattr(resp, "request", None), "headers", {}) or {})
            if resp else dict(req.get("headers", {}))
        )

        req_body = None
        try:
            if resp is not None and resp.request is not None:
                req_body = getattr(resp.request, "body", None)
        except Exception:
            req_body = req.get("json") if req.get("json") is not None else req.get("data")

        tr = TestResult(
            test_case=name,
            method=req.get("method", method),
            url=effective_url or req.get("url", ""),
            status_code=status_code,
            response_time=resp_time,
            is_vulnerable=is_vuln,
            response_sample=(sample or ""),
            request_sample=self._safe_body_sample(req_body),
            params=dict(req.get("params") or {}),
            headers=_headers_to_list(req_headers),
            request_body=self._safe_body_sample(req_body),
            response_headers=_headers_to_list(getattr(resp, "headers", {}) if resp else {}),
            request_cookies=getattr(self.session.cookies, "get_dict", lambda: {})(),
            response_cookies=getattr(getattr(resp, "cookies", None), "get_dict", lambda: {})() if resp else {},
            sensitive_hit=bool(contains_sensitive),
            cross_user=bool(cross_user),
            true_positive=bool(true_pos),
            size_alert=bool(large_body),
            error=error_msg,
            timestamp=datetime.utcnow().isoformat(),
        )

        tr.fingerprint = self._fingerprint(tr.method, tr.url, tr.status_code, body_text[:2048] if body_text else tr.response_sample)
        return tr

    #================funtion _sanitize_response description =============
    def _sanitize_response(self, text: str, max_length: int = 200) -> str:
        if not text:
            return ""
        sanitized = re.sub(r'(password|token|secret|authorization)"?\s*:\s*"[^"]+"', r'\1":"*****"', text, flags=re.I)
        return (sanitized[:max_length] + "...") if len(sanitized) > max_length else sanitized

    #================funtion _filter_issues keep true positives and deduplicate ##########

    def _filter_issues(self) -> None:
        if not isinstance(self.issues, list) or not self.issues:
            self.issues = []
            return

        filtered: List[dict] = []
        for it in self.issues:
            try:
                code = int(it.get("status_code", 0) or 0)
            except Exception:
                continue

            if code in self.ignore_statuses:
                continue

            if self.ignore_http_5xx and (500 <= code < 600):
                desc = (it.get("description") or "").lower()
                body = (it.get("response_sample") or "") + " " + (it.get("response_body") or "")
                if "other_user" not in desc or not self._looks_like_server_error_leak(body):
                    continue

            sev = (it.get("severity") or "").strip()
            cross_user = bool(it.get("cross_user"))
            body_sample = (it.get("response_body") or it.get("response_sample") or "")
            non_generic = not self._is_generic_success(body_sample)

            keep = False
            if bool(it.get("is_vulnerable")) or bool(it.get("true_positive")):
                keep = True
            elif sev in ("Medium", "High", "Critical"):
                keep = True
            elif cross_user and code in (200, 206, 302) and non_generic:
                keep = True

            if not keep:
                continue

            filtered.append(it)

        dedup: Dict[str, dict] = {}
        for it in filtered:
            fp = it.get("fingerprint") or self._fingerprint(
                it.get("method", ""),
                it.get("url", it.get("endpoint", "")),
                int(it.get("status_code", 0) or 0),
                (it.get("response_body") or it.get("response_sample") or ""),
            )
            it["fingerprint"] = fp
            if fp in dedup:
                dedup[fp]["duplicate_count"] = dedup[fp].get("duplicate_count", 1) + 1
                variants = dedup[fp].setdefault("variants", [])
                desc = it.get("description", "")
                if desc and desc not in variants:
                    variants.append(desc)
            else:
                dedup[fp] = it

        self.issues = list(dedup.values())

    #================funtion run description =============
    def run(self, swagger_spec: Optional[Dict[str, Any]] = None) -> List[TestResult]:
        spec = swagger_spec or self.swagger_spec or {}
        endpoints = self.get_object_endpoints(spec)
        bar = tqdm(endpoints, desc="BOLA", unit="endpoint", dynamic_ncols=True) if self.show_subbars else endpoints

        unique_results: List[TestResult] = []
        seen: Dict[str, TestResult] = {}

        iterator = enumerate(bar)
        for i, ep in iterator:
            results = self.test_endpoint(self.base_url, ep, progress_position=(i + 1 if self.show_subbars else None))
            for tr in results:

                fp = tr.fingerprint or self._fingerprint(tr.method, tr.url, tr.status_code, tr.response_sample)
                if fp in seen:
                    seen_tr = seen[fp]
                    seen_tr.duplicate_count += 1
                    if tr.test_case not in (getattr(seen_tr, "variants", []) or []):
                        setattr(seen_tr, "variants", (getattr(seen_tr, "variants", []) or []) + [tr.test_case])
                    continue
                setattr(tr, "variants", [tr.test_case])
                seen[fp] = tr
                unique_results.append(tr)

        self.issues = [tr.to_dict() for tr in unique_results if _is_real_issue(tr.to_dict())]
        return unique_results

    #================funtion generate_report render issues to HTML or Markdown ##########
    def generate_report(self, fmt: str = "html") -> str:
        self._filter_issues()
        gen = ReportGenerator(issues=self.issues, scanner="Bola Api1", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    #================funtion save_report persist report to disk ##########
    def save_report(self, path: str, fmt: str = "html"):
        self._filter_issues()
        ReportGenerator(self.issues, scanner="Bola Api1", base_url=self.base_url).save(path, fmt=fmt)
