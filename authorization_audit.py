########################################################
# APISCAN - API Security Scanner                       #
# Licensed under  AGPL-3.0 License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.2  2-11--2025                             #
########################################################                                
                             
from __future__ import annotations

import base64
import json
import logging
import re
import requests
import urllib3
from tqdm import tqdm
from report_utils import ReportGenerator
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig,              
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Issue = Dict[str, Any]


def _headers_to_list(hdrs) -> List[Tuple[str, str]]:
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items()) if hdrs else []


class AuthorizationAuditor:
    # ----------------------- Funtion __init__ ----------------------------#
    def __init__(
        self,
        base_url: str,
        session: requests.Session,
        *,
        spec: Optional[Dict[str, Any]] = None,
        flow: Optional[str] = None,
        timeout: float = 10.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        if session is None:
            raise ValueError("Session is required; configure via auth_utils.configure_authentication(args).")
        if not base_url or not isinstance(base_url, str):
            raise ValueError("base_url is required (e.g., 'https://api.example.com/').")

        self.session = session
        self.timeout = timeout
        self.logger = logger or logging.getLogger(__name__)
        self.base_url = base_url.rstrip("/") + "/"
        self.flow = (flow or "none").lower()

                                                                               
        self._respect_session_auth = True
        self._forbid_local_auth_headers = True
        self.strip_auth_on_auth_endpoints = True                                                       

                        
        self.authz_issues: List[Dict[str, Any]] = []
        self.roles: Dict[str, Dict[str, Any]] = {"anonymous": {}, "user": {}, "admin": {}}
        self.request_templates: Dict[str, Any] = self._default_request_templates()

                                                                                               
        self.swagger_data: Dict[str, Any] = spec or {}
        if self.swagger_data:
            self.discovered_endpoints: List[Dict[str, Any]] = self._parse_swagger_data()
        else:
            self.discovered_endpoints: List[Dict[str, Any]] = self._discover_endpoints()

                                                                                          
        self._op_index: Dict[Tuple[str, str], dict] = {}
        for _op in oas_iter_ops(self.swagger_data or {}):
            self._op_index[(_op["method"], _op["path"])] = _op

        self._op_shape_index: Dict[Tuple[str, str], dict] = {}
        for (m, p), op in self._op_index.items():
            self._op_shape_index[(m, self._canonical_path(p))] = op

                                                                         
        self._global_security = self.swagger_data.get("security", None)

        self.logger.debug(
            "AuthorizationAuditor ready (base_url=%s, endpoints=%d, flow=%s)",
            self.base_url, len(self.discovered_endpoints), self.flow
        )

                                                               
    # ----------------------- Funtion _default_request_templates ----------------------------#
    def _default_request_templates(self) -> Dict[str, Any]:
                                                                
        return {
            "login": {
                "method": "POST",
                "path": "/api/auth/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "{username}", "password": "{password}"},
            },
            "forget-password": {
                "method": "POST",
                "path": "/identity/api/auth/forget-password",
                "headers": {"Content-Type": "application/json"},
                "body": {"email": "test@example.com"},
            },
            "user_profile": {"method": "GET", "path": "/api/users/{userId}", "headers": {}},
            "admin_config": {"method": "GET", "path": "/api/admin/config", "headers": {}},
            "headers": {"Accept": "application/json", "User-Agent": "APISecurityScanner/2.1"},
        }

    def add_role_token(self, role: str, token: str) -> None:
        if role not in self.roles:
            self.roles[role] = {}
        self.roles[role]["token"] = token

    # ----------------------- Funtion _parse_swagger_data ----------------------------#
    def _parse_swagger_data(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(self.swagger_data, dict):
            return out
        for path, verbs in self.swagger_data.get("paths", {}).items():
            for verb, meta in verbs.items():
                if verb.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    continue
                sensitive = self._is_sensitive(meta, path)
                security = meta.get("security", [])
                parameters = meta.get("parameters", [])
                request_body = meta.get("requestBody") if isinstance(meta, dict) else None
                out.append(
                    {
                        "url": urljoin(self.base_url, path),
                        "methods": [verb.upper()],
                        "sensitive": sensitive,
                        "security": security,
                        "parameters": parameters,
                        "path": path,
                        "operation_id": meta.get("operationId", ""),
                        "request_body": request_body,
                    }
                )
        return out

    # ----------------------- Funtion _discover_endpoints ----------------------------#
    def _discover_endpoints(self) -> List[Dict[str, Any]]:
        common_paths = [
            "/api/admin",
            "/api/users",
            "/admin",
            "/users",
            "/api/v1/users",
            "/api/v1/admin",
            "/api/auth",
            "/auth",
            "/api/config",
            "/config",
            "/api/settings",
            "/settings",
            "/identity/api/auth/forget-password",
            "/identity/api/auth/login",
            "/workshop/api/shop/orders",
        ]
        discovered = []
        for p in common_paths:
            methods = ["GET"]
            if "auth" in p or "login" in p or "forget-password" in p:
                methods = ["POST"]
            elif "orders" in p:
                methods = ["GET", "POST", "PUT"]
            discovered.append(
                {
                    "url": urljoin(self.base_url, p),
                    "methods": methods,
                    "sensitive": any((keyword in p for keyword in ["admin", "config", "settings", "auth", "orders"])),
                    "security": [],
                    "parameters": [],
                    "path": p,
                    "operation_id": "",
                }
            )
        return discovered

    # ----------------------- Funtion _is_sensitive ----------------------------#
    def _is_sensitive(self, meta: Dict[str, Any], path: str = "") -> bool:
        indicators = (
            "admin",
            "delete",
            "write",
            "internal",
            "config",
            "settings",
            "password",
            "secret",
            "key",
            "orders",
        )
        tags = " ".join(meta.get("tags", [])).lower()
        if any((indicator in tags for indicator in indicators)):
            return True
        operation_id = meta.get("operationId", "").lower()
        if any((indicator in operation_id for indicator in indicators)):
            return True
        if any((indicator in path.lower() for indicator in indicators)):
            return True
        for field in ["summary", "description"]:
            if field in meta and any((indicator in meta[field].lower() for indicator in indicators)):
                return True
        return False

    # ----------------------- Funtion _canonical_path ----------------------------#
    def _canonical_path(self, p: str) -> str:
        p = "/" + (p or "").lstrip("/")
        return re.sub(r"\{[^}]+\}", "{}", p)

    # ----------------------- Funtion _abs_url ----------------------------#
    def _abs_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    # ----------------------- Funtion _looks_like_auth_endpoint ----------------------------#
    def _looks_like_auth_endpoint(self, path: str) -> bool:
        u = path.lower()
        return any(x in u for x in [
            "/auth/", "login", "signup", "register", "verify-email", "check-otp",
            "forget-password", "reset-password"
        ])

    # ----------------------- Funtion _req_from_spec ----------------------------#
    def _req_from_spec(self, method: str, path_template: str) -> Dict[str, Any]:
        key = (method.upper(), path_template)
        op = self._op_index.get(key)
        if not op:
            shape = self._canonical_path(path_template)
            op = self._op_shape_index.get((method.upper(), shape))
        if not op:
            raise KeyError(f"Operation not found: {method} {path_template}")
        return oas_build_request(self.swagger_data, self.base_url, op, None)

    # ----------------------- Funtion _op_requires_auth ----------------------------#
    def _op_requires_auth(self, op: Optional[dict]) -> Optional[bool]:
        if not op:
            return None
        sec = op.get("security")
        if sec is None:
            sec = self._global_security
        if sec is None:
            return None
        if isinstance(sec, list) and len(sec) == 0:
            return False
        return True

    # ----------------------- Funtion _prepare_request_data ----------------------------#
    def _prepare_request_data(self, endpoint: Dict[str, Any], method: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        json_data = None
        form_data = None
        endpoint_path = endpoint.get("path", "")
        template_found = False
        for template_name, template in self.request_templates.items():
            if template_name == "headers":
                continue
            if template.get("path") and template["path"] in endpoint_path:
                if "body" in template:
                    json_data = json.loads(json.dumps(template["body"]))                
                template_found = True
                break
        if not template_found and endpoint.get("request_body"):
            content = endpoint["request_body"].get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
                json_data = self._generate_example_from_schema(schema)
        if method.upper() == "GET":
            return (None, None)
        return (json_data, form_data)

    # ----------------------- Funtion _generate_example_from_schema ----------------------------#
    def _generate_example_from_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        example = {}
        if "properties" in schema:
            for prop_name, prop_schema in schema["properties"].items():
                prop_type = prop_schema.get("type", "string")
                if prop_type == "string":
                    if prop_schema.get("format") == "email":
                        example[prop_name] = "test@example.com"
                    elif prop_schema.get("format") == "date-time":
                        example[prop_name] = datetime.now().isoformat()
                    else:
                        example[prop_name] = f"test_{prop_name}"
                elif prop_type == "number":
                    example[prop_name] = 123.45
                elif prop_type == "integer":
                    example[prop_name] = 123
                elif prop_type == "boolean":
                    example[prop_name] = True
                elif prop_type == "array":
                    example[prop_name] = ["item1", "item2"]
        return example

                                                                 
    # ----------------------- Funtion test_authorization ----------------------------#
    def test_authorization(self, show_progress: bool = True) -> List[Dict[str, Any]]:
        endpoints = self.discovered_endpoints or []
        if not endpoints:
            print("Warning: No endpoints discovered for testing")
            return []
        iterator = tqdm(endpoints, desc="Testing endpoints", unit="endpoint") if show_progress else endpoints
        for ep in iterator:
            url = ep.get("url")
            methods = ep.get("methods", ["GET"])
            if show_progress:
                tqdm.write(f"Testing {methods} {url}")
            self._test_endpoint(ep)
        return self._filtered_issues()

    # ----------------------- Funtion _test_endpoint ----------------------------#
    def _test_endpoint(self, ep: Dict[str, Any]) -> None:
        for verb in ep.get("methods", ["GET"]):
            self._do_request(ep, verb, role="anonymous", should_access=not ep.get("sensitive", False))
            if "user" in self.roles:
                self._do_request(ep, verb, role="user", should_access=True)
            if "admin" in self.roles:
                self._do_request(ep, verb, role="admin", should_access=True)

    # ----------------------- Funtion _request_for_role ----------------------------#
    def _request_for_role(self, req: Dict[str, Any], role: str, *, suppress_auth: bool = False) -> Dict[str, Any]:
        out = dict(req)
        out["headers"] = dict(req.get("headers") or {})
                                                           
        if suppress_auth:
            out["headers"].pop("Authorization", None)
            return out
        if role != "anonymous":
            tok = self.roles.get(role, {}).get("token")
            if tok and "Authorization" not in getattr(self.session, "headers", {}):
                out["headers"].setdefault("Authorization", f"Bearer {tok}")
        return out

    # ----------------------- Funtion _do_request ----------------------------#
    def _do_request(self, ep: Dict[str, Any], verb: str, role: str, should_access: bool) -> None:
        method = verb.upper()
        path = ep.get("path") or urlparse(ep.get("url", "")).path or "/"
        path = "/" + path.lstrip("/")

                                             
        try:
            req = self._req_from_spec(method, path)
        except KeyError:
            req = {"method": method, "url": self._abs_url(path), "headers": dict(self.request_templates.get("headers", {}))}

                             
        base_hdrs = self.request_templates.get("headers", {"User-Agent": "APISecurityScanner/2.1", "Accept": "application/json"})
        req.setdefault("headers", {})
        for k, v in base_hdrs.items():
            req["headers"].setdefault(k, v)

                          
        json_data, form_data = self._prepare_request_data(ep, verb)
        if method != "GET":
            if json_data is not None:
                req["json"] = json_data
            if form_data is not None:
                req["data"] = form_data

        is_auth_ep = self._looks_like_auth_endpoint(path)
        rreq = self._request_for_role(req, role, suppress_auth=is_auth_ep)

                                                                                                           
        if is_auth_ep and self.strip_auth_on_auth_endpoints and "Authorization" in getattr(self.session, "headers", {}):
            tmp = requests.Session()
            tmp.verify = getattr(self.session, "verify", True)
            tmp.trust_env = getattr(self.session, "trust_env", True)
            tmp.proxies = getattr(self.session, "proxies", {})
            try:
                tmp.cookies.update(self.session.cookies.get_dict())
            except Exception:
                pass
            ses = tmp
        else:
            ses = self.session

        try:
            r = ses.request(**rreq, timeout=self.timeout)
            allowed = 200 <= r.status_code < 400
            if r.status_code in (400, 404):
                return

                                                             
            op = self._op_index.get((method, path)) or self._op_shape_index.get((method, self._canonical_path(path)))
            exp = self._op_requires_auth(op)
            if exp is None:
                should = should_access
            else:
                should = (role != "anonymous") if exp else True

            if allowed != should:
                desc = "Unauthorized access" if allowed else "Access denied"
                sev = "High" if allowed and should is False else "Medium"
                eff_url = getattr(getattr(r, "request", None), "url", rreq.get("url"))
                self._log_issue(
                    url=eff_url,
                    description=f"{desc} - {method} as {role} (expected: {should})",
                    severity=sev,
                    details={"method": method, "role": role, "expected_access": should},
                    response_obj=r,
                )
        except requests.Timeout:
            self._log_issue(url=rreq.get("url", ep["url"]), description=f"Request timeout - {method} as {role}", severity="Low", details={"method": method, "role": role})
        except requests.ConnectionError:
            self._log_issue(url=rreq.get("url", ep["url"]), description=f"Connection error - {method} as {role}", severity="Low", details={"method": method, "role": role})
        except Exception as exc:
            self._log_issue(url=rreq.get("url", ep["url"]), description=f"Request error - {method} as {role}: {exc}", severity="Low", details={"method": method, "role": role})

                                                                 
    # ----------------------- Funtion _filtered_issues ----------------------------#
        
    def _filtered_issues(self) -> List[Dict[str, Any]]:
            if not self.authz_issues:
                return []

            ignore_statuses = {0, 400, 404, 405}
            out: List[Dict[str, Any]] = []
            for it in self.authz_issues:
                try:
                    code = int(it.get("status_code", 0) or 0)
                except Exception:
                    continue
                if code in ignore_statuses:
                    continue
                if 500 <= code < 600:
                    continue

                path = str(it.get("endpoint") or "")
                desc = (it.get("description") or "").lower()
                body = it.get("response_body") or ""
                
                sensitive_flag = False
                if ".env" in path or "exposed" in desc or "sensitive" in desc:
                    sensitive_flag = True
                else:
                   
                    import re, json
                    if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", body, flags=re.I):
                        sensitive_flag = True
                    if re.search(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", body):
                        sensitive_flag = True
                    if re.search(r'"(access_)?token"\s*:\s*"', body, flags=re.I):
                        sensitive_flag = True

                if code == 200 and not sensitive_flag:
                   
                    generic = False
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            keys = set(map(lambda k: str(k).lower(), data.keys()))
                            if keys and keys.issubset({"message","status","detail","error"}):
                                generic = all(not isinstance(v, (dict, list)) for v in data.values())
                    except Exception:
                        txt = (body or "").strip().lower()
                        if len(txt) <= 64 and txt in {"ok","success","done","created","updated","deleted"}:
                            generic = True
                    if generic:
                        continue

                
                try:
                    canon = self._canonical_path(path)
                except Exception:
                    canon = path

                def _shape(text: str) -> str:
                    if not text:
                        return ""
                    try:
                        import json, re
                        data = json.loads(text)
                    except Exception:
                        import re
                        return re.sub(r"\s+", " ", text).strip()[:4096]
                    def norm(v):
                        if isinstance(v, dict):
                            return {k: norm(val) for k,val in sorted(v.items(), key=lambda x: x[0]) if k not in {"timestamp","time","date","requestId","request_id"}}
                        if isinstance(v, list):
                            return [norm(v[0])] if v else []
                        if isinstance(v, str):
                            return "S"
                        if isinstance(v, (int,float)):
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

                import hashlib
                shape = _shape(body)
                fp = f"{it.get('method','')}|{canon}|{code}|{hashlib.sha1(shape.encode('utf-8','ignore')).hexdigest()}"

                it["fingerprint"] = fp
                out.append(it)
           
            dedup: Dict[str, Dict[str, Any]] = {}
            for it in out:
                fp = it.get("fingerprint")
                if not fp:
                    continue
                if fp in dedup:
                    d = dedup[fp]
                    d["duplicate_count"] = d.get("duplicate_count", 1) + 1
                    v = d.setdefault("variants", [])
                    desc = it.get("description","")
                    if desc and desc not in v:
                        v.append(desc)
                else:
                    it.setdefault("duplicate_count", 1)
                    it.setdefault("variants", [it.get("description","")])
                    dedup[fp] = it
            return list(dedup.values())

        # ----------------------- Funtion _log_issue ----------------------------#
    def _log_issue(
        self,
        url: str,
        description: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
        response_obj: Optional[requests.Response] = None,
    ) -> None:
        details = details or {}
        status_code = getattr(response_obj, "status_code", None)
        if status_code is None or status_code == 0 or status_code in (400, 404):
            return
        real_url = getattr(getattr(response_obj, "request", None), "url", None) if response_obj is not None else None
        used_url = real_url or url
        endpoint_path = urlparse(used_url).path
        entry: Dict[str, Any] = {
            "url": used_url,
            "endpoint": endpoint_path,
            "method": details.get("method", "GET"),
            "description": description,
            "severity": severity,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "request_headers": {},
            "response_headers": {},
            "request_cookies": {},
            "response_cookies": {},
            "request_body": None,
            "response_body": None,
        }
        if response_obj is not None:
            entry["response_headers"] = dict(response_obj.headers)
            entry["response_body"] = response_obj.text[:2048]
            entry["response_cookies"] = response_obj.cookies.get_dict()
            if response_obj.request is not None:
                entry["request_headers"] = dict(response_obj.request.headers)
                body = response_obj.request.body
                entry["request_body"] = body[:1024] if isinstance(body, (str, bytes)) else body
                entry["request_cookies"] = self.session.cookies.get_dict()
        for k, v in (details or {}).items():
            if k not in entry:
                entry[k] = v
        self.authz_issues.append(entry)

        # ----------------------- Funtion generate_report ----------------------------#
    def generate_report(self, fmt: str = "html") -> str:
        issues = self._filtered_issues()
        gen = ReportGenerator(issues, scanner="Authorization", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    # ----------------------- Funtion save_report ----------------------------#
    def save_report(self, path: str, fmt: str = "html") -> None:
        issues = self._filtered_issues()
        ReportGenerator(issues, scanner="Authorization", base_url=self.base_url).save(path, fmt=fmt)
