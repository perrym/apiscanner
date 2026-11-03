########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 24-06-2026                               #
########################################################
from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlencode, urljoin

import requests
from tqdm import tqdm

from report_utils import ReportGenerator

SENSITIVE_KEY_RX = re.compile(
    r"(password|passphrase|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|ssn|bsn|iban|credit|card|cvv|pin|otp|"
    r"mfa|totp|jwt|session|cookie|bearer|authorization)",
    re.IGNORECASE,
)

EXPAND_PARAM_CANDIDATES: List[Dict[str, str]] = [
    {"fields": "*"},
    {"select": "*"},
    {"include": "*"},
    {"expand": "*"},
    {"$select": "*"},
    {"$expand": "*"},
    {"projection": "all"},
]


#================funtion _safe_json Parse response body as JSON when possible =============
CREDENTIAL_KEY_RX = re.compile(
    r"(?:[a-z0-9]+[_-])?(password|passwd|pwd|passphrase|password[_-]?hash|hashed[_-]?password|pass[_-]?hash|"
    r"secret|secret[_-]?key|client[_-]?secret|api[_-]?key|private[_-]?key)", re.I)


def _credential_values(obj: Any, prefix: str = "") -> Set[str]:
    # Credential-named keys that carry a non-empty string value.
    found: Set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, str) and v and CREDENTIAL_KEY_RX.fullmatch(str(k)):
                found.add(key)
            found |= _credential_values(v, key)
    elif isinstance(obj, list):
        for item in obj[:3]:
            found |= _credential_values(item, prefix)
    return found


def _resolve_ref(spec: dict, node: Any, depth: int = 0) -> Any:
    while isinstance(node, dict) and "$ref" in node and depth < 8:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        target: Any = spec
        try:
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError):
            return {}
        node, depth = target, depth + 1
    return node


def _schema_properties(spec: dict, schema: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
    # Declared properties of an object schema; None when the schema does not constrain fields.
    schema = _resolve_ref(spec, schema)
    if not isinstance(schema, dict) or depth > 8:
        return None
    if schema.get("additionalProperties") not in (None, False):
        return None
    props: Dict[str, Any] = dict(schema.get("properties") or {})
    for key in ("allOf", "oneOf", "anyOf"):
        for part in schema.get(key) or []:
            sub = _schema_properties(spec, part, depth + 1)
            if sub is None and key == "allOf":
                return None
            props.update(sub or {})
    return props or None


def _undocumented_fields(spec: dict, schema: Any, data: Any, prefix: str = "", depth: int = 0) -> Set[str]:
    found: Set[str] = set()
    schema = _resolve_ref(spec, schema)
    if depth > 8 or not isinstance(schema, dict):
        return found
    if isinstance(data, dict):
        props = _schema_properties(spec, schema)
        if props is None:
            return found
        for key, value in data.items():
            if key not in props:
                found.add(prefix + str(key))
            else:
                found |= _undocumented_fields(spec, props[key], value, f"{prefix}{key}.", depth + 1)
    elif isinstance(data, list) and schema.get("items"):
        for item in data[:3]:
            found |= _undocumented_fields(spec, schema["items"], item, prefix, depth + 1)
    return found


def _response_schema(spec: dict, operation: dict, status: int) -> Any:
    responses = (operation or {}).get("responses") or {}
    code = str(status)
    entry = responses.get(code) or responses.get(code[0] + "XX") or responses.get(code[0] + "xx")
    if entry is None and 200 <= status < 300:
        entry = next((v for k, v in responses.items() if str(k).startswith("2")), None)
    entry = _resolve_ref(spec, entry)
    if not isinstance(entry, dict):
        return None
    if "schema" in entry:
        return entry["schema"]
    for media, body in (entry.get("content") or {}).items():
        if "json" in media.lower() and isinstance(body, dict) and body.get("schema"):
            return body["schema"]
    return None


def _safe_json(resp: requests.Response) -> Optional[Any]:
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" not in ctype and not (resp.text or "").lstrip().startswith(("{", "[")):
        return None
    try:
        return resp.json()
    except Exception:
        return None


#================funtion _flatten_keys Flatten nested JSON keys into dot-notation set =============
def _flatten_keys(obj: Any, prefix: str = "", out: Optional[Set[str]] = None) -> Set[str]:
    if out is None:
        out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.add(key)
            _flatten_keys(v, key, out)
    elif isinstance(obj, list):
        for item in obj[:3]:
            _flatten_keys(item, prefix, out)
    return out


#================funtion _contains_sensitive_keys Detect keys that match sensitive patterns =============
def _contains_sensitive_keys(keys: Set[str]) -> List[str]:
    return sorted({k for k in keys if SENSITIVE_KEY_RX.search(k)})


#================funtion _build_url Join base URL and path safely =============
def _build_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/") + "/"
    return urljoin(base, (path or "").lstrip("/"))


#================funtion _add_query Append query parameters to URL =============
def _add_query(url: str, params: Dict[str, str]) -> str:
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(params, doseq=True)


#================funtion _parse_header Parse a single HTTP header string into dict =============
def _parse_header(raw: str) -> Dict[str, str]:
    raw = (raw or "").strip()
    if not raw or ":" not in raw:
        return {}
    name, val = raw.split(":", 1)
    name = name.strip()
    val = val.strip()
    return {name: val} if name else {}


@dataclass
class Finding:
    endpoint: str
    url: str
    method: str
    description: str
    severity: str
    timestamp: str
    status_code: int = 0
    request: Optional[Dict[str, Any]] = None
    response_headers: Optional[List[tuple[str, str]]] = None
    response_body: str = ""
    extra: Optional[Dict[str, Any]] = None

    #================funtion to_dict Serialize Finding into a plain dictionary =============
    def to_dict(self) -> Dict[str, Any]:
        d = {
            "endpoint": self.endpoint,
            "url": self.url,
            "method": self.method,
            "description": self.description,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "request": self.request or {},
            "response_headers": self.response_headers or [],
            "response_body": self.response_body,
        }
        if self.extra:
            d.update(self.extra)
        return d


class ObjectPropertyAuditor:
    #================funtion __init__ Initialize auditor configuration and runtime state =============
    def __init__(
        self,
        *,
        base_url: str,
        session: requests.Session,
        show_progress: bool = True,
        timeout: float = 5.0,
        max_body: int = 4096,
        active_mode: bool = False,
        active_ok: bool = False,
        active_header: str = "",
        swagger_spec: Optional[dict] = None,
        test_user_id: str = "1001",
        test_admin_id: str = "9999",
    ) -> None:
        if not base_url or not isinstance(base_url, str):
            raise ValueError("base_url is required")
        if session is None:
            raise ValueError("session is required")

        self.base_url = base_url.rstrip("/") + "/"
        self.session = session
        self.show_progress = show_progress
        self.timeout = float(timeout)
        self.max_body = int(max_body)

        self.test_user_id = str(test_user_id)
        self.test_admin_id = str(test_admin_id)

        self.active_mode = bool(active_mode)
        self.active_ok = bool(active_ok)
        self.active_header = _parse_header(active_header)

        self.spec = swagger_spec or {}
        self.issues: List[Dict[str, Any]] = []
        self.diagnostics = []
        self.coverage = {}

    #================funtion _log Record a finding with request/response context =============
    def _log(
        self,
        *,
        endpoint: str,
        url: str,
        method: str,
        description: str,
        severity: str,
        response: Optional[requests.Response] = None,
        request_data: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        status = int(getattr(response, "status_code", 0) or 0)
        headers_list: List[tuple[str, str]] = []
        body = ""
        if response is not None:
            try:
                headers_list = [(str(k), str(v)) for k, v in response.headers.items()]
            except Exception:
                headers_list = []
            try:
                body = (response.text or "")[: self.max_body]
            except Exception:
                body = ""

        self.issues.append(
            Finding(
                endpoint=endpoint or url,
                url=url,
                method=(method or "GET").upper(),
                description=description,
                severity=severity,
                timestamp=datetime.utcnow().isoformat(),
                status_code=status,
                request=request_data or {},
                response_headers=headers_list,
                response_body=body,
                extra=extra,
            ).to_dict()
        )

    #================funtion _probe Execute an HTTP request with optional JSON body =============
    def _probe(self, method: str, url: str, *, json_body: Any = None) -> Optional[requests.Response]:
        self.coverage['started'] = self.coverage.get('started', 0) + 1
        try:
            from openapi_universal import iter_operations, build_request
            from urllib.parse import urlsplit
            import re
            kwargs = {}
            target = urlsplit(url).path
            operation = next((op for op in iter_operations(self.spec) if op['method']==method.upper()
                              and re.fullmatch(re.sub(r'\{[^}]+\}', '[^/]+', re.escape(op['path']).replace(r'\{','{').replace(r'\}','}')),target)),None)
            if operation:
                built = build_request(self.spec,self.base_url,operation)
                kwargs = {k:v for k,v in built.items() if k not in ('method','url')}
            kwargs.setdefault('headers',{}).update(dict(self.active_header))
            kwargs['timeout'] = self.timeout
            if json_body is not None:
                kwargs['json'] = json_body
            response = self.session.request(method.upper(),url,**kwargs)
        except (requests.RequestException, ValueError) as exc:
            self.coverage['failed'] = self.coverage.get('failed', 0) + 1
            self.diagnostics.append(dict(audit='API3',url=url,error=str(exc)))
            return None
        if 200 <= response.status_code < 300:
            self.coverage['completed'] = self.coverage.get('completed', 0) + 1
        elif response.status_code in (401,403,404,405):
            self.coverage['blocked'] = self.coverage.get('blocked', 0) + 1
            self.diagnostics.append(dict(audit='API3',url=url,status=response.status_code,execution_status='blocked',reason='Baseline access or method rejected'))
        else:
            self.coverage['failed'] = self.coverage.get('failed', 0) + 1
            self.diagnostics.append(dict(audit='API3',url=url,status=response.status_code,error='Request rejected or server error'))
        return response

    #================funtion _is_safe_method Identify read-only HTTP methods =============
    def _is_safe_method(self, method: str) -> bool:
        return (method or "").upper() in {"GET", "HEAD", "OPTIONS"}

    #================funtion _check_sensitive_fields Flag sensitive-looking fields in responses =============
    def _check_sensitive_fields(
        self, endpoint: str, method: str, url: str, resp: requests.Response
    ) -> None:
        data = _safe_json(resp)
        if data is None:
            return
        keys = _flatten_keys(data)
        hits = _contains_sensitive_keys(keys)
        if not hits:
            return
        credentials = sorted(_credential_values(data))
        if credentials:
            sev = "Low"
            description = ("Credential-type field names in response: " + ", ".join(credentials[:10])
                           + "; data sensitivity and authorization boundary require review.")
        else:
            sev = "Info"
            description = ("Observation: response contains potentially sensitive field names; "
                           "data sensitivity, ownership and authorization boundary unverified.")
        self._log(
            endpoint=endpoint,
            url=url,
            method=method,
            description=description,
            severity=sev,
            response=resp,
            extra={"sensitive_fields": hits},
        )

    def _check_undocumented_fields(self, endpoint: str, method: str, url: str, resp: requests.Response) -> None:
        seen = self.__dict__.setdefault("_undocumented_seen", set())
        if (endpoint, method) in seen:
            return
        seen.add((endpoint, method))
        operation = ((self.spec.get("paths") or {}).get(endpoint) or {}).get(method.lower())
        schema = _response_schema(self.spec, operation, resp.status_code)
        data = _safe_json(resp)
        if schema is None or data is None:
            return
        extra = sorted(_undocumented_fields(self.spec, schema, data))
        if not extra:
            return
        sensitive = [k for k in extra if SENSITIVE_KEY_RX.search(k.rsplit(".", 1)[-1])]
        shown = ", ".join(extra[:15]) + (f" (+{len(extra) - 15} more)" if len(extra) > 15 else "")
        if sensitive:
            severity = "Low"
            description = ("Undocumented response fields with sensitive names: " + ", ".join(sensitive[:10])
                           + "; all undocumented fields: " + shown + ". Possible excessive data exposure; review required.")
        else:
            severity = "Info"
            description = ("Observation: response contains fields not declared in the OpenAPI response schema: "
                           + shown + "; data exposure impact unverified.")
        self._log(endpoint=endpoint, url=url, method=method, description=description, severity=severity,
                  response=resp, extra={"undocumented_fields": extra})

    #================funtion _check_field_expansion Detect expansion via common query parameters =============
    def _check_field_expansion(
        self, endpoint: str, method: str, base_url: str, baseline_keys: Set[str]
    ) -> None:
        for params in EXPAND_PARAM_CANDIDATES:
            test_url = _add_query(base_url, params)
            resp = self._probe(method, test_url)
            if resp is None or resp.status_code < 200 or resp.status_code >= 300:
                continue
            data = _safe_json(resp)
            if data is None:
                continue
            keys = _flatten_keys(data)
            if not keys:
                continue
            new_keys = keys - baseline_keys
            if not new_keys:
                continue

            new_hits = _contains_sensitive_keys(new_keys)
            severity = "Medium"
            desc = (
                "Output expands when using common field-selection/expansion parameters; "
                "review authorization and data filtering."
            )
            if new_hits:
                severity = "Info"
                desc = (
                    "Sensitive fields become visible when using field-selection/expansion "
                    "parameters; likely property-level authorization issue."
                )

            self._log(
                endpoint=endpoint,
                url=test_url,
                method=method,
                description=desc,
                severity=severity,
                response=resp,
                extra={
                    "baseline_url": base_url,
                    "expansion_params": params,
                    "new_fields_sample": sorted(list(new_keys))[:50],
                    "new_sensitive_fields": new_hits,
                },
            )
            return

    #================funtion _active_mass_assignment Active write test for mass assignment indicators =============
    def _active_mass_assignment(self, endpoint: str, url: str) -> None:
        if not (self.active_mode and self.active_ok):
            if self.active_mode and not self.active_ok:
                self._log(
                    endpoint=endpoint,
                    url=url,
                    method="POST/PUT/PATCH",
                    description=(
                        "API3 ACTIVE requested but not acknowledged. Use --api3-active-ok "
                        "YES to enable write tests."
                    ),
                    severity="Info",
                )
            return

        malicious_fields = {
            "is_admin": True,
            "isAdmin": True,
            "role": "administrator",
            "permissions": "all",
            "accountType": "premium",
            "balance": 999999,
            "emailVerified": True,
            "twoFactorEnabled": False,
            "ownerId": self.test_admin_id,
            "userId": self.test_admin_id,
        }

        for method in ("POST", "PUT", "PATCH"):
            resp = self._probe(method, url, json_body=malicious_fields)
            if resp is None:
                continue
            if resp.status_code not in (200, 201):
                continue

            data = _safe_json(resp)
            if not isinstance(data, dict):
                continue

            changed = []
            for k, v in malicious_fields.items():
                if k in data and data.get(k) == v:
                    changed.append(k)

            if changed:
                self._log(
                    endpoint=endpoint,
                    url=url,
                    method=method,
                    description=(
                        "Mass assignment/property manipulation indicators: server reflected "
                        "privileged fields from client input; persistence, field policy and privilege impact unverified."
                    ),
                    severity="Info",
                    response=resp,
                    request_data={"json": malicious_fields},
                    extra={"modified_fields": changed},
                )
                return

    #================funtion test_object_properties Run API3 property-level checks across endpoints =============
    def test_object_properties(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self.issues = []
        self.diagnostics = []
        self.coverage = dict(audit='API3',started=0,completed=0,failed=0,skipped=0,not_applicable=0,blocked=0,
            note='HTTP requests; passive field checks by default. Write tests require active mode.')
        eps = endpoints or []

        iterator = (
            tqdm(eps, desc="API3 property endpoints", unit="endpoint")
            if self.show_progress
            else eps
        )
        for ep in iterator:
            try:
                path = ep.get("path") or ep.get("url") or "/"
                method = (ep.get("method") or "GET").upper()
                from scanner_quality import normalize_endpoint, path_values
                url = normalize_endpoint(path,self.base_url,path_values(self.spec,getattr(self,"path_parameter_values",{})))

                if self._is_safe_method(method):
                    resp = self._probe(method, url)
                    if resp is not None:
                        if resp.status_code not in (401, 403, 404, 405) and (
                            200 <= resp.status_code < 300
                        ):
                            data = _safe_json(resp)
                            if data is not None:
                                keys = _flatten_keys(data)
                                self._check_sensitive_fields(path, method, url, resp)
                                self._check_undocumented_fields(path, method, url, resp)
                                self._check_field_expansion(path, method, url, keys)
                else:
                    # Passive inspection needs a declared read operation.
                    from openapi_universal import iter_operations
                    declared_get = any(op['path']==path and op['method']=='GET' for op in iter_operations(self.spec))
                    if self.spec and not declared_get:
                        self.coverage['not_applicable'] += 1
                        get_resp = None
                    else:
                        get_resp = self._probe('GET', url)
                    if get_resp is not None and get_resp.status_code not in (401, 403, 404, 405) and (
                        200 <= get_resp.status_code < 300
                    ):
                        self._check_sensitive_fields(path, 'GET', url, get_resp)
                        self._check_undocumented_fields(path, 'GET', url, get_resp)

                if self.active_mode:
                    self._active_mass_assignment(path, url)

            except Exception as exc:
                self.coverage['skipped'] += 1
                self.diagnostics.append(dict(audit='API3',url=ep.get('path'),error=str(exc)))

        self.coverage['state'] = 'incomplete' if self.coverage['failed'] or self.coverage['skipped'] or self.coverage['blocked'] else ('completed' if self.coverage['completed'] else 'not_applicable')
        return self.issues

    #================funtion generate_report Generate a report in markdown or HTML format =============
    def generate_report(self, fmt: str = "markdown") -> str:
        gen = ReportGenerator(
            self.issues,
            scanner="Broken Object Property Level Authorization (API3)",
            base_url=self.base_url,
        )
        if fmt == "markdown":
            return gen.generate_markdown()
        if fmt == "html":
            return gen.generate_html()
        return gen.generate_html()

    #================funtion save_report Save a report file to disk =============
    def save_report(self, path: str, fmt: str = "markdown") -> None:
        ReportGenerator(
            self.issues,
            scanner="Broken Object Property Level Authorization (API3)",
            base_url=self.base_url,
        ).save(path, fmt=fmt)
