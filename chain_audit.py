########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.0 07-07-2026                               #
########################################################

"""
Chain Auditor  after a successful BOLA test, automatically reuse leaked data
in other endpoints from the same Swagger spec.

How it works:
  1. Take all BOLA findings with cross_user=True or sensitive_hit=True
  2. Extract leaked tokens, emails, user IDs, roles from response bodies
  3. Search the Swagger spec for parameters that accept these values
  4. Send "chained" requests and report privilege escalations
"""

from __future__ import annotations

import json
import os
import re
import time
import logging
import hashlib
import concurrent.futures
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Iterable
from urllib.parse import urljoin

import requests
from requests import exceptions as req_exc
from tqdm import tqdm

from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig as OASSecurityConfig,
)

try:
    from swagger_utils import OpenAPIRequestBuilder, DummyGeneratorConfig
    _HAS_DUMMY_GEN = True
except ImportError:
    _HAS_DUMMY_GEN = False

logger = logging.getLogger(__name__)

# 
#  Data-extractie: herken gevoelige velden in BOLA responses
# 


_JWT_RE = re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_API_KEY_RE = re.compile(r"(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{16,})", re.I)
_BEARER_RE = re.compile(r"(?:bearer|token)\s+([A-Za-z0-9._\-+/=]{20,})", re.I)


_SENSITIVE_JSON_FIELDS: Dict[str, str] = {
    "access_token": "token",
    "refresh_token": "token",
    "token": "token",
    "id_token": "token",
    "jwt": "token",
    "bearer": "token",
    "api_key": "token",
    "apikey": "token",
    "session": "token",
    "auth": "token",

    "email": "email",
    "username": "identity",
    "login": "identity",
    "user": "identity",
    "name": "identity",

    "id": "resource_id",
    "uuid": "resource_id",
    "guid": "resource_id",
    "user_id": "resource_id",
    "userId": "resource_id",
    "account_id": "resource_id",
    "customer_id": "resource_id",
    "order_id": "resource_id",

    "role": "role",
    "permissions": "role",
    "group": "role",
    "type": "role",
    "is_admin": "role",
    "isAdmin": "role",
    "admin": "role",
}


@dataclass
class ExtractedValue:
    """A value leaked from a BOLA response."""
    key: str           # the JSON key or pattern name (e.g. "access_token")
    value: str         # the leaked value itself
    kind: str          # token | email | identity | resource_id | role
    source_url: str    # the BOLA endpoint URL this came from
    source_method: str


@dataclass
class ChainFinding:
    """A finding after a chain test."""
    description: str
    source_bola_url: str
    chained_url: str
    chained_method: str
    leaked_key: str
    leaked_kind: str
    status_code: int
    response_sample: str = ""
    severity: str = "Medium"
    response_time: float = 0.0
    error: Optional[str] = None
    timestamp: str = ""
    # Fields for reproducible audit trail
    curl_command: str = ""
    injected_header: str = ""
    injected_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.chained_method,
            "url": self.chained_url,
            "endpoint": self.chained_url,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "description": self.description,
            "severity": self.severity,
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "request_parameters": {},
            "request_headers": [],
            "request_cookies": {},
            "request_body": "",
            "response_headers": [],
            "response_cookies": {},
            "response_body": self.response_sample,
            "true_positive": True,
            "cross_user": True,
            "sensitive_hit": True,
            "chain_source": self.source_bola_url,
            "chain_leaked_key": self.leaked_key,
            "chain_leaked_kind": self.leaked_kind,
            "chain_curl": self.curl_command,
            "fingerprint": hashlib.sha1(
                f"chain|{self.chained_method}|{self.chained_url}|{self.status_code}".encode()
            ).hexdigest(),
            "duplicate_count": 1,
            "variants": [self.description],
        }

    def build_curl(self, token: str = "***REDACTED***") -> str:
        """Generate a reproducible curl command for this chain finding."""
        header_parts = []
        if self.injected_header:
            safe_val = token if self.leaked_kind == "token" else self.injected_value
            header_parts.append(f'-H "{self.injected_header}: {safe_val}"')
        parts = [
            "curl", "-X", self.chained_method,
        ] + header_parts + [
            f'"{self.chained_url}"',
        ]
        self.curl_command = " ".join(parts)
        return self.curl_command


# 
#  Data-extractie helpers
# 

def _extract_from_json(data: Any, source_url: str = "", source_method: str = "") -> List[ExtractedValue]:
    """Loop recursief door JSON en pluk alle herkenbare velden."""
    out: List[ExtractedValue] = []
    seen: set = set()

    def walk(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                kind = _SENSITIVE_JSON_FIELDS.get(kl)
                if kind and isinstance(v, str) and v.strip():
                    val = v.strip()
                    if val not in seen and 1 < len(val) < 2048:
                        seen.add(val)
                        out.append(ExtractedValue(
                            key=str(k), value=val, kind=kind,
                            source_url=source_url, source_method=source_method,
                        ))
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(obj, list):
            for item in obj:
                walk(item, prefix)

    walk(data)
    return out


def _extract_from_text(text: str, source_url: str = "", source_method: str = "") -> List[ExtractedValue]:
    """Extract tokens, emails, API keys from plain text."""
    out: List[ExtractedValue] = []
    seen: set = set()
    t = str(text or "")

    for m in _JWT_RE.finditer(t):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            out.append(ExtractedValue(key="jwt", value=val, kind="token",
                                      source_url=source_url, source_method=source_method))

    for m in _EMAIL_RE.finditer(t):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            out.append(ExtractedValue(key="email", value=val, kind="email",
                                      source_url=source_url, source_method=source_method))

    for m in _API_KEY_RE.finditer(t):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            out.append(ExtractedValue(key="api_key", value=val, kind="token",
                                      source_url=source_url, source_method=source_method))

    for m in _BEARER_RE.finditer(t):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            out.append(ExtractedValue(key="bearer_token", value=val, kind="token",
                                      source_url=source_url, source_method=source_method))

    return out


def extract_all_from_response(body_text: str, source_url: str = "", source_method: str = "") -> List[ExtractedValue]:
    """Try JSON first, then plain text."""
    result: List[ExtractedValue] = []
    if not body_text:
        return result
    try:
        data = json.loads(body_text)
        result.extend(_extract_from_json(data, source_url, source_method))
    except (json.JSONDecodeError, ValueError):
        pass
    result.extend(_extract_from_text(body_text, source_url, source_method))
    return result


# 
#  Endpoint-parameter matching: which endpoint can use this data?
# 

_PREFIX_RANK: Dict[str, int] = {"": 0, "x-": 1, "x_": 1}

def _param_accepts_kind(param_name: str, param_loc: str, kind: str) -> bool:
    """Check whether a Swagger parameter matches the 'kind' of the leaked value."""
    pn = str(param_name or "").lower()

    # Rank by prefix: native takes priority over x-* custom headers
    rank = 100
    for prefix, r in _PREFIX_RANK.items():
        if pn.startswith(prefix):
            rank = r
            pn_core = pn[len(prefix):]
            break
    else:
        pn_core = pn

    if kind == "token":
        token_names = {"authorization", "token", "access_token", "bearer", "api_key", "apikey",
                       "x-api-key", "x-auth-token", "auth", "jwt", "session", "id_token",
                       "refresh_token"}
        if param_loc in ("header",):
            return pn_core.rstrip("_") in token_names
        return any(t in pn_core for t in ("token", "api_key", "apikey", "auth", "key"))

    if kind == "email":
        return pn in {"email", "e-mail", "mail", "username", "login", "user"}

    if kind == "identity":
        return pn in {"username", "user", "login", "name", "account", "profile", "email"}

    if kind == "resource_id":
        id_names = {"id", "uuid", "guid", "user_id", "userid", "account_id", "accountid",
                    "customer_id", "order_id", "product_id", "item_id"}
        return pn_core in id_names or any(
            suffix in pn_core for suffix in ("_id", "id", "uuid", "guid", "key", "slug")
        )

    if kind == "role":
        return pn in {"role", "type", "group", "permissions", "is_admin", "isadmin", "admin"}

    return False


def _validate_value_format(ev: ExtractedValue, param: Dict[str, Any]) -> bool:
    """Validate whether the ExtractedValue format matches the Swagger parameter.
    Returns False when formats clearly mismatch (UUID vs integer etc.)."""
    schema = param.get("schema", {}) or {}
    fmt = (schema.get("format") or "").lower().strip()
    ptype = (schema.get("type") or "string").lower().strip()

    val = ev.value.strip()
    if not val:
        return False

    # UUID format check
    if fmt == "uuid" or (ptype == "string" and "uuid" in (param.get("name") or "").lower()):
        uuid_re = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        )
        if not uuid_re.match(val):
            return False

    # Integer/number format check
    if ptype in ("integer", "number") or fmt in ("int32", "int64", "float", "double"):
        try:
            int(val)
        except (ValueError, TypeError):
            try:
                float(val)
            except (ValueError, TypeError):
                return False

    # Email format check
    if fmt == "email" or param.get("name", "").lower() in ("email", "e-mail"):
        if "@" not in val or "." not in val.split("@")[-1]:
            return False

    # Date/datetime format  skip if we have random strings
    if fmt in ("date", "date-time"):
        date_re = re.compile(r"^\d{2,4}[-/]\d{2}[-/]\d{2,4}")
        if not date_re.match(val):
            return False

    return True


def find_chainable_endpoints(
    extracted: List[ExtractedValue],
    swagger_spec: Dict[str, Any],
    bola_endpoint_paths: set,
) -> List[Tuple[ExtractedValue, Dict[str, Any], str]]:
    """
    For each ExtractedValue, search the Swagger spec for endpoints that:
      - are NOT the BOLA source endpoint itself
      - have a parameter that accepts the same 'kind' of data

    Returns: list of (ExtractedValue, op_dict, match_param_name)
    """
    matches: List[Tuple[ExtractedValue, Dict[str, Any], str]] = []
    seen_combos: set = set()

    for op in oas_iter_ops(swagger_spec or {}):
        op_path = op.get("path") or ""
        op_method = op.get("method") or "GET"

        # Skip the source endpoint itself
        if op_path in bola_endpoint_paths:
            continue

        # Merge path-level + operation-level parameters
        meta = op.get("raw", {}) or {}
        path_params = (meta.get("parameters") or []) if isinstance(meta, dict) else []
        op_params = op.get("parameters") or []
        all_params = list(path_params) + list(op_params)

        # Also check body properties (for JSON requestBody)
        rb = (op.get("requestBody") or meta.get("requestBody")) if isinstance(meta, dict) else op.get("requestBody")
        body_params: List[Dict[str, Any]] = []
        if rb and isinstance(rb, dict):
            for content_type, content_spec in (rb.get("content") or {}).items():
                if not isinstance(content_spec, dict):
                    continue
                schema = content_spec.get("schema") or {}
                for prop_name, prop_schema in (schema.get("properties") or {}).items():
                    body_params.append({
                        "name": prop_name,
                        "in": "body",
                        "required": prop_name in (schema.get("required") or []),
                        "schema": prop_schema or {},
                    })

        effective_params: List[Dict[str, Any]] = list(all_params) + body_params

        for ev in extracted:
            for param in effective_params:
                pname = param.get("name") or ""
                ploc = param.get("in") or "query"
                if _param_accepts_kind(pname, ploc, ev.kind):
                    # Validate format match (UUID vs integer etc.)
                    if not _validate_value_format(ev, param):
                        continue
                    combo_key = (ev.value, op_path, op_method, pname)
                    if combo_key not in seen_combos:
                        seen_combos.add(combo_key)
                        matches.append((ev, op, pname))

    return matches


# 
#  Chain Auditor (main class)
# 

class ChainAuditor:
    """Runs chained requests based on BOLA findings."""

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        swagger_spec: Dict[str, Any],
        bola_results: List[Any],
        timeout: float = 10.0,
        test_delay: float = 0.0,
        max_workers: int = 2,
        show_progress: bool = True,
    ) -> None:
        self.session = session
        self.base_url = base_url.rstrip("/") + "/" if base_url else ""
        self.swagger_spec = swagger_spec or {}
        self.timeout = timeout
        self.test_delay = float(os.environ.get("APISCAN_CHAIN_DELAY", str(test_delay)))
        self.max_workers = max_workers
        self.show_progress = show_progress

        # Normalize BOLA results to uniform dicts
        self.bola_results: List[Dict[str, Any]] = []
        for r in bola_results or []:
            if hasattr(r, "to_dict"):
                d = r.to_dict()
            elif isinstance(r, dict):
                d = r
            else:
                continue
            if d.get("cross_user") or d.get("sensitive_hit") or d.get("true_positive"):
                self.bola_results.append(d)

        self.findings: List[ChainFinding] = []
        self._op_index: Dict[Tuple[str, str], dict] = {}
        for _op in oas_iter_ops(self.swagger_spec):
            self._op_index[(_op["method"], _op["path"])] = _op

    #  helpers 

    def _abs_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    def _canonical_path(self, p: str) -> str:
        p = "/" + (p or "").lstrip("/")
        return re.sub(r"\{[^}]+\}", "{}", p)

    #  lazy-init body generator (avoid init on every call) 
    _dummy_builder: Any = None

    def _build_req_from_op(self, method: str, path_template: str) -> Dict[str, Any]:
        key = (method.upper(), path_template)
        op = self._op_index.get(key)
        if not op:
            canon = self._canonical_path(path_template)
            op = next((v for (m, p), v in self._op_index.items()
                       if m.upper() == method.upper() and self._canonical_path(p) == canon), None)
        if not op:
            return {
                "method": method.upper(),
                "url": self._abs_url(path_template),
                "headers": {"User-Agent": "APISecurityScanner-Chain/1.0"},
            }
        try:
            req = oas_build_request(self.swagger_spec, self.base_url, op, None)
        except TypeError:
            return {
                "method": method.upper(),
                "url": self._abs_url(path_template),
                "headers": {"User-Agent": "APISecurityScanner-Chain/1.0"},
            }

        # For POST/PUT/PATCH: generate a dummy body so the endpoint
        # doesn't fail on missing fields. Chain-mode then injects
        # only the leaked value into the right field.
        m_upper = method.upper()
        if m_upper in ("POST", "PUT", "PATCH") and _HAS_DUMMY_GEN:
            if self._dummy_builder is None:
                try:
                    self._dummy_builder = OpenAPIRequestBuilder(
                        self.swagger_spec,
                        config=DummyGeneratorConfig(),
                    )
                except Exception as e:
                    logger.warning("Chain: dummy generator init failed: %s", e)
                    self._dummy_builder = False  # mark as failed
            if self._dummy_builder and self._dummy_builder is not False:
                try:
                    rb = (op.get("raw", {}) or {}).get("requestBody") or op.get("requestBody")
                    if rb and isinstance(rb, dict):
                        for ct, cs in (rb.get("content") or {}).items():
                            schema = cs.get("schema") or {}
                            if schema.get("properties"):
                                body = {}
                                for prop_name, prop_schema in schema.get("properties", {}).items():
                                    body[prop_name] = self._dummy_builder.generate_value(
                                        prop_name, prop_schema
                                    )
                                if "application/json" in ct:
                                    req["json"] = body
                                elif "application/x-www-form-urlencoded" in ct:
                                    req["data"] = body
                                break  # only use first content-type
                except Exception as e:
                    logger.warning("Chain: body generation failed for %s %s: %s",
                                   m_upper, path_template, e)

        return req

    @staticmethod
    def _normalize_token_value(ev: ExtractedValue, param_name: str, param_loc: str) -> str:
        """Put the token in the correct format for the context (Bearer prefix etc.)."""
        val = ev.value
        if param_loc == "header" and param_name.lower() in ("authorization", "auth"):
            if not val.lower().startswith("bearer "):
                val = f"Bearer {val}"
        # Cleanup: remove any quotes that were in the JSON
        val = val.strip('"\'')
        return val

    def _inject_into_request(
        self, req: Dict[str, Any], ev: ExtractedValue, param_name: str
    ) -> Dict[str, Any]:
        """Inject the leaked value into the request at the right location."""
        out = dict(req)
        out.setdefault("headers", {})
        out.setdefault("params", {})

        # Find the parameter object to determine location
        meta = out.get("_op_raw", {}) or {}
        path_params = (meta.get("parameters") or []) if isinstance(meta, dict) else []
        op_params = out.get("_op_params") or []
        all_p = list(path_params) + list(op_params)

        loc = "query"
        for p in all_p:
            if isinstance(p, dict) and p.get("name") == param_name:
                loc = p.get("in", "query")
                break

        # Also check body params (from requestBody schema)
        rb = out.get("_op_requestBody") or {}
        if isinstance(rb, dict):
            for ct, cs in (rb.get("content") or {}).items():
                props = (cs.get("schema") or {}).get("properties") or {}
                if param_name in props:
                    loc = "body"
                    break

        # Normalize the value (Bearer prefix, quotes, etc.)
        normalized = self._normalize_token_value(ev, param_name, loc)

        if loc == "header":
            out["headers"][param_name] = normalized
        elif loc == "path":
            out["url"] = (out.get("url") or "").replace(f"{{{param_name}}}", normalized)
        elif loc == "body":
            body = dict(out.get("json") or {})
            body[param_name] = normalized
            out["json"] = body
        else:
            out["params"][param_name] = normalized

        # Save for curl generation
        out["_chain_injected_header"] = param_name if loc == "header" else ""
        out["_chain_injected_value"] = normalized

        return out

    def _send(self, req: Dict[str, Any]) -> Tuple[Optional[requests.Response], float, Optional[str]]:
        """Send request with exponential backoff on rate-limiting (429/503)."""
        max_attempts = 3
        backoff = 2.0  # start at 2 seconds
        start = time.time()
        last_err: Optional[str] = None

        for attempt in range(1, max_attempts + 1):
            try:
                resp = self.session.request(**req, timeout=self.timeout, allow_redirects=False)
                code = getattr(resp, "status_code", 0) or 0
                if code in (429, 503):
                    logger.warning(
                        "Chain: rate limiting detected (HTTP %d) op %s %s  backoff %.1fs (poging %d/%d)",
                        code, req.get("method", "GET"), req.get("url", ""),
                        backoff, attempt, max_attempts,
                    )
                    if attempt < max_attempts:
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                return resp, time.time() - start, None
            except (req_exc.Timeout, req_exc.ConnectionError) as exc:
                last_err = str(exc)
                if attempt < max_attempts:
                    time.sleep(backoff)
                    backoff *= 2
                continue
            except Exception as exc:
                return None, time.time() - start, str(exc)

        return None, time.time() - start, last_err

    def _classify_chain_severity(
        self, status_code: int, body_text: str, ev_kind: str
    ) -> str:
        """Determine severity of a chain result."""
        if status_code in (0, 400, 401, 403, 404, 405):
            return "Low"
        if 500 <= status_code < 600:
            return "Low"
        if status_code in (200, 201, 202, 204, 206, 302):
            # Check for privilege escalation indicators
            t = (body_text or "").lower()
            admin_markers = ("admin", "administrator", "superuser", "root", "role")
            if ev_kind == "role" and any(m in t for m in admin_markers):
                return "High"
            if ev_kind == "token" and status_code == 200:
                return "High"
            # If we could use an identity or resource_id, it's potentially medium+
            if ev_kind in ("identity", "resource_id") and status_code == 200:
                return "Medium"
            return "Medium"
        return "Low"

    #  hoofdlogica 

    def run(self) -> List[ChainFinding]:
        """Voer de volledige chain-audit uit."""

        # 1. Verzamel alle BOLA-source endpoint paths
        bola_paths: set = set()
        for br in self.bola_results:
            url = br.get("url") or br.get("endpoint") or ""
            try:
                from urllib.parse import urlparse
                bola_paths.add(urlparse(url).path)
            except Exception:
                bola_paths.add(url)

        # 2. Extract leaked data from BOLA responses
        all_extracted: List[ExtractedValue] = []
        for br in self.bola_results:
            body = br.get("response_body") or br.get("response_sample") or ""
            eu = br.get("url") or br.get("endpoint") or ""
            em = br.get("method") or "GET"
            sc = int(br.get("status_code", 0) or 0)

            vals = extract_all_from_response(body, source_url=eu, source_method=em)
            all_extracted.extend(vals)

            # Deep Scan: if we have a 200 OK without extractable data,
            # add a stub ExtractedValue to check if the ID
            # is usable in other endpoints at all.
            if not vals and sc == 200:
                # Try to extract a resource_id from the URL
                stub_id = ""
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(eu)
                    # Look for ID patterns in the path
                    path_parts = parsed.path.strip("/").split("/")
                    # Take the last segment as a potential ID
                    if path_parts:
                        last = path_parts[-1]
                        if re.match(r"^[0-9a-fA-F-]{4,36}$", last):
                            stub_id = last
                except Exception:
                    pass
                if stub_id:
                    all_extracted.append(ExtractedValue(
                        key="id_from_url", value=stub_id, kind="resource_id",
                        source_url=eu, source_method=em,
                    ))
                    logger.debug("Chain: stub resource_id '%s' added from URL.", stub_id)

        if not all_extracted:
            logger.info("Chain: no extractable data in BOLA responses, audit stopped.")
            return []

        logger.info("Chain: %d values extracted from %d BOLA findings.",
                     len(all_extracted), len(self.bola_results))
        for ev in all_extracted:
            logger.info("Chain:   [%s] '%s' = '%s...' from %s %s",
                         ev.kind, ev.key, ev.value[:50], ev.source_method, ev.source_url)

        # 3. Match with other endpoints
        matches = find_chainable_endpoints(all_extracted, self.swagger_spec, bola_paths)

        if not matches:
            logger.info("Chain: no matchable endpoints found for leaked data.")
            return []

        logger.info("Chain: %d chain candidates found (%d unique source values).",
                     len(matches), len({ev.value for ev, _, _ in matches}))
        for ev, op, pname in matches[:10]:  # log eerste 10 matches
            logger.info("Chain:   match: %s '%s'  %s %s (param: %s)",
                         ev.kind, ev.value[:40], op.get("method", "GET"),
                         op.get("path", "/"), pname)

        # 4. Build and send chained requests
        chain_tasks: List[Tuple[ExtractedValue, Dict[str, Any], str]] = []
        for ev, op, pname in matches:
            chain_tasks.append((ev, op, pname))

        if self.show_progress:
            bar = tqdm(chain_tasks, desc="Chain", unit="chain", dynamic_ncols=True)
        else:
            bar = chain_tasks

        for ev, op, pname in bar:
            time.sleep(self.test_delay)

            method = op.get("method") or "GET"
            path = op.get("path") or "/"

            try:
                req = self._build_req_from_op(method, path)
            except Exception:
                continue

            # Save op raw data for injection logic
            req["_op_raw"] = op.get("raw", {})
            req["_op_params"] = op.get("parameters") or []
            req["_op_requestBody"] = (op.get("raw", {}) or {}).get("requestBody")

            # Validate that the JSON body is serializable
            if "json" in req:
                try:
                    json.dumps(req["json"])
                except (TypeError, ValueError) as e:
                    logger.warning("Chain: body not JSON-serializable for %s %s: %s",
                                   method, path, e)
                    del req["json"]  # remove invalid body

            req = self._inject_into_request(req, ev, pname)

            # Read curl info before cleanup
            injected_header = req.get("_chain_injected_header", "")
            injected_value = req.get("_chain_injected_value", "")

            # Clean up internal keys before _send()  requests doesn't accept unknown kwargs
            for k in ("_op_raw", "_op_params", "_op_requestBody",
                       "_chain_injected_header", "_chain_injected_value"):
                req.pop(k, None)

            resp, elapsed, err = self._send(req)

            status_code = getattr(resp, "status_code", 0) or 0 if resp else 0
            body_text = getattr(resp, "text", "") if resp else ""
            eff_url = getattr(getattr(resp, "request", None), "url", req.get("url", ""))

            if err:
                logger.warning(
                    "Chain request FAILED: %s %s | %s",
                    method.upper(), eff_url, err[:120],
                )

            severity = self._classify_chain_severity(status_code, body_text, ev.kind)

            logger.info(
                "Chain request: %s %s | injected %s='%s' (kind=%s)  HTTP %d (%s)",
                method.upper(), eff_url, pname, ev.value[:60], ev.kind,
                status_code, severity,
            )

            sample = ""
            if body_text:
                try:
                    sample = json.dumps(json.loads(body_text), ensure_ascii=False)[:512]
                except Exception:
                    sample = body_text[:512]

            finding = ChainFinding(
                description=(
                    f"Leaked {ev.kind} '{ev.key}' from {ev.source_method} {ev.source_url} "
                    f"injected into {method} {path} (param: {pname})  HTTP {status_code}"
                ),
                source_bola_url=ev.source_url,
                chained_url=eff_url or self._abs_url(path),
                chained_method=method.upper(),
                leaked_key=ev.key,
                leaked_kind=ev.kind,
                status_code=status_code,
                response_sample=sample,
                severity=severity,
                response_time=elapsed,
                error=err,
                timestamp=datetime.utcnow().isoformat(),
                injected_header=injected_header,
                injected_value=injected_value,
            )
            finding.build_curl()
            self.findings.append(finding)

        # 5. Summary and filter for real hits
        status_counts = Counter(f.status_code for f in self.findings)
        sev_counts = Counter(f.severity for f in self.findings)
        logger.info("Chain: HTTP status distribution: %s",
                     dict(sorted(status_counts.items())))
        logger.info("Chain: Severity distribution: %s",
                     dict(sorted(sev_counts.items())))

        real = [f for f in self.findings
                if f.status_code in (200, 201, 202, 204, 206)
                and f.severity in ("Medium", "High")]
        logger.info("Chain: %d of %d chain-requests were successful (Medium).",
                     len(real), len(self.findings))

        return self.findings

    def get_issues(self) -> List[Dict[str, Any]]:
        """Return chain findings as dicts for reporting."""
        return [f.to_dict() for f in self.findings
                if f.severity in ("Medium", "High", "Critical")]
