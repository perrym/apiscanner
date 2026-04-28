########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 4.0 26-04-2026                              #
########################################################

from __future__ import annotations
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from tqdm import tqdm

from report_utils import ReportGenerator

try:
    from openapi_universal import iter_operations as oas_iter_ops
except Exception:
    oas_iter_ops = None

Issue = Dict[str, Any]

_MAX_BODY_LEN = 2048
_MAX_WORKERS = 10


def _normalize_path(path: Any) -> str:
    p = (str(path.get("path") or "") if isinstance(path, dict) else str(path or "")).strip()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def _documented_prefix(path: str) -> str:
    prefix = _normalize_path(path).split("{", 1)[0].rstrip("/")
    return prefix or "/"


class InventoryAuditor:
    _DEBUG_PATHS = [
        # Swagger / OpenAPI
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/swagger.json",
        "/swagger.yaml",
        "/openapi",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api-docs/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/docs",
        "/doc",
        "/redoc",
        # Spring Boot / Java
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/configprops",
        "/actuator/loggers",
        "/actuator/metrics",
        "/actuator/httptrace",
        "/actuator/threaddump",
        "/actuator/heapdump",
        "/actuator/shutdown",
        "/h2-console",
        "/console",
        # Infrastructure / debug
        "/metrics",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/live",
        "/livez",
        "/ping",
        "/status",
        "/info",
        "/debug",
        "/debug/vars",
        "/debug/pprof",
        "/config",
        "/phpinfo",
        "/phpinfo.php",
        "/server-status",
        "/server-info",
        # Secrets / sensitive files
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.git",
        "/.git/config",
        "/.gitignore",
        "/.htaccess",
        "/config.json",
        "/settings.json",
        "/appsettings.json",
        "/web.config",
        "/application.properties",
        "/application.yaml",
        # Admin panels
        "/admin",
        "/admin/api",
        "/administrator",
        "/internal",
        "/internal/api",
        "/private",
        "/private/api",
        "/manage",
        # Identity / OAuth
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/.well-known/oauth-authorization-server",
        "/oauth/token",
        "/oauth2/token",
        "/connect/token",
        "/auth/token",
        # Other
        "/graphql",
        "/graphiql",
        "/playground",
        "/robots.txt",
        "/sitemap.xml",
    ]


    #================funtion __init__ description =============
    def __init__(
        self,
        *args,
        base_url: Optional[str] = None,
        session: Optional[requests.Session] = None,
        timeout: int = 5,
        swagger_spec: Optional[Dict[str, Any]] = None,
        logger: Any = None,
        **kwargs,
    ) -> None:


        if (session is None or base_url is None) and len(args) >= 2:
            if isinstance(args[1], requests.Session):
                base_url, session = args[0], args[1]
            elif isinstance(args[0], requests.Session):
                session, base_url = args[0], args[1]

        if session is None or base_url is None:
            raise ValueError("session and base_url are required")

        if "://" not in str(base_url):
            base_url = "http://" + str(base_url)

        self.base_url = str(base_url).rstrip("/")
        self.session = session
        self.timeout = int(timeout)
        self.logger = logger

        self._lock = threading.Lock()
        self._issues: List[Issue] = []
        self._security_headers_checked = False
        self.spec: Dict[str, Any] = swagger_spec or kwargs.get("spec") or {}


    #================funtion _tw description =============
    def _tw(self, msg: str, level: str = "info") -> None:
        _R  = '\033[0m'
        _RED = '\033[91m'; _YEL = '\033[93m'; _CYN = '\033[96m'
        _icons  = {'error': _RED+'\u2716'+_R, 'warn': _YEL+'\u25b2'+_R, 'info': _CYN+'\u25c6'+_R}
        _labels = {'error': _RED+'Error'+_R,  'warn': _YEL+'Warn' +_R, 'info': _CYN+'Info' +_R}
        ic = _icons.get(level, _icons['info'])
        lb = _labels.get(level, _labels['info'])
        text = f"  {ic}  {lb}  {msg}"
        try:
            tqdm.write(text)
        except Exception:
            print(text)


    @staticmethod
    #================funtion endpoints_from_swagger description =============
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        return list((spec.get("paths") or {}).keys())


    @staticmethod
    #================funtion endpoints_from_universal description =============
    def endpoints_from_universal(spec: Dict[str, Any]) -> List[str]:
        if not spec or not oas_iter_ops:
            return []
        paths: set[str] = set()
        try:
            for op in oas_iter_ops(spec):
                p = (op.get("path") or "/").strip()
                if p:
                    paths.add(p)
        except Exception:
            return []
        return sorted(paths)


    #================funtion _filtered_issues description =============
    def _filtered_issues(self) -> List[Issue]:
        cleaned: List[Issue] = []
        seen: set[tuple[str, str, str, int]] = set()
        for issue in self._issues:
            if not issue.get("issue") or not issue.get("endpoint"):
                continue
            key = (
                str(issue.get("issue") or ""),
                str(issue.get("endpoint") or ""),
                str(issue.get("description") or ""),
                int(issue.get("status_code") or 0),
            )
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(issue)
        return cleaned


    #================funtion _is_api_response description =============
    def _is_api_response(self, resp: requests.Response) -> bool:
        content_type = (resp.headers.get("Content-Type", "") or "").split(";", 1)[0].lower()
        api_types = {
            "application/json",
            "application/x-yaml",
            "application/vnd.oai.openapi",
            "application/vnd.api+json",
            "application/problem+json",
            "application/xml",
            "text/xml",
            "text/json",
        }
        if content_type in api_types:
            return True
        try:
            parsed = resp.json()
            if isinstance(parsed, dict) and {"openapi", "swagger"} & set(parsed.keys()):
                return True
        except Exception:
            pass
        return False


    #================funtion test_inventory description =============
    def test_inventory(self, documented_paths: Optional[List[Any]] = None) -> List[Issue]:

        if documented_paths is None and self.spec:
            documented_paths = self.endpoints_from_universal(self.spec)

        doc_set: set[str] = {_normalize_path(p) for p in (documented_paths or [])}

        paths_to_check: List[str] = []
        paths_to_check.extend(self._DEBUG_PATHS)


        for v in range(1, 12):
            for prefix in (
                "", "/api", "/rest", "/services",
                "/orders", "/products", "/users",
                "/apis", "/app", "/backend",
            ):
                paths_to_check.append(f"{prefix}/v{v}")


        seen: set[str] = set()
        paths_to_check = [p for p in paths_to_check if not (p in seen or seen.add(p))]

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            fut_map = {executor.submit(self._check_path, p, doc_set): p for p in paths_to_check}

            for fut in tqdm(as_completed(fut_map), total=len(fut_map), desc="Testing paths", unit="path"):
                path = fut_map[fut]
                try:
                    fut.result()
                except Exception as e:
                    if self.logger:
                        try:
                            self.logger.debug("Error testing inventory path %s: %s", path, e)
                        except Exception:
                            pass

        return self._filtered_issues()


    #================funtion _check_path description =============
    def _check_path(self, path: str, documented: set[str]) -> None:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        clean_path = path.rstrip("/")

        try:
            resp = self.session.head(url, timeout=self.timeout)
            if resp.status_code == 405:
                resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            if self.logger:
                try:
                    self.logger.debug("Inventory request failed for %s: %s", url, e)
                except Exception:
                    pass
            return


        if getattr(resp.request, "method", "").upper() == "HEAD" and resp.status_code < 400:
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                pass

        if resp.status_code >= 400:
            # Retry with Accept: application/json in case server needs explicit content negotiation
            if resp.status_code in (406, 415):
                try:
                    resp = self.session.get(
                        url,
                        headers={"Accept": "application/json"},
                        timeout=self.timeout,
                    )
                except requests.RequestException:
                    return
            if resp.status_code >= 400:
                return


        if not self._security_headers_checked:
            try:
                self._check_security_headers(resp, url)
            except Exception as e:
                if self.logger:
                    try:
                        self.logger.debug("Security header check failed for %s: %s", url, e)
                    except Exception:
                        pass
            finally:
                self._security_headers_checked = True

        if not self._is_api_response(resp):
            return

        documented_matches = [(doc, _documented_prefix(doc)) for doc in documented]
        if documented and not any(
            clean_path == doc
            or clean_path == prefix
            or clean_path.startswith(f"{prefix}/")
            for doc, prefix in documented_matches
        ):
            self._log("Undocumented endpoint", url, f"Server returned {resp.status_code}", resp)

        for debug in self._DEBUG_PATHS:
            if clean_path.startswith(debug.rstrip("/")):
                self._log("Debug endpoint exposed", url, f"Matched pattern '{debug}'", resp)
                self._check_debug_exposure(resp)

        ver = re.search(r"(?:^|/)v(\d+)(?=/|$)", clean_path, re.I)
        if ver and documented:
            try:
                v_num = int(ver.group(1))
                max_v = self._max_version(documented)
                if max_v and v_num < max_v:
                    self._log("Deprecated API version", url, f"Version v{v_num} but latest is v{max_v}", resp)
            except ValueError:
                pass

        self._extract_hosts(resp.text, resp)


    #================funtion _check_debug_exposure description =============
    def _check_debug_exposure(self, response: requests.Response) -> None:
        text = response.text or ""
        text_lower = text.lower()
        if "swagger-ui" in text_lower:
            self._log("Debug exposure", "Swagger UI", "", response)
        if "h2-console" in text_lower:
            self._log("Debug exposure", "H2 console", "", response)
        if "<heap>" in text:
            self._log("Debug exposure", "Memory dump tag", "", response)
        # Stack trace patterns
        if any(p in text_lower for p in ("traceback (most recent", "at java.", "at org.", "at com.", "exception in thread", "null pointer exception", "stacktrace")):
            self._log("Stack trace exposed", "Stack trace in response body", "", response)
        # Database connection strings
        if any(p in text_lower for p in ("jdbc:", "mongodb://", "postgres://", "mysql://", "server=.", "data source=", "connectionstring")):
            self._log("Database connection string exposed", "DB credentials or connection info in response", "", response)
        # Internal IP addresses
        for ip in re.findall(r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', text):
            self._log("Internal IP address exposed", ip, "Private IP found in response body", response)
        # Secret/key patterns
        if re.search(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*[\w/+]{10,}', text):
            self._log("Potential secret exposed", "Secret key or token pattern in response body", "", response)


    #================funtion _check_security_headers description =============
    def _check_security_headers(self, response: requests.Response, path: str) -> None:
        hdrs = response.headers or {}
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        missing: List[str] = []

        if "strict-transport-security" not in hdrs_lower:
            missing.append("HSTS")
        if (hdrs.get("X-Content-Type-Options", "") or "").lower() != "nosniff":
            missing.append("X-Content-Type-Options")
        if "X-Frame-Options" not in hdrs and "content-security-policy" not in hdrs_lower:
            missing.append("X-Frame-Options")
        if "Content-Security-Policy" not in hdrs:
            missing.append("CSP")
        if "Referrer-Policy" not in hdrs:
            missing.append("Referrer-Policy")
        if "permissions-policy" not in hdrs_lower and "feature-policy" not in hdrs_lower:
            missing.append("Permissions-Policy")
        cache = (hdrs.get("Cache-Control", "") or "").lower()
        if not any(d in cache for d in ("no-store", "no-cache", "private")):
            missing.append("Cache-Control (no-store/no-cache/private)")

        if missing:
            self._log("Missing security headers", path, "Missing: " + ", ".join(missing), response)


    #================funtion _max_version description =============
    def _max_version(self, paths: set[str]) -> int:
        max_v = 0
        for p in paths:
            for num in re.findall(r"(?:^|/)v(\d+)(?:/|$)", p, re.I):
                try:
                    max_v = max(max_v, int(num))
                except ValueError:
                    continue
        return max_v


    #================funtion _extract_hosts description =============
    def _extract_hosts(self, body: str, response: Optional[requests.Response] = None) -> None:
        base_hostname = urlparse(self.base_url).hostname
        for host in re.findall(r"https?://([\w.-]+)/", body or ""):
            if host and host != base_hostname:
                self._log("Reference to external host", host, "Found in response body", response)


    #================funtion _severity_for classify inventory issues ##########
    def _severity_for(self, issue: str, endpoint: str, description: str, response: Optional[requests.Response]) -> str:
        text = " ".join((issue or "", endpoint or "", description or "")).lower()
        if "missing security headers" in text:
            return "High"
        if any(marker in text for marker in ("secret", "private key", ".env", ".git/config", "heapdump", "shutdown")):
            return "High"
        if any(marker in text for marker in ("stack trace", "database connection", "internal ip", "actuator/env", "actuator/beans", "actuator/configprops")):
            return "Medium"
        if "debug endpoint" in text or "swagger" in text or "openapi" in text or "graphql" in text:
            return "Low"
        if "deprecated api version" in text or "undocumented endpoint" in text:
            return "Low"
        return "Info"


    #================funtion _log description =============
    def _log(
        self,
        issue: str,
        endpoint: str,
        description: str,
        response: Optional[requests.Response] = None,
    ) -> None:
        entry: Issue = {
            "issue": issue,
            "title": issue,
            "endpoint": endpoint,
            "description": description,
            "severity": self._severity_for(issue, endpoint, description, response),
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }

        if response is not None:
            req = getattr(response, "request", None)
            entry.update(
                {
                    "method": getattr(req, "method", ""),
                    "status_code": getattr(response, "status_code", 0),
                    "request_headers": dict(getattr(req, "headers", {}) or {}),
                    "response_headers": dict(getattr(response, "headers", {}) or {}),
                    "request_cookies": getattr(getattr(req, "_cookies", None), "get_dict", lambda: {})(),
                    "response_cookies": getattr(getattr(response, "cookies", None), "get_dict", lambda: {})(),
                }
            )

            body = getattr(req, "body", b"")
            if isinstance(body, (bytes, bytearray)):
                try:
                    entry["request_body"] = body.decode(errors="replace")[:_MAX_BODY_LEN]
                except Exception:
                    entry["request_body"] = repr(body)[:_MAX_BODY_LEN]
            else:
                entry["request_body"] = str(body or "")[:_MAX_BODY_LEN]

            try:
                entry["response_body"] = (response.text or "")[:_MAX_BODY_LEN]
            except Exception:
                entry["response_body"] = ""

        with self._lock:
            self._issues.append(entry)


    #================funtion generate_report description =============
    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner="Inventory (API-09)", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()


    #================funtion save_report description =============
    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(self._filtered_issues(), scanner="Inventory (API-09)", base_url=self.base_url).save(path, fmt=fmt)
