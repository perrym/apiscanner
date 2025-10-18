#########################################
# APISCAN - API Security Scanner        #
# MIT License - Perry Mertens  2025 (c) #
#########################################                                  
                                  
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


class InventoryAuditor:
    _DEBUG_PATHS = [
        "/swagger",
        "/swagger-ui",
        "/swagger.json",
        "/openapi",
        "/openapi.json",
        "/actuator",
        "/metrics",
        "/config",
        "/h2-console",
        "/health",
        "/debug",
        "/console",
        "/phpinfo",
        "/.env",
        "/.git",
    ]

    # ----------------------- Funtion __init__ ----------------------------#
    def __init__(
        self,
        *args,
        base_url: Optional[str] = None,
        session: Optional[requests.Session] = None,
        timeout: int = 5,
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
        self.timeout = int(timeout)
        self._lock = threading.Lock()
        self._issues: List[Issue] = []
        self._security_headers_checked = False
        self.spec: Dict[str, Any] = swagger_spec or kwargs.get("spec") or {}

    # ----------------------- Funtion endpoints_from_swagger ----------------------------#
    @staticmethod
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        return list((spec.get("paths") or {}).keys())

    # ----------------------- Funtion endpoints_from_universal ----------------------------#
    @staticmethod
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

    # ----------------------- Funtion _filtered_issues ----------------------------#
    def _filtered_issues(self) -> List[Issue]:
        return [i for i in self._issues if i.get("issue") and i.get("endpoint")]

    # ----------------------- Funtion _is_api_response ----------------------------#
    def _is_api_response(self, resp: requests.Response) -> bool:
        content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].lower()
        api_types = {
            "application/json",
            "application/x-yaml",
            "application/vnd.oai.openapi",
            "application/vnd.api+json",
        }
        if content_type in api_types:
            return True
        try:
            parsed = resp.json()
            if isinstance(parsed, dict) and {"openapi", "swagger"} & parsed.keys():
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        return False

    # ----------------------- Funtion test_inventory ----------------------------#
    def test_inventory(self, documented_paths: Optional[List[Any]] = None) -> List[Issue]:
        if documented_paths is None and self.spec:
            documented_paths = self.endpoints_from_universal(self.spec)

        doc_set: set[str] = {
            (p["path"] if isinstance(p, dict) else str(p)).rstrip("/")
            for p in (documented_paths or [])
        }

        paths_to_check: List[str] = []
        paths_to_check.extend(self._DEBUG_PATHS)

        for v in range(1, 8):
            for prefix in ["", "/api", "/rest", "/services", "/orders", "/products", "/apis"]:
                paths_to_check.append(f"{prefix}/v{v}")

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            fut_map = {
                executor.submit(self._check_path, path, doc_set): path
                for path in paths_to_check
            }
            for fut in tqdm(as_completed(fut_map), total=len(fut_map), desc="Testing paths", unit="path"):
                path = fut_map[fut]
                try:
                    fut.result()
                except Exception as e:
                    self._log("Error testing path", path, f"Exception: {str(e)}")

        return self._issues

    # ----------------------- Funtion _check_path ----------------------------#
    def _check_path(self, path: str, documented: set[str]) -> None:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        clean_path = path.rstrip("/")

        try:
            resp = self.session.head(url, timeout=self.timeout)
            if resp.status_code == 405:
                resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self._log("Request error", path, f"Exception: {str(e)}")
            return

        if resp.request.method == "HEAD" and resp.status_code < 400:
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                pass

        if resp.status_code >= 400:
            return

        if not getattr(self, "_security_headers_checked", False):
            self._check_security_headers(resp, url)
            self._security_headers_checked = True

        if not self._is_api_response(resp):
            return

        base_matches = [doc.rstrip("/").split("{", 1)[0] for doc in documented]
        if not any(clean_path == doc or clean_path.startswith(f"{doc}/") for doc in base_matches):
            self._log("Undocumented endpoint", url, f"Server returned {resp.status_code}", resp)

        for debug in self._DEBUG_PATHS:
            if clean_path.startswith(debug.rstrip("/")):
                self._log("Debug endpoint exposed", url, f"Matched pattern '{debug}'", resp)
                self._check_debug_exposure(resp)

        ver = re.search(r"(?:^|/)v(\d+)(?=/|$)", clean_path, re.I)
        if ver:
            try:
                v_num = int(ver.group(1))
                max_v = self._max_version(documented)
                if v_num < max_v:
                    self._log("Deprecated API version", url, f"Version v{v_num} but latest is v{max_v}", resp)
            except ValueError:
                pass

        self._extract_hosts(resp.text)

    def _check_debug_exposure(self, response: requests.Response) -> None:
        text_lower = (response.text or "").lower()
        if "swagger-ui" in text_lower:
            self._log("Debug exposure", "Swagger UI", "", response)
        if "h2-console" in text_lower:
            self._log("Debug exposure", "H2 console", "", response)
        if "<heap>" in response.text:
            self._log("Debug exposure", "Memory dump tag", "", response)

    # ----------------------- Funtion _check_security_headers ----------------------------#
    def _check_security_headers(self, response: requests.Response, path: str) -> None:
        missing = []
        hdrs = response.headers
        if "strict-transport-security" not in hdrs:
            missing.append("HSTS")
        if hdrs.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in hdrs:
            missing.append("X-Frame-Options")
        if "content-security-policy" not in hdrs:
            missing.append("CSP")
        if missing:
            self._log("Missing security headers", path, "Missing: " + ", ".join(missing), response)

    def _max_version(self, paths: set[str]) -> int:
        max_v = 0
        for p in paths:
            for num in re.findall(r"(?:^|/)v(\d+)(?:/|$)", p, re.I):
                try:
                    max_v = max(max_v, int(num))
                except ValueError:
                    continue
        return max_v

    def _extract_hosts(self, body: str) -> None:
        base_hostname = urlparse(self.base_url).hostname
        for host in re.findall(r"https?://([\w.-]+)/", body or ""):
            if host and host != base_hostname:
                self._log("Reference to external host", host, "Found in response body")

    # ----------------------- Funtion _log ----------------------------#
    def _log(
        self,
        issue: str,
        endpoint: str,
        description: str,
        response: Optional[requests.Response] = None,
    ) -> None:
        entry: Issue = {
            "issue": issue,
            "endpoint": endpoint,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        }
        if response is not None:
            req = response.request
            entry.update(
                {
                    "method": getattr(req, "method", ""),
                    "status_code": response.status_code,
                    "request_headers": dict(getattr(req, "headers", {}) or {}),
                    "response_headers": dict(response.headers or {}),
                    "request_cookies": getattr(getattr(req, "_cookies", None), "get_dict", lambda: {})(),
                    "response_cookies": response.cookies.get_dict(),
                    "request_body": (
                        req.body.decode()
                        if hasattr(req, "body") and isinstance(req.body, (bytes, bytearray))
                        else str(getattr(req, "body", "") or "")
                    )[:_MAX_BODY_LEN],
                    "response_body": (response.text or "")[:_MAX_BODY_LEN],
                }
            )
        with self._lock:
            self._issues.append(entry)

    # ----------------------- Funtion generate_report ----------------------------#
    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner="Inventory (API-09)", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    # ----------------------- Funtion save_report ----------------------------#
    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(self._filtered_issues(), scanner="Inventory (API-09)", base_url=self.base_url).save(path, fmt=fmt)
