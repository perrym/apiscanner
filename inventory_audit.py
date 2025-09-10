##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
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

Issue = Dict[str, Any]

_MAX_BODY_LEN = 2048  # trim bodies to 2 kB
_MAX_WORKERS = 10  # maximum number of threads

class InventoryAuditor:
    """OWASP API-Security 2023 - API-9 Improper Inventory Management."""

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

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        timeout: int = 5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self._lock = threading.Lock()
        self._issues: List[Issue] = []
        self._security_headers_checked = False

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        """Return the list of paths that exist in the OpenAPI spec."""
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        return list(spec.get("paths", {}).keys())

    def _filtered_issues(self) -> List[Issue]:
        """Remove empty or malformed issues."""
        return [i for i in self._issues if i.get("issue") and i.get("endpoint")]

    def _is_api_response(self, resp: requests.Response) -> bool:
        """
        Heuristiek: retourneer True als de response waarschijnlijk een
        API-payload is, niet een HTML/JS frontend.
        """
        content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].lower()
       
        api_types = {
            "application/json",
            "application/x-yaml",
            "application/vnd.oai.openapi",
            "application/vnd.api+json",
        }
        if content_type in api_types:
            return True

        # 2) Fallback: probeer te parsen als JSON - echte OpenAPI heeft 'openapi' of 'swagger' key
        try:
            parsed = resp.json()
            if isinstance(parsed, dict) and {"openapi", "swagger"} & parsed.keys():
                return True
        except (ValueError, json.JSONDecodeError):
            pass

        return False

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def test_inventory(self, documented_paths: List[Any]) -> List[Issue]:
        """Test alle paden en retourneer gevonden issues."""
        doc_set: set[str] = {
            (p["path"] if isinstance(p, dict) else p).rstrip("/")
            for p in documented_paths
        }

        # Genereer alle te controleren paden
        paths_to_check = []
        
        # Static debug paths
        paths_to_check.extend(self._DEBUG_PATHS)
        
        # Simple version guessing
        for v in range(1, 8):
            for prefix in ["", "/api", "/rest", "/services", "/orders", "/products", "/apis"]:
                paths_to_check.append(f"{prefix}/v{v}")

        # Controleer paden met threading en tqdm voor voortgang
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            # Submit alle taken
            future_to_path = {
                executor.submit(self._check_path, path, doc_set): path 
                for path in paths_to_check
            }
            
            # Verwerk resultaten met tqdm voor voortgangsvisualisatie
            for future in tqdm(
                as_completed(future_to_path), 
                total=len(paths_to_check),
                desc="Testing paths",
                unit="path"
            ):
                path = future_to_path[future]
                try:
                    future.result()  # Haal resultaat op (of verwerk excepties)
                except Exception as e:
                    self._log(f"Error testing path {path}", path, f"Exception: {str(e)}")

        return self._issues

    
    # ------------------------------------------------------------------ #
    # Internal checks
    # ------------------------------------------------------------------ #
    def _check_path(self, path: str, documented: set[str]) -> None:
        url = urljoin(self.base_url, path.lstrip("/"))
        full_url = url
        clean_path = path.rstrip("/")

        try:
            resp = self.session.head(url, timeout=self.timeout)
            if resp.status_code == 405:
                resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            self._log(f"Request error for path {path}", path, f"Exception: {str(e)}")
            return

        if resp.request.method == "HEAD" and resp.status_code < 400:
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException:
                pass

        if resp.status_code >= 400:
            return

        # Only check security headers once during entire scan
        if not getattr(self, "_security_headers_checked", False):
            self._check_security_headers(resp, full_url)
            self._security_headers_checked = True

        # Stop further checks if not API-like
        if not self._is_api_response(resp):
            return

        # Undocumented endpoint
        base_matches = [doc.rstrip("/").split("{", 1)[0] for doc in documented]
        if not any(
            clean_path == doc or clean_path.startswith(f"{doc}/")
            for doc in base_matches
        ):
            self._log(
                "Undocumented endpoint",
                full_url,
                f"Server returned {resp.status_code}",
                resp,
            )

        # Debug endpoints
        for debug in self._DEBUG_PATHS:
            if clean_path.startswith(debug.rstrip("/")):
                self._log(
                    "Debug endpoint exposed",
                    full_url,
                    f"Matched pattern '{debug}'",
                    resp,
                )
                self._check_debug_exposure(resp)

        # Deprecated API version
        ver = re.search(r"(?:^|/)v(\d+)(?=/|$)", clean_path, re.I)
        if ver:
            try:
                v_num = int(ver.group(1))
                max_v = self._max_version(documented)
                if v_num < max_v:
                    self._log(
                        "Deprecated API version",
                        full_url,
                        f"Version v{v_num} but latest is v{max_v}",
                        resp,
                    )
            except ValueError:
                pass

        # Extract external hosts in response
        self._extract_hosts(resp.text)

    # ------------------------------------------------------------------ #
    # Detail helpers
    # ------------------------------------------------------------------ #
    def _check_debug_exposure(self, response: requests.Response) -> None:
        text_lower = response.text.lower()
        if "swagger-ui" in text_lower:
            self._log("Debug exposure", "Swagger UI", "", response)
        if "h2-console" in text_lower:
            self._log("Debug exposure", "H2 console", "", response)
        if "<heap>" in response.text:
            self._log("Debug exposure", "Memory dump tag", "", response)

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
            self._log(
                "Missing security headers",
                path,
                "Missing: " + ", ".join(missing),
                response,                
            )                            

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
        for host in re.findall(r"https?://([\w.-]+)/", body):
            if host != base_hostname:
                self._log(
                    "Reference to external host",
                    host,
                    "Found in response body",
                )

    # ------------------------------------------------------------------ #
    # Logging helper
    # ------------------------------------------------------------------ #
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
                    "method": req.method,
                    "status_code": response.status_code,
                    "request_headers": dict(req.headers),
                    "response_headers": dict(response.headers),
                    "request_cookies": (
                        req._cookies.get_dict()
                        if hasattr(req, "_cookies")
                        else {}
                    ),
                    "response_cookies": response.cookies.get_dict(),
                    "request_body": (
                        req.body.decode()
                        if isinstance(req.body, (bytes, bytearray))
                        else str(req.body or "")
                    )[:_MAX_BODY_LEN],
                    "response_body": response.text[:_MAX_BODY_LEN],
                }
            )

        with self._lock:
            self._issues.append(entry)


    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(
            self._filtered_issues(),
            scanner="Inventory (API-09)",
            base_url=self.base_url,
        )
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(
            self._filtered_issues(),
            scanner="Inventory (API-09)",
            base_url=self.base_url,
        ).save(path, fmt=fmt)
