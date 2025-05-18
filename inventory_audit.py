#
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
"""inventory_audit.py – OWASP API9:2023 (Improper Inventory Management)
=====================================================================
Detects outdated, undocumented or debug-like endpoints and hosts.
Combines Swagger inventory, heuristic endpoint lists and (optional)
live scanning via HTTP OPTIONS to find discrepancies.

Features
--------
* **Undocumented paths**      – endpoint not found in Swagger.
* **Deprecated API versions** – version number in path < latest known version.
* **Exposed debug endpoints** – `/actuator`, `/swagger`, `/h2-console`, …
* **Multiple hosts**          – responses reference other sub-domains.
* **Markdown / JSON report**  – groups findings by category.
"""

from __future__ import annotations

import json
import re
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import argparse as _arg
import requests
from report_utils import ReportGenerator
Issue = Dict[str, Any]
Endpoint = Dict[str, str]


class InventoryAuditor:
    """Audit Improper Inventory Management – OWASP API9:2023."""

    _DEBUG_PATHS = [
        "/swagger", "/swagger-ui", "/swagger.json", "/openapi", "/openapi.json",
        "/actuator", "/metrics", "/config", "/h2-console", "/health", "/debug",
    ]
    _VERSION_RE = re.compile(r"v(?P<num>\d+)$", re.I)

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, timeout: int = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self._lock = threading.Lock()
        self._issues: List[Issue] = []

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @staticmethod
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        return list(spec.get("paths", {}).keys())

    def test_inventory(self, documented_paths: List[str]) -> List[Issue]:
        """Compare documented_paths (from Swagger) with heuristic scans."""
        doc_set = set(documented_paths)
        # 1. Heuristic debug paths
        for p in self._DEBUG_PATHS:
            self._check_path(p, doc_set)
        # 2. Version enumeration: /v1,/v2,/v3..
        for v in range(1, 6):
            self._check_path(f"/v{v}", doc_set)
        return self._issues

    # ------------------------------------------------------------------
    def _check_path(self, path: str, documented: set):
        url = urljoin(self.base_url, path.lstrip("/"))
        try:
            r = self.session.options(url, timeout=self.timeout)
        except requests.RequestException:
            return
        if r.status_code >= 400:
            return
        # Issue 1: Undocumented
        if path not in documented and not any(path.startswith(d + "/") for d in documented):
            self._log("Undocumented endpoint", path, f"OPTIONS {r.status_code}")
        # Issue 2: Debug
        if path in self._DEBUG_PATHS:
            self._log("Debug endpoint exposed", path, "Accessible")
        # Issue 3: Deprecated version
        m = self._VERSION_RE.search(path)
        if m and int(m.group("num")) < self._max_version(documented):
            self._log("Deprecated API version", path, "Older than latest spec version")
        # Issue 4: Other host leaks
        self._extract_hosts(r.text)

    def _max_version(self, doc_paths: set) -> int:
        max_v = 0
        for p in doc_paths:
            m = self._VERSION_RE.search(p)
            if m:
                max_v = max(max_v, int(m.group("num")))
        return max_v

    def _extract_hosts(self, text: str):
        for m in re.finditer(r"https?://([\w.-]+)/", text):
            host = m.group(1)
            if host not in urlparse(self.base_url).hostname:
                self._log("Reference to external host", host, "Found in response body")

    # ------------------------------------------------------------------
    def _log(self, issue: str, target: str, detail: str):
        with self._lock:
            self._issues.append({
                "issue": issue,
                "target": target,
                "detail": detail,
                "timestamp": datetime.now().isoformat(),
            })

    def generate_report(self, fmt: str = "markdown") -> str:
        return ReportGenerator(
            issues=self._issues,
            scanner="Inventory (API09)",
            base_url=self.base_url
        ).generate_markdown() if fmt == "markdown" else ReportGenerator(
            issues=self._issues,
            scanner="Inventory (API09)",
            base_url=self.base_url
        ).generate_json()
        
        
    def save_report(self, path: str, fmt: str = "markdown"):
        ReportGenerator(self._issues, scanner="Inventory (API09)", base_url=self.base_url).save(path, fmt=fmt)





# ------------------------------------------------------------------
# Compatibility alias for scripts expecting test_endpoints
# ------------------------------------------------------------------
if not hasattr(InventoryAuditor, "test_endpoints"):
    def _alias(self, endpoints):
        """Alias: calls test_inventory internally."""
        # endpoints can be list[str] or list[dict]
        paths = [
            e["path"] if isinstance(e, dict) and "path" in e else str(e)
            for e in endpoints
        ]
        return self.test_inventory(paths)
    setattr(InventoryAuditor, "test_endpoints", _alias)


# CLI (stand-alone)
if __name__ == "__main__":
    p = _arg.ArgumentParser(description="Audit OWASP API9 – Inventory Management")
    p.add_argument("--url", required=True)
    p.add_argument("--swagger", required=True)
    args = p.parse_args()

    sess = requests.Session()
    aud = InventoryAuditor(args.url, sess)
    documented = InventoryAuditor.endpoints_from_swagger(args.swagger)
    aud.test_inventory(documented)
    print(aud.generate_report())