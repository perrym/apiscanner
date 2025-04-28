"""inventory_audit.py – OWASP API9:2023 (Improper Inventory Management)
=====================================================================
Detecteert verouderde, ongedocumenteerde of debug‑achtige endpoints en hosts.
Combineert Swagger‑inventaris, heuristische endpoint‑lijsten en (optionele)
live‑scan via HTTP OPTIONS om discrepanties te vinden.

Features
--------
* **Undocumented paths**      – endpoint komt niet voor in Swagger.
* **Deprecated API versions** – versienummer in pad < laatst bekende versie.
* **Exposed debug endpoints** – `/actuator`, `/swagger`, `/h2-console`, …
* **Multiple hosts**          – responses verwijzen naar andere sub‑domeinen.
* **Markdown / JSON rapport** – groepeert bevindingen per categorie.
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

import requests

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
        """Vergelijk documented_paths (uit Swagger) met heuristische scans."""
        doc_set = set(documented_paths)
        # 1. Heuristische debug paths
        for p in self._DEBUG_PATHS:
            self._check_path(p, doc_set)
        # 2. Versie‑enumeratie: /v1,/v2,/v3..
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
        if not self._issues:
            return "Geen inventory‑problemen gevonden."
        if fmt == "json":
            return json.dumps(self._issues, indent=2)
        lines: List[str] = [
            "# API Security Audit – Improper Inventory Management (API9:2023)",
            f"Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Doel: {self.base_url}",
            "\n## Bevindingen",
        ]
        by_issue: Dict[str, List[Issue]] = defaultdict(list)
        for i in self._issues:
            by_issue[i["issue"]].append(i)
        for issue, items in by_issue.items():
            lines.append(f"\n### {issue} ({len(items)})")
            for it in items:
                lines.append(f"* {it['target']} – {it['detail']}")
        return "\n".join(lines)


# ------------------------------------------------------------------
# Compatibiliteits-alias voor scripts die test_endpoints verwachten
# ------------------------------------------------------------------
if not hasattr(InventoryAuditor, "test_endpoints"):
    def _alias(self, endpoints):
        """Alias: roept intern test_inventory aan."""
        # endpoints kan list[str] of list[dict] zijn
        paths = [
            e["path"] if isinstance(e, dict) and "path" in e else str(e)
            for e in endpoints
        ]
        return self.test_inventory(paths)
    setattr(InventoryAuditor, "test_endpoints", _alias)




# CLI (stand‑alone)
if __name__ == "__main__":
    import argparse as _arg

    p = _arg.ArgumentParser(description="Audit OWASP API9 – Inventory Management")
    p.add_argument("--url", required=True)
    p.add_argument("--swagger", required=True)
    args = p.parse_args()

    sess = requests.Session()
    aud = InventoryAuditor(args.url, sess)
    documented = InventoryAuditor.endpoints_from_swagger(args.swagger)
    aud.test_inventory(documented)
    print(aud.generate_report())
