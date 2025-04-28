# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
"""
misconfiguration_audit_pro.py – PRO versie
Met:
- Headers & Response checks
- Reflected SSRF detection
- Blind SSRF timing detection
- Payload shuffling & Rate-limiting
- PRO-level nette Markdown rapportage
"""

from __future__ import annotations
import argparse
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin, quote_plus
import requests

Endpoint = Dict[str, Any]
Finding = Dict[str, Any]

class MisconfigurationAuditorPro:
    DEFAULT_CONCURRENCY = 12
    DEFAULT_TIMEOUT = 8
    RATE_LIMIT_AFTER_ERRORS = 10
    RANDOM_SLEEP_AFTER_REQUESTS = 50

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, concurrency: int = DEFAULT_CONCURRENCY, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.concurrency = concurrency
        self.timeout = timeout
        self._findings: List[Finding] = []
        self._lock = threading.Lock()
        self._response_analyzers = [
            self._security_header_analyzer,
            self._reflected_ssrf_analyzer,
            self._blind_ssrf_analyzer,
            self._server_error_analyzer,
        ]
        self._error_count = 0
        self._request_counter = 0

    @classmethod
    def endpoints_from_swagger(cls, swagger_path: str) -> List[Endpoint]:
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        server = spec.get("servers", [{}])[0].get("url", "")
        eps: List[Endpoint] = []
        for path, item in spec.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                if method in item:
                    eps.append({
                        "base": server,
                        "path": path,
                        "method": method.upper(),
                    })
        return eps

    def _default_payloads(self) -> Iterable[str]:
        base = ["http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/"]
        fancy = [
            "http://127.0.0.1@evil.com/",
            "http://evil.com@127.0.0.1/",
            "http://127%2e0%2e0%2e1/",
            "http://127。0。0。1/",
        ]
        all_payloads = base + fancy
        random.shuffle(all_payloads)
        return all_payloads

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            for _ in as_completed(futures):
                pass
        return self._findings

    def _test_single_endpoint(self, ep: Endpoint):
        full_url = urljoin(ep.get("base") or self.base_url, ep["path"].lstrip("/"))
        for payload in list(self._default_payloads()):
            try:
                crafted_url = full_url + f"?q={quote_plus(payload)}"
                start = time.time()
                resp = self.session.request(ep["method"], crafted_url, timeout=self.timeout, allow_redirects=True)
                dur = time.time() - start
                self._request_counter += 1
            except requests.RequestException:
                self._error_count += 1
                if self._error_count >= self.RATE_LIMIT_AFTER_ERRORS:
                    time.sleep(1)
                    self._error_count = 0
                continue

            if self._request_counter % self.RANDOM_SLEEP_AFTER_REQUESTS == 0:
                time.sleep(random.uniform(0.1, 0.3))

            for analyzer in self._response_analyzers:
                finding = analyzer(ep, payload, resp, dur)
                if finding:
                    self._record_finding(finding)

    def _security_header_analyzer(self, ep: Endpoint, payload: str, resp: requests.Response, dur: float) -> Optional[Finding]:
        missing = []
        for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
            if header not in resp.headers:
                missing.append(header)
        if missing:
            return self._build_finding(ep, payload, resp, dur, f"Ontbrekende headers: {', '.join(missing)}", "Medium")
        return None

    def _reflected_ssrf_analyzer(self, ep: Endpoint, payload: str, resp: requests.Response, dur: float) -> Optional[Finding]:
        if payload in resp.text:
            return self._build_finding(ep, payload, resp, dur, "Payload gereflecteerd (mogelijk reflected SSRF)", "High")
        return None

    def _blind_ssrf_analyzer(self, ep: Endpoint, payload: str, resp: requests.Response, dur: float) -> Optional[Finding]:
        if dur > 3.0:
            return self._build_finding(ep, payload, resp, dur, f"Langzame respons ({dur:.2f}s) – mogelijk blind SSRF", "Medium")
        return None

    def _server_error_analyzer(self, ep: Endpoint, payload: str, resp: requests.Response, dur: float) -> Optional[Finding]:
        if resp.status_code >= 500:
            return self._build_finding(ep, payload, resp, dur, f"Server error {resp.status_code}", "High")
        return None

    def _build_finding(self, ep: Endpoint, payload: str, resp: requests.Response, dur: float, reason: str, severity: str) -> Finding:
        return {
            "endpoint": f"{ep['method']} {ep['path']}",
            "payload": payload,
            "result": reason,
            "severity": severity,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "response_time": f"{dur:.2f}s",
            "response_status": resp.status_code,
            "response_headers": dict(resp.headers),
            "response_sample": resp.text[:200] if resp.text.strip() else "(Geen body ontvangen)",
        }

    def _record_finding(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def generate_report(self, fmt: str = "markdown") -> str:
        if not self._findings:
            return "Geen misconfiguraties of kwetsbaarheden gevonden."
        if fmt == "json":
            return json.dumps(self._findings, indent=2)

        out: List[str] = [
            "# API Security Audit – Misconfiguraties & SSRF", 
            f"📅 Scan uitgevoerd op: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"🌐 Target: {self.base_url}",
            f"⚙️ Configuratie: {self.concurrency} threads, timeout {self.timeout}s",
            "\n---",
        ]

        severity_order = ["Critical", "High", "Medium", "Low"]
        sev_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

        for sev in severity_order:
            issues = [f for f in self._findings if f["severity"] == sev]
            if not issues:
                continue
            out.append(f"\n## {sev_icons.get(sev, '')} {sev} Bevindingen\n")
            for i in issues:
                out.append(f"### {i['endpoint']}")
                out.append(f"- **Kwetsbaarheid**: {i['result']}")
                out.append(f"- **Payload**: `{i['payload']}`")
                out.append(f"- **Response tijd**: {i['response_time']}")
                out.append(f"- **Statuscode**: {i['response_status']}")
                out.append(f"- **Belangrijke headers**:")
                out.append(f"  ```json\n{json.dumps(i.get('response_headers', {}), indent=2)}\n```")
                out.append(f"- **Response voorbeeld**:")
                out.append(f"  ```\n{i.get('response_sample', '')}\n```\n")

        return "\n".join(out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit OWASP API8 – Misconfiguraties & SSRF")
    parser.add_argument("--url", required=True, help="Basis-API-URL")
    parser.add_argument("--swagger", required=True, help="Pad naar Swagger/OpenAPI-JSON")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args()

    sess = requests.Session()
    aud = MisconfigurationAuditorPro(args.url, sess)
    eps = MisconfigurationAuditorPro.endpoints_from_swagger(args.swagger)
    aud.test_endpoints(eps)
    print(aud.generate_report(args.output))
