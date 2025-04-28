# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
from __future__ import annotations
import argparse
import json
import random
import string
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests

Flow = Dict[str, Any]
Issue = Dict[str, Any]
SideEffectChecker = Callable[[requests.Response], bool]


class BusinessFlowAuditor:
    DEFAULT_HEADERS = {"User-Agent": "BusinessFlowAuditor/2.0"}

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, concurrency: int = 20, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)
        self.timeout = timeout
        self.concurrency = concurrency
        self._issues: List[Issue] = []
        self._lock = threading.Lock()

    def _abs_url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    def _nonce(self) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=8))

    def load_swagger(self, swagger_url: str) -> List[Flow]:
        try:
            resp = self.session.get(swagger_url, timeout=10)
            resp.raise_for_status()
            spec = resp.json()
            flows = []
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in {"POST", "PUT", "PATCH"}:
                        flows.append({
                            "name": details.get("operationId", f"{method.upper()}_{path.strip('/').replace('/', '_')}").lower(),
                            "url": path,
                            "method": method.upper(),
                            "body": {}
                        })
            return flows
        except Exception as e:
            print(f"⚠️ Fout bij laden van Swagger: {e}")
            return []

    def load_flows_file(self, path: str) -> List[Flow]:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f"Flows-bestand niet gevonden: {path}")
        if p.suffix.lower() in {".yml", ".yaml"}:
            import yaml
            return yaml.safe_load(p.read_text(encoding="utf-8"))
        else:
            return json.loads(p.read_text(encoding="utf-8"))

    def discover_business_flows(self) -> List[Flow]:
        candidates = [
            ("ticket_purchase", "/tickets/buy", "POST"),
            ("order_checkout", "/checkout", "POST"),
            ("comment_post", "/comments", "POST"),
            ("subscription", "/subscribe", "POST"),
        ]
        flows: List[Flow] = []
        for name, path, method in candidates:
            url = self._abs_url(path)
            try:
                r = self.session.options(url, timeout=3)
                if r.status_code < 500:
                    flows.append({"name": name, "url": path, "method": method, "body": {}})
            except Exception:
                continue
        return flows

    def test_business_flows(self, flows: List[Flow]) -> List[Issue]:
        for flow in flows:
            self._run_tests_for_flow(flow)
        return self._issues

    def generate_report(self, fmt: str = "markdown") -> str:
        if not self._issues:
            return "Geen misbruik van business-flows gevonden."

        if fmt == "json":
            return json.dumps(self._issues, indent=2)

        lines = [
            "# API Security Audit – Sensitive Business Flows (API6:2023)",
            f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Geteste URL: {self.base_url}",
            "\n## Bevindingen",
        ]
        by_sev: Dict[str, List[Issue]] = defaultdict(list)
        for issue in self._issues:
            by_sev[issue["severity"]].append(issue)

        for severity in ("Critical", "High", "Medium", "Low"):
            if not by_sev[severity]:
                continue
            lines.append(f"\n### {severity} risico’s")
            for issue in by_sev[severity]:
                lines.append(f"#### {issue['flow']} – {issue['endpoint']}")
                lines.append(f"- **Beschrijving**: {issue['description']}")
                lines.append(f"- **Tijdstip**: {issue['timestamp']}")
                if issue.get("request"):
                    lines.append("- **Request data**:")
                    lines.append(f"  ```json\n  {json.dumps(issue['request'], indent=2)}\n  ```")
                if issue.get("response_headers") is not None:
                    lines.append("- **Response headers**:")
                    lines.append(f"  ```json\n  {json.dumps(issue['response_headers'], indent=2)}\n  ```")
                if issue.get("response_body") is not None:
                    lines.append("- **Response body**:")
                    lines.append(f"  ```\n  {issue['response_body']}\n  ```")
        return "\n".join(lines)

    def _log(self, flow: Flow, desc: str, sev: str, req: Optional[dict] = None, resp: Optional[requests.Response] = None):
        with self._lock:
            self._issues.append({
                "flow": flow.get("name"),
                "endpoint": self._abs_url(flow["url"]),
                "description": desc,
                "severity": sev,
                "timestamp": datetime.now().isoformat(),
                "request": req,
                "response_headers": dict(resp.headers) if resp else {},
                "response_body": resp.text if resp else ""
            })

    def _run_tests_for_flow(self, flow: Flow):
        for test in (
            self._test_concurrency,
            self._test_duplicate_submission,
            self._test_price_manipulation,
            self._test_coupon_bruteforce,
            self._test_rate_limit_sequential,
            self._test_method_override,
            self._test_field_pollution,
        ):
            try:
                test(flow)
            except Exception as exc:
                self._log(flow, f"Test error: {exc}", "Medium")

    def _send(self, flow: Flow, *, body: Optional[Dict[str, Any]] = None, override_method: Optional[str] = None) -> Optional[requests.Response]:
        url = self._abs_url(flow["url"])
        method = (override_method or flow.get("method", "POST")).upper()
        headers = {**flow.get("headers", {}), "X-Audit-Nonce": self._nonce()}
        params = flow.get("params", {})

        try:
            if method == "GET":
                return self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            return self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=body or flow.get("body", {}),
                timeout=self.timeout,
            )
        except requests.RequestException:
            return None

    def _extract_id(self, resp: Optional[requests.Response]) -> Optional[str]:
        if not resp:
            return None
        try:
            data = resp.json()
            for k in ("id", "order_id", "ticket_id", "transaction_id"):
                if k in data:
                    return str(data[k])
        except Exception:
            pass
        return None

    def _test_concurrency(self, flow: Flow):
        def _invoke() -> Optional[requests.Response]:
            return self._send(flow)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(_invoke) for _ in range(self.concurrency)]
            responses = [f.result() for f in as_completed(futures)]

        success = [r for r in responses if r and r.status_code == 200]
        if len(success) == self.concurrency:
            self._log(flow, f"No throttling at {self.concurrency} parallel requests", "High", resp=success[0])

    def _test_duplicate_submission(self, flow: Flow):
        r1 = self._send(flow)
        time.sleep(0.5)
        r2 = self._send(flow)

        ids = {self._extract_id(r) for r in (r1, r2) if r}
        if len(ids) == 2:
            self._log(flow, "Duplicate submission accepted (idempotency ontbreekt)", "Medium", resp=r2)

    _PRICE_KEYS = {"price", "amount", "total", "cost"}

    def _test_price_manipulation(self, flow: Flow):
        payload = flow.get("body") or {}
        if not (self._PRICE_KEYS & payload.keys()):
            return
        manipulated = {**payload}
        for k in self._PRICE_KEYS & payload.keys():
            manipulated[k] = 0
        r = self._send(flow, body=manipulated)
        if r and r.status_code == 200:
            self._log(flow, "Price manipulation: 0 euro geaccepteerd", "Critical", manipulated, r)

    def _test_coupon_bruteforce(self, flow: Flow):
        if "coupon" not in (flow.get("body") or {}):
            return

        for _ in range(20):
            coupon = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            attempt = {**flow["body"], "coupon": coupon}
            r = self._send(flow, body=attempt)
            if r and r.status_code == 200:
                self._log(flow, f"Coupon brute-force succeeded: {coupon}", "High", attempt, r)
                break

    def _test_rate_limit_sequential(self, flow: Flow):
        for _ in range(25):
            r = self._send(flow)
            if r and r.status_code in {429, 503}:
                return
        self._log(flow, "No rate-limiting after 25 rapid requests", "High", resp=r)

    def _test_method_override(self, flow: Flow):
        for verb in ("PUT", "DELETE", "PATCH"):
            r = self._send(flow, override_method=verb)
            if r and r.status_code == 200:
                self._log(flow, f"Method override to {verb} allowed", "Medium", resp=r)
                break

    def _test_field_pollution(self, flow: Flow):
        noisy = {**flow.get("body", {}), "__polluted": "yes"}
        r = self._send(flow, body=noisy)
        if r and r.status_code == 200:
            self._log(flow, "Unexpected field accepted", "Low", noisy, r)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit OWASP API6 – Sensitive Business Flows")
    parser.add_argument("--url", required=True, help="Base API URL (bijv. https://api.example.com)")
    parser.add_argument("--swagger", help="URL naar Swagger/OpenAPI JSON")
    parser.add_argument("--flows", help="Path naar flows (JSON/YAML)")
    parser.add_argument("--concurrency", type=int, default=20, help="Aantal gelijktijdige requests")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP-timeout in seconden")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args()

    sess = requests.Session()
    auditor = BusinessFlowAuditor(args.url, session=sess, concurrency=args.concurrency, timeout=args.timeout)

    flows: List[Flow] = []

    if args.swagger:
        flows = auditor.load_swagger(args.swagger)
    if not flows and args.flows:
        flows = auditor.load_flows_file(args.flows)
    if not flows:
        flows = auditor.discover_business_flows()

    if not flows:
        raise SystemExit("Geen testbare business-flows gevonden!")

    print(f"\n🔍 {len(flows)} flows geladen. Start met testen...")
    auditor.test_business_flows(flows)
    report = auditor.generate_report(args.output)

    output_dir = Path(f"business_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    output_dir.mkdir(exist_ok=True)
    outfile = output_dir / f"business_flow_report.{args.output}.txt"
    outfile.write_text(report, encoding="utf-8")
    print(f"\n📁 Rapport opgeslagen in: {outfile}")
