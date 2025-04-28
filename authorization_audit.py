# Ultimate Swagger Generator
# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
import requests
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
import urllib3
from urllib.parse import urlparse, urljoin
import base64
import re
from typing import Tuple
from collections import Counter

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AuthorizationAuditor:
    """Enhanced Authorization Auditor that integrates with Swagger and fallback discovery"""

    def __init__(
        self,
        base_url: str,
        swagger_data: Optional[Dict] = None,
        session: Optional[requests.Session] = None
    ):
        # Allow passing requests.Session as second positional argument
        if isinstance(swagger_data, requests.Session):
            session = swagger_data
            swagger_data = None

        self.base_url = self._normalize_url(base_url)
        self.session = session or self._create_session()
        self.authz_issues: List[Dict] = []
        self.swagger_data = swagger_data

        # Parse swagger endpoints or fallback to discovery
        if swagger_data:
            self.discovered_endpoints = self._parse_swagger_data()
        else:
            self.discovered_endpoints = self._discover_endpoints()

        # Define test roles
        self.roles = {
            "anonymous": {"token": None, "description": "No authentication"},
            "user": {"username": "testuser", "password": "testpass", "token": None},
            "editor": {"username": "editor", "password": "editorpass", "token": None},
            "admin": {"username": "admin", "password": "adminpass", "token": None},
        }

        # Get tokens for all roles
        self._get_all_tokens()

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
        return url.rstrip('/') + '/'

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "APISecurityScanner/2.0",
            "Accept": "application/json"
        })
        session.verify = False
        return session

    def _parse_swagger_data(self) -> List[Dict]:
        endpoints: List[Dict] = []
        paths = self.swagger_data.get("paths", {}) if isinstance(self.swagger_data, dict) else {}
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    endpoint = {
                        "url": urljoin(self.base_url, path),
                        "methods": [method.upper()],
                        "security": details.get("security", []),
                        "tags": details.get("tags", []),
                        "operationId": details.get("operationId", ""),
                        "sensitive": self._is_endpoint_sensitive(details)
                    }
                    endpoints.append(endpoint)
        return endpoints

    def _discover_endpoints(self) -> List[Dict]:
        endpoints: List[Dict] = []
        common_paths = [
            "/api/users", "/api/products", "/api/orders", "/api/admin",
            "/v1/users", "/v1/products", "/v1/config", "/v1/admin",
            "/users", "/products", "/admin", "/config"
        ]
        for path in common_paths:
            endpoints.append({
                "url": urljoin(self.base_url, path),
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "sensitive": 'admin' in path.lower()
            })
        return endpoints

    def _is_endpoint_sensitive(self, details: Dict) -> bool:
        security = details.get("security", [])
        tags = details.get("tags", [])
        oper = details.get("operationId", "").lower()
        for sec in security:
            for req in sec.values():
                if any(s in ["admin", "write", "delete"] for s in req):
                    return True
        indic = ["admin", "internal", "private", "write", "delete", "config"]
        if any(tag.lower().find(i) >= 0 for tag in tags for i in indic):
            return True
        if any(i in oper for i in indic):
            return True
        return False

    def _get_all_tokens(self):
        for role, cfg in self.roles.items():
            if role == "anonymous":
                continue
            token = self._get_token(cfg["username"], cfg["password"])
            if token:
                self.roles[role]["token"] = token
            else:
                fallback = self._try_cloud_specific_auth(role)
                self.roles[role]["token"] = fallback
                if not fallback:
                    self._log_issue(
                        url=self.base_url,
                        description=f"Geen token voor rol {role} verkregen",
                        severity="Low",
                        details={"role": role}
                    )

    def _get_token(self, username: str, password: str) -> Optional[str]:
        if not self.swagger_data:
            return None
        schemes = self.swagger_data.get("components", {}).get("securitySchemes", {})
        for sch in schemes.values():
            if sch.get("type") == "http" and sch.get("scheme") == "bearer":
                for ep in ["/auth/login", "/oauth/token", "/api/login", "/identity/connect/token"]:
                    try:
                        r = self.session.post(
                            urljoin(self.base_url, ep),
                            json={"username": username, "password": password},
                            headers={"Content-Type": "application/json"},
                            timeout=5
                        )
                        if r.status_code == 200:
                            return r.json().get("access_token")
                    except Exception:
                        pass
        return None

    def _try_cloud_specific_auth(self, role: str) -> Optional[str]:
        # AWS metadata
        try:
            md = self.session.get(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                timeout=2
            )
            if md.status_code == 200:
                return md.text.strip()
        except Exception:
            pass
        # Azure MSI
        try:
            az = self.session.get(
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/",
                headers={"Metadata": "true"},
                timeout=2
            )
            if az.status_code == 200:
                return az.json().get("access_token")
        except Exception:
            pass
        return None

    def test_authorization(self) -> List[Dict]:
        for ep in self.discovered_endpoints:
            self._test_endpoint_authorization(ep)
        self._test_missing_authorization_headers()
        self._test_rate_limiting_bypass()
        self._test_jwt_validation()
        self._test_idor_vulnerabilities()
        return self.authz_issues

    def _test_endpoint_authorization(self, endpoint: Dict):
        required = bool(endpoint.get("security")) or endpoint.get("sensitive", False)
        for m in endpoint.get("methods", ["GET"]):
            self._test_access(endpoint, m, "anonymous", should_access=not required)
            if self.roles["user"]["token"]:
                self._test_access(endpoint, m, "user", should_access=not endpoint.get("sensitive", False))
            if self.roles["admin"]["token"]:
                self._test_access(endpoint, m, "admin", should_access=True)

    def _test_access(self, endpoint: Dict, method: str, role: str, should_access: bool):
        headers = {}
        if role != "anonymous" and self.roles[role]["token"]:
            headers["Authorization"] = f"Bearer {self.roles[role]['token']}"
        try:
            r = self.session.request(method, endpoint["url"], headers=headers, timeout=5, verify=False)
            got = r.status_code in [200, 201, 204]
            if got != should_access:
                self._log_auth_issue(
                    endpoint=endpoint,
                    method=method,
                    role=role,
                    expected=should_access,
                    actual=got,
                    status_code=r.status_code,
                    response=r.text[:200] if got else None,
                    response_headers=dict(r.headers)
                )
        except Exception as e:
            self._log_issue(
                url=endpoint["url"],
                description=f"Request failed - {method} as {role}",
                severity="Medium",
                details={"error": str(e)}
            )

    def _log_auth_issue(
        self,
        endpoint: Dict,
        method: str,
        role: str,
        expected: bool,
        actual: bool,
        status_code: int,
        response: Optional[str],
        response_headers: Optional[Dict[str, Any]] = None
    ):
        """Log an authorization mismatch issue"""
        if actual and not expected:
            desc = f"Unauthorized access - {method} as {role}"
            severity = "High"
        elif expected and not actual:
            desc = f"Excessive restriction - {method} as {role}"
            severity = "Medium"
        else:
            return
        details: Dict[str, Any] = {
            "expected_access": "Allowed" if expected else "Denied",
            "actual_access": "Allowed" if actual else "Denied",
            "status_code": status_code,
            "tags": endpoint.get("tags"),
            "security": endpoint.get("security")
        }
        if response:
            details["response_sample"] = response
        if response_headers is not None:
            details["response_headers"] = response_headers
        self._log_issue(
            url=endpoint["url"],
            description=desc,
            severity=severity,
            details=details
        )

    def _test_missing_authorization_headers(self):
        for ep in self.discovered_endpoints:
            try:
                r = self.session.get(ep["url"], timeout=5, verify=False)
                if r.status_code in [200, 201, 204]:
                    self._log_issue(
                        url=ep["url"],
                        description="Endpoint accepteert zonder Authorization-header",
                        severity="Medium",
                        details={"status": r.status_code}
                    )
            except Exception:
                pass

    def _test_rate_limiting_bypass(self):
        for ep in self.discovered_endpoints:
            success = 0
            for _ in range(10):
                try:
                    r = self.session.get(ep["url"], timeout=5, verify=False)
                    if r.status_code in [200, 201, 204]:
                        success += 1
                except Exception:
                    pass
            if success > 5:
                self._log_issue(
                    url=ep["url"],
                    description="Rate-limiting mogelijk omzeild",
                    severity="Medium",
                    details={"successful_requests": success}
                )

    def _test_jwt_validation(self):
        if not self.roles["user"]["token"]:
            return
        cases = [
            ("none-alg", self._set_jwt_alg(self.roles["user"]["token"], "none")),
            ("empty-sig", self._set_jwt_signature(self.roles["user"]["token"], "")),
            ("modify-role", self._modify_jwt_claim(self.roles["user"]["token"], "role", "admin"))
        ]
        ep = next((e for e in self.discovered_endpoints if e.get("sensitive")), None)
        if not ep:
            return
        for name, tok in cases:
            try:
                r = self.session.get(
                    ep["url"],
                    headers={"Authorization": f"Bearer {tok}"},
                    timeout=5,
                    verify=False
                )
                if r.status_code in [200, 201, 204]:
                    self._log_issue(
                        url=ep["url"],
                        description=f"JWT-validatie mislukt - {name}",
                        severity="High",
                        details={"case": name, "response_headers": dict(r.headers)}
                    )
            except Exception:
                pass

    def _test_idor_vulnerabilities(self):
        pattern = re.compile(r"/(\d+)|/[\w-]+(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})")
        for ep in self.discovered_endpoints:
            if pattern.search(ep["url"]) and "GET" in ep.get("methods", []):
                self._test_idor_scenario(ep)

    def _test_idor_scenario(self, endpoint: Dict):
        try:
            r1 = self.session.get(
                endpoint["url"],
                headers={"Authorization": f"Bearer {self.roles['user']['token']}"},
                timeout=5,
                verify=False
            )
            r2 = self.session.get(
                endpoint["url"],
                headers={"Authorization": f"Bearer {self.roles['editor']['token']}"},
                timeout=5,
                verify=False
            )
            if r1.status_code == 200 and r1.text == r2.text:
                self._log_issue(
                    url=endpoint["url"],
                    description="IDOR-vuln detecteerd",
                    severity="High",
                    details={"scenario": "user vs editor", "response_headers": dict(r1.headers)}
                )
        except Exception as e:
            self._log_issue(
                url=endpoint["url"],
                description="IDOR-test mislukt",
                severity="Medium",
                details={"error": str(e)}
            )

    # JWT manipulation helpers
    def _set_jwt_alg(self, token: str, alg: str) -> str:
        try:
            hdr = json.loads(base64.b64decode(token.split('.')[0] + '==='))
            hdr['alg'] = alg
            nh = base64.b64encode(json.dumps(hdr).encode()).decode().rstrip('=')
            parts = token.split('.')
            return f"{nh}.{parts[1]}.{parts[2]}"
        except Exception:
            return token

    def _set_jwt_signature(self, token: str, sig: str) -> str:
        parts = token.split('.')
        return f"{parts[0]}.{parts[1]}.{sig}" if len(parts) >= 2 else token

    def _modify_jwt_claim(self, token: str, claim: str, value: Any) -> str:
        try:
            parts = token.split('.')
            payload = json.loads(base64.b64decode(parts[1] + '==='))
            payload[claim] = value
            np = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{parts[0]}.{np}.{parts[2]}"
        except Exception:
            return token

    def _log_issue(self, url: str, description: str, severity: str, details: Optional[Dict] = None):
        """Log a security issue"""
        self.authz_issues.append({
            "url": url,
            "description": description,
            "severity": severity,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        })
        
        
    def generate_report(self, output_format: str = "markdown"):
        """Generate report with cloud-specific findings"""
        if not self.authz_issues:
            return "No authorization issues found"

        if output_format == "json":
            return json.dumps({
                "meta": {
                    "scan_date": datetime.now().isoformat(),
                    "target": self.base_url,
                    "cloud_detected": self._detect_cloud_provider()
                },
                "findings": self.authz_issues
            }, indent=2)
        return self._generate_markdown_report()

    def _generate_markdown_report(self) -> str:
         # 0. Bereken samenvatting
        counts = Counter(iss["severity"] for iss in self.authz_issues)
        high_eps = sorted({iss["url"] for iss in self.authz_issues if iss["severity"] == "High"})

        # 1. Header + samenvatting
        md_lines = [
            f"# Authorization Audit Report voor {self.base_url}",
            "",
            "## Samenvatting",
            f"- 🛑 High: {counts['High']} issues",
            f"- ⚠️ Medium: {counts['Medium']} issues",
            f"- ℹ️ Low: {counts['Low']} issues",
        ]
        if high_eps:
            md_lines += ["", "### Endpoints met High-severity issues"]
            md_lines += [f"- `{ep}`" for ep in high_eps]
        md_lines.append("")  # lege regel vóór details

        # 2. Organiseer issues per endpoint
        per_endpoint: Dict[str, List[Dict]] = {}
        for issue in self.authz_issues:
            per_endpoint.setdefault(issue["url"], []).append(issue)

        # 3. Voor elke endpoint: bestaande grouped-logic
        for url, issues in per_endpoint.items():
            md_lines.append(f"## Endpoint: `{url}`")
            grouped: Dict[
                Tuple[str, Optional[str], int, Optional[Tuple]],
                Dict[str, Any]
            ] = {}

            for iss in issues:
                # parse zoals eerder…
                m = re.match(r"^(?P<base>.+?) - (?P<method>\w+) as (?P<role>\w+)$", iss["description"])
                if m:
                    base, method, role = m.group("base"), m.group("method"), m.group("role")
                else:
                    base, method, role = iss["description"], None, None

                details = iss.get("details", {})
                status = details.get("status_code", details.get("status", 0))
                rh = details.get("response_headers")
                rh_key = tuple(sorted(rh.items())) if isinstance(rh, dict) else None

                key = (base, role, status, rh_key)
                grp = grouped.setdefault(key, {
                    "methods": set(), "first_ts": iss["timestamp"], "details": details
                })
                grp["methods"].update([method] if method else [])
                grp["first_ts"] = min(grp["first_ts"], iss["timestamp"])

            # render grouped entries
            for (base, role, status, rh_key), info in grouped.items():
                title = f"{base} as {role}" if role else base
                methods = ", ".join(sorted(info["methods"])) if info["methods"] else ""
                ts = info["first_ts"]
                line = f"- **{title}**"
                if methods:
                    line += f" — methods: {methods}"
                line += f"  \n  _Eerste timestamp_: {ts}"
                md_lines.append(line)

                md_lines.append("  - Details:")
                if status:
                    md_lines.append(f"    - **status_code**: `{status}`")
                for k, v in info["details"].items():
                    if k in ("status_code", "response_headers"):
                        continue
                    md_lines.append(f"    - **{k}**: `{v}`")
                if rh_key:
                    md_lines.append("    - **response_headers:**")
                    for h, val in rh_key:
                        md_lines.append(f"      - `{h}`: `{val}`")

            md_lines.append("")  # lege regel tussen endpoints

        return "\n".join(md_lines)


    


    def _detect_cloud_provider(self) -> Optional[str]:
        """Detect if running on a cloud platform"""
        if "amazonaws.com" in self.base_url:
            return "AWS"
        if "azure" in self.base_url:
            return "Azure"
        if "googleapis.com" in self.base_url:
            return "GCP"
        return None
