# broken_auth_audit.py
#
# Licensed under the MIT License.
# Copyright (c) 2025 Perry Mertens
#
# Broken Authentication Auditor (OWASP API2)
# This version aligns its logging & reporting with broken_object_property_audit.py:
#   * Skip issues where no HTTP response was received (status_code == 0)
#   * Capture full HTTP context (request/response headers & body)
#   * generate_report/save_report automatically filter such skipped issues
#   * Fixes wrong argument name "response" in _test_weak_credentials
#
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests
from report_utils import ReportGenerator


class AuthAuditor:
    """OWASP API2:2023 - Broken Authentication auditor"""

    def __init__(self, base_url: str, session: Optional[requests.Session] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.auth_issues: List[Dict[str, Any]] = []

        # ------------------------------------------------------------------ #
    # Logging helper
    # ------------------------------------------------------------------ #
        # ------------------------------------------------------------------ #
    # Helper om één finding te loggen
    # ------------------------------------------------------------------ #
    def _log_issue(
        self,
        endpoint: str,
        description: str,
        severity: str,
        request_data: Optional[Dict[str, Any]] = None,
        response_obj: Optional[requests.Response] = None,
    ) -> None:
        """Log een bevinding (skip als er helemaal geen HTTP-antwoord was)."""
        status_code = getattr(response_obj, "status_code", 0)
        if status_code == 0:                # geen respons → geen finding
            return

        # Garandeer ALTIJD url & method
        url = getattr(response_obj, "url", endpoint)
        method = (
            getattr(getattr(response_obj, "request", None), "method", None)
            or (request_data or {}).get("method")
            or "POST"
        ).upper()

        entry: Dict[str, Any] = {
            "endpoint": endpoint,
            "url": url,                     # verplicht voor HTML-rapport
            "method": method,               # idem
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "request": request_data or {},
            "status_code": status_code,
            # ↓ worden zo nodig aangevuld
            "request_headers": {},
            "request_body": None,
            "response_headers": {},
            "response_body": "",
        }

        # Vul contextvelden zodra ze er zijn
        if response_obj is not None:
            entry["response_headers"] = dict(response_obj.headers)
            entry["response_body"] = response_obj.text[:2048]
            if response_obj.request is not None:
                entry["request_headers"] = dict(response_obj.request.headers)
                entry["request_body"] = getattr(response_obj.request, "body", None)

        self.auth_issues.append(entry)

    

    # --------------------------------------------------------------------- #
    # Toplevel test runner
    # --------------------------------------------------------------------- #

    def test_authentication_mechanisms(self, auth_endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all authentication tests against provided endpoints.

        Each *endpoint* dict must contain:
            url      - full URL or path
            methods  - allowed HTTP verbs (optional)
        """
        if not auth_endpoints:
            auth_endpoints = self._discover_auth_endpoints()

        for ep in auth_endpoints:
            try:
                self._test_auth_endpoint(ep)
            except Exception as exc:  # noqa: BLE001
                # generic catch - still log but without HTTP context
                self._log_issue(
                    endpoint=ep.get("url", "-"),
                    description=f"Test error: {exc}",
                    severity="Medium",
                )

        return self.auth_issues

    # --------------------------------------------------------------------- #
    # Endpoint discovery
    # --------------------------------------------------------------------- #

    def _discover_auth_endpoints(self) -> List[Dict[str, str]]:
        common = ["/auth/login", "/oauth/token", "/api/login", "/user/authenticate"]
        discovered: List[Dict[str, str]] = []

        for path in common:
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.options(url, timeout=3)
                if resp.status_code < 500:
                    discovered.append({"url": url, "methods": resp.headers.get("Allow", "POST")})
            except requests.RequestException:
                continue

        # Fallback default
        if not discovered:
            discovered = [
                {"url": f"{self.base_url}/auth/login", "methods": "POST"},
                {"url": f"{self.base_url}/oauth/token", "methods": "POST"},
            ]
        return discovered

    # --------------------------------------------------------------------- #
    # Composite test orchestrator
    # --------------------------------------------------------------------- #

    def _test_auth_endpoint(self, endpoint: Dict[str, Any]) -> None:
        tests = [
            self._test_weak_credentials,
            self._test_token_security,
            self._test_rate_limiting,
            self._test_jwt_issues,
        ]
        for test in tests:
            try:
                test(endpoint)
            except Exception as exc:  # noqa: BLE001
                self._log_issue(endpoint["url"], f"Test error: {exc}", severity="Medium")

    # --------------------------------------------------------------------- #
    # Test cases
    # --------------------------------------------------------------------- #

    def _test_weak_credentials(self, endpoint: Dict[str, Any]) -> None:
        weak_creds = [
            ("admin", "admin"),
            ("user", "password"),
            ("test", "test123"),
            ("", ""),
        ]
        for username, password in weak_creds:
            data = {"username": username, "password": password}
            resp = self.session.post(endpoint["url"], json=data, timeout=5)
            if resp.status_code == 200:
                self._log_issue(
                    endpoint["url"],
                    f"Weak credentials accepted: {username}/{password}",
                    severity="High",
                    request_data=data,
                    response_obj=resp,
                )

    def _test_token_security(self, endpoint: Dict[str, Any]) -> None:
        valid_resp = self.session.post(
            endpoint["url"], json={"username": "test", "password": "validpass"}, timeout=5
        )
        if valid_resp.status_code != 200:
            return

        token = (
            valid_resp.json().get("access_token")
            or valid_resp.json().get("token")
            or valid_resp.json().get("jwt")
        )
        if not token:
            return

        # Very long lifetime
        long_resp = self.session.post(
            endpoint["url"],
            json={"username": "test", "password": "validpass", "expires_in": 999999},
            timeout=5,
        )
        if long_resp.status_code == 200:
            self._log_issue(
                endpoint["url"],
                "Tokens can be given extremely long lifetimes",
                severity="Medium",
                request_data={"expires_in": 999999},
                response_obj=long_resp,
            )

        # Token revocation / logout
        logout_url = endpoint["url"].replace("login", "logout")
        revoke_resp = self.session.post(logout_url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if revoke_resp.status_code >= 400:
            self._log_issue(
                endpoint["url"],
                "Tokens cannot be revoked",
                severity="Medium",
                response_obj=revoke_resp,
            )

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        """
        Controleer of er rate-limiting is op het opgegeven auth-endpoint.

        - Pakt de *toegestane* HTTP-method uit endpoint["methods"].
        - Stuurt 10 snelle inlogpogingen met random credentials.
        - Meldt alleen 'No rate limiting' als het endpoint de pogingen
        echt verwerkt (≠ 404/405/501) én nooit een 429 terugstuurt.
        """
        # 1. Bepaal de juiste methode (fallback = POST)
        allowed = [m.strip().upper()
                for m in endpoint.get("methods", "POST").split(",")]
        method = "POST" if "POST" in allowed else allowed[0]

        last_resp: Optional[requests.Response] = None
        processed = False  # komt er minimaal één 'echte' (200/400/401/403) respons?

        for i in range(10):
            try:
                last_resp = self.session.request(
                    method,
                    endpoint["url"],
                    json={"username": f"attacker{i}", "password": "wrong"},
                    timeout=5,
                )
            except requests.RequestException:
                continue  # netwerk- of TLS-fout, probeer de volgende poging

            if last_resp.status_code == 429:
                return  # rate-limiting aanwezig → geen issue loggen

            if last_resp.status_code in (404, 405, 501):
                # Methode niet toegestaan of endpoint bestaat niet → test niet relevant
                self._log_issue(
                    endpoint["url"],
                    f"Method {method} not allowed - rate-limit test skipped",
                    severity="Info",
                    response_obj=last_resp,
                )
                return

            # respons werd écht verwerkt door de authenticatieroute
            if last_resp.status_code < 500:
                processed = True

        # Komt hier alleen als er geen enkele 429 was
        if processed:
            self._log_issue(
                endpoint["url"],
                "No rate limiting on auth endpoint",
                severity="Medium",
                response_obj=last_resp,
            )


    def _test_jwt_issues(self, endpoint: Dict[str, Any]) -> None:
        resp = self.session.post(endpoint["url"], json={"username": "test", "password": "validpass"}, timeout=5)
        if resp.status_code != 200:
            return
        token = resp.json().get("access_token") or resp.json().get("token")
        if not token:
            return

        # Tamper signature
        modified = token[:-5] + "aaaaa"
        check_resp = self.session.get(
            f"{self.base_url}/api/protected", headers={"Authorization": f"Bearer {modified}"}, timeout=5
        )
        if check_resp.status_code == 200:
            self._log_issue(
                endpoint["url"],
                "JWT signature is not verified",
                severity="Critical",
                response_obj=check_resp,
            )

   
   
    # --------------------------------------------------------------------- #
    # Report helpers
    # --------------------------------------------------------------------- #

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        """Return issues that have an actual HTTP response (status_code ≠ 0)."""
        return [i for i in self.auth_issues if i.get("status_code", 1) != 0]


    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(
            self._filtered_issues(),
            scanner="BrokenAuth (API02)",   # titel in header
            base_url=self.base_url,
        )
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()
       
    
    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(
            self._filtered_issues(),
            scanner="BrokenAuth (API02)",
            base_url=self.base_url,
        ).save(path, fmt=fmt)
    
  

