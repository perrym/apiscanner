# authorization_audit.py
##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
from __future__ import annotations
import base64
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import requests
import urllib3
from report_utils import ReportGenerator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def _headers_to_list(hdrs):
    """
    urllib3.HTTPHeaderDict -> Set-Cookie 
    """
    if hasattr(hdrs, "getlist"):        # urllib3.HTTPHeaderDict
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())

class AuthorizationAuditor:
    """OWASP API01 - Broken Authorization Auditor (clean logging)."""
    def __init__(
        self,
        base_url: str,
        swagger_data: Optional[Dict[str, Any]] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        if isinstance(swagger_data, requests.Session):
            session, swagger_data = swagger_data, None

        self.base_url = (
            f"https://{base_url}".rstrip("/") + "/" if not urlparse(base_url).scheme else base_url.rstrip("/") + "/"
        )
        self.session = session or self._make_session()
        self.swagger_data = swagger_data
        self.authz_issues: List[Dict[str, Any]] = []

        self.discovered_endpoints = (
            self._parse_swagger_data() if swagger_data else self._discover_endpoints()
        )

        self.roles: Dict[str, Dict[str, Any]] = {
            "anonymous": {"token": None},
            "user": {"username": "testuser", "password": "testpass", "token": None},
            "admin": {"username": "admin", "password": "adminpass", "token": None},
        }
        self._get_all_tokens()

    # --------------------------- helpers --------------------------- #

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": "APISecurityScanner/2.1", "Accept": "application/json"})
        s.verify = False
        return s

    def _parse_swagger_data(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(self.swagger_data, dict):
            return out
        for path, verbs in self.swagger_data.get("paths", {}).items():
            for verb, meta in verbs.items():
                if verb.upper() not in {"GET", "POST", "PUT", "PATCH"}:
                    continue
                out.append(
                    {
                        "url": urljoin(self.base_url, path),
                        "methods": [verb.upper()],
                        "sensitive": self._is_sensitive(meta),
                        "security": meta.get("security", []),
                    }
                )
        return out

    def _discover_endpoints(self) -> List[Dict[str, Any]]:
        paths = ["/api/admin", "/api/users", "/admin", "/users"]
        return [{"url": urljoin(self.base_url, p), "methods": ["GET"], "sensitive": "admin" in p} for p in paths]

    def _is_sensitive(self, meta: Dict[str, Any]) -> bool:
        indic = ("admin", "delete", "write", "internal")
        tags = " ".join(meta.get("tags", [])).lower()
        if any(i in tags for i in indic):
            return True
        return False

    # --------------------------- tokens --------------------------- #

    def _get_all_tokens(self) -> None:
        for role, cfg in self.roles.items():
            if role == "anonymous":
                continue
            cfg["token"] = "dummy-token"  # simplified (placeholder)

    # --------------------------- main tests --------------------------- #

    def test_authorization(self) -> List[Dict[str, Any]]:
        for ep in self.discovered_endpoints:
            self._test_endpoint(ep)
        return self.authz_issues

    def _test_endpoint(self, ep: Dict[str, Any]) -> None:
        for verb in ep.get("methods", ["GET"]):
            self._do_request(ep, verb, role="anonymous", should_access=not ep.get("sensitive", False))

    def _do_request(self, ep: Dict[str, Any], verb: str, role: str, should_access: bool) -> None:
        headers = {
            "User-Agent": "APISecurityScanner/2.1",
            "Accept": "application/json"
        }

        if role != "anonymous" and self.roles[role]["token"]:
            headers["Authorization"] = f"Bearer {self.roles[role]['token']}"

        try:
            if role == "anonymous":
                # Gebruik expliciete, schone request zonder session (om lekken te voorkomen)
                r = requests.request(
                    method=verb,
                    url=ep["url"],
                    headers=headers,
                    timeout=5,
                    verify=False,
                )
            else:
                # Normale sessie met mogelijk cookies of headers
                r = self.session.request(
                    method=verb,
                    url=ep["url"],
                    headers=headers,
                    timeout=5,
                    verify=False,
                )

            allowed = r.status_code in (200, 201, 204)

            if allowed != should_access:
                desc = "Unauthorized access" if allowed else "Access denied"
                sev = "High" if allowed else "Medium"
                self._log_issue(
                    url=ep["url"],
                    description=f"{desc} - {verb} as {role}",
                    severity=sev,
                    details={"method": verb, "role": role},
                    response_obj=r,
                )

        except Exception as exc:
            self._log_issue(
                url=ep["url"],
                description=f"Request error - {verb} as {role}: {exc}",
                severity="Low",
                details={"method": verb, "role": role},
            )


    def _filtered_issues(self) -> List[Dict[str, Any]]:
        uniq = {}
        for it in self.authz_issues:
            if not it.get("status_code"):
                continue
            k = (it["endpoint"], it["method"], it["description"], it["status_code"])
            uniq.setdefault(k, it)          # eerste wint, latere duplicates skippen
        return list(uniq.values())

    # --------------------------- logging --------------------------- #

    def _log_issue(
        self,
        url: str,
        description: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
        response_obj: Optional[requests.Response] = None,
    ) -> None:
        details = details or {}
        status_code = getattr(response_obj, "status_code", None)
        if status_code in (None, 0):
            return  # ignore - no HTTP response

        entry: Dict[str, Any] = {
            "url": url,
            "endpoint": url,  
            "method": response_obj.request.method if response_obj and response_obj.request else details.get("method", "GET"),
            "description": description,
            "severity": severity,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "request_headers": {},
            "response_headers": {},
            "request_cookies": {},
            "response_cookies": {},
            "request_body": None,
            "response_body": None,
        }

        if response_obj is not None:
            entry["response_headers"] = dict(response_obj.headers)
            entry["response_body"] = response_obj.text[:2048]
            entry["response_cookies"] = response_obj.cookies.get_dict()
            
            if response_obj.request is not None:
                entry["request_headers"] = dict(response_obj.request.headers)
                entry["request_body"] = response_obj.request.body
                entry["request_cookies"] = self.session.cookies.get_dict()

        # merge non-conflicting details
        for k, v in details.items():
            if k not in entry:
                entry[k] = v

        self.authz_issues.append(entry)

    # --------------------------- reporting --------------------------- #

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return [i for i in self.authz_issues if i.get("status_code")]

    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner="Authorization", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(self._filtered_issues(), scanner="Authorization", base_url=self.base_url).save(path, fmt=fmt)
