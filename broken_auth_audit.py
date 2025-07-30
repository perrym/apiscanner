##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
"""
Combined Broken Authentication **and** Crypto/Transport Security Auditor
-----------------------------------------------------------------------
This single module now covers
    - **OWASP API2: Broken Authentication**  - weak creds, token issues, JWT, rate-limiting
    - **OWASP API8: Security Misconfiguration** - missing TLS, deprecated TLS versions, weak ciphers,
      exposed secrets, weak password hashes, JWT "alg:none"

The auditor keeps one shared *issues* list so the main CLI (`apiscan.py`) does
not need to change: just instantiate **AuthAuditor** and call
`test_authentication_mechanisms()` - all crypto findings land in the same list.

Optional dependency: *sslyze*  6 for deep cipher-suite scans. If it is not
installed the cipher-test is skipped automatically.
"""
from __future__ import annotations

import base64
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path
import requests
from urllib.parse import urlparse
from urllib.parse import urljoin 
from report_utils import ReportGenerator
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None  # cryptography not installed

# ---------------------------------------------------------------------------
# Optional dependency (cipher-suite scan)
# ---------------------------------------------------------------------------
try:
    from sslyze import ServerScanRequest, Scanner, ServerScanResult  # type: ignore
except ImportError:  # pragma: no cover
    Scanner = None  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_swagger_from_cli() -> dict | None:
    """
    Look for '--swagger <file>' in sys.argv and return the parsed JSON spec.
    Returns None when the flag is missing or the file cannot be read.
    """
    try:
        args = sys.argv
        if "--swagger" in args:
            idx = args.index("--swagger")
            if idx + 1 < len(args):
                p = Path(args[idx + 1]).expanduser().resolve()
                if p.is_file() and p.stat().st_size:
                    with p.open("r", encoding="utf-8") as fh:
                        return json.load(fh)
    except Exception:
        pass
    return None




def _headers_to_list(hdrs):
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())

def _load_remote_openapi(base_url: str, sess: requests.Session) -> dict | None:
    """
    Try to download an OpenAPI / Swagger JSON document from common locations.
    Returns the parsed spec or None when nothing is found.
    """
    candidates = [
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/swagger/v1/swagger.json",
    ]
    for path in candidates:
        try:
            resp = sess.get(urljoin(base_url + "/", path.lstrip("/")), timeout=5, verify=False)
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
        except requests.RequestException:
            continue
    return None


class AuthAuditor:
    """Combined Auth & Crypto auditor (OWASP API2 + parts of API8)."""

    # ===================================================================== #
    # Init & logging
    # ===================================================================== #
    def __init__(self, base_url: str, session: Optional[requests.Session] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.auth_issues: List[Dict[str, Any]] = []

    @property
    def _host(self) -> str:
        """Extract hostname from base URL."""
        parsed = urlparse(self.base_url)
        return parsed.hostname or parsed.netloc.split(":")[0]

    @property
    def _port(self) -> int:
        """Extract port from base URL with HTTPS default."""
        parsed = urlparse(self.base_url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    def _log_issue(
        self,
        endpoint: str,
        description: str,
        severity: str,
        request_data: Optional[Dict[str, Any]] = None,
        response_obj: Optional[requests.Response] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        status_code = getattr(response_obj, "status_code", 0)
        # Allow crypto tests that are not based on HTTP response (status_code may be 0)
        if response_obj is None and extra is None:
            # still record finding without HTTP context - used by TLS probes
            status_code = 0

        url = (
            getattr(response_obj, "url", None)
            or endpoint
        )
        method = (
            getattr(getattr(response_obj, "request", None), "method", None)
            or (request_data or {}).get("method", "GET")
        ).upper()

        entry: Dict[str, Any] = {
            "endpoint": endpoint,
            "url": url,
            "method": method,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "status_code": status_code,
            "request": request_data or {},
            "request_headers": {},
            "request_body": None,
            "response_headers": {},
            "response_body": "",
        }
        if response_obj is not None:
            entry["response_headers"] = _headers_to_list(response_obj.raw.headers)
            entry["response_body"] = response_obj.text[:2048]
            if response_obj.request is not None:
                entry["request_headers"] = _headers_to_list(response_obj.request.headers)
                entry["request_body"] = getattr(response_obj.request, "body", None)
        if extra:
            entry.update(extra)
        # cookies
        entry["request_cookies"] = self.session.cookies.get_dict()
        if response_obj is not None:
            entry["response_cookies"] = response_obj.cookies.get_dict()
        self.auth_issues.append(entry)

    # ===================================================================== #
    # Public runner
    # ===================================================================== #
    def _load_all_get_endpoints(self) -> list[str]:
        if not hasattr(self, "openapi_spec") or not self.openapi_spec:
            print("[Password-hash check] Skipped - no OpenAPI spec present.")
            return []

        endpoints = []
        for path, methods in self.openapi_spec.get("paths", {}).items():
            for method, meta in methods.items():
                if method.lower() == "get":
                    full_url = f"{self.base_url.rstrip('/')}{path}"
                    endpoints.append(full_url)
        return endpoints

    
    def test_authentication_mechanisms(
        self,
        swagger_endpoints: list[dict] | None = None
    ) -> list[dict]:
        #   Save the raw list exactly as we received it
        self._all_endpoints = swagger_endpoints or []
        #  Normalise every entry to include url / methods
        def _norm(items: list[dict]) -> list[dict]:
            out = []
            for ep in items:
                path   = ep["path"]
                method = ep["method"].upper()
                url    = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
                out.append({"path": path, "method": method, "url": url, "methods": method})
            return out

        norm_eps = _norm(self._all_endpoints)
        self._swagger_get_eps = [ep for ep in norm_eps if ep["method"] == "GET"]
        #  Split lists for different probes
        auth_keywords = (
            "auth", "login", "token", "signin", "authenticate",
            "oauth", "saml", "jwt", "oidc", "mfa", "2fa",
            "magiclink", "passwordless", "sso"
        )
        auth_eps = [
            {"url": ep["url"], "methods": ep["methods"]}
            for ep in norm_eps
            if any(k in ep["path"].lower() for k in auth_keywords)
        ] or [{"url": ep["url"], "methods": ep["methods"]} for ep in norm_eps]  # fallback

        self._swagger_get_eps = [ep for ep in norm_eps if ep["method"] == "GET"]
        #  Authtests (Broken Authentication)
        for ep in auth_eps:
            method = ep["methods"]
            print(f"-> Testing auth endpoint {method} {ep['url']}")
            try:
                self._test_endpoint_auth(ep)
            except Exception as exc:
                self._log_issue(ep["url"], f"Auth test error: {exc}", "Medium")
        #.  Crypto / transportlayer tests
        try:
            self._run_crypto_suite()
        except Exception as exc:
            self._log_issue(self.base_url, f"Crypto test error: {exc}", "Medium")

        return self._filtered_issues()

        
    

    
    # ===================================================================== #
    # Endpoint discovery
    # ===================================================================== #
    def _discover_auth_endpoints(self) -> list[dict[str, str]]:
        """
        Return a list of authentication endpoints.

        - If an OpenAPI / Swagger spec can be obtained (remote download or the
        --swagger file passed to apiscan.py), extract every operation whose path
        contains any of the auth-related keywords below.

        - If no spec is available, fall back to two classic login/token routes so
        the Broken Authentication audit can still execute.

        The function never appends the big generic 'common' list, so you avoid the
        405 'method not allowed' noise.
        """
        # ---------- obtain the spec ----------
        spec = _load_remote_openapi(self.base_url, self.session)
        if spec is None:
            spec = _load_swagger_from_cli()

        endpoints: list[dict[str, str]] = []

        # ---------- extract from spec ----------
        if spec:
            keywords = (
                "auth", "login", "token", "signin", "authenticate",
                "oauth", "saml", "jwt", "oidc", "mfa", "2fa", "magiclink",
                "passwordless", "sso",
            )
            for path, item in spec.get("paths", {}).items():
                if not any(k in path.lower() for k in keywords):
                    continue                     # skip non-auth paths

                for method in item:              # method = "get", "post", ...
                    full_url = urljoin(
                        self.base_url.rstrip("/") + "/",
                        path.lstrip("/"),
                    )
                    endpoints.append({
                        "url": full_url,
                        "methods": method.upper(),
                    })

            if endpoints:
                return endpoints                 # done - use spec only

        # ---------- minimal fallback ----------
        return [
            {"url": f"{self.base_url.rstrip('/')}/auth/login",  "methods": "POST"},
            {"url": f"{self.base_url.rstrip('/')}/oauth/token", "methods": "POST"},
        ]

    # ===================================================================== #
    # AUTHENTICATION TEST SUITE
    # ===================================================================== #
    def _test_endpoint_auth(self, endpoint: Dict[str, Any]) -> None:
        tests = [
            self._test_weak_credentials,
            self._test_token_security,
            self._test_rate_limiting,
            self._test_jwt_issues,
        ]
        for t in tests:
            try:
                t(endpoint)
            except Exception as exc:  # noqa: BLE001
                self._log_issue(endpoint["url"], f"Auth sub-test error: {exc}", "Medium")

    # -------------------- individual auth tests -------------------- #
    def _test_weak_credentials(self, endpoint: Dict[str, Any]) -> None:
        weak = [
            ("admin", "admin"),
            ("user", "password"),
            ("test", "test123"),
            ("", ""),
        ]
        for u, p in weak:
            data = {"username": u, "password": p}
            resp = self.session.post(endpoint["url"], json=data, timeout=5)
            if resp.status_code == 200:
                self._log_issue(endpoint["url"], f"Weak creds accepted: {u}/{p}", "High", data, resp)

    def _test_token_security(self, endpoint: Dict[str, Any]) -> None:
        valid_resp = self.session.post(endpoint["url"], json={"username": "test", "password": "validpass"}, timeout=5)
        if valid_resp.status_code != 200:
            return
        token = (
            valid_resp.json().get("access_token")
            or valid_resp.json().get("token")
            or valid_resp.json().get("jwt")
        )
        if not token:
            return
        # long expiry
        long_resp = self.session.post(endpoint["url"], json={"username": "test", "password": "validpass", "expires_in": 999999}, timeout=5)
        if long_resp.status_code == 200:
            self._log_issue(endpoint["url"], "Tokens can be issued with very long lifetimes", "Medium", {"expires_in": 999999}, long_resp)
        # revocation check
        logout_url = endpoint["url"].replace("login", "logout")
        revoke_resp = self.session.post(logout_url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if revoke_resp.status_code >= 400:
            self._log_issue(endpoint["url"], "Tokens appear non-revocable", "Medium", response_obj=revoke_resp)

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        allowed = [m.strip().upper() for m in endpoint.get("methods", "POST").split(",")]
        method = "POST" if "POST" in allowed else allowed[0]
        processed = False
        last_resp: Optional[requests.Response] = None
        for i in range(10):
            try:
                last_resp = self.session.request(method, endpoint["url"], json={"username": f"att{i}", "password": "bad"}, timeout=5)
            except requests.RequestException:
                continue
            if last_resp.status_code == 429:
                return  # rate-limit OK
            if last_resp.status_code in (404, 405, 501):
                self._log_issue(endpoint["url"], f"Method {method} not allowed - RL test skipped", "Info", response_obj=last_resp)
                return
            if last_resp.status_code < 500:
                processed = True
        if processed:
            self._log_issue(endpoint["url"], "No rate-limiting on auth endpoint", "Medium", response_obj=last_resp)

    def _test_jwt_issues(self, endpoint: Dict[str, Any]) -> None:
        """Test JWT tokens for common vulnerabilities."""
        # Helper function to decode JWT header
        def decode_jwt_header(token: str) -> Dict[str, Any]:
            try:
                header_b64 = token.split('.')[0]
                # Add padding if needed (base64 requires length multiple of 4)
                padding = '=' * (-len(header_b64) % 4)
                return json.loads(base64.urlsafe_b64decode(header_b64 + padding))
            except Exception:
                return {}

        # Helper function to decode JWT payload
        def decode_jwt_payload(token: str) -> Dict[str, Any]:
            try:
                payload_b64 = token.split('.')[1]
                padding = '=' * (-len(payload_b64) % 4)
                return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
            except Exception:
                return {}

        # Get valid token
        resp = self.session.post(
            endpoint["url"],
            json={"username": "test", "password": "validpass"},
            timeout=5
        )
        if resp.status_code != 200:
            return

        token = resp.json().get("access_token") or resp.json().get("token")
        if not token or token.count(".") != 2:
            return

        # 1. Check for 'alg:none' vulnerability
        header = decode_jwt_header(token)
        alg = header.get("alg", "").lower()
        if alg == "none":
            self._log_issue(
                endpoint["url"],
                "JWT uses 'alg:none' - no signature required!",
                "Critical",
                response_obj=resp
            )

        # 2. Test signature validation
        if len(token) > 10:  # Ensure token is long enough
            tampered = token[:-5] + "abcde"
            check = self.session.get(
                f"{self.base_url}/api/protected",
                headers={"Authorization": f"Bearer {tampered}"},
                timeout=5
            )
            if check.status_code == 200:
                self._log_issue(
                    endpoint["url"],
                    "JWT signature not validated - tampered token accepted",
                    "Critical",
                    response_obj=check
                )

        # 3. Test missing expiration claim
        payload = decode_jwt_payload(token)
        if not payload.get("exp"):
            self._log_issue(
                endpoint["url"],
                "JWT missing expiration claim (exp)",
                "Medium",
                response_obj=resp
            )

    # ===================================================================== #
    # CRYPTO / TRANSPORT SECURITY SUITE (API8)
    # ===================================================================== #
    def _run_crypto_suite(self) -> None:
        """Run all crypto tests with individual error handling."""
        crypto_tests = [
            self._test_plain_http,
            self._test_tls_versions,
            self._test_cipher_suites,
            self._test_secret_exposure,
            lambda: self._test_password_hash_strength(self._swagger_get_eps),
            self._test_self_signed_cert, 
        ]
        
        for test in crypto_tests:
            try:
                test()
            except Exception as e:
                self._log_issue(
                    self.base_url,
                    f"Crypto test failed: {getattr(test, '__name__', str(test))}",
                    "High",
                    extra={
                        "error_type": "CryptoTestException",
                        "details": str(e)
                    }
                )


    # -------------------- crypto test helpers -------------------- #
    def _test_plain_http(self) -> None:
        """
        Check if the target is reachable over plain HTTP and log a High severity
        issue when TLS is missing or optional.

        Case 1: Base URL starts with http://
            -> Service is only reachable over HTTP. Log finding and return.

        Case 2: Base URL starts with https://
            -> Try to reach the same host over HTTP on port 80.
            If reachable without redirect, log finding.
        """
        http_url = "http://" + self.base_url.split("://", 1)[1]

        # Case 1: auditor invoked with http://
        if self.base_url.startswith("http://"):
            self._log_issue(
                http_url,
                "Secure transport layer missing - service is only reachable over HTTP",
                "High",
            )
            return

        # Case 2: auditor invoked with https://
        try:
            resp = self.session.get(http_url, timeout=5, allow_redirects=False)
            if resp.status_code < 400 and resp.status_code not in (301, 302, 307, 308):
                self._log_issue(
                    http_url,
                    "Secure transport layer missing - HTTP endpoint reachable without enforced redirect to HTTPS",
                    "High",
                    response_obj=resp,
                )
        except requests.RequestException:
            # No HTTP endpoint. Considered secure.
            pass

    def _test_tls_versions(self) -> None:
        """
        Probe the server on port 443 for support of deprecated protocols
        (SSLv2, SSLv3, TLS 1.0, TLS 1.1). If the handshake succeeds for any
        protocol the function logs a High severity finding.
        """
        host = self._host
        port = 443

        deprecated_versions = []
        if hasattr(ssl.TLSVersion, "SSLv2"):
            deprecated_versions.append(("SSLv2", ssl.TLSVersion.SSLv2))
        if hasattr(ssl.TLSVersion, "SSLv3"):
            deprecated_versions.append(("SSLv3", ssl.TLSVersion.SSLv3))
        deprecated_versions.extend([
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ])

        for name, version in deprecated_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers("ALL:@SECLEVEL=0")
                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        # Handshake succeeded
                        self._log_issue(
                            f"https://{host}:{port}",
                            f"Server accepts deprecated protocol {name}",
                            "High",
                        )
            except ssl.SSLError:
                # Server rejected this protocol
                continue
            except (socket.timeout, OSError):
                # Network error, stop further probing to avoid noise
                break

    
    def _test_cipher_suites(self) -> None:
        if Scanner is None:
            return
            
        host = self._host
        port = self._port
        try:
            scanner = Scanner()
            scan_req = ServerScanRequest(hostname=host, ip_address=host, port=port)
            scanner.queue_scan(scan_req)
            scanner.run_scans()
            res = scanner.get_results()[scan_req]
            
            try:
                cs = res.scan_result.tls_cipher_suites
                for accepted in cs.accepted_cipher_suites:
                    if "RC4" in accepted.cipher_suite.name or "DES" in accepted.cipher_suite.name:
                        self._log_issue(
                            self.base_url, 
                            f"Weak cipher supported: {accepted.cipher_suite.name}", 
                            "Medium", 
                            extra={"cipher": accepted.cipher_suite.name}
                        )
            except Exception as e:
                self._log_issue(
                    self.base_url,
                    f"Cipher suite analysis failed: {str(e)}",
                    "Medium"
                )
        except Exception as e:
            self._log_issue(
                self.base_url,
                f"SSLyze scan failed: {str(e)}",
                "Medium"
            )

    def _test_secret_exposure(self) -> None:
        """
        Probe common secret files and config artefacts.
        Logs a High-severity finding when an HTTP 200 body matches high-risk tokens.
        """
        paths = [
            # Environment files
            "/.env", "/.env.local", "/.env.prod", "/.env.production", "/.docker.env",
            # VCS metadata
            "/.git/config", "/.git/HEAD", "/.gitignore", "/.gitlab-ci.yml",
            # CI / CD configs
            "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/main.yml",
            # PHP / WordPress
            "/config.php", "/wp-config.php",
            # Rails
            "/config/database.yml", "/config/secrets.yml",
            # Java / Spring
            "/application.properties", "/application.yml", "/WEB-INF/web.xml",
            # Azure Functions
            "/local.settings.json",
            # Docker
            "/Dockerfile", "/docker-compose.yml",
            # SSH keys
            "/id_rsa", "/id_dsa", "/.ssh/authorized_keys",
            # Cloud credentials
            "/.aws/credentials",
            # Package managers
            "/.npmrc", "/composer.json", "/composer.lock",
            "/package.json", "/package-lock.json", "/.pypirc",
            # Gradle
            "/.gradle/gradle.properties",
            # Databases / dumps
            "/db.sqlite3", "/backup.sql", "/dump.sql",
            # Generic catch-alls
            "/keys.txt", "/secret.txt",
        ]

        token_pattern = re.compile(
            r"(-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----|"      # PEM keys
            r"aws_secret_access_key|aws_access_key_id|aws_secret|"  # AWS
            r"s3_access_key|s3_secret_key|amazon_aws|"              # AWS alt
            r"azure_client_secret|azure_tenant_id|azure_client_id|" # Azure AD
            r"azure_storage_account|azure_storage_key|sas_token|"   # Azure Storage
            r"subscription_key|accountkey|connectionstring|"        # Azure misc
            r"google_api_key|gcp_service_account|"                  # Google Cloud
            r"firebase_secret|firebase_database_url|"               # Firebase
            r"private_token|private_key|"                           # Generic tokens
            r"access_token|refresh_token|auth_token|bearer|"        # OAuth / JWT
            r"client_secret|consumer_key|consumer_secret|"          # OAuth apps
            r"api_key|apikey|secret_key|"                           # Generic API keys
            r"password)",
            re.I,
        )

        for path in paths:
            url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                # Use HEAD first to avoid downloading multi-MB dumps
                head = self.session.head(url, allow_redirects=True, timeout=3)
                if head.status_code != 200:
                    continue
                if int(head.headers.get("content-length", "0")) > 2_000_000:
                    continue  # skip very large files

                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and token_pattern.search(resp.text):
                    self._log_issue(
                        url,
                        f"Sensitive file {path} exposed",
                        "High",
                        response_obj=resp,
                    )
            except requests.RequestException:
                continue

    

# -----------------------------------------------------------------
# Password-hash strength probe
# -----------------------------------------------------------------
    def _test_password_hash_strength(self, endpoints: list[dict]) -> None:
        """
        Iterate over every GET endpoint in *endpoints* and look for weak /
        unhashed passwords in JSON responses.
        """
        if not endpoints:
            print("[Password-hash check] Skipped - no endpoints provided")
            return

        total = len(endpoints)
        print(f"[Password hash check] Scanning {total} endpoint(s)...")

        weak_re = re.compile(r"^\$2[aby]\$|\$argon2", re.I)   # bcrypt / argon2
        findings = 0

        for idx, ep in enumerate(endpoints, start=1):
            if ep.get("method", "").upper() != "GET":
                continue                                      # only GET returns data

            url = urljoin(self.base_url.rstrip("/") + "/", ep["path"].lstrip("/"))
            print(f"  {idx:02}/{total:02}  -> {url}")

            try:
                r = self.session.get(url, timeout=5)
                if r.status_code != 200:
                    continue
                if "json" not in r.headers.get("Content-Type", ""):
                    continue

                payload = r.json()
                records = payload if isinstance(payload, list) else [payload]

                for obj in records[:50]:                      # examine max 50 items
                    pwd = next(
                        (str(v) for k, v in obj.items() if "password" in k.lower()),
                        None
                    )
                    if pwd and not weak_re.match(pwd):
                        print(f"  !! weak hash for user {obj.get('id')}")
                        self._log_issue(
                            url,
                            "Weak or unhashed password stored",
                            "High",
                            response_obj=r,
                            extra={"user": obj.get("id")},
                        )
                        findings += 1
                        break                                  # one finding is enough
            except (requests.RequestException, ValueError):
                continue                                       # skip unreachable / invalid JSON

        if findings:
            print(f"[Password hash check] Done - {findings} weak hash issue(s) logged.")
        else:
            print("[Password hash check] Done - no weak hashes found.")



    
    def _test_self_signed_cert(self) -> None:
        """
        Detects self-signed or otherwise untrusted TLS certificates.

        * High severity when issuer == subject (self-signed).
        * Medium severity when the certificate is simply untrusted.
        """
        host = self._host
        port = self._port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True  # verify_mode is CERT_REQUIRED by default

            with socket.create_connection((host, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    # Handshake succeeded and cert is trusted
                    return

        except ssl.SSLCertVerificationError as exc:
            # Retrieve raw certificate for further inspection
            try:
                with socket.create_connection((host, port), timeout=5) as s:
                    with ssl.SSLContext().wrap_socket(s, server_hostname=host) as raw:
                        der = raw.getpeercert(binary_form=True)
            except Exception:
                der = None

            if der and x509:
                cert = x509.load_der_x509_certificate(der, default_backend())
                if cert.issuer == cert.subject:
                    severity = "High"
                    desc = "Server presents a self-signed TLS certificate"
                else:
                    severity = "Medium"
                    desc = "Server TLS certificate is not trusted by the system store"
            else:
                severity = "Medium"
                desc = "Server TLS certificate is not trusted by the system store"

            self._log_issue(
                f"https://{host}:{port}",
                desc,
                severity,
                extra={
                    "error": str(exc),
                    "observed_utc": datetime.utcnow().isoformat(),
                },
            )

        except (socket.timeout, OSError):
            # Connection failed; other probes will handle it
            pass

    
    # ===================================================================== #
    # REPORT HELPERS
    # ===================================================================== #
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return self.auth_issues  # include even status_code==0 crypto issues

    def generate_report(self, fmt: str = "html") -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner="BrokenAuth (API02)", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    def save_report(self, path: str, fmt: str = "html") -> None:
        ReportGenerator(self._filtered_issues(), scanner="Auth+Crypto", base_url=self.base_url).save(path, fmt=fmt)