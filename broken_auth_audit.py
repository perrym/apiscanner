# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
from __future__ import annotations
import base64
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path
import sys
import requests
from urllib.parse import urlparse, urljoin
from tqdm import tqdm
from report_utils import ReportGenerator
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None
try:
    from sslyze import ServerScanRequest, Scanner, ServerScanResult
except ImportError:
    Scanner = None

# Load Swagger spec from CLI argument
def _load_swagger_from_cli() -> dict | None:
    try:
        args = sys.argv
        if '--swagger' in args:
            idx = args.index('--swagger')
            if idx + 1 < len(args):
                p = Path(args[idx + 1]).expanduser().resolve()
                if p.is_file() and p.stat().st_size:
                    with p.open('r', encoding='utf-8') as fh:
                        return json.load(fh)
    except Exception:
        pass
    return None

# Convert headers object to list
def _headers_to_list(hdrs):
    if hasattr(hdrs, 'getlist'):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())

# Try to download remote OpenAPI/Swagger spec
def _load_remote_openapi(base_url: str, sess: requests.Session) -> dict | None:
    candidates = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/swagger/v1/swagger.json']
    for path in candidates:
        try:
            resp = sess.get(urljoin(base_url + '/', path.lstrip('/')), timeout=5, verify=False)
            if resp.status_code == 200 and resp.headers.get('content-type', '').startswith('application/json'):
                return resp.json()
        except requests.RequestException:
            continue
    return None

class AuthAuditor:

    def __init__(self, base_url: str, session: Optional[requests.Session]=None, *, show_progress: bool=True) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.auth_issues: List[Dict[str, Any]] = []
        self.show_progress = show_progress
        self._swagger_get_eps: List[Dict[str, Any]] = []
        self._all_endpoints: List[Dict[str, Any]] = []

    @property
    def _host(self) -> str:
        parsed = urlparse(self.base_url)
        return parsed.hostname or parsed.netloc.split(':')[0]

    @property
    def _port(self) -> int:
        parsed = urlparse(self.base_url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == 'https' else 80

    def _log_issue(self, endpoint: str, description: str, severity: str, request_data: Optional[Dict[str, Any]]=None, response_obj: Optional[requests.Response]=None, extra: Optional[Dict[str, Any]]=None) -> None:
        status_code = getattr(response_obj, 'status_code', 0)
        if response_obj is None and extra is None:
            status_code = 0
        url = getattr(response_obj, 'url', None) or endpoint
        method = (getattr(getattr(response_obj, 'request', None), 'method', None) or (request_data or {}).get('method', 'GET')).upper()
        entry: Dict[str, Any] = {'endpoint': endpoint, 'url': url, 'method': method, 'description': description, 'severity': severity, 'timestamp': datetime.now().isoformat(), 'status_code': status_code, 'request': request_data or {}, 'request_headers': {}, 'request_body': None, 'response_headers': {}, 'response_body': ''}
        if response_obj is not None:
            entry['response_headers'] = _headers_to_list(response_obj.raw.headers)
            entry['response_body'] = response_obj.text[:2048]
            if response_obj.request is not None:
                entry['request_headers'] = _headers_to_list(response_obj.request.headers)
                entry['request_body'] = getattr(response_obj.request, 'body', None)
        if extra:
            entry.update(extra)
        entry['request_cookies'] = self.session.cookies.get_dict()
        if response_obj is not None:
            entry['response_cookies'] = response_obj.cookies.get_dict()
        self.auth_issues.append(entry)

    def test_authentication_mechanisms(self, swagger_endpoints: list[dict] | None=None) -> list[dict]:
        self._all_endpoints = swagger_endpoints or []

        def _norm(items: list[dict]) -> list[dict]:
            out = []
            for ep in items:
                path = ep['path']
                method = ep['method'].upper()
                url = urljoin(self.base_url.rstrip('/') + '/', path.lstrip('/'))
                out.append({'path': path, 'method': method, 'url': url, 'methods': method})
            return out
        norm_eps = _norm(self._all_endpoints)
        self._swagger_get_eps = [ep for ep in norm_eps if ep['method'] == 'GET']
        auth_keywords = ('auth', 'login', 'token', 'signin', 'authenticate', 'oauth', 'saml', 'jwt', 'oidc', 'mfa', '2fa', 'magiclink', 'passwordless', 'sso')
        auth_eps = [{'url': ep['url'], 'methods': ep['methods']} for ep in norm_eps if any((k in ep['path'].lower() for k in auth_keywords))] or [{'url': ep['url'], 'methods': ep['methods']} for ep in norm_eps]
        iterator = tqdm(auth_eps, desc='API2 auth endpoints', unit='endpoint') if self.show_progress else auth_eps
        for ep in iterator:
            method = ep['methods']
            if self.show_progress:
                tqdm.write(f"-> Testing auth endpoint {method} {ep['url']}")
            try:
                self._test_endpoint_auth(ep)
            except Exception as exc:
                self._log_issue(ep['url'], f'Auth test error: {exc}', 'Medium')
        crypto_tests = [self._test_plain_http, self._test_tls_versions, self._test_cipher_suites, self._test_secret_exposure, lambda: self._test_password_hash_strength(self._swagger_get_eps), self._test_self_signed_cert]
        citerator = tqdm(crypto_tests, desc='API2 crypto checks', unit='check') if self.show_progress else crypto_tests
        for test in citerator:
            try:
                test()
            except Exception as e:
                self._log_issue(self.base_url, f"Crypto test failed: {getattr(test, '__name__', str(test))}", 'High', extra={'error_type': 'CryptoTestException', 'details': str(e)})
        return self._filtered_issues()

    def _test_endpoint_auth(self, endpoint: Dict[str, Any]) -> None:
        tests = [self._test_weak_credentials, self._test_token_security, self._test_rate_limiting, self._test_jwt_issues]
        subiter = tqdm(tests, desc='auth subtests', unit='test', leave=False) if self.show_progress else tests
        for t in subiter:
            try:
                t(endpoint)
            except Exception as exc:
                self._log_issue(endpoint['url'], f'Auth sub-test error: {exc}', 'Medium')

    def _test_weak_credentials(self, endpoint: Dict[str, Any]) -> None:
        weak = [('admin', 'admin'), ('user', 'password'), ('test', 'test123'), ('', '')]
        for u, p in weak:
            data = {'username': u, 'password': p}
            try:
                resp = self.session.post(endpoint['url'], json=data, timeout=5)
            except requests.RequestException:
                continue
            if resp.status_code == 200:
                self._log_issue(endpoint['url'], f'Weak creds accepted: {u}/{p}', 'High', data, resp)

    def _test_token_security(self, endpoint: Dict[str, Any]) -> None:
        try:
            valid_resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass'}, timeout=5)
        except requests.RequestException:
            return
        if valid_resp.status_code != 200:
            return
        body = {}
        try:
            body = valid_resp.json()
        except Exception:
            pass
        token = body.get('access_token') or body.get('token') or body.get('jwt')
        if not token:
            return
        try:
            long_resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass', 'expires_in': 999999}, timeout=5)
            if long_resp.status_code == 200:
                self._log_issue(endpoint['url'], 'Tokens can be issued with very long lifetimes', 'Medium', {'expires_in': 999999}, long_resp)
        except requests.RequestException:
            pass
        logout_url = endpoint['url'].replace('login', 'logout')
        try:
            revoke_resp = self.session.post(logout_url, headers={'Authorization': f'Bearer {token}'}, timeout=5)
            if revoke_resp.status_code >= 400:
                self._log_issue(endpoint['url'], 'Tokens appear non-revocable', 'Medium', response_obj=revoke_resp)
        except requests.RequestException:
            pass

    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        allowed = [m.strip().upper() for m in endpoint.get('methods', 'POST').split(',')]
        method = 'POST' if 'POST' in allowed else allowed[0]
        processed = False
        last_resp: Optional[requests.Response] = None
        for i in range(10):
            try:
                last_resp = self.session.request(method, endpoint['url'], json={'username': f'att{i}', 'password': 'bad'}, timeout=5)
            except requests.RequestException:
                continue
            if last_resp.status_code == 429:
                return
            if last_resp.status_code in (404, 405, 501):
                self._log_issue(endpoint['url'], f'Method {method} not allowed - RL test skipped', 'Info', response_obj=last_resp)
                return
            if last_resp.status_code < 500:
                processed = True
        if processed:
            self._log_issue(endpoint['url'], 'No rate-limiting on auth endpoint', 'Medium', response_obj=last_resp)

    def _test_jwt_issues(self, endpoint: Dict[str, Any]) -> None:

        def _b64json(part: str) -> Dict[str, Any]:
            try:
                pad = '=' * (-len(part) % 4)
                return json.loads(base64.urlsafe_b64decode(part + pad))
            except Exception:
                return {}
        try:
            resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass'}, timeout=5)
        except requests.RequestException:
            return
        if resp.status_code != 200:
            return
        try:
            token = resp.json().get('access_token') or resp.json().get('token')
        except Exception:
            token = None
        if not token or token.count('.') != 2:
            return
        header = _b64json(token.split('.')[0])
        alg = (header.get('alg') or '').lower()
        if alg == 'none':
            self._log_issue(endpoint['url'], "JWT uses 'alg:none' - no signature required!", 'Critical', response_obj=resp)
        if len(token) > 10:
            tampered = token[:-5] + 'abcde'
            try:
                check = self.session.get(f'{self.base_url}/api/protected', headers={'Authorization': f'Bearer {tampered}'}, timeout=5)
                if check.status_code == 200:
                    self._log_issue(endpoint['url'], 'JWT signature not validated - tampered token accepted', 'Critical', response_obj=check)
            except requests.RequestException:
                pass
        try:
            payload = _b64json(token.split('.')[1])
            if not payload.get('exp'):
                self._log_issue(endpoint['url'], 'JWT missing expiration claim (exp)', 'Medium', response_obj=resp)
        except Exception:
            pass

    def _run_crypto_suite(self) -> None:
        for test in [self._test_plain_http, self._test_tls_versions, self._test_cipher_suites, self._test_secret_exposure, lambda: self._test_password_hash_strength(self._swagger_get_eps), self._test_self_signed_cert]:
            try:
                test()
            except Exception as e:
                self._log_issue(self.base_url, f"Crypto test failed: {getattr(test, '__name__', str(test))}", 'High', extra={'error_type': 'CryptoTestException', 'details': str(e)})

    def _test_plain_http(self) -> None:
        http_url = 'http://' + self.base_url.split('://', 1)[1]
        if self.base_url.startswith('http://'):
            self._log_issue(http_url, 'Secure transport layer missing - service is only reachable over HTTP', 'High')
            return
        try:
            resp = self.session.get(http_url, timeout=5, allow_redirects=False)
            if resp.status_code < 400 and resp.status_code not in (301, 302, 307, 308):
                self._log_issue(http_url, 'HTTP endpoint reachable without enforced redirect to HTTPS', 'High', response_obj=resp)
        except requests.RequestException:
            pass

    def _test_tls_versions(self) -> None:
        host = self._host
        port = 443
        deprecated_versions = []
        if hasattr(ssl.TLSVersion, 'SSLv2'):
            deprecated_versions.append(('SSLv2', ssl.TLSVersion.SSLv2))
        if hasattr(ssl.TLSVersion, 'SSLv3'):
            deprecated_versions.append(('SSLv3', ssl.TLSVersion.SSLv3))
        deprecated_versions.extend([('TLSv1.0', ssl.TLSVersion.TLSv1), ('TLSv1.1', ssl.TLSVersion.TLSv1_1)])
        for name, version in deprecated_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers('ALL:@SECLEVEL=0')
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        self._log_issue(f'https://{host}:{port}', f'Server accepts deprecated protocol {name}', 'High')
            except ssl.SSLError:
                continue
            except (socket.timeout, OSError):
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
                    name = accepted.cipher_suite.name
                    if 'RC4' in name or 'DES' in name:
                        self._log_issue(self.base_url, f'Weak cipher supported: {name}', 'Medium', extra={'cipher': name})
            except Exception as e:
                self._log_issue(self.base_url, f'Cipher suite analysis failed: {str(e)}', 'Medium')
        except Exception as e:
            self._log_issue(self.base_url, f'SSLyze scan failed: {str(e)}', 'Medium')

    def _test_secret_exposure(self) -> None:
        paths = ['/.env', '/.env.local', '/.env.prod', '/.env.production', '/.docker.env', '/.git/config', '/.git/HEAD', '/.gitignore', '/.gitlab-ci.yml', '/.travis.yml', '/.circleci/config.yml', '/.github/workflows/main.yml', '/config.php', '/wp-config.php', '/config/database.yml', '/config/secrets.yml', '/application.properties', '/application.yml', '/WEB-INF/web.xml', '/local.settings.json', '/Dockerfile', '/docker-compose.yml', '/id_rsa', '/id_dsa', '/.ssh/authorized_keys', '/.aws/credentials', '/.npmrc', '/composer.json', '/composer.lock', '/package.json', '/package-lock.json', '/.pypirc', '/.gradle/gradle.properties', '/db.sqlite3', '/backup.sql', '/dump.sql', '/keys.txt', '/secret.txt']
        token_pattern = re.compile('(-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----|aws_secret_access_key|aws_access_key_id|aws_secret|s3_access_key|s3_secret_key|amazon_aws|azure_client_secret|azure_tenant_id|azure_client_id|azure_storage_account|azure_storage_key|sas_token|subscription_key|accountkey|connectionstring|google_api_key|gcp_service_account|firebase_secret|firebase_database_url|private_token|private_key|access_token|refresh_token|auth_token|bearer|client_secret|consumer_key|consumer_secret|api_key|apikey|secret_key|password)', re.I)
        it = tqdm(paths, desc='secret exposure paths', unit='path', leave=False) if self.show_progress else paths
        for path in it:
            url = urljoin(self.base_url.rstrip('/') + '/', path.lstrip('/'))
            try:
                head = self.session.head(url, allow_redirects=True, timeout=3)
                if head.status_code != 200:
                    continue
                if int(head.headers.get('content-length', '0')) > 2000000:
                    continue
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and token_pattern.search(resp.text):
                    self._log_issue(url, f'Sensitive file {path} exposed', 'High', response_obj=resp)
            except requests.RequestException:
                continue

    def _test_password_hash_strength(self, endpoints: list[dict]) -> None:
        if not endpoints:
            if self.show_progress:
                tqdm.write('[Password-hash check] Skipped - no endpoints provided')
            return
        weak_re = re.compile('^\\$2[aby]\\$|\\$argon2', re.I)
        get_eps = [ep for ep in endpoints if ep.get('method', '').upper() == 'GET']
        it = tqdm(get_eps, desc='password-hash GETs', unit='endpoint', leave=False) if self.show_progress else get_eps
        for ep in it:
            url = urljoin(self.base_url.rstrip('/') + '/', ep['path'].lstrip('/'))
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code != 200:
                    continue
                if 'json' not in r.headers.get('Content-Type', ''):
                    continue
                payload = r.json()
                records = payload if isinstance(payload, list) else [payload]
                for obj in records[:50]:
                    pwd = next((str(v) for k, v in obj.items() if 'password' in k.lower()), None)
                    if pwd and (not weak_re.match(pwd)):
                        self._log_issue(url, 'Weak or unhashed password stored', 'High', response_obj=r, extra={'user': obj.get('id')})
                        break
            except (requests.RequestException, ValueError):
                continue

    def _test_self_signed_cert(self) -> None:
        host = self._host
        port = self._port or 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            with socket.create_connection((host, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    return
        except ssl.SSLCertVerificationError as exc:
            try:
                with socket.create_connection((host, port), timeout=5) as s:
                    with ssl.SSLContext().wrap_socket(s, server_hostname=host) as raw:
                        der = raw.getpeercert(binary_form=True)
            except Exception:
                der = None
            if der and x509:
                cert = x509.load_der_x509_certificate(der, default_backend())
                if cert.issuer == cert.subject:
                    severity = 'High'
                    desc = 'Server presents a self-signed TLS certificate'
                else:
                    severity = 'Medium'
                    desc = 'Server TLS certificate is not trusted by the system store'
            else:
                severity = 'Medium'
                desc = 'Server TLS certificate is not trusted by the system store'
            self._log_issue(f'https://{host}:{port}', desc, severity, extra={'error': str(exc), 'observed_utc': datetime.utcnow().isoformat()})
        except (socket.timeout, OSError):
            pass

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return self.auth_issues

    def generate_report(self, fmt: str='html') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='BrokenAuth (API02)', base_url=self.base_url)
        return gen.generate_html() if fmt == 'html' else gen.generate_markdown()

    def save_report(self, path: str, fmt: str='html') -> None:
        ReportGenerator(self._filtered_issues(), scanner='Auth+Crypto', base_url=self.base_url).save(path, fmt=fmt)
