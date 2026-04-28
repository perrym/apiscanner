########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 4.0 26-04-2026                              #
########################################################                   
from __future__ import annotations
import base64
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from tqdm import tqdm
from report_utils import ReportGenerator
from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig as OASSecurityConfig
try:
    from sslyze import ServerScanRequest, Scanner
except Exception:
    Scanner = None

#================funtion _headers_to_list _headers_to_list =============
def _headers_to_list(h):
    try:
        if hasattr(h, 'getlist'):
            out = []
            for k in h:
                for v in h.getlist(k):
                    out.append((str(k), str(v)))
            return out
        return [(str(k), str(v)) for k, v in (h.items() if hasattr(h, 'items') else [])]
    except Exception:
        return []

class AuthAuditor:

    #================funtion __init__ __init__ =============
    def __init__(self, session: requests.Session, *, base_url: str, swagger_spec: Optional[Dict[str, Any]]=None, show_progress: bool=True, timeout: float=5.0) -> None:
        if session is None:
            raise ValueError('Session is required')
        if not base_url or not isinstance(base_url, str):
            raise ValueError('base_url is required')
        self.session = session
        self.base_url = base_url.rstrip('/') + '/'
        self.spec = swagger_spec or {}
        self.show_progress = show_progress
        self.timeout = timeout
        self.auth_issues: List[Dict[str, Any]] = []
        self._swagger_get_eps: List[Dict[str, Any]] = []

    @property
    #================funtion _host _host =============
    def _host(self) -> str:
        parsed = urlparse(self.base_url)
        return parsed.hostname or parsed.netloc.split(':')[0]

    @property
    #================funtion _port _port =============
    def _port(self) -> int:
        parsed = urlparse(self.base_url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == 'https' else 80

    #================funtion _log_issue _log_issue =============
    def _log_issue(self, endpoint: str, description: str, severity: str, request_data: Optional[Dict[str, Any]]=None, response_obj: Optional[requests.Response]=None, extra: Optional[Dict[str, Any]]=None) -> None:
        status_code = getattr(response_obj, 'status_code', 0)
        url = getattr(response_obj, 'url', None) or endpoint
        method = (getattr(getattr(response_obj, 'request', None), 'method', None) or (request_data or {}).get('method', 'GET')).upper()
        entry: Dict[str, Any] = {'endpoint': endpoint, 'url': url, 'method': method, 'description': description, 'severity': severity, 'timestamp': datetime.utcnow().isoformat(), 'status_code': status_code, 'request': request_data or {}, 'request_headers': {}, 'request_body': None, 'response_headers': {}, 'response_body': ''}
        if response_obj is not None:
            entry['response_headers'] = _headers_to_list(getattr(response_obj, 'headers', {}))
            entry['response_body'] = (response_obj.text or '')[:2048]
            if response_obj.request is not None:
                entry['request_headers'] = _headers_to_list(getattr(response_obj.request, 'headers', {}))
                entry['request_body'] = getattr(response_obj.request, 'body', None)
        if extra:
            entry.update(extra)
        entry['request_cookies'] = getattr(self.session.cookies, 'get_dict', lambda: {})()
        if response_obj is not None:
            entry['response_cookies'] = getattr(response_obj.cookies, 'get_dict', lambda: {})()
        self.auth_issues.append(entry)

    #================funtion _endpoints_from_spec _endpoints_from_spec =============
    def _endpoints_from_spec(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            sec = OASSecurityConfig()
            for op in oas_iter_ops(self.spec or {}):
                req = oas_build_request(self.spec, self.base_url, op, sec)
                url = req['url']
                method = (req['method'] or 'GET').upper()
                path = op.get('path') or url
                tags = op.get('tags') or []
                out.append({'path': path, 'method': method, 'url': url, 'tags': tags})
        except Exception:
            pass
        return out

    #================funtion _select_auth_endpoints _select_auth_endpoints =============
    def _select_auth_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        keys = ('auth', 'login', 'token', 'signin', 'authenticate', 'oauth', 'saml', 'jwt', 'oidc', 'mfa', '2fa', 'magiclink', 'passwordless', 'sso')
        # Exclude action-only endpoints that are not actual login/session mechanisms
        _action_skip = ('forget', 'reset', 'change', 'activate', 'verify', 'confirm', 'revoke', 'refresh')
        eps = []
        for ep in endpoints:
            path = (ep.get('path') or ep.get('url') or '').lower()
            tags = ' '.join(ep.get('tags') or []).lower()
            if any((k in path for k in keys)) or any((k in tags for k in keys)):
                if any(s in path for s in _action_skip):
                    continue  # skip forget-password, reset-password, change-email etc.
                eps.append({'url': ep.get('url') or '', 'method': ep.get('method', 'POST')})
        if not eps:
            for ep in endpoints:
                eps.append({'url': ep.get('url') or '', 'method': ep.get('method', 'POST')})
        return eps

    #================funtion test_authentication_mechanisms test_authentication_mechanisms =============
    def test_authentication_mechanisms(self, swagger_endpoints: Optional[List[Dict[str, Any]]]=None) -> List[Dict[str, Any]]:
        if swagger_endpoints:
            endpoints = []
            for ep in swagger_endpoints:
                path = ep.get('path', '/')
                method = ep.get('method', 'GET').upper()
                url = urljoin(self.base_url, path.lstrip('/'))
                endpoints.append({'path': path, 'method': method, 'url': url, 'tags': []})
        else:
            endpoints = self._endpoints_from_spec()
        norm_eps = [{'url': e['url'], 'method': e.get('method', 'POST')} for e in endpoints if e.get('url')]
        self._swagger_get_eps = [{'path': e.get('path', ''), 'method': e.get('method', 'GET')} for e in endpoints if e.get('method', '').upper() == 'GET']
        auth_eps = self._select_auth_endpoints(endpoints)
        iterator = tqdm(auth_eps, desc='API2 auth endpoints', unit='endpoint') if self.show_progress else auth_eps
        for ep in iterator:
            try:
                self._test_endpoint_auth(ep)
            except Exception as exc:
                self._log_issue(ep['url'], f'Auth test error: {exc}', 'Medium')
        crypto_tests = [self._test_secure_transport, self._test_certificate_validation, self._test_quantum_resistance, self._test_https_ddos_resilience, self._test_secret_exposure, lambda: self._test_password_hash_strength(self._swagger_get_eps)]
        citerator = tqdm(crypto_tests, desc='API2 crypto checks', unit='check') if self.show_progress else crypto_tests
        for test in citerator:
            try:
                test()
            except Exception as e:
                self._log_issue(self.base_url, f"Crypto test failed: {getattr(test, '__name__', str(test))}", 'High', extra={'error_type': 'CryptoTestException', 'details': str(e)})
        return self._filtered_issues()

    #================funtion _test_endpoint_auth _test_endpoint_auth =============
    def _test_endpoint_auth(self, endpoint: Dict[str, Any]) -> None:
        tests = [self._test_weak_credentials, self._test_token_security, self._test_rate_limiting, self._test_jwt_issues]
        subiter = tqdm(tests, desc='auth subtests', unit='test', leave=False) if self.show_progress else tests
        for t in subiter:
            try:
                t(endpoint)
            except Exception as exc:
                self._log_issue(endpoint['url'], f'Auth sub-test error: {exc}', 'Medium')

    #================funtion _test_weak_credentials _test_weak_credentials =============
    def _test_weak_credentials(self, endpoint: Dict[str, Any]) -> None:
        weak = [('admin', 'admin'), ('user', 'password'), ('test', 'test123'), ('', '')]
        for u, p in weak:
            data = {'username': u, 'password': p}
            try:
                resp = self.session.post(endpoint['url'], json=data, timeout=self.timeout)
            except requests.RequestException:
                return  # endpoint unreachable — skip remaining credential attempts
            if resp.status_code == 200:
                self._log_issue(endpoint['url'], f'Weak creds accepted: {u}/{p}', 'High', data, resp)

    #================funtion _test_token_security _test_token_security =============
    def _test_token_security(self, endpoint: Dict[str, Any]) -> None:
        try:
            valid_resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass'}, timeout=self.timeout)
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
            long_resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass', 'expires_in': 999999}, timeout=self.timeout)
            if long_resp.status_code == 200:
                self._log_issue(endpoint['url'], 'Tokens can be issued with very long lifetimes', 'Medium', {'expires_in': 999999}, long_resp)
        except requests.RequestException:
            pass
        logout_url = endpoint['url'].replace('login', 'logout')
        try:
            revoke_resp = self.session.post(logout_url, headers={'Authorization': f'Bearer {token}'}, timeout=self.timeout)
            if revoke_resp.status_code >= 400:
                self._log_issue(endpoint['url'], 'Tokens appear non-revocable', 'Medium', response_obj=revoke_resp)
        except requests.RequestException:
            pass

    #================funtion _test_rate_limiting _test_rate_limiting =============
    def _test_rate_limiting(self, endpoint: Dict[str, Any]) -> None:
        method = endpoint.get('method', 'POST').upper()
        processed = False
        last_resp: Optional[requests.Response] = None
        for i in range(5):  # 5 requests is enough to trigger rate limiting
            try:
                last_resp = self.session.request(method, endpoint['url'], json={'username': f'att{i}', 'password': 'bad'}, timeout=self.timeout)
            except requests.RequestException:
                return  # endpoint unreachable — can't test rate limiting
            if last_resp.status_code == 429:
                return
            if last_resp.status_code in (404, 405, 501):
                self._log_issue(endpoint['url'], f'Method {method} not allowed - RL test skipped', 'Info', response_obj=last_resp)
                return
            if last_resp.status_code < 500:
                processed = True
        if processed:
            self._log_issue(endpoint['url'], 'No rate-limiting on auth endpoint', 'Medium', response_obj=last_resp)

    #================funtion _test_jwt_issues _test_jwt_issues =============
    def _test_jwt_issues(self, endpoint: Dict[str, Any]) -> None:

        def _b64json(part: str) -> Dict[str, Any]:
            try:
                pad = '=' * (-len(part) % 4)
                return json.loads(base64.urlsafe_b64decode(part + pad))
            except Exception:
                return {}
        try:
            resp = self.session.post(endpoint['url'], json={'username': 'test', 'password': 'validpass'}, timeout=self.timeout)
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
                check = self.session.get(urljoin(self.base_url, 'api/protected'), headers={'Authorization': f'Bearer {tampered}'}, timeout=self.timeout)
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

    #================funtion _test_secure_transport _test_secure_transport =============
    def _test_secure_transport(self) -> None:
        if self.base_url.startswith('http://'):
            self._log_issue(self.base_url, 'Service uses HTTP instead of HTTPS', 'Critical')
            return  # no TLS tests for plaintext HTTP target
        http_url = 'http://' + self.base_url.split('://', 1)[1]
        try:
            resp = self.session.get(http_url, timeout=5, allow_redirects=False)
            if resp.status_code < 400 and resp.status_code not in (301, 302, 307, 308):
                self._log_issue(http_url, 'HTTP endpoint reachable without HTTPS redirect', 'High', response_obj=resp)
            elif resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get('Location', '')
                if not location.startswith('https://'):
                    self._log_issue(http_url, f'HTTP redirects to non-HTTPS location: {location}', 'High', response_obj=resp)
        except requests.RequestException:
            pass
        self._test_tls_versions_improved()

    #================funtion _test_tls_versions_improved _test_tls_versions_improved =============
    def _test_tls_versions_improved(self) -> None:
        host = self._host
        port = self._port
        deprecated_protocols = [(ssl.PROTOCOL_SSLv2, 'SSLv2'), (ssl.PROTOCOL_SSLv3, 'SSLv3'), (ssl.PROTOCOL_TLSv1, 'TLSv1.0'), (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1')]
        for protocol, name in deprecated_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        self._log_issue(f'https://{host}:{port}', f'Server accepts deprecated protocol: {name}', 'High', extra={'protocol': name})
            except (ssl.SSLError, socket.timeout, OSError):
                continue

    #================funtion _test_certificate_validation _test_certificate_validation =============
    def _test_certificate_validation(self) -> None:
        host = self._host
        port = self._port
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    if cert and 'notAfter' in cert:
                        not_after = cert['notAfter']
                        exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if exp_date < datetime.utcnow():
                            self._log_issue(self.base_url, 'SSL certificate has expired', 'Critical', extra={'expiration_date': not_after})
                        elif (exp_date - datetime.utcnow()).days < 30:
                            self._log_issue(self.base_url, 'SSL certificate expires soon', 'Medium', extra={'expiration_date': not_after, 'days_remaining': (exp_date - datetime.utcnow()).days})
                    if cert and 'subject' in cert:
                        subject = cert['subject']
                        subject_str = ', '.join([f'{k}={v}' for item in subject for k, v in item])
                        if not any((org in subject_str for org in ['CN=', 'O=', 'OU='])):
                            self._log_issue(self.base_url, 'SSL certificate has incomplete subject information', 'Medium', extra={'subject': subject_str})
        except ssl.SSLCertVerificationError as e:
            self._log_issue(self.base_url, f'SSL certificate validation failed: {str(e)}', 'High', extra={'error_type': 'CertificateValidationError'})
        except Exception as e:
            self._log_issue(self.base_url, f'Certificate check failed: {str(e)}', 'Medium', extra={'error_type': 'CertificateCheckError'})

    #================funtion _test_cipher_suites _test_cipher_suites =============
    def _test_cipher_suites(self) -> None:
        if Scanner is None:
            self._test_cipher_suites_basic()
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
                if hasattr(res.scan_result, 'tls_cipher_suites'):
                    cs = res.scan_result.tls_cipher_suites
                    for accepted in cs.accepted_cipher_suites:
                        name = accepted.cipher_suite.name
                        if any((weak in name for weak in ['RC4', 'DES', '3DES', 'NULL', 'ANON', 'EXPORT'])):
                            self._log_issue(self.base_url, f'Weak cipher supported: {name}', 'Medium', extra={'cipher': name})
            except Exception as e:
                self._log_issue(self.base_url, f'Cipher suite analysis failed: {str(e)}', 'Medium')
        except Exception as e:
            self._log_issue(self.base_url, f'SSLyze scan failed: {str(e)}', 'Medium')

    #================funtion _test_cipher_suites_basic _test_cipher_suites_basic =============
    def _test_cipher_suites_basic(self) -> None:
        host = self._host
        port = self._port
        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'ANON', 'EXPORT', 'MD5', 'RC2']
        try:
            context = ssl.create_default_context()
            context.set_ciphers('DEFAULT')
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        if any((weak in cipher_name for weak in weak_ciphers)):
                            self._log_issue(self.base_url, f'Potentially weak cipher in use: {cipher_name}', 'Medium', extra={'cipher': cipher_name})
        except Exception as e:
            pass

    #================funtion _test_https_ddos_resilience _test_https_ddos_resilience =============
    def _test_https_ddos_resilience(self) -> None:
        """Detect missing protections against HTTPS-based DDoS: HTTP/2 floods and CVE-2023-44487 Rapid Reset."""
        resp = None
        has_rl = False
        has_waf = False
        # Probe root URL for headers (works for both HTTP and HTTPS)
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout, allow_redirects=False)
            hdrs_lower = {k.lower(): v for k, v in resp.headers.items()}
            rl_keys = ('x-ratelimit-limit', 'ratelimit-limit', 'x-rate-limit', 'retry-after', 'x-ratelimit-remaining')
            has_rl = any(h in hdrs_lower for h in rl_keys)
            waf_header_markers = ('cf-ray', 'x-sucuri-id', 'x-cdn', 'x-akamai-edgescape', 'x-amz-cf-id',
                                  'x-azure-ref', 'x-fw-hash', 'x-fastly-request-id', 'x-varnish')
            server = hdrs_lower.get('server', '').lower()
            has_waf = (any(m in hdrs_lower for m in waf_header_markers) or
                       any(cdn in server for cdn in ('cloudflare', 'akamai', 'fastly', 'varnish', 'sucuri')))
            # HSTS missing on HTTPS targets
            if self.base_url.startswith('https://') and 'strict-transport-security' not in hdrs_lower:
                self._log_issue(
                    self.base_url,
                    'Missing Strict-Transport-Security (HSTS) header. Clients may be downgraded to HTTP.',
                    'Medium',
                    response_obj=resp,
                )
        except requests.RequestException:
            pass

        # HTTP/2 and HTTP/3 checks only apply to HTTPS
        if not self.base_url.startswith('https://'):
            return
        host = self._host
        port = self._port

        # Detect HTTP/2 support via ALPN negotiation in TLS handshake
        http2_enabled = False
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    http2_enabled = (ssock.selected_alpn_protocol() == 'h2')
        except (ssl.SSLError, socket.timeout, OSError):
            pass

        # Detect HTTP/3 advertised via Alt-Svc header
        http3_advertised = False
        alt_svc_val = ''
        if resp is not None:
            alt_svc_val = resp.headers.get('Alt-Svc', '')
            http3_advertised = 'h3' in alt_svc_val

        if http2_enabled:
            if not has_waf:
                self._log_issue(
                    f'https://{host}:{port}',
                    'HTTP/2 is enabled without detected WAF/CDN protection. Vulnerable to HTTP/2 Rapid Reset '
                    '(CVE-2023-44487): a single TCP connection can open and cancel thousands of streams per second, '
                    'causing extreme server-side CPU load without triggering classic connection-count limits. '
                    'Attackers use encrypted HTTP/2 to bypass shallow packet-inspection firewalls.',
                    'High',
                    extra={
                        'protocol': 'HTTP/2',
                        'cve': 'CVE-2023-44487',
                        'attack': 'HTTP/2 Rapid Reset flood / HTTPS DDoS',
                        'recommendation': (
                            '1) Deploy WAF or CDN with HTTP/2 flood mitigation (Cloudflare, AWS Shield Advanced, Azure DDoS Protection). '
                            '2) Enforce SETTINGS_MAX_CONCURRENT_STREAMS (recommended: ≤100). '
                            '3) Apply server patches: nginx ≥1.25.3, Apache httpd ≥2.4.58, HAProxy ≥2.9.0. '
                            '4) Rate-limit new TLS sessions per source IP at load-balancer level.'
                        ),
                    },
                )
            elif not has_rl:
                self._log_issue(
                    f'https://{host}:{port}',
                    'HTTP/2 is enabled. A WAF/CDN appears present but no rate-limiting response headers '
                    'were detected. Verify the WAF is configured for HTTP/2 stream-level throttling '
                    '(CVE-2023-44487 Rapid Reset).',
                    'Medium',
                    extra={
                        'protocol': 'HTTP/2',
                        'cve': 'CVE-2023-44487',
                        'recommendation': 'Enable per-IP HTTP/2 stream rate limiting in your WAF/CDN configuration.',
                    },
                )

        if http3_advertised and not has_waf:
            self._log_issue(
                f'https://{host}:{port}',
                'HTTP/3 (QUIC/UDP) is advertised via Alt-Svc without detected WAF protection. '
                'HTTP/3 floods are harder to mitigate than TCP-based attacks because UDP stateless amplification '
                'and QUIC connection multiplexing bypass many traditional DDoS filters. '
                'Ensure your edge supports QUIC-level rate limiting.',
                'Medium',
                extra={
                    'protocol': 'HTTP/3 (QUIC)',
                    'alt_svc': alt_svc_val,
                    'attack': 'QUIC/UDP amplification flood',
                    'recommendation': (
                        'Use a CDN/WAF with native QUIC support and rate limiting. '
                        'Consider disabling HTTP/3 (Alt-Svc: h3) until edge protection is confirmed.'
                    ),
                },
            )

    #================funtion _test_quantum_resistance _test_quantum_resistance =============
    def _test_quantum_resistance(self) -> None:
        """Detect cryptographic algorithms broken by Shor's algorithm on quantum computers."""
        if not self.base_url.startswith('https://'):
            self._log_issue(
                self.base_url,
                'Service uses HTTP – quantum-resistant cryptography cannot be assessed on a plaintext channel',
                'Info',
            )
            return
        host = self._host
        port = self._port
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()           # (name, proto, bits)
                    cert_der = ssock.getpeercert(binary_form=True)
        except (ssl.SSLError, socket.timeout, OSError):
            return

        # ── Key-exchange check ──────────────────────────────────────────────────
        if cipher:
            cname = cipher[0]
            # Static RSA key exchange: no forward secrecy AND fully broken by Shor
            if cname.startswith(('RSA_', 'TLS_RSA_WITH')):
                self._log_issue(
                    f'https://{host}:{port}',
                    f'Cipher suite uses static RSA key exchange (no forward secrecy, quantum-vulnerable): {cname}. '
                    'Shor\'s algorithm can derive the session key from a recorded session.',
                    'Critical',
                    extra={'cipher': cname, 'attack': "Shor's algorithm", 'recommendation': 'Use TLS 1.3 with X25519Kyber768 or ML-KEM hybrid key exchange'},
                )
            elif any(kex in cname for kex in ('ECDHE', 'DHE')):
                # Forward-secret but quantum-vulnerable key exchange
                self._log_issue(
                    f'https://{host}:{port}',
                    f'Key exchange {cname} provides forward secrecy but is broken by Shor\'s algorithm. '
                    'A harvest-now-decrypt-later attack allows future decryption once a cryptographically relevant quantum computer exists.',
                    'Medium',
                    extra={'cipher': cname, 'attack': "Shor's algorithm (harvest-now-decrypt-later)", 'recommendation': 'Deploy post-quantum hybrid key exchange: X25519Kyber768 (NIST ML-KEM / FIPS 203)'},
                )

        # ── Certificate public-key check ────────────────────────────────────────
        if not cert_der:
            return
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec, dsa as _dsa, ed25519 as _ed25519, ed448 as _ed448
            cert = _x509.load_der_x509_certificate(cert_der)
            pub = cert.public_key()
            sig_alg = cert.signature_algorithm_oid.dotted_string

            if isinstance(pub, _rsa.RSAPublicKey):
                bits = pub.key_size
                sev = 'Critical' if bits < 2048 else 'High' if bits < 4096 else 'Medium'
                self._log_issue(
                    f'https://{host}:{port}',
                    f'Certificate uses RSA-{bits} signature key. RSA is fully broken by Shor\'s algorithm; '
                    f'key size {bits} bits offers no additional protection against a quantum adversary.',
                    sev,
                    extra={'key_algorithm': 'RSA', 'key_size': bits, 'sig_oid': sig_alg,
                           'attack': "Shor's algorithm",
                           'recommendation': 'Migrate to ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)'},
                )
            elif isinstance(pub, _ec.EllipticCurvePublicKey):
                curve = pub.curve.name
                self._log_issue(
                    f'https://{host}:{port}',
                    f'Certificate uses ECDSA ({curve}). Elliptic-curve discrete-log is broken by Shor\'s algorithm; '
                    'a harvest-now-decrypt-later attack applies to long-lived certificates.',
                    'Medium',
                    extra={'key_algorithm': 'ECDSA', 'curve': curve, 'sig_oid': sig_alg,
                           'attack': "Shor's algorithm",
                           'recommendation': 'Migrate to ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)'},
                )
            elif isinstance(pub, _dsa.DSAPublicKey):
                self._log_issue(
                    f'https://{host}:{port}',
                    'Certificate uses DSA public key. DSA is fully broken by Shor\'s algorithm.',
                    'High',
                    extra={'key_algorithm': 'DSA', 'sig_oid': sig_alg,
                           'attack': "Shor's algorithm",
                           'recommendation': 'Migrate to ML-DSA (CRYSTALS-Dilithium, FIPS 204)'},
                )
            # Ed25519/Ed448 are quantum-vulnerable too (discrete-log on twisted Edwards curves)
            elif isinstance(pub, (_ed25519.Ed25519PublicKey, _ed448.Ed448PublicKey)):
                alg = 'Ed25519' if isinstance(pub, _ed25519.Ed25519PublicKey) else 'Ed448'
                self._log_issue(
                    f'https://{host}:{port}',
                    f'Certificate uses {alg}. While resistant to classical attacks, {alg} is broken by Shor\'s algorithm on a sufficiently powerful quantum computer.',
                    'Medium',
                    extra={'key_algorithm': alg, 'attack': "Shor's algorithm",
                           'recommendation': 'Migrate to ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)'},
                )
            # else: unknown/PQC key type — no issue logged
        except ImportError:
            pass

    #================funtion _test_secret_exposure _test_secret_exposure =============
    def _test_secret_exposure(self) -> None:
        paths = ['/.env', '/.env.local', '/.git/config', '/.git/HEAD', '/.gitignore', '/.github/workflows/main.yml', '/config.php', '/wp-config.php', '/application.properties', '/application.yml', '/Dockerfile', '/docker-compose.yml', '/id_rsa', '/.ssh/authorized_keys', '/.aws/credentials', '/package.json', '/package-lock.json', '/db.sqlite3', '/backup.sql', '/dump.sql', '/keys.txt', '/secret.txt']
        token_rx = re.compile('(-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----|aws_secret_access_key|aws_access_key_id|azure_client_secret|google_api_key|private_token|private_key|access_token|refresh_token|auth_token|bearer|client_secret|api_key|apikey|secret_key|password)', re.I)
        it = tqdm(paths, desc='secret exposure paths', unit='path', leave=False) if self.show_progress else paths
        for path in it:
            url = urljoin(self.base_url, path.lstrip('/'))
            try:
                head = self.session.head(url, allow_redirects=True, timeout=3)
                if head.status_code != 200:
                    continue
                if int(head.headers.get('content-length', '0')) > 2000000:
                    continue
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and token_rx.search(resp.text or ''):
                    self._log_issue(url, f'Sensitive file {path} exposed', 'High', response_obj=resp)
            except requests.RequestException:
                continue

    #================funtion _test_password_hash_strength _test_password_hash_strength =============
    def _test_password_hash_strength(self, endpoints: List[Dict[str, Any]]) -> None:
        if not endpoints:
            return
        weak_re = re.compile('^\\$2[aby]\\$|\\$argon2', re.I)
        get_eps = [ep for ep in endpoints if ep.get('method', '').upper() == 'GET']
        it = tqdm(get_eps, desc='password-hash GETs', unit='endpoint', leave=False) if self.show_progress else get_eps
        for ep in it:
            url = urljoin(self.base_url, (ep.get('path') or '').lstrip('/'))
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code != 200:
                    continue
                if weak_re.search(r.text or ''):
                    self._log_issue(url, 'Potential password hash exposure or weak hash presence in response', 'High', response_obj=r)
            except requests.RequestException:
                continue

    #================funtion _filtered_issues _filtered_issues =============
    def _filtered_issues(self) -> List[Dict[str, Any]]:
        return [i for i in self.auth_issues if i.get('status_code', 1) != 0 or i.get('severity') in ('High', 'Critical')]

    #================funtion generate_report generate_report =============
    def generate_report(self, fmt: str='markdown') -> str:
        gen = ReportGenerator(self._filtered_issues(), scanner='Broken Authentication (API2)', base_url=self.base_url)
        if fmt == 'markdown':
            return gen.generate_markdown()
        if fmt == 'html':
            return gen.generate_html()
        return gen.generate_html()

    #================funtion save_report save_report =============
    def save_report(self, path: str, fmt: str='markdown') -> None:
        ReportGenerator(self._filtered_issues(), scanner='Broken Authentication (API2)', base_url=self.base_url).save(path, fmt=fmt)
