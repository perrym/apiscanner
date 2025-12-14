########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the MIT License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.1 14-12-2025                               #
########################################################

from __future__ import annotations
import concurrent.futures
import json
import logging
import os
import random
import re
import string
import threading
import itertools
import time
from collections import defaultdict
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import requests
import urllib.parse as urlparse
import urllib3
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry
from report_utils import ReportGenerator
from urllib.parse import urlsplit as _pt_urlsplit, urlunsplit as _pt_urlunsplit
import io
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from colorama import Fore, Style
except ModuleNotFoundError:

    class _No:
        CYAN = GREEN = YELLOW = MAGENTA = RED = RESET_ALL = ''
    Fore = Style = _No()
try:
    from hyper.contrib import HTTP20Adapter
    _HAS_H2 = True
except Exception:
    _HAS_H2 = False
try:
    from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig as OASSecurityConfig
    _HAS_OAS_UNIVERSAL = True
except Exception:
    _HAS_OAS_UNIVERSAL = False

Issue = Dict[str, Any]
SAFE_STATUSES = {400, 401, 403, 404, 405, 422}
WAF_MARKERS = ('cloudflare', 'akamai', 'imperva', 'mod_security', 'aws waf', 'request blocked', 'access denied')
PROBLEM_JSON_CT = 'application/problem+json'
stop_requested = threading.Event()


os.environ.setdefault('APISCAN_MAX_WORKERS', '8')
os.environ.setdefault('APISCAN_TIMEOUT', '5')
os.environ.setdefault('APISCAN_RATE_LIMIT', '0.5')


#================funtion _pt_normalize_url description =============
def _pt_normalize_url(u: str) -> str:
    if '://' not in u:
        u = 'https://' + u.lstrip('/')
    return u


#================funtion build_traversal_variants_segment_replace description =============
def build_traversal_variants_segment_replace(url: str, replace_index: int=-2, max_dot: int=4, max_ddot: int=4, max_ellipsis: int=4) -> list[str]:
    url = _pt_normalize_url(url)
    parts = _pt_urlsplit(url)
    path = parts.path or '/'
    lead = '' if path.startswith('/') else None
    segs = [s for s in path.split('/') if s != '']
    if not segs:
        return []
    idx = replace_index if replace_index >= 0 else len(segs) + replace_index
    if idx < 0 or idx >= len(segs):
        return []


    #================funtion join_segments description =============
    def join_segments(_lead, _segs):
        out = '/'.join(_segs)
        if _lead == '':
            out = '/' + out
        return out or '/'


    #================funtion replace_with description =============
    def replace_with(rep_segment: str, count: int) -> str:
        new_segs = segs[:idx] + [rep_segment] * count + segs[idx + 1:]
        return _pt_urlunsplit((parts.scheme, parts.netloc, join_segments(lead, new_segs), parts.query, parts.fragment))
    variants: list[str] = []
    for n in range(1, max(0, int(max_dot)) + 1):
        v = replace_with('.', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    for n in range(1, max(0, int(max_ddot)) + 1):
        v = replace_with('..', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    for n in range(1, max(0, int(max_ellipsis)) + 1):
        v = replace_with('...', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    seen, out = (set(), [])
    for v in variants:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


#================funtion _encode_siblings description =============
def _encode_siblings(v: str) -> list[str]:
    out: list[str] = []
    out.append(v.replace('.', '%2e'))
    out.append(v.replace('/', '%2f'))
    out.append(v.replace('.', '%2e').replace('/', '%2f'))
    return out


#================funtion build_traversal_variants_insert_between description =============
def build_traversal_variants_insert_between(url: str, insert_before_index: int=-1, max_dot: int=4, max_ddot: int=4, max_ellipsis: int=4) -> list[str]:
    url = _pt_normalize_url(url)
    parts = _pt_urlsplit(url)
    path = parts.path or '/'
    lead = '' if path.startswith('/') else None
    segs = [s for s in path.split('/') if s != '']
    idx = insert_before_index if insert_before_index >= 0 else len(segs) + insert_before_index
    if idx < 0:
        idx = 0
    if idx > len(segs):
        idx = len(segs)


    #================funtion join_segments description =============
    def join_segments(_lead, _segs):
        out = '/'.join(_segs)
        if _lead == '':
            out = '/' + out
        return out or '/'


    #================funtion insert_with description =============
    def insert_with(rep_segment: str, count: int) -> str:
        new_segs = segs[:idx] + [rep_segment] * count + segs[idx:]
        new_path = join_segments(lead, new_segs)
        return _pt_urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
    variants: list[str] = []
    for n in range(1, max(0, int(max_dot)) + 1):
        v = insert_with('.', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    for n in range(1, max(0, int(max_ddot)) + 1):
        v = insert_with('..', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    for n in range(1, max(0, int(max_ellipsis)) + 1):
        v = insert_with('...', n)
        variants.append(v)
        variants.extend(_encode_siblings(v))
    seen, out = (set(), [])
    for v in variants:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


#================funtion listen_for_quit description =============
def listen_for_quit():
    print("Enter 'Q' to stop scanning...")
    while True:
        inp = os.sys.stdin.readline().strip().lower()
        if inp == 'q':
            stop_requested.set()
            print('\n[!] Stop requested - finishing active tasks.\n')
            break
os.environ['APISCAN_ENABLE_CONSOLE_STOP'] = '1'
if os.getenv('APISCAN_ENABLE_CONSOLE_STOP', '0') == '1':
    listener_thread = threading.Thread(target=listen_for_quit, daemon=True)
    listener_thread.start()


#================funtion _headers_to_list description =============
def _headers_to_list(headerobj):
    if hasattr(headerobj, 'getlist'):
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())

class SafeConsumptionAuditor:


    NOSQL_NEGATIVE_PATTERNS = (
        'mongo: no documents in result',
        'no documents in result',
        'document not found',
        'no such document',
    )

    #================funtion _encode_siblings description =============
    def _encode_siblings(self, v: str) -> list[str]:
        out: list[str] = []
        out.append(v.replace('/./', '/.%2f/').replace('./', '.%2f'))
        out.append(v.replace('/../', '/..%2f/').replace('../', '..%2f'))
        out.append(v.replace('/./', '/%2e/').replace('./', '%2e/'))
        out.append(v.replace('/../', '/%2e%2e/').replace('../', '%2e%2e/'))
        out.append(v.replace('/./', '/%252e/').replace('./', '%252e/'))
        out.append(v.replace('/../', '/%252e%252e/').replace('../', '%252e%252e/'))
        return out

    #================funtion _dirtrav_body_vectors description =============
    def _dirtrav_body_vectors(self) -> list[str]:
        base = ['..', '..', '..', '...']
        enc  = ['%2e%2e', '%252e%252e']
        tails = ['etc/passwd', 'WEB-INF/web.xml', 'windows/win.ini']
        out = []
        for t in tails:
            for b in base:
                out.append(f"{b}/{t}")
                out.append(f"{b}\\{t}")
                out.append(f"{b}/./{t}")
                out.append(f"{b}/../{t}")
            for e in enc:
                out.append(f"{e}/%2f{t}")
                out.append(f"{e}%2f{t}")
        out += ['../', '../../', '..\\', '..%2f', '%2e%2e/']
        seen, res = set(), []
        for v in out:
            if v not in seen:
                res.append(v); seen.add(v)
        return res[:64]

    _PATH_FIELD_CANDIDATES = (
        'file','filename','filepath','path','dir','directory','folder',
        'template','include','page','report','export','backup','log','config','resource'
    )


    #================funtion _test_directory_traversal description =============
    def _test_directory_traversal(self, ep: str) -> None:
        url = ep if ep.startswith("http") else f"{self.base_url}{ep}"

        vectors = [
            "../", "..%2f", "%2e%2e%2f", "..%2F", "..;/", "..\\", "..%5c", "%2e%2e%5c"
        ]
        targets = [
            ("/etc/passwd", ["root:x:0:0:", "/bin/"]),
            ("/etc/hosts",  ["127.0.0.1", "localhost"]),
            ("/proc/self/environ", ["PATH="]),
            ("C:\\Windows\\win.ini", ["[fonts]", "[extensions]"]),
            ("WEB-INF/web.xml", ["<web-app", "<servlet>"]),
        ]

        #================funtion strong_hit description =============
        def strong_hit(body: str) -> bool:
            low = (body or "").lower()
            return any(sig in low for sig in (
                "root:x:0:0:", "daemon:x:1:1:", "localhost", "path=",
                "[extensions]", "[fonts]", "<web-app"
            ))

        #================funtion dirlist_hit description =============
        def dirlist_hit(body: str) -> bool:
            low = (body or "").lower()
            return any(sig in low for sig in (
                "index of /", "parent directory", "<title>index of", "directory listing for"
            ))

        traversal_tokens = (
            "../", "..\\",
            "%2e%2e", "%2e%2e%2f", "%2e%2e%5c",
            "..%2f", "..%5c",
            "%2f..", "%5c.."
        )


        for vec in vectors:
            for tgt, sigs in targets:
                u = f"{url}/{vec}{{postId}}{tgt}"
                try:
                    r = self.session.get(u, timeout=self.timeout, allow_redirects=False)
                    body = r.text or ""


                    if strong_hit(body) or any(s.lower() in body.lower() for s in sigs):
                        self._log("Directory Traversal (suffix)", f"Markers for {tgt} detected.", "High", u, response=r,
                                extra={"vector": "dirtrav", "base_endpoint": url})
                        return
                    if dirlist_hit(body):
                        self._log("Potential Directory Listing (suffix)", "Directory listing patterns detected.", "Medium", u, response=r,
                                extra={"vector": "dirtrav", "base_endpoint": url})
                        return


                    if r.status_code in (301, 302, 307, 308):
                        loc = (r.headers.get("Location") or "").lower()
                        if any(t in loc for t in traversal_tokens):
                            self._log(f"Directory traversal (suffix) - suspicious redirect [{r.status_code}]",
                                    u, "Medium", payload=u, response=r,
                                    extra={"vector": "dirtrav", "base_endpoint": url, "location": loc})

                except Exception:
                    pass


        for vec in vectors:
            for tgt, sigs in targets:
                u2 = f"{url}/{vec}{tgt}"
                try:
                    r = self.session.get(u2, timeout=self.timeout, allow_redirects=False)
                    body = r.text or ""

                    if strong_hit(body) or any(s.lower() in body.lower() for s in sigs):
                        self._log("Directory Traversal (path)", f"Markers for {tgt} detected in path.", "High", u2, response=r,
                                extra={"vector": "dirtrav", "base_endpoint": url})
                        return
                    if dirlist_hit(body):
                        self._log("Potential Directory Listing (path)", "Directory listing patterns detected.", "Medium", u2, response=r,
                                extra={"vector": "dirtrav", "base_endpoint": url})
                        return

                    if r.status_code in (301, 302, 307, 308):
                        loc = (r.headers.get("Location") or "").lower()
                        if any(t in loc for t in traversal_tokens):
                            self._log(f"Directory traversal (path) - suspicious redirect [{r.status_code}]",
                                    u2, "Medium", payload=u2, response=r,
                                    extra={"vector": "dirtrav", "base_endpoint": url, "location": loc})
                except Exception:
                    pass


    @staticmethod

    #================funtion endpoints_from_swagger_with_methods description =============
    def endpoints_from_swagger_with_methods(swagger_path: str):


        from pathlib import Path
        import json

        raw = Path(swagger_path).read_text(encoding="utf-8")
        spec = json.loads(raw)

        servers = []
        for srv in (spec.get("servers") or []):
            u = (srv.get("url") or "").strip()
            if not u:
                continue

            if u.endswith("/"):
                u = u[:-1]
            servers.append(u)

        paths = spec.get("paths") or {}
        out = []
        for path, ops in paths.items():
            if not isinstance(ops, dict):
                continue

            if not path.startswith("/"):
                path = "/" + path
            for method, op in ops.items():
                m = (method or "").upper()
                if m not in ("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"):
                    continue
                if servers:
                    for s in servers:
                        out.append((f"{s}{path}", m))
                else:

                    out.append((path, m))
        return out


    @staticmethod

    #================funtion endpoints_from_swagger description =============
    def endpoints_from_swagger(swagger_path: str):


        pairs = SafeConsumptionAuditor.endpoints_from_swagger_with_methods(swagger_path)
        urls = []
        seen = set()
        for url, _m in pairs:
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls


    #================funtion _looks_interesting_body description =============
    def _looks_interesting_body(self, text: str) -> tuple[bool, str]:
        if not text: return (False, 'none')
        low = text.lower()
        strong = (
            'root:x:0:0:', 'daemon:x:1:1:', 'index of /', '<title>index of',
            'parent directory', 'directory listing for', 'directory of ',
            '[extensions]', 'for 16-bit app support'
        )
        weak = ('/etc/passwd', 'bin:x:', 'boot.ini', ':\\windows\\', 'web-inf/web.xml')
        for s in strong:
            if s in low: return (True, 'high')
        import re as _re
        wc = sum(1 for w in weak if w in low)
        if wc >= 2: return (True, 'medium')
        if wc == 1:
            has_links = any(t in low for t in ('<a href="','&lt;a href=','href="','>../<','>..</a>'))
            has_sizes = _re.search(r'\b\d+\s*(bytes?|kb|mb|gb)\b', low)
            if has_links or has_sizes: return (True, 'medium')
        return (False, 'none')


    #================funtion _likely_fp_body description =============
    def _likely_fp_body(self, resp, body_text: str) -> bool:
        if not resp: return False
        ctype = (resp.headers.get('Content-Type') or '').lower()
        low = (body_text or '').lower()
        if resp.status_code in (401,403) and any(t in low for t in ('invalid token','unauthorized','authentication','forbidden')):
            return True
        if 'application/json' in ctype and resp.status_code >= 400:
            return True
        if ctype.startswith(('image/','video/','audio/')) or 'application/octet-stream' in ctype:
            return True
        return False


    #================funtion _body_candidates_json description =============
    def _body_candidates_json(self, base_obj: dict):
        out = []
        vecs = self._dirtrav_body_vectors()
        keys = list(base_obj.keys())
        target_keys = [k for k in keys if k.lower() in self._PATH_FIELD_CANDIDATES or any(p in k.lower() for p in self._PATH_FIELD_CANDIDATES)]
        if not target_keys: target_keys = keys
        cap = 6
        import json as _json
        for k in target_keys[:6]:
            for v in vecs[:cap]:
                obj = dict(base_obj); obj[k] = v
                out.append(('application/json', _json.dumps(obj).encode('utf-8'), f'json:{k}'))
        return out[:24]


    #================funtion _body_candidates_form description =============
    def _body_candidates_form(self, base_map: dict):
        out = []
        vecs = self._dirtrav_body_vectors()
        keys = list(base_map.keys())
        target = [k for k in keys if k.lower() in self._PATH_FIELD_CANDIDATES or any(p in k.lower() for p in self._PATH_FIELD_CANDIDATES)]
        if not target: target = keys
        cap = 6
        for k in target[:6]:
            for v in vecs[:cap]:
                m = dict(base_map); m[k] = v
                out.append(('application/x-www-form-urlencoded', m, f'form:{k}'))
        return out[:24]


    #================funtion _body_candidates_multipart description =============
    def _body_candidates_multipart(self):
        out = []
        vecs = self._dirtrav_body_vectors()
        for v in vecs[:8]:
            files = {'file': (v, io.BytesIO(b'test'), 'application/octet-stream')}
            data = {'path': v}
            out.append(('multipart/form-data', (data, files), f'multipart:filename'))
        return out


    #================funtion _build_default_json description =============
    def _build_default_json(self):
        return {'path':'/tmp/a', 'file':'a.txt', 'name':'x'}


    #================funtion _build_default_form description =============
    def _build_default_form(self):
        return {'path':'/tmp/a', 'file':'a.txt'}


    #================funtion _classify_and_log_body description =============
    def _classify_and_log_body(self, endpoint, label, r, body_text, confidence):
        ctype = (r.headers.get('Content-Type') or '').lower()
        is_binary = ctype.startswith(('image/', 'video/', 'audio/')) or 'application/octet-stream' in ctype
        if is_binary:
            return

        if r.status_code == 200:
            sev = 'High' if confidence == 'high' else ('Medium' if confidence == 'medium' else 'Low')
            self._log(
                f'Directory traversal (body:{label}) [{r.status_code}]',
                endpoint,
                sev,
                payload=getattr(self, '_last_payload', f'body:{label}'),
                response=r,
                extra={'vector': 'dirtrav-body', 'confidence': confidence}
            )
            return

        if r.status_code in (301, 302, 307, 308):
            loc = (r.headers.get('Location') or '').lower()


            traversal_tokens = (
                "../", "..\\",
                "%2e%2e", "%2e%2e%2f", "%2e%2e%5c",
                "..%2f", "..%5c",
                "%2f..", "%5c..",
                "%252e%252e", "%252e%252e%252f", "%252e%252e%255c",
            )

            if any(t in loc for t in traversal_tokens):
                self._log(
                    f'Directory traversal (body:{label}) - suspicious redirect [{r.status_code}]',
                    endpoint,
                    'Medium',
                    payload=getattr(self, '_last_payload', f'body:{label}'),
                    response=r,
                    extra={'vector': 'dirtrav-body', 'location': loc}
                )
            return

        if r.status_code in (401, 403) and confidence == 'high':
            self._log(
                f'Directory traversal (body:{label}) [{r.status_code}]',
                endpoint,
                'Low',
                payload=getattr(self, '_last_payload', f'body:{label}'),
                response=r,
                extra={'vector': 'dirtrav-body', 'confidence': confidence}
            )
            return


    #================funtion _test_directory_traversal_body description =============
    def _test_directory_traversal_body(self, endpoint: str, method: str = 'POST') -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            vectors = []


            allowed = set()
            try:
                self._throttle(domain)
                opt = self.session.request('OPTIONS', endpoint, timeout=(2, 3), allow_redirects=False)
                allowed = {m.strip().upper() for m in (opt.headers.get('Allow') or '').split(',') if m}
            except Exception:
                pass
            cand_methods = [m for m in (method.upper(), 'POST', 'PUT', 'PATCH') if m]
            if allowed:
                c2 = [m for m in cand_methods if m in allowed]
                cand_methods = c2 or cand_methods

            base_json = self._build_default_json()
            vectors += self._body_candidates_json(base_json)

            base_form = self._build_default_form()
            vectors += self._body_candidates_form(base_form)

            vectors += self._body_candidates_multipart()

            if getattr(self, 'fast_mode', False):
                vectors = vectors[:16]

            #================funtion do_req description =============
            def do_req(entry):
                ctype, payload, label = entry
                try:
                    self._throttle(domain)
                except Exception:
                    pass
                hdrs = dict(getattr(self.session, 'headers', {}))
                hdrs['X-APISCAN-Payload'] = f'body:{label}'
                self._last_payload = f'body:{label}'

                m = cand_methods[0] if cand_methods else method.upper()

                if ctype == 'application/json':
                    r = self.session.request(m, endpoint, headers={**hdrs, 'Content-Type': 'application/json'},
                                             data=payload, timeout=(3, getattr(self,'timeout',10)), allow_redirects=False)
                elif ctype == 'application/x-www-form-urlencoded':
                    r = self.session.request(m, endpoint, headers=hdrs, data=payload,
                                             timeout=(3, getattr(self,'timeout',10)), allow_redirects=False)
                else:
                    data, files = payload
                    r = self.session.request(m, endpoint, headers=hdrs, data=data, files=files,
                                             timeout=(3, getattr(self,'timeout',10)), allow_redirects=False)

                body_text = r.text or ''
                if self._likely_fp_body(r, body_text):
                    return
                interesting, conf = self._looks_interesting_body(body_text)
                if interesting:
                    self._classify_and_log_body(endpoint, label, r, body_text, conf)

            workers = min(8, max(1, len(vectors)))
            import concurrent.futures as _cf
            with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = []
                for v in vectors:
                    if stop_requested.is_set():
                        break
                    futs.append(ex.submit(do_req, v))
                for f in _cf.as_completed(futs):
                    try: f.result()
                    except Exception: pass

        except Exception as e:
            self._log('Directory traversal (body) setup failed', endpoint, 'Info',
                      extra={'error': str(e), 'vector':'dirtrav-body'})

    @staticmethod


    #================funtion endpoints_from_openapi_universal description =============
    def endpoints_from_openapi_universal(spec: dict, base_url: str, sec_cfg: 'OASSecurityConfig | None'=None) -> list[str]:
        if not globals().get('_HAS_OAS_UNIVERSAL', False):
            raise RuntimeError('openapi_universal is not available')
        eps: set[str] = set()
        for op in oas_iter_ops(spec):
            try:
                req = oas_build_request(spec, base_url, op, sec_cfg)
                url = req.get('url')
                if isinstance(url, str) and url:
                    eps.add(url.rstrip('/'))
            except Exception:
                continue
        return sorted(eps)


    #================funtion scan_openapi_universal description =============
    def scan_openapi_universal(self, spec: dict, base_url: str, sec_cfg: 'OASSecurityConfig | None'=None) -> list[dict]:
        endpoints = self.endpoints_from_openapi_universal(spec, base_url, sec_cfg)
        return self.test_endpoints(endpoints)
    SQL_ENGINE_MARKERS = {'sqlsyntaxerror', 'psql:', 'psycopg2', 'org.hibernate', 'mysql server version', 'sqlite error', 'sqlserverexception', 'odbc sql', 'syntax error at or near', 'unclosed quotation mark', 'ora-', 'pls-', 'ora-00933', 'ora-01756'}
    NOSQL_ENGINE_MARKERS = {'mongoerror', 'bson', 'cast to objectid', 'pymongo.errors', 'elasticsearch_exception'}
    SSTI_MARKERS = {'jinja2.exceptions', 'freemarker.core', 'mustache', 'thymeleaf'}
    LDAP_ERROR_KEYWORDS = {'ldaperror', 'invalid dn', 'bad search filter', 'unbalanced parenthesis', 'javax.naming.directory'}
    XXE_ERROR_KEYWORDS = {'entity not defined', 'saxparseexception', 'xerces', 'external entity', 'disallow-doctype', 'dtd is prohibited', 'doctype is not allowed'}
    STACKTRACE_MARKERS = {'traceback (most recent call last)', 'java.lang.', 'nullpointerexception', 'indexerror', 'keyerror'}
    JSON_PARSE_ERRORS = {'invalid character', 'unexpected token', 'json parse error', 'malformed json', 'no json object could be decoded', 'cannot deserialize instance of', 'body contains invalid json'}
    WAF_PATTERNS = {'access denied', 'request blocked', 'akamai ghost', 'mod_security', 'cloudflare', 'your request was blocked', 'bot protection', 'forbidden by rule'}
    IGNORE_NETWORK_TIMEOUTS = True
    NETWORK_TIMEOUT_PATTERNS = ('httpconnectionpool', 'read timed out', 'connect timeout', 'connecttimeout', 'write timeout', 'newconnectionerror', 'failed to establish a new connection', 'max retries exceeded', 'temporarily unavailable')
    GENERIC_4XX = {400, 401, 403, 404, 405, 406, 409, 415, 422, 429}


    #================funtion __init__ description =============
    def __init__(self, base_url: str, session: Optional[requests.Session]=None, *, timeout: Optional[int]=None, rate_limit: Optional[float]=None, log_monitor: Optional[Callable[[Dict[str, Any]], None]]=None) -> None:
        self.timeout = timeout if timeout is not None else int(os.getenv('APISCAN_TIMEOUT', '3'))
        self.rate_limit = rate_limit if rate_limit is not None else float(os.getenv('APISCAN_RATE_LIMIT', '1.0'))
        default_max_workers = min(32, max(8, (os.cpu_count() or 1) * 4))
        self.max_workers = int(os.getenv('APISCAN_MAX_WORKERS', str(default_max_workers)))
        self.base_url: str = base_url.rstrip('/')
        self.session: requests.Session = session or self._create_secure_session()
        self.log_monitor = log_monitor
        self.server_log_provider: Optional[Callable[[], List[str]]] = None
        self.fast_mode = os.getenv('APISCAN_FAST', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.triage_payloads_per_type = 2
        self.per_host_max_concurrency = int(os.getenv('APISCAN_PER_HOST', '8'))
        self.host_semaphores: defaultdict[str, threading.BoundedSemaphore] = defaultdict(lambda: threading.BoundedSemaphore(self.per_host_max_concurrency))
        self.last_request_ts: defaultdict[str, float] = defaultdict(lambda: 0.0)
        self.issues: List[Dict[str, Any]] = []
        self.issues_lock = threading.Lock()
        self.canary_domain: str = os.getenv('APISCAN_CANARY', '').strip('.')
        json_path = Path(__file__).parent / 'data' / 'injection_payloads.json'
        if not json_path.exists():
            print(f'Error: {json_path} not found. Module cannot continue.')
            os.sys.exit(1)
        try:
            with json_path.open('r', encoding='utf-8') as f:
                payloads_data = json.load(f)
            self.INJECTION_PAYLOADS = payloads_data['injection_payloads']
            self.CRLF_PAYLOADS = payloads_data['crlf_payloads']
            self.HPP_PARAMS = payloads_data['hpp_params']
            self.SSRF_PAYLOADS = payloads_data['ssrf_payloads']
            self.NOSQL_ERROR_KEYWORDS = payloads_data['nosql_error_keywords']
            self.SQL_ERROR_KEYWORDS = payloads_data['sql_error_keywords']
            self.SQL_ERROR_REGEX = payloads_data['sql_error_regex']
            self.GRAPHQL_INTROSPECTION_QUERY = payloads_data['graphql_introspection_query']
            self.SQL_ERROR_RX = [re.compile(p, re.I) for p in self.SQL_ERROR_REGEX]
            self.DIR_TRAVERSAL_PAYLOADS = payloads_data.get('directory_traversal_payloads', [])
            self.DIR_TRAVERSAL_FILES = payloads_data.get('directory_traversal_files', [])
        except (KeyError, json.JSONDecodeError) as e:
            print(f'Error parsing JSON payload file: {e}')
            os.sys.exit(1)
        print(f'[INIT] Auditor ready for {self.base_url} (timeout={self.timeout}s, rate_limit={self.rate_limit}s, max_workers={self.max_workers}, per_host={self.per_host_max_concurrency})')

    @staticmethod

    #================funtion _create_secure_session description =============
    def _create_secure_session() -> requests.Session:
        s = requests.Session()
        retries = Retry(total=2, connect=2, read=2, backoff_factor=0.2, status_forcelist=[500, 502, 503], allowed_methods=['HEAD', 'GET', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH'], raise_on_status=False, raise_on_redirect=False)
        adapter = HTTPAdapter(max_retries=retries, pool_connections=200, pool_maxsize=200, pool_block=True)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        use_http2 = os.getenv('APISCAN_HTTP2', '0') == '1' or bool(globals().get('APISCAN_HTTP2', 0))
        if use_http2:
            try:
                from hyper.contrib import HTTP20Adapter
                s.mount('https://', HTTP20Adapter())
            except Exception:
                pass
        s.headers.update({'User-Agent': 'safe_consumption10/10', 'Accept': 'application/json, */*;q=0.1', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive'})
        return s


    #================funtion _throttle description =============
    def _throttle(self, domain: str) -> None:
        sem = self.host_semaphores[domain]
        sem.acquire()
        try:
            now = time.perf_counter()
            delta = now - self.last_request_ts[domain]
            if delta < self.rate_limit:
                time.sleep(self.rate_limit - delta)
            self.last_request_ts[domain] = time.perf_counter()
        finally:
            sem.release()

    @staticmethod

    #================funtion _safe_body description =============
    def _safe_body(data: Any) -> str:
        if data is None:
            return ''
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8', 'replace')
            except Exception:
                return f'<<{len(data)} bytes>>'
        return str(data)


    #================funtion _log description =============
    def _log(self, issue: str, target: str, severity: str, *, payload=None, response=None, extra=None) -> None:
        if extra and getattr(self, 'IGNORE_NETWORK_TIMEOUTS', True):
            err_low = str(extra.get('error', '')).lower()
            for p in getattr(self, 'NETWORK_TIMEOUT_PATTERNS', ('timeout', 'timed out', 'read timed out', 'connect timeout')):
                if p in err_low:
                    return
        skip_markers = ('failed to parse', "name 'parsed' is not defined")
        chk = [issue]
        if extra and 'error' in extra:
            chk.append(str(extra['error']))
        for f in chk:
            low = str(f).lower()
            if any((k in low for k in skip_markers)):
                return

        #================funtion _is_binary_response description =============
        def _is_binary_response(resp) -> bool:
            try:
                ctype = (resp.headers.get('Content-Type') or '').lower()
            except Exception:
                ctype = ''
            if ctype.startswith(('image/', 'audio/', 'video/')):
                return True
            if any((x in ctype for x in ('application/pdf', 'application/octet-stream', 'application/zip', 'application/gzip'))):
                return True
            disp = (resp.headers.get('Content-Disposition') or '').lower()
            if 'filename=' in disp and disp.endswith(('.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.gz')):
                return True
            data = getattr(resp, 'content', b'') or b''
            if not data:
                return False
            sample = data[:1024]
            printable = sum((32 <= b < 127 or b in (9, 10, 13) for b in sample))
            return printable / max(1, len(sample)) < 0.8
        if response is not None:
            low_issue = (issue or '').lower()
            if ('sql injection' in low_issue or 'sqli' in low_issue) and _is_binary_response(response):
                if os.getenv('APISCAN_IGNORE_BINARY_SUSPECTS', '1').strip().lower() in ('1', 'true', 'yes', 'on'):
                    return
                else:
                    severity = 'Info'
                    if not extra:
                        extra = {}
                    extra['note'] = 'Downgraded: binary response (image/pdf/zip)'
        entry = {'issue': issue, 'description': issue, 'severity': severity, 'target': target, 'payload': payload if payload is not None else '', 'status_code': response.status_code if response is not None else '-'}
        if extra:
            entry.update(extra)
        try:
            import urllib.parse as urlparse
            if response is not None and getattr(response, 'request', None) is not None:
                req = response.request
                full_url = getattr(req, 'url', target) or target
                parsed = urlparse.urlparse(full_url)
                entry.update(method=req.method or 'GET', url=full_url, endpoint=parsed.path or '/', request_headers=dict(getattr(req, 'headers', {}) or {}), response_headers=dict(response.headers or {}), request_cookies=getattr(response, 'cookies', {}).get_dict() if hasattr(response, 'cookies') else {}, response_cookies=response.cookies.get_dict() if hasattr(response, 'cookies') else {})
                try:
                    rb = getattr(req, 'body', b'')
                    entry['request_body'] = self._safe_body(rb)[:20000]
                except Exception:
                    entry['request_body'] = ''
                try:
                    ct = (response.headers.get('Content-Type') or '').lower()
                    if not self._is_generic_html_error(response) and (not ct.startswith(('image/', 'video/', 'audio/'))) and ('application/octet-stream' not in ct):
                        entry['response_body'] = (response.text or '')[:20000]
                        entry['response_body_len'] = len(response.text or '')
                    else:
                        raw = getattr(response, 'content', b'') or b''
                        entry['response_body'] = f'<<binary {len(raw)} bytes>>'
                        entry['response_body_len'] = len(raw)
                    entry['response_content_type'] = ct
                except Exception:
                    pass
            else:
                entry.setdefault('url', target)
                entry.setdefault('endpoint', urlparse.urlparse(target).path or '/')
        except Exception as e:
            entry['parse_error'] = str(e)
            entry.setdefault('url', target)
            entry.setdefault('endpoint', urlparse.urlparse(target).path or '/')
        if entry.get('status_code') == '-' or 'timeout' in str(entry.get('error', '')).lower():
            entry['severity'] = 'Info'
        with self.issues_lock:
            self.issues.append(entry)
        if getattr(self, 'log_monitor', None):
            try:
                self.log_monitor(entry)
            except Exception:
                pass
        try:
            if str(entry.get('severity', '')).lower() != 'info':
                print(f"[{entry['severity']}] {entry.get('issue', '')} @ {entry.get('url', '')}")
        except Exception:
            pass


    #================funtion _has_engine_marker description =============
    def _has_engine_marker(self, text: str, attack_type: str) -> bool:
        t = text.lower()
        if attack_type == 'sql':
            return any((k in t for k in self.SQL_ENGINE_MARKERS | self.STACKTRACE_MARKERS))
        if attack_type == 'nosql':
            return any((k in t for k in self.NOSQL_ENGINE_MARKERS | self.STACKTRACE_MARKERS))
        if attack_type == 'ssti':
            return any((k in t for k in self.SSTI_MARKERS | self.STACKTRACE_MARKERS))
        if attack_type == 'ldap':
            return any((k in t for k in self.LDAP_ERROR_KEYWORDS | self.STACKTRACE_MARKERS))
        if attack_type == 'xxe':
            return any((k in t for k in self.XXE_ERROR_KEYWORDS | self.STACKTRACE_MARKERS))
        return False


    #================funtion _is_parse_error description =============
    def _is_parse_error(self, response: requests.Response) -> bool:
        try:
            ctype = (response.headers.get('Content-Type') or '').lower()
        except Exception:
            ctype = ''
        body = (response.text or '').lower()
        return any((p in body for p in self.JSON_PARSE_ERRORS)) or ('application/json' in ctype and response.status_code == 400)


    #================funtion _looks_like_waf description =============
    def _looks_like_waf(self, response: requests.Response) -> bool:
        body = (response.text or '').lower()
        return response.status_code in {403, 406, 429} or any((p in body for p in self.WAF_PATTERNS))


    #================funtion _is_generic_html_error description =============
    def _is_generic_html_error(self, response) -> bool:
        try:
            status = int(getattr(response, 'status_code', 0))
        except Exception:
            status = 0
        try:
            ctype = (response.headers.get('Content-Type') or '').lower()
        except Exception:
            ctype = ''
        body = getattr(response, 'text', '') or ''
        head = body.strip()[:200].lower()
        title_low = ''
        try:
            import re as _re
            m = _re.search('<title>([^<]+)</title>', body, _re.I)
            title_low = (m.group(1) if m else '').strip().lower()
        except Exception:
            title_low = ''
        looks_html = 'text/html' in ctype or head.startswith('<!doctype html') or head.startswith('<html')
        looks_error = 'error' in title_low or 'server error' in head or 'internal server error' in head
        return status >= 500 and looks_html and looks_error


    #================funtion _payload_reflected description =============
    def _payload_reflected(self, payload: str, response_text: str) -> bool:
        if not payload:
            return False
        t = (response_text or '').lower()
        from urllib.parse import quote
        variants = {payload.lower(), quote(payload).lower(), quote(payload, safe='').lower()}
        return any((v in t for v in variants))


    #================funtion classify_transport_anomaly description =============
    def classify_transport_anomaly(self, url: str, method: str, exc: Exception | None, elapsed: float) -> str:
        e = (str(exc) if exc else '').lower()
        if 'hpe_invalid' in e or 'invalid chunk size' in e or 'http/1.1 400 bad request' in e:
            return 'Medium'
        if elapsed > 8.0 and (not e):
            return 'Info'
        return 'Info'


    #================funtion _dedupe_issues description =============
    def _dedupe_issues(self) -> None:

            #================funtion _canon description =============
            def _canon(f: dict) -> tuple:
                issue = (f.get('issue') or '').lower()
                desc = (f.get('description') or '').lower()
                method = f.get('method') or 'GET'
                path = f.get('path') or f.get('endpoint') or f.get('url') or ''
                status = f.get('status_code')
                payload = f.get('payload') or ''
                vector = (f.get('vector') or '').lower()
                if vector == 'generic-5xx' or 'server error without sql evidence' in issue or 'generic 5xx response without sql/db markers' in desc:
                    return ('generic-5xx', method, path, status)
                if vector == 'dirtrav' or issue.startswith('directory traversal'):
                    base_ep = f.get('base_endpoint') or path
                    sev = f.get('severity')
                    return ('dirtrav', method, base_ep, sev)
                if vector == 'cors' or issue == 'Broad CORS policy':
                    return ('cors', method, path, 200)
                return ('default', method, path, status, (f.get('issue') or ''), payload)

            merged: dict[tuple, dict] = {}
            for f in self.issues:
                k = _canon(f)
                cur = merged.get(k)
                if cur is None:
                    f['duplicates'] = 0

                    if (f.get('vector') or '').lower() == 'dirtrav':
                        f['evidence_urls'] = [f.get('url') or f.get('endpoint')]
                    elif (f.get('vector') or '').lower() == 'cors':
                        f['evidence_origins'] = [f.get('origin')] if f.get('origin') else []
                    elif (f.get('vector') or '').lower() == 'generic-5xx':
                        f['evidence_payloads'] = [f.get('payload')] if f.get('payload') else []
                    merged[k] = f
                else:
                    cur['duplicates'] = int(cur.get('duplicates', 0)) + 1

                    v = (f.get('vector') or '').lower()
                    if v == 'dirtrav':
                        urls = cur.setdefault('evidence_urls', [])
                        u = f.get('url') or f.get('endpoint')
                        if u and u not in urls and len(urls) < 10:
                            urls.append(u)
                    elif v == 'cors':
                        origins = cur.setdefault('evidence_origins', [])
                        o = f.get('origin')
                        if o and o not in origins and len(origins) < 10:
                            origins.append(o)
                    elif v == 'generic-5xx':
                        payloads = cur.setdefault('evidence_payloads', [])
                        pld = f.get('payload')
                        if pld and pld not in payloads and len(payloads) < 10:
                            payloads.append(pld)
            self.issues = list(merged.values())


    #================funtion _dump_raw_issues description =============
    def _dump_raw_issues(self, log_dir: Path) -> Path:
        import json as _json
        import datetime as _dt
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.utcnow().isoformat(timespec='seconds').replace(':', '-')
        path = log_dir / f'unsafe_raw_{ts}.json'
        with path.open('w', encoding='utf-8') as fh:
            _json.dump(self.issues, fh, indent=2, ensure_ascii=False)
        print(f'[LOG] Full issue log written to {path}')
        return path

    @staticmethod


    #================funtion third_party_hosts_from_swagger description =============
    def third_party_hosts_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding='utf-8'))
        hosts: Set[str] = set()
        for srv in spec.get('servers', []):
            url = srv.get('url')
            if url:
                parsed = urlparse.urlparse(url)
                if parsed.netloc:
                    hosts.add(parsed.netloc.split(':')[0])


        #================funtion walk description =============
        def walk(node: Any):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == '$ref' and isinstance(v, str) and v.startswith('http'):
                        hosts.add(urlparse.urlparse(v).netloc.split(':')[0])
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(spec)
        return sorted(hosts)


    #================funtion _is_payload_reflected description =============
    def _is_payload_reflected(self, finding: dict) -> bool:
        payload = finding.get('payload') or ''
        body = (finding.get('response_body') or '').lower()
        return payload.lower() in body


    #================funtion _test_injection description =============
    def _test_injection(self, test_url: str | tuple, attack_type: str, *, method: str = 'auto', payload: str | None = None) -> None:


        if stop_requested.is_set():
            return


        if isinstance(test_url, tuple) and len(test_url) == 2:
            test_url, method = test_url[0], test_url[1] or method

        defaults = {
            'sql': "' OR 1=1--",
            'nosql': '{"$ne": "invalid"}',
            'xss': '<script>alert(1)</script>',
            'lfi': '../../etc/passwd',
            'rce': '$(reboot)',
            'header': 'X-Injected: header',
            'hpp': 'id=1&id=2',
            'graphql': '__schema'
        }
        p = payload or defaults.get(attack_type, '1')

        parsed = urlparse.urlparse(test_url)
        domain = parsed.netloc or parsed.hostname or ''
        base = test_url.split('?', 1)[0]

        param_candidates = [
            'q', 'query', 'search', 'id', 'user', 'username', 'email', 'name',
            'term', 's', 'page', 'limit', 'offset', 'code', 'token', 'redirect', 'next', 'return', 'ref'
        ]


        allowed = set()
        try:
            self._throttle(domain)
            try:
                opt = self.session.request('OPTIONS', base, timeout=(2, 3), allow_redirects=False)
                allow_hdr = opt.headers.get('Allow') or opt.headers.get('allow') or ''
                allowed = {m.strip().upper() for m in allow_hdr.split(',') if m.strip()}
            except Exception:
                allowed = set()
        except Exception:

            allowed = set()


        if method == 'auto' and allowed:
            for cand in ('POST', 'PUT', 'PATCH', 'GET'):
                if cand in allowed:
                    method = cand
                    break

        tried_any = False
        try:

            fast = getattr(self, 'fast_mode', False) or os.environ.get('APISCAN_FAST') == '1'
            max_per_type = getattr(self, 'triage_payloads_per_type', 6)

            if method in ('auto', 'GET'):
                tried_any = True
                if parsed.query:
                    from urllib.parse import parse_qsl, urlencode
                    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
                    keys = list(q.keys())[:5]
                    for k in keys:
                        old = q.get(k)
                        q[k] = p
                        attack_q = urlencode(q, doseq=True)
                        attack_url = base + '?' + attack_q
                        r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)
                        if self._is_injection_successful(r, attack_type, payload=p):
                            self._log(f'Possible {attack_type.upper()} injection', attack_url, 'Critical', payload=p, response=r)
                            return
                        q[k] = old

                candidates = param_candidates[:5] if not fast else param_candidates[:3]
                for k in candidates:
                    attack_url = f'{base}?{k}={urlparse.quote_plus(p)}'
                    r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)
                    if self._is_injection_successful(r, attack_type, payload=p):
                        self._log(f'Possible {attack_type.upper()} injection', attack_url, 'Critical', payload=p, response=r)
                        return


            post_allowed = ('POST' in allowed) or (method in ('auto', 'POST')) or (not allowed)
            if post_allowed:

                if allowed and 'POST' not in allowed and method not in ('POST', 'PUT', 'PATCH'):
                    post_allowed = False


            if post_allowed:
                tried_any = True

                form_keys = param_candidates[:6] if not fast else param_candidates[:3]
                form_body = {k: p for k in form_keys}
                try:
                    r = self.session.post(base, data=form_body, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                    if self._is_injection_successful(r, attack_type, payload=p):
                        self._log(f'Possible {attack_type.upper()} injection', base + ' (form)', 'Critical', payload=p, response=r)
                        return
                except Exception:
                    pass


                try:
                    files = {'file': ('expl.txt', p)}
                    r = self.session.post(base, files=files, data={}, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                    if self._is_injection_successful(r, attack_type, payload=p):
                        self._log(f'Possible {attack_type.upper()} injection', base + ' (multipart)', 'Critical', payload=p, response=r)
                        return
                except Exception:
                    pass


                try:
                    json_body = {k: p for k in param_candidates[:5]}
                    r = self.session.post(base, json=json_body, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                    if self._is_injection_successful(r, attack_type, payload=p):
                        self._log(f'Possible {attack_type.upper()} injection', base + ' (json)', 'Critical', payload=p, response=r)
                        return
                except Exception:
                    pass


            if '%7B' in test_url.lower() and '%7D' in test_url.lower():
                attack_url = re.sub(r'%7B[^%]+%7D', urlparse.quote_plus(p), test_url, count=1, flags=re.I)
                try:
                    r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)
                    if self._is_injection_successful(r, attack_type, payload=p):
                        self._log(f'Possible {attack_type.upper()} injection', attack_url, 'Critical', payload=p, response=r)
                        return
                except Exception:
                    pass

            if not tried_any:
                self._log('Injection test skipped (no method)', test_url, 'Info')
        except Exception as exc:
            self._log('Injection test failed', test_url, 'Info', extra={'error': str(exc), 'type': attack_type})


    #================funtion _run_injection_tests_parallel description =============
    def _run_injection_tests_parallel(self, endpoint, test_type: str) -> None:
        if stop_requested.is_set():
            return
        payloads = list(self.INJECTION_PAYLOADS[test_type])
        if self.fast_mode and len(payloads) > self.triage_payloads_per_type:
            payloads = payloads[:self.triage_payloads_per_type]


        if isinstance(endpoint, tuple) and len(endpoint) == 2:
            base_endpoint, preferred_method = endpoint[0], endpoint[1]
        else:
            base_endpoint, preferred_method = endpoint, 'auto'

        test_urls: List[Tuple[str, str, str]] = []
        for p in payloads:
            if stop_requested.is_set():
                return

            method_preference = preferred_method if preferred_method and preferred_method != 'AUTO' else ('POST' if '/posts' in base_endpoint else 'auto')
            test_url = f'{base_endpoint}?input={urlparse.quote(p)}'
            test_urls.append((test_url, method_preference, p))
            test_urls.append((base_endpoint.replace('%7BpostId%7D', urlparse.quote_plus(p)), 'GET', p))


        workers = min(8, max(1, len(test_urls)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            if stop_requested.is_set():
                return
            futures = []
            for test_url, method, payload in test_urls:
                if stop_requested.is_set():
                    break
                futures.append(executor.submit(self._test_injection, test_url, test_type, method=method, payload=payload))
            for future in concurrent.futures.as_completed(futures):
                if stop_requested.is_set():
                    for f in futures:
                        f.cancel()
                    return
                try:
                    future.result()
                except Exception:
                    pass


    #================funtion _test_header_manipulation description =============
    def _test_header_manipulation(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            if not domain:
                self._log('Header manipulation test invalid host', endpoint, 'Low')
                return
            host_payloads = ['localhost', '127.0.0.1', 'evil.com', f'{domain}.evil.com', 'localhost:8080', '2130706433', '0x7f000001', '0177.0000.0000.0001']
            for host in host_payloads:
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    r = self.session.get(endpoint, headers={'Host': host}, timeout=(3, self.timeout), allow_redirects=False)
                    if host.lower() in (r.text or '').lower():
                        self._log('Host header reflection', endpoint, 'Medium', extra={'host_header': host, 'response_sample': (r.text or '')[:200]}, response=r)
                    ep_low = endpoint.lower()
                    if ('password' in ep_low and 'reset' in ep_low) and (host in r.headers.get('Location', '') or host.lower() in (r.text or '').lower()):
                        self._log('Possible password reset poisoning via Host', endpoint, 'High', extra={'host_header': host}, response=r)
                except Exception as e:
                    sev = self.classify_transport_anomaly(endpoint, 'GET', e, 0.0)
                    self._log('Host header test failed', endpoint, sev, extra={'error': str(e), 'host': host})
            smuggling_headers = [('Transfer-Encoding', 'chunked'), ('Content-Length', '0'), ('Content-Length', '100'), ('Content-Length', 'abc')]
            for header, value in smuggling_headers:
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    payload = '0\r\n\r\n' if header.lower() == 'transfer-encoding' else ''
                    t0 = time.monotonic()
                    r = self.session.post(endpoint, headers={header: value}, data=payload, timeout=(3, self.timeout), allow_redirects=False)
                    elapsed = max(0.0, time.monotonic() - t0)
                    body_low = (r.text or '').lower()
                    if r.status_code in (400, 502) and any((s in body_low for s in ('invalid header', 'invalid chunk size', 'hpe_invalid', 'http/1.1 400 bad request', 'bad chunk'))):
                        self._log('HTTP Request Smuggling indicator', endpoint, 'Medium', extra={'header': f'{header}: {value}', 'status': r.status_code}, response=r)
                    elif r.status_code == 408 or elapsed > self.timeout * 0.9:
                        sev = self.classify_transport_anomaly(endpoint, 'POST', None, elapsed)
                        self._log('Request smuggling test borderline/timeout', endpoint, sev, extra={'header': f'{header}: {value}', 'elapsed_s': round(elapsed, 3)}, response=r)
                except Exception as e:
                    sev = self.classify_transport_anomaly(endpoint, 'POST', e, 0.0)
                    self._log('Request smuggling test failed', endpoint, sev, extra={'error': str(e), 'header': header})
            sec_headers = {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1', 'X-Forwarded-Host': 'evil.com', 'X-Original-URL': '/admin', 'X-Rewrite-URL': '/admin'}
            try:
                self._throttle(domain)
                r0 = self.session.get(endpoint, timeout=(3, self.timeout), allow_redirects=False)
            except Exception:
                r0 = None

            #================funtion _is_html description =============
            def _is_html(resp: requests.Response) -> bool:
                ct = (resp.headers.get('Content-Type') or '').lower()
                if 'text/html' in ct or 'application/xhtml+xml' in ct:
                    return True
                head = (resp.text or '')[:200].lstrip().lower()
                return head.startswith('<!doctype html') or head.startswith('<html')
            ADMIN_RE = re.compile('(?i)(?:<title>[^<]*admin[^<]*</title>|\\badmin\\s*panel\\b|href=["\\\']/admin[^"\\\']*)')
            for h, v in sec_headers.items():
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    r = self.session.get(endpoint, headers={h: v}, timeout=(3, self.timeout), allow_redirects=False)
                    became_allowed = (r0 is not None and r0.status_code in {401, 403, 404}) and r.status_code == 200
                    admin_like = _is_html(r) and ADMIN_RE.search(r.text or '') is not None
                    loc = (r.headers.get('Location') or '').lower()
                    rewrote_to_admin = '/admin' in loc
                    poisoned_host = h == 'X-Forwarded-Host' and (v.lower() in loc or v.lower() in (r.text or '').lower())
                    strong_signal = h in {'X-Original-URL', 'X-Rewrite-URL'} and (admin_like or rewrote_to_admin) or (h in {'X-Forwarded-For', 'X-Real-IP'} and became_allowed) or poisoned_host
                    if strong_signal:
                        self._log('Possible access control bypass via spoofed header', endpoint, 'High', extra={'header': f'{h}: {v}', 'baseline_status': getattr(r0, 'status_code', '-'), 'location': r.headers.get('Location', '')}, response=r)
                except Exception as e:
                    sev = self.classify_transport_anomaly(endpoint, 'GET', e, 0.0)
                    self._log('Security header test failed', endpoint, sev, extra={'error': str(e), 'header': h})
            inj_headers = [('User-Agent', '<script>alert(1)</script>'), ('Referer', 'javascript:alert(1)'), ('Origin', 'http://evil.com'), ('Cookie', 'session=../../../../etc/passwd')]
            for h, p in inj_headers:
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    r = self.session.get(endpoint, headers={h: p}, timeout=(3, self.timeout), allow_redirects=False)
                    body = r.text or ''
                    if p.lower() in body.lower():
                        self._log('Header-based XSS reflection', endpoint, 'High', extra={'header': h, 'payload': p}, response=r)
                    loc = r.headers.get('Location', '')
                    if loc and p in loc:
                        self._log('Header-based open redirect', endpoint, 'Medium', extra={'header': h, 'payload': p, 'location': loc}, response=r)
                except Exception as e:
                    sev = self.classify_transport_anomaly(endpoint, 'GET', e, 0.0)
                    self._log('Header injection test failed', endpoint, sev, extra={'error': str(e), 'header': h})
            cors_origins = ['https://attacker.com', 'null', 'http://localhost', 'http://127.0.0.1']
            for origin in cors_origins:
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    r = self.session.get(endpoint, headers={'Origin': origin}, timeout=(3, self.timeout), allow_redirects=False)
                    status = r.status_code
                    acao = r.headers.get('Access-Control-Allow-Origin') or ''
                    acac = (r.headers.get('Access-Control-Allow-Credentials') or '').lower()
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    disp = (r.headers.get('Content-Disposition') or '').lower()
                    if status < 200 or status >= 300:
                        continue
                    is_textual = 'application/json' in ctype or ctype.startswith('text/') or 'application/xml' in ctype or ('application/javascript' in ctype)
                    is_static = ctype.startswith(('image/', 'video/', 'audio/', 'font/')) or 'application/octet-stream' in ctype or 'application/pdf' in ctype or ('filename=' in disp)
                    if not is_textual or is_static:
                        continue
                    if acao == '*' and acac == 'true':
                        self._log('CORS misconfiguration: wildcard with credentials', endpoint, 'High', extra={'origin': origin, 'acao': acao, 'acac': acac}, response=r)
                        continue
                    if acao == '*' or origin in acao:
                        sev = 'Medium' if acac == 'true' else 'Info'
                        self._log('Broad CORS policy', endpoint, sev, extra={ 'origin': origin, 'acao': acao, 'acac': acac, 'content_type': ctype, 'vector':'cors' }, response=r)
                except Exception as e:
                    sev = self.classify_transport_anomaly(endpoint, 'GET', e, 0.0)
                    self._log('CORS test failed', endpoint, sev, extra={'error': str(e), 'origin': origin})
        except Exception as e:
            self._log('Header manipulation test setup failed', endpoint, 'Medium', extra={'error': str(e)})


    #================funtion _test_blind_sqli description =============
    def _test_blind_sqli(self, endpoint: str) -> None:
        """Blind SQLi (boolean + time-based) heuristic.

        Does not require HTTP 200. Compares response signatures vs baseline.
        """
        try:
            parsed = urlparse.urlparse(endpoint)
        except Exception:
            return

        base = endpoint.split("?", 1)[0]
        domain = parsed.netloc or urlparse.urlparse(base).netloc
        if not domain:
            return


        from urllib.parse import parse_qsl, urlencode

        q_items = parse_qsl(parsed.query, keep_blank_values=True)
        q = dict(q_items)
        if q:
            keys = list(q.keys())[:3]
        else:

            keys = ["id", "q", "search"]

        #================funtion _signature description =============
        def _signature(resp) -> tuple:
            try:
                body = self._safe_body(resp)
            except Exception:
                body = ""
            ct = (resp.headers.get("Content-Type", "") if getattr(resp, "headers", None) else "")
            return (getattr(resp, "status_code", 0), len(body or ""), ct.split(";", 1)[0].lower())


        true_p = "' OR 1=1--"
        false_p = "' OR 1=2--"


        time_payloads = [
            "' OR SLEEP(5)-- ",
            "'; SELECT SLEEP(5)-- ",
            "' OR pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
        ]

        for k in keys:

            q0 = dict(q) if q else {}
            q0[k] = q0.get(k, "1") or "1"
            u0 = base + "?" + urlencode(q0, doseq=True)


            qt = dict(q0); qt[k] = true_p
            qf = dict(q0); qf[k] = false_p
            ut = base + "?" + urlencode(qt, doseq=True)
            uf = base + "?" + urlencode(qf, doseq=True)

            try:
                self._throttle(domain)
                r0 = self.session.get(u0, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                self._throttle(domain)
                rt = self.session.get(ut, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                self._throttle(domain)
                rf = self.session.get(uf, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
            except Exception as e:

                self._log("Blind SQLi probe failed", base, "Info", extra={"error": str(e), "param": k})
                continue

            s0 = _signature(r0)
            st = _signature(rt)
            sf = _signature(rf)


            len0, lent, lenf = s0[1], st[1], sf[1]
            maxlen = max(len0, lent, lenf, 1)
            diff_tf = abs(lent - lenf) / maxlen
            diff_t0 = abs(lent - len0) / maxlen
            diff_f0 = abs(lenf - len0) / maxlen

            status_changed = (st[0] != sf[0]) or (st[0] != s0[0]) or (sf[0] != s0[0])

            if diff_tf >= 0.25 and (diff_t0 >= 0.15 or diff_f0 >= 0.15 or status_changed):
                self._log(
                    "Possible Blind SQL Injection (boolean-based)",
                    base,
                    "High",
                    payload={"param": k, "true": true_p, "false": false_p},
                    response=rt,
                    extra={
                        "confidence": "medium",
                        "baseline_status": s0[0],
                        "true_status": st[0],
                        "false_status": sf[0],
                        "baseline_len": len0,
                        "true_len": lent,
                        "false_len": lenf,
                    },
                )

                try:
                    import time as _time

                    t0 = 0.0
                    for _ in range(2):
                        self._throttle(domain)
                        t_start = _time.perf_counter()
                        self.session.get(u0, timeout=(3, max(self.timeout, 10)), allow_redirects=False)
                        t0 += (_time.perf_counter() - t_start)
                    t0 /= 2.0

                    confirmed = False
                    for tp in time_payloads:
                        qd = dict(q0); qd[k] = tp
                        ud = base + "?" + urlencode(qd, doseq=True)
                        delays = []
                        for _ in range(2):
                            self._throttle(domain)
                            t_start = _time.perf_counter()
                            self.session.get(ud, timeout=(3, max(self.timeout, 15)), allow_redirects=False)
                            delays.append(_time.perf_counter() - t_start)

                        if all((d - t0) >= 3.5 for d in delays):
                            confirmed = True
                            self._log(
                                "Possible Blind SQL Injection (time-based)",
                                base,
                                "Critical",
                                payload={"param": k, "time_payload": tp},
                                extra={"confidence": "high", "baseline_avg_s": round(t0, 3), "delays_s": [round(d, 3) for d in delays]},
                            )
                            break
                    if confirmed:
                        return
                except Exception:
                    pass
                return

        return

    #================funtion _is_injection_successful description =============
    def _is_injection_successful(
        self,
        response: requests.Response,
        attack_type: str,
        *,
        baseline_latency: float = 0.5,
        payload: str = ''
    ) -> bool:
        if response is None:
            return False

        try:
            status = int(getattr(response, 'status_code', 0))
        except Exception:
            status = 0

        text = response.text or ''
        low = text.lower()


        if status in {400, 422} and self._is_parse_error(response):
            return False


        if attack_type == 'nosql':
            if any(p in low for p in self.NOSQL_NEGATIVE_PATTERNS):
                return False


        if attack_type == 'sql':
            if self._has_sql_evidence(text):
                return True
            try:
                elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0
            except Exception:
                elapsed = 0.0


            return False


        if status >= 500:
            if attack_type == 'nosql':

                return any((k in low for k in self.NOSQL_ERROR_KEYWORDS)) or self._has_engine_marker(low, 'nosql')
            if attack_type in {'ssti', 'ldap', 'xxe'}:
                return self._has_engine_marker(low, attack_type)
            return False


        if attack_type == 'nosql':
            specific = any((re.search(p, low) for p in ('mongo.*error', 'mongodb.*error', 'bson.*error')))
            keywords = any((k in low for k in self.NOSQL_ERROR_KEYWORDS))
            return specific or keywords or self._has_engine_marker(low, 'nosql')


        if attack_type == 'xss':
            if not payload or payload.lower() not in low:
                return False
            return any((s in text for s in (f'="{payload}"', f'>{payload}<', f"'{payload}'", f'`{payload}`'))) or self._is_payload_reflected(text, payload)


        if attack_type == 'xxe':
            ctype = (response.headers.get('Content-Type') or '').lower()
            CONTENT_MARKERS = ('root:x:0:0:', 'daemon:x:', '/bin/bash', 'for 16-bit app support', '[extensions]')
            PATH_ONLY_MARKERS = ('/etc/passwd', '/etc/hosts', 'c:\\windows\\win.ini', 'file:///etc/passwd', 'file:///etc/hosts')

            if any(ind in low for ind in CONTENT_MARKERS):
                if not ('text/html' in ctype and '<html' in low):
                    return True
            if any(ind in low for ind in PATH_ONLY_MARKERS):
                return False

            blocked_patterns = (
                r'doctype.*(disallowed|prohibit|denied)',
                r'entity\s+.*(not\s+defined|cannot\s+be\s+resolved)',
            )
            if any((re.search(pat, low) for pat in blocked_patterns)):
                return False

            specific = any((re.search(p, low) for p in (
                r'xxe',
                r'xml.*parser.*error',
                r'entity.*reference',
                r'doctype.*not.*allowed'
            )))
            return specific or self._has_engine_marker(low, 'xxe')

        return False


    #================funtion _is_false_positive description =============
    def _is_false_positive(self, response: requests.Response) -> bool:
        content = (response.text or '').lower()
        false_positive_indicators = ['cloudflare', 'akamai', 'waf', 'firewall', 'access denied', 'forbidden', 'security policy', 'page not found', 'error occurred', 'try again', 'not found', 'invalid request', 'bad request']
        waf_patterns = ('cloudflare', 'akamaighost', 'imperva', 'barracuda', 'fortinet')
        has_fp_indicator = any((indicator in content for indicator in false_positive_indicators))
        has_waf_pattern = any((re.search(pattern, content) for pattern in waf_patterns))
        return has_fp_indicator or has_waf_pattern


    #================funtion _detect_server_errors description =============
    def _detect_server_errors(self, endpoint: str) -> None:
        prov = getattr(self, 'server_log_provider', None)
        if callable(prov):
            try:
                errors = prov() or []
            except Exception:
                errors = []
            for error in errors:
                if 'sql' in error.lower() and endpoint in error:
                    self._log('SQL error detected in server logs', endpoint, 'High', extra={'error': error})


    #================funtion _test_basic_security description =============
    def _test_basic_security(self, endpoint: str) -> None:
        try:
            r = self.session.get(endpoint, timeout=(3, self.timeout), allow_redirects=False)
        except Exception as e:
            self._log('Request failed (network/timeout)', endpoint, 'Info', extra={'error': str(e)})
            return
        status = r.status_code
        ctype = (r.headers.get('Content-Type') or '').lower()
        is_textual = 'application/json' in ctype or ctype.startswith('text/') or 'application/xml' in ctype or ('application/javascript' in ctype)
        if 200 <= status < 300:
            return
        if status in {401, 403}:
            self._log('Auth required / forbidden (expected)', endpoint, 'Info', response=r)
            return
        if status in {404}:
            self._log('Not found (expected)', endpoint, 'Info', response=r)
            return
        if status in {405}:
            allow = r.headers.get('Allow')
            self._log('Method not allowed (use correct verb)', endpoint, 'Info', extra={'allow': allow} if allow else None, response=r)
            return
        if status in {422}:
            self._log('Unprocessable entity (expected validation)', endpoint, 'Info', response=r)
            return
        if 300 <= status < 400:
            loc = r.headers.get('Location')
            self._log('Redirect response', endpoint, 'Info', extra={'location': loc} if loc else None, response=r)
            return
        if status >= 500:
            self._log('Server error (5xx) observed', endpoint, 'Info', extra={'content_type': ctype} if ctype else None, response=r)
            return
        if 400 <= status < 500:
            self._log('Client error without evidence', endpoint, 'Info', response=r)
            return
        self._log('Unexpected response status', endpoint, 'Info', response=r)


    #================funtion _test_crlf_injection description =============
    def _test_crlf_injection(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            if not domain:
                self._log('CRLF test invalid host', endpoint, 'Low')
                return
            canary_name = 'X-CRLF-Canary'
            canary_val = f'apiscan-{self.generate_random_id(8)}'
            canary_cookie = f'{canary_name}={canary_val}'
            canary_path = f'/{canary_val}'
            canary_loc = f'https://example.com{canary_path}'
            base_variants = [f'%0d%0a{canary_name}: {canary_val}', f'%0d%0aSet-Cookie: {canary_cookie}', f'%0d%0aLocation: {canary_loc}', f'%0d%0aX-Accel-Redirect: {canary_path}']
            extra_variants = []
            try:
                for p in self.CRLF_PAYLOADS or []:
                    if 'X-Injected:' in p:
                        extra_variants.append(p.replace('X-Injected: header', f'{canary_name}: {canary_val}'))
                    else:
                        extra_variants.append(p)
            except Exception:
                pass
            variants = base_variants + extra_variants
            params_to_try = ['q', 'search', 'redirect', 'url', 'return', 'next']

            #================funtion _all_headers description =============
            def _all_headers(resp: requests.Response) -> List[Tuple[str, str]]:
                try:
                    return _headers_to_list(resp.raw.headers)
                except Exception:
                    return list(resp.headers.items())
            for param in params_to_try:
                if stop_requested.is_set():
                    return
                for inj in variants:
                    if stop_requested.is_set():
                        return
                    url = f'{endpoint}'
                    sep = '&' if '?' in url else '?'
                    test_url = f'{url}{sep}{param}=test{inj}'
                    try:
                        self._throttle(domain)
                        r = self.session.get(test_url, timeout=(3, self.timeout), allow_redirects=False)
                        hdrs = _all_headers(r)
                        hdrs_dict = {k.lower(): v for k, v in hdrs}
                        body_low = (r.text or '').lower()
                        if canary_name.lower() in hdrs_dict and canary_val in hdrs_dict[canary_name.lower()]:
                            self._log('CRLF injection (response header injection)', test_url, 'High', payload=inj, response=r, extra={'param': param, 'injected_header': canary_name, 'value': canary_val})
                            continue
                        loc = r.headers.get('Location', '')
                        if loc and canary_val in loc:
                            self._log('CRLF injection (Location header poisoned)', test_url, 'High', payload=inj, response=r, extra={'param': param, 'location': loc})
                            continue
                        set_cookie_lines = [v for k, v in hdrs if k.lower() == 'set-cookie']
                        if any((canary_name.lower() in v.lower() and canary_val in v for v in set_cookie_lines)):
                            self._log('CRLF injection (Set-Cookie poisoned)', test_url, 'High', payload=inj, response=r, extra={'param': param, 'set_cookie': set_cookie_lines[:2]})
                            continue
                        if f'{canary_name.lower()}: {canary_val.lower()}' in body_low:
                            self._log('CRLF header string reflected in body', test_url, 'Info', payload=inj, response=r, extra={'param': param})
                            continue
                    except Exception as e:
                        sev = self.classify_transport_anomaly(endpoint, 'GET', e, 0.0)
                        self._log('CRLF test failed', test_url, sev, extra={'error': str(e), 'param': param, 'payload': inj})
        except Exception as e:
            self._log('CRLF test setup failed', endpoint, 'Medium', extra={'error': str(e)})


    #================funtion _test_ssrf description =============
    def _test_ssrf(self, endpoint: str) -> None:
        return


    #================funtion _is_ssrf_successful description =============
    def _is_ssrf_successful(self, response: requests.Response, payload: str) -> bool:
        return

    @staticmethod


    #================funtion generate_random_id description =============
    def generate_random_id(length: int=8) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


    #================funtion _test_graphql_introspection description =============
    def _test_graphql_introspection(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc or ''
            for path in ('/graphql', '/v1/graphql', '/api/graphql'):
                url = f"{endpoint.rstrip('/')}{path}"
                try:
                    self._throttle(domain)
                    r = self.session.post(url, json={'query': self.GRAPHQL_INTROSPECTION_QUERY}, timeout=(3, self.timeout))
                    if r.status_code == 200 and '__schema' in (r.text or ''):
                        self._log('GraphQL introspection enabled', endpoint, 'Medium', response=r)
                        break
                except Exception:
                    continue
        except Exception as e:
            self._log('GraphQL test failed', endpoint, 'Info', extra={'error': str(e)})


    #================funtion _test_hpp description =============
    def _test_hpp(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc or ''
            try:
                self._throttle(domain)
                options_response = self.session.request('OPTIONS', endpoint, timeout=(2, 3), allow_redirects=False)
                allowed_methods = {m.strip().upper() for m in options_response.headers.get('Allow', '').split(',') if m}
                if 'GET' not in allowed_methods and options_response.status_code != 200:
                    return
            except Exception:
                pass
            for param in self.HPP_PARAMS:
                url = f'{endpoint}?{param}=1&{param}=2'
                try:
                    self._throttle(domain)
                    r = self.session.get(url, timeout=(3, self.timeout), allow_redirects=False)
                    if r.status_code == 405:
                        continue
                    body = r.text or ''
                    body_has_combo = '1,2' in body or ',1' in body
                    param_reflected = any([f'{param}=1' in body and f'{param}=2' in body, f'{param}=1,2' in body, f'{param}=2,1' in body, f'{param}[]=1' in body and f'{param}[]=2' in body])
                    if body_has_combo or param_reflected:
                        severity = 'Medium' if r.status_code < 300 and (body_has_combo or param_reflected) else 'Info'
                        self._log('HPP detected', url, severity, response=r, extra={'parameter': param})
                except Exception as e:
                    self._log('HPP test failed', url, 'Info', extra={'error': str(e)})
        except Exception as e:
            self._log('HPP test setup failed', endpoint, 'Info', extra={'error': str(e)})


    #================funtion _test_directory_traversal description =============
    def _test_directory_traversal(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''


            repl_index   = int(os.getenv('APISCAN_TRAV_REPLACE_INDEX', '-2'))
            ins_before   = int(os.getenv('APISCAN_TRAV_INSERT_BEFORE_INDEX', '-1'))
            max_dot      = int(os.getenv('APISCAN_TRAV_MAX_DOT', '3'))
            max_ddot     = int(os.getenv('APISCAN_TRAV_MAX_DDOT', '3'))
            max_ellipsis = int(os.getenv('APISCAN_TRAV_MAX_ELLIPSIS', '2'))

            rep_variants = build_traversal_variants_segment_replace(endpoint, repl_index, max_dot, max_ddot, max_ellipsis)
            ins_variants = build_traversal_variants_insert_between(endpoint, ins_before, max_dot, max_ddot, max_ellipsis)

            if getattr(self, 'fast_mode', False):
                rep_variants = rep_variants[:min(4, len(rep_variants))]
                ins_variants = ins_variants[:min(4, len(ins_variants))]


            extra = []
            for v in (rep_variants + ins_variants):
                pv = v if v.endswith('/') else v + '/'
                extra.extend([pv + 'etc/passwd', pv + 'WEB-INF/web.xml', pv + 'windows/win.ini'])

            strong_indicators = [
                'root:x:0:0:', 'daemon:x:1:1:', 'index of /', '<title>index of',
                'parent directory', 'directory listing for', 'directory of ',
                '[extensions]', 'for 16-bit app support'
            ]
            weak_indicators = [
                '/etc/passwd', 'bin:x:', 'boot.ini', ':\\windows\\', 'web-inf/web.xml'
            ]

            #================funtion is_likely_false_positive description =============
            def is_likely_false_positive(resp, body_text: str) -> bool:
                if not resp:
                    return False
                ctype = (resp.headers.get('Content-Type') or '').lower()
                if resp.status_code in (401, 403):
                    low = (body_text or '').lower()
                    if any(t in low for t in ['invalid token', 'unauthorized', 'authentication', 'crapiresponse']):
                        return True
                if 'application/json' in ctype and resp.status_code >= 400:
                    return True
                if ctype.startswith(('image/', 'video/', 'audio/')) or 'application/octet-stream' in ctype:
                    return True
                return False

            #================funtion looks_interesting description =============
            def looks_interesting(text: str) -> tuple[bool, str]:
                if not text:
                    return (False, 'none')
                low = text.lower()
                for ind in strong_indicators:
                    if ind in low:
                        return (True, 'high')
                weak_count = sum(1 for ind in weak_indicators if ind in low)
                if weak_count >= 2:
                    return (True, 'medium')
                if weak_count == 1:
                    has_links = any(m in low for m in ['<a href="', '&lt;a href=', 'href="', '>../<', '>..</a>'])
                    has_sizes = re.search(r'\b\d+\s*(bytes?|kb|mb|gb)\b', low)
                    if has_links or has_sizes:
                        return (True, 'medium')
                return (False, 'none')

            #================funtion do_req description =============
            def do_req(url, label):
                try:
                    self._throttle(domain)
                    hdrs = dict(getattr(self.session, 'headers', {}))
                    hdrs['X-APISCAN-Payload'] = url
                    r = self.session.get(url, headers=hdrs, timeout=(3, getattr(self, 'timeout', 10)), allow_redirects=False)
                    body = r.text or ''

                    if is_likely_false_positive(r, body):
                        return

                    is_interesting, confidence = looks_interesting(body)
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    is_binary = ctype.startswith(('image/', 'video/', 'audio/')) or 'application/octet-stream' in ctype
                    if is_binary:
                        return

                    if r.status_code == 200 and is_interesting:
                        sev = 'High' if confidence == 'high' else ('Medium' if confidence == 'medium' else 'Low')
                        self._log(f'Directory traversal ({label}) [{r.status_code}]', url, sev,
                                payload=url, response=r,
                                extra={'vector': 'dirtrav', 'base_endpoint': endpoint, 'confidence': confidence})

                    elif r.status_code in (301, 302, 307, 308):
                        loc = (r.headers.get('Location') or '').lower()
                        if any(p in loc for p in ('../', '..\\', '%2e%2e', 'etc/passwd', 'web-inf')):
                            self._log(f'Directory traversal ({label}) - suspicious redirect [{r.status_code}]',
                                    url, 'Medium', payload=url, response=r,
                                    extra={'vector': 'dirtrav', 'base_endpoint': endpoint, 'location': loc})

                    elif r.status_code in (401, 403) and is_interesting and confidence == 'high':
                        self._log(f'Directory traversal ({label}) [{r.status_code}]', url, 'Low',
                                payload=url, response=r,
                                extra={'vector': 'dirtrav', 'base_endpoint': endpoint, 'confidence': confidence})

                except Exception as e:
                    self._log('Directory traversal request error', url, 'Info',
                            extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint})

            variants = [('segment replace', u) for u in rep_variants] + [('segment insert', u) for u in ins_variants]
            variants += [('suffix', u) for u in extra]


            seen = set()
            filtered = []
            orig_path = urlparse.urlsplit(endpoint).path
            for label, u in variants:
                vp = urlparse.urlsplit(u).path
                key = (label, vp)
                if vp != orig_path and key not in seen:
                    filtered.append((label, u))
                    seen.add(key)

            workers = min(8, max(1, len(filtered)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = []
                for label, u in filtered:
                    if stop_requested.is_set():
                        break
                    futures.append(executor.submit(do_req, u, label))
                for f in concurrent.futures.as_completed(futures):
                    try:
                        f.result()
                    except Exception:
                        pass

        except Exception as e:
            self._log('Directory traversal test setup failed', endpoint, 'Info',
                    extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint})


    #================funtion _test_docker_api description =============
    def _test_docker_api(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            host = urlparse.urlparse(endpoint).hostname
            if not host:
                self._log('Docker test invalid host', endpoint, 'Low')
                return
            self._throttle(host)
            r = self.session.get(f'http://{host}:2375/version', timeout=(3, self.timeout))
            if r.status_code == 200:
                self._log('Docker Remote API open', f'http://{host}:2375/version', 'High', response=r)
        except Exception as e:
            self._log('Docker test failed', f'http://{host}:2375/version', 'Info', extra={'error': str(e)})


    #================funtion _test_kubernetes_api description =============
    def _test_kubernetes_api(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            host = urlparse.urlparse(endpoint).hostname
            if not host:
                self._log('Kubernetes test invalid host', endpoint, 'Low')
                return
            for port in (6443, 2379):
                if stop_requested.is_set():
                    break
                try:
                    self._throttle(host)
                    url = f'https://{host}:{port}/version'
                    r = self.session.get(url, timeout=(3, self.timeout), verify=False)
                    if r.status_code == 200:
                        self._log('Kubernetes API open', url, 'High', response=r)
                except Exception as e:
                    self._log('Kubernetes test failed', url, 'Info', extra={'error': str(e)})
        except Exception as e:
            self._log('Kubernetes test setup failed', endpoint, 'Info', extra={'error': str(e)})


    #================funtion _test_sensitive_data_exposure description =============
    def _test_sensitive_data_exposure(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc or ''
            self._throttle(domain)
            url = f'{self.base_url}/api/v1/config' if endpoint == self.base_url else f'{endpoint}/api/v1/config'
            r = self.session.get(url, timeout=(3, self.timeout))
            if getattr(r, 'status_code', 0) >= 400:
                return
            content = (r.text or '').lower()
            for term in ('password', 'secret', 'token', 'key', 'credential'):
                if term in content:
                    self._log('Sensitive data exposure', url, 'High', response=r)
                    break
        except Exception as e:
            self._log('Sensitive data test failed', endpoint, 'Info', extra={'error': str(e), 'status_code': 0})


    #================funtion _is_endpoint_reachable description =============
    def _is_endpoint_reachable(self, endpoint: str) -> bool:
        """Quick reachability check to avoid spending time on dead endpoints.
        Returns True when the endpoint does not look like a hard 404.
        """
        try:
            domain = urlparse.urlparse(endpoint).netloc or ""
            self._throttle(domain)
            resp = self.session.head(endpoint, timeout=(2, 3), allow_redirects=False)
            if resp.status_code in (405, 501):
                self._throttle(domain)
                resp = self.session.get(endpoint, timeout=(3, 5), allow_redirects=False)
            return resp.status_code != 404
        except requests.RequestException:
            return False
        except Exception:
            return False

    #================funtion test_endpoints description =============
    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        MAX_WORKERS = self.max_workers
        print(f'{Fore.CYAN}[INFO] Starting full scan with {MAX_WORKERS} workers - Perry Mertens pamsniffer@gmail.com 2025 (C) {Style.RESET_ALL}')
        global stop_requested
        stop_requested.clear()
        reachable_endpoints = []
        with tqdm(total=len(endpoints), desc='Pre-scanning') as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pre_executor:
                future_to_ep = {pre_executor.submit(self._is_endpoint_reachable, ep): ep for ep in endpoints}
                for future in concurrent.futures.as_completed(future_to_ep):
                    if stop_requested.is_set():
                        for f in future_to_ep:
                            f.cancel()
                        break
                    ep = future_to_ep[future]
                    try:
                        if future.result(timeout=self.timeout * 2):
                            reachable_endpoints.append(ep)
                    except Exception as e:
                        self._log(f'Pre-scan failed for {ep}', str(e), 'Info')
                    finally:
                        pbar.update(1)
        if stop_requested.is_set():
            return self.issues

        base_core_tests = 8

        base_core_tests += 1

        opt_traversal = 0
        if hasattr(self, '_test_directory_traversal'):
            opt_traversal += 1
        if hasattr(self, '_test_directory_traversal_body'):
            opt_traversal += 1

        tests_per_endpoint = base_core_tests + opt_traversal + len(self.INJECTION_PAYLOADS)
        total_tasks = len(reachable_endpoints) * tests_per_endpoint
        with tqdm(total=total_tasks, desc=f'Scanning endpoints ({len(reachable_endpoints)})') as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as main_executor:
                all_tasks = []
                for ep in reachable_endpoints:
                    if stop_requested.is_set():
                        break
                    test_fns = [partial(self._test_basic_security, ep), partial(self._test_crlf_injection, ep), partial(self._test_hpp, ep), partial(self._test_sensitive_data_exposure, ep), partial(self._test_graphql_introspection, ep), partial(self._test_header_manipulation, ep)] + [partial(self._test_blind_sqli, ep)]
                    if hasattr(self, '_test_directory_traversal'):
                        test_fns.append(partial(self._test_directory_traversal, ep))
                    if hasattr(self, '_test_directory_traversal_body'):
                        test_fns.append(partial(self._test_directory_traversal_body, ep))
                    for t in self.INJECTION_PAYLOADS:
                        test_fns.append(partial(self._run_injection_tests_parallel, ep, t))
                    for fn in test_fns:
                        if stop_requested.is_set():
                            break
                        all_tasks.append(main_executor.submit(fn))
                for future in concurrent.futures.as_completed(all_tasks):
                    if stop_requested.is_set():
                        for task in all_tasks:
                            task.cancel()
                        break
                    try:
                        future.result(timeout=self.timeout * 20)
                    except concurrent.futures.TimeoutError:
                        self._log('Test timeout', 'N/A', 'Info')
                    except Exception as e:
                        self._log('Test failed', 'N/A', 'Info', extra={'error': str(e)})
                    finally:
                        pbar.update(1)
        print(f'{Fore.CYAN}[INFO] Scan completed. Found {len(self.issues)} issues.{Style.RESET_ALL}')
        try:
            summary = self.counts_by_category(include_info=False)
            print(f'{Fore.CYAN}[SUMMARY] Findings by category (actionable):{Style.RESET_ALL}')
            for k, v in summary.items():
                print(f'  - {k}: {v}')
            summary_all = self.counts_by_category(include_info=True)
            print(f'{Fore.CYAN}[SUMMARY] Findings by category (all severities):{Style.RESET_ALL}')
            for k, v in summary_all.items():
                print(f'  - {k}: {v}')
        except Exception:
            pass
        return self.issues


#================funtion _response_signature description =============
def _response_signature(self, resp: requests.Response | None) -> tuple[int, int, str]:
    if resp is None:
        return (0, 0, "")
    try:
        status = int(getattr(resp, "status_code", 0))
    except Exception:
        status = 0
    try:
        body = getattr(resp, "text", "") or ""
        blen = len(body)
    except Exception:
        blen = 0
    try:
        ctype = (resp.headers.get("Content-Type") or "").split(";", 1)[0].lower()
    except Exception:
        ctype = ""
    return (status, blen, ctype)


#================funtion _sig_diff description =============
def _sig_diff(self, a: tuple[int, int, str], b: tuple[int, int, str]) -> int:

    score = 0
    if a[0] != b[0]:
        score += 3

    if abs(a[1] - b[1]) > max(50, int(0.15 * max(a[1], b[1], 1))):
        score += 2
    if a[2] != b[2]:
        score += 1
    return score


#================funtion _request_with_timing description =============
def _request_with_timing(self, method: str, url: str, *, params=None, json_body=None) -> tuple[requests.Response | None, float]:
    self._throttle(urlparse.urlparse(url).netloc if hasattr(urlparse, "urlparse") else urlparse.urlparse(url).netloc)
    try:
        r = self.session.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            timeout=(3, max(self.timeout, 12)),
            allow_redirects=False
        )
        try:
            elapsed = r.elapsed.total_seconds() if r.elapsed else 0.0
        except Exception:
            elapsed = 0.0
        return r, float(elapsed)
    except Exception:
        return None, 0.0


#================funtion _test_blind_sqli description =============
def _test_blind_sqli(self, endpoint: str) -> None:
    """Blind SQL injection heuristics (boolean-based + optional time-based).

    This does NOT require HTTP 200. We compare response signatures against a baseline.
    """
    if stop_requested.is_set():
        return

    base = endpoint

    param_names = ["id", "q", "search", "query", "name", "input", "user", "email", "ref", "next", "return"]
    true_payloads = ["' OR 1=1--", "\" OR 1=1--", "') OR ('1'='1", "1 OR 1=1"]
    false_payloads = ["' OR 1=2--", "\" OR 1=2--", "') OR ('1'='2", "1 OR 1=2"]


    p0 = {param_names[0]: "1"}
    r0, t0 = self._request_with_timing("GET", base, params=p0)
    sig0 = self._response_signature(r0)


    best = None
    for pn in param_names:
        if stop_requested.is_set():
            return
        for tp, fp in zip(true_payloads, false_payloads):
            rT, _ = self._request_with_timing("GET", base, params={pn: tp})
            rF, _ = self._request_with_timing("GET", base, params={pn: fp})
            sigT = self._response_signature(rT)
            sigF = self._response_signature(rF)

            diff_tf = self._sig_diff(sigT, sigF)
            diff_t0 = self._sig_diff(sigT, sig0)
            diff_f0 = self._sig_diff(sigF, sig0)
            score = diff_tf + max(diff_t0, diff_f0)
            if best is None or score > best[0]:
                best = (score, pn, tp, fp, sigT, sigF, rT, rF)

    if best and best[0] >= 5:
        _, pn, tp, fp, sigT, sigF, rT, rF = best
        desc = f"Boolean-based response difference for parameter '{pn}'. TRUE({tp}) vs FALSE({fp}). baseline={sig0}, true={sigT}, false={sigF}"

        self._log("Possible Blind SQL Injection", base, desc, "High", payload=tp, response=rT)


    time_payloads = [
        ("';SELECT SLEEP(5)--", 4.0),
        ("';SELECT pg_sleep(5)--", 4.0),
        ("';WAITFOR DELAY '0:0:5'--", 4.0),
    ]

    b_times = []
    for _ in range(2):
        _, bt = self._request_with_timing("GET", base, params=p0)
        if bt:
            b_times.append(bt)
    if not b_times:
        return
    b_avg = sum(b_times) / len(b_times)

    for pn in param_names[:4]:
        for payload, min_delta in time_payloads:
            if stop_requested.is_set():
                return

            delays = []
            for _ in range(2):
                rD, td = self._request_with_timing("GET", base, params={pn: payload})
                if td:
                    delays.append(td)
            if len(delays) == 2 and all((d - b_avg) >= min_delta for d in delays):
                desc = f"Time-based delay detected for parameter '{pn}'. baseline_avg={b_avg:.2f}s delays={delays}"
                self._log("Possible Time-based Blind SQL Injection", base, desc, "Critical", payload=payload, response=rD)
                return
    #================funtion _has_sql_evidence description =============
    def _has_sql_evidence(self, body: str) -> bool:
        low = (body or '').lower()
        if any((k in low for k in self.SQL_ENGINE_MARKERS)):
            return True
        if any((rx.search(low) for rx in getattr(self, 'SQL_ERROR_RX', []))):
            return True
        if any((k in low for k in self.SQL_ERROR_KEYWORDS)):
            sqlish = (' sql ', 'sqlsyntaxerror', 'syntax error at or near', 'mysql', 'postgres', 'psql', 'psycopg', 'odbc', 'oracle', 'ora-', 'unclosed quotation mark', 'incorrect syntax near')
            if any((t in low for t in sqlish)):
                return True
        return False


    #================funtion _is_endpoint_reachable description =============
    def _is_endpoint_reachable(self, endpoint: str) -> bool:

        #================funtion _ok description =============
        def _ok(code: int) -> bool:
            return (200 <= code < 400) or code in (401, 403, 405)

        sess = getattr(self, "session", None) or getattr(self, "sess", None)
        if sess is None:
            return True

        try:
            r = sess.head(endpoint, timeout=self.timeout, allow_redirects=True)
            if _ok(getattr(r, "status_code", 0)):
                return True
            r2 = sess.get(endpoint, timeout=self.timeout, allow_redirects=True)
            return _ok(getattr(r2, "status_code", 0))
        except Exception:
            try:
                r2 = sess.get(endpoint, timeout=self.timeout, allow_redirects=True)
                return _ok(getattr(r2, "status_code", 0))
            except Exception:
                return False


    #================funtion _filter_issues description =============
    def _filter_issues(self) -> list[dict]:
        cleaned, seen = ([], set())

        IGNORE_TIMEOUTS = bool(getattr(self, 'IGNORE_NETWORK_TIMEOUTS', True))
        NETWORK_TIMEOUT_PATTERNS = tuple(getattr(self, 'NETWORK_TIMEOUT_PATTERNS', (
            'httpconnectionpool', 'read timed out', 'connect timeout', 'connecttimeout',
            'write timeout', 'newconnectionerror', 'failed to establish a new connection',
            'max retries exceeded', 'temporarily unavailable', 'winerror 10060', 'winerror 10061'
        )))
        GENERIC_4XX = {400, 401, 403, 404, 405, 406, 409, 415, 422, 429}

        for issue in self.issues:
            desc_text = str(issue.get('description', ''))
            desc_low = desc_text.lower()
            err_low = str(issue.get('error', '')).lower()
            body = issue.get('response_body') or ''
            body_low = body.lower()

            if 'failed to parse' in desc_low or "name 'parsed' is not defined" in desc_low:
                continue

            if any(p in err_low for p in NETWORK_TIMEOUT_PATTERNS):
                if IGNORE_TIMEOUTS:
                    continue
                else:
                    issue['severity'] = 'Info'

            try:
                status = int(issue.get('status_code', 0))
            except (ValueError, TypeError):
                status = 0

            hdrs_map = {}
            rh = issue.get('response_headers')
            if isinstance(rh, dict):
                hdrs_map = {str(k): str(v) for k, v in rh.items()}
            elif isinstance(rh, list):
                hdrs_map = {str(k): str(v) for k, v in rh}
            else:
                rh_list = issue.get('response_headers_list') or []
                try:
                    hdrs_map = {str(k): str(v) for k, v in rh_list}
                except Exception:
                    hdrs_map = {}

            #================funtion _h description =============
            def _h(name: str) -> str:
                return (hdrs_map.get(name) or hdrs_map.get(name.title()) or '').lower()

            ctype = _h('Content-Type')
            acao = _h('Access-Control-Allow-Origin')
            acac = _h('Access-Control-Allow-Credentials')
            cdisp = _h('Content-Disposition')
            loc_low = _h('Location')


            if issue.get('issue', '').startswith('Possible SQL injection'):
                try:
                    has_evidence = bool(self._has_sql_evidence(body))
                except Exception:
                    has_evidence = False


                if status in GENERIC_4XX or 'application/problem+json' in ctype:
                    if not has_evidence:
                        issue['severity'] = 'Info'
                        issue['issue'] = 'Possible SQL injection (blocked/validated)'
                        issue['description'] = 'Request rejected (4xx/problem+json) without SQL/DB error markers'
                        issue['confidence'] = issue.get('confidence') or 'low'
                    cleaned.append(issue)
                    continue


                if status >= 500 and not has_evidence:
                    issue['severity'] = 'Info'
                    issue['issue'] = 'Server error without SQL evidence'
                    issue['description'] = 'Generic 5xx response without SQL/DB markers'
                    cleaned.append(issue)
                    continue


                if not has_evidence:
                    continue


            if ('nosql' in desc_low) or issue.get('issue', '').lower().startswith('possible nosql'):

                if any(p in body_low for p in self.NOSQL_NEGATIVE_PATTERNS):
                    continue

                if status in GENERIC_4XX and 'application/json' in ctype:
                    issue['severity'] = 'Info'


            if desc_low.startswith('possible ssrf'):
                generic_err = ('connection refused', 'timed out', 'no route to host', 'dns error', 'invalid host')
                if any(g in body_low for g in generic_err) or status in {400, 404, 405}:
                    issue['severity'] = 'Info'


            if desc_low.startswith('possible access control bypass via spoofed header'):
                is_json = 'application/json' in ctype
                admin_hit = re.search('(?i)(<title>[^<]*admin[^<]*</title>|\\badmin\\s*panel\\b|href=["\\\']/admin)', body) is not None
                if is_json and (not loc_low):
                    issue['severity'] = 'Info'
                elif not admin_hit and '/admin' not in loc_low:
                    issue['severity'] = 'Info'


            if issue.get('issue', '').lower().startswith('broad cors policy'):
                is_static = ctype.startswith(('image/', 'video/', 'audio/', 'font/')) or 'application/octet-stream' in ctype or 'application/pdf' in ctype or ('filename=' in cdisp)
                if is_static and acac != 'true' and (issue.get('severity') in (None, 'Low', 'Info')):
                    continue

            if status == 404:


                if not any(s in body_low for s in (
                    'root:x:0:0:', 'daemon:x:', 'index of /', '<web-app', '[extensions]'
                )):
                    continue
                if issue.get('severity') in ('High', 'Critical'):
                    issue['severity'] = 'Info'

            if issue.get('status_code') == '-' or 'timeout' in err_low:
                issue['severity'] = 'Info'

            dedup_key = (issue.get('method'), issue.get('path') or issue.get('endpoint'),
                        issue.get('status_code'), issue.get('issue'), issue.get('payload'))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            cleaned.append(issue)

        self.issues = cleaned
        self._dedupe_issues()
        return self.issues


    #================funtion _filtered description =============
    def _filtered(self) -> list[dict]:
        return self._filter_issues()


    #================funtion _looks_like_secret description =============
    def _looks_like_secret(self, text: str) -> bool:
        if not text:
            return False
        t = text.strip()
        b64 = re.findall('[A-Za-z0-9+/=]{24,}', t)
        hx = re.findall('\\b[0-9a-fA-F]{32,}\\b', t)
        prefixes = ('AKIA', 'ASIA', 'sk_live_', 'sk_test_', 'xoxb-', 'xoxp-', 'ghp_', 'gho_', 'ghu_', 'eyJ')
        has_prefix = any((p in t for p in prefixes))

        #================funtion _entropy description =============
        def _entropy(s: str) -> float:
            from math import log2
            if not s:
                return 0.0
            from collections import Counter
            counts = Counter(s)
            n = len(s)
            return -sum((c / n * log2(c / n) for c in counts.values()))
        candidates = b64 + hx
        high_entropy = any((_entropy(c) >= 3.0 for c in candidates if len(c) >= 24))
        return bool(candidates) or has_prefix or high_entropy


    #================funtion _category_of_issue description =============
    def _category_of_issue(self, text: str) -> str:
        t = (text or '').lower()
        if 'sql injection' in t or 'sqli' in t:
            return 'SQLi'
        if 'nosql' in t:
            return 'NoSQLi'
        if 'directory traversal' in t:
            return 'Directory Traversal'
        if 'crlf' in t:
            return 'CRLF'
        if 'hpp' in t:
            return 'HPP'
        if 'sensitive data exposure' in t:
            return 'Sensitive Data Exposure'
        if 'graphql introspection' in t:
            return 'GraphQL'
        if 'host header' in t:
            return 'Header Manipulation'
        if 'access control bypass' in t:
            return 'Access Control'
        if 'cors' in t:
            return 'CORS'
        if 'docker remote api' in t:
            return 'Docker API'
        if 'kubernetes api' in t:
            return 'Kubernetes API'
        if 'smuggling' in t:
            return 'Request Smuggling'
        if 'xss' in t:
            return 'XSS'
        if 'open redirect' in t:
            return 'Open Redirect'
        if 'server error without sql evidence' in t:
            return 'Server Errors'
        if 'basic auth' in t or 'not found' in t or 'method not allowed' in t:
            return 'Baseline'
        return 'Other'


    #================funtion counts_by_category description =============
    def counts_by_category(self, include_info: bool=False) -> dict:
        out = {}
        for f in self.issues:
            sev = str(f.get('severity', '')).lower()
            if not include_info and sev == 'info':
                continue
            c = self._category_of_issue(f.get('issue', ''))
            out[c] = out.get(c, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))


    #================funtion generate_report description =============
    def generate_report(self) -> str:
        self._filter_issues()
        gen = ReportGenerator(issues=self.issues, scanner='SafeConsumption (API10)', base_url=self.base_url)
        return gen.generate_html()


    #================funtion save_report description =============
    def save_report(self, path: str, fmt: str='html') -> None:
        ReportGenerator(issues=self._filter_issues(), scanner='SafeConsumption (API10)', base_url=self.base_url).save(path, fmt=fmt)

    @staticmethod


    #================funtion xml_endpoints_from_openapi description =============
    def xml_endpoints_from_openapi(spec: dict, base_url: str, sec_cfg: 'OASSecurityConfig | None'=None) -> list[str]:
        if not globals().get('_HAS_OAS_UNIVERSAL', False):
            raise RuntimeError('openapi_universal is not available')
        eps: set[str] = set()
        for op in oas_iter_ops(spec):
            rb = op.get('requestBody') or {}
            content = rb.get('content') or {} if isinstance(rb, dict) else {}
            cts = {ct.lower() for ct in content.keys()} if isinstance(content, dict) else set()
            accepts_xml = any((ct in cts for ct in ('application/xml', 'text/xml', 'application/soap+xml')))
            if not accepts_xml:
                continue
            try:
                req = oas_build_request(spec, base_url, op, sec_cfg)
                url = req.get('url')
                if isinstance(url, str) and url:
                    eps.add(url.rstrip('/'))
            except Exception:
                continue
        return sorted(eps)


    #================funtion _test_directory_traversal description =============
    def _test_directory_traversal(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parts = urlparse.urlsplit(endpoint)
            base_path = parts.path or '/'
            if not base_path or base_path == '/':
                return
            domain = parts.netloc or parts.hostname or ''
            #================funtion join description =============
            def join(path):
                return urlparse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))

            seeds = [base_path.rstrip('/'), base_path.rstrip('/') + '/']
            variants = set()
            for s in seeds:
                for inj in ('./', '../', '..%2F', '%2e/', '%2e%2e/', '%2e%2e%2f', '..%252f'):
                    variants.add(s + inj)

            suffixes = ['etc/passwd', 'WEB-INF/web.xml', 'windows/win.ini']
            test_urls = []
            for v in variants:
                p = v if v.endswith('/') else v + '/'
                for suf in suffixes:
                    test_urls.append(join(p + suf))

            strong = ['root:x:0:0:', 'daemon:x:1:1:', 'Index of /', '<title>Index of', 'Parent Directory', 'Directory listing for', 'Directory of ', '[extensions]', 'for 16-bit app support']
            weak = ['/etc/passwd', 'bin:x:', 'boot.ini', '\\Windows\\', 'WEB-INF/web.xml']

            #================funtion looks_interesting description =============
            def looks_interesting(text: str):
                if not text:
                    return (False, 'none')
                low = text.lower()
                for s in strong:
                    if s.lower() in low:
                        return (True, 'high')
                wc = sum(1 for w in weak if w.lower() in low)
                if wc >= 2:
                    return (True, 'medium')
                if wc == 1 and (('href="' in low) or ('>../<' in low) or ('>..</a>' in low)):
                    return (True, 'medium')
                return (False, 'none')

            for u in test_urls:
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    hdrs = dict(getattr(self.session, 'headers', {}))
                    hdrs['X-APISCAN-Payload'] = u
                    r = self.session.get(u, headers=hdrs, timeout=(3, getattr(self, 'timeout', 10)), allow_redirects=False)
                    body = r.text or ''
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    if ctype.startswith(('image/','video/','audio/')) or 'application/octet-stream' in ctype:
                        continue

                    low = body.lower()
                    if r.status_code in (401, 403) and any(t in low for t in ('invalid token','unauthorized','authentication')):
                        continue
                    if 'application/json' in ctype and r.status_code >= 400:
                        continue

                    interesting, conf = looks_interesting(body)
                    if not interesting:
                        continue

                    if r.status_code == 200:
                        sev = 'High' if conf == 'high' else ('Medium' if conf == 'medium' else 'Low')
                    elif r.status_code in (301,302,307,308) and any(k in (r.headers.get('Location','').lower()) for k in ('../','%2e%2e','etc/passwd','web-inf')):
                        sev = 'Medium'
                    else:
                        sev = 'Low'

                    self._log('Directory traversal (suffix)', u, sev, payload=u, response=r,
                              extra={'vector':'dirtrav','base_endpoint': endpoint, 'confidence': conf, 'request_body_preview': None})
                except Exception as e:
                    self._log('Directory traversal request error', u, 'Info', extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint})
        except Exception as e:
            self._log('Directory traversal test setup failed', endpoint, 'Info', extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint})


    #================funtion _is_injection_successful description =============
    def _is_injection_successful(
        self,
        response: requests.Response,
        attack_type: str,
        *,
        baseline_latency: float = 0.5,
        payload: str = ''
    ) -> bool:
        if response is None:
            return False

        try:
            status = int(getattr(response, 'status_code', 0))
        except Exception:
            status = 0

        text = response.text or ''
        low = text.lower()


        if status in {400, 422} and self._is_parse_error(response):
            return False


        if attack_type == 'nosql':
            if any(p in low for p in self.NOSQL_NEGATIVE_PATTERNS):
                return False


        if attack_type == 'sql':
            if self._has_sql_evidence(text):
                return True
            try:
                elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0
            except Exception:
                elapsed = 0.0
            return False


        if status >= 500:
            if attack_type == 'nosql':
                return any((k in low for k in self.NOSQL_ERROR_KEYWORDS)) or self._has_engine_marker(low, 'nosql')
            if attack_type in {'ssti', 'ldap', 'xxe'}:
                return self._has_engine_marker(low, attack_type)
            return False


        if attack_type == 'nosql':
            specific = any((re.search(p, low) for p in ('mongo.*error', 'mongodb.*error', 'bson.*error')))
            keywords = any((k in low for k in self.NOSQL_ERROR_KEYWORDS))
            return specific or keywords or self._has_engine_marker(low, 'nosql')


        if attack_type == 'xss':
            if not payload or payload.lower() not in low:
                return False
            return any((s in text for s in (f'="{payload}"', f'>{payload}<', f"'{payload}'", f'`{payload}`'))) or self._is_payload_reflected(text, payload)


        if attack_type == 'xxe':
            ctype = (response.headers.get('Content-Type') or '').lower()
            CONTENT_MARKERS = ('root:x:0:0:', 'daemon:x:', '/bin/bash', 'for 16-bit app support', '[extensions]')
            PATH_ONLY_MARKERS = ('/etc/passwd', '/etc/hosts', 'c:\\\\windows\\\\win.ini', 'file:///etc/passwd', 'file:///etc/hosts')

            if any(ind in low for ind in CONTENT_MARKERS):
                if not ('text/html' in ctype and '<html' in low):
                    return True
            if any(ind in low for ind in PATH_ONLY_MARKERS):
                return False

            blocked_patterns = (r'doctype.*(disallowed|prohibit|denied)', r'entity\\s+.*(not\\s+defined|cannot\\s+be\\s+resolved)')
            if any((re.search(pat, low) for pat in blocked_patterns)):
                return False

            specific = any((re.search(p, low) for p in (r'xxe', r'xml.*parser.*error', r'entity.*reference', r'doctype.*not.*allowed')))
            return specific or self._has_engine_marker(low, 'xxe')

        return False

    #================funtion _filter_issues description =============
    def _filter_issues(self) -> list[dict]:
        cleaned, seen = ([], set())

        IGNORE_TIMEOUTS = bool(getattr(self, 'IGNORE_NETWORK_TIMEOUTS', True))
        NETWORK_TIMEOUT_PATTERNS = tuple(getattr(self, 'NETWORK_TIMEOUT_PATTERNS', (
            'httpconnectionpool', 'read timed out', 'connect timeout', 'connecttimeout',
            'write timeout', 'newconnectionerror', 'failed to establish a new connection',
            'max retries exceeded', 'temporarily unavailable', 'winerror 10060', 'winerror 10061'
        )))
        GENERIC_4XX = {400, 401, 403, 404, 405, 406, 409, 415, 422, 429}

        for issue in self.issues:
            desc_text = str(issue.get('description', ''))
            desc_low = desc_text.lower()
            err_low = str(issue.get('error', '')).lower()
            body = issue.get('response_body') or ''
            body_low = body.lower()

            if 'failed to parse' in desc_low or "name 'parsed' is not defined" in desc_low:
                continue

            if any(p in err_low for p in NETWORK_TIMEOUT_PATTERNS):
                if IGNORE_TIMEOUTS:
                    continue
                else:
                    issue['severity'] = 'Info'

            try:
                status = int(issue.get('status_code', 0))
            except (ValueError, TypeError):
                status = 0

            hdrs_map = {}
            rh = issue.get('response_headers')
            if isinstance(rh, dict):
                hdrs_map = {str(k): str(v) for k, v in rh.items()}
            elif isinstance(rh, list):
                hdrs_map = {str(k): str(v) for k, v in rh}
            else:
                rh_list = issue.get('response_headers_list') or []
                try:
                    hdrs_map = {str(k): str(v) for k, v in rh_list}
                except Exception:
                    hdrs_map = {}

            #================funtion _h description =============
            def _h(name: str) -> str:
                return (hdrs_map.get(name) or hdrs_map.get(name.title()) or '').lower()

            ctype = _h('Content-Type')
            acao = _h('Access-Control-Allow-Origin')
            acac = _h('Access-Control-Allow-Credentials')
            cdisp = _h('Content-Disposition')
            loc_low = _h('Location')


            if issue.get('issue', '').startswith('Possible SQL injection'):
                try:
                    has_evidence = bool(self._has_sql_evidence(body))
                except Exception:
                    has_evidence = False


                if status in GENERIC_4XX or 'application/problem+json' in ctype:
                    if not has_evidence:
                        issue['severity'] = 'Info'
                        issue['issue'] = 'Possible SQL injection (blocked/validated)'
                        issue['description'] = 'Request rejected (4xx/problem+json) without SQL/DB error markers'
                        issue['confidence'] = issue.get('confidence') or 'low'
                    cleaned.append(issue)
                    continue


                if status >= 500 and not has_evidence:
                    issue['severity'] = 'Info'
                    issue['issue'] = 'Server error without SQL evidence'
                    issue['description'] = 'Generic 5xx response without SQL/DB markers'
                    cleaned.append(issue)
                    continue


                if not has_evidence:
                    continue


            if ('nosql' in desc_low) or issue.get('issue', '').lower().startswith('possible nosql'):
                if any(p in body_low for p in self.NOSQL_NEGATIVE_PATTERNS):
                    continue
                if status in GENERIC_4XX and 'application/json' in ctype:
                    issue['severity'] = 'Info'


            issue_name = (issue.get('issue') or '').lower()
            if issue_name.startswith('directory traversal'):
                confidence = (issue.get('confidence') or '').lower()
                if status in (401, 403) and any(s in body_low for s in ('unauthorized', 'invalid token', 'authentication')):
                    if confidence != 'high':
                        continue
                if 'application/json' in ctype and status >= 400 and confidence != 'high':
                    continue
                if confidence == 'low' and issue.get('severity') in ('High', 'Medium'):
                    issue['severity'] = 'Low'


            if desc_low.startswith('possible ssrf'):
                generic_err = ('connection refused', 'timed out', 'no route to host', 'dns error', 'invalid host')
                if any(g in body_low for g in generic_err) or status in {400, 404, 405}:
                    issue['severity'] = 'Info'


            if desc_low.startswith('possible access control bypass via spoofed header'):
                is_json = 'application/json' in ctype
                admin_hit = re.search('(?i)(<title>[^<]*admin[^<]*</title>|\\badmin\\s*panel\\b|href=[\"\\\']/admin)', body) is not None
                if is_json and (not loc_low):
                    issue['severity'] = 'Info'
                elif not admin_hit and '/admin' not in loc_low:
                    issue['severity'] = 'Info'


            if issue.get('issue', '').lower().startswith('broad cors policy'):
                is_static = ctype.startswith(('image/', 'video/', 'audio/', 'font/')) or 'application/octet-stream' in ctype or 'application/pdf' in ctype or ('filename=' in cdisp)
                if is_static and acac != 'true' and (issue.get('severity') in (None, 'Low', 'Info')):
                    continue

            if status == 404:


                if not any(s in body_low for s in (
                    'root:x:0:0:', 'daemon:x:', 'index of /', '<web-app', '[extensions]'
                )):
                    continue
                if issue.get('severity') in ('High', 'Critical'):
                    issue['severity'] = 'Info'

            if issue.get('status_code') == '-' or 'timeout' in err_low:
                issue['severity'] = 'Info'

            dedup_key = (issue.get('method'), issue.get('path') or issue.get('endpoint'), issue.get('status_code'), issue.get('issue'), issue.get('payload'))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            cleaned.append(issue)

        self.issues = cleaned
        self._dedupe_issues()
        return self.issues
