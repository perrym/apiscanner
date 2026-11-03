########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 07-07-2026                               #
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
import hashlib
import hmac
import base64
import sys
from collections import defaultdict
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import requests
import urllib.parse as urlparse
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from report_utils import ReportGenerator
from urllib.parse import urlsplit as _pt_urlsplit, urlunsplit as _pt_urlunsplit, parse_qs
import io
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import httpx
    _HAS_HTTPX = True
except Exception:
    httpx = None
    _HAS_HTTPX = False
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
# Input or baseline prevented the test from starting; not an execution failure.
UNTESTED_ISSUES = frozenset(('SQL baseline unsuitable', 'SQL request input unavailable',
                             'SQL test unavailable', 'NoSQL baseline unsuitable'))

os.environ.setdefault('APISCAN_MAX_WORKERS', '6')
os.environ.setdefault('APISCAN_TIMEOUT', '2')
os.environ.setdefault('APISCAN_RATE_LIMIT', '0')
os.environ.setdefault('APISCAN_DEEP_SCAN', '0')
os.environ.setdefault('APISCAN_FAST', '1')
os.environ.setdefault('APISCAN_PARAM_DISCOVERY', '1')
os.environ.setdefault('APISCAN_STATEFUL', '0')
os.environ.setdefault('APISCAN_INTENSITY', 'medium')
os.environ.setdefault('APISCAN_ADAPTIVE', '1')
os.environ.setdefault('APISCAN_NO_TQDM', '0')
os.environ.setdefault('APISCAN_PHASE1_SAMPLE', '20')
os.environ.setdefault('APISCAN_API10_QUICK', '1')
os.environ.setdefault('APISCAN_API10_QUICK_MAX_ENDPOINTS', '30')
os.environ.setdefault('APISCAN_API10_QUICK_SQL_MAX_TESTS', '10')
os.environ.setdefault('APISCAN_API10_QUICK_DIRTRAV_MAX_TESTS', '8')
os.environ.setdefault('APISCAN_API10_QUICK_HPP_MAX_PARAMS', '3')
os.environ.setdefault('APISCAN_API10_QUICK_REDIRECT_MAX_TESTS', '6')
os.environ.setdefault('APISCAN_HTTP_RETRIES', '0')
os.environ.setdefault('APISCAN_DIRTRAV_PROGRESS', '0')
os.environ.setdefault('APISCAN_DIRTRAV_WORKERS', '6')
os.environ.setdefault('APISCAN_TRAV_MAX_DDOT', '2')        # was 3; fewer traversal variants
os.environ.setdefault('APISCAN_TRAV_MAX_ELLIPSIS', '1')    # was 2; fewer ellipsis variants
os.environ.setdefault("APISCAN_PAYLOADS_PATH", r"data/injection_payloads_fast.json")
# full payload scan (slower, more thorough): # os.environ.setdefault("APISCAN_PAYLOADS_PATH", r"data/injection_payloads.json")




#================ _pt_normalize_url description ##########


def _pt_normalize_url(u: str) -> str:
    if '://' not in u:
        u = 'https://' + u.lstrip('/')
    return u


#================ build_traversal_variants_segment_replace description ##########


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


    #================ join_segments description ##########
    def join_segments(_lead, _segs):
        out = '/'.join(_segs)
        if _lead == '':
            out = '/' + out
        return out or '/'


    #================ replace_with description ##########
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


#================ _encode_siblings description ##########


def _encode_siblings(v: str) -> list[str]:
    parts = _pt_urlsplit(v)
    path = parts.path or '/'

    def with_path(encoded_path: str) -> str:
        return _pt_urlunsplit((parts.scheme, parts.netloc, encoded_path, parts.query, parts.fragment))

    out: list[str] = []
    out.append(with_path(path.replace('.', '%2e')))
    out.append(with_path(path.replace('/', '%2f')))
    out.append(with_path(path.replace('.', '%2e').replace('/', '%2f')))
    return out


#================ build_traversal_variants_insert_between description ##########


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


    #================ join_segments description ##########
    def join_segments(_lead, _segs):
        out = '/'.join(_segs)
        if _lead == '':
            out = '/' + out
        return out or '/'


    #================ insert_with description ##########
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


#================ listen_for_quit description ##########


def listen_for_quit():
    if not sys.stdin.isatty():
        return
    print(f"\n  {Colors.CYAN}\u25c6{Colors.RESET}  {Colors.YELLOW}Press {Colors.WHITE}Q{Colors.RESET}{Colors.YELLOW} + Enter at any time to stop scanning gracefully{Colors.RESET}\n")
    while not stop_requested.is_set():
        try:
            inp = sys.stdin.readline().strip().lower()
            if inp == 'q':
                stop_requested.set()
                print(f'\n  {Colors.RED}\u2716{Colors.RESET}  {Colors.RED}Stop requested{Colors.RESET} \u2014 finishing active tasks ...\n')
                break
        except (EOFError, OSError):
            break

os.environ['APISCAN_ENABLE_CONSOLE_STOP'] = '1'
if os.getenv('APISCAN_ENABLE_CONSOLE_STOP', '0') == '1':
    listener_thread = threading.Thread(target=listen_for_quit, daemon=True)
    listener_thread.start()


#================ _headers_to_list description ##########


def _resolve_schema_ref(spec, schema, depth=0):
    # Follow local $ref pointers and composed schemas to the object that declares properties.
    while isinstance(schema, dict) and '$ref' in schema and depth < 8:
        ref = schema['$ref']
        if not isinstance(ref, str) or not ref.startswith('#/'):
            return {}
        target = spec
        try:
            for part in ref[2:].split('/'):
                target = target[part.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError):
            return {}
        schema, depth = target, depth + 1
    if isinstance(schema, dict) and not schema.get('properties') and depth < 8:
        for key in ('allOf', 'oneOf', 'anyOf'):
            for part in schema.get(key) or []:
                resolved = _resolve_schema_ref(spec, part, depth + 1)
                if resolved.get('properties'):
                    return resolved
    return schema if isinstance(schema, dict) else {}


def _headers_to_list(headerobj):
    if hasattr(headerobj, 'getlist'):
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())


class ProgressBar:

    #================ __init__ description ##########
    def __init__(self, total, desc="", unit="it"):
        self.total = total
        self.desc = desc
        self.unit = unit
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0
        self.width = 50


    #================ update description ##########
    def update(self, n=1):
        self.current += n
        self._display()


    #================ _display description ##########
    def _display(self):
        now = time.time()
        if now - self.last_update < 0.1 and self.current < self.total:
            return

        self.last_update = now
        elapsed = now - self.start_time

        if self.total > 0:
            percent = (self.current / self.total) * 100
            filled = int(self.width * self.current // self.total)
            bar = '#' * filled + '-' * (self.width - filled)

            if self.current > 0:
                eta = (elapsed / self.current) * (self.total - self.current)
                eta_str = f"ETA: {eta:.1f}s"
            else:
                eta_str = "ETA: ?"

            # Use \\n when stdout is not a TTY (GUI/pipe) so readline()
            # can consume the line immediately.  \\r is only safe on real terminals.
            end_char = '\r' if sys.stdout.isatty() else '\n'
            sys.stdout.write(f'{end_char}{self.desc}: |{bar}| {percent:.1f}% ({self.current}/{self.total}) '
                           f'[{elapsed:.1f}s, {eta_str}]')
            sys.stdout.flush()

            if self.current >= self.total:
                sys.stdout.write('\n')
                sys.stdout.flush()


    #================ close description ##########
    def close(self):
        if self.current < self.total:
            self.current = self.total
            self._display()


    #================ __enter__ description ##########
    def __enter__(self):
        return self


    #================ __exit__ description ##########
    def __exit__(self, *args):
        self.close()


class HttpxSessionWrapper:
    #================ __init__ description ##########
    def __init__(
        self,
        *,
        headers: dict[str, str] | None = None,
        http2: bool = False,
        retries: int = 2,
        status_forcelist: set[int] | None = None,
        verify: bool = True,
        max_connections: int = 400,
        max_keepalive: int = 400,
    ) -> None:
        if not _HAS_HTTPX:
            raise RuntimeError("httpx is not available, cannot use HTTP/2 client")

        self._retries = max(0, int(retries))
        self._status_forcelist = status_forcelist or {500, 502, 503}
        limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_keepalive)
        self._client = httpx.Client(http2=http2, headers=headers or {}, verify=verify, limits=limits, follow_redirects=False)

    #================ close description ##########
    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    #================ _to_httpx_timeout description ##########
    @staticmethod
    def _to_httpx_timeout(timeout: object) -> "httpx.Timeout | None":
        if timeout is None:
            return None
        if isinstance(timeout, (int, float)):
            return httpx.Timeout(timeout)
        if isinstance(timeout, tuple) and len(timeout) >= 2:
            connect_t = timeout[0]
            read_t = timeout[1]
            try:
                return httpx.Timeout(connect=connect_t, read=read_t, write=read_t, pool=connect_t)
            except Exception:
                return httpx.Timeout(None)
        return None

    #================ request description ##########
    def request(self, method: str, url: str, **kwargs):
        allow_redirects = bool(kwargs.pop("allow_redirects", False))
        timeout = self._to_httpx_timeout(kwargs.pop("timeout", None))
        kwargs.setdefault("follow_redirects", allow_redirects)
        if timeout is not None:
            kwargs["timeout"] = timeout

        for attempt in range(self._retries + 1):
            try:
                resp = self._client.request(method, url, **kwargs)
                if resp.status_code in self._status_forcelist and attempt < self._retries:
                    continue
                return resp
            except Exception:
                if attempt >= self._retries:
                    raise
        raise RuntimeError("unreachable")

    #================ get description ##########
    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    #================ post description ##########
    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    #================ options description ##########
    def options(self, url: str, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

class SafeConsumptionAuditor:
    NOSQL_NEGATIVE_PATTERNS = (
        'mongo: no documents in result',
        'no documents in result',
        'document not found',
        'no such document',
    )

    JWT_PAYLOADS = [
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0',
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY7ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.',
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0'
    ]

    RATE_LIMIT_BYPASS_HEADERS = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '192.168.1.1'},
        {'X-Originating-IP': '10.0.0.1'},
        {'X-Client-IP': '172.16.0.1'},
        {'X-Remote-IP': '169.254.0.1'},
        {'X-Remote-Addr': 'fd00::1'},
        {'X-Cluster-Client-IP': '100.64.0.1'}
    ]

    SSRF_ADVANCED_PAYLOADS = [
        "gopher://127.0.0.1:80/_GET%20/",
        "dict://127.0.0.1:6379/info",
        "file:///etc/passwd",
        "ldap://127.0.0.1:389",
        "tftp://127.0.0.1:69/test",
        "sftp://localhost:22/etc/passwd"
    ]

    BUSINESS_LOGIC_PAYLOADS = [
        {'price': -999999.99, 'quantity': 100},
        {'quantity': 9999999999},
        {'discount': 150.0},
        {'amount': 0.0000001},
        {'balance': '-999999999'},
        {'status': 'approved'},
        {'role': 'admin'},
        {'is_admin': True},
        {'email_verified': True},
        {'permissions': ['*']}
    ]


    #================ _encode_siblings description ##########
    def _encode_siblings(self, v: str) -> list[str]:
        out: list[str] = []
        out.append(v.replace('/./', '/.%2f/').replace('./', '.%2f'))
        out.append(v.replace('/../', '/..%2f/').replace('../', '..%2f'))
        out.append(v.replace('/./', '/%2e/').replace('./', '%2e/'))
        out.append(v.replace('/../', '/%2e%2e/').replace('../', '%2e%2e/'))
        out.append(v.replace('/./', '/%252e/').replace('./', '%252e/'))
        out.append(v.replace('/../', '/%252e%252e/').replace('../', '%252e%252e/'))
        return out


    #================ _dirtrav_body_vectors description ##########
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


    #================ __init__ description ##########
    def __init__(self, base_url: str, session: Optional[requests.Session]=None, *, timeout: Optional[int]=None, rate_limit: Optional[float]=None, log_monitor: Optional[Callable[[Dict[str, Any]], None]]=None) -> None:
        self.timeout = timeout if timeout is not None else int(os.getenv('APISCAN_TIMEOUT', '3'))
        self.rate_limit = rate_limit if rate_limit is not None else float(os.getenv('APISCAN_RATE_LIMIT', '1.0'))
        default_max_workers = 6
        configured_max_workers = int(os.getenv('APISCAN_MAX_WORKERS', str(default_max_workers)))
        allow_low_workers = os.getenv('APISCAN_ALLOW_LOW_WORKERS', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.max_workers = configured_max_workers if allow_low_workers else max(default_max_workers, configured_max_workers)
        self.base_url: str = base_url.rstrip('/')
        self.session: requests.Session = session or self._create_secure_session()
        # Ensure 5xx responses are returned as-is instead of being retried
        # into oblivion by a parent session's status_forcelist (causes all
        # findings to be lost as telemetry-only when endpoints don't exist).
        try:
            _retry = Retry(total=0, status_forcelist=[], raise_on_status=False)
            _adapter = HTTPAdapter(max_retries=_retry, pool_connections=400, pool_maxsize=400, pool_block=False)
            self.session.mount('http://', _adapter)
            self.session.mount('https://', _adapter)
        except Exception:
            pass
        self.log_monitor = log_monitor
        self.server_log_provider: Optional[Callable[[], List[str]]] = None
        self.fast_mode = os.getenv('APISCAN_FAST', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.deep_scan = os.getenv('APISCAN_DEEP_SCAN', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.param_discovery = os.getenv('APISCAN_PARAM_DISCOVERY', '1').strip().lower() in ('1', 'true', 'yes', 'on')
        self.stateful = os.getenv('APISCAN_STATEFUL', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        self.adaptive = os.getenv('APISCAN_ADAPTIVE', '1').strip().lower() in ('1', 'true', 'yes', 'on')
        self.quick_mode = os.getenv('APISCAN_API10_QUICK', '1').strip().lower() in ('1', 'true', 'yes', 'on')
        self.quick_max_endpoints = max(1, int(os.getenv('APISCAN_API10_QUICK_MAX_ENDPOINTS', '20')))
        self.quick_sql_max_tests = max(1, int(os.getenv('APISCAN_API10_QUICK_SQL_MAX_TESTS', '10')))
        self.quick_dirtrav_max_tests = max(1, int(os.getenv('APISCAN_API10_QUICK_DIRTRAV_MAX_TESTS', '8')))
        self.quick_hpp_max_params = max(1, int(os.getenv('APISCAN_API10_QUICK_HPP_MAX_PARAMS', '3')))
        self.quick_redirect_max_tests = max(1, int(os.getenv('APISCAN_API10_QUICK_REDIRECT_MAX_TESTS', '6')))
        self.intensity = os.getenv('APISCAN_INTENSITY', 'medium').lower()
        # Honor TQDM_DISABLE (set by GUI subprocess) â€” tqdm carriage returns
        # block line-buffered pipe readers; use ProgressBar fallback instead.
        self.no_tqdm = (
            os.getenv('APISCAN_NO_TQDM', '0').strip().lower() in ('1', 'true', 'yes', 'on')
            or os.getenv('TQDM_DISABLE', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        )
        self.triage_payloads_per_type = 2 if self.fast_mode else 6 if self.intensity == 'low' else 12 if self.intensity == 'medium' else 24
        # Deep scan auto-override: full payloads, high intensity, no quick mode
        if self.deep_scan:
            if self.intensity == 'medium':
                self.intensity = 'high'
            if self.quick_mode:
                self.quick_mode = False
            if self.fast_mode:
                self.fast_mode = False
            # Switch to full payload file unless user explicitly set a custom path
            _user_payload = os.getenv('APISCAN_PAYLOADS_PATH', '').strip()
            if not _user_payload or 'fast' in _user_payload.lower():
                os.environ['APISCAN_PAYLOADS_PATH'] = 'data/injection_payloads.json'
        self.phase1_sample = max(1, int(os.getenv('APISCAN_PHASE1_SAMPLE', '20')))
        configured_per_host = int(os.getenv('APISCAN_PER_HOST', '6'))
        self.per_host_max_concurrency = configured_per_host if allow_low_workers else max(default_max_workers, configured_per_host)
        self.host_semaphores: defaultdict[str, threading.BoundedSemaphore] = defaultdict(lambda: threading.BoundedSemaphore(self.per_host_max_concurrency))
        self.last_request_ts: defaultdict[str, float] = defaultdict(lambda: 0.0)
        self.issues: List[Dict[str, Any]] = []
        self.issues_lock = threading.Lock()
        self.telemetry: List[Dict[str, Any]] = []
        self.telemetry_lock = threading.Lock()
        self.canary_domain: str = os.getenv('APISCAN_CANARY', '').strip('.')
        self.endpoint_cache = {}
        self.param_cache = {}
        self._options_cache: dict[str, set] = {}
        self._options_cache_lock = threading.Lock()
        # Traversal config cached once â€” read in every _test_directory_traversal call otherwise
        self._trav_repl_index    = int(os.getenv('APISCAN_TRAV_REPLACE_INDEX',        '-2'))
        self._trav_ins_before    = int(os.getenv('APISCAN_TRAV_INSERT_BEFORE_INDEX',  '-1'))
        self._trav_max_dot       = int(os.getenv('APISCAN_TRAV_MAX_DOT',              '3'))
        self._trav_max_ddot      = int(os.getenv('APISCAN_TRAV_MAX_DDOT',             '3'))
        self._trav_max_ellipsis  = int(os.getenv('APISCAN_TRAV_MAX_ELLIPSIS',         '2'))
        self._dirtrav_progress   = os.getenv('APISCAN_DIRTRAV_PROGRESS', '0') == '1'
        self._dirtrav_workers_env = os.getenv('APISCAN_DIRTRAV_WORKERS')
        env_payloads = os.getenv("APISCAN_PAYLOADS_PATH", "").strip()
        base = Path(__file__).resolve().parent

        def resolve_payload(p: str) -> Path:
            if not p:
                raise FileNotFoundError(
                    "APISCAN_PAYLOADS_PATH is not set or empty. "
                    "Expected e.g. 'data/injection_payloads_fast.json' "
                    "or 'data/injection_payloads.json'."
                )

            path = Path(p)
            if not path.is_absolute():
                path = (base / path).resolve()
            else:
                path = path.resolve()

            if not path.is_file():
                raise FileNotFoundError(f"Payload file not found: {path}")

            return path

        try:
            json_path = resolve_payload(env_payloads)
        except FileNotFoundError as e:
            print(f"  \033[91m\u2716\033[0m  \033[91mError\033[0m  Config: {e}")
            sys.exit(1)

        _mode_tag = ""
        if self.deep_scan:
            _mode_tag = "  \033[95m[deep mode]\033[0m"
        elif self.quick_mode and self.fast_mode:
            _mode_tag = "  \033[93m[quick + fast mode]\033[0m"
        elif self.quick_mode:
            _mode_tag = "  \033[93m[quick mode]\033[0m"
        elif self.fast_mode:
            _mode_tag = "  \033[93m[fast mode]\033[0m"
        print(f"  \033[96m\u25c6\033[0m  \033[96mInfo\033[0m  Payload file: {json_path}{_mode_tag}")

                
        
        
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
            self.OPEN_REDIRECT_PAYLOADS = payloads_data.get('open_redirect_payloads', [])
            self.HOST_HEADER_PAYLOADS = payloads_data.get('host_header_payloads', [])
            self.FORWARDED_HEADER_SETS = payloads_data.get('forwarded_header_sets', [])
            self.GRAPHQL_EXTRA_QUERIES = payloads_data.get('graphql_extra_queries', [])
            self.JWT_ERROR_KEYWORDS = payloads_data.get('jwt_error_keywords', [
                'jwt', 'token invalid', 'signature invalid', 'malformed token',
                'token expired', 'invalid signature', 'alg none'
            ])
            self.BOLA_PATTERNS = payloads_data.get('bola_patterns', [
                'access denied', 'unauthorized', 'forbidden', 'not your resource'
            ])

        except (KeyError, json.JSONDecodeError) as e:
            print(f'{Colors.RED}Error parsing JSON payload file: {e}{Colors.RESET}')
            sys.exit(1)


        self.DB_SPECIFIC_PATTERNS = {
            'mysql': ['mysql_error', 'mysqli_', 'you have an error in your sql syntax',
                     'mysql server version', 'for the right syntax to use'],
            'postgres': ['postgresql error', 'pg_', 'syntax error at position',
                        'postgresql', 'pqexec', 'libpq'],
            'oracle': ['ora-', 'pl/sql', 'oracle error', 'ora_', 'oracle.*exception'],
            'mssql': ['microsoft sql server', 'sqlserver', 'incorrect syntax near',
                     'sql server', 'odbc sql server', 'sqlcmd'],
            'sqlite': ['sqlite error', 'sqlite3.', 'sqlite exception', 'sqlite3 error']
        }


        self.TIME_PATTERNS = [
            r'(\d+)\s*second',
            r'delay\s*[\'"]?\d+',
            r'benchmark\([^)]+\)',
            r'pg_sleep',
            r'sleep\(',
            r'waitfor\s+delay'
        ]

        self._print_banner()
        print(f"  \033[96m\u25c6\033[0m  \033[96mInfo\033[0m  Auditor ready  \033[2m{self.base_url}  timeout={self.timeout}s  workers={self.max_workers}  intensity={self.intensity}\033[0m")
        if self.deep_scan:
            print(f"  \033[93m\u25b2\033[0m  \033[93mWarn\033[0m  Deep scan enabled")
        if self.adaptive:
            print(f"  \033[93m\u25b2\033[0m  \033[93mWarn\033[0m  Adaptive scanning enabled")
        print()


    #================ _print_banner description ##########
    def _print_banner(self):
        _C = '\033[96m'; _R = '\033[0m'; _D = '\033[2m'
        print(f"\n  {_C}\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{_R}")
        print(f"  {_C}\u25b6{_R}  \033[1m\033[97mAPI10{_R}  {_C}Unsafe Consumption of APIs{_R}  {_D}v5.5{_R}")
        print(f"  {_C}\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{_R}")

    #================ _create_secure_session description ##########
    @staticmethod

    def _create_secure_session() -> requests.Session:
        use_http2 = os.getenv('APISCAN_HTTP2', '0').strip().lower() in ('1', 'true', 'yes', 'on')
        verify_tls = os.getenv('APISCAN_TLS_VERIFY', '1').strip().lower() in ('1', 'true', 'yes', 'on')

        headers = {
            'User-Agent': 'safe_consumption_enhanced/5.0',
            'Accept': 'application/json, */*;q=0.1',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        # Prefer modern HTTP/2 stack when requested: httpx (h2-based)
        if use_http2 and _HAS_HTTPX:
            try:
                return HttpxSessionWrapper(
                    headers=headers,
                    http2=True,
                    retries=max(0, int(os.getenv('APISCAN_HTTP_RETRIES', '0'))),
                    status_forcelist={500, 502, 503},
                    verify=verify_tls,
                    max_connections=400,
                    max_keepalive=400,
                )
            except Exception:
                pass

        # Fallback: requests (HTTP/1.1)
        s = requests.Session()
        retry_total = max(0, int(os.getenv('APISCAN_HTTP_RETRIES', '0')))
        retries = Retry(
            total=retry_total,
            connect=retry_total,
            read=0,
            status=0,
            backoff_factor=0.2,
            status_forcelist=[],
            allowed_methods=['HEAD', 'GET', 'OPTIONS'],
            raise_on_status=False,
            raise_on_redirect=False,
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=400, pool_maxsize=400, pool_block=False)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.headers.update(headers)
        s.verify = verify_tls
        return s
    #================ _throttle description ##########
    def _throttle(self, domain: str) -> None:
        sem = self.host_semaphores[domain]
        acquired = sem.acquire(timeout=30)
        if not acquired:
            return
        try:
            now = time.perf_counter()
            delta = now - self.last_request_ts[domain]
            wait = max(0.0, self.rate_limit - delta)
            self.last_request_ts[domain] = max(self.last_request_ts[domain], now + wait)
        finally:
            sem.release()
        if wait > 0:
            time.sleep(wait)

    #================ _safe_body description ##########
    @staticmethod

    def _safe_body(data: Any) -> str:
        if data is None:
            return ''
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8', 'replace')
            except Exception:
                return f'<<{len(data)} bytes>>'
        return str(data)

    #================ _record_telemetry description ##########
    def _record_telemetry(self, issue: str, target: str, *, payload=None, extra=None, response=None) -> None:
        from probe_policy import ProbeSkipped, SKIP_REASONS
        # Existing probe handlers record exceptions here. Propagate policy skips
        # out of those handlers so their payload loops stop immediately.
        state = getattr(self, '_execution_state', None)
        if extra and extra.get('error') in SKIP_REASONS:
            if state is not None and getattr(state, 'planning', False):
                # Planning controls may encounter a route already bounded by probes.
                # The policy retains its unique diagnostic; do not abort the scan.
                return
            raise ProbeSkipped(extra['error'])
        untested = issue in UNTESTED_ISSUES
        if state is not None and untested:
            state.untested = True
        elif state is not None and (extra and extra.get('error') or 'invalid host' in issue.lower()):
            state.failed = True
        entry = {
            'issue': issue,
            'target': target,
            'payload': payload if payload is not None else '',
            'timestamp': datetime.now().isoformat(),
        }
        if untested:
            entry['execution_status'] = 'untested'
        if extra:
            entry.update(extra)
        if response is not None:
            try:
                entry['status_code'] = int(getattr(response, 'status_code', 0))
                entry['response_content_type'] = response.headers.get('Content-Type', '')
            except Exception:
                pass
        try:
            parsed = urlparse.urlparse(target)
            entry.setdefault('url', target)
            entry.setdefault('endpoint', parsed.path or '/')
        except Exception:
            entry.setdefault('url', target)
        with self.telemetry_lock:
            self.telemetry.append(entry)


    #================ _log description ##########
    def _log(self, issue: str, target: str, severity: str, *, payload=None, response=None, extra=None) -> None:
        if issue == 'Request smuggling test borderline/timeout':
            diagnostic = dict(extra or {})
            diagnostic['execution_status'] = 'inconclusive'
            diagnostic['error'] = 'Timeout or delayed response alone does not establish request smuggling'
            self._record_telemetry(issue, target, payload=payload, extra=diagnostic, response=response)
            return
        if response is None and ('invalid host' in issue.lower() or (extra and extra.get('error'))):
            self._record_telemetry(issue, target, payload=payload, extra=extra, response=response)
            return
        if extra and getattr(self, 'IGNORE_NETWORK_TIMEOUTS', True):
            err_low = str(extra.get('error', '')).lower()
            for p in getattr(self, 'NETWORK_TIMEOUT_PATTERNS', ('timeout', 'timed out', 'read timed out', 'connect timeout')):
                if p in err_low:
                    self._record_telemetry(issue, target, payload=payload, extra=extra, response=response)
                    return

        skip_markers = ('failed to parse', "name 'parsed' is not defined")
        chk = [issue]
        if extra and 'error' in extra:
            chk.append(str(extra['error']))
        for f in chk:
            low = str(f).lower()
            if any((k in low for k in skip_markers)):
                self._record_telemetry(issue, target, payload=payload, extra=extra, response=response)
                return

        if response is None and extra and extra.get('error') and str(severity).lower() == 'info':
            self._record_telemetry(issue, target, payload=payload, extra=extra)
            return


        #================ _is_binary_response description ##########
        def _is_binary_response(resp) -> bool:
            try:
                ctype = (resp.headers.get('Content-Type') or '').lower()
            except Exception:
                ctype = ''
            if ctype.startswith(('image/', 'audio/', 'video/')) or 'application/pdf' in ctype or 'application/octet-stream' in ctype:
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

        # --- Severity gating to reduce false positives (generic & audit-friendly) ---
        # 1) Treat common "defensive" statuses as non-findings unless data is actually returned.
        # 2) Keep CORS wildcard findings at Medium only when 200 OK and sensitive-ish JSON is returned.
        #    Otherwise downgrade to Low/Info.
        try:
            sev_rank = {'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

            def _norm_sev(s: str) -> str:
                s = (s or '').strip().lower()
                if s in ('critical',): return 'Critical'
                if s in ('high',): return 'High'
                if s in ('medium',): return 'Medium'
                if s in ('low',): return 'Low'
                return 'Info'

            def _sev_at_most(cur: str, cap: str) -> str:
                cur = _norm_sev(cur)
                cap = _norm_sev(cap)
                return cur if sev_rank[cur] <= sev_rank[cap] else cap

            def _sev_at_least(cur: str, floor: str) -> str:
                cur = _norm_sev(cur)
                floor = _norm_sev(floor)
                return cur if sev_rank[cur] >= sev_rank[floor] else floor

            def _safe_text(resp) -> str:
                try:
                    t = resp.text or ''
                except Exception:
                    try:
                        t = resp.content.decode('utf-8', 'replace')
                    except Exception:
                        t = ''
                return t[:4096] if t else ''

            def _has_sensitive_jsonish(text: str) -> bool:
                if not text:
                    return False
                low = text.lower()
                # pragmatic indicators; keeps it generic across APIs
                indicators = (
                    '"email"', '"role"', '"token"', '"jwt"', '"credit"', '"account"', '"user"', '"id"', '"phone"', '"number"'
                )
                return any(k in low for k in indicators)

            def _is_error_only_json(resp, text: str) -> bool:
                if not text:
                    return False
                try:
                    ct = (resp.headers.get('Content-Type') or '').lower()
                except Exception:
                    ct = ''
                if 'json' not in ct:
                    return False
                try:
                    obj = json.loads(text)
                except Exception:
                    return False

                # Allow common error envelope keys (varies across APIM/WSO2/custom gateways)
                allowed_keys = {
                    'error', 'message', 'errors', 'detail', 'details', 'code', 'status',
                    'timestamp', 'path', 'traceid', 'requestid', 'correlationid', 'type', 'title'
                }

                def _keys_only(o):
                    if isinstance(o, dict):
                        return set(str(k).lower() for k in o.keys())
                    return set()

                keys = _keys_only(obj)
                if not keys:
                    # some APIs return JSON strings like "Forbidden"
                    if isinstance(obj, str) and obj.strip():
                        return True
                    return False

                # Error-only JSON means keys are a subset of allowed keys and it does not contain obvious data
                return keys.issubset(allowed_keys)

            def _is_cors_wildcard(resp) -> bool:
                try:
                    acao = (resp.headers.get('Access-Control-Allow-Origin') or '').strip()
                except Exception:
                    acao = ''
                return acao == '*'

            severity = _norm_sev(severity)

            if response is not None:
                sc = getattr(response, 'status_code', None)
                body_preview = _safe_text(response)

                # SAFE_STATUSES (400/401/403/404/405/422) are usually expected defenses.
                # Downgrade them unless we actually got content back that looks like data exposure.
                if isinstance(sc, int) and sc in SAFE_STATUSES:

                    # Defensive statuses are usually expected, but do not downgrade if we still see data exposure.

                    if _has_sensitive_jsonish(body_preview):

                        severity = _sev_at_least(severity, 'Medium')

                    elif _is_error_only_json(response, body_preview):

                        # JSON error envelope (e.g., {"error":"Forbidden"}) -> expected behavior

                        severity = _sev_at_most(severity, 'Info')

                    elif body_preview and len(body_preview.strip()) > 0:

                        severity = _sev_at_most(severity, 'Low')

                    else:

                        severity = _sev_at_most(severity, 'Info')
                # Wildcard access alone does not prove exposure of confidential data.
                low_issue = (issue or '').lower()
                if 'cors' in low_issue:
                    if _is_cors_wildcard(response):
                        severity = 'Info'
                    else:
                        severity = _sev_at_most(severity, 'Low')

                # "Request smuggling borderline/timeout" without clear desync signal should be informational.
                if 'request smuggling' in low_issue and isinstance(sc, int) and sc >= 500:
                    severity = _sev_at_most(severity, 'Info')
        except Exception:
            # Do not break scanning if severity gating fails for any reason.
            pass


        entry = {
            'issue': issue,
            'description': issue,
            'severity': severity,
            'confidence': 'medium' if severity in ('Critical', 'High', 'Medium') else 'low',
            'target': target,
            'payload': payload if payload is not None else '',
            'status_code': response.status_code if response is not None else '-',
            'timestamp': datetime.now().isoformat()
        }

        if extra:
            entry.update(extra)

        try:
            if response is not None and getattr(response, 'request', None) is not None:
                req = response.request
                full_url = getattr(req, 'url', target) or target
                parsed = urlparse.urlparse(full_url)
                entry.update(
                    method=req.method or 'GET',
                    url=full_url,
                    endpoint=parsed.path or '/',
                    request_headers=dict(getattr(req, 'headers', {}) or {}),
                    response_headers=dict(response.headers or {}),
                    request_cookies=getattr(response, 'cookies', {}).get_dict() if hasattr(response, 'cookies') else {},
                    response_cookies=response.cookies.get_dict() if hasattr(response, 'cookies') else {}
                )

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

        from scanner_quality import filtering_observation
        if filtering_observation(entry.get('issue')):
            entry['severity'] = 'Info'
            entry['confidence'] = 'low'
            entry['evidence_status'] = 'observation'
            entry['risk_score'] = 0.0
        else:
            entry['risk_score'] = self._calculate_risk_score(entry)

        with self.issues_lock:
            self.issues.append(entry)

        if entry.get('severity') in ['Critical', 'High', 'Medium']:
            self._print_issue_to_console(entry)

        if getattr(self, 'log_monitor', None):
            try:
                self.log_monitor(entry)
            except Exception:
                pass



    #================ _dump_raw_issues description ##########
    def _dump_raw_issues(self, output_dir: str) -> None:
        from pathlib import Path
        import json
        output_root = Path(output_dir).parent
        output_root.mkdir(parents=True, exist_ok=True)
        (output_root / 'api10_sql_coverage.json').write_text(json.dumps({
            'run_marker': getattr(self, 'sql_run_marker', ''),
            'operations': getattr(self, 'sql_details', [])}, indent=2), encoding='utf-8')
        (output_root / 'api10_write_journal.json').write_text(json.dumps({
            'run_marker': getattr(self, 'sql_run_marker', ''),
            'requests': getattr(self, 'sql_write_journal', [])}, indent=2), encoding='utf-8')
        coverage_file = Path(output_dir) / 'coverage_api10.json'
        coverage_file.parent.mkdir(parents=True, exist_ok=True)
        coverage_file.write_text(json.dumps(getattr(self, 'coverage', {
            'audit': 'API10', 'state': 'not_measured'}), indent=2), encoding='utf-8')
        try:
            import json
            from pathlib import Path

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = output_path / f"raw_issues_{timestamp}.json"

            serializable_issues = []
            for issue in self.issues:
                serializable_issue = {}
                for key, value in issue.items():
                    try:
                        json.dumps(value)
                        serializable_issue[key] = value
                    except (TypeError, ValueError):
                        serializable_issue[key] = str(value)
                serializable_issues.append(serializable_issue)

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(serializable_issues, f, indent=2, ensure_ascii=False)

            print(f"  \033[92m\u2714\033[0m  \033[92mOK\033[0m  API10 raw issues saved: {filename}")

            if self.telemetry:
                telemetry_file = output_path / f"telemetry_{timestamp}.json"
                serializable_telemetry = []
                for item in self.telemetry:
                    serializable_item = {}
                    for key, value in item.items():
                        try:
                            json.dumps(value)
                            serializable_item[key] = value
                        except (TypeError, ValueError):
                            serializable_item[key] = str(value)
                    serializable_telemetry.append(serializable_item)
                with open(telemetry_file, 'w', encoding='utf-8') as f:
                    json.dump(serializable_telemetry, f, indent=2, ensure_ascii=False)
                print(f"  \033[92m\u2714\033[0m  \033[92mOK\033[0m  Telemetry saved: {telemetry_file}")
        except Exception as e:
            print(f"  \033[91m\u2716\033[0m  \033[91mError\033[0m  Failed to save raw issues: {e}")


    #================ _console_write description ##########
    def _console_write(self, text: str = "") -> None:
        if HAS_TQDM and not self.no_tqdm:
            try:
                from tqdm import tqdm
                tqdm.write(text)
            except Exception:
                print(text)
        else:
            print(text)






    #================ _print_issue_to_console description ##########
    def _print_issue_to_console(self, issue: dict):
        severity = issue.get('severity', 'Info')
        issue_text = issue.get('issue', 'Unknown')
        url = issue.get('url', issue.get('target', 'Unknown'))
        status = issue.get('status_code', '?')
        risk_score = issue.get('risk_score', 0)

        url_display = url if len(url) <= 100 else url[:97] + '...'

        _R  = '\033[0m'; _DIM = '\033[2m'
        _SEV = {'Critical': '\033[1m\033[91m', 'High': '\033[1m\033[93m',
                'Medium':   '\033[92m',         'Low':  '\033[96m', 'Info': '\033[97m'}
        sc = _SEV.get(severity, '\033[97m')
        badge = f"{sc}{severity.upper():<8}{_R}"
        risk_str = f"  {_DIM}risk={risk_score:.1f}{_R}" if risk_score > 0 else ""
        status_str = f"  {_DIM}HTTP {status}{_R}" if status != '?' else ""

        self._console_write(f"  \033[93m\u25c8{_R}  {badge}  {issue_text}{risk_str}")
        self._console_write(f"      {_DIM}{url_display}{status_str}{_R}")
        self._console_write("")



    #================ _test_jwt_vulnerabilities description ##########
    def _test_jwt_vulnerabilities(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''

            for jwt_token in self.JWT_PAYLOADS:
                if stop_requested.is_set():
                    return

                try:
                    self._throttle(domain)

                    headers_list = [
                        {'Authorization': f'Bearer {jwt_token}'},
                        {'Authorization': f'Token {jwt_token}'},
                        {'Authorization': f'JWT {jwt_token}'},
                        {'X-Auth-Token': jwt_token},
                        {'X-JWT-Token': jwt_token}
                    ]

                    for headers in headers_list:
                        try:
                            r = self.session.get(endpoint, headers=headers, timeout=(3, self.timeout), allow_redirects=False)
                            body_low = (r.text or '').lower()

                            if any(kw in body_low for kw in self.JWT_ERROR_KEYWORDS):
                                # A validation message means the forged token was rejected: diagnostic only.
                                with self._options_cache_lock:
                                    seen = self.__dict__.setdefault('_jwt_reject_seen', set())
                                    first = endpoint not in seen
                                    seen.add(endpoint)
                                if first:
                                    self._record_telemetry('JWT rejection message observed', endpoint,
                                        payload=jwt_token[:50] + '...', response=r,
                                        extra={'execution_status': 'response_received',
                                               'note': 'Forged token rejected with a validation message; expected behaviour'})

                            if 'alg' in jwt_token and 'none' in jwt_token.lower():
                                if r.status_code < 400:
                                    self._log(
                                        'Possible JWT algorithm confusion',
                                        endpoint,
                                        'High',
                                        payload=jwt_token[:50] + '...',
                                        response=r,
                                        extra={'vulnerability': 'JWT alg=none accepted'}
                                    )

                        except Exception:
                            continue

                except Exception as e:
                    self._log('JWT test failed', endpoint, 'Info', extra={'error': str(e)})

        except Exception as e:
            self._log('JWT test setup failed', endpoint, 'Info', extra={'error': str(e)})


    #================ _test_rate_limit_bypass description ##########
    def _test_rate_limit_bypass(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''

            baseline_status = 0
            try:
                self._throttle(domain)
                baseline = self.session.get(endpoint, timeout=(3, self.timeout))
                baseline_status = baseline.status_code
            except Exception:
                pass

            # Only test bypass if the endpoint actually rate-limits us.
            # Without this guard we send 7Ã—5=35 extra requests per endpoint for nothing.
            if baseline_status != 429:
                return

            for ip_headers in self.RATE_LIMIT_BYPASS_HEADERS:
                if stop_requested.is_set():
                    return

                try:
                    self._throttle(domain)
                    status_codes = []
                    for i in range(5):
                        try:
                            r = self.session.get(endpoint, headers=ip_headers, timeout=(2, self.timeout))
                            status_codes.append(r.status_code)
                        except Exception:
                            status_codes.append(0)

                    successful = sum(1 for s in status_codes if 200 <= s < 300)
                    rate_limited = sum(1 for s in status_codes if s == 429)

                    if successful >= 3 and baseline_status == 429:
                        self._log(
                            'Possible rate limit bypass via IP spoofing',
                            endpoint,
                            'Medium',
                            extra={
                                'headers': ip_headers,
                                'successful_requests': successful,
                                'baseline_status': baseline_status
                            }
                        )

                except Exception:
                    continue

        except Exception as e:
            self._log('Rate limit bypass test failed', endpoint, 'Info', extra={'error': str(e)})


    #================ _test_ssrf_advanced description ##########
    def _test_ssrf_advanced(self, endpoint: str) -> None:
        if stop_requested.is_set() or not self.deep_scan:
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''

            param_candidates = ['url', 'uri', 'path', 'file', 'image', 'load', 'redirect', 'return', 'next']

            for param in param_candidates:
                for payload in self.SSRF_ADVANCED_PAYLOADS:
                    if stop_requested.is_set():
                        return

                    try:
                        self._throttle(domain)

                        if '?' in endpoint:
                            test_url = f"{endpoint}&{param}={urlparse.quote(payload)}"
                        else:
                            test_url = f"{endpoint}?{param}={urlparse.quote(payload)}"

                        r = self.session.get(test_url, timeout=(5, self.timeout * 2), allow_redirects=False)
                        body_low = (r.text or '').lower()
                        response_time = r.elapsed.total_seconds() if r.elapsed else 0

                        ssrf_indicators = [
                            'connection refused',
                            'connection timeout',
                            'no route to host',
                            'gopher',
                            'dict://',
                            'localhost',
                            '127.0.0.1',
                            'internal server error'
                        ]

                        has_indicator = any(ind in body_low for ind in ssrf_indicators)
                        slow_response = response_time > 3.0

                        if has_indicator or slow_response:
                            severity = 'High' if 'gopher://' in payload or 'dict://' in payload else 'Medium'
                            self._log(
                                f'Possible SSRF ({param})',
                                test_url,
                                severity,
                                payload=payload,
                                response=r,
                                extra={
                                    'parameter': param,
                                    'response_time': response_time,
                                    'has_ssrf_indicator': has_indicator
                                }
                            )

                    except Exception as e:
                        if 'timeout' in str(e).lower() or 'read timed' in str(e).lower():
                            self._log(
                                'SSRF test timeout (possible outbound connection)',
                                endpoint,
                                'Medium',
                                extra={
                                    'parameter': param,
                                    'payload': payload,
                                    'error': str(e)
                                }
                            )
                        continue

        except Exception as e:
            self._log('Advanced SSRF test failed', endpoint, 'Info', extra={'error': str(e)})


    #================ _test_business_logic description ##########
    def _test_business_logic(self, endpoint: str) -> None:
        if stop_requested.is_set() or not self.deep_scan:
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''

            methods_to_test = ['POST', 'PUT', 'PATCH']

            for method in methods_to_test:
                for payload in self.BUSINESS_LOGIC_PAYLOADS:
                    if stop_requested.is_set():
                        return

                    try:
                        self._throttle(domain)
                        content_types = ['application/json', 'application/x-www-form-urlencoded']

                        for content_type in content_types:
                            headers = {'Content-Type': content_type}

                            if content_type == 'application/json':
                                data = json.dumps(payload)
                            else:
                                data = payload

                            r = self.session.request(
                                method,
                                endpoint,
                                data=data,
                                headers=headers,
                                timeout=(3, self.timeout),
                                allow_redirects=False
                            )

                            if r.status_code in [200, 201]:
                                suspicious = False
                                reason = ""

                                if payload.get('price', 0) < 0:
                                    suspicious = True
                                    reason = "Negative price accepted"
                                elif payload.get('discount', 0) > 100:
                                    suspicious = True
                                    reason = "Discount >100% accepted"
                                elif payload.get('role') == 'admin':
                                    suspicious = True
                                    reason = "Admin role assignment possible"
                                elif payload.get('is_admin') is True:
                                    suspicious = True
                                    reason = "is_admin=true accepted"

                                if suspicious:
                                    self._log(
                                        f'Business logic flaw: {reason}',
                                        endpoint,
                                        'High',
                                        payload=payload,
                                        response=r,
                                        extra={
                                            'method': method,
                                            'flaw_type': reason
                                        }
                                    )

                    except Exception:
                        continue

        except Exception as e:
            self._log('Business logic test failed', endpoint, 'Info', extra={'error': str(e)})
    #================ _test_open_redirect description ##########
    def _test_open_redirect(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return

        payloads = getattr(self, 'OPEN_REDIRECT_PAYLOADS', []) or []
        if not payloads:
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            params = self._discover_parameters(endpoint)

            redirect_param_candidates = {
                'redirect', 'redirecturi', 'redirect_uri', 'redirecturl', 'redirect_url', 'redir',
                'return', 'returnurl', 'return_url', 'returnto', 'return_to', 'next', 'nexturl',
                'next_url', 'url', 'target', 'dest', 'destination', 'continue', 'callback',
                'goto', 'forward', 'location', 'to'
            }
            test_params = [p for p in params if p.lower() in redirect_param_candidates]
            if not test_params:
                test_params = ['redirect', 'returnUrl', 'next']

            redirect_tests_sent = 0
            max_redirect_tests = self.quick_redirect_max_tests if self.quick_mode and not self.deep_scan else 50
            for p in test_params[:5]:
                for pay in payloads[: min(10, len(payloads))]:
                    if redirect_tests_sent >= max_redirect_tests:
                        return
                    if stop_requested.is_set():
                        return
                    try:
                        self._throttle(domain)
                        redirect_tests_sent += 1

                        if '?' in endpoint:
                            test_url = f"{endpoint}&{urlparse.quote(p)}={urlparse.quote(str(pay))}"
                        else:
                            test_url = f"{endpoint}?{urlparse.quote(p)}={urlparse.quote(str(pay))}"

                        r = self.session.get(test_url, timeout=(3, self.timeout), allow_redirects=False)

                        location = (r.headers.get('Location') or '').strip()
                        loc_low = location.lower()

                        if 300 <= int(getattr(r, 'status_code', 0)) < 400 and location:
                            if __import__('response_evidence').redirect_to_host(location, test_url, 'evil.example'):
                                self._log(
                                    'Possible open redirect',
                                    test_url,
                                    'Medium',
                                    payload=pay,
                                    response=r,
                                    extra={'parameter': p, 'location': location[:500], 'confidence': 'medium'}
                                )
                                continue

                        body_low = (r.text or '').lower()
                        if 'evil.example' in body_low and not location:
                            self._log(
                                'Potential redirect parameter reflection',
                                test_url,
                                'Low',
                                payload=pay,
                                response=r,
                                extra={'parameter': p, 'confidence': 'low'}
                            )
                    except Exception:
                        continue

        except Exception as e:
            self._log('Open redirect test failed', endpoint, 'Info', extra={'error': str(e)})


    #================ _test_host_header_injection description ##########
    def _test_host_controls(self, endpoint):
        import uuid
        from urllib.parse import urlsplit
        with self._options_cache_lock:
            seen = getattr(self, '_host_control_seen', set())
            if endpoint in seen:
                return
            seen.add(endpoint)
            self._host_control_seen = seen
        host = 'apiscan-' + uuid.uuid4().hex[:12] + '.invalid'
        domain = urlsplit(endpoint).netloc
        try:
            self._throttle(domain)
            baseline = self.session.get(endpoint, timeout=(3, self.timeout), allow_redirects=False)
        except requests.RequestException as exc:
            self._record_telemetry('Host control baseline failed', endpoint, extra={'error': str(exc)})
            return
        for header in ('Host', 'X-Forwarded-Host', 'X-Host'):
            if stop_requested.is_set():
                return
            try:
                self._throttle(domain)
                response = self.session.get(endpoint, headers={header: host}, timeout=(3, self.timeout), allow_redirects=False)
            except requests.RequestException as exc:
                self._record_telemetry('Host control probe failed', endpoint, extra={'error': str(exc)})
                continue
            location = response.headers.get('Location', '')
            if host == urlsplit(location).hostname and location != baseline.headers.get('Location', ''):
                self._log('Response redirect influenced by untrusted host header', endpoint, 'Low',
                    response=response, extra={'header': header, 'injected_host': host,
                    'baseline_status': baseline.status_code, 'location': location,
                    'note': 'Redirect manipulation observed; security impact requires review'})
            elif host in (response.text or '') and host not in (baseline.text or ''):
                self._log('Observation: injected host reflected in response; impact unverified', endpoint, 'Info',
                    response=response, extra={'header': header, 'injected_host': host,
                    'baseline_status': baseline.status_code})

    def _test_host_header_injection(self, endpoint: str) -> None:
        return self._test_host_controls(endpoint)


    @staticmethod
    def _redirect_echoes_request(request_url: str, location: str) -> bool:
        # Same-host redirect to the decoded, normalized request path: URL canonicalization, not file access.
        import posixpath
        from urllib.parse import urljoin, unquote

        def normalized(u: str) -> str:
            path = urlparse.urlsplit(u).path
            for _ in range(3):
                decoded = unquote(path)
                if decoded == path:
                    break
                path = decoded
            path = re.sub(r'/{2,}', '/', path.replace('\\', '/')) or '/'
            return posixpath.normpath(path).rstrip('/').lower()

        if not location:
            return False
        target = urljoin(request_url, location)
        if urlparse.urlsplit(target).netloc.lower() != urlparse.urlsplit(request_url).netloc.lower():
            return False
        return normalized(target) == normalized(request_url)

    def _declared_query_params(self, endpoint: str) -> List[str]:
        names: List[str] = []
        matching = getattr(self.session, 'matching', None)
        try:
            operations = matching(endpoint) if callable(matching) else []
        except Exception:
            operations = []
        for op in operations or []:
            for param in op.get('parameters') or []:
                name = param.get('name')
                if param.get('in') == 'query' and name and name not in names:
                    names.append(name)
        return names

    def _param_candidates(self, endpoint: str, fallback, limit: Optional[int] = None) -> List[str]:
        declared = self._declared_query_params(endpoint)
        if declared and not self.deep_scan:
            return declared
        fallback = list(fallback or [])
        if limit and not self.deep_scan:
            fallback = fallback[:limit]
        return list(dict.fromkeys([*declared, *fallback]))

    def _discover_parameters(self, endpoint: str) -> List[str]:
        if endpoint in self.param_cache:
            return self.param_cache[endpoint]

        # Ordered: declared spec params first, then observed, then generic guesses.
        discovered: Dict[str, None] = dict.fromkeys(self._declared_query_params(endpoint))

        try:
            parsed = urlparse.urlparse(endpoint)

            if parsed.query:
                params = parse_qs(parsed.query)
                discovered.update(dict.fromkeys(params.keys()))

            if self.param_discovery:
                for method in ['GET', 'POST']:
                    if stop_requested.is_set():
                        break

                    try:
                        self._throttle(parsed.netloc or parsed.hostname or '')

                        if method == 'GET':
                            r = self.session.get(endpoint, timeout=3, allow_redirects=False)
                        else:
                            r = self.session.post(endpoint, json={}, timeout=3, allow_redirects=False)

                        ctype = r.headers.get('Content-Type', '').lower()

                        if 'application/json' in ctype:
                            try:
                                found = set()
                                self._extract_keys_from_json(r.json(), found)
                                discovered.update(dict.fromkeys(sorted(found)))
                            except Exception:
                                pass

                        response_text = r.text or ''
                        param_patterns = [
                            r'"(\w+)"\s*:',
                            r'name=["\'](\w+)["\']',
                            r'param(?:eter)?[=:]\s*["\']?(\w+)'
                        ]

                        for pattern in param_patterns:
                            matches = re.findall(pattern, response_text, re.I)
                            discovered.update(dict.fromkeys(matches))

                    except Exception:
                        continue

            common_params = [
                'id', 'name', 'email', 'user', 'username', 'password', 'token',
                'key', 'secret', 'q', 'query', 'search', 'filter', 'sort',
                'page', 'limit', 'offset', 'status', 'type', 'category',
                'file', 'path', 'url', 'redirect', 'callback', 'jsonp'
            ]

            discovered.update(dict.fromkeys(common_params))

            result = list(discovered)
            self.param_cache[endpoint] = result
            return result

        except Exception as e:
            return list(discovered)


    #================ _extract_keys_from_json description ##########
    def _extract_keys_from_json(self, data, discovered: set, path=""):
        if isinstance(data, dict):
            for k, v in data.items():
                discovered.add(k)
                self._extract_keys_from_json(v, discovered, f"{path}.{k}")
        elif isinstance(data, list) and data:
            self._extract_keys_from_json(data[0], discovered, path)


    #================ _has_sql_evidence_improved description ##########
    def _has_sql_evidence_improved(self, body: str) -> bool:
        if not body:
            return False

        low = body.lower()

        for db_type, patterns in self.DB_SPECIFIC_PATTERNS.items():
            if any(p in low for p in patterns):
                return True

        if any(rx.search(low) for rx in getattr(self, 'SQL_ERROR_RX', [])):
            return True

        for pattern in self.TIME_PATTERNS:
            if re.search(pattern, low, re.I):
                return True

        sql_keywords_in_error = [
            'sql syntax',
            'syntax error',
            'unclosed quotation',
            'near "',
            'unknown column',
            'table.*not exist',
            'column.*not found'
        ]

        error_context = False
        error_indicators = ['error', 'exception', 'failure', 'invalid']

        if any(ind in low for ind in error_indicators):
            error_context = True

        if error_context and any(kw in low for kw in sql_keywords_in_error):
            return True

        return False


    #================ _is_likely_false_positive_improved description ##########
    def _is_likely_false_positive_improved(self, response, issue_type: str) -> bool:
        if not response:
            return False

        try:
            ctype = response.headers.get('Content-Type', '').lower()
            body = (response.text or '').lower()

            fp_patterns = {
                'sqli': [
                    'sqlite is not', 'sqlalchemy', 'sequelize', 'orm error',
                    'doctrine', 'entity framework', 'typeorm', 'prisma'
                ],
                'xss': [
                    'angular.js', 'react', 'vue.js', '<script>safe',
                    'sanitized', 'escaped', 'xss protected'
                ],
                'lfi': [
                    'file not found', 'invalid path', 'security policy',
                    'access denied', 'permission denied'
                ],
                'rce': [
                    'command not found', 'permission denied', 'no such file',
                    'invalid command'
                ],
                'nosql': [
                    'mongoose', 'mongodb driver', 'invalid bson',
                    'document validation failed'
                ]
            }

            if issue_type in fp_patterns:
                if any(fp in body for fp in fp_patterns[issue_type]):
                    return True

            generic_error_indicators = [
                '<title>error</title>',
                '<h1>error</h1>',
                'an error occurred',
                'please try again',
                'contact administrator',
                'technical difficulties'
            ]

            if any(ind in body for ind in generic_error_indicators):
                return True

            if 'application/json' in ctype:
                try:
                    data = json.loads(response.text)
                    if isinstance(data, dict) and 'error' in data:
                        return True
                except:
                    pass

            suspicious_words = ['error', 'exception', 'invalid', 'failed', 'wrong']
            safe_words = ['please', 'try again', 'contact support', 'valid', 'success']

            suspicious_count = sum(1 for w in suspicious_words if w in body)
            safe_count = sum(1 for w in safe_words if w in body)

            if safe_count > suspicious_count:
                return True

        except Exception:
            pass

        return False


    #================ _calculate_risk_score description ##########
    def _calculate_risk_score(self, issue: dict) -> float:
        score = 0.0

        severity_map = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 4.0,
            'Low': 2.0,
            'Info': 0.5
        }

        base_severity = issue.get('severity', 'Info')
        score += severity_map.get(base_severity, 0.5)

        confidence = issue.get('confidence', 'low')
        if confidence == 'high':
            score += 1.5
        elif confidence == 'medium':
            score += 1.0

        issue_text = (issue.get('issue') or '').lower()

        high_impact_keywords = [
            'remote code', 'command injection', 'rce', 'sql injection',
            'directory traversal', 'file inclusion', 'xxe', 'ssrf'
        ]

        for keyword in high_impact_keywords:
            if keyword in issue_text:
                score += 2.0
                break

        medium_impact_keywords = [
            'xss', 'csrf', 'idor', 'access control', 'authentication bypass',
            'information disclosure', 'data exposure'
        ]

        for keyword in medium_impact_keywords:
            if keyword in issue_text:
                score += 1.0
                break

        if issue.get('response_body') and len(issue.get('response_body', '')) > 100:
            score += 0.5

        try:
            status = int(issue.get('status_code', 0))
            if status >= 500:
                score += 0.5
        except:
            pass

        return min(10.0, max(0.0, score))



    #================ test_endpoints description ##########
    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        from probe_policy import ProbePolicySession
        original = self.session
        policy = ProbePolicySession(original, getattr(self,'swagger_spec',{}), self.base_url)
        self.session = policy
        try:
            return self._test_endpoints_with_policy(endpoints)
        finally:
            self.session = original
            self.coverage['probe_policy'] = policy.summary()
            if policy.summary()['skipped_requests']:
                self.coverage['scope_limited'] = True

    def _test_endpoints_with_policy(self, endpoints: List[str]) -> List[Issue]:
        self._schema_sql_seen = set()
        import uuid
        self.sql_run_marker = uuid.uuid4().hex[:12]
        self.sql_details = []
        self.sql_write_journal = []
        self._host_control_seen = set()
        from scanner_quality import normalize_endpoint, coverage_summary
        self.coverage = {'audit': 'API10', 'input_endpoints': len(endpoints),
                         'valid_endpoints': 0, 'started': 0, 'completed': 0,
                         'failed': 0, 'untested': 0, 'skipped': 0, 'skipped_tasks': 0, 'not_applicable': 0,
                         'unsupported_tests': ['request_smuggling', 'blind_sql_boolean_non_get', 'blind_sql_time', 'sql_delete', 'schema_body_non_sql_injection'], 'scope_limited': True}
        self._coverage_lock = threading.Lock()
        self._execution_state = threading.local()
        self._execution_state.planning = True
        normalized = []
        for endpoint in endpoints:
            try:
                url = normalize_endpoint(endpoint, self.base_url,
                                         getattr(self, 'path_parameter_values', {}))
                if url not in normalized:
                    normalized.append(url)
            except (TypeError, ValueError) as exc:
                self.coverage['skipped'] += 1
                self._record_telemetry('Endpoint validation failed', str(endpoint),
                                       extra={'error': str(exc), 'execution_status': 'skipped'})
        self.coverage['valid_endpoints'] = len(normalized)
        global stop_requested
        stop_requested.clear()
        try:
            if not normalized:
                return self.issues
            if self.adaptive:
                return self.adaptive_scanning_with_progress(normalized)
            return self._comprehensive_scan_with_progress(normalized)
        finally:
            if stop_requested.is_set():
                self.coverage['skipped'] += 1
            if hasattr(self.session, 'diagnostics'):
                for record in self.session.diagnostics('API10'):
                    self._record_telemetry('Probe skipped by request policy', record['path'], extra=record)
            self.coverage = coverage_summary(self.coverage, self.telemetry)
            if hasattr(self.session,'summary'): self.coverage['probe_policy'] = self.session.summary()
            self.coverage['sql'] = {
                'operations_total': len(getattr(self, 'sql_details', [])),
                'operations_tested': sum(x['state'] == 'completed' for x in getattr(self, 'sql_details', [])),
                'details_file': 'api10_sql_coverage.json',
                'probe_requests': sum(x['probe_requests'] for x in getattr(self, 'sql_details', [])),
                'note': 'SQL error detection, repeated GET boolean checks and observed JSON-login bypass controls. Capped declared fields; invalid baselines remain untested. Boolean body/path and time-based checks remain unsupported.'}

            print('API10 coverage: ' + json.dumps(self.coverage, ensure_ascii=False))


    #================ adaptive_scanning_with_progress description ##########
    def adaptive_scanning_with_progress(self, endpoints: list):
        total_endpoints = len(endpoints)

        print(f'{Colors.BLUE}{"="*70}{Colors.RESET}')
        print(f'{Colors.BOLD}{Colors.GREEN}[PHASE 1] Quick reconnaissance ({total_endpoints} endpoints){Colors.RESET}')
        print(f'{Colors.BLUE}{"-"*70}{Colors.RESET}')

        sample_size = min(self.phase1_sample, total_endpoints)
        sample_endpoints = random.sample(endpoints, sample_size) if total_endpoints > sample_size else endpoints

        fast_tests = [
            partial(self._test_basic_security),
            partial(self._test_crlf_injection),
            partial(self._test_open_redirect),
        ]
        completed = 0
        total_tasks = len(sample_endpoints) * len(fast_tests)
        self._phase1_pairs = set()
        self._phase1_active = True

        if HAS_TQDM and not self.no_tqdm:
            sys.stdout.flush()
            time.sleep(0.1)
            with tqdm(total=total_tasks, desc="Phase 1 - Recon", unit="test", ncols=80, mininterval=0.1) as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = []
                    for endpoint in sample_endpoints:
                        for test in fast_tests:
                            futures.append(self._schedule_test(executor, test, endpoint, pbar.update))

                    for future in concurrent.futures.as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass
        else:
            print(f'{Colors.WHITE}  Running quick tests...{Colors.RESET}')
            progress = ProgressBar(total_tasks, desc="Phase 1 - Recon")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for endpoint in sample_endpoints:
                    for test in fast_tests:
                        futures.append(self._schedule_test(executor, test, endpoint, progress.update))

                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass

            progress.close()

        self._phase1_active = False
        print(f'{Colors.GREEN}  [] Phase 1 completed - {len(self.issues)} issues found{Colors.RESET}')

        sql_found = any('sql' in str(i).lower() for i in self.issues)
        auth_found = any('auth' in str(i).lower() or '401' in str(i.get('status_code', '')) for i in self.issues)
        admin_found = any('admin' in str(i).lower() for i in self.issues)

        print(f'\n{Colors.BLUE}{"="*70}{Colors.RESET}')
        print(f'{Colors.BOLD}{Colors.GREEN}[PHASE 2] Targeted scanning{Colors.RESET}')
        print(f'{Colors.BLUE}{"-"*70}{Colors.RESET}')

        print(f'{Colors.WHITE}  Identifying promising endpoints...{Colors.RESET}')
        promising_endpoints = []

        if HAS_TQDM and not self.no_tqdm:
            sys.stdout.flush()
            for endpoint in tqdm(endpoints, desc="Analyzing endpoints", unit="endpoint", ncols=80, mininterval=0.1):
                if self._is_promising_endpoint(endpoint):
                    promising_endpoints.append(endpoint)
        else:
            progress = ProgressBar(len(endpoints), desc="Analyzing endpoints")
            for endpoint in endpoints:
                if self._is_promising_endpoint(endpoint):
                    promising_endpoints.append(endpoint)
                progress.update()
            progress.close()

        print(f'{Colors.WHITE}  [Found] {len(promising_endpoints)} promising endpoints{Colors.RESET}')

        intensive_tests = []

        if self.quick_mode and not self.deep_scan:
            base_tests = [
                partial(self._test_basic_security),
                partial(self._test_waf_detection),
                partial(self._test_crlf_injection),
                partial(self._test_hpp),
                partial(self._test_sensitive_data_exposure),
                partial(self._test_open_redirect),
                partial(self._test_host_header_injection),
                partial(self._test_header_manipulation),
                partial(self._test_directory_traversal),
            ]
        else:
            # Full set: run these regardless of what Phase 1 found.
            base_tests = [
                partial(self._test_basic_security),
                partial(self._test_waf_detection),
                partial(self._test_crlf_injection),
                partial(self._test_hpp),
                partial(self._test_sensitive_data_exposure),
                partial(self._test_graphql_introspection),
                partial(self._test_open_redirect),
                partial(self._test_host_header_injection),
                partial(self._test_directory_traversal),
                partial(self._test_jwt_vulnerabilities),
                partial(self._test_business_logic),
            ]
            base_tests.extend([
                partial(self._test_blind_sqli),
                partial(self._test_directory_traversal_body),
                partial(self._test_header_manipulation),
                partial(self._test_rate_limit_bypass),
            ])
        # Injection payloads (XSS, SQLi, NoSQLi, LFI, RCE, SSTI, â€¦)
        injection_types = list(self.INJECTION_PAYLOADS)
        if self.quick_mode and not self.deep_scan:
            quick_types = {'sql', 'path', 'xss', 'nosql', 'lfi', 'ssti'}
            injection_types = [t for t in injection_types if t in quick_types]
        for _t in injection_types:
            base_tests.append(partial(self._run_injection_tests_parallel, test_type=_t))

        intensive_tests = list(base_tests)

        # Additional focused tests based on Phase 1 findings
        if sql_found:
            if self.quick_mode and not self.deep_scan:
                print(f'{Colors.YELLOW}  [Focus] SQL patterns detected - covered by quick SQL payload tests{Colors.RESET}')
            else:
                print(f'{Colors.YELLOW}  [Focus] SQL patterns detected - running intensive SQL tests{Colors.RESET}')
                intensive_tests.append(partial(self._run_intensive_sql_tests))

        if auth_found or admin_found:
            print(f'{Colors.YELLOW}  [Focus] Auth/admin patterns detected - already covered in base set{Colors.RESET}')

        if self.deep_scan:
            intensive_tests.extend([
                partial(self._test_ssrf_advanced),
                partial(self._test_rate_limit_bypass)
            ])

        remaining = [e for e in endpoints if e not in set(promising_endpoints)]
        target_endpoints = promising_endpoints + remaining
        target_endpoints = self._prioritize_sql_inputs(target_endpoints)
        all_prioritized = list(target_endpoints)
        if self.quick_mode and not self.deep_scan:
            before_cap = len(target_endpoints)
            target_endpoints = target_endpoints[:self.quick_max_endpoints]
            if before_cap > len(target_endpoints):
                print(f'{Colors.YELLOW}  [Quick] Limiting Phase 2 to {len(target_endpoints)}/{before_cap} endpoints. Set APISCAN_API10_QUICK=0 for full coverage.{Colors.RESET}')
            before_auth_skip = len(target_endpoints)
            target_endpoints = [e for e in target_endpoints if not self._should_skip_heavy_endpoint(e)]
            skipped_auth = before_auth_skip - len(target_endpoints)
            if skipped_auth:
                print(f'{Colors.YELLOW}  [Quick] Skipped heavy tests for {skipped_auth} protected endpoints without credentials{Colors.RESET}')
        elif self.deep_scan:
            deep_max = int(os.getenv('APISCAN_DEEP_MAX_ENDPOINTS', '15'))
            before_cap = len(target_endpoints)
            target_endpoints = target_endpoints[:deep_max]
            if before_cap > len(target_endpoints):
                print(f'{Colors.MAGENTA}  [Deep] Limiting Phase 2 to {len(target_endpoints)}/{before_cap} endpoints ({len(intensive_tests)} tests each). Set APISCAN_DEEP_MAX_ENDPOINTS for more.{Colors.RESET}')

        # Schema SQL probes are cheap; run them on endpoints beyond the cap as well.
        kept = set(target_endpoints)
        quick_only = self.quick_mode and not self.deep_scan
        sql_only = [e for e in all_prioritized
                    if e not in kept and not (quick_only and self._should_skip_heavy_endpoint(e))]
        batches = [(test, target_endpoints) for test in intensive_tests]
        if sql_only:
            batches.append((partial(self._test_schema_sql), sql_only))
            print(f'{Colors.WHITE}  [SQL] Schema SQL probes also run on {len(sql_only)} endpoints outside the Phase 2 cap{Colors.RESET}')

        if hasattr(self, 'coverage'):
            self.coverage['phase2_selection'] = {
                'available_endpoints': len(endpoints), 'selected_endpoints': len(target_endpoints),
                'excluded_endpoints': len(set(endpoints) - set(target_endpoints)),
                'sql_only_endpoints': len(sql_only),
                'note': 'Existing quick/deep endpoint caps apply; declared SQL inputs are prioritized. Excluded endpoints receive schema SQL probes only.'}

        print(f'{Colors.WHITE}  [Testing] {len(target_endpoints)} endpoints with {len(intensive_tests)} test types{Colors.RESET}')

        total_phase2_tests = sum(len(batch_endpoints) for _, batch_endpoints in batches)

        # â”€â”€ Build human-readable labels for each test â”€â”€
        _TEST_LABELS = {
            "_test_basic_security": "Basic Security Headers",
            "_test_waf_detection": "WAF Detection",
            "_test_crlf_injection": "CRLF Injection",
            "_test_hpp": "HTTP Parameter Pollution",
            "_test_sensitive_data_exposure": "Sensitive Data Exposure",
            "_test_graphql_introspection": "GraphQL Introspection",
            "_test_open_redirect": "Open Redirect",
            "_test_host_header_injection": "Host Header Injection",
            "_test_directory_traversal": "Directory Traversal",
            "_test_jwt_vulnerabilities": "JWT Vulnerabilities",
            "_test_business_logic": "Business Logic",
            "_test_blind_sqli": "Blind SQL Injection",
            "_test_directory_traversal_body": "Directory Traversal (Body)",
            "_test_header_manipulation": "Header Manipulation",
            "_test_rate_limit_bypass": "Rate Limit Bypass",
            "_run_injection_tests_parallel": None,  # dynamic label from test_type
            "_run_intensive_sql_tests": "Intensive SQL Tests",
            "_test_ssrf_advanced": "SSRF Advanced",
            "_test_schema_sql": "Schema SQL (outside cap)",
        }
        def _test_label(test) -> str:
            """Return a human-readable label for a test partial."""
            try:
                fn = test.func if hasattr(test, 'func') else test
                name = fn.__name__
                if name == "_run_injection_tests_parallel":
                    kw = getattr(test, 'keywords', {}) or {}
                    tt = kw.get('test_type', 'Injection')
                    return f"Injection ({tt.upper()})"
                return _TEST_LABELS.get(name, name.replace('_', ' ').strip().title())
            except Exception:
                return "Unknown"

        if HAS_TQDM and not self.no_tqdm:
            sys.stdout.flush()
            with tqdm(total=total_phase2_tests, desc="Phase 2 - Starting", unit="test", ncols=80, mininterval=0.1) as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    # Process test types in batches so we can show the current test name
                    for test, batch_endpoints in batches:
                        label = _test_label(test)
                        pbar.set_description(f"Phase 2 - {label}")
                        batch_futures = []
                        for endpoint in batch_endpoints:
                            batch_futures.append(self._schedule_test(executor, test, endpoint, pbar.update))
                        for future in concurrent.futures.as_completed(batch_futures):
                            try:
                                future.result()
                            except Exception:
                                pass
        else:
            progress = ProgressBar(total_phase2_tests, desc="Phase 2 - Starting")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                for test, batch_endpoints in batches:
                    label = _test_label(test)
                    progress.desc = f"Phase 2 - {label}"
                    batch_futures = []
                    for endpoint in batch_endpoints:
                        batch_futures.append(self._schedule_test(executor, test, endpoint, progress.update))
                    for future in concurrent.futures.as_completed(batch_futures):
                        try:
                            future.result()
                        except Exception:
                            pass

            progress.close()

        print(f'{Colors.GREEN}  [] Phase 2 completed{Colors.RESET}')

        self._print_final_report()
        return self.issues


    #================ _run_test_with_callback description ##########
    def _prioritize_sql_inputs(self, endpoints):
        from openapi_universal import iter_operations
        from scanner_quality import normalize_endpoint, path_values
        from urllib.parse import urlsplit
        spec = getattr(self, 'swagger_spec', {})
        values = path_values(spec, getattr(self, 'path_parameter_values', {}))
        priority = {}
        for operation in iter_operations(spec):
            try:
                path = urlsplit(normalize_endpoint(operation['path'], self.base_url, values)).path
            except ValueError:
                continue
            raw = spec.get('paths', {}).get(operation['path'], {}).get(operation['method'].lower(), {})
            rank = 4
            if raw.get('x-discovery-state') == 'observed-login':
                rank = 0
            elif any(p.get('in') == 'query' for p in operation.get('parameters', [])):
                rank = 1
            elif any(_resolve_schema_ref(spec, media.get('schema')).get('properties') for media in (operation.get('requestBody') or {}).get('content', {}).values()):
                rank = 2
            elif any(p.get('in') == 'path' for p in operation.get('parameters', [])):
                rank = 3
            priority[path] = min(priority.get(path, 4), rank)
        return sorted(endpoints, key=lambda endpoint: priority.get(urlsplit(endpoint).path, 4))

    def _test_applicability(self, test_func, endpoint):
        function = getattr(test_func, 'func', test_func)
        name = getattr(function, '__name__', '')
        if name == '_test_blind_sqli':
            return 'Blind SQL probes unsupported'
        matching = getattr(self.session, 'matching', None)
        if not callable(matching):
            return None
        operations = matching(endpoint)
        if not operations:
            return None
        methods = {op['method'].upper() for op in operations}
        if name == '_run_injection_tests_parallel' and (getattr(test_func, 'keywords', {}) or {}).get('test_type') == 'sql':
            return None if methods - {'DELETE', 'HEAD', 'OPTIONS'} else 'No supported SQL operation'
        if name in ('_test_schema_sql', '_run_intensive_sql_tests'):
            return None
        known = {'_test_basic_security', '_test_waf_detection', '_test_crlf_injection', '_test_hpp', '_test_sensitive_data_exposure', '_test_graphql_introspection', '_test_directory_traversal_body', '_test_open_redirect', '_test_host_header_injection', '_test_header_manipulation', '_test_directory_traversal', '_test_jwt_vulnerabilities', '_test_rate_limit_bypass', '_test_ssrf_advanced', '_test_business_logic', '_run_injection_tests_parallel'}
        if name not in known:
            return None
        needed = {'POST'} if name == '_test_graphql_introspection' else (
            {'POST', 'PUT', 'PATCH'} if name == '_test_directory_traversal_body' else {'GET'})
        if not methods & needed:
            return 'Test requires declared ' + '/'.join(sorted(needed))
        return None

    def _schedule_test(self, executor, test_func, endpoint, callback):
        key = (getattr(getattr(test_func, 'func', test_func), '__name__', ''), endpoint)
        if getattr(self, '_phase1_active', False):
            self._phase1_pairs.add(key)
        elif key in getattr(self, '_phase1_pairs', ()):
            callback(1)
            done = concurrent.futures.Future()
            done.set_result(None)
            return done
        reason = self._test_applicability(test_func, endpoint)
        if reason:
            with self._coverage_lock:
                self.coverage['not_applicable'] = self.coverage.get('not_applicable', 0) + 1
                reasons = self.coverage.setdefault('not_applicable_reasons', {})
                reasons[reason] = reasons.get(reason, 0) + 1
            callback(1)
            result = concurrent.futures.Future()
            result.set_result(None)
            return result
        return executor.submit(self._run_test_with_callback, test_func, endpoint, callback)

    def _run_test_with_callback(self, test_func, endpoint, callback):
        from probe_policy import ProbeSkipped
        state = self._execution_state
        state.planning = False
        state.failed = False
        state.skipped = False
        state.untested = False
        with self._coverage_lock:
            self.coverage['started'] += 1
        try:
            test_func(endpoint)
        except ProbeSkipped:
            state.skipped = True
        except Exception as exc:
            state.failed = True
            self._record_telemetry('Test execution failed', endpoint,
                extra={'error': str(exc), 'test_name': getattr(test_func, '__name__', str(test_func)),
                       'execution_status': 'failed'})
        finally:
            with self._coverage_lock:
                key = ('failed' if state.failed else 'skipped_tasks' if state.skipped
                       else 'untested' if state.untested else 'completed')
                self.coverage[key] = self.coverage.get(key, 0) + 1
            callback(1)


    #================ _is_promising_endpoint description ##########
    def _is_promising_endpoint(self, endpoint: str) -> bool:
        url_lower = endpoint.lower()

        keywords = [
            'api', 'admin', 'user', 'auth', 'login', 'logout', 'register',
            'upload', 'download', 'export', 'import', 'config', 'settings',
            'profile', 'account', 'password', 'reset', 'token', 'key',
            'secret', 'credential', 'database', 'backup', 'restore'
        ]

        if any(kw in url_lower for kw in keywords):
            return True

        param_keywords = ['id=', 'token=', 'key=', 'secret=', 'auth=', 'pass=']
        if any(param in url_lower for param in param_keywords):
            return True

        extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']
        if any(ext in url_lower for ext in extensions):
            return True

        if re.search(r'/\d+/', endpoint):
            return True

        return False


    #================ _run_intensive_sql_tests description ##########
    def _run_intensive_sql_tests(self, endpoint: str):
        return self._test_schema_sql(endpoint)


    def _comprehensive_scan_with_progress(self, endpoints: List[str]) -> List[Issue]:
        print(f'{Colors.WHITE}  Total endpoints: {len(endpoints)}{Colors.RESET}')
        print(f'{Colors.WHITE}  [STEP 1] Checking endpoint reachability...{Colors.RESET}')
        reachable_endpoints: List[str] = []
        if HAS_TQDM and not self.no_tqdm:
            sys.stdout.flush()
            for ep in tqdm(
                endpoints,
                desc="Checking reachability",
                unit="endpoint",
                ncols=80,
                mininterval=0.1,
            ):
                if stop_requested.is_set():
                    break
                if self._is_endpoint_reachable(ep):
                    reachable_endpoints.append(ep)
        else:
            progress = ProgressBar(len(endpoints), desc="Checking reachability")
            for ep in endpoints:
                if stop_requested.is_set():
                    break
                if self._is_endpoint_reachable(ep):
                    reachable_endpoints.append(ep)
                progress.update(1)
            progress.close()

        print(f'{Colors.WHITE}  Eligible endpoints (reachability or declared operation): {len(reachable_endpoints)}{Colors.RESET}')

        if not reachable_endpoints:
            print(f'{Colors.RED}  [] No reachable endpoints found{Colors.RESET}')
            return self.issues

        per_endpoint_tests = [
            self._test_basic_security,
            self._test_waf_detection,
            self._test_crlf_injection,
            self._test_hpp,
            self._test_sensitive_data_exposure,
            self._test_graphql_introspection,
            self._test_header_manipulation,
            self._test_open_redirect,
            self._test_host_header_injection,
            self._test_blind_sqli,
            self._test_directory_traversal,
            self._test_directory_traversal_body,
            self._test_jwt_vulnerabilities,
            self._test_rate_limit_bypass,
            self._test_business_logic,
        ]

        if self.deep_scan:
            per_endpoint_tests.append(self._test_ssrf_advanced)

        base_tests = len(per_endpoint_tests) + len(self.INJECTION_PAYLOADS)

        total_tasks = len(reachable_endpoints) * base_tests
        print(
            f'{Colors.WHITE}  [STEP 2] Running security tests ({total_tasks} total tests)...{Colors.RESET}'
        )

        if HAS_TQDM and not self.no_tqdm:
            sys.stdout.flush()
            with tqdm(
                total=total_tasks,
                desc="Running tests",
                unit="test",
                ncols=80,
                mininterval=0.1,
            ) as pbar:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_workers
                ) as main_executor:
                    all_tasks: List[concurrent.futures.Future] = []

                    for ep in reachable_endpoints:
                        if stop_requested.is_set():
                            break

                        test_fns = list(per_endpoint_tests)
                        for t in self.INJECTION_PAYLOADS:
                            test_fns.append(
                                partial(self._run_injection_tests_parallel, test_type=t)
                            )

                        for fn in test_fns:
                            if stop_requested.is_set():
                                break
                            all_tasks.append(
                                self._schedule_test(
                                    main_executor, fn, ep, pbar.update
                                )
                            )

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
                            self._log(
                                'Test failed',
                                'N/A',
                                'Info',
                                extra={'error': str(e)[:100]},
                            )

        else:
            progress = ProgressBar(total_tasks, desc="Running tests")
            start_time = time.time()

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as main_executor:
                all_tasks: List[concurrent.futures.Future] = []

                for ep in reachable_endpoints:
                    if stop_requested.is_set():
                        break

                    test_fns = list(per_endpoint_tests)

                    for t in self.INJECTION_PAYLOADS:
                        test_fns.append(
                            partial(self._run_injection_tests_parallel, test_type=t)
                        )

                    for fn in test_fns:
                        if stop_requested.is_set():
                            break
                        all_tasks.append(
                            self._schedule_test(
                                main_executor, fn, ep, progress.update
                            )
                        )

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
                        self._log(
                            'Test failed',
                            'N/A',
                            'Info',
                            extra={'error': str(e)[:100]},
                        )

            progress.close()
            elapsed = time.time() - start_time
            print(f'{Colors.WHITE}  Scan completed in {elapsed:.1f} seconds{Colors.RESET}')


        self._print_final_report()

        return self.issues




    #================ _print_final_report description ##########
    def _print_final_report(self):
        print(f'\n{Colors.BLUE}{"="*70}{Colors.RESET}')
        print(f'{Colors.BOLD}{Colors.GREEN}SCAN COMPLETED{Colors.RESET}')
        print(f'{Colors.BLUE}{"="*70}{Colors.RESET}')

        raw_count = len(self.issues)
        raw_records = self.issues
        raw_telemetry = list(self.telemetry)
        self.issues = [dict(item) for item in raw_records]
        try:
            self._filter_issues()
            filtered_records = self.issues
        finally:
            self.issues = raw_records
            self.telemetry[:] = raw_telemetry
        print(f'API10 raw observations: {raw_count}; filtered/deduplicated results: {len(filtered_records)}')
        total_issues = len(filtered_records)
        if total_issues == 0:
            print(f'{Colors.GREEN} No reportable results after filtering; check coverage and diagnostics.{Colors.RESET}')
            return

        severity_counts = defaultdict(int)
        for issue in filtered_records:
            severity = issue.get('severity', 'Info')
            severity_counts[severity] += 1

        print(f'{Colors.WHITE}Filtered results (including observations): {total_issues}{Colors.RESET}')
        print(f'\n{Colors.BOLD}{Colors.CYAN}[FINDINGS BY SEVERITY]{Colors.RESET}')

        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                if severity == 'Critical':
                    color = Colors.RED
                    symbol = ''
                elif severity == 'High':
                    color = Colors.RED
                    symbol = ''
                elif severity == 'Medium':
                    color = Colors.YELLOW
                    symbol = ''
                elif severity == 'Low':
                    color = Colors.CYAN
                    symbol = ''
                else:
                    color = Colors.WHITE
                    symbol = ''

                print(f'{color}  {symbol} {severity:8}: {count:3} issues{Colors.RESET}')

        risk_scores = [i.get('risk_score', 0) for i in filtered_records if i.get('severity') != 'Info']
        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            max_risk = max(risk_scores)
            print(f'\n{Colors.BOLD}{Colors.CYAN}[RISK ASSESSMENT]{Colors.RESET}')
            print(f'{Colors.WHITE}  Average risk score: {avg_risk:.1f}/10.0{Colors.RESET}')
            print(f'{Colors.WHITE}  Maximum risk score: {max_risk:.1f}/10.0{Colors.RESET}')

            high_risk = [i for i in filtered_records if i.get('risk_score', 0) >= 7.0]
            if high_risk:
                print(f'\n{Colors.BOLD}{Colors.RED}[HIGH RISK ISSUES FOUND]{Colors.RESET}')
                for idx, issue in enumerate(high_risk[:5]):
                    risk = issue.get('risk_score', 0)
                    severity = issue.get('severity', 'Unknown')
                    issue_text = issue.get('issue', 'Unknown')
                    if len(issue_text) > 80:
                        issue_text = issue_text[:77] + '...'

                    print(f'{Colors.RED}  {idx+1}. [{severity}] {issue_text}')
                    print(f'     Risk Score: {risk:.1f}/10.0{Colors.RESET}')

        categories = defaultdict(int)
        for issue in filtered_records:
            if issue.get('severity') != 'Info':
                cat = self._category_of_issue(issue.get('issue', ''))
                categories[cat] += 1

        if categories:
            print(f'\n{Colors.BOLD}{Colors.CYAN}[FINDINGS BY CATEGORY]{Colors.RESET}')
            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                print(f'{Colors.WHITE}  {cat:25}: {count:3} issues{Colors.RESET}')

        telemetry_count = len(getattr(self, 'telemetry', []) or [])
        if telemetry_count:
            print(f'\n{Colors.BOLD}{Colors.CYAN}[TELEMETRY]{Colors.RESET}')
            print(f'{Colors.WHITE}  Network/diagnostic events: {telemetry_count:3} saved separately{Colors.RESET}')

        print(f'\n{Colors.GREEN} Module execution finished; coverage and diagnostics determine test completeness.{Colors.RESET}')
        print(f'{Colors.WHITE}   Run generate_report() for detailed HTML report{Colors.RESET}')
        print(f'{Colors.BLUE}{"="*70}{Colors.RESET}')



    #================ _test_basic_security description ##########
    def _get_with_recovery(self, endpoint, **kwargs):
        # Retry only this safe baseline GET once; write probes are never replayed.
        for attempt in range(2):
            try:
                return self.session.get(endpoint, **kwargs)
            except (requests.ConnectionError, requests.Timeout):
                if attempt:
                    raise
                time.sleep(0.2)

    def _test_basic_security(self, endpoint: str) -> None:
        try:
            r = self._get_with_recovery(endpoint, timeout=(3, self.timeout), allow_redirects=False)
            status = r.status_code

            if status in {401, 403}:
                # If no authentication is configured, 401/403 is expected â€” suppress.
                if self._has_auth_configured():
                    self._log('Auth required / forbidden', endpoint, 'Info', response=r)
            elif status == 404:
                self._log('Not found', endpoint, 'Info', response=r)
            elif status == 405:
                allow = r.headers.get('Allow')
                self._log('Method not allowed', endpoint, 'Info',
                        extra={'allow': allow} if allow else None, response=r)
            elif status >= 500:
                self._log('Server error observed', endpoint, 'Info', response=r)

        except Exception as e:
            self._log('Request failed', endpoint, 'Info', extra={'error': str(e)})


    #================ _test_waf_detection description ##########
    def _test_waf_detection(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return

        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            baseline_status = None
            try:
                self._throttle(domain)
                baseline = self.session.get(endpoint, timeout=(3, self.timeout), allow_redirects=False)
                baseline_status = baseline.status_code
                baseline_server = baseline.headers.get('Server', '')
            except Exception:
                baseline_server = ''

            waf_payloads = [
                "' OR '1'='1",
                ".%2f.%2fetc%2fpasswd",
                "<img src=x onerror=alert(1)>",
                "|cat /etc/passwd",
                "${7*7}",
                "<!--#exec cmd=\"ls\"-->",
                "%00",
                "././",
            ]

            blocked_count = 0
            total_tested = 0

            for payload in waf_payloads[:5]:
                if stop_requested.is_set():
                    return

                try:
                    self._throttle(domain)
                    test_url = f"{endpoint}?test={urlparse.quote(payload)}"
                    r = self.session.get(test_url, timeout=(3, self.timeout), allow_redirects=False)
                    total_tested += 1

                    server_header = r.headers.get('Server', '')
                    body = r.text or ''
                    body_low = body.lower()
                    is_blocked = False
                    blocking_reason = ""

                    if r.status_code == 400 and 'bad request' in body_low:
                        is_blocked = True
                        blocking_reason = "400 Bad Request"
                    elif r.status_code == 403:
                        is_blocked = True
                        blocking_reason = "403 Forbidden"
                    elif r.status_code == 406:
                        is_blocked = True
                        blocking_reason = "406 Not Acceptable"
                    elif r.status_code == 429:
                        is_blocked = True
                        blocking_reason = "429 Too Many Requests"
                    elif r.status_code == 413:
                        is_blocked = True
                        blocking_reason = "413 Payload Too Large"
                    elif any(waf_marker in body_low for waf_marker in WAF_MARKERS):
                        is_blocked = True
                        blocking_reason = "WAF signature detected"

                    if is_blocked:
                        blocked_count += 1

                        waf_type = "Unknown WAF/Filter"
                        if 'openresty' in server_header.lower():
                            waf_type = "OpenResty server (filter product unverified)"
                        elif 'cloudflare' in server_header.lower() or 'cloudflare' in body_low:
                            waf_type = "Cloudflare"
                        elif 'akamai' in server_header.lower() or 'akamai' in body_low:
                            waf_type = "Akamai"
                        elif 'mod_security' in body_low or 'modsecurity' in body_low:
                            waf_type = "ModSecurity"
                        elif 'imperva' in body_low:
                            waf_type = "Imperva"
                        elif 'aws waf' in body_low:
                            waf_type = "AWS WAF"
                        elif 'barracuda' in body_low:
                            waf_type = "Barracuda"
                        elif 'fortinet' in body_low or 'fortiweb' in body_low:
                            waf_type = "Fortinet"

                        if blocked_count == 1 or waf_type != "Unknown WAF/Filter":
                            severity = 'Medium' if waf_type != "Unknown WAF/Filter" else 'Low'
                            self._log(
                                f'WAF/Input filtering detected: {waf_type}',
                                endpoint,
                                severity,
                                payload=payload[:50],
                                response=r,
                                extra={
                                    'waf_type': waf_type,
                                    'blocking_reason': blocking_reason,
                                    'server_header': server_header,
                                    'baseline_status': baseline_status,
                                    'note': f'Payload blocked with {r.status_code}'
                                }
                            )

                except Exception as req_err:
                    self._log(
                        'WAF test request failed',
                        endpoint,
                        'Info',
                        extra={'error': str(req_err), 'payload': payload[:50]}
                    )
                    continue

            if total_tested > 0 and blocked_count / total_tested >= 0.6:
                self._log(
                    'Strong input validation/WAF present',
                    endpoint,
                    'Low',
                    extra={
                        'blocked_ratio': f'{blocked_count}/{total_tested}',
                        'note': 'High percentage of suspicious requests blocked'
                    }
                )

        except Exception as e:
            self._log('WAF detection test failed', endpoint, 'Info', extra={'error': str(e)})





    #================ _test_crlf_injection description ##########
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
            base_variants = [f'%0d%0a{canary_name}: {canary_val}', f'%0d%0aSet-Cookie: {canary_cookie}']
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
            params_to_try = self._param_candidates(
                endpoint, ['q', 'search', 'redirect', 'url', 'return', 'next'],
                limit=3 if self.quick_mode else None)[:6]


            #================ _all_headers description ##########
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
                        # Encoded canary reflection in a canonical redirect is not header injection.
                        set_cookie_lines = [v for k, v in hdrs if k.lower() == 'set-cookie']
                        if any(re.match(r'^\s*' + re.escape(canary_name) + r'\s*=\s*' + re.escape(canary_val) + r'(?:;|$)', v, re.I) for v in set_cookie_lines):
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


    #================ _test_hpp description ##########
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
            hpp_params = self._param_candidates(endpoint, self.HPP_PARAMS)
            if self.quick_mode and not self.deep_scan:
                hpp_params = hpp_params[:self.quick_hpp_max_params]
            for param in hpp_params:
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


    #================ _test_sensitive_data_exposure description ##########
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


    #================ _test_graphql_introspection description ##########
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





    #================ _test_header_manipulation description ##########
    def _test_header_manipulation(self, endpoint: str) -> None:
        return self._test_host_controls(endpoint)


    def _test_blind_sqli(self, endpoint: str) -> None:
        # Response length alone cannot establish a boolean SQL injection.
        with self._options_cache_lock:
            unsupported = self.coverage.setdefault('unsupported_tests', [])
            for name in ('blind_sql_boolean_non_get', 'blind_sql_time'):
                if name not in unsupported:
                    unsupported.append(name)


    def _dirtrav_success_indicators(self, body: str) -> bool:
        if not body:
            return False
        signatures = [
            "root:x:0:0",
            "[extensions]",
            "[fonts]",
            "apache2",
        ]
        low = body.lower()
        return any(sig.lower() in low for sig in signatures)



    #================ _test_directory_traversal description ##########
    def _test_directory_traversal(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''

            repl_index = self._trav_repl_index
            ins_before = self._trav_ins_before
            max_dot    = self._trav_max_dot
            max_ddot   = self._trav_max_ddot
            max_ellipsis = self._trav_max_ellipsis

            base_resp = None
            try:
                self._throttle(domain)
                base_resp = self.session.get(
                    endpoint,
                    headers={'X-APISCAN-Base': '1'},
                    timeout=(3, getattr(self, 'timeout', 10)),
                    allow_redirects=False,
                )
            except Exception:
                base_resp = None

            #================ _get_status description ##########
            def _get_status(resp):
                try:
                    return int(getattr(resp, 'status_code', 0))
                except Exception:
                    return 0

            login_tokens = ('login', 'signin', 'sign-in', 'logon', 'oauth2', 'aad', 'account', 'identity')
            base_status = _get_status(base_resp) if base_resp is not None else 0
            base_loc = (base_resp.headers.get('Location') or '').lower() if base_resp is not None else ''
            base_body_low = (base_resp.text or '').lower() if base_resp is not None else ''

            #================ is_protected_status description ##########
            def is_protected_status(status: int, loc: str, body_low: str) -> bool:
                if status in (401, 403):
                    return True
                if status in (301, 302, 307, 308) and any(t in loc for t in login_tokens):
                    return True
                # Words in successful API data or SPA bundles do not prove denial.
                return False

            baseline_protected = False
            if base_resp is not None:
                baseline_protected = is_protected_status(base_status, base_loc, base_body_low)

            rep_variants = build_traversal_variants_segment_replace(
                endpoint, repl_index, max_dot, max_ddot, max_ellipsis
            )
            ins_variants = build_traversal_variants_insert_between(
                endpoint, ins_before, max_dot, max_ddot, max_ellipsis
            )

            if getattr(self, 'fast_mode', False):
                rep_variants = rep_variants[:min(4, len(rep_variants))]
                ins_variants = ins_variants[:min(4, len(ins_variants))]

            extra = []
            for v in (rep_variants + ins_variants):
                pv = v if v.endswith('/') else v + '/'
                extra.extend([
                    pv + 'etc/passwd',
                    pv + 'WEB-INF/web.xml',
                    pv + 'windows/win.ini',
                ])

            strong_indicators = [
                'root:x:0:0:', 'daemon:x:1:1:',
                'index of /', '<title>index of',
                'parent directory', 'directory listing for', 'directory of ',
                '[extensions]', 'for 16-bit app support',
            ]
            weak_indicators = [
                '/etc/passwd', 'bin:x:', 'boot.ini', ':\\windows\\', 'web-inf/web.xml',
            ]

            #================ is_likely_false_positive description ##########
            def is_likely_false_positive(resp, body_text: str) -> bool:
                if not resp:
                    return False
                ctype = (resp.headers.get('Content-Type') or '').lower()
                if resp.status_code in (401, 403):
                    low = (body_text or '').lower()
                    if any(s in low for s in ('invalid token', 'unauthorized', 'authentication', 'crapiresponse')):
                        return True
                if 'application/json' in ctype and resp.status_code >= 400:
                    return True
                if ctype.startswith(('image/', 'video/', 'audio/')) or 'application/octet-stream' in ctype:
                    return True
                return False

            #================ looks_interesting description ##########
            def looks_interesting(text: str) -> tuple[bool, str]:
                # Challenge prose, reflected paths and links do not establish file access.
                # Require actual file structure, absent from the baseline response.
                signatures = (
                    r'(?m)^root:[^:\r\n]*:0:0:[^\r\n]+$',
                    r'(?m)^daemon:[^:\r\n]*:\d+:\d+:[^\r\n]+$',
                    r'(?m)^\[extensions\]\s*$',
                    r'<title>\s*index of [^<]+</title>',
                )
                for signature in signatures:
                    if re.search(signature, text or '', re.I) and not re.search(signature, base_resp.text if base_resp is not None else '', re.I):
                        return True, 'high'
                return False, 'none'

            use_dirtrav_pb = HAS_TQDM and not self.no_tqdm and self._dirtrav_progress
            dirtrav_pbar = None

            #================ do_req description ##########
            def do_req(url: str, label: str):
                nonlocal dirtrav_pbar
                if stop_requested.is_set():
                    return
                try:
                    self._throttle(domain)
                    r = self.session.get(
                        url,
                        headers={'X-APISCAN-DirTrav': label},
                        timeout=(3, getattr(self, 'timeout', 10)),
                        allow_redirects=False,
                    )
                    body = r.text or ''
                    body_low = body.lower()
                    loc = (r.headers.get('Location') or '')

                    if baseline_protected:
                        new_protected = is_protected_status(r.status_code, loc.lower(), body_low)
                        # A route change alone cannot prove access to the same protected object.
                        # Exclude frontend HTML fallbacks and retain structured data as a candidate.
                        structured_data = False
                        if 'json' in (r.headers.get('Content-Type') or '').lower():
                            try:
                                data = r.json()
                                structured_data = isinstance(data, (dict, list)) and bool(data)
                                if isinstance(data, dict) and any(k in data for k in ('error', 'errors')):
                                    structured_data = False
                            except (ValueError, TypeError):
                                pass
                        if not new_protected and r.status_code == 200 and structured_data:
                            self._log(
                                'Unverified access-control candidate via path traversal',
                                url,
                                'Info',
                                payload=url,
                                response=r,
                                extra={
                                    'vector': 'dirtrav-auth',
                                    'base_endpoint': endpoint,
                                    'baseline_status': base_status,
                                    'baseline_location': base_loc,
                                    'new_status': r.status_code,
                                    'new_location': loc,
                                    'label': label,
                                    'confidence': 'unverified',
                                    'note': 'Denied baseline changed to structured data; protected resource identity and authorization policy require verification.',
                                },
                            )
                            return

                    if is_likely_false_positive(r, body):
                        return

                    is_interesting, confidence = looks_interesting(body)
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    is_binary = (
                        ctype.startswith(('image/', 'video/', 'audio/'))
                        or 'application/octet-stream' in ctype
                    )
                    if is_binary:
                        return

                    if r.status_code == 200 and is_interesting:
                        sev = 'High' if confidence == 'high' else ('Medium' if confidence == 'medium' else 'Low')
                        self._log(
                            f'Directory traversal ({label}) [{r.status_code}]',
                            url,
                            sev,
                            payload=url,
                            response=r,
                            extra={
                                'vector': 'dirtrav',
                                'base_endpoint': endpoint,
                                'confidence': confidence,
                            },
                        )

                    elif r.status_code in (301, 302, 307, 308):
                        loc2 = loc
                        if (not self._redirect_echoes_request(url, loc2)
                                and any(p in loc2.lower() for p in ('./', '.\\', '%2e%2e', 'etc/passwd', 'web-inf'))):
                            self._log(
                                f'Directory traversal ({label}) - suspicious redirect [{r.status_code}]',
                                url,
                                'Medium',
                                payload=url,
                                response=r,
                                extra={
                                    'vector': 'dirtrav',
                                    'base_endpoint': endpoint,
                                    'location': loc2,
                                },
                            )

                    elif r.status_code in (401, 403) and is_interesting and confidence == 'high':
                        self._log(
                            f'Directory traversal ({label}) [{r.status_code}]',
                            url,
                            'Low',
                            payload=url,
                            response=r,
                            extra={
                                'vector': 'dirtrav',
                                'base_endpoint': endpoint,
                                'confidence': confidence,
                            },
                        )

                except Exception as e:
                    self._log(
                        'Directory traversal request error',
                        url,
                        'Info',
                        extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint},
                    )
                finally:
                    if dirtrav_pbar is not None:
                        dirtrav_pbar.update(1)

            variants = [('segment replace', u) for u in rep_variants] + [('segment insert', u) for u in ins_variants]
            variants += [('suffix', u) for u in extra]

            seen = set()
            filtered: list[tuple[str, str]] = []
            orig_path = urlparse.urlsplit(endpoint).path
            for label, u in variants:
                vp = urlparse.urlsplit(u).path
                key = (label, vp)
                if vp != orig_path and key not in seen:
                    filtered.append((label, u))
                    seen.add(key)
            if self.quick_mode and not self.deep_scan:
                filtered = filtered[:self.quick_dirtrav_max_tests]

            variant_count = len(filtered)
            if variant_count == 0:
                return

            if use_dirtrav_pb:
                try:
                    desc = f"DirTrav {endpoint}"
                    if len(desc) > 60:
                        desc = desc[:57] + "..."
                    dirtrav_pbar = tqdm(
                        total=variant_count,
                        desc=desc,
                        unit="req",
                        ncols=80,
                        mininterval=0.1,
                        leave=False,
                    )
                except Exception:
                    dirtrav_pbar = None

            raw_env = self._dirtrav_workers_env
            try:
                total_endpoints = int(getattr(self, 'total_endpoints', 0) or len(getattr(self, 'endpoints', [])))
            except Exception:
                total_endpoints = 0

            per_host_cap = int(getattr(self, 'per_host_max_concurrency', 4))
            global_cap = max(1, int(getattr(self, 'max_workers', 8)))

            if raw_env is not None:
                dirtrav_cap = max(1, int(raw_env))
                source = 'env'
            else:
                if total_endpoints and total_endpoints <= 10:
                    dirtrav_cap = min(8, global_cap // 2 or 1, per_host_cap * 2)
                else:
                    dirtrav_cap = min(4, max(1, global_cap // 4), per_host_cap)
                dirtrav_cap = max(1, dirtrav_cap)
                source = 'auto'

            workers = min(variant_count, dirtrav_cap)
            workers = max(1, workers)

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = []
                    for label, u in filtered:
                        if stop_requested.is_set():
                            break
                        futures.append(executor.submit(do_req, u, label))
                    # Per-endpoint dirtrav timeout: 120 seconds prevents a single
                    # slow/stuck endpoint from hanging the entire Phase 2 scan.
                    dirtrav_deadline = 120
                    for f in concurrent.futures.as_completed(futures, timeout=dirtrav_deadline):
                        try:
                            f.result()
                        except Exception:
                            pass
            except concurrent.futures.TimeoutError:
                if dirtrav_pbar is not None:
                    dirtrav_pbar.close()
                dirtrav_pbar = None
            finally:
                if dirtrav_pbar is not None:
                    dirtrav_pbar.close()

        except Exception as e:
            self._log(
                'Directory traversal test setup failed',
                endpoint,
                'Info',
                extra={'error': str(e), 'vector': 'dirtrav', 'base_endpoint': endpoint},
            )


    #================ _test_directory_traversal_body description ##########
    def _test_directory_traversal_body(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            parsed = urlparse.urlparse(endpoint)
            domain = parsed.netloc or parsed.hostname or ''
            vectors: list[tuple[str, Any, str]] = []

            allowed = set()
            try:
                self._throttle(domain)
                opt = self.session.request(
                    'OPTIONS',
                    endpoint,
                    timeout=(2, 3),
                    allow_redirects=False,
                )
                allowed = {m.strip().upper() for m in (opt.headers.get('Allow') or '').split(',') if m}
            except Exception:
                pass

            cand_methods = ['POST', 'PUT', 'PATCH']
            if allowed:
                c2 = [m for m in cand_methods if m in allowed]
                cand_methods = c2 or cand_methods

            base_json = {'path': '/tmp/a', 'file': 'a.txt', 'name': 'x'}
            vectors += self._body_candidates_json(base_json)

            base_form = {'path': '/tmp/a', 'file': 'a.txt'}
            vectors += self._body_candidates_form(base_form)

            vectors += self._body_candidates_multipart()

            if getattr(self, 'fast_mode', False):
                vectors = vectors[:16]

            use_dirtrav_pb = HAS_TQDM and not self.no_tqdm and self._dirtrav_progress
            dirtrav_pbar = None

            #================ do_req description ##########
            def do_req(entry):
                nonlocal dirtrav_pbar
                if stop_requested.is_set():
                    return
                ctype, payload, label = entry
                try:
                    self._throttle(domain)
                except Exception:
                    pass

                hdrs = dict(getattr(self.session, 'headers', {}))
                hdrs['X-APISCAN-Payload'] = f'body:{label}'
                self._last_payload = f'body:{label}'

                m = cand_methods[0] if cand_methods else 'POST'

                try:
                    if ctype == 'application/json':
                        r = self.session.request(
                            m,
                            endpoint,
                            headers={**hdrs, 'Content-Type': 'application/json'},
                            data=payload,
                            timeout=(3, getattr(self, 'timeout', 10)),
                            allow_redirects=False,
                        )
                    elif ctype == 'application/x-www-form-urlencoded':
                        r = self.session.request(
                            m,
                            endpoint,
                            headers=hdrs,
                            data=payload,
                            timeout=(3, getattr(self, 'timeout', 10)),
                            allow_redirects=False,
                        )
                    else:
                        data, files = payload
                        r = self.session.request(
                            m,
                            endpoint,
                            headers=hdrs,
                            data=data,
                            files=files,
                            timeout=(3, getattr(self, 'timeout', 10)),
                            allow_redirects=False,
                        )
                except Exception as e:
                    self._log(
                        'Directory traversal (body) request error',
                        endpoint,
                        'Info',
                        extra={'error': str(e), 'vector': 'dirtrav-body', 'label': label},
                    )
                    return
                finally:
                    if dirtrav_pbar is not None:
                        dirtrav_pbar.update(1)

                body_text = r.text or ''
                if self._likely_fp_body(r, body_text):
                    return

                interesting, conf = self._looks_interesting_body(body_text)
                if interesting:
                    self._classify_and_log_body(endpoint, label, r, body_text, conf)

            vector_count = len(vectors)
            if vector_count == 0:
                return

            if use_dirtrav_pb:
                try:
                    desc = f"DirTrav body {endpoint}"
                    if len(desc) > 60:
                        desc = desc[:57] + "..."
                    dirtrav_pbar = tqdm(
                        total=vector_count,
                        desc=desc,
                        unit="req",
                        ncols=80,
                        mininterval=0.1,
                        leave=False,
                    )
                except Exception:
                    dirtrav_pbar = None

            raw_env = self._dirtrav_workers_env
            try:
                total_endpoints = int(getattr(self, 'total_endpoints', 0) or len(getattr(self, 'endpoints', [])))
            except Exception:
                total_endpoints = 0

            per_host_cap = int(getattr(self, 'per_host_max_concurrency', 4))
            global_cap = max(1, int(getattr(self, 'max_workers', 8)))

            if raw_env is not None:
                dirtrav_cap = max(1, int(raw_env))
                source = 'env'
            else:
                if total_endpoints and total_endpoints <= 10:
                    dirtrav_cap = min(8, global_cap // 2 or 1, per_host_cap * 2)
                else:
                    dirtrav_cap = min(4, max(1, global_cap // 4), per_host_cap)
                dirtrav_cap = max(1, dirtrav_cap)
                source = 'auto'

            workers = min(vector_count, dirtrav_cap)
            workers = max(1, workers)

            import concurrent.futures as _cf
            try:
                with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = []
                    for v in vectors:
                        if stop_requested.is_set():
                            break
                        futs.append(ex.submit(do_req, v))
                    for f in _cf.as_completed(futs):
                        try:
                            f.result()
                        except Exception:
                            pass
            finally:
                if dirtrav_pbar is not None:
                    dirtrav_pbar.close()

        except Exception as e:
            self._log(
                'Directory traversal (body) setup failed',
                endpoint,
                'Info',
                extra={'error': str(e), 'vector': 'dirtrav-body', 'base_endpoint': endpoint},
            )


    #================ _looks_interesting_body description ##########
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


    #================ _likely_fp_body description ##########
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


    #================ _body_candidates_json description ##########
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


    #================ _body_candidates_form description ##########
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


    #================ _body_candidates_multipart description ##########
    def _body_candidates_multipart(self):
        out = []
        vecs = self._dirtrav_body_vectors()
        for v in vecs[:8]:
            files = {'file': (v, io.BytesIO(b'test'), 'application/octet-stream')}
            data = {'path': v}
            out.append(('multipart/form-data', (data, files), f'multipart:filename'))
        return out



    #================ _is_generic_400_parser_error description ##########
    def _is_generic_400_parser_error(self, r: requests.Response) -> bool:
        if not r or r.status_code != 400:
            return False

        ctype = (r.headers.get('Content-Type') or '').lower()
        body = (r.text or '').lower()
        server = (r.headers.get('Server') or '').lower()

        if 'text/html' not in ctype and not body.startswith('<html'):
            return False

        if '<h1>400 bad request</h1>' in body or '<title>400 bad request</title>' in body:
            return True

        if any(x in server for x in ('openresty', 'nginx', 'haproxy', 'varnish')):
            return True

        return False


    #================ _classify_and_log_body description ##########
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


    #================ _run_injection_tests_parallel description ##########
    def _inspect_sql_error_response(self, response, url, *, baseline):
        body = response.text or ''
        low = body.lower()
        database = self._has_sql_evidence_improved(body) or any(marker in low for marker in (
            'mongo: no documents', 'mongoerror', 'pymongo.errors', 'bson', 'elasticsearch_exception'))
        stacktrace = any(marker in low for marker in (
            'traceback (most recent call last)', 'java.lang.',
            'org.springframework.', 'at system.', 'stack trace:',
            'exception in thread', 'fatal error: uncaught'))
        internal_path = re.search(r'(?:/usr/|/var/www/|/home/|[A-Za-z]:\\)[^\r\n<>]{3,120}', body) is not None
        if 'mongo: no documents in result' in low and not stacktrace and not internal_path:
            self._log('Observation: MongoDB reports no matching document', url, 'Info',
                response=response, extra={'vector': 'error-observation', 'baseline_response': baseline,
                    'note': 'No matching object; this does not demonstrate SQL injection or sensitive data exposure'})
            return
        if database or stacktrace or internal_path:
            self._log('Database error details disclosed' if database else ('Stack trace disclosed' if stacktrace else 'Internal file path disclosed'),
                url, 'Medium', response=response,
                extra={'vector': 'error-disclosure', 'confidence': 'medium',
                       'baseline_response': baseline,
                       'note': 'Error detail disclosure; this does not establish SQL injection'})

    def _test_schema_sql(self, endpoint):
        from copy import deepcopy
        from openapi_universal import iter_operations, build_request
        from scanner_quality import normalize_endpoint, path_values
        from urllib.parse import urlsplit
        if stop_requested.is_set():
            return
        endpoint = endpoint[0] if isinstance(endpoint, tuple) else endpoint
        with self._options_cache_lock:
            seen = getattr(self, '_schema_sql_seen', set())
            if endpoint in seen:
                return
            seen.add(endpoint)
            self._schema_sql_seen = seen
        spec = getattr(self, 'swagger_spec', {})
        values = path_values(spec, getattr(self, 'path_parameter_values', {}))
        operations = []
        for op in iter_operations(spec):
            try:
                url = normalize_endpoint(op['path'], self.base_url, values)
            except ValueError:
                continue
            if urlsplit(url).path == urlsplit(endpoint).path:
                operations.append((op, url))
        if not operations:
            self._record_telemetry('SQL test unavailable', endpoint,
                extra={'error': 'No matching OpenAPI operation', 'execution_status': 'inconclusive'})
            return
        def leaves(value, prefix=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, prefix + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value[:3]):
                    yield from leaves(child, prefix + (index,))
            elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
                yield prefix
        import uuid
        from api10_support import prepare_sql_request, write_record
        if not hasattr(self, 'sql_run_marker'):
            self.sql_run_marker = uuid.uuid4().hex[:12]
        if not hasattr(self, 'sql_details'):
            self.sql_details = []
            self.sql_write_journal = []
        payloads = ["'", "' OR '1'='1'--"]
        field_limit = 4 if self.quick_mode else 12
        for op, url in operations:
            req = build_request(spec, self.base_url, op, None)
            # The shared builder creates empty nested objects; populate declared JSON fields.
            from openapi_universal import _body_from_schema
            def json_example(schema, depth=0):
                if not isinstance(schema, dict) or depth > 6:
                    return {}
                if '$ref' in schema:
                    ref = schema['$ref']
                    if not ref.startswith('#/'):
                        return {}
                    resolved = spec
                    try:
                        for part in ref[2:].split('/'):
                            resolved = resolved[part.replace('~1', '/').replace('~0', '~')]
                    except (KeyError, TypeError):
                        return {}
                    return json_example(resolved, depth + 1)
                if 'example' in schema:
                    return deepcopy(schema['example'])
                if schema.get('type') == 'object' or 'properties' in schema:
                    return {name: json_example(child, depth + 1)
                            for name, child in schema.get('properties', {}).items()}
                if schema.get('type') == 'array':
                    return [json_example(schema.get('items', {}), depth + 1)]
                return _body_from_schema(schema, spec)
            content = (op.get('requestBody') or {}).get('content', {})
            json_schema = (content.get('application/json') or {}).get('schema')
            if json_schema:
                media_example = content['application/json'].get('example')
                req['json'] = deepcopy(media_example) if media_example is not None else json_example(json_schema)
                req.pop('data', None)
            sql_fixtures = dict(getattr(spec, 'request_data', {}))
            sql_fixtures.update(getattr(self, 'sql_request_data', {}))
            req = prepare_sql_request(req, op, sql_fixtures, self.sql_run_marker)
            req.update(url=url, timeout=self.timeout, allow_redirects=False)
            req.setdefault('headers', {})['X-Apiscan-Run'] = self.sql_run_marker
            detail = {'method': op['method'], 'path': op['path'], 'url': url,
                      'state': 'not_applicable', 'baseline_status': None,
                      'fields_available': 0, 'fields_tested': [], 'probe_requests': 0,
                      'probe_responses': 0, 'probe_failures': 0, 'reason': 'No supported scalar fields'}
            with self._options_cache_lock:
                self.sql_details.append(detail)
            if op['method'].upper() == 'DELETE':
                detail.update(reason='DELETE excluded from SQL baseline/probe requests')
                continue
            fields = []
            for location in ('params', 'json', 'data'):
                if location in req and isinstance(req[location], (dict, list)):
                    fields.extend((location, chain) for chain in leaves(req[location]))
            for name, file in req.get('files', {}).items():
                fields.append(('files', (name, 0 if file[0] is not None else 1)))
            for param in op.get('parameters', []):
                if param.get('in') == 'path':
                    fields.append(('path', (param['name'],)))
            raw_operation = spec.get('paths', {}).get(op['path'], {}).get(op['method'].lower(), {})
            if raw_operation.get('x-discovery-state') == 'observed-login':
                from differential_checks import login_sql
                from universal_runtime import isolated_session, anonymous_request
                login_client = isolated_session(self.session)
                try:
                    login_request = anonymous_request(req, spec)
                    def isolated_login_send(**candidate):
                        login_client.cookies.clear()
                        return login_client.request(**candidate)
                    login_result = login_sql(isolated_login_send, login_request,
                        before_send=lambda: self._throttle(urlsplit(url).netloc))
                finally:
                    login_client.close()
                detail['login_sql'] = login_result
                detail['probe_requests'] += login_result['requests']
                detail['probe_responses'] += login_result['responses']
                detail['probe_failures'] += login_result['failures']
                if login_result['state'] == 'candidate':
                    self._log('Possible SQL authentication bypass', url, 'High',
                        extra={'vector':'sql-login', 'method':'POST','confidence':'medium',
                               'status_code':login_result['status_code'],
                               'evidence':login_result,
                               'note':'Observed login tested in isolated session with invalid credentials; issued tokens were not used or exported'})
            detail['fields_available'] = len(fields)
            detail['field_limit'] = field_limit
            detail['scope_limited'] = len(fields) > field_limit
            if not fields:
                if raw_operation.get('x-requires-request-data'):
                    detail.update(state='untested', reason='Discovered runtime body requires --request-data-file')
                    self._record_telemetry('SQL request input unavailable', url,
                        extra={'method':op['method'],'reason':detail['reason']})
                continue
            try:
                self._throttle(urlsplit(url).netloc)
                baseline = self.session.request(**deepcopy(req))
                detail['baseline_status'] = baseline.status_code
                record = write_record(req, baseline, self.sql_run_marker, 'baseline')
                if record:
                    with self._options_cache_lock:
                        self.sql_write_journal.append(record)
            except requests.RequestException as exc:
                detail.update(state='incomplete', reason='Baseline transport error')
                self._record_telemetry('SQL baseline failed', url, extra={'error': str(exc)})
                continue
            baseline_db_error = self._has_sql_evidence_improved(baseline.text or '')
            if baseline_db_error or baseline.status_code >= 500:
                self._inspect_sql_error_response(baseline, url, baseline=True)
            from response_evidence import baseline_problem
            problem = baseline_problem(baseline.status_code)
            if problem or baseline_db_error:
                detail.update(state='untested', reason=('Baseline database error' if baseline_db_error else problem))
                if 300 <= baseline.status_code < 400:
                    detail['redirect_location'] = baseline.headers.get('Location', '')[:1000]
                detail['next_action'] = {
                    400: 'Supply valid operation input with --request-data-file',
                    422: 'Supply schema-valid operation input with --request-data-file',
                    401: 'Supply valid authentication',
                    403: 'Check authentication, permissions and required operation input',
                    404: 'Check route and existing object IDs with --ids-file',
                    415: 'Check declared request media type and body',
                    301: 'Set the authorized canonical API base URL and recheck the operation baseline',
                    302: 'Check whether the redirect requires login or a different authorized API base URL',
                    307: 'Set the authorized canonical API base URL and recheck the operation baseline',
                    308: 'Set the authorized canonical API base URL and recheck the operation baseline',
                }.get(baseline.status_code, 'Inspect saved baseline response body and resolve server errors before differential SQL testing')

                self._record_telemetry('SQL baseline unsuitable', url,
                    extra={'error': 'Baseline unsuitable or already contains database errors',
                           'status_code': baseline.status_code,
                           'response_body': (baseline.text or '')[:20000],
                           'response_content_type': baseline.headers.get('Content-Type', ''),
                           'method': req['method']})
                continue
            detail.update(state='completed', reason='SQL error probes, quote-pair differential and applicable GET boolean controls')

            def build_probe(location, chain, value):
                probe = deepcopy(req)
                if location == 'path':
                    probe['url'] = normalize_endpoint(op['path'], self.base_url,
                        dict(values, **{chain[0]: value}))
                elif location == 'files':
                    file = list(probe['files'][chain[0]])
                    file[chain[1]] = value
                    probe['files'][chain[0]] = tuple(file)
                else:
                    container = probe[location]
                    for key in chain[:-1]:
                        container = container[key]
                    container[chain[-1]] = value
                return probe

            def send_probe(probe, payload):
                self._throttle(urlsplit(url).netloc)
                detail['probe_requests'] += 1
                try:
                    response = self.session.request(**probe)
                except requests.RequestException as exc:
                    detail['probe_failures'] += 1
                    detail.update(state='incomplete', reason='SQL probe transport error')
                    self._record_telemetry('SQL probe failed', url, payload=payload,
                        extra={'error': str(exc), 'method': op['method']})
                    return None
                detail['probe_responses'] += 1
                record = write_record(probe, response, self.sql_run_marker, 'sql_probe')
                if record:
                    with self._options_cache_lock:
                        self.sql_write_journal.append(record)
                return response

            def original_value(location, chain):
                if location == 'path':
                    value = values.get(chain[0])
                elif location == 'files':
                    return ''
                else:
                    value = req.get(location)
                    try:
                        for key in chain:
                            value = value[key]
                    except (KeyError, IndexError, TypeError):
                        return ''
                if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                    return ''
                return str(value)

            for location, chain in fields[:field_limit]:
                field_name = location + ':' + '.'.join(map(str, chain))
                detail['fields_tested'].append(field_name)
                base_value = original_value(location, chain)
                marked = location in ('json', 'data') and str(chain[-1]).lower() in ('name', 'title', 'description')
                quote_payload = quote_response = quote_url = None
                error_logged = False
                for payload in (base_value + "'", "' OR '1'='1'--"):
                    if stop_requested.is_set():
                        return
                    if marked and 'apiscan_' not in payload:
                        payload = 'apiscan_' + self.sql_run_marker + payload
                    probe = build_probe(location, chain, payload)
                    response = send_probe(probe, payload)
                    if response is None:
                        continue
                    if quote_payload is None:
                        quote_payload, quote_response, quote_url = payload, response, probe['url']
                    if response.status_code >= 500:
                        self._record_telemetry('SQL probe server error response', probe['url'],
                            payload=payload, response=response,
                            extra={'execution_status': 'response_received',
                                   'response_body': (response.text or '')[:20000],
                                   'method': req['method']})
                        if not self._has_sql_evidence_improved(response.text or ''):
                            self._inspect_sql_error_response(response, probe['url'], baseline=False)
                    if self._has_sql_evidence_improved(response.text or ''):
                        error_logged = True
                        self._log('Possible SQL injection', probe['url'], 'High',
                            payload=payload, response=response,
                            extra={'vector': 'sql-error', 'method': op['method'],
                                   'tested_field': field_name,
                                   'baseline_status': baseline.status_code,
                                   'confidence': 'medium',
                                   'note': 'Database error absent from baseline; exploitability requires review'})

                # Silent 500 on a quote: confirm with escaped quote, inert control and repeat.
                if (error_logged or quote_response is None or quote_response.status_code < 500
                        or not quote_payload.endswith("'")):
                    continue
                prefix = quote_payload[:-1]
                statuses = {}
                for label, value in (('escaped', prefix + "''"), ('control', prefix + 'apiscan'),
                                     ('repeat', quote_payload)):
                    if stop_requested.is_set():
                        return
                    response = send_probe(build_probe(location, chain, value), value)
                    if response is None:
                        break
                    statuses[label] = response.status_code
                if (len(statuses) == 3 and statuses['repeat'] >= 500
                        and statuses['escaped'] == baseline.status_code
                        and statuses['control'] == baseline.status_code):
                    self._log('Possible SQL injection (quote-pair differential)', quote_url, 'High',
                        payload=quote_payload, response=quote_response,
                        extra={'vector': 'sql-quote-pair', 'method': op['method'],
                               'tested_field': field_name,
                               'baseline_status': baseline.status_code,
                               'statuses': dict(quote=quote_response.status_code, **statuses),
                               'confidence': 'medium',
                               'note': 'Unbalanced quote gives a repeatable server error; escaped quote and inert control match the baseline. No database error disclosed; review required'})

            # Boolean comparison is deliberately limited to read-only query fields.
            from differential_checks import boolean_sql
            detail['boolean'] = []
            if req['method'].upper() == 'GET':
                query_fields = [chain[0] for location, chain in fields
                                if location == 'params' and len(chain) == 1]
                for field in query_fields[:(2 if self.quick_mode else 4)]:
                    if stop_requested.is_set():
                        return
                    result = boolean_sql(self.session.request, req, baseline, field,
                        before_send=lambda: self._throttle(urlsplit(url).netloc))
                    detail['boolean'].append(result)
                    detail['probe_requests'] += result['requests']
                    detail['probe_responses'] += result['responses']
                    detail['probe_failures'] += result['failures']
                    if result['state'] in ('incomplete', 'inconclusive'):
                        detail.update(state='incomplete', reason=result['reason'])
                        self._record_telemetry('Boolean SQL comparison incomplete', url,
                            extra={'method':'GET','tested_field':str(field),'reason':result['reason']})
                    if result['state'] == 'candidate':
                        self._log('Possible boolean SQL injection', url, 'High',
                            extra={'vector':'sql-boolean', 'method':'GET',
                                   'status_code':result['status_code'],
                                   'tested_field':'params:'+str(field),
                                   'confidence':'medium', 'evidence':result,
                                   'note':'Repeated structured-response differential; review query semantics'})

            login_detail = detail.get('login_sql', {})
            if login_detail.get('state') in ('incomplete', 'inconclusive'):
                detail.update(state='incomplete', reason=login_detail['reason'])
                self._record_telemetry('SQL login comparison incomplete', url,
                    extra={'method':'POST','reason':login_detail['reason']})

    def _run_injection_tests_parallel(self, endpoint, test_type: str) -> None:
        if test_type == 'sql':
            return self._test_schema_sql(endpoint)
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
            method_preference = preferred_method if preferred_method and preferred_method.upper() != 'AUTO' else 'auto'
            test_url = f'{base_endpoint}?input={urlparse.quote(p)}'
            test_urls.append((test_url, method_preference, p))
            test_urls.append((base_endpoint.replace('%7BpostId%7D', urlparse.quote_plus(p)), 'GET', p))

        if self.quick_mode and not self.deep_scan and test_type == 'sql':
            test_urls = test_urls[:self.quick_sql_max_tests]

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
                except concurrent.futures.CancelledError:
                    continue
                except __import__('probe_policy').ProbeSkipped:
                    self._execution_state.skipped = True
                    for pending in futures:
                        pending.cancel()
                except Exception as exc:
                    self._record_telemetry('Injection worker failed', base_endpoint, extra={'error': str(exc)})


    #================ _test_injection description ##########
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

        nosql_baseline = nosql_control = None

        if self.quick_mode and not self.deep_scan and attack_type in {'sql', 'path'}:
            try:
                self._throttle(domain)
                r = self.session.get(test_url, timeout=(1, self.timeout), allow_redirects=False)
                if self._is_injection_successful(r, attack_type, payload=p, baseline_response=nosql_baseline, control_response=nosql_control):
                    self._log('NoSQL error triggered by probe; exploitability unverified' if attack_type == 'nosql' else f'Possible {attack_type.upper()} injection', test_url, 'Medium' if attack_type == 'nosql' else 'Critical', payload=p, response=r)
            except Exception as req_err:
                self._log(
                    'Quick injection probe failed',
                    test_url,
                    'Info',
                    extra={'error': str(req_err), 'type': attack_type}
                )
            return

        param_candidates = self._param_candidates(base, [
            'q', 'query', 'search', 'id', 'user', 'username', 'email', 'name',
            'term', 's', 'page', 'limit', 'offset', 'code', 'token', 'redirect', 'next', 'return', 'ref'
        ])

        allowed = set()
        try:
            with self._options_cache_lock:
                cached = self._options_cache.get(base)
            if cached is not None:
                allowed = cached
            else:
                try:
                    self._throttle(domain)
                    opt = self.session.request('OPTIONS', base, timeout=(2, 3), allow_redirects=False)
                    allow_hdr = opt.headers.get('Allow') or opt.headers.get('allow') or ''
                    allowed = {m.strip().upper() for m in allow_hdr.split(',') if m.strip()}
                except Exception:
                    allowed = set()
                with self._options_cache_lock:
                    self._options_cache[base] = allowed
        except Exception:
            allowed = set()

        declared_operations = self.session.matching(base) if callable(getattr(self.session, 'matching', None)) else []
        if declared_operations:
            allowed = {op['method'].upper() for op in declared_operations}
            method = 'GET' if 'GET' in allowed else method

        if method == 'auto' and allowed:
            for cand in ('POST', 'PUT', 'PATCH', 'GET'):
                if cand in allowed:
                    method = cand
                    break

        nosql_baseline = nosql_control = None
        if attack_type == 'nosql':
            try:
                self._throttle(domain)
                nosql_baseline = self.session.get(base, timeout=(3, self.timeout), allow_redirects=False)
                self._throttle(domain)
                nosql_control = self.session.get(base+'?input=apiscan_inert_control', timeout=(3, self.timeout), allow_redirects=False)
                if not (200 <= nosql_baseline.status_code < 300 and 200 <= nosql_control.status_code < 300):
                    self._record_telemetry('NoSQL baseline unsuitable', base, extra={'baseline_status':nosql_baseline.status_code,'control_status':nosql_control.status_code})
                    return
            except Exception as exc:
                self._record_telemetry('NoSQL control failed', base, extra={'error':str(exc)})
                return

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

                        try:
                            self._throttle(domain)
                            r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)


                            if r.status_code == 400:
                                server_header = r.headers.get('Server', '').lower()
                                body_low = (r.text or '').lower()

                                waf_detected = False
                                waf_name = "Unknown"

                                if 'cloudflare' in server_header or 'cloudflare' in body_low:
                                    waf_detected = True
                                    waf_name = "Cloudflare WAF"
                                elif 'akamai' in server_header or 'akamai' in body_low:
                                    waf_detected = True
                                    waf_name = "Akamai"
                                elif any(marker in body_low for marker in ['mod_security', 'modsecurity']):
                                    waf_detected = True
                                    waf_name = "ModSecurity"

                                if waf_detected:
                                    self._log(
                                        f'WAF detected: {waf_name} - Blocked {attack_type.upper()} attempt',
                                        attack_url,
                                        'Low',
                                        payload=p[:100],
                                        response=r,
                                        extra={
                                            'waf': waf_name,
                                            'attack_type': attack_type,
                                            'parameter': k,
                                            'note': 'Injection attempt blocked by WAF'
                                        }
                                    )
                                elif 'bad request' in body_low:

                                    self._log(
                                        f'Strict input validation - {attack_type.upper()} blocked (400)',
                                        attack_url,
                                        'Low',
                                        payload=p[:100],
                                        response=r,
                                        extra={
                                            'attack_type': attack_type,
                                            'parameter': k,
                                            'server': server_header,
                                            'note': 'Request rejected with 400 Bad Request'
                                        }
                                    )


                            if self._is_injection_successful(r, attack_type, payload=p, baseline_response=nosql_baseline, control_response=nosql_control):
                                self._log('NoSQL error triggered by probe; exploitability unverified' if attack_type == 'nosql' else f'Possible {attack_type.upper()} injection', attack_url, 'Medium' if attack_type == 'nosql' else 'Critical', payload=p, response=r)
                                return
                        except Exception as req_err:
                            self._log('Request failed during injection test', attack_url, 'Info',
                                    extra={'error': str(req_err), 'type': attack_type})
                        finally:
                            q[k] = old

                candidates = param_candidates[:5] if not fast else param_candidates[:3]
                for k in candidates:
                    attack_url = f'{base}?{k}={urlparse.quote_plus(p)}'
                    try:
                        self._throttle(domain)
                        r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)


                        if r.status_code == 400:
                            server_header = r.headers.get('Server', '').lower()
                            body_low = (r.text or '').lower()

                            if 'openresty' in server_header or 'bad request' in body_low:
                                self._log(
                                    f'Input filtering detected - {attack_type.upper()} blocked',
                                    attack_url,
                                    'Low',
                                    payload=p[:100],
                                    response=r,
                                    extra={
                                        'attack_type': attack_type,
                                        'parameter': k,
                                        'server': server_header,
                                        'note': '400 Bad Request on suspicious input'
                                    }
                                )


                        if self._is_injection_successful(r, attack_type, payload=p, baseline_response=nosql_baseline, control_response=nosql_control):
                            self._log('NoSQL error triggered by probe; exploitability unverified' if attack_type == 'nosql' else f'Possible {attack_type.upper()} injection', attack_url, 'Medium' if attack_type == 'nosql' else 'Critical', payload=p, response=r)
                            return
                    except Exception as req_err:
                        self._log('Request failed during injection test', attack_url, 'Info',
                                extra={'error': str(req_err), 'type': attack_type})

            post_allowed = ('POST' in allowed) or (method in ('auto', 'POST')) or (not allowed)
            if allowed and 'POST' not in allowed and method not in ('POST', 'PUT', 'PATCH'):
                post_allowed = False

            if declared_operations:
                # Generic injection uses query probes. Schema-aware SQL handles
                # declared write bodies separately; do not fabricate form bodies.
                post_allowed = False

            if post_allowed:
                tried_any = True
                form_keys = param_candidates[:6] if not fast else param_candidates[:3]
                form_body = {k: p for k in form_keys}

                try:
                    self._throttle(domain)
                    r = self.session.post(base, data=form_body, timeout=(3, max(self.timeout, 10)), allow_redirects=False)


                    if r.status_code == 400:
                        server_header = r.headers.get('Server', '').lower()
                        body_low = (r.text or '').lower()

                        if 'openresty' in server_header or 'bad request' in body_low:
                            self._log(
                                f'POST input filtering detected - {attack_type.upper()} blocked',
                                base + ' (POST)',
                                'Low',
                                payload=p[:100],
                                response=r,
                                extra={
                                    'attack_type': attack_type,
                                    'method': 'POST',
                                    'server': server_header,
                                    'note': '400 Bad Request on POST with suspicious input'
                                }
                            )


                    if self._is_injection_successful(r, attack_type, payload=p, baseline_response=nosql_baseline, control_response=nosql_control):
                        self._log('NoSQL error triggered by probe; exploitability unverified' if attack_type == 'nosql' else f'Possible {attack_type.upper()} injection', base + ' (form)', 'Medium' if attack_type == 'nosql' else 'Critical', payload=p, response=r)
                        return
                except Exception as req_err:
                    self._log('POST injection test failed', base, 'Info',
                            extra={'error': str(req_err), 'type': attack_type})

            if '%7B' in test_url.lower() and '%7D' in test_url.lower():
                attack_url = re.sub(r'%7B[^%]+%7D', urlparse.quote_plus(p), test_url, count=1, flags=re.I)
                try:
                    self._throttle(domain)
                    r = self.session.get(attack_url, timeout=(3, self.timeout), allow_redirects=False)


                    if r.status_code == 400:
                        server_header = r.headers.get('Server', '').lower()
                        body_low = (r.text or '').lower()

                        if 'openresty' in server_header or 'bad request' in body_low:
                            self._log(
                                f'Template parameter filtering - {attack_type.upper()} blocked',
                                attack_url,
                                'Low',
                                payload=p[:100],
                                response=r,
                                extra={
                                    'attack_type': attack_type,
                                    'server': server_header,
                                    'note': '400 Bad Request on template parameter injection'
                                }
                            )


                    if self._is_injection_successful(r, attack_type, payload=p, baseline_response=nosql_baseline, control_response=nosql_control):
                        self._log('NoSQL error triggered by probe; exploitability unverified' if attack_type == 'nosql' else f'Possible {attack_type.upper()} injection', attack_url, 'Medium' if attack_type == 'nosql' else 'Critical', payload=p, response=r)
                        return
                except Exception as req_err:
                    self._log('Template injection test failed', attack_url, 'Info',
                            extra={'error': str(req_err), 'type': attack_type})

            if not tried_any:
                self._log('Injection test skipped (no method)', test_url, 'Info')
        except Exception as exc:
            self._log('Injection test failed', test_url, 'Info', extra={'error': str(exc), 'type': attack_type})


    def _nosql_error_signatures(self, response):
        if response is None:
            return set()
        text = response.text or ''
        try:
            data = response.json()
            if not isinstance(data, dict):
                return set()
            error = data.get('error') or data.get('errors')
            if not error and response.status_code >= 400:
                error = data.get('message')
            if not error:
                return set()  # Normal JSON records, including educational hints.
            text = json.dumps(error)
        except (ValueError, TypeError):
            if response.status_code < 400:
                return set()
        patterns = (
            r'\b(?:MongoServerError|MongoError|BSONError|BSONTypeError|MongoParseError)\b',
            r'\bpymongo\.errors\.[A-Za-z]+',
            r'\bunrecognized pipeline stage(?: name)?\b',
            r'\bunknown (?:top level )?operator\s*:\s*\$',
        )
        return {pattern for pattern in patterns if re.search(pattern, text, re.I)}

    #================ _is_injection_successful description ##########
    def _is_injection_successful(self, response: requests.Response, attack_type: str, *, baseline_latency: float = 0.5, payload: str = '', baseline_response=None, control_response=None) -> bool:
        if response is None:
            return False

        try:
            status = int(getattr(response, 'status_code', 0))
        except Exception:
            status = 0

        text = response.text or ''
        low = text.lower()


        server_header = response.headers.get('Server', '').lower()

        if status == 400 and 'openresty' in server_header and 'bad request' in low:

            return False


        if status in [403, 406, 429, 400] and any(waf_indicator in low for waf_indicator in [
            'access denied', 'request blocked', 'forbidden',
            'security violation', 'mod_security', 'cloudflare'
        ]):

            return False


        if status in {400, 422} and self._is_parse_error(response):
            return False

        if attack_type == 'nosql':
            if baseline_response is None or control_response is None:
                return False
            evidence = self._nosql_error_signatures(response)
            return bool(evidence - self._nosql_error_signatures(baseline_response)
                        - self._nosql_error_signatures(control_response))

        if attack_type == 'sql':
            if self._has_sql_evidence_improved(text):
                return True
            try:
                elapsed = response.elapsed.total_seconds() if response.elapsed else 0.0
            except Exception:
                elapsed = 0.0
            return False

        if status >= 500:
            if attack_type in {'ssti', 'ldap', 'xxe'}:
                return self._has_engine_marker(low, attack_type)
            return False

        if attack_type == 'xss':
            if not payload or payload.lower() not in low:
                return False
            ctype = (response.headers.get('Content-Type') or '').lower()
            if ctype and not any(t in ctype for t in ('html', 'xml')):
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

    #================ _has_engine_marker description ##########
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


    #================ _is_parse_error description ##########
    def _is_parse_error(self, response: requests.Response) -> bool:
        try:
            ctype = (response.headers.get('Content-Type') or '').lower()
        except Exception:
            ctype = ''
        body = (response.text or '').lower()
        return any((p in body for p in self.JSON_PARSE_ERRORS)) or ('application/json' in ctype and response.status_code == 400)


    #================ _looks_like_waf description ##########
    def _looks_like_waf(self, response: requests.Response) -> bool:
        body = (response.text or '').lower()
        return response.status_code in {403, 406, 429} or any((p in body for p in self.WAF_PATTERNS))


    #================ _is_generic_400_bad_request description ##########
    def _is_generic_400_bad_request(self, r: requests.Response) -> bool:
        try:
            if getattr(r, "status_code", 0) != 400:
                return False

            server = (r.headers.get("Server") or "").lower()
            ctype = (r.headers.get("Content-Type") or "").lower()
            body = (r.text or "").strip().lower()


            if "text/html" not in ctype and not body.startswith("<html"):
                return False

            if len(body) > 4096:
                return False


            markers = (
                "<title>400 bad request</title>",
                "<h1>400 bad request</h1>",
            )
            if not any(m in body[:1200] for m in markers):
                return False


            if "openresty" in server or "nginx" in server:
                return True
            if "openresty/" in body or "nginx/" in body:
                return True

            return False
        except Exception:
            return False


    #================ _is_generic_html_error description ##########
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


    #================ _payload_reflected description ##########
    def _payload_reflected(self, payload: str, response_text: str) -> bool:
        if not payload:
            return False
        t = (response_text or '').lower()
        from urllib.parse import quote
        variants = {payload.lower(), quote(payload).lower(), quote(payload, safe='').lower()}
        return any((v in t for v in variants))


    #================ _is_payload_reflected description ##########
    def _is_payload_reflected(self, text: str, payload: str) -> bool:
        if not payload or not text:
            return False
        return payload.lower() in text.lower()


    #================ classify_transport_anomaly description ##########
    def classify_transport_anomaly(self, url: str, method: str, exc: Exception | None, elapsed: float) -> str:
        e = (str(exc) if exc else '').lower()
        if 'hpe_invalid' in e or 'invalid chunk size' in e or 'http/1.1 400 bad request' in e:
            return 'Medium'
        if elapsed > 8.0 and (not e):
            return 'Info'
        return 'Info'


    #================ _detect_server_errors description ##########
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


    #================ _is_endpoint_reachable description ##########
    def _is_endpoint_reachable(self, endpoint: str) -> bool:
        if hasattr(self.session,'matching'):
            operations=self.session.matching(endpoint)
            if operations and not any(op['method']=='GET' for op in operations):
                self._record_telemetry('Read-only reachability deferred',endpoint,
                    extra={'execution_status':'not_applicable','note':'Declared non-GET operation retained for method-specific tests; no preliminary write sent.'})
                return True
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

    #================ _should_skip_heavy_endpoint description ##########
    def _should_skip_heavy_endpoint(self, endpoint: str) -> bool:
        if hasattr(self.session,'matching'):
            operations=self.session.matching(endpoint)
            if operations and not any(op['method']=='GET' for op in operations): return False
        try:
            if self._has_auth_configured():
                return False
            domain = urlparse.urlparse(endpoint).netloc or ""
            self._throttle(domain)
            resp = self.session.get(endpoint, timeout=(2, 4), allow_redirects=False)
            if resp.status_code in (401, 403):
                # No auth configured â€” 401/403 is expected, suppress finding.
                return True
        except Exception as e:
            self._record_telemetry(
                'Endpoint precheck failed',
                endpoint,
                extra={'error': str(e), 'vector': 'precheck'},
            )
        return False

    #================ _has_auth_configured check if any auth is set up ##########
    def _has_auth_configured(self) -> bool:
        try:
            headers = getattr(self.session, 'headers', {}) or {}
            return bool(
                headers.get('Authorization')
                or headers.get('X-API-Key')
                or headers.get('Api-Key')
                or headers.get('Cookie')
            )
        except Exception:
            return False


    #================ _filter_issues description ##########
    def _filter_issues(self) -> list[dict]:
        cleaned, seen = ([], set())

        IGNORE_TIMEOUTS = bool(getattr(self, 'IGNORE_NETWORK_TIMEOUTS', True))
        NETWORK_TIMEOUT_PATTERNS = tuple(getattr(self, 'NETWORK_TIMEOUT_PATTERNS', (
            'httpconnectionpool',
            'read timed out',
            'connect timeout',
            'connecttimeout',
            'write timeout',
            'newconnectionerror',
            'failed to establish a new connection',
            'max retries exceeded',
            'temporarily unavailable',
            'winerror 10060',
            'winerror 10061',
        )))
        GENERIC_4XX = set(getattr(self, 'GENERIC_4XX', {
            400, 401, 403, 404, 405, 406, 409, 415, 422, 429
        }))

        for issue in self.issues:
            desc_text = str(issue.get('description', ''))
            desc_low = desc_text.lower()
            err_low = str(issue.get('error', '')).lower()
            body = issue.get('response_body') or ''
            body_low = body.lower()
            is_waf_detection = any(term in desc_low for term in [
                'waf detected',
                'input filtering detected',
                'openresty',
                'cloudflare',
                'akamai',
                'mod_security'
            ])

            if is_waf_detection:

                issue['severity'] = 'Info'
                issue['risk_score'] = 0.0
                issue['evidence_status'] = 'observation' 
                cleaned.append(issue)
                continue


            if 'failed to parse' in desc_low or "name 'parsed' is not defined" in desc_low:
                continue

            if any(p in err_low for p in NETWORK_TIMEOUT_PATTERNS):
                if IGNORE_TIMEOUTS:
                    continue
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

            #================ _h description ##########
            def _h(name: str) -> str:
                return (hdrs_map.get(name) or hdrs_map.get(name.title()) or '').lower()

            ctype = _h('Content-Type')
            acao = _h('Access-Control-Allow-Origin')
            acac = _h('Access-Control-Allow-Credentials')
            cdisp = _h('Content-Disposition')
            loc_low = _h('Location')

            issue_name = (issue.get('issue') or '').lower()
            vector_name = (issue.get('vector') or '').lower()

            if issue_name.startswith('possible sql injection'):
                has_evidence = False
                try:
                    if hasattr(self, '_has_sql_evidence_improved'):
                        has_evidence = bool(self._has_sql_evidence_improved(body))
                except Exception:
                    has_evidence = False

                if status in GENERIC_4XX or 'application/problem+json' in ctype:
                    if not has_evidence:
                        issue['severity'] = 'Info'
                        issue['issue'] = 'Possible SQL injection (blocked or validated)'
                        issue['description'] = (
                            'Request rejected (4xx/problem+json) without SQL or database error markers'
                        )
                        issue['confidence'] = issue.get('confidence') or 'low'
                    cleaned.append(issue)
                    continue

                if status >= 500 and not has_evidence:
                    issue['severity'] = 'Info'
                    issue['issue'] = 'Server error without SQL evidence'
                    issue['description'] = 'Generic 5xx response without SQL or database error markers'
                    cleaned.append(issue)
                    continue

                if not has_evidence:
                    continue

            if ('nosql' in desc_low) or issue_name.startswith('possible nosql'):
                neg_patterns = getattr(self, 'NOSQL_NEGATIVE_PATTERNS', ())
                if any(p in body_low for p in neg_patterns):
                    continue
                if status in GENERIC_4XX and 'application/json' in ctype:
                    issue['severity'] = 'Info'

            if issue_name.startswith('directory traversal'):
                confidence = (issue.get('confidence') or '').lower()

                if vector_name == 'dirtrav-auth':
                    if status in (200, 201, 202, 204, 206, 301, 302, 303, 307, 308):
                        if issue.get('severity') in (None, 'Low', 'Info'):
                            issue['severity'] = 'High' if confidence == 'high' else 'Medium'
                        if not issue_name.startswith('access control bypass'):
                            issue['issue'] = (
                                'Access control bypass via directory traversal to auth endpoint'
                            )
                    elif status in (401, 403):
                        if confidence == 'high' and issue.get('severity') in (None, 'Low', 'Info'):
                            issue['severity'] = 'Medium'
                        if not issue_name.startswith('access control bypass'):
                            issue['issue'] = (
                                'Access control bypass via directory traversal to auth endpoint'
                            )
                else:
                    if status in (401, 403) and any(
                        s in body_low for s in ('unauthorized', 'invalid token', 'authentication')
                    ):
                        if confidence != 'high':
                            continue

                    if 'application/json' in ctype and status >= 400 and confidence != 'high':
                        continue

                    if confidence == 'low' and issue.get('severity') in ('High', 'Medium'):
                        issue['severity'] = 'Low'

            if desc_low.startswith('possible ssrf'):
                generic_err = (
                    'connection refused',
                    'timed out',
                    'no route to host',
                    'dns error',
                    'invalid host',
                )
                if any(g in body_low for g in generic_err) or status in {400, 404, 405}:
                    issue['severity'] = 'Info'

            if desc_low.startswith('possible access control bypass via spoofed header'):
                is_json = 'application/json' in ctype
                admin_hit = False
                try:
                    import re as _re
                    admin_hit = _re.search(
                        r'(?i)(<title>[^<]*admin[^<]*</title>|\badmin\s*panel\b|href=["\']/admin)',
                        body,
                    ) is not None
                except Exception:
                    admin_hit = False

                if is_json and not loc_low:
                    issue['severity'] = 'Info'
                elif not admin_hit and '/admin' not in loc_low:
                    issue['severity'] = 'Info'

            if issue_name.startswith('broad cors policy'):
                is_static = (
                    ctype.startswith(('image/', 'video/', 'audio/', 'font/'))
                    or 'application/octet-stream' in ctype
                    or 'application/pdf' in ctype
                    or 'filename=' in cdisp
                )
                if is_static and acac != 'true' and issue.get('severity') in (None, 'Low', 'Info'):
                    continue

            if status == 404 and 'directory traversal' not in issue_name:
                interesting_markers = (
                    'root:x:0:0:',
                    'daemon:x:',
                    'index of /',
                    '<web-app',
                    '[extensions]',
                )
                if not any(s in body_low for s in interesting_markers):
                    continue
                if issue.get('severity') in ('High', 'Critical'):
                    issue['severity'] = 'Info'

            if issue.get('status_code') in ('-', None) or 'timeout' in err_low:
                if issue.get('error') or issue.get('parse_error'):
                    self._record_telemetry(
                        issue.get('issue', 'Telemetry'),
                        issue.get('target') or issue.get('url') or issue.get('endpoint') or '',
                        payload=issue.get('payload'),
                        extra={k: v for k, v in issue.items() if k not in ('response_body', 'response_headers')},
                    )
                    continue
                issue['severity'] = 'Info'

            if issue.get('severity') == 'Info' and issue.get('confidence') == 'low':
                has_response = bool(issue.get('response_body') or issue.get('response_headers'))
                has_control_signal = status in (401, 403, 405, 429)
                if not has_response and not has_control_signal:
                    self._record_telemetry(
                        issue.get('issue', 'Low confidence info'),
                        issue.get('target') or issue.get('url') or issue.get('endpoint') or '',
                        payload=issue.get('payload'),
                        extra={k: v for k, v in issue.items() if k not in ('response_body', 'response_headers')},
                    )
                    continue

            # Make payload hashable for dedup (dict payloads from business logic etc.)
            _payload = issue.get('payload', '')
            if isinstance(_payload, dict):
                _payload = json.dumps(_payload, sort_keys=True, default=str)
            elif not isinstance(_payload, (str, int, float, bool, type(None))):
                _payload = str(_payload)
            dedup_key = (
                issue.get('method'),
                issue.get('path') or issue.get('endpoint'),
                issue.get('status_code'),
                issue.get('issue'),
                _payload,
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            cleaned.append(issue)

        self.issues = cleaned
        self._dedupe_issues()
        return self.issues


    #================ _dedupe_issues description ##########
    def _dedupe_issues(self) -> None:
        #================ _canon description ##########
        def _canon(f: dict) -> tuple:
            issue = (f.get('issue') or '').lower()
            desc = (f.get('description') or '').lower()
            method = (f.get('method') or 'GET').upper()
            path = f.get('path') or f.get('endpoint') or f.get('url') or ''
            status = f.get('status_code')
            payload = f.get('payload') or ''
            # Ensure payload is hashable (e.g., business_logic uses dict payloads)
            if isinstance(payload, dict):
                payload = json.dumps(payload, sort_keys=True, default=str)
            elif not isinstance(payload, (str, int, float, bool, type(None))):
                payload = str(payload)
            vector = (f.get('vector') or '').lower()

            if (
                vector == 'generic-5xx'
                or 'server error without sql evidence' in issue
                or 'generic 5xx response without sql/db markers' in desc
            ):
                return ('generic-5xx', method, path, status)

            if vector in ('dirtrav', 'dirtrav-auth') or issue.startswith('directory traversal'):
                base_ep = f.get('base_endpoint') or path
                sev = f.get('severity')
                key_kind = 'dirtrav-auth' if vector == 'dirtrav-auth' or 'auth' in issue else 'dirtrav'
                return (key_kind, method, base_ep, sev)

            if vector == 'cors' or issue == 'broad cors policy':
                return ('cors', method, path, 200)

            return ('default', method, path, status, issue, payload)

        merged: dict[tuple, dict] = {}

        for f in self.issues:
            k = _canon(f)
            cur = merged.get(k)

            if cur is None:
                f['duplicates'] = 0

                v = (f.get('vector') or '').lower()
                if v in ('dirtrav', 'dirtrav-auth'):
                    urls: list[str] = []
                    u = f.get('url') or f.get('endpoint')
                    if u:
                        urls.append(u)
                    f['evidence_urls'] = urls
                elif v == 'cors':
                    origins: list[str] = []
                    o = f.get('origin')
                    if o:
                        origins.append(o)
                    f['evidence_origins'] = origins
                elif v == 'generic-5xx':
                    payloads: list[str] = []
                    pld = f.get('payload')
                    if pld:
                        payloads.append(pld)
                    f['evidence_payloads'] = payloads

                merged[k] = f
            else:
                cur['duplicates'] = int(cur.get('duplicates', 0)) + 1
                v = (f.get('vector') or '').lower()

                if v in ('dirtrav', 'dirtrav-auth'):
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


    #================ _category_of_issue description ##########
    def _category_of_issue(self, text: str) -> str:
        t = (text or '').lower()
        if any(term in t for term in ['waf detected', 'input filtering', 'openresty', 'mod_security']):
            return 'WAF/Filtering'
        if 'nosql' in t:
            return 'NoSQLi'
        if 'sql injection' in t or 'sqli' in t:
            return 'SQLi'
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


    #================ counts_by_category description ##########
    def counts_by_category(self, include_info: bool=False) -> dict:
        out = {}
        for f in self.issues:
            sev = str(f.get('severity', '')).lower()
            if not include_info and sev == 'info':
                continue
            c = self._category_of_issue(f.get('issue', ''))
            out[c] = out.get(c, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))


    #================ generate_report description ##########
    def generate_report(self) -> str:
        self._filter_issues()
        gen = ReportGenerator(issues=self.issues, scanner='SafeConsumption Enhanced/4.0', base_url=self.base_url)
        return gen.generate_html()


    #================ save_report description ##########
    def save_report(self, path: str, fmt: str='html') -> None:
        ReportGenerator(issues=self._filter_issues(), scanner='SafeConsumption Enhanced/4.0', base_url=self.base_url).save(path, fmt=fmt)

    #================ generate_random_id description ##########
    @staticmethod

    def generate_random_id(length: int=8) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    #================ endpoints_from_swagger description ##########
    @staticmethod

    def endpoints_from_swagger(swagger_path: str, base_url: Optional[str] = None):
        pairs = SafeConsumptionAuditor.endpoints_from_swagger_with_methods(swagger_path, base_url=base_url)
        urls = []
        seen = set()
        for url, _m in pairs:
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls

    #================ endpoints_from_swagger_with_methods description ##########
    @staticmethod

    def endpoints_from_swagger_with_methods(swagger_path: str, base_url: Optional[str] = None):
        from pathlib import Path
        import json

        raw = Path(swagger_path).read_text(encoding="utf-8")
        path_lower = str(swagger_path).lower()
        if path_lower.endswith(('.yml', '.yaml')):
            import yaml as _yaml
            spec = _yaml.safe_load(raw) or {}
        else:
            try:
                spec = json.loads(raw)
            except json.JSONDecodeError:
                import yaml as _yaml
                spec = _yaml.safe_load(raw) or {}

        # CLI --url selects the target deployment. Spec server origins may
        # describe another environment (e.g. localhost versus 127.0.0.1).
        # Keep the original spec-only behavior for callers without an override.
        if base_url is not None:
            from urllib.parse import urlsplit
            parsed = urlsplit(base_url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('API10 target must be an HTTP(S) base URL without credentials, query or fragment')
            servers = [base_url.rstrip('/')]
        else:
            servers = [str(server.get('url') or '').rstrip('/')
                       for server in (spec.get('servers') or [])
                       if isinstance(server, dict) and server.get('url')]

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

    #================ third_party_hosts_from_swagger description ##########
    @staticmethod

    def third_party_hosts_from_swagger(swagger_path: str) -> List[str]:
        from pathlib import Path
        import json
        raw = Path(swagger_path).read_text(encoding='utf-8')
        path_lower = str(swagger_path).lower()
        if path_lower.endswith(('.yml', '.yaml')):
            import yaml as _yaml
            spec = _yaml.safe_load(raw) or {}
        else:
            try:
                spec = json.loads(raw)
            except json.JSONDecodeError:
                import yaml as _yaml
                spec = _yaml.safe_load(raw) or {}
        hosts: Set[str] = set()
        for srv in spec.get('servers', []):
            url = srv.get('url')
            if url:
                parsed = urlparse.urlparse(url)
                if parsed.netloc:
                    hosts.add(parsed.netloc.split(':')[0])


        #================ walk description ##########
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
        return list(hosts)
