########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0 License                 #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.1 07-07-2026                              #
########################################################


from __future__ import annotations
try:
    from urllib3.util.retry import Retry
except Exception:
    Retry = None
import argparse
import sqlite3
import builtins
import json
import logging
import queue
import sys
import os
import time
import webbrowser
import csv as _csv
import re as _re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
import requests
import urllib3
from tqdm import tqdm
import math

_METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'}

def _split_method_endpoint(method: str | None, endpoint: str | None) -> tuple[str, str]:
    m = str(method or '').strip().upper()
    ep = str(endpoint or '').strip()
    parts = ep.split(None, 1)
    if (not m or m not in _METHODS) and len(parts) == 2 and parts[0].upper() in _METHODS:
        m = parts[0].upper()
        ep = parts[1].strip()
    if not m:
        m = 'GET'
    return m, ep

# ================= AI CLIENT (new preferred, v3 fallback) =================
try:
    from ai_client import live_probe, analyze_endpoints_with_llm, save_ai_summary
except ImportError:
    try:
        import importlib
        _ai_v3 = importlib.import_module('ai_client_v3')
        live_probe = getattr(_ai_v3, 'live_probe', None)
        analyze_endpoints_with_llm = getattr(_ai_v3, 'analyze_endpoints_with_llm', None)
        save_ai_summary = getattr(_ai_v3, 'save_ai_summary', None)
    except Exception:
        live_probe = None
        analyze_endpoints_with_llm = None
        save_ai_summary = None


#================funtion clear_screen clear_screen =============
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
clear_screen()
print('Loading APISCAN one-moment')

try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init()
except Exception:

    class _Dummy:
        RESET_ALL = ''
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
        BRIGHT = DIM = ''
    Fore = _Dummy()
    Style = _Dummy()
from requests.adapters import HTTPAdapter
try:
    from bola_audit import BOLAAuditor
    from broken_auth_audit import AuthAuditor
    from broken_object_property_audit import ObjectPropertyAuditor
    from resource_consumption_audit import ResourceConsumptionAuditor as ResourceAuditor
    from authorization_audit import AuthorizationAuditor
    from business_flow_audit import BusinessFlowAuditor
    from ssrf_audit import SSRFAuditor
    from misconfiguration_audit import MisconfigurationAuditorPro as MisconfigurationAuditor
    from inventory_audit import InventoryAuditor
    from safe_consumption_audit import SafeConsumptionAuditor
    from chain_audit import ChainAuditor
    from version import __version__
    from auth_utils import configure_authentication, AuthConfigError
    from report_utils import HTMLReportGenerator, RISK_INFO
    from doc_generator import generate_combined_html
    from swagger_utils import enable_dummy_mode, extract_variables, write_variables_file
    from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig as OASSecurityConfig, load_spec as oas_load_spec
except ImportError as e:
    print(f'Error importing required modules: {e}')
    print('Please ensure all audit modules are available in the Python path.')
    sys.exit(1)
try:
    import colorama
    colorama.just_fix_windows_console()
    colorama.init(autoreset=True, strip=False, convert=True)
except Exception:
    pass

# ================= SECURITY HARDENING HELPERS (OWASP) =====================
# Centralised, defensive helpers used across the scanner.
#  - Secret redaction in logs and error messages   (OWASP A09)
#  - Strict file validation before opening user-supplied paths (A03/A08)
#  - URL / filename sanitisation against traversal & control chars (A03)
#  - Safe JSON loading with hard size limits (A03/A05 DoS)
#  - Regex validation to mitigate ReDoS from --rewrite (A03)
# These helpers are intentionally side-effect free.
_MAX_JSON_FILE_BYTES = 16 * 1024 * 1024          # 16 MB hard cap on JSON inputs
_MAX_SWAGGER_FILE_BYTES = 64 * 1024 * 1024       # 64 MB hard cap on Swagger spec
_MAX_REWRITE_PATTERN_LEN = 512                   # cap regex length (ReDoS mitigation)
_ALLOWED_PROXY_SCHEMES = {'http', 'https', 'socks5', 'socks5h', 'socks4', 'socks4a'}
_SAFE_FILENAME_RE = _re.compile(r'[^A-Za-z0-9._-]+')
_SENSITIVE_HEADER_NAMES = {
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'x-api-key', 'x-auth-token', 'x-access-token', 'x-csrf-token',
    'api-key', 'apikey', 'x-amz-security-token',
}
_SENSITIVE_QUERY_KEYS = {
    'access_token', 'token', 'id_token', 'refresh_token', 'api_key',
    'apikey', 'client_secret', 'password', 'pwd', 'secret', 'sig', 'signature',
}

_SENSITIVE_HEADER_LINE_RE = _re.compile(r'(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token)\s*:\s*.*$')
_INLINE_BEARER_RE = _re.compile(r'(?i)(authorization\s*:\s*bearer\s+)([A-Za-z0-9._\-~+/=]+)')


def _redact_value(_v: object) -> str:
    return '***REDACTED***'


def _redact_headers(headers: object) -> dict:
    if not isinstance(headers, dict):
        return {}
    out = {}
    for k, v in headers.items():
        try:
            if str(k).lower() in _SENSITIVE_HEADER_NAMES:
                out[k] = _redact_value(v)
            else:
                out[k] = v
        except Exception:
            out[k] = _redact_value(v)
    return out


def _redact_header_text_blob(text: object) -> str:
    s = str(text or '')
    s = _SENSITIVE_HEADER_LINE_RE.sub(lambda m: f'{m.group(1)}: ***REDACTED***', s)
    return _INLINE_BEARER_RE.sub(lambda m: f'{m.group(1)}***REDACTED***', s)


def _redact_headers_any(headers: object) -> object:
    if isinstance(headers, dict):
        return _redact_headers(headers)
    if isinstance(headers, str):
        return _redact_header_text_blob(headers)
    try:
        out = []
        for item in headers or []:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                if str(k).lower() in _SENSITIVE_HEADER_NAMES:
                    out.append([k, '***REDACTED***'])
                else:
                    out.append([k, v])
            else:
                out.append(item)
        return out
    except Exception:
        return headers


def _redact_deep(obj: object) -> object:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _SENSITIVE_HEADER_NAMES:
                out[k] = '***REDACTED***'
            else:
                out[k] = _redact_deep(v)
        return out
    if isinstance(obj, list):
        return [_redact_deep(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_deep(v) for v in obj)
    if isinstance(obj, str):
        return _redact_header_text_blob(obj)
    return obj


def _redact_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        return ''
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        parts = urlsplit(url)
        netloc = parts.hostname or ''
        if parts.port:
            netloc = f'{netloc}:{parts.port}'
        # Drop userinfo (user:pass@host) entirely
        q_pairs = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            if k.lower() in _SENSITIVE_QUERY_KEYS:
                q_pairs.append((k, _redact_value(v)))
            else:
                q_pairs.append((k, v))
        new_q = urlencode(q_pairs, doseq=True)
        return urlunsplit((parts.scheme, netloc, parts.path, new_q, ''))
    except Exception:
        return url


def _sanitize_filename(name: str, fallback: str = 'target') -> str:
    s = _SAFE_FILENAME_RE.sub('_', str(name or '')).strip('._-')
    if not s:
        s = fallback
    return s[:120]


def _validate_input_file(path: str | os.PathLike, max_bytes: int, label: str) -> Path:
    if not path:
        raise ValueError(f'{label}: no path provided')
    p = Path(str(path)).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f'{label}: file not found: {p}')
    if not p.is_file():
        raise ValueError(f'{label}: not a regular file: {p}')
    try:
        size = p.stat().st_size
    except OSError as e:
        raise ValueError(f'{label}: cannot stat file: {e}') from e
    if size == 0:
        raise ValueError(f'{label}: file is empty')
    if size > max_bytes:
        raise ValueError(f'{label}: file too large ({size} > {max_bytes} bytes)')
    return p


def _safe_load_json_file(path: str | os.PathLike, label: str,
                        max_bytes: int = _MAX_JSON_FILE_BYTES) -> Any:
    p = _validate_input_file(path, max_bytes, label)
    with p.open('r', encoding='utf-8') as fh:
        return json.load(fh)


def _validate_proxy(proxy: str) -> str:
    if not proxy:
        return ''
    pr = proxy if '://' in proxy else f'http://{proxy}'
    from urllib.parse import urlsplit
    parts = urlsplit(pr)
    if (parts.scheme or '').lower() not in _ALLOWED_PROXY_SCHEMES:
        raise ValueError(f'unsupported proxy scheme: {parts.scheme!r}')
    if parts.username or parts.password:
        raise ValueError('proxy URL must not embed credentials; use env vars instead')
    if not parts.hostname:
        raise ValueError('proxy URL missing host')
    return pr


def _validate_rewrite_pattern(rule: str) -> str:
    if not isinstance(rule, str) or '=>' not in rule:
        raise ValueError('rewrite must be of form <regex>=><replacement>')
    pat, _sep, rep = rule.partition('=>')
    pat = pat.strip()
    rep = rep.strip()
    if not pat or len(pat) > _MAX_REWRITE_PATTERN_LEN:
        raise ValueError('rewrite regex empty or too long')
    try:
        _re.compile(pat)
    except _re.error as e:
        raise ValueError(f'invalid rewrite regex: {e}') from e
    return f'{pat}=>{rep}'


# ==========================================================================

OUT_DIR: Path | None = None
DB = None
manual_file_map = {'BOLA': 'bola', 'BrokenAuth': 'broken_auth', 'Property': 'property', 'Resource': 'resource', 'AdminAccess': 'admin_access', 'BusinessFlows': 'business_flows', 'SSRF': 'ssrf', 'Misconfig': 'misconfig', 'Inventory': 'inventory', 'UnsafeConsumption': 'unsafe_consumption', 'Chain-Escalation': 'chain_escalation'}
MAX_THREADS = 20
DUMMY_MODE = False
_ID_MAP = {}
MISSING_RE = _re.compile('(missing|require[sd])\\s+[\'\\"]?([A-Za-z0-9_]+)[\'\\"]?', _re.I)
logger = logging.getLogger('apiscan')

class EvidenceDatabase:

    #================funtion __init__ __init__ =============
    def __init__(self, path: str, run_id: str | None=None):
        self.path = Path(path)
        self.run_id = run_id or ''
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        # Open with a sane timeout so concurrent writers don't deadlock silently.
        self.conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None,
                                    check_same_thread=False)
        try:
            cur = self.conn.cursor()
            # Defensive pragmas (A05). secure_delete avoids leaving evidence
            # fragments on disk; WAL improves resilience without weakening safety.
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.execute('PRAGMA secure_delete=ON')
            cur.execute('PRAGMA foreign_keys=ON')
            cur.execute('PRAGMA trusted_schema=OFF')
        except Exception:
            pass
        # Restrict DB file to current user on POSIX.
        try:
            if os.name == 'posix' and self.path.exists():
                os.chmod(self.path, 0o600)
        except Exception:
            pass
        self._init_schema()

    #================funtion _init_schema _init_schema =============
    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute('\n            CREATE TABLE IF NOT EXISTS finding (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                run_id TEXT,\n                risk_key TEXT,\n                title TEXT,\n                description TEXT,\n                category TEXT,\n                severity TEXT,\n                status TEXT,\n                method TEXT,\n                endpoint TEXT,\n                req_headers TEXT,\n                req_body TEXT,\n                res_headers TEXT,\n                res_body TEXT,\n                res_status INTEGER,\n                created_at TEXT\n            )\n            ')
        cur.execute('\n            CREATE TABLE IF NOT EXISTS endpoint (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                run_id TEXT,\n                method TEXT,\n                url TEXT,\n                first_seen TEXT,\n                last_seen TEXT,\n                max_severity TEXT,\n                last_status INTEGER,\n                last_ms INTEGER,\n                count_ok INTEGER DEFAULT 0,\n                count_fail INTEGER DEFAULT 0,\n                UNIQUE(run_id, method, url)\n            )\n            ')
        cur.execute('\n            CREATE TABLE IF NOT EXISTS endpoint_hit (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                run_id TEXT,\n                method TEXT,\n                url TEXT,\n                ts TEXT,\n                status INTEGER,\n                ms INTEGER,\n                note TEXT\n            )\n            ')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_finding_run ON finding(run_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_finding_cat ON finding(category)')
        self.conn.commit()

    #================funtion record_endpoint record_endpoint =============
    def record_endpoint(self, method: str, url: str, run_id: str | None=None, severity: str | None=None, status: int | None=None, ms: int | None=None, ok: bool | None=None) -> None:
        now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        run_id = run_id or self.run_id or ''
        sev = (severity or '').strip().lower()
        order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, '': -1, None: -1}
        cur = self.conn.cursor()
        cur.execute('SELECT max_severity FROM endpoint WHERE run_id=? AND method=? AND url=?', (run_id, method, url))
        row = cur.fetchone()
        if row:
            old = (row[0] or '').lower()
            keep = sev if order.get(sev, -1) > order.get(old, -1) else old
            cur.execute(
                'UPDATE endpoint SET last_seen=?, max_severity=?, last_status=?, last_ms=? WHERE run_id=? AND method=? AND url=?',
                (now, keep or None, status, ms, run_id, method, url)
            )
        else:
            cur.execute(
                'INSERT INTO endpoint(run_id, method, url, first_seen, last_seen, max_severity, last_status, last_ms) VALUES (?,?,?,?,?,?,?,?)',
                (run_id, method, url, now, now, sev or None, status, ms)
            )
        self.conn.commit()

    #================funtion store_issues store_issues =============
    def store_issues(self, category: str, issues, base_url: str | None=None) -> None:
        if not issues:
            return
        from datetime import datetime as _dt
        now = _dt.utcnow().isoformat(timespec='seconds') + 'Z'
        import json as _json
        prepared = []
        for it in issues:
            d = it if isinstance(it, dict) else it.to_dict() if hasattr(it, 'to_dict') else {'raw': repr(it)}
            method = str(d.get('method') or d.get('http_method') or d.get('verb') or '').upper()
            endpoint = d.get('endpoint') or d.get('url') or d.get('path') or ''
            method, endpoint = _split_method_endpoint(method, endpoint)
            title = d.get('title') or d.get('issue') or d.get('description') or method + ' ' + endpoint
            desc = d.get('description') or d.get('message') or ''
            sev = d.get('severity') or 'Info'
            status = d.get('status') or ''
            sc = None
            for k in ('status_code', 'res_status', 'http_status', 'status'):
                v = d.get(k)
                if v is None:
                    continue
                try:
                    sc = int(v)
                    break
                except Exception:
                    continue
            req_headers = d.get('request_headers') or d.get('req_headers') or {}
            req_body = d.get('payload') or d.get('request') or d.get('request_body') or ''
            res_headers = d.get('response_headers') or d.get('res_headers') or {}
            res_body = d.get('response_body') or d.get('res_body') or ''
            req_headers = _redact_headers_any(req_headers)
            res_headers = _redact_headers_any(res_headers)
            req_body = _redact_deep(req_body)
            res_body = _redact_deep(res_body)
            prepared.append({
                'title': str(title),
                'desc': str(desc),
                'sev': str(sev).capitalize(),
                'status': str(status),
                'method': method,
                'endpoint': endpoint,
                'req_headers': _json.dumps(req_headers, ensure_ascii=False) if not isinstance(req_headers, str) else req_headers,
                'req_body': _json.dumps(req_body, ensure_ascii=False) if isinstance(req_body, (dict, list)) else str(req_body),
                'res_headers': _json.dumps(res_headers, ensure_ascii=False) if not isinstance(res_headers, str) else res_headers,
                'res_body': _json.dumps(res_body, ensure_ascii=False) if isinstance(res_body, (dict, list)) else str(res_body),
                'res_status': sc if isinstance(sc, int) else None,
            })

        deduped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in prepared:
            key = (
                category.strip().lower(),
                item['title'].strip().lower(),
                item['sev'].strip().lower(),
                item['endpoint'].strip().lower(),
            )
            if key not in deduped:
                item['duplicate_count'] = 1
                item['methods_seen'] = {item['method']} if item['method'] else set()
                deduped[key] = item
                continue
            base = deduped[key]
            base['duplicate_count'] = int(base.get('duplicate_count', 1)) + 1
            if item.get('method'):
                base.setdefault('methods_seen', set()).add(item['method'])
            # Prefer a concrete HTTP status if one of the duplicates has it.
            if base.get('res_status') in (None, 0) and item.get('res_status') not in (None, 0):
                base['res_status'] = item.get('res_status')
            # Keep richer textual evidence when available.
            if len(str(item.get('res_body') or '')) > len(str(base.get('res_body') or '')):
                base['res_body'] = item.get('res_body')

        rows = []
        for item in deduped.values():
            dup_count = int(item.get('duplicate_count', 1))
            methods_seen = sorted([m for m in item.get('methods_seen', set()) if m])
            desc = item.get('desc', '')
            if dup_count > 1:
                methods_txt = ', '.join(methods_seen) if methods_seen else 'mixed'
                suffix = f' [deduplicated {dup_count} similar findings; methods: {methods_txt}]'
                if suffix not in desc:
                    desc = (desc + suffix).strip()
            rows.append((
                self.run_id,
                category,
                item['title'],
                desc,
                category,
                item['sev'],
                item['status'],
                item['method'],
                item['endpoint'],
                item['req_headers'],
                item['req_body'],
                item['res_headers'],
                item['res_body'],
                item['res_status'],
                now,
            ))
        cur = self.conn.cursor()
        cur.executemany('INSERT INTO finding(run_id, risk_key, title, description, category, severity, status, method, endpoint, req_headers, req_body, res_headers, res_body, res_status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
# Update endpoint.max_severity based on inserted findings for this category + run
        try:
            cur.execute("""
                SELECT method, endpoint, MAX(
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 4
                        WHEN 'high' THEN 3
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 1
                        WHEN 'info' THEN 0
                        ELSE -1
                    END
                ) AS max_rank
                FROM finding
                WHERE run_id = ? AND category = ?
                GROUP BY method, endpoint
            """, (run_id, category))
        except Exception:
            pass

#================function _normalize_version_in_url description ##########
def _normalize_version_in_url(u: str) -> str:
    try:
        #================funtion repl repl =============
        def repl(m):
            major = m.group(1)
            minor = m.group(2) or '0'
            minor_norm = str(int(minor))
            return f'/v{major}.{minor_norm}/'
        return _re.sub('/v(\\d+)\\.(\\d+)/', repl, u)
    except Exception:
        return u

#================funtion _sec_from_args _sec_from_args =============
def _sec_from_args(args) -> OASSecurityConfig:
    api_key_val = getattr(args, 'apikey', None)
    api_key_name = getattr(args, 'apikey_header', 'X-API-Key')
    return OASSecurityConfig(api_key_header_name=api_key_name, api_key_value=api_key_val, api_key_query_name=None, bearer_token=getattr(args, 'token', None))

#================function _swagger_example_value description ##########
def _swagger_example_value(param: dict) -> Any:
    schema = (param or {}).get('schema') or {}
    if param.get('example') is not None:
        return param['example']
    if schema.get('example') is not None:
        return schema['example']
    if schema.get('default') is not None:
        return schema['default']
    enum_values = schema.get('enum') or param.get('enum') or []
    if enum_values:
        return enum_values[0]
    ptype = (schema.get('type') or param.get('type') or 'string').lower()
    pformat = (schema.get('format') or param.get('format') or '').lower()
    if ptype == 'integer':
        return 1
    if ptype == 'number':
        return 1.0
    if ptype == 'boolean':
        return True
    if pformat == 'uuid':
        return '00000000-0000-0000-0000-000000000000'
    return 'test'


def _extract_path_params_from_parameters(parameters: list[dict] | None) -> dict[str, str]:
    path_params: dict[str, str] = {}
    for param in parameters or []:
        if (param or {}).get('in') != 'path':
            continue
        name = str((param or {}).get('name') or '').strip()
        if not name:
            continue
        value = _swagger_example_value(param)
        if value is None:
            continue
        path_params[name] = str(value)
    return path_params


def _build_ai_endpoint(endpoint: dict) -> dict:
    parameters = endpoint.get('parameters')
    if parameters is None:
        parameters = (endpoint.get('raw') or {}).get('parameters')

    item = {
        'path': endpoint.get('path'),
        'method': endpoint.get('method'),
    }
    if parameters:
        item['parameters'] = parameters
        path_params = _extract_path_params_from_parameters(parameters)
        if path_params:
            item['path_params'] = path_params
    return item

#================funtion _endpoints_from_universal _endpoints_from_universal =============
def _endpoints_from_universal(spec: dict) -> list[dict]:
    eps = []
    try:
        for op in oas_iter_ops(spec):
            raw = op.get('raw') or {}
            eps.append({
                'path': op['path'],
                'method': op['method'],
                'operationId': raw.get('operationId') or f"{op['method']}_{op['path'].strip('/').replace('/', '_')}",
                'tags': raw.get('tags', []),
                'parameters': op.get('parameters', []),
                'raw': raw,
            })
    except Exception as e:
        logger.debug(f'Universal endpoint extraction failed: {e}')
    return eps

#================funtion extract_endpoints_from_paths extract_endpoints_from_paths =============
def extract_endpoints_from_paths(spec):
    endpoints = []
    paths = (spec or {}).get('paths', {})
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        path_level_params = ops.get('parameters', []) if isinstance(ops.get('parameters', []), list) else []
        for method, op in ops.items():
            if method.upper() in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'):
                op_params = op.get('parameters', []) if isinstance(op, dict) else []
                merged_params = []
                seen = set()
                for param in list(path_level_params) + list(op_params):
                    if not isinstance(param, dict):
                        continue
                    key = (param.get('name'), param.get('in'))
                    if key in seen:
                        continue
                    seen.add(key)
                    merged_params.append(param)
                endpoints.append({'path': path, 'method': method.upper(), 'operationId': op.get('operationId') or f"{method}_{path.strip('/').replace('/', '_')}", 'tags': op.get('tags', []), 'parameters': merged_params, 'raw': op})
    return endpoints

#================funtion styled_print styled_print =============
def styled_print(message: str, status: str='info') -> None:
    icons   = {'info': '◆', 'ok': '✔', 'warn': '▲', 'fail': '✖', 'run': '▶', 'done': '●'}
    labels  = {'info': 'Info', 'ok': 'OK', 'warn': 'WARN', 'fail': 'FAIL', 'run': '...', 'done': 'Done'}
    colors  = {'info': Fore.CYAN, 'ok': Fore.GREEN, 'warn': Fore.YELLOW, 'fail': Fore.RED, 'run': Fore.CYAN, 'done': Fore.GREEN}
    bright  = {'ok': True, 'done': True, 'fail': True}
    R = Style.RESET_ALL
    br = Style.BRIGHT if bright.get(status) else ''
    ic = icons.get(status, '◆')
    lb = labels.get(status, 'Info')
    co = colors.get(status, Fore.CYAN)
    print(f"  {br}{co}{ic}{R}  {Style.BRIGHT}{lb}:{R} {message}")


#================funtion print_banner print_banner =============
def print_banner() -> None:
    try:
        from version import __version__ as _v
    except Exception:
        _v = '4.0'
    C = Style.BRIGHT + Fore.CYAN
    G = Style.BRIGHT + Fore.GREEN
    W = Style.BRIGHT + Fore.WHITE
    M = Fore.MAGENTA
    Y = Fore.YELLOW
    R = Style.RESET_ALL
    art = [
        f" {G}█████╗ ██████╗ ██╗███████╗ ██████╗ █████╗ ███╗   ██╗{R}",
        f"{G}██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔══██╗████╗  ██║{R}",
        f"{G}███████║██████╔╝██║███████╗██║     ███████║██╔██╗ ██║{R}",
        f"{G}██╔══██║██╔═══╝ ██║╚════██║██║     ██╔══██║██║╚██╗██║{R}",
        f"{G}██║  ██║██║     ██║███████║╚██████╗██║  ██║██║ ╚████║{R}",
        f"{G}╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{R}",
    ]
    sep = C + '═' * 62 + R
    print()
    print(sep)
    for line in art:
        print(f'  {line}')
    print()
    print(f'  {W}API Security Scanner{R}  {C}·{R}  {Y}OWASP API Top 10 (2023){R}  {C}·{R}  {C}v{_v}{R}')
    print(f'  {M}Perry Mertens{R}  {C}·{R}  pamsniffer@gmail.com  {C}·{R}  {W}© 2026{R}')
    print(sep)
    print()

#================funtion _scan_section _scan_section =============
def _scan_section(num: int, title: str) -> None:
    C = Style.BRIGHT + Fore.CYAN
    W = Style.BRIGHT + Fore.WHITE
    D = Fore.CYAN
    R = Style.RESET_ALL
    rule = D + '─' * 60 + R
    tqdm.write(f'\n{rule}')
    tqdm.write(f'  {C}▶{R}  {W}API{num}{R}  {Fore.CYAN}{title}{R}')
    tqdm.write(rule)

#================funtion _scan_issue _scan_issue =============
def _scan_issue(sev: str, desc: str, ep: str) -> None:
    _SEV = {
        'critical': Style.BRIGHT + Fore.RED,
        'high':     Style.BRIGHT + Fore.YELLOW,
        'medium':   Fore.GREEN,
        'low':      Fore.CYAN,
        'info':     Fore.WHITE,
    }
    R = Style.RESET_ALL
    sc = _SEV.get(sev.lower(), Fore.WHITE)
    badge = f"{sc}{sev.upper():<8}{R}"
    tqdm.write(f"  {Fore.YELLOW}◈{R}  {badge}  {desc}  {Fore.CYAN}@{R}  {ep}")

#================funtion _scan_err _scan_err =============
def _scan_err(label: str, err: object) -> None:
    R  = Style.RESET_ALL
    msg = str(err)
    # Suppress connection-pool noise from endpoints that don't exist
    msg_low = msg.lower()
    if any(k in msg_low for k in ('httpconnectionpool', 'max retries exceeded', 'failed to establish a new connection')):
        return  # silent — endpoint doesn't exist, not a real error
    if 'timed out' in msg.lower() or 'timeout' in msg.lower():
        msg = 'Timeout'
    elif 'ConnectionError' in msg or 'Connection refused' in msg:
        msg = 'Connection refused'
    elif len(msg) > 90:
        msg = msg[:87] + '...'
    tqdm.write(f"  {Style.BRIGHT}{Fore.RED}✖{R}  {Fore.RED}{label}{R}  {Style.DIM}{msg}{R}")

#================funtion normalize_url normalize_url =============
def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError('URL must be a non-empty string')
    if not url.lower().startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.lower().startswith('http://'):
        try:
            styled_print(f'Using plaintext HTTP for {_redact_url(url)} - traffic is not encrypted', 'warn')
        except Exception:
            pass
    return url

#================funtion create_output_directory create_output_directory =============
def create_output_directory(base_url: str) -> Path:
    try:
        from urllib.parse import urlsplit
        host = urlsplit(base_url).netloc or base_url
    except Exception:
        host = base_url or 'target'
    clean = _sanitize_filename(host, fallback='target')
    timestamp = datetime.now().strftime('%d-%m-%Y_%H%M%S')
    out_dir = Path.cwd() / f'audit_{clean}_{timestamp}'
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        # POSIX-only: restrict directory to current user.
        if os.name == 'posix':
            os.chmod(out_dir, 0o700)
    except Exception:
        pass
    return out_dir

#================funtion save_html_report save_html_report =============
def save_html_report(issues, risk_key: str, url: str, output_dir: Path) -> None:
    html_report = HTMLReportGenerator(issues=issues, scanner=RISK_INFO[risk_key]['title'], base_url=url)
    filename = f'api_{manual_file_map[risk_key]}_report.html'
    html_report.save(output_dir / filename)

#================funtion _canonical_path_min _canonical_path_min =============
def _canonical_path_min(p: str) -> str:
    import re as _re
    p = '/' + (p or '').lstrip('/')
    return _re.sub('\\{[^}]+\\}', '{}', p)

#================funtion _json_shape_min _json_shape_min =============
def _json_shape_min(text: str) -> str:
    if not text:
        return ''
    try:
        import json as _json
        data = _json.loads(text)
    except Exception:
        import re as _re
        return _re.sub('\\s+', ' ', text).strip()[:4096]

    #================funtion _n _n =============
    def _n(v):
        if isinstance(v, dict):
            return {k: _n(val) for k, val in sorted(v.items(), key=lambda x: x[0]) if k not in {'timestamp', 'time', 'date', 'requestId', 'request_id'}}
        if isinstance(v, list):
            return [_n(v[0])] if v else []
        if isinstance(v, str):
            return 'S'
        if isinstance(v, (int, float)):
            return 'N'
        if isinstance(v, bool):
            return 'B'
        if v is None:
            return 'null'
        return 'X'
    try:
        shaped = _n(data)
        import json as _json
        return _json.dumps(shaped, separators=(',', ':'), ensure_ascii=False)[:8192]
    except Exception:
        import re as _re
        return _re.sub('\\s+', ' ', text).strip()[:4096]

#================funtion _is_sensitive_body_min _is_sensitive_body_min =============
def _is_sensitive_body_min(body: str) -> bool:
    if not body:
        return False
    import re as _re
    if _re.search('[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}', body, flags=_re.I):
        return True
    if _re.search('\\beyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\b', body):
        return True
    if _re.search('"(access_)?token"\\s*:\\s*"', body, flags=_re.I):
        return True
    return False

#================funtion _filter_auth_issues_min _filter_auth_issues_min =============
def _filter_auth_issues_min(issues):
    if not issues:
        return []
    out = []
    for it in issues:
        try:
            code = int(it.get('status_code', 0) or 0)
        except Exception:
            continue
        if code in {0, 400, 404, 405}:
            if it.get('severity') not in ('High', 'Critical'):
                continue
        if 500 <= code < 600:
            continue
        body = it.get('response_body') or ''
        path = str(it.get('endpoint') or '')
        if code == 200 and (not (_is_sensitive_body_min(body) or '.env' in path or '/.env' in path)):
            generic = False
            try:
                import json as _json
                data = _json.loads(body)
                if isinstance(data, dict):
                    keys = set(map(lambda k: str(k).lower(), data.keys()))
                    if keys and keys.issubset({'message', 'status', 'detail', 'error'}):
                        generic = all((not isinstance(v, (dict, list)) for v in data.values()))
            except Exception:
                txt = (body or '').strip().lower()
                if len(txt) <= 64 and txt in {'ok', 'success', 'done', 'created', 'updated', 'deleted'}:
                    generic = True
            if generic:
                continue
        try:
            from hashlib import sha1 as _sha1
            method = it.get('method', '')
            canon = _canonical_path_min(path)
            shape = _json_shape_min(body)
            fp = f"{method}|{canon}|{code}|{_sha1(shape.encode('utf-8', 'ignore')).hexdigest()}"
        except Exception:
            fp = None
        it['fingerprint'] = fp
        out.append(it)
    dedup = {}
    for it in out:
        fp = it.get('fingerprint')
        if not fp:
            continue
        if fp in dedup:
            d = dedup[fp]
            d['duplicate_count'] = d.get('duplicate_count', 1) + 1
            v = d.setdefault('variants', [])
            desc = it.get('description', '')
            if desc and desc not in v:
                v.append(desc)
        else:
            it.setdefault('duplicate_count', 1)
            it.setdefault('variants', [it.get('description', '')])
            dedup[fp] = it
    return list(dedup.values())

#================funtion check_api_reachable check_api_reachable =============
def check_api_reachable(url: str, session: requests.Session, retries: int=3, delay: int=3) -> None:
    safe_url = _redact_url(url)
    for attempt in range(1, retries + 1):
        try:
            styled_print(f'Connecting to {safe_url}  (attempt {attempt}/{retries})', 'run')
            resp = session.get(url, timeout=5, verify=getattr(session, 'verify', True))
            code = resp.status_code
            if not resp.content:
                styled_print('Empty response body from server', 'warn')
            if 200 <= code < 400 or code in (401, 403, 404, 405):
                styled_print(f'Reachable  {Style.BRIGHT}{Fore.WHITE}{safe_url}{Style.RESET_ALL}  →  HTTP {code}', 'ok')
                return
            styled_print(f'Unexpected HTTP {code} from {safe_url}', 'warn')
        except requests.exceptions.RequestException as e:
            # Avoid leaking secrets that may appear in URL/proxy/error text.
            logger.error('Attempt %d failed: %s', attempt, type(e).__name__)
            styled_print(f'Connection attempt {attempt} failed: {type(e).__name__}', 'warn')
        if attempt < retries:
            styled_print(f'Retrying in {delay}s ...', 'info')
            time.sleep(delay)
        else:
            styled_print(f'Cannot reach {safe_url} after {retries} attempts — aborting', 'fail')
            sys.exit(1)

#================funtion load_id_map load_id_map =============
def load_id_map(path: str | None):
    global _ID_MAP
    _ID_MAP = {}
    if not path:
        return
    try:
        data = _safe_load_json_file(path, label='ids-file')
        if not isinstance(data, dict):
            raise ValueError('ids-file must contain a JSON object')
        # Coerce keys to str to avoid odd lookups; keep values as-is.
        _ID_MAP = {str(k): v for k, v in data.items()}
        styled_print(f'Loaded IDs map with {len(_ID_MAP)} entries', 'info')
    except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError) as e:
        styled_print(f'Could not read ids-file: {e}', 'warn')
        logger.warning('load_id_map failed: %s', e)
        _ID_MAP = {}

#================funtion _id_lookup _id_lookup =============
def _id_lookup(name: str) -> str | None:
    if not name:
        return None
    key = name.strip()
    return str(_ID_MAP.get(key)) if key in _ID_MAP else None

#================funtion _apply_rewrites _apply_rewrites =============
def _apply_rewrites(full_url, rewrites):
    if not rewrites:
        return full_url
    original = full_url
    for rule in rewrites:
        if '=>' not in rule:
            continue
        pat, rep = [x.strip() for x in rule.split('=>', 1)]
        try:
            new_url = _re.sub(pat, rep, full_url)
            if new_url != full_url:
                logger.debug('[rewrite] %r => %r :: %s -> %s', pat, rep, full_url, new_url)
            full_url = new_url
        except _re.error as e:
            logger.warning('[rewrite] invalid regex %r: %s', pat, e)
    return full_url

#================funtion _normalize_path_generic _normalize_path_generic =============
def _normalize_path_generic(path: str) -> str:
    import re
    if not isinstance(path, str) or not path:
        return '/'
    path = re.sub('^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*', '', path)
    if not path.startswith('/'):
        path = '/' + path
    path = re.sub('/{2,}', '/', path)
    path = path.strip()
    if len(path) > 1 and path.endswith('/'):
        path = path[:-1]
    return path

#================funtion _sanitize_url _sanitize_url =============
def _sanitize_url(url: str, rewrites: list[str] | None=None) -> str:
    if not isinstance(url, str) or not url:
        return url
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(url)
    path = _normalize_path_generic(parts.path or '/')
    out = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    out = _apply_rewrites(out, rewrites)
    return out

#================funtion _sanitize_url2 _sanitize_url2 =============
def _sanitize_url2(url: str, rewrites: list[str] | None=None, disable: bool=False) -> str:
    if not isinstance(url, str) or not url:
        return url
    if disable:
        return _apply_rewrites(url, rewrites)
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(url)
    path = _normalize_path_generic(parts.path or '/')
    out = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    out = _apply_rewrites(out, rewrites)
    return out

#================funtion _merge_header_overrides _merge_header_overrides =============
def _merge_header_overrides(args) -> dict:
    overrides = {}

    #================funtion put put =============
    def put(name, value):
        if not name or value is None:
            return
        overrides[str(name).lower()] = (str(name), str(value))
    if str(getattr(args, 'flow', '')).lower() == 'token':
        tok = getattr(args, 'token', None)
        if tok:
            put('Authorization', f'Bearer {tok}')
    if getattr(args, 'apikey', None) and getattr(args, 'apikey_header', None):
        put(getattr(args, 'apikey_header'), getattr(args, 'apikey'))
    for raw in getattr(args, 'extra_header', None) or []:
        if not raw or ':' not in raw:
            continue
        name, val = raw.split(':', 1)
        put(name.strip(), val.strip())
    hf = getattr(args, 'headers_file', None)
    if hf:
        try:
            data = _safe_load_json_file(hf, label='headers-file')
            if not isinstance(data, dict):
                raise ValueError('headers-file must contain a JSON object')
            for k, v in data.items():
                put(k, v)
        except (ValueError, FileNotFoundError, json.JSONDecodeError, OSError) as e:
            styled_print(f'Could not read headers-file: {e}', 'warn')
            logger.warning('headers-file load failed: %s', e)
    return overrides

#================funtion _parse_success_codes _parse_success_codes =============
def _parse_success_codes(spec_str: str):
    parts = [p.strip() for p in (spec_str or '').split(',') if p.strip()]
    ranges = []
    singles = set()
    for p in parts:
        if '-' in p:
            a, b = p.split('-', 1)
            try:
                a = int(a)
                b = int(b)
                if a <= b:
                    ranges.append((a, b))
            except Exception:
                pass
        else:
            try:
                singles.add(int(p))
            except Exception:
                pass

#================funtion ok ok =============
    def ok(code: int) -> bool:
        if code in singles:
            return True
        for a, b in ranges:
            if a <= code <= b:
                return True
        return False
    return ok

#================funtion _plan_sample_for _plan_sample_for =============
def _plan_sample_for(name: str) -> str:
    v = _id_lookup(name)
    if v is not None:
        return v
    n = (name or '').lower()
    if 'uuid' in n or 'guid' in n:
        return '00000000-0000-4000-8000-000000000000'
    if n.endswith('id') or 'id' in n or any((k in n for k in ['number', 'no', 'seq', 'version'])):
        return '1'
    if 'code' in n:
        return 'C123'
    if 'email' in n:
        return 'user@example.com'
    if 'date' in n:
        return '2025-01-01'
    return 'sample'

#================funtion _plan_fill_path_params _plan_fill_path_params =============
def _plan_fill_path_params(url: str) -> str:
    import re as _re
    return _re.sub('{([^}]+)}', lambda m: _plan_sample_for(m.group(1)), url)

#================funtion _plan_build_example_from_schema _plan_build_example_from_schema =============
def _plan_build_example_from_schema(schema: dict):
    if not isinstance(schema, dict):
        return {}
    t = schema.get('type')
    if t == 'object' or 'properties' in schema:
        return {k: _plan_build_example_from_schema(v) for k, v in (schema.get('properties') or {}).items()}
    if t == 'array':
        return [_plan_build_example_from_schema(schema.get('items', {}) or {})]
    if t == 'integer':
        return 1
    if t == 'number':
        return 1
    if t == 'boolean':
        return False
    if t == 'string':
        return 'string'
    return {}

#================funtion _plan_body_from_requestbody _plan_body_from_requestbody =============
def _plan_body_from_requestbody(op: dict):
    rb = (op or {}).get('requestBody') or {}
    content = rb.get('content') or {}
    mt = 'application/json' if 'application/json' in content else next(iter(content.keys()), None)
    if not mt:
        if 'required' in rb and rb.get('required', False) and DUMMY_MODE:
            return ('application/json', {}, True)
        return (None, None, False)
    block = content.get(mt) or {}
    ex = block.get('example')
    if ex is None and isinstance(block.get('examples'), dict):
        first = next(iter(block['examples'].values()), {})
        if isinstance(first, dict):
            ex = first.get('value')
    if ex is None and 'schema' in block:
        try:
            ex = _plan_build_example_from_schema(block['schema'])
        except Exception:
            ex = None
    if ex is None and isinstance(block.get('schema'), dict) and ('multipart/form-data' in (mt or '').lower()):
        sch = block['schema']
        try:
            if sch.get('type') == 'object' and isinstance(sch.get('properties'), dict):
                props = sch.get('properties') or {}
                if 'file' in props:
                    ex = {'file': b'APISCAN'}
                else:
                    ex = {k: 'text' for k in props.keys()}
        except Exception:
            ex = {'file': b'APISCAN'}
    if ex is None and rb.get('required', False):
        if 'json' in (mt or '').lower():
            ex = {}
        else:
            ex = ''
    as_json = 'json' in (mt or '').lower() and isinstance(ex, (dict, list))
    return (mt, ex, as_json)

#================funtion plan_requests plan_requests =============
def plan_requests(spec, base_url, csv_path=None, rewrites=None, disable_sanitize: bool=False, normalize_version: bool=False):
    if csv_path is None:
        try:
            csv_path = str(OUT_DIR / 'apiscan-plan.csv')
        except Exception:
            csv_path = 'apiscan-plan.csv'
    if rewrites is None:
        rewrites = []
    rows = []
    count = 0
    used_universal = False
    try:
        sec = _sec_from_args(builtins.args) if hasattr(builtins, 'args') else _sec_from_args(argparse.Namespace())
        for op in oas_iter_ops(spec):
            req = oas_build_request(spec, base_url, op, sec)
            method = req['method']
            url = req['url']
            if normalize_version:
                url = _normalize_version_in_url(url)
            body = req.get('json')
            ctype = req['headers'].get('Content-Type', '')
            if isinstance(body, (dict, list)):
                blen = len(json.dumps(body))
                mode = 'json'
            else:
                blen = len(body or '') if body is not None else 0
                mode = 'raw'
            logger.debug('[PLAN] %s %s ct=%s len=%d json=%s', method, url, ctype or '', blen, mode == 'json')
            rows.append([method, url, ctype or '', blen, mode])
            count += 1
        used_universal = True
    except Exception:
        used_universal = False
    if not used_universal:
        paths = (spec or {}).get('paths', {}) or {}
        for pth, item in paths.items():
            if not isinstance(item, dict):
                continue
            for m in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
                op = item.get(m.lower())
                if not isinstance(op, dict):
                    continue
                url = base_url.rstrip('/') + '/' + pth.lstrip('/')
                url = _plan_fill_path_params(url)
                url = _sanitize_url2(url, rewrites, disable=disable_sanitize)
                if normalize_version:
                    url = _normalize_version_in_url(url)
                ct, body, as_json = (None, None, False)
                if m in ('POST', 'PUT', 'PATCH'):
                    try:
                        ct, body, as_json = _plan_body_from_requestbody(op)
                    except Exception:
                        ct, body, as_json = (None, None, False)
                    if ct and 'json' in str(ct).lower():
                        ct = 'application/json; charset=UTF-8'
                blen = (len(json.dumps(body)) if isinstance(body, (dict, list)) else len(body or '')) if body is not None else 0
                logger.debug('[PLAN] %s %s ct=%s len=%d json=%s', m, url, ct, blen, as_json)
                rows.append([m, url, ct or '', blen, 'json' if as_json else 'raw'])
                count += 1
                try:
                    if 'DB' in globals() and DB:
                        DB.record_endpoint(m, url, run_id=getattr(DB, 'run_id', None))
                except Exception:
                    pass
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f)
            w.writerow(['method', 'url', 'content_type', 'body_len', 'mode'])
            w.writerows(rows)
        logger.debug('[PLAN] written: %s (%d requests)', csv_path, count)
    except Exception as e:
        logger.debug('[PLAN] CSV write failed: %s', e)
    return count

#================funtion verify_plan verify_plan =============
def verify_plan(args, session, spec: dict, base_url: str, csv_path: str=None, rewrites=None, disable_sanitize: bool=False):
    if csv_path is None:
        try:
            csv_path = str(OUT_DIR / 'apiscan-verify.csv')
        except Exception:
            csv_path = 'apiscan-verify.csv'
    if rewrites is None:
        rewrites = []
    ok_code = _parse_success_codes(getattr(args, 'success_codes', '200-299'))
    results = []
    total = oks = fails = 0
    used_universal = False
    try:
        sec = _sec_from_args(args)
        for op in oas_iter_ops(spec):
            req = oas_build_request(spec, base_url, op, sec)
            method = req['method']
            url = req['url']
            t0 = time.time()
            try:
                r = session.request(**req, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                status = r.status_code
            except Exception:
                status = 0
            ms = int((time.time() - t0) * 1000)
            ok = ok_code(status)
            total += 1
            oks += 1 if ok else 0
            fails += 1 if not ok else 0
            logger.debug('[VERIFY] %s %s -> %d (%d ms)%s', method, url, status, ms, ' OK' if ok else ' FAIL')
            results.append([method, url, status, ms, 'OK' if ok else 'FAIL'])
            try:
                if 'DB' in globals() and DB:
                    DB.record_endpoint(method, url, run_id=getattr(DB, 'run_id', None), status=status, ms=ms, ok=bool(ok))
            except Exception:
                pass
        used_universal = True
    except Exception:
        used_universal = False
    if not used_universal:
        paths = (spec or {}).get('paths', {}) or {}
        for pth, item in paths.items():
            if not isinstance(item, dict):
                continue
            for m in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
                op = item.get(m.lower())
                if not isinstance(op, dict):
                    continue
                url = base_url.rstrip('/') + '/' + pth.lstrip('/')
                try:
                    url = _plan_fill_path_params(url)
                except Exception:
                    pass
                url = _sanitize_url2(url, rewrites, disable=disable_sanitize)
                if getattr(args, 'normalize_version', False):
                    url = _normalize_version_in_url(url)
                ct, body, as_json = (None, None, False)
                if m in ('POST', 'PUT', 'PATCH'):
                    try:
                        ct, body, as_json = _plan_body_from_requestbody(op)
                    except Exception:
                        ct, body, as_json = (None, None, False)
                headers = {}
                if ct and 'multipart/form-data' not in (ct or '').lower():
                    headers['Content-Type'] = ct
                overrides = _merge_header_overrides(args)
                for _, (orig, val) in overrides.items():
                    headers[orig] = val
                t0 = time.time()
                try:
                    if m in ('POST', 'PUT', 'PATCH'):
                        if isinstance(ct, str) and 'multipart/form-data' in ct.lower() and isinstance(body, dict):
                            files, data = ({}, {})
                            for k, v in body.items():
                                if isinstance(v, (bytes, bytearray)):
                                    files[k] = ('apiscan.bin', v)
                                else:
                                    data[k] = v
                            headers.pop('Content-Type', None)
                            r = session.request(m, url, headers=headers, files=files, data=data, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                        elif as_json and isinstance(body, (dict, list)):
                            r = session.request(m, url, headers=headers, json=body, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                        elif body is not None:
                            r = session.request(m, url, headers=headers, data=body, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                        else:
                            r = session.request(m, url, headers=headers, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                    else:
                        r = session.request(m, url, headers=headers, timeout=getattr(args, 'timeout', 10), verify=not getattr(args, 'insecure', False))
                    status = r.status_code
                except Exception:
                    status = 0
                ms = int((time.time() - t0) * 1000)
                ok = ok_code(status)
                total += 1
                oks += 1 if ok else 0
                fails += 1 if not ok else 0
                logger.debug('[VERIFY] %s %s -> %d (%d ms)%s', m, url, status, ms, ' OK' if ok else ' FAIL')
                results.append([m, url, status, ms, 'OK' if ok else 'FAIL'])
                try:
                    if 'DB' in globals() and DB:
                        DB.record_endpoint(m, url, run_id=getattr(DB, 'run_id', None), status=status, ms=ms, ok=bool(ok))
                except Exception:
                    pass
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f)
            w.writerow(['method', 'url', 'status', 'ms', 'result'])
            w.writerows(results)
        logger.debug('[VERIFY] written: %s  OK=%d FAIL=%d TOTAL=%d', csv_path, oks, fails, total)
    except Exception as e:
        logger.debug('[VERIFY] CSV write failed: %s', e)
    return (oks, fails, total)

def auto_generate_swagger(args, output_dir: Path | None=None) -> str:
    from swagger_universal_tool import UltimateSwaggerGenerator
    from datetime import datetime as _dt

    timestamp = _dt.now().strftime('%Y%m%d_%H%M%S')
    run_dir = Path(output_dir) if output_dir else Path.cwd()
    log_dir = run_dir / 'log'
    log_dir.mkdir(parents=True, exist_ok=True)
    output_file = log_dir / f'swagger_auto_{timestamp}.json'

    print(f'[*] No Swagger provided; starting crawl for {args.url}')
    print(f'[*] Output: {output_file}')

    effective_aggressive = bool(getattr(args, 'crawl_aggressive', False) or not getattr(args, 'crawl_passive', False))
    if effective_aggressive and not getattr(args, 'crawl_aggressive', False):
        print('[*] Crawl draait in aggressive modus (default). Gebruik --crawl-passive voor lichtere crawl.')

    generator = UltimateSwaggerGenerator(
        base_url=args.url,
        delay=0.0,
        aggressive=effective_aggressive,
        insecure=bool(getattr(args, 'insecure', False))
    )

    # Forward auth options from apiscan args to crawler.
    if getattr(args, 'token', None):
        generator.set_token_auth(args.token)
    if getattr(args, 'apikey', None):
        header = getattr(args, 'apikey_header', 'X-API-Key')
        generator.set_custom_header(header, args.apikey)

    generator.crawl(
        max_depth=getattr(args, 'crawl_depth', 3),
        aggressive=effective_aggressive
    )
    generator._prune_non_json_paths()
    generator.save_swagger(str(output_file))

    if getattr(args, 'crawl_validate', True):
        output_file = validate_crawled_swagger(str(output_file), args, output_dir=run_dir)

    print(f'[+] Swagger generated: {output_file}')
    return str(output_file)

def validate_crawled_swagger(swagger_path: str, args, output_dir: Path | None=None) -> str:
    from datetime import datetime as _dt

    methods = {'get', 'head', 'options', 'post', 'put', 'patch', 'delete', 'trace'}

    with open(swagger_path, 'r', encoding='utf-8') as f:
        spec = json.load(f)

    paths = (spec or {}).get('paths') or {}
    if not isinstance(paths, dict) or not paths:
        return swagger_path

    try:
        session = configure_authentication(args)
    except Exception:
        session = requests.Session()

    try:
        session.verify = not getattr(args, 'insecure', False)
    except Exception:
        pass

    try:
        if getattr(args, 'proxy', None):
            session.proxies.update({'http': args.proxy, 'https': args.proxy})
    except Exception:
        pass

    timeout = max(1.0, min(float(getattr(args, 'timeout', 5.0)), 10.0))
    workers = max(1, int(getattr(args, 'crawl_validate_workers', 8) or 8))
    mode = str(getattr(args, 'crawl_validate_mode', 'balanced') or 'balanced').strip().lower()

    def _has_sample_response(path_item: dict[str, Any]) -> bool:
        for k, op in (path_item or {}).items():
            if not isinstance(k, str) or k.startswith('x-') or not isinstance(op, dict):
                continue
            responses = op.get('responses') or {}
            if not isinstance(responses, dict):
                continue
            for _, resp in responses.items():
                if not isinstance(resp, dict):
                    continue
                desc = str(resp.get('description') or '').lower()
                content = resp.get('content') or {}
                if content:
                    return True
                if desc and 'no sample response' not in desc:
                    return True
        return False

    # Detect SPA homepages — cache the base URL response for comparison
    _homepage_body: Optional[str] = None
    _homepage_len: int = 0
    try:
        _hr = session.get(args.url, timeout=timeout, allow_redirects=True)
        _hct = (getattr(_hr, 'headers', {}) or {}).get('Content-Type', '').lower()
        if 'text/html' in _hct:
            _homepage_body = getattr(_hr, 'text', '') or ''
            _homepage_len = len(_homepage_body)
    except Exception:
        pass

    # ── Helpers for detecting non-existent path errors ──
    _PATH_NOT_FOUND_BODY = _re.compile(
        r'unexpected\s+path', _re.IGNORECASE
    )
    _PATH_NOT_FOUND_JSON_MSG = _re.compile(
        r'(?:unexpected|unknown|invalid|no\s+such|not\s+found|no\s+route)\s+(?:path|route|endpoint|url|resource)'
        r'|cannot\s+(?:GET|POST|PUT|DELETE|PATCH)\b'  # Express "Cannot GET /…"
        r'|no\s+route\s+found',  # Express "No route found for …"
        _re.IGNORECASE
    )
    _NOT_FOUND_HTML_TITLE = _re.compile(
        r'<title>[^<]*(?:404|not\s+found|page\s+not\s+found)[^<]*</title>',
        _re.IGNORECASE
    )

    def _is_path_not_found_error(resp) -> bool:
        if resp is None:
            return False
        try:
            code = int(getattr(resp, 'status_code', 0) or 0)
        except Exception:
            return False
        if code not in (500, 501):
            return False
        try:
            ct = str((getattr(resp, 'headers', {}) or {}).get('Content-Type', '')).lower()
        except Exception:
            ct = ''
        try:
            body = getattr(resp, 'text', '') or ''
        except Exception:
            body = ''
        body_low = body.lower()
        body_short = body_low[:2048]

        # Juice Shop: "Unexpected path: /api/whatever"
        if _PATH_NOT_FOUND_BODY.search(body_short):
            return True

        # JSON error envelopes: {"error":{"message":"Unexpected path: ..."}}
        if 'json' in ct and body_short:
            try:
                import json as _json
                obj = _json.loads(body)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                msg = str(obj.get('message', obj.get('error', ''))).lower()
                if isinstance(obj.get('error'), dict):
                    msg = str(obj['error'].get('message', '')).lower()
                if _PATH_NOT_FOUND_JSON_MSG.search(msg):
                    return True

        # HTML 404-style pages served as 500
        if 'text/html' in ct and _NOT_FOUND_HTML_TITLE.search(body_short):
            return True

        return False

    def _probe(path: str, path_item: dict[str, Any]) -> tuple[str, bool]:
        if not isinstance(path_item, dict):
            return path, False

        if mode == 'strict' and _has_sample_response(path_item):
            return path, True

        op_methods = []
        for key in path_item.keys():
            if isinstance(key, str) and key.lower() in methods:
                op_methods.append(key.lower())

        safe_methods = [m for m in ('get', 'head', 'options') if m in op_methods]
        if not safe_methods:
            # Write-only endpoint — probe with GET to see if the path exists at all
            probe_url2 = urljoin(args.url.rstrip('/') + '/', _re.sub(r'\{[^}]+\}', '1', path).lstrip('/'))
            try:
                r = session.get(probe_url2, timeout=timeout, allow_redirects=False)
                code = int(getattr(r, 'status_code', 0) or 0)
                ct = str((getattr(r, 'headers', {}) or {}).get('Content-Type', '')).lower()
                if code == 200 and 'text/html' in ct and _homepage_body:
                    rb = getattr(r, 'text', '') or ''
                    if len(rb) == _homepage_len and rb == _homepage_body:
                        return path, False  # SPA fallback, not real
                # 5xx "path not found" = endpoint doesn't exist
                if _is_path_not_found_error(r):
                    return path, False
                if code in (401, 403, 405):
                    return path, True  # exists but GET not allowed
                if code == 200 and any(h in ct for h in ('json', 'xml', 'problem+json')):
                    return path, True
            except Exception:
                pass
            return path, False  # can't verify, drop it

        probe_url = urljoin(args.url.rstrip('/') + '/', _re.sub(r'\{[^}]+\}', '1', path).lstrip('/'))
        for m in safe_methods:
            try:
                resp = session.request(m.upper(), probe_url, timeout=timeout, allow_redirects=False)
                code = int(getattr(resp, 'status_code', 0) or 0)
                ct = str((getattr(resp, 'headers', {}) or {}).get('Content-Type', '')).lower()
                body_len = len(getattr(resp, 'text', '') or '')
            except Exception:
                code = 0
                ct = ''
                body_len = 0

            # 200 with HTML identical to homepage = SPA catch-all, not a real endpoint
            if code == 200 and 'text/html' in ct and _homepage_body:
                resp_body = getattr(resp, 'text', '') or ''
                if len(resp_body) == _homepage_len and resp_body == _homepage_body:
                    continue  # SPA fallback — try next method

            # 5xx with "path not found" message = endpoint doesn't exist
            if _is_path_not_found_error(resp):
                continue  # try next method

            if mode == 'strict':
                if code in (200, 201, 202, 204, 401, 403, 405):
                    if any(h in ct for h in ('json', 'xml', 'problem+json', 'vnd.api+json')) or body_len > 0:
                        return path, True
            else:
                if code and code != 404:
                    # In balanced mode, also skip SPA homepage matches
                    if code == 200 and 'text/html' in ct and _homepage_body:
                        resp_body = getattr(resp, 'text', '') or ''
                        if len(resp_body) == _homepage_len and resp_body == _homepage_body:
                            continue
                    return path, True
        return path, False

    kept: dict[str, Any] = {}
    dropped = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe, p, item) for p, item in paths.items()]
        for fut in as_completed(futures):
            p, ok = fut.result()
            if ok:
                kept[p] = paths[p]
            else:
                dropped += 1

    if not kept:
        print('[!] Crawl-validatie leverde 0 endpoints op; behoud originele crawl-output.')
        return swagger_path

    # ── BOLA enrichment: add {id} sibling for collection endpoints ──
    # Crawls often discover /api/orders but not /api/orders/{id} because
    # individual resource URLs may not be linked from list responses.
    # Without {id} paths the BOLA scanner has no object parameters to test.
    _enriched = dict(kept)
    _resource_words = (
        'order', 'item', 'product', 'user', 'basket', 'post', 'comment',
        'message', 'review', 'feedback', 'account', 'profile', 'payment',
        'address', 'category', 'group', 'file', 'event', 'log', 'notification',
        'permission', 'role', 'setting', 'config', 'coupon', 'token', 'wallet',
        'card', 'delivery', 'track', 'complaint', 'refund', 'report', 'invoice',
    )
    for path, path_item in kept.items():
        if not isinstance(path_item, dict):
            continue
        # Skip paths that already have a path parameter
        if '{' in path:
            continue
        # Check if the last segment suggests a resource collection
        last_seg = path.rstrip('/').rsplit('/', 1)[-1].lower()
        if not any(last_seg == w or last_seg == w + 's' for w in _resource_words):
            continue
        id_path = path.rstrip('/') + '/{id}'
        if id_path in kept or id_path in _enriched:
            continue
        id_item: dict[str, Any] = {}
        for method, op in path_item.items():
            if not isinstance(method, str) or not isinstance(op, dict):
                continue
            m_upper = method.upper()
            if m_upper not in ('GET', 'HEAD', 'OPTIONS'):
                continue  # only safe read methods for auto-generated {id} paths
            id_op = dict(op)
            # Inject {id} path parameter
            existing_params = list(id_op.get('parameters', []))
            existing_names = {p.get('name') for p in existing_params if isinstance(p, dict)}
            if 'id' not in existing_names:
                existing_params.append({
                    'name': 'id',
                    'in': 'path',
                    'required': True,
                    'schema': {'type': 'integer'},
                })
            id_op['parameters'] = existing_params
            id_op['summary'] = id_op.get('summary', '') + ' (auto-generated BOLA candidate)'
            id_item[method] = id_op
        if id_item:
            _enriched[id_path] = id_item

    spec['paths'] = _enriched
    ts = _dt.now().strftime('%Y%m%d_%H%M%S')
    run_dir = Path(output_dir) if output_dir else Path(swagger_path).resolve().parent.parent
    log_dir = run_dir / 'log'
    log_dir.mkdir(parents=True, exist_ok=True)
    validated_path = log_dir / f'swagger_auto_validated_{ts}.json'
    with open(validated_path, 'w', encoding='utf-8') as f:
        json.dump(spec, f, indent=2, ensure_ascii=False)

    enriched = len(_enriched) - len(kept)
    print(f'[*] Crawl-validatie ({mode}): behouden={len(kept)} verwijderd={dropped} BOLA-enriched=+{enriched}')
    print(f'[+] Validated Swagger written: {validated_path}')
    return str(validated_path)

def _count_spec_operations(spec: dict[str, Any] | None) -> int:
    methods = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'}
    count = 0
    paths = ((spec or {}).get('paths') or {}) if isinstance(spec, dict) else {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for key in path_item.keys():
            if isinstance(key, str) and key.lower() in methods:
                count += 1
    return count

def merge_swagger_specs(primary_swagger: str, crawled_swagger: str, output_dir: Path | None=None) -> str:
    from datetime import datetime as _dt

    with open(primary_swagger, 'r', encoding='utf-8') as f:
        primary = json.load(f)
    with open(crawled_swagger, 'r', encoding='utf-8') as f:
        crawled = json.load(f)

    primary_paths = primary.setdefault('paths', {})
    crawled_paths = (crawled or {}).get('paths', {}) or {}
    methods = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'}

    for path, path_item in crawled_paths.items():
        if not isinstance(path_item, dict):
            continue
        if path not in primary_paths or not isinstance(primary_paths.get(path), dict):
            primary_paths[path] = path_item
            continue
        for key, value in path_item.items():
            if isinstance(key, str) and key.lower() in methods and key not in primary_paths[path]:
                primary_paths[path][key] = value

    timestamp = _dt.now().strftime('%Y%m%d_%H%M%S')
    run_dir = Path(output_dir) if output_dir else Path(primary_swagger).resolve().parent.parent
    log_dir = run_dir / 'log'
    log_dir.mkdir(parents=True, exist_ok=True)
    merged_file = log_dir / f'swagger_merged_{timestamp}.json'
    with open(merged_file, 'w', encoding='utf-8') as f:
        json.dump(primary, f, indent=2, ensure_ascii=False)

    print(
        '[*] Swagger merge: '
        f'primary={_count_spec_operations(primary)} ops, '
        f'crawled={_count_spec_operations(crawled)} ops, '
        f'merged={_count_spec_operations(primary)} ops'
    )
    print(f'[+] Merged Swagger written: {merged_file}')
    return str(merged_file)

#================funtion main main =============
def main() -> None:
    parser = argparse.ArgumentParser(description=f'APISCAN {__version__} - API Security Scanner')
    parser.add_argument('--url', required=True, help='Base URL of the API to scan')
    parser.add_argument('--swagger', help='Path to Swagger/OpenAPI JSON file (optional with --crawl)')
    parser.add_argument(
        '--crawl',
        action='store_true',
        help='Auto-generate Swagger spec by crawling target before scanning'
    )
    parser.add_argument(
        '--crawl-depth',
        type=int,
        default=3,
        help='Crawl depth for auto-discovery (default: 3)'
    )
    parser.add_argument(
        '--crawl-aggressive',
        action='store_true',
        help='Enable aggressive crawl mode (brute-force common endpoints)'
    )
    parser.add_argument(
        '--crawl-passive',
        action='store_true',
        help='Disable default aggressive crawl behavior and use lighter discovery only'
    )
    parser.add_argument(
        '--crawl-validate',
        dest='crawl_validate',
        action='store_true',
        help='Validate discovered crawl endpoints with lightweight probes (default: on)'
    )
    parser.add_argument(
        '--no-crawl-validate',
        dest='crawl_validate',
        action='store_false',
        help='Skip post-crawl endpoint validation'
    )
    parser.add_argument(
        '--crawl-validate-workers',
        type=int,
        default=8,
        help='Concurrent workers for post-crawl validation probes (default: 8)'
    )
    parser.add_argument(
        '--crawl-validate-mode',
        choices=['balanced', 'strict'],
        default='balanced',
        help='Validation strictness after crawl: balanced (default) or strict'
    )
    parser.add_argument('--threads', type=int, default=16, help='Number of concurrent threads to use (default: 16)')
    parser.add_argument('--db-path', help='Optional SQLite DB file to cache findings')
    parser.add_argument('--plan-only', action='store_true', help='Build all requests and write apiscan-plan.csv, do not send')
    parser.add_argument('--plan-then-scan', action='store_true', help='First build full plan (CSV), then perform the scan')
    parser.add_argument('--verify-plan', action='store_true', help='After planning, actually send each planned request and expect success')
    parser.add_argument('--success-codes', default='200-299', help='Comma list of codes or ranges, e.g., 200-299,302')
    parser.add_argument('--flow', choices=['none', 'token', 'client', 'basic', 'digest', 'ntlm', 'auth', 'form'], default='none', help='Authentication flow: none, token (Bearer), client (OAuth2 Client Credentials), basic (Basic Auth), digest (HTTP Digest), ntlm (Windows NTLM), auth (OAuth2 Authorization Code), form (auto-detect login form)')
    parser.add_argument('--token', help='Bearer token value (used with --flow token)')
    parser.add_argument('--basic-auth', help='Basic auth in the form user:password (used with --flow basic)')
    # Auto form-login arguments
    parser.add_argument('--login-url', help='Login page/endpoint URL (for --flow form)')
    parser.add_argument('--login-username', help='Username or email for auto form-login (for --flow form)')
    parser.add_argument('--login-password', help='Password for auto form-login (for --flow form)')
    parser.add_argument('--token-path', help='JSON dot-path to token in login response, e.g. authentication.token (for --flow form)')
    parser.add_argument('--apikey', help='API key value (sent in header specified by --apikey-header)')
    parser.add_argument('--apikey-header', default='X-API-Key', help='Header name for API key (default: X-API-Key)')
    parser.add_argument('--ntlm', help='NTLM credentials in the form DOMAIN\\user:password (used with --flow ntlm)')
    parser.add_argument('--client-cert', help='Path to client certificate file (PEM, used for mTLS)')
    parser.add_argument('--client-key', help='Path to private key file (PEM, used for mTLS)')
    parser.add_argument('--cert-password', help='Password for client certificate private key (if encrypted)')
    parser.add_argument('--client-id', help='OAuth2 Client ID (for --flow client or auth)')
    parser.add_argument('--client-secret', help='OAuth2 Client Secret (for --flow client or auth)')
    parser.add_argument('--token-url', help='OAuth2 Token endpoint URL (for --flow client or auth)')
    parser.add_argument('--auth-url', help='OAuth2 Authorization endpoint URL (for --flow auth)')
    parser.add_argument('--redirect-uri', help='Redirect URI for OAuth2 Authorization Code flow')
    parser.add_argument('--scope', help='OAuth2 scope(s), space-separated')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS certificate validation (DANGEROUS, use only for testing)')
    parser.add_argument('--timeout', type=float, default=5.0, help='Request timeout in seconds (float, 0 < t <= 600)')
    parser.add_argument('--retry500', type=int, default=1, help='adaptive retries on HTTP 5xx for POST/PUT/PATCH')
    parser.add_argument('--no-retry-500', dest='retry500', action='store_const', const=0, help='disable adaptive 5xx retries')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (verbose logging)')
    parser.add_argument('--dummy', action='store_true', help='Use dummy data for request bodies and parameters')
    parser.add_argument('--export_vars', metavar='PATH', help='Export variables template YAML if .yml/.yaml else JSON')
    parser.add_argument('--proxy', help='Optional proxy URL, e.g. http://127.0.0.1:8080')
    parser.add_argument('--headers-file', help='Path to JSON file with header overrides')
    parser.add_argument('--ids-file', help='JSON file mapping path parameter names to concrete values')
    parser.add_argument('--rewrite', action='append', default=[], help='Regex=>replacement rewrite applied to each URL (can be repeated)')
    parser.add_argument('--no-sanitize', action='store_true', help='Disable built-in URL normalization; only apply explicit --rewrite rules')
    parser.add_argument('--api3-active', action='store_true', dest='api3_active', help='Enable active mass-assignment write tests for API3 (sends modified JSON to write endpoints)')
    parser.add_argument('--chain-mode', action='store_true', dest='chain_mode', help='Auto-escalate BOLA findings: re-inject leaked data into other endpoints')
    parser.add_argument('--chain-depth', type=int, default=1, dest='chain_depth', metavar='N', help='Recursive chain depth (default: 1, max: 3)')
    parser.add_argument('--api11', action='store_true', help='Run AI-assisted OWASP Top 10 analysis')
    for i in range(1, 11):
        parser.add_argument(f'--api{i}', action='store_true', help=f'Run only API{i} audit')
    group_nv = parser.add_mutually_exclusive_group()
    group_nv.add_argument('--normalize-version', dest='normalize_version', action='store_true', help='Normalize version segments in URLs like /v2.00/ -> /v2.0/ during planning and verify.')
    group_nv.add_argument('--no-normalize-version', dest='normalize_version', action='store_false', help='Disable version normalization in URLs (default).')
    parser.set_defaults(normalize_version=False, crawl_validate=True)
    # Normalize argument names to lowercase so --URL, --Token, --Swagger etc. all work
    _argv = []
    for _a in sys.argv[1:]:
        if _a.startswith('--'):
            _name, _, _val = _a[2:].partition('=')
            _a = '--' + _name.lower() + ('=' + _val if _ else '')
        elif _a.startswith('-') and len(_a) > 1 and not _a[1:].lstrip('-'):
            _a = '-' + _a[1:].lower()
        _argv.append(_a)
    args = parser.parse_args(_argv)
    builtins.args = args
    # --- Hardened argument validation (OWASP A03/A05) ---
    try:
        if not isinstance(args.timeout, (int, float)) or args.timeout <= 0 or args.timeout > 600:
            parser.error('--timeout must be > 0 and <= 600 seconds')
        if getattr(args, 'crawl_depth', 3) < 1:
            parser.error('--crawl-depth must be >= 1')
        if getattr(args, 'crawl_validate_workers', 8) < 1:
            parser.error('--crawl-validate-workers must be >= 1')
        if getattr(args, 'rewrite', None):
            args.rewrite = [_validate_rewrite_pattern(r) for r in args.rewrite]
        if getattr(args, 'proxy', None):
            args.proxy = _validate_proxy(args.proxy)
        for _label, _attr, _cap in (
            ('client-cert', 'client_cert', _MAX_JSON_FILE_BYTES),
            ('client-key',  'client_key',  _MAX_JSON_FILE_BYTES),
            ('headers-file', 'headers_file', _MAX_JSON_FILE_BYTES),
            ('ids-file',     'ids_file',     _MAX_JSON_FILE_BYTES),
        ):
            _val = getattr(args, _attr, None)
            if _val:
                _validate_input_file(_val, _cap, _label)
    except (ValueError, FileNotFoundError) as e:
        parser.error(str(e))
    if args.url:
        # normalize_url enforces https-by-default and warns on http://.
        args.url = normalize_url(args.url)
    output_dir = create_output_directory(args.url)
    if args.crawl:
        if args.swagger:
            print('[*] Zowel --swagger als --crawl opgegeven; crawl wordt toegevoegd aan bestaande swagger.')
            crawled_swagger = auto_generate_swagger(args, output_dir=output_dir)
            try:
                args.swagger = merge_swagger_specs(args.swagger, crawled_swagger, output_dir=output_dir)
            except Exception as e:
                print(f'[!] Merge mislukt ({e}); ga verder met opgegeven --swagger.')
        else:
            args.swagger = auto_generate_swagger(args, output_dir=output_dir)
    elif not args.swagger:
        print('[-] Geef --swagger op of gebruik --crawl voor auto-discovery')
        sys.exit(1)
    clear_screen()
    print_banner()
    if getattr(args, 'dummy', False):
        try:
            enable_dummy_mode(True)
            globals()['DUMMY_MODE'] = True
            if getattr(args, 'debug', False):
                print('[DEBUG] Dummy mode enabled in swagger_utils')
        except Exception:
            pass
    load_id_map(getattr(args, 'ids_file', None))
    builtins.debug_mode = args.debug
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[DEBUG] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[INFO] %(message)s')
    selected_apis = [11] if args.api11 else [i for i in range(1, 11) if getattr(args, f'api{i}')] or list(range(1, 11))
    global OUT_DIR
    OUT_DIR = output_dir
    if not getattr(args, 'db_path', None):
        try:
            default_db_dir = output_dir / 'db'
            default_db_dir.mkdir(parents=True, exist_ok=True)
            args.db_path = str(default_db_dir / 'results.db')
        except Exception:
            args.db_path = 'results.db'
    log_dir = output_dir / 'log'
    log_dir.mkdir(exist_ok=True)
    logfile = log_dir / f"apiscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(logfile, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    logger = logging.getLogger('apiscan')
    logger.propagate = False
    db = None
    globals()['DB'] = None
    run_id = datetime.now().strftime('%Y%m%d-%H%M%S')
    if args.url:
        try:
            from urllib.parse import urlsplit as _us
            host = (_us(args.url).netloc or 'host').replace(':', '_')
            run_id = f'{host}-{run_id}'
        except Exception:
            pass
    if args.db_path:
        try:
            db = EvidenceDatabase(args.db_path, run_id=run_id)
            styled_print(f'Using evidence database at {db.path}', 'info')
        except Exception as e:
            styled_print(f'WARNING: could not initialize evidence database: {e}', 'warn')
            db = None
    try:
        sess = configure_authentication(args)
    except AuthConfigError as e:
        styled_print(f'Authentication configuration failed: {e}', 'fail')
        if str(getattr(args, 'flow', '')).lower() == 'token':
            styled_print('use: --flow token --token <JWT_OF_API_TOKEN>', 'info')
        sys.exit(2)
    except Exception as e:
        styled_print(f'Unexpected authentication error: {e}', 'fail')
        if getattr(args, 'debug', False):
            logger.exception('Authentication setup exception')
        sys.exit(2)
    try:
        sess.verify = not args.insecure
    except Exception:
        pass
    try:
        if args.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            # Prominent operator-visible warning (OWASP A02).
            styled_print('TLS certificate validation is DISABLED (--insecure). Use only against test systems.', 'warn')
            logger.warning('TLS certificate validation disabled by user (--insecure)')
    except Exception:
        pass
    if getattr(args, 'proxy', None):
        pr = args.proxy  # already validated above
        sess.proxies.update({'http': pr, 'https': pr})
        banner = f'PROXY MODE ENABLED -> {_redact_url(pr)}'
        logger.info(banner)
        try:
            print(Fore.MAGENTA + banner + Style.RESET_ALL)
        except Exception:
            print(banner)
    _retry = (
        Retry(total=3, read=0, connect=1, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504], allowed_methods=False)
        if Retry else 3
    )
    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=_retry)
    sess.mount('http://', adapter)
    sess.mount('https://', adapter)
    check_api_reachable(args.url, sess)
    try:
        swagger_path = Path(args.swagger).resolve()
        if not swagger_path.exists():
            raise FileNotFoundError(f'Swagger file not found: {swagger_path}')
        if not swagger_path.is_file():
            raise ValueError(f'Path is not a file: {swagger_path}')
        _sz = swagger_path.stat().st_size
        if _sz == 0:
            raise ValueError('Swagger file is empty')
        if _sz > _MAX_SWAGGER_FILE_BYTES:
            raise ValueError(f'Swagger file too large ({_sz} > {_MAX_SWAGGER_FILE_BYTES} bytes)')
        logger.info(f'Loading Swagger from: {swagger_path}')
        styled_print(f'Loading validated Swagger file: {swagger_path}', 'info')
        spec = oas_load_spec(str(swagger_path), inject_base_url=args.url)
        _bola_workers = int(os.environ.get('APISCAN_BOLA_WORKERS', str(max(1, min(args.threads, MAX_THREADS)))))
        # Single-pass endpoint extraction — avoid creating BOLAAuditor just for discovery;
        # it will be created again (with caching) when the BOLA scan actually runs.
        uni_eps = _endpoints_from_universal(spec)
        endpoints = uni_eps[:]
        if not endpoints:
            print('[debug] No endpoints found by discovery; falling back to raw paths')
            endpoints = extract_endpoints_from_paths(spec)
        ai_sources = []
        seen_ai = set()
        for source in (uni_eps, endpoints):
            for ep in source or []:
                key = ((ep or {}).get('method', '').upper(), (ep or {}).get('path', ''))
                if not key[0] or not key[1] or key in seen_ai:
                    continue
                seen_ai.add(key)
                ai_sources.append(ep)
        ai_endpoints = [_build_ai_endpoint(ep) for ep in ai_sources]
        logger.debug(f'Swagger loaded - {len(endpoints)} endpoints')
        styled_print(f'Swagger loaded - {len(endpoints)} endpoints found', 'ok')
        if db is not None:
            from urllib.parse import urljoin as _uij
            try:
                for _ep in endpoints:
                    try:
                        _m = (_ep.get('method') or '').upper()
                        _p = _ep.get('path') or ''
                        if not (_m and _p):
                            continue
                        _u = _uij(args.url.rstrip('/') + '/', _p.lstrip('/'))
                        db.record_endpoint(_m, _u, run_id=run_id)
                    except Exception:
                        pass
            except Exception:
                pass
    except (FileNotFoundError, ValueError) as e:
        logger.error(f'Swagger processing failed: {e}')
        styled_print(str(e), 'fail')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Unexpected error during Swagger parsing: {e}')
        styled_print('Unexpected error during Swagger parsing', 'fail')
        sys.exit(1)
    base = args.url
    if getattr(args, 'plan_only', False) or getattr(args, 'plan_then_scan', False):
        plan_requests(spec, base, csv_path=None, rewrites=getattr(args, 'rewrite', []), disable_sanitize=getattr(args, 'no_sanitize', False), normalize_version=getattr(args, 'normalize_version', False))
        if getattr(args, 'plan_only', False):
            styled_print('Plan-only mode: done.', 'ok')
            return
    if getattr(args, 'verify_plan', False):
        oks, fails, total = verify_plan(args, sess, spec, base, csv_path=None, rewrites=getattr(args, 'rewrite', []), disable_sanitize=getattr(args, 'no_sanitize', False))
        if fails > 0 and (not getattr(args, 'plan_then_scan', False)):
            styled_print(f'Verify found {fails} failures out of {total}', 'warn')
        elif fails == 0:
            styled_print('Verify passed: all planned requests succeeded', 'ok')
    if args.export_vars:
        try:
            vars_doc = extract_variables(spec)
            out_file = write_variables_file(vars_doc, args.export_vars)
            styled_print(f'Variables template written to {out_file}', 'ok')
            sys.exit(0)
        except Exception as e:
            styled_print(f'FAIL exporting variables: {e}', 'fail')
            sys.exit(1)
    vulnerability_summary = {}
    
    if 1 in selected_apis:
        _bola_workers = int(os.environ.get('APISCAN_BOLA_WORKERS', str(max(1, min(args.threads, MAX_THREADS)))))
        _scan_section(1, f'BOLA – Broken Object Level Authorization  (threads={_bola_workers})')
        logger.info('Running API1 - BOLA')
        bola = BOLAAuditor(session=sess, base_url=args.url, swagger_spec=spec, show_subbars=(_bola_workers == 1))
        endpoints = bola.get_object_endpoints(spec) or []
        bola_results = []
        max_workers = _bola_workers
        if max_workers == 1:
            for ep in tqdm(endpoints, desc='BOLA endpoints', unit='endpoint'):
                try:
                    res = bola.test_endpoint(args.url, ep)
                    if res:
                        bola_results.extend(res)
                except Exception as e:
                    _scan_err(f"{ep.get('method')} {ep.get('path')}", e)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(bola.test_endpoint, args.url, ep): ep for ep in endpoints}
                for fut in tqdm(as_completed(futures), total=len(futures), desc='BOLA endpoints', unit='endpoint'):
                    ep = futures[fut]
                    try:
                        res = fut.result()
                        if res:
                            bola_results.extend(res)
                    except Exception as e:
                        _scan_err(f"{ep.get('method')} {ep.get('path')}", e)
        bola.issues = [r.to_dict() for r in bola_results if getattr(r, 'status_code', 0) != 0 and getattr(r, 'test_case', '') != 'valid']
        try:
            bola.generate_report()
        except Exception as e:
            _scan_err('API1 report generation', e)
        found = len(bola.issues)
        vulnerability_summary['BOLA'] = found
        msg = f'{Fore.GREEN}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}' if found == 0 else f'{Fore.YELLOW}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}' if found < 5 else f'{Fore.RED}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}'
        save_html_report(bola.issues, 'BOLA', args.url, output_dir)
        if db is not None:
            db.store_issues('BOLA', bola.issues, base_url=args.url)
        styled_print(msg, 'done')

        # ── Chain-mode: escalation after BOLA ──────────────────────
        if getattr(args, 'chain_mode', False) and bola_results:
            chain_depth = min(max(1, int(getattr(args, 'chain_depth', 1) or 1)), 3)
            all_chain_issues: list = []
            source_results = bola_results  # start with BOLA results

            for depth in range(1, chain_depth + 1):
                label = f'Chain L{depth} – Escalation of BOLA leaks' if chain_depth > 1 else 'Chain – Escalation of BOLA leaks'
                _scan_section(0, label)
                logger.info('Running Chain Auditor depth %d/%d (post-BOLA escalation)', depth, chain_depth)

                try:
                    chain = ChainAuditor(
                        session=sess,
                        base_url=args.url,
                        swagger_spec=spec,
                        bola_results=source_results,
                        timeout=args.timeout,
                        max_workers=min(args.threads, 4),
                        show_progress=True,
                    )
                    chain.findings = chain.run()
                    chain_issues = chain.get_issues()
                    all_chain_issues.extend(chain_issues)

                    depth_found = len(chain_issues)
                    if depth_found == 0:
                        logger.info('Chain depth %d: no escalations found, stopping recursion.', depth)
                        break

                    # Feed chain results back as source for next depth
                    source_results = chain_issues
                except Exception as e:
                    _scan_err('Chain auditor', e)
                    logger.exception('Chain auditor exception at depth %d', depth)
                    break

            chain_found = len(all_chain_issues)
            vulnerability_summary['Chain-Escalation'] = chain_found
            if all_chain_issues:
                save_html_report(all_chain_issues, 'Chain-Escalation', args.url, output_dir)
                if db is not None:
                    db.store_issues('Chain-Escalation', all_chain_issues, base_url=args.url)
            cmsg = (f'{Fore.GREEN}Chain complete - {chain_found} escalations found{Style.RESET_ALL}'
                    if chain_found == 0
                    else f'{Fore.RED}Chain complete - {chain_found} escalations found{Style.RESET_ALL}')
            styled_print(cmsg, 'done')
    
    if 2 in selected_apis:
        _scan_section(2, 'Broken Authentication')
        logger.info('Running API2 - Broken Authentication')
        norm_eps = []
        for ep in endpoints:
            try:
                path = ep['path']
                method = ep['method'].upper()
                norm_eps.append({'path': path, 'method': method})
            except KeyError:
                continue
        aa = AuthAuditor(session=sess, base_url=args.url, swagger_spec=spec, show_progress=True)
        auth_issues = aa.test_authentication_mechanisms(norm_eps)
        auth_issues = _filter_auth_issues_min(auth_issues)
        for issue in auth_issues:
            desc = issue.get('description', 'Unknown')
            ep = issue.get('endpoint', issue.get('url', ''))
            sev = issue.get('severity', 'Info')
            _scan_issue(sev, desc, ep)
        vulnerability_summary['Authentication'] = len(auth_issues)
        save_html_report(auth_issues, 'BrokenAuth', args.url, output_dir)
        if db is not None:
            db.store_issues('Authentication', auth_issues, base_url=args.url)
        styled_print(f'API2 complete - {len(auth_issues)} issues', 'done')
    
    if 3 in selected_apis:
        _scan_section(3, 'Object Property Level Authorization')
        logger.info('Running API3 - Property-level Authorization')
        pa = ObjectPropertyAuditor(
            base_url=args.url,
            session=sess,
            show_progress=True,
            timeout=5.0,
            active_mode=getattr(args, 'api3_active', False),
            active_ok=getattr(args, 'api3_active', False),
        )
        prop_issues = pa.test_object_properties(endpoints)
        for issue in prop_issues:
            _scan_issue(issue.get('severity', 'info'), issue.get('description', 'Unknown'), issue.get('endpoint', 'Unknown'))
        vulnerability_summary['Property-Level Auth'] = len(prop_issues)
        save_html_report(prop_issues, 'Property', args.url, output_dir)
        if db is not None:
            db.store_issues('Property', prop_issues, base_url=args.url)
        styled_print(f'API3 complete - {len(prop_issues)} issues', 'done')
    
    if 4 in selected_apis:
        _scan_section(4, 'Unrestricted Resource Consumption')
        logger.info('Running API4 - Resource Consumption')
        rc = ResourceAuditor(session=sess, base_url=args.url, swagger_spec=spec, show_progress=True)
        res_issues = rc.test_resource_consumption()
        vulnerability_summary['Resource Consumption'] = len(res_issues)
        save_html_report(res_issues, 'Resource', args.url, output_dir)
        if db is not None:
            db.store_issues('Resource', res_issues, base_url=args.url)
        styled_print(f'API4 complete - {len(res_issues)} issues', 'done')
    
    if 5 in selected_apis:
        _scan_section(5, 'Function Level Authorization')
        logger.info('Running API5 - Function-level Authorization')
        za = AuthorizationAuditor(session=sess, base_url=args.url, spec=spec, flow=getattr(args, 'flow', 'none'), logger=logger)
        authz_issues = za.test_authorization(show_progress=True)
        for issue in authz_issues:
            _scan_issue(issue.get('severity', 'info'), issue.get('description', 'Unknown'), issue.get('endpoint', 'Unknown'))
        vulnerability_summary['Admin Access'] = len(authz_issues)
        save_html_report(authz_issues, 'AdminAccess', args.url, output_dir)
        if db is not None:
            db.store_issues('AdminAccess', authz_issues, base_url=args.url)
        styled_print(f'API5 complete - {len(authz_issues)} issues', 'done')
    
    if 6 in selected_apis:
        _scan_section(6, 'Unrestricted Access to Sensitive Business Flows')
        logger.info('Running API6 - Sensitive Business Flows')
        bf = BusinessFlowAuditor(session=sess, base_url=args.url, swagger_spec=spec, flow=getattr(args, 'flow', 'none'))
        business_eps = []
        for ep in [e for e in endpoints if e['method'] in {'POST', 'PUT', 'PATCH'}]:
            raw_op = ep.get('raw') or {}
            body = {}
            rb = raw_op.get('requestBody') or {}
            content = rb.get('content', {})
            if 'application/json' in content:
                ex = content['application/json'].get('example')
                if isinstance(ex, dict):
                    body = ex
            business_eps.append({
                'name': (ep.get('operationId') or f"{ep['method']} {ep['path']}").replace(' ', '_'),
                'url': urljoin(args.url.rstrip('/') + '/', ep['path'].lstrip('/')),
                'path': ep['path'],
                'method': ep['method'],
                'body': body,
            })
        biz_issues = bf.test_business_flows(business_eps)
        vulnerability_summary['Business Flows'] = len(biz_issues)
        save_html_report(biz_issues, 'BusinessFlows', args.url, output_dir)
        if db is not None:
            db.store_issues('BusinessFlows', biz_issues, base_url=args.url)
        styled_print(f'API6 complete - {len(biz_issues)} issues', 'done')
    
    if 7 in selected_apis:
        # SSRF scan is extremely slow (~600K requests) and yields almost nothing
        # without authentication tokens.  Auto-skip to save ~40 minutes.
        has_auth = bool(
            (getattr(args, 'token', None) or '').lower() not in ('', 'none')
            or getattr(args, 'apikey', None)
            or getattr(args, 'auth', None) not in (None, 'none')
        )
        if not has_auth:
            styled_print('API7 SSRF skipped – no authentication configured (use --token for SSRF scans)', 'warn')
            vulnerability_summary['SSRF'] = 0
        else:
            _scan_section(7, 'Server Side Request Forgery')
            logger.info('Running API7 - SSRF')
            ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger, default_base=args.url)
            if ss_eps:
                ss = SSRFAuditor(session=sess, base_url=args.url, swagger_spec=spec)
                ssrf_issues = ss.test_endpoints(ss_eps)
                vulnerability_summary['SSRF'] = len(ssrf_issues)
                save_html_report(ssrf_issues, 'SSRF', args.url, output_dir)
                if db is not None:
                    db.store_issues('SSRF', ssrf_issues, base_url=args.url)
                styled_print(f'API7 complete - {len(ssrf_issues)} issues', 'done')
            else:
                styled_print('No SSRF endpoints found', 'warn')
                vulnerability_summary['SSRF'] = 0
    
    if 8 in selected_apis:
        _scan_section(8, 'Security Misconfiguration')
        logger.info('Running API8 - Security Misconfiguration')
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            mc = MisconfigurationAuditor(base_url=args.url, session=sess, show_progress=True, debug=args.debug)
            misconf_issues = mc.test_endpoints(misconf_eps)
            vulnerability_summary['Misconfiguration'] = len(misconf_issues)
            save_html_report(misconf_issues, 'Misconfig', args.url, output_dir)
            if db is not None:
                db.store_issues('Misconfiguration', misconf_issues, base_url=args.url)
            styled_print(f'API8 complete - {len(misconf_issues)} issues', 'done')
        else:
            styled_print('No misconfiguration endpoints found', 'warn')
            vulnerability_summary['Misconfiguration'] = 0
    
    if 9 in selected_apis:
        _scan_section(9, 'Improper Inventory Management')
        logger.info('Running API9 - Improper Inventory Management')
        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger) or []
        if not inv_eps and spec:
            inv_eps = InventoryAuditor.endpoints_from_universal(spec) or []
        inv = InventoryAuditor(session=sess, base_url=args.url, swagger_spec=spec)
        inv_issues = inv.test_inventory(inv_eps if inv_eps else None)
        vulnerability_summary['Inventory'] = len(inv_issues)
        save_html_report(inv_issues, 'Inventory', args.url, output_dir)
        if db is not None:
            db.store_issues('Inventory', inv_issues, base_url=args.url)
        styled_print(f'API9 complete - {len(inv_issues)} issues', 'done')
   
    if 10 in selected_apis:
        _scan_section(10, 'Unsafe Consumption of APIs')
        logger.info('Running API10 - Safe Consumption')
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        if db is not None:
            from urllib.parse import urljoin as _uij
            try:
                for _se in safe_eps:
                    try:
                        _m = (_se.get('method') or _se.get('http_method') or 'GET').upper()
                        _p = _se.get('path') or _se.get('url') or ''
                        if not _p:
                            continue
                        _u = _p if _p.startswith('http') else _uij(args.url.rstrip('/') + '/', _p.lstrip('/'))
                        db.record_endpoint(_m, _u, run_id=run_id)
                    except Exception:
                        pass
            except Exception:
                pass
        sc = SafeConsumptionAuditor(base_url=args.url, session=sess)
        if not safe_eps:
            styled_print('No API10 endpoints found', 'warn')
            vulnerability_summary['Unsafe Consumption'] = 0
        else:
            raw_issues = sc.test_endpoints(safe_eps)
            sc._dump_raw_issues(output_dir / 'log')
            # Use public helper if available (prevents AttributeError when implementation changes)
            try:
                if hasattr(sc, 'filter_issues') and callable(getattr(sc, 'filter_issues')):
                    sc.issues = sc.filter_issues() or sc.issues
                elif hasattr(sc, '_filter_issues') and callable(getattr(sc, '_filter_issues')):
                    sc.issues = sc._filter_issues() or sc.issues
            except Exception:
                pass
            sc._dedupe_issues()
            safe_issues = sc.issues
            vulnerability_summary['Unsafe Consumption'] = len(safe_issues)
            save_html_report(safe_issues, 'UnsafeConsumption', args.url, output_dir)
            if db is not None:
                db.store_issues('UnsafeConsumption', safe_issues, base_url=args.url)
            styled_print(f'API10 complete - {len(safe_issues)} issues', 'done')
    
    #========================= AI MODULE  =======================
         
    if 11 in selected_apis:
        styled_print('API11 - AI-assisted OWASP analysis', 'info')
        logger.info('Running API11 - AI-assisted audit')
        if not (live_probe and analyze_endpoints_with_llm and save_ai_summary):
            styled_print('AI client not available (ai_client / ai_client_v3 not found)', 'fail')
            logger.error('AI client import error - ai_client / ai_client_v3 missing')
        else:
            provider = os.getenv('LLM_PROVIDER', '').strip().lower()
            required = ['LLM_PROVIDER', 'LLM_MODEL']
            if provider != 'ollama':
                required.append('LLM_API_KEY')

            missing = [v for v in required if not os.getenv(v)]
            if missing:
                styled_print(f"Missing required LLM settings for API11: {', '.join(missing)}", 'fail')
                print('\nExample configuration:\n')
                if provider == 'ollama':
                    print('  $env:LLM_PROVIDER="ollama"')
                    print('  $env:LLM_MODEL="mistral"\n')
                else:
                    print('  $env:LLM_PROVIDER="openai_compat"')
                    print('  $env:LLM_MODEL="gpt-4o-mini"')
                    print('  $env:LLM_API_KEY="sk-..."\n')
                sys.exit(3)

            try:
                probe_result = live_probe()
                if not probe_result.get('ok', False):
                    styled_print(f"LLM connection failed: {probe_result.get('error', 'Unknown error')}", 'fail')
                    logger.error(f'LLM connection failed: {probe_result}')
                else:
                    provider_name = (
                        probe_result.get('provider')
                        or probe_result.get('info', {}).get('provider')
                        or 'Unknown'
                    )
                    styled_print(f"Connected to LLM provider: {provider_name}", 'ok')
                    styled_print('Starting AI security analysis...', 'info')
                    ai_results = analyze_endpoints_with_llm(
                        ai_endpoints,
                        live_base_url=args.url,
                        print_results=True,
                        enable_live_scan=True,
                        safe_mode=True,
                        compare_auth=True,
                    )
                    save_ai_summary(ai_results, output_dir / 'AI-api11_scanresults.json')
                    if db is not None:
                        try:
                            ai_issues = []
                            for result in ai_results:
                                if isinstance(result, dict):
                                    if result.get('skipped'):
                                        continue
                                    
                                    analysis = result.get('analysis')
                                    if not analysis:
                                        continue
                                    issue = {
                                        'method': result.get('method', 'GET'),
                                        'endpoint': result.get('path', ''),
                                        'url': args.url + result.get('path', '') if args.url else result.get('path', ''),
                                        'title': f"{result.get('method', 'GET')} {result.get('path', '')}",
                                        'description': analysis.get('explanation', ''),
                                        'category': 'AI-OWASP',
                                        'severity': analysis.get('risk', 'Informal'),
                                        'status': 'confirmed',
                                        'status_code': 200,
                                        'request_headers': {},
                                        'response_headers': {},
                                        'response_body': json.dumps(analysis, ensure_ascii=False) if analysis else '',
                                        'analysis_details': analysis
                                    }
                                    ai_issues.append(issue)
                            
                            if ai_issues:
                                db.store_issues('AI-OWASP', ai_issues, base_url=args.url)
                                styled_print(f'AI results stored in database ({len(ai_issues)} findings)', 'ok')
                                vulnerability_summary['AI-OWASP'] = len(ai_issues)
                            else:
                                styled_print('No AI findings to store in database', 'info')
                                vulnerability_summary['AI-OWASP'] = 0
                                
                        except Exception as e:
                            styled_print(f'Failed to store AI results in database: {e}', 'warn')
                            logger.error(f'Database store error: {e}')
                            vulnerability_summary['AI-OWASP'] = 0
                    else:
                        styled_print('No database available for AI results', 'warn')
                        vulnerability_summary['AI-OWASP'] = len([r for r in ai_results if not r.get('skipped') and r.get('analysis')])

                    styled_print(f'API11 complete - {len(ai_results)} endpoints analyzed', 'done')

            except Exception as e:
                styled_print(f'AI analysis failed: {e}', 'fail')
                logger.exception('AI analysis exception')
                vulnerability_summary['AI-OWASP'] = 0   

    print('\n' + '=' * 50)
    print('SCAN finished'.center(50))
    print('=' * 50)

    from build_review import build_review
    review_out = output_dir / 'review.html'
    build_review(db_path=args.db_path, out_path=review_out, run_id=run_id)
    print(f'OK: review.html written -> {review_out}')

    if not getattr(args, 'no_open', False):
        try:
            uri = review_out.resolve().as_uri()
        except Exception:
            uri = f'file://{review_out.resolve()}'

        opened = False
        try:
            opened = webbrowser.open(uri, new=2)
        except Exception:
            opened = False

        if not opened:
            try:
                path_str = str(review_out.resolve())
                if sys.platform.startswith('win'):
                    os.startfile(path_str)
                elif sys.platform.startswith('darwin'):
                    subprocess.Popen(['open', path_str])
                else:
                    subprocess.Popen(['xdg-open', path_str])
            except Exception:
                print(f"Could not auto open browser. Open manually: {uri}")

    styled_print('Scan complete. All results and logs have been saved.', 'ok')
    html_files = sorted((str(f) for f in output_dir.glob('api_*_report.html')))
    if not html_files:
        styled_print('No HTML reports to combine, skipping.', 'info')
    else:
        styled_print('Combining HTML reports', 'info')
        try:
            generate_combined_html(output=str(output_dir / 'combined_report.html'), files=html_files)
            styled_print('Combined HTML report saved.', 'ok')
        except Exception as exc:
            styled_print(f'Combined HTML report failed: {exc}', 'fail')
    
     
if __name__ == '__main__':
    main()
