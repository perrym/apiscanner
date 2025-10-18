########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the MIT License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.0 18-10-2025                                                     #
########################################################                                                        
 
"""APISCAN is a private and proprietary API security tool, developed independently for internal use and research purposes.
It supports OWASP API Security Top 10 (2023) testing, OpenAPI-based analysis, active scanning, and multi-format reporting.
Redistribution is not permitted without explicit permission.
Important: Testing with APISCAN is only permitted on systems and APIs for which you have explicit authorization.
Unauthorized testing is strictly prohibited.
"""
from __future__ import annotations

import argparse
import builtins
import json
import logging
import queue
import sys
import os
import time
import csv as _csv
import re as _re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
OUT_DIR: Path | None = None

from typing import Any
from urllib.parse import urljoin
import requests
import urllib3
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
from version import __version__
from auth_utils import configure_authentication
from report_utils import HTMLReportGenerator, RISK_INFO
from doc_generator import generate_combined_html
from swagger_utils import enable_dummy_mode, extract_variables, write_variables_file
import re as _re_ver

                                 
from openapi_universal import (
    iter_operations as oas_iter_ops,
    build_request as oas_build_request,
    SecurityConfig as OASSecurityConfig,
    load_spec as oas_load_spec,
)


try:
    import colorama
                                                                            
    colorama.just_fix_windows_console()
    colorama.init(autoreset=True, strip=False, convert=True)
except Exception:
    pass


MISSING_RE = _re.compile(r"(missing|require[sd])\\s+['\\\"]?([A-Za-z0-9_]+)['\\\"]?", _re.I)
def _guess_fill_for_key(k):
    kl = (k or "").lower()
    if kl.endswith("id") or kl in ("id","user_id","order_id","vehicle_id","post_id"):
        v = _pool_pick(kl, None)
        return v if v is not None else 1
    if kl in ("email","user_email","username"):
        return _pool_pick(kl, None) or "a@a.de"
    if kl in ("token","otp","code","pin","coupon"):
        return _pool_pick(kl, None) or "123456"
    if "qr" in kl:
        return _pool_pick("qr", None) or _pool_pick("code", None) or "123456"
    if any(s in kl for s in ("reason","message","comment","text","title","name")):
        return "test"
    return "text"
def _augment_body_missing_field_from_error(body, rtext):
    if not isinstance(body, dict):
        return body
    added = False
    txt = rtext or ""
    for m in MISSING_RE.finditer(txt):
        fld = m.group(2)
        if fld and fld not in body:
            body[fld] = _guess_fill_for_key(fld)
            added = True
    return body

def _normalize_version_in_url(u: str) -> str:
    try:
        def repl(m):
            major = m.group(1)
            minor = m.group(2) or "0"
            minor_norm = str(int(minor))
            return f"/v{major}.{minor_norm}/"
        return _re_ver.sub(r"/v(\\d+)\\.(\\d+)/", repl, u)
    except Exception:
        return u
DUMMY_MODE = False

manual_file_map = {
    "BOLA": "bola",
    "BrokenAuth": "broken_auth",
    "Property": "property",
    "Resource": "resource",
    "AdminAccess": "admin_access",
    "BusinessFlows": "business_flows",
    "SSRF": "ssrf",
    "Misconfig": "misconfig",
    "Inventory": "inventory",
    "UnsafeConsumption": "unsafe_consumption",
}

logger = logging.getLogger("apiscan")
MAX_THREADS = 20

# ----------------------- Funtion _sec_from_args ----------------------------#
def _sec_from_args(args) -> OASSecurityConfig:
    api_key_val = getattr(args, 'apikey', None)
    api_key_name = getattr(args, 'apikey_header', 'X-API-Key')
    return OASSecurityConfig(
        api_key_header_name=api_key_name,
        api_key_value=api_key_val,
        api_key_query_name=None,
        bearer_token=getattr(args, 'token', None),
    )


def _endpoints_from_universal(spec: dict) -> list[dict]:
    eps = []
    try:
        for op in oas_iter_ops(spec):
            eps.append({"path": op["path"], "method": op["method"], "operationId": op.get("operation",{}).get("operationId") or f"{op['method']}_{op['path'].strip('/').replace('/','_')}", "tags": op.get("operation",{}).get("tags", [])})
    except Exception:
        pass
    return eps


# ----------------------- Funtion extract_endpoints_from_paths ----------------------------#
def extract_endpoints_from_paths(spec):
    endpoints = []
    paths = (spec or {}).get("paths", {})
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.upper() in ("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"):
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "operationId": op.get("operationId") or f"{method}_{path.strip('/').replace('/','_')}",
                    "tags": op.get("tags", []),
                    "raw": op
                })
    return endpoints

# ----------------------- Funtion styled_print ----------------------------#
def styled_print(message: str, status: str = "info") -> None:
    symbols = {"info": "Info:", "ok": "OK:", "warn": "WARNING:", "fail": "FAIL:", "run": "->", "done": "Done"}
    colors = {
        "info": "\x1b[94m",
        "ok": "\x1b[92m",
        "warn": "\x1b[93m",
        "fail": "\x1b[91m",
        "run": "\x1b[96m",
        "done": "\x1b[92m",
    }
    reset = "\x1b[0m"
    print(f"{colors.get(status, '')}{symbols.get(status, '')} {message}{reset}")

# ----------------------- Funtion normalize_url ----------------------------#
def normalize_url(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "http://" + url

# ----------------------- Funtion create_output_directory ----------------------------#
def create_output_directory(base_url: str) -> Path:
    clean = base_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%d-%m-%Y_%H%M%S")
    out_dir = Path(f"audit_{clean}_{timestamp}")
    out_dir.mkdir(exist_ok=True)
    return out_dir

# ----------------------- Funtion save_html_report ----------------------------#
def save_html_report(issues, risk_key: str, url: str, output_dir: Path) -> None:
    html_report = HTMLReportGenerator(issues=issues, scanner=RISK_INFO[risk_key]["title"], base_url=url)
    filename = f"api_{manual_file_map[risk_key]}_report.html"
    html_report.save(output_dir / filename)

# ----------------------- Funtion check_api_reachable ----------------------------#
def _canonical_path_min(p: str) -> str:
    import re as _re
    p = "/" + (p or "").lstrip("/")
    return _re.sub(r"\{[^}]+\}", "{}", p)

def _json_shape_min(text: str) -> str:
    if not text:
        return ""
    try:
        import json as _json
        data = _json.loads(text)
    except Exception:
        import re as _re
        return _re.sub(r"\s+", " ", text).strip()[:4096]
    def _n(v):
        if isinstance(v, dict):
            return {k: _n(val) for k,val in sorted(v.items(), key=lambda x: x[0]) if k not in {"timestamp","time","date","requestId","request_id"}}
        if isinstance(v, list):
            return [_n(v[0])] if v else []
        if isinstance(v, str):
            return "S"
        if isinstance(v, (int,float)):
            return "N"
        if isinstance(v, bool):
            return "B"
        if v is None:
            return "null"
        return "X"
    try:
        shaped = _n(data)
        import json as _json
        return _json.dumps(shaped, separators=(",", ":"), ensure_ascii=False)[:8192]
    except Exception:
        import re as _re
        return _re.sub(r"\s+", " ", text).strip()[:4096]

def _is_sensitive_body_min(body: str) -> bool:
    if not body:
        return False
    import re as _re
    if _re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", body, flags=_re.I):
        return True
    if _re.search(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", body):
        return True
    if _re.search(r'"(access_)?token"\s*:\s*"', body, flags=_re.I):
        return True
    return False

def _filter_auth_issues_min(issues):
    if not issues:
        return []
    out = []
    for it in issues:
        try:
            code = int(it.get("status_code", 0) or 0)
        except Exception:
            continue
        if code in {0, 400, 404, 405}:
            continue
        if 500 <= code < 600:
            continue
        body = it.get("response_body") or ""
        path = str(it.get("endpoint") or "")
        if code == 200 and not (_is_sensitive_body_min(body) or ".env" in path or "/.env" in path):
            generic = False
            try:
                import json as _json
                data = _json.loads(body)
                if isinstance(data, dict):
                    keys = set(map(lambda k: str(k).lower(), data.keys()))
                    if keys and keys.issubset({"message","status","detail","error"}):
                        generic = all(not isinstance(v, (dict, list)) for v in data.values())
            except Exception:
                txt = (body or "").strip().lower()
                if len(txt) <= 64 and txt in {"ok","success","done","created","updated","deleted"}:
                    generic = True
            if generic:
                continue
        try:
            from hashlib import sha1 as _sha1
            method = it.get("method","")
            canon = _canonical_path_min(path)
            shape = _json_shape_min(body)
            fp = f"{method}|{canon}|{code}|{_sha1(shape.encode('utf-8','ignore')).hexdigest()}"
        except Exception:
            fp = None
        it["fingerprint"] = fp
        out.append(it)
    dedup = {}
    for it in out:
        fp = it.get("fingerprint")
        if not fp:
            continue
        if fp in dedup:
            d = dedup[fp]
            d["duplicate_count"] = d.get("duplicate_count", 1) + 1
            v = d.setdefault("variants", [])
            desc = it.get("description","")
            if desc and desc not in v:
                v.append(desc)
        else:
            it.setdefault("duplicate_count", 1)
            it.setdefault("variants", [it.get("description","")])
            dedup[fp] = it
    return list(dedup.values())

def check_api_reachable(url: str, session: requests.Session, retries: int = 3, delay: int = 3) -> None:
    for attempt in range(1, retries + 1):
        try:
            print("APISCAN by Perry Mertens pamsniffer@gmail.com(2025)")
            print(f"Checking connection to {url} (attempt {attempt}/{retries})...")
            resp = session.get(url, timeout=5, verify=getattr(session, 'verify', True))
            print(f"Response status code: {resp.status_code}")
            if not resp.content:
                print("Empty response body detected.")
            code = resp.status_code
            if 200 <= code < 400 or code in (401, 403, 404, 405):
                print(f"Connection successful to {url} (status: {code})")
                return
            print(f"Unexpected response from server: {code}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Attempt {attempt} failed: {e}")
        if attempt < retries:
            print(f"Retrying in {delay} seconds...")
            time.sleep(delay)
        else:
            print(f"ERROR: Cannot connect to {url} after {retries} attempts.")
            sys.exit(1)

                                                             
import re as _re_sub

_ID_MAP = {}

# ----------------------- Funtion load_id_map ----------------------------#
def load_id_map(path: str | None):
    global _ID_MAP
    _ID_MAP = {}
    if not path:
        return
    try:
        import json as _json
        from pathlib import Path as _Path
        _ID_MAP = _json.loads(_Path(path).read_text(encoding="utf-8"))
        styled_print(f"Loaded IDs map with {len(_ID_MAP)} entries", "info")
    except Exception as e:
        styled_print(f"Could not read ids-file: {e}", "warn")
        _ID_MAP = {}

def _id_lookup(name: str) -> str | None:
    if not name:
        return None
    key = name.strip()
    return str(_ID_MAP.get(key)) if key in _ID_MAP else None

import re
from typing import Optional, List
from urllib.parse import urlsplit, urlunsplit

def _apply_rewrites(full_url, rewrites):
    if not rewrites:
        return full_url
    original = full_url
    for rule in rewrites:
        if "=>" not in rule:
            continue
        pat, rep = [x.strip() for x in rule.split("=>", 1)]
        try:
            new_url = re.sub(pat, rep, full_url)
            if new_url != full_url:
                print(f"[rewrite] {pat!r} => {rep!r} :: {full_url} -> {new_url}")
            full_url = new_url
        except re.error as e:
            print(f"[rewrite] invalid regex {pat!r}: {e}")
    return full_url

def _normalize_path_generic(path: str) -> str:

    import re
    if not isinstance(path, str) or not path:
        return "/"
    path = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*", "", path)
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)
    path = path.strip()
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path

                                                                               
# ----------------------- Funtion _sanitize_url ----------------------------#
def _sanitize_url(url: str, rewrites: list[str] | None = None) -> str:
    if not isinstance(url, str) or not url:
        return url
    parts = urlsplit(url)
    path  = _normalize_path_generic(parts.path or "/")
    out   = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    out = _apply_rewrites(out, rewrites)
    return out

# ----------------------- Funtion _sanitize_url2 ----------------------------#
def _sanitize_url2(url: str, rewrites: list[str] | None = None, disable: bool = False) -> str:
    if not isinstance(url, str) or not url:
        return url
    if disable:
        return _apply_rewrites(url, rewrites)
    parts = urlsplit(url)
    path  = _normalize_path_generic(parts.path or "/")
    out   = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    out   = _apply_rewrites(out, rewrites)
    return out

                                                                  
def _merge_header_overrides(args) -> dict:
    overrides = {}
    def put(name, value):
        if not name or value is None:
            return
        overrides[str(name).lower()] = (str(name), str(value))

    if str(getattr(args, "flow", "")).lower() == "token":
        tok = getattr(args, "token", None)
        if tok:
            put("Authorization", f"Bearer {tok}")

    if getattr(args, "apikey", None) and getattr(args, "apikey_header", None):
        put(getattr(args, "apikey_header"), getattr(args, "apikey"))

                                                
    for raw in (getattr(args, "extra_header", None) or []):
        if not raw or ":" not in raw:
            continue
        name, val = raw.split(":", 1)
        put(name.strip(), val.strip())

    hf = getattr(args, "headers_file", None)
    if hf:
        try:
            with open(hf, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k,v in data.items():
                    put(k, v)
        except Exception:
            pass

    return overrides

                                                 
# ----------------------- Funtion _parse_success_codes ----------------------------#
def _parse_success_codes(spec_str: str):
    parts = [p.strip() for p in (spec_str or "").split(",") if p.strip()]
    ranges = []
    singles = set()
    for p in parts:
        if "-" in p:
            a,b = p.split("-",1)
            try:
                a = int(a); b = int(b)
                if a <= b:
                    ranges.append((a,b))
            except Exception:
                pass
        else:
            try:
                singles.add(int(p))
            except Exception:
                pass
    def ok(code: int) -> bool:
        if code in singles: return True
        for a,b in ranges:
            if a <= code <= b: return True
        return False
    return ok


# ----------------------- Funtion verify_plan ----------------------------#
def verify_plan(args, session, spec: dict, base_url: str, csv_path: str = None, rewrites=None, disable_sanitize: bool = False):
                                                                                     
    if csv_path is None:
        try:
            csv_path = str(OUT_DIR / "apiscan-verify.csv")
        except Exception:
            csv_path = "apiscan-verify.csv"
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
            method = req["method"]; url = req["url"]
            t0 = time.time()
            try:
                r = session.request(**req, timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                status = r.status_code
            except Exception:
                status = 0
            ms = int((time.time()-t0)*1000)
            ok = ok_code(status)
            total += 1; oks += 1 if ok else 0; fails += 1 if not ok else 0
            print(f"[VERIFY] {method} {url} -> {status} ({ms} ms){' OK' if ok else ' FAIL'}")
            results.append([method, url, status, ms, 'OK' if ok else 'FAIL'])
        used_universal = True
    except Exception:
        used_universal = False

    if not used_universal:
                                      
        paths = (spec or {}).get('paths', {}) or {}
        for pth, item in paths.items():
            if not isinstance(item, dict):
                continue
            for m in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'):
                op = item.get(m.lower())
                if not isinstance(op, dict):
                    continue
                url = (base_url.rstrip('/') + '/' + pth.lstrip('/'))
                try:
                    url = _plan_fill_path_params(url)
                except Exception:
                    pass
                url = _sanitize_url2(url, rewrites, disable=disable_sanitize)
                if getattr(args, "normalize_version", False):
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
                    if m in ('POST','PUT','PATCH'):
                        if isinstance(ct, str) and 'multipart/form-data' in ct.lower() and isinstance(body, dict):
                            files, data = {}, {}
                            for k, v in body.items():
                                if isinstance(v, (bytes, bytearray)):
                                    files[k] = ('apiscan.bin', v)
                                else:
                                    data[k] = v
                            headers.pop('Content-Type', None)
                            r = session.request(m, url, headers=headers, files=files, data=data,
                                                timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                        elif as_json and isinstance(body, (dict, list)):
                            r = session.request(m, url, headers=headers, json=body,
                                                timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                        elif body is not None:
                            r = session.request(m, url, headers=headers, data=body,
                                                timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                        else:
                            r = session.request(m, url, headers=headers,
                                                timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                    else:
                        r = session.request(m, url, headers=headers,
                                            timeout=getattr(args,'timeout',10), verify=not getattr(args,'insecure',False))
                    status = r.status_code
                except Exception:
                    status = 0

                ms = int((time.time()-t0)*1000)
                ok = ok_code(status)
                total += 1; oks += 1 if ok else 0; fails += 1 if not ok else 0
                print(f"[VERIFY] {m} {url} -> {status} ({ms} ms){' OK' if ok else ' FAIL'}")
                results.append([m, url, status, ms, 'OK' if ok else 'FAIL'])

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f); w.writerow(['method','url','status','ms','result']); w.writerows(results)
        print(f"[VERIFY] written: {csv_path}  OK={oks} FAIL={fails} TOTAL={total}")
    except Exception as e:
        print(f"[VERIFY] CSV write failed: {e}")
    return oks, fails, total


                                                                                               
import json as _json

# ----------------------- Funtion _plan_sample_for ----------------------------#
def _plan_sample_for(name: str) -> str:
    v = _id_lookup(name)
    if v is not None:
        return v
    n = (name or '').lower()
    if 'uuid' in n or 'guid' in n:
        return '00000000-0000-4000-8000-000000000000'
    if n.endswith('id') or 'id' in n or any(k in n for k in ['number','no','seq','version']):
        return '1'
    if 'code' in n:
        return 'C123'
    if 'email' in n:
        return 'user@example.com'
    if 'date' in n:
        return '2025-01-01'
    return 'sample'

# ----------------------- Funtion _plan_fill_path_params ----------------------------#
def _plan_fill_path_params(url: str) -> str:
    import re as _re
    return _re.sub(r'{([^}]+)}', lambda m: _plan_sample_for(m.group(1)), url)

# ----------------------- Funtion _plan_build_example_from_schema ----------------------------#
def _plan_build_example_from_schema(schema: dict):
    if not isinstance(schema, dict): return {}
    t = schema.get('type')
    if t == 'object' or 'properties' in schema:
        return {k: _plan_build_example_from_schema(v) for k, v in (schema.get('properties') or {}).items()}
    if t == 'array': return [_plan_build_example_from_schema(schema.get('items', {}) or {})]
    if t == 'integer': return 1
    if t == 'number':  return 1
    if t == 'boolean': return False
    if t == 'string':  return 'string'
    return {}

# ----------------------- Funtion _plan_body_from_requestbody ----------------------------#
def _plan_body_from_requestbody(op: dict):
    rb = (op or {}).get('requestBody') or {}
    content = rb.get('content') or {}
    mt = 'application/json' if 'application/json' in content else (next(iter(content.keys()), None))

    if not mt:
        if 'required' in rb and rb.get('required', False) and DUMMY_MODE:
            return 'application/json', {}, True
        return None, None, False

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

    if ex is None and isinstance(block.get('schema'), dict) and 'multipart/form-data' in (mt or '').lower():
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
            ex = ""

    as_json = ('json' in (mt or '').lower()) and isinstance(ex, (dict, list))
    return mt, ex, as_json


# ----------------------- Funtion plan_requests ----------------------------#
def plan_requests(spec, base_url, csv_path=None, rewrites=None, disable_sanitize: bool = False, normalize_version: bool = False):
                                                                                       
    if csv_path is None:
        try:
            csv_path = str(OUT_DIR / "apiscan-plan.csv")
        except Exception:
            csv_path = "apiscan-plan.csv"
    if rewrites is None:
        rewrites = []

    rows = []
    count = 0
    used_universal = False

    try:
        sec = _sec_from_args(builtins.args) if hasattr(builtins, "args") else _sec_from_args(argparse.Namespace())
        for op in oas_iter_ops(spec):
            req = oas_build_request(spec, base_url, op, sec)
            method = req["method"]
            url = req["url"]
            body = req.get("json")
            ctype = req["headers"].get("Content-Type", "")
            if isinstance(body, (dict, list)):
                blen = len(json.dumps(body))
                mode = "json"
            else:
                blen = len(body or "") if body is not None else 0
                mode = "raw"
            print(f"[PLAN] {method} {url} ct={ctype or ''} len={blen} json={mode=='json'}")
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
            for m in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'):
                op = item.get(m.lower())
                if not isinstance(op, dict):
                    continue
                url = (base_url.rstrip('/') + '/' + pth.lstrip('/'))
                url = _plan_fill_path_params(url)
                url = _sanitize_url2(url, rewrites, disable=disable_sanitize)
                if normalize_version:
                    url = _normalize_version_in_url(url)
                ct, body, as_json = (None, None, False)
                if m in ('POST','PUT','PATCH'):
                    try:
                        ct, body, as_json = _plan_body_from_requestbody(op)
                    except Exception:
                        ct, body, as_json = (None, None, False)
                    if ct and 'json' in str(ct).lower():
                        ct = 'application/json; charset=UTF-8'
                blen = (len(json.dumps(body)) if isinstance(body,(dict,list)) else len(body or '')) if body is not None else 0
                print(f'[PLAN] {m} {url} ct={ct} len={blen} json={as_json}')
                rows.append([m, url, ct or '', blen, 'json' if as_json else 'raw'])
                count += 1

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f); w.writerow(['method','url','content_type','body_len','mode']); w.writerows(rows)
        print(f'[PLAN] written: {csv_path} ({count} requests)')
    except Exception as e:
        print(f'[PLAN] CSV write failed: {e}')
    return count


# ----------------------- Funtion main ----------------------------#
def main() -> None:
    parser = argparse.ArgumentParser(description=f"APISCAN {__version__} - API Security Scanner")

    parser.add_argument("--retry500", type=int, default=1, help="adaptive retries on HTTP 5xx for POST/PUT/PATCH")
    parser.add_argument("--no-retry-500", dest="retry500", action="store_const", const=0, help="disable adaptive 5xx retries")
    parser.add_argument("--url", required=True, help="Base URL of the API to scan")
    parser.add_argument('--plan-only', action='store_true', help='Build all requests and write apiscan-plan.csv, do not send')
    parser.add_argument('--plan-then-scan', action='store_true', help='First build full plan (CSV), then perform the scan')
    parser.add_argument('--verify-plan', action='store_true', help='After planning, actually send each planned request and expect success')
    parser.add_argument('--success-codes', default='200-299', help='Comma list of codes or ranges, e.g., 200-299,302')
    parser.add_argument("--swagger", required=True, help="Path to Swagger/OpenAPI JSON file")
    parser.add_argument("--flow",
        choices=["none","token","client","basic","ntlm","auth"],
        default="none",
        help="Authentication flow: none, token (Bearer), client (OAuth2 Client Credentials), "
            "basic (Basic Auth), ntlm (Windows NTLM), auth (OAuth2 Authorization Code)"
    )
    parser.add_argument("--token", help="Bearer token value (used with --flow token)")
    parser.add_argument("--basic-auth", help="Basic auth in the form user:password (used with --flow basic)")
    parser.add_argument("--apikey", help="API key value (sent in header specified by --apikey-header)")
    parser.add_argument("--apikey-header", default="X-API-Key",help="Header name for API key (default: X-API-Key)")
    parser.add_argument("--ntlm", help="NTLM credentials in the form DOMAIN\\user:password (used with --flow ntlm)")
    parser.add_argument("--client-cert", help="Path to client certificate file (PEM, used for mTLS)")
    parser.add_argument("--client-key", help="Path to private key file (PEM, used for mTLS)")
    parser.add_argument("--cert-password", help="Password for client certificate private key (if encrypted)")
    parser.add_argument("--insecure", action="store_true",help="Disable TLS certificate validation (DANGEROUS, use only for testing)")
    parser.add_argument("--client-id", help="OAuth2 Client ID (for --flow client or auth)")
    parser.add_argument("--client-secret", help="OAuth2 Client Secret (for --flow client or auth)")
    parser.add_argument("--token-url", help="OAuth2 Token endpoint URL (for --flow client or auth)")
    parser.add_argument("--auth-url", help="OAuth2 Authorization endpoint URL (for --flow auth)")
    parser.add_argument("--redirect-uri", help="Redirect URI for OAuth2 Authorization Code flow")
    parser.add_argument("--scope", help="OAuth2 scope(s), space-separated")
    parser.add_argument("--threads", type=int, default=2, help="Number of concurrent threads to use")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug output (verbose logging)")
    parser.add_argument("--api11", action="store_true", help="Run AI-assisted OWASP Top 10 analysis")
    parser.add_argument("--dummy", action="store_true", help="Use dummy data for request bodies and parameters")
    parser.add_argument("--export_vars", metavar="PATH", help="Export variables template YAML if .yml/.yaml else JSON")
    parser.add_argument("--proxy", help="Optional proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--ids-file", help="JSON file mapping path parameter names to concrete values")
    parser.add_argument("--rewrite", action="append", default=[], help="Regex=>replacement rewrite applied to each URL (can be repeated)")
    parser.add_argument("--no-sanitize", action="store_true", help="Disable built-in URL normalization; only apply explicit --rewrite rules")

                                                                                   

                                                                                   
    group_nv = parser.add_mutually_exclusive_group()
    group_nv.add_argument(
        "--normalize-version",
        dest="normalize_version",
        action="store_true",
        help="Normalize version segments in URLs like /v2.00/ -> /v2.0/ during planning and verify."
    )
    group_nv.add_argument(
        "--no-normalize-version",
        dest="normalize_version",
        action="store_false",
        help="Disable version normalization in URLs (default)."
    )
    parser.set_defaults(normalize_version=False)
    for i in range(1, 11):
        parser.add_argument(
f"--api{i}", action="store_true", help=f"Run only API{i} audit")

    args = parser.parse_args()
    if args.url and "://" not in args.url:
        args.url = "http://" + args.url
    if getattr(args, "dummy", False):
        try:
            enable_dummy_mode(True)
            globals()['DUMMY_MODE'] = True
            if getattr(args, "debug", False):
                print("[DEBUG] Dummy mode enabled in swagger_utils")
        except Exception:
            pass

    load_id_map(getattr(args, 'ids_file', None))

    builtins.debug_mode = args.debug
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="[DEBUG] %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="[INFO] %(message)s")

    selected_apis = [11] if args.api11 else [i for i in range(1, 11) if getattr(args, f"api{i}")] or list(range(1, 11))

    args.url = normalize_url(args.url)
    output_dir = create_output_directory(args.url)

    global OUT_DIR
    OUT_DIR = output_dir
    log_dir = output_dir / "log"
    log_dir.mkdir(exist_ok=True)
    logfile = log_dir / f"apiscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

    logger = logging.getLogger("apiscan")
    logger.propagate = False

    sess = configure_authentication(args)
    try:
        sess.verify = not args.insecure
    except Exception:
        pass
    if getattr(args, 'proxy', None):
        pr = args.proxy if "://" in args.proxy else f"http://{args.proxy}"
        sess.proxies.update({
            "http": pr,
            "https": pr
        })
        banner = f"PROXY MODE ENABLED -> {pr}"
        logger.info(banner)
        try:
            print(Fore.MAGENTA + banner + Style.RESET_ALL)
        except Exception:
            print(banner)

    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=3)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    check_api_reachable(args.url, sess)

    try:
        swagger_path = Path(args.swagger).resolve()
        if not swagger_path.exists():
            raise FileNotFoundError(f"Swagger file not found: {swagger_path}")
        if not swagger_path.is_file():
            raise ValueError(f"Path is not a file: {swagger_path}")
        if swagger_path.stat().st_size == 0:
            raise ValueError("Swagger file is empty")

        logger.info(f"Loading Swagger from: {swagger_path}")
        styled_print(f"Loading validated Swagger file: {swagger_path}", "info")

        spec = oas_load_spec(str(swagger_path), inject_base_url=args.url)

        bola = BOLAAuditor(session=sess, base_url=args.url, swagger_spec=spec)

        endpoints = bola.get_object_endpoints(spec) or []
        uni_eps = _endpoints_from_universal(spec)
        if uni_eps:
            key = lambda d: (d.get('method','').upper(), d.get('path',''))
            seen = {key(e) for e in endpoints}
            endpoints.extend([e for e in uni_eps if key(e) not in seen])
        if not endpoints:
            print("[debug] No endpoints found by discovery; falling back to raw paths")
            endpoints = extract_endpoints_from_paths(spec)

        ai_endpoints = [
            {"path": ep["path"], "method": ep["method"]}
            for ep in endpoints if ep.get("path") and ep.get("method")
        ]

        logger.debug(f"Swagger loaded - {len(endpoints)} endpoints")
        styled_print(f"Swagger loaded - {len(endpoints)} endpoints found", "ok")

    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Swagger processing failed: {e}")
        styled_print(str(e), "fail")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during Swagger parsing: {e}")
        styled_print("Unexpected error during Swagger parsing", "fail")
        sys.exit(1)
                                                                                   
    base = args.url
    if getattr(args, 'plan_only', False) or getattr(args, 'plan_then_scan', False):
        plan_requests(spec, base, csv_path=None, rewrites=getattr(args, 'rewrite', []), disable_sanitize=getattr(args, 'no_sanitize', False))
        if getattr(args, 'plan_only', False):
            styled_print('Plan-only mode: done.', 'ok')
            return
                                                                                                   
    if getattr(args, 'verify_plan', False):
        oks, fails, total = verify_plan(args, sess, spec, base, csv_path=None, rewrites=getattr(args, 'rewrite', []), disable_sanitize=getattr(args, 'no_sanitize', False))
        if fails > 0 and not getattr(args, 'plan_then_scan', False):
            styled_print(f'Verify found {fails} failures out of {total}', 'warn')
        elif fails == 0:
            styled_print('Verify passed: all planned requests succeeded', 'ok')

    if args.export_vars:
        try:
            vars_doc = extract_variables(spec)
            out_file = write_variables_file(vars_doc, args.export_vars)
            styled_print(f"Variables template written to {out_file}", "ok")
            sys.exit(0)
        except Exception as e:
            styled_print(f"FAIL exporting variables: {e}", "fail")
            sys.exit(1)

# --------------------- API1: BOLA ----------
    if 1 in selected_apis:
        tqdm.write(f"{Fore.CYAN}[API1] Starting BOLA (threads={args.threads}){Style.RESET_ALL}")
        logger.info("Running API1 - BOLA")

        if args.url and "://" not in args.url:
            args.url = "http://" + args.url

        bola = BOLAAuditor(session=sess, base_url=args.url, swagger_spec=spec)

        endpoints = bola.get_object_endpoints(spec) or []

        bola_results = []

        max_workers = max(1, min(args.threads, MAX_THREADS))
        if max_workers == 1:
            for ep in tqdm(endpoints, desc="BOLA endpoints", unit="endpoint"):
                try:
                    res = bola.test_endpoint(args.url, ep)
                    if res:
                        bola_results.extend(res)
                except Exception as e:
                    tqdm.write(f"{Fore.RED}[API1][ERR] {ep.get('method')} {ep.get('path')}: {e}{Style.RESET_ALL}")
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(bola.test_endpoint, args.url, ep): ep for ep in endpoints}
                for fut in tqdm(as_completed(futures), total=len(futures), desc="BOLA endpoints", unit="endpoint"):
                    ep = futures[fut]
                    try:
                        res = fut.result()
                        if res:
                            bola_results.extend(res)
                    except Exception as e:
                        tqdm.write(f"{Fore.RED}[API1][ERR] {ep.get('method')} {ep.get('path')}: {e}{Style.RESET_ALL}")

        bola.issues = [r.to_dict() for r in bola_results if getattr(r, "status_code", 0) != 0]
        try:
            bola.generate_report()
        except Exception as e:
            tqdm.write(f"{Fore.RED}[API1][ERR] report generation failed: {e}{Style.RESET_ALL}")

        found = sum(1 for r in bola_results if getattr(r, "is_vulnerable", False))
        msg = (
            f"{Fore.GREEN}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}" if found == 0 else
            f"{Fore.YELLOW}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}" if found < 5 else
            f"{Fore.RED}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}"
        )
        save_html_report(bola.issues, "BOLA", args.url, output_dir)
        styled_print(msg, "done")

# --------------------- API2: Broken Authentication ----------
    if 2 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API2 - Broken Authentication{Style.RESET_ALL}")
        logger.info("Running API2 - Broken Authentication")
        norm_eps = []
        for ep in endpoints:
            try:
                path = ep["path"]
                method = ep["method"].upper()
                norm_eps.append({"path": path, "method": method})
            except KeyError:
                continue
        aa = AuthAuditor(session=sess, base_url=args.url, swagger_spec=spec, show_progress=True)
        auth_issues = aa.test_authentication_mechanisms(norm_eps)
        auth_issues = _filter_auth_issues_min(auth_issues)
        for issue in auth_issues:
            desc = issue.get("description", "Unknown")
            ep   = issue.get("endpoint", issue.get("url", ""))
            sev  = issue.get("severity", "Info")
            tqdm.write(f"-> Auth issue [{sev}]: {desc} @ {ep}")
        save_html_report(auth_issues, "BrokenAuth", args.url, output_dir)
        styled_print(f"API2 complete - {len(auth_issues)} issues", "done")

# --------------------- API3: Property-level Authorization (Object Property) ----------
    if 3 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API3 - Property-level Authorization{Style.RESET_ALL}")
        logger.info("Running API3 - Property-level Authorization")
        pa = ObjectPropertyAuditor(args.url, sess, show_progress=True)
        prop_issues = pa.test_object_properties(endpoints)
        for issue in prop_issues:
            tqdm.write(
                f"-> Property issue: {issue.get('description','Unknown')} @ {issue.get('endpoint','Unknown')}"
            )
        save_html_report(prop_issues, "Property", args.url, output_dir)
        styled_print(f"API3 complete - {len(prop_issues)} issues", "done")

# --------------------- API4: Resource Consumption ----------
    if 4 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API4 - Resource Consumption{Style.RESET_ALL}")
        logger.info("Running API4 - Resource Consumption")
        rc = ResourceAuditor(session=sess, base_url=args.url, swagger_spec=spec, show_progress=True)
        res_issues = rc.test_resource_consumption()
        save_html_report(res_issues, "Resource", args.url, output_dir)
        styled_print(f"API4 complete - {len(res_issues)} issues", "done")

# --------------------- API5: Function-level Authorization ----------
    if 5 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API5 - Function-level Authorization{Style.RESET_ALL}")
        logger.info("Running API5 - Function-level Authorization")

        za = AuthorizationAuditor(session=sess, base_url=args.url, spec=spec, flow=getattr(args, "flow", "none"), logger=logger)
        authz_issues = za.test_authorization(show_progress=True)

        for issue in authz_issues:
            tqdm.write(f"-> Authorization issue: {issue.get('description','Unknown')} @ {issue.get('endpoint','Unknown')}")
        save_html_report(authz_issues, "AdminAccess", args.url, output_dir)
        styled_print(f"API5 complete - {len(authz_issues)} issues", "done")

# --------------------- API6: Sensitive Business Flows ----------
    if 6 in selected_apis:
        print(" API6 - Sensitive Business Flows")
        logger.info("Running API6 - Sensitive Business Flows")
        bf = BusinessFlowAuditor(session=sess, base_url=args.url, swagger_spec=spec, flow=getattr(args, "flow", "none"))
        business_eps = [{"name": (ep.get("operationId") or f"{ep['method']} {ep['path']}").replace(" ", "_"), "url": urljoin(args.url.rstrip("/") + "/", ep["path"].lstrip("/")), "method": ep["method"], "body": {}} for ep in endpoints if ep["method"] in {"POST", "PUT", "PATCH"}]
        biz_issues = bf.test_business_flows(business_eps)
        save_html_report(biz_issues, "BusinessFlows", args.url, output_dir)
        styled_print(f"API6 complete - {len(biz_issues)} issues", "done")

# --------------------- API7: SSRF ----------
    if 7 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API7 - SSRF{Style.RESET_ALL}")
        logger.info("Running API7 - SSRF")

        ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger, default_base=args.url)
        if ss_eps:
            ss = SSRFAuditor(session=sess, base_url=args.url, swagger_spec=spec)
            ssrf_issues = ss.test_endpoints(ss_eps)
            save_html_report(ssrf_issues, 'SSRF', args.url, output_dir)
            styled_print(f"API7 complete - {len(ssrf_issues)} issues", "done")
        else:
            styled_print("No SSRF endpoints found", "warn")

# --------------------- API8: Security Misconfiguration ----------
    if 8 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API8 - Security Misconfiguration{Style.RESET_ALL}")
        logger.info("Running API8 - Security Misconfiguration")
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            mc = MisconfigurationAuditor(args.url, sess, show_progress=True, debug=args.debug)
            misconf_issues = mc.test_endpoints(misconf_eps)
            save_html_report(misconf_issues, 'Misconfig', args.url, output_dir)
            styled_print(f"API8 complete - {len(misconf_issues)} issues", "done")
        else:
            styled_print("No misconfiguration endpoints found", "warn")
# --------------------- API9: Improper Inventory Management ----------
    if 9 in selected_apis:
        print(" API9 - Improper Inventory Management")
        logger.info("Running API9 - Improper Inventory Management")

        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger) or []
        if not inv_eps and spec:
            inv_eps = InventoryAuditor.endpoints_from_universal(spec) or []

        inv = InventoryAuditor(session=sess, base_url=args.url, swagger_spec=spec)
        inv_issues = inv.test_inventory(inv_eps if inv_eps else None)

        save_html_report(inv_issues, "Inventory", args.url, output_dir)
        styled_print(f"API9 complete - {len(inv_issues)} issues", "done")


# --------------------- API10: Safe Consumption of 3rd-Party APIs ----------
    if 10 in selected_apis:
        print(" API10 - Safe Consumption of 3rd-Party APIs")
        logger.info("Running API10 - Safe Consumption")
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        for ep in safe_eps:
            print(f"-> Safe API consumption check {ep}")
        sc = SafeConsumptionAuditor(base_url=args.url, session=sess)
        safe_issues = sc.test_endpoints(safe_eps)
        sc._dump_raw_issues(output_dir / "log")
        sc._filter_issues()
        sc._dedupe_issues()
        save_html_report(safe_issues, "UnsafeConsumption", args.url, output_dir)
        styled_print(f"API10 complete - {len(safe_issues)} issues", "done")

                                                              
    if 11 in selected_apis:
        styled_print("API11 - AI-assisted OWASP analysis", "info")
        logger.info("Running API11 - AI-assisted audit")

                                                                                  
        required = ["LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY"]
        missing = [v for v in required if not os.getenv(v)]
        if missing:
            styled_print(
                f"Missing required LLM settings for API11: {', '.join(missing)}",
                "fail"
            )
            print(
                "\\nSet them, for example:\\n"
                "  export LLM_PROVIDER=openai_compat\\n"
                "  export LLM_MODEL=gpt-4o-mini\\n"
                "  export LLM_API_KEY=sk-...\\n"
            )
            sys.exit(3)

        try:
            from ai_client import live_probe
            probe_result = live_probe()

            if not probe_result.get("ok", False):
                styled_print(f"LLM connection failed: {probe_result.get('error', 'Unknown error')}", "fail")
                logger.error(f"LLM connection failed: {probe_result}")
            else:
                styled_print(f"Connected to LLM provider: {probe_result.get('provider', 'Unknown')}", "ok")

                from ai_client import analyze_endpoints_with_llm, save_ai_summary
                ai_results = analyze_endpoints_with_llm(ai_endpoints, live_base_url=args.url, print_results=True)
                save_ai_summary(ai_results, output_dir / "AI-api11_scanresults.json")
                styled_print(f"API11 complete - {len(ai_results)} endpoints analyzed", "done")
        except ImportError as e:
            styled_print(f"AI client not available: {e}", "fail")
            logger.exception("AI client import error")
        except Exception as e:
            styled_print(f"AI analysis failed: {e}", "fail")
            logger.exception("AI analysis exception")

    vulnerability_summary = {
        "BOLA": sum(1 for result in bola_results if getattr(result, "is_vulnerable", False)) if 'bola_results' in locals() else 0,
        "Authentication": len(auth_issues) if 'auth_issues' in locals() else 0,
        "Property-Level Auth": len(prop_issues) if 'prop_issues' in locals() else 0,
        "Resource Consumption": len(res_issues) if 'res_issues' in locals() else 0,
        "Admin Access": len(authz_issues) if 'authz_issues' in locals() else 0,
        "Business Flows": len(biz_issues) if 'biz_issues' in locals() else 0,
        "SSRF": len(getattr(ss, "_issues", [])) if 'ss' in locals() else 0,
        "Misconfiguration": len(misconf_issues) if 'misconf_issues' in locals() else 0,
        "Inventory": len(inv_issues) if 'inv_issues' in locals() else 0,
        "Unsafe Consumption": len(safe_issues) if 'safe_issues' in locals() else 0,
    }

    total_vulnerabilities = sum(vulnerability_summary.values())

                                                          
    print("\\n" + "="*50)
    print("VULNERABILITY SCAN SUMMARY".center(50))
    print("="*50)

    for category, count in vulnerability_summary.items():
        color = Fore.GREEN if count == 0 else Fore.YELLOW if count < 5 else Fore.RED
        print(f" {category:<22}: {color}{count:>3}{Style.RESET_ALL}")

    print("-"*50)
    total_color = Fore.GREEN if total_vulnerabilities == 0 else Fore.YELLOW if total_vulnerabilities < 10 else Fore.RED
    print(f" {'TOTAL VULNERABILITIES':<22}: {total_color}{total_vulnerabilities:>3}{Style.RESET_ALL}")
    print("="*50)

    styled_print("Scan complete. All results and logs have been saved.", "ok")

    html_files = sorted(str(f) for f in output_dir.glob("api_*_report.html"))
    if not html_files:
        styled_print("No HTML reports to combine, skipping.", "info")
    else:
        styled_print("Combining HTML reports", "info")
        try:
            generate_combined_html(output=str(output_dir / "combined_report.html"), files=html_files)
            styled_print("Combined HTML report saved.", "ok")
        except Exception as exc:
            styled_print(f"Combined HTML report failed: {exc}", "fail")

if __name__ == "__main__":
    main()
