########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.2 1-4-2026                                 #
########################################################

from __future__ import annotations
import argparse
import json
import re
import sqlite3
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

#================funtion _maybe_headers_to_text _maybe_headers_to_text =============
def _maybe_headers_to_text(h: Any) -> str:
    if h is None:
        return ''
    if isinstance(h, dict):
        return '\n'.join((f'{k}: {v}' for k, v in h.items()))
    s = '' if h is None else str(h)
    if not s:
        return ''
    parts = s.splitlines()
    first = parts[0] if parts else ''
    keep_status = first.strip().lower().startswith('http/')
    preserved = first if keep_status else None
    tail = '\n'.join(parts[1:]) if keep_status else s

    def _from_obj(obj: Any) -> str | None:
        if isinstance(obj, dict):
            return '\n'.join((f'{k}: {v}' for k, v in obj.items()))
        if isinstance(obj, (list, tuple)):
            out = []
            for item in obj:
                if isinstance(item, dict) and len(item) == 1:
                    k, v = next(iter(item.items()))
                    out.append(f'{k}: {v}')
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    k, v = item
                    out.append(f'{k}: {v}')
            if out:
                return '\n'.join(out)
        return None
    try:
        obj = json.loads(tail)
        text = _from_obj(obj)
        if text is not None:
            return preserved + '\n' + text if preserved else text
    except Exception:
        pass
    try:
        stripped = tail.lstrip()
        if stripped.startswith('[') or stripped.startswith('{'):
            import ast
            obj = ast.literal_eval(tail)
            text = _from_obj(obj)
            if text is not None:
                return preserved + '\n' + text if preserved else text
    except Exception:
        pass
    out = []
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        if ':' in line:
            k, v = line.split(':', 1)
            out.append(f'{k.strip()}: {v.strip()}')
        else:
            out.append(line)
    norm = '\n'.join(out).strip()
    return preserved + ('\n' + norm if norm else '') if preserved else norm


#================funtion _parse_status_from_headers _parse_status_from_headers =============
def _parse_status_from_headers(h: Any) -> int | None:
    if isinstance(h, dict):
        for k in (':status', 'status', 'Status', 'STATUS'):
            if k in h:
                v = str(h[k]).strip()
                if v.isdigit():
                    return int(v)
        for k in ('status-line', 'Status-Line'):
            v = h.get(k)
            if isinstance(v, str):
                m = re.search('\\b(\\d{3})\\b', v)
                if m:
                    return int(m.group(1))
        return None
    s = str(h) if h is not None else ''
    if not s:
        return None
    m = re.search('http/\\d(?:\\.\\d)?\\s+(\\d{3})', s, flags=re.I)
    if m:
        return int(m.group(1))
    m2 = re.search('\\bstatus\\s*:\\s*(\\d{3})\\b', s, flags=re.I)
    if m2:
        return int(m2.group(1))
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return _parse_status_from_headers(obj)
    except Exception:
        pass
    return None


#================funtion _parse_status_from_body _parse_status_from_body =============
def _parse_status_from_body(b: Any) -> int | None:
    try:
        obj = b if isinstance(b, (dict, list)) else json.loads('' if b is None else str(b))
        if isinstance(obj, dict):
            for k in ('status', 'statusCode', 'code'):
                v = obj.get(k)
                if v is not None and str(v).strip().isdigit():
                    return int(str(v).strip())
    except Exception:
        pass
    s = '' if b is None else str(b)
    if s:
        m = re.search('\\bstatus[^0-9]{0,8}(\\d{3})\\b', s, flags=re.I)
        if m:
            return int(m.group(1))
    return None


#================funtion _extract_status_code _extract_status_code =============
def _extract_status_code(res_headers: Any, res_body: Any) -> int | None:
    st = _parse_status_from_headers(res_headers)
    if st is not None:
        return st
    st = _parse_status_from_body(res_body)
    if st is not None:
        return st
    return None
#================funtion  Safe errors handeling =============

SAFE_IGNORE = {
    400: (
        "Failed to read request",
        "400 Bad Request",
        "<h1>400 Bad Request</h1>",
        "openresty/",
        "unexpected end of JSON input",
        "invalid json",
        "cannot parse json",
    ),
    401: ("Unauthorized", "Missing token", "invalid token"),
    403: ("Forbidden",),
    404: ("Not Found",),
    405: (
        "Method Not Allowed",
        "Method 'GET' is not supported.",
        'Method "POST" not allowed.',
        'Method "GET" not allowed.',
        "not allowed.",
    ),
}

def is_expected_behavior(method: str, status: int | None, body: Any) -> bool:
    if not status:
        return False

    body_text = "" if body is None else str(body)
    body_lower = body_text.lower()

    msgs = SAFE_IGNORE.get(status)
    if msgs:
        for msg in msgs:
            if msg.lower() in body_lower:
                return True

    if status == 405:
        # JSON/body variants
        if "method" in body_lower and "not allowed" in body_lower:
            return True
        # some frameworks return empty body
        if not body_text.strip():
            return True

    return False

#================funtion _map_severity _map_severity =============
def _map_severity(s: str | None) -> str:
    if not s:
        return 'info'
    t = str(s).strip().lower()
    if t in {'critical', 'crit'}:
        return 'critical'
    if t in {'high'}:
        return 'high'
    if t in {'medium', 'med'}:
        return 'medium'
    if t in {'low'}:
        return 'low'
    return 'info'


#================funtion _map_severity_canon _map_severity_canon =============
def _map_severity_canon(s: str | None) -> str:
    return _map_severity(s)


#================funtion _map_status _map_status =============
def _map_status(s: str | None) -> str:
    t = (s or '').strip().lower()
    if t in {'', 'open', 'new'}:
        return 'open'
    if t in {'confirmed', 'valid'}:
        return 'confirmed'
    if t in {'false_positive', 'false-positive', 'fp'}:
        return 'false-positive'
    if t in {'fixed', 'resolved'}:
        return 'fixed'
    return 'open'


#================funtion _db_items_for_template _db_items_for_template =============
def _db_items_for_template(db_path: Path, run_id: str | None = None) -> list[dict]:
    with sqlite3.connect(str(db_path)) as c:
        c.row_factory = sqlite3.Row
        q = (
            "SELECT id, run_id, risk_key, title, description, category, "
            "severity, status, method, endpoint, req_headers, req_body, "
            "res_headers, res_body, res_status, created_at "
            "FROM finding"
        )
        params: tuple = ()
        if run_id:
            q += " WHERE run_id = ?"
            params = (run_id,)
        q += " ORDER BY id ASC"
        rows = c.execute(q, params).fetchall()

    items: list[dict] = []

    for r in rows:
        _res_headers = r["res_headers"]
        _res_body = r["res_body"]

        try:
            if isinstance(_res_headers, str) and _res_headers.strip().startswith(("{", "[")):
                _res_headers = json.loads(_res_headers)
        except Exception:
            pass

        try:
            if isinstance(_res_body, str) and _res_body.strip().startswith(("{", "[")):
                _res_body = json.loads(_res_body)
        except Exception:
            pass

        method = (r["method"] or "GET").upper()
        endpoint = r["endpoint"] or ""
        title = r["title"] or f"{method} {endpoint}"

        status_code: int | None = None
        if r["res_status"] is not None:
            try:
                v = int(r["res_status"])
                status_code = v if v > 0 else None
            except (ValueError, TypeError):
                status_code = None

        if status_code is None:
            try:
                status_code = _extract_status_code(_res_headers, _res_body)
                if isinstance(status_code, int) and status_code <= 0:
                    status_code = None
            except Exception:
                status_code = None

        if status_code is not None and is_expected_behavior(method, status_code, _res_body):
            continue

        items.append(
            {
                "id": r["id"],
                "title": title,
                "description": r["description"] or "",
                "endpoint": endpoint,
                "url": endpoint,
                "method": method,
                "category": r["category"] or (r["risk_key"] or ""),
                "severity": _map_severity_canon(r["severity"]),
                "status": _map_status(r["status"]),
                "date": r["created_at"] or "",
                "request": {
                    "headers": _maybe_headers_to_text(r["req_headers"]),
                    "body": r["req_body"] or "",
                },
                "response": {
                    "status": int(status_code) if isinstance(status_code, int) and status_code > 0 else "",
                    "headers": _maybe_headers_to_text(_res_headers),
                    "body": _res_body
                    if isinstance(_res_body, str)
                    else json.dumps(_res_body, ensure_ascii=False),
                },
                "risk_key": r["risk_key"] or "",
            }
        )

    return items


#================funtion _db_endpoints _db_endpoints =============
def _db_endpoints(db_path: Path, run_id: str | None=None) -> list[dict]:
    with sqlite3.connect(str(db_path)) as c:
        c.row_factory = sqlite3.Row
        q = 'SELECT method, url, max_severity, last_status, last_ms, count_ok, count_fail, first_seen, last_seen FROM endpoint'
        params: tuple = ()
        if run_id:
            q += ' WHERE run_id = ?'
            params = (run_id,)
        q += ' ORDER BY method, url'
        rows = c.execute(q, params).fetchall()
    out = []
    for r in rows:
        out.append({'method': (r['method'] or '').upper(), 'url': r['url'] or '', 'severity': _map_severity(r['max_severity']) if hasattr(globals().get('_map_severity'), '__call__') else r['max_severity'] or '', 'last_status': r['last_status'] or '', 'last_ms': r['last_ms'] or '', 'ok': r['count_ok'] or 0, 'fail': r['count_fail'] or 0, 'first_seen': r['first_seen'] or '', 'last_seen': r['last_seen'] or ''})
    return out


#================funtion _normalize_for_ui _normalize_for_ui =============
def _normalize_for_ui(it: dict) -> dict:
    out = dict(it or {})
    out['method'] = str(out.get('method') or 'GET').upper()
    ep = out.get('endpoint') or out.get('url') or ''
    out['endpoint'] = ep
    out['url'] = ep
    sev = (out.get('severity') or '').strip().lower()
    if sev not in {'critical', 'high', 'medium', 'low', 'info'}:
        sev = _map_severity_canon(sev)
    out['severity'] = sev
    st = (out.get('status') or '').strip().lower().replace('_', '-')
    if st in {'', 'open', 'new', 'todo'}:
        st = 'pending'
    elif st in {'confirmed', 'valid', 'fixed', 'resolved'}:
        st = 'confirmed'
    elif st in {'false-positive', 'falsepositive', 'fp'}:
        st = 'false-positive'
    out['status'] = st
    try:
        rs = int(out.get('response', {}).get('status'))
        out['response']['status'] = rs if rs > 0 else ''
    except Exception:
        try:
            rs = int(out.get('res_status'))
            out.setdefault('response', {})['status'] = rs if rs > 0 else ''
        except Exception:
            out.setdefault('response', {})['status'] = ''

    def _to_text(v):
        if v is None:
            return ''
        if isinstance(v, str):
            return v
        try:
            return json.dumps(v, ensure_ascii=False, indent=None)
        except Exception:
            return str(v)
    out.setdefault('request', {})
    out['request']['headers'] = _to_text(out['request'].get('headers'))
    out['request']['body'] = _to_text(out['request'].get('body'))
    out.setdefault('response', {})
    out['response']['headers'] = _to_text(out['response'].get('headers'))
    out['response']['body'] = _to_text(out['response'].get('body'))
    out['category'] = out.get('category') or out.get('risk_key') or ''
    risk_key = (out.get('risk_key') or out.get('category') or '').strip()
    info = _risk_info_lookup(risk_key)
    if info:
        out['risk_info'] = info

    return out


_MINIMAL_TEMPLATE = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8" />\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <title>API Scan Review by Perry Mertens 2025 pamsniffer@gmail.com</title>\n  <style>\n    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }\n    h1 { margin-bottom: 8px; }\n    .meta { color: #666; margin-bottom: 16px; }\n    .item { border: 1px solid #ddd; border-radius: 8px; padding: 12px 16px; margin: 10px 0; }\n    .pill { display:inline-block; padding:2px 8px; border-radius: 999px; font-size:12px; margin-left: 6px; }\n    .sev-critical { background:#fee; color:#c00; }\n    .sev-high { background:#ffe9e9; color:#b00; }\n    .sev-medium { background:#fff3cd; color:#9a6; }\n    .sev-low { background:#e7f3ff; color:#06c; }\n    .sev-info { background:#eef2f7; color:#345; }\n    .signal-pill { display:inline-block; padding:1px 6px; border-radius: 4px; font-size:10px; margin-left: 4px; background:#e0e0e0; color:#333; }\n    pre { background:#f6f8fa; padding:10px; border-radius:6px; overflow:auto; }\n    .cols { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }\n    .k { color:#666; }\n  </style>\n</head>\n<body>\n  <h1>API Scan Review</h1>\n  <div class="meta">Generated: <span id="ts"></span> — Items: <span id="cnt"></span></div>\n  <div id="list"></div>\n  <script id="data" type="application/json"></script>\n  <script>\n    const items = window.__APISCAN_ITEMS__ || JSON.parse(document.getElementById("data").textContent || "[]");\n    document.getElementById("ts").textContent = new Date().toISOString().slice(0,19).replace("T"," ");\n    document.getElementById("cnt").textContent = items.length;\n    const m = {"critical":"sev-critical","high":"sev-high","medium":"sev-medium","low":"sev-low","info":"sev-info"};\n    const list = document.getElementById("list");\n    for (const it of items) {\n      const div = document.createElement("div");\n      div.className = "item";\n      const sev = (it.severity||"info").toLowerCase();\n      const signals = it.signals || [];\n      const signalPills = signals.map(s => `<span class="signal-pill">${s}</span>`).join("");\n      div.innerHTML = `\n        <div><strong>${it.title || ""}</strong>\n          <span class="pill ${m[sev]||"sev-info"}">${sev}</span>\n          <span class="pill">${it.method || ""}</span>\n          <span class="pill">${it.response?.status || ""}</span>\n          ${signalPills}\n        </div>\n        <div class="k">${it.category || ""} — ${it.date || ""}</div>\n        <div class="cols">\n          <div>\n            <h4>Request</h4>\n            <pre>${(it.request?.headers||"")}</pre>\n            <pre>${(it.request?.body||"")}</pre>\n          </div>\n          <div>\n            <h4>Response</h4>\n            <pre>${(it.response?.headers||"")}</pre>\n            <pre>${(it.response?.body||"")}</pre>\n          </div>\n        </div>\n      `;\n      list.appendChild(div);\n    }\n  </script>\n</body>\n</html>'


#================funtion _load_template _load_template =============
def _load_template(template: Path | None) -> str:
    cand: list[Path] = []
    if template is not None:
        if isinstance(template, str):
            template = Path(template)
        cand.append(template)
    here = Path(__file__).resolve().parent
    cand += [here / 'html' / 'template_scan_en.html', Path.cwd() / 'html' / 'template_scan_en.html', Path('html') / 'template_scan_en.html']
    for p in cand:
        if isinstance(p, Path) and p.exists():
            return p.read_text(encoding='utf-8', errors='ignore')
    return _MINIMAL_TEMPLATE


#================funtion _inject_json_into_template _inject_json_into_template =============
def _inject_json_into_template(template_str: str, items: list[dict]) -> str:
    payload = json.dumps(items, ensure_ascii=False).replace('</', '<\\/')
    if '<script id="data"' in template_str:
        return re.sub('(<script id="data"[^>]*>)([\\s\\S]*?)(</script>)', lambda m: m.group(1) + payload + m.group(3), template_str, count=1)
    return template_str.replace('</body>', f'<script>window.__APISCAN_ITEMS__ = {payload};</script></body>')


#================funtion _inject_two_payloads _inject_two_payloads =============
def _inject_two_payloads(template_str: str, items: list[dict], endpoints: list[dict]) -> str:
    s = _inject_json_into_template(template_str, items)
    payload_eps = json.dumps(endpoints, ensure_ascii=False).replace('</', '<\\/')
    ep_script = '<script>window.__APISCAN_ENDPOINTS__ = ' + payload_eps + ";</script>\n<script>(function(){\n  try {\n    var eps = window.__APISCAN_ENDPOINTS__ || [];\n    if (!eps.length) return;\n    var anchor = document.getElementById('inventory-root') || document.body;\n    var container = document.createElement('div');\n    container.className = 'inventory-block';\n    var h2 = document.createElement('h2');\n    h2.textContent = 'Inventory (all scanned endpoints)';\n    container.appendChild(h2);\n    var wrapper = document.createElement('div');\n    wrapper.className = 'inventory-scroll';\n    var table = document.createElement('table');\n    var thead = document.createElement('thead');\n    var thr = document.createElement('tr');\n    var headers = ['Method','URL','Max Sev','Last Status','Last ms','OK','FAIL'];\n    headers.forEach(function(h){\n      var th = document.createElement('th');\n      th.textContent = h;\n      thr.appendChild(th);\n    });\n    thead.appendChild(thr); table.appendChild(thead);\n    var tbody = document.createElement('tbody');\n    function addCell(tr, txt){\n      var td = document.createElement('td');\n      td.textContent = (txt == null ? '' : String(txt));\n      tr.appendChild(td);\n    }\n    for (var i = 0; i < eps.length; i++){\n      var e = eps[i] || {};\n      var tr = document.createElement('tr');\n      addCell(tr, e.method || '');\n      addCell(tr, e.url || '');\n      addCell(tr, e.severity || '');\n      addCell(tr, e.last_status == null ? '' : e.last_status);\n      addCell(tr, e.last_ms == null ? '' : e.last_ms);\n      addCell(tr, e.ok == null ? 0 : e.ok);\n      addCell(tr, e.fail == null ? 0 : e.fail);\n      tbody.appendChild(tr);\n    }\n    table.appendChild(tbody);\n    wrapper.appendChild(table);\n    container.appendChild(wrapper);\n    anchor.appendChild(container);\n  } catch (e) {\n    if (window.console && console.warn) console.warn('Inventory render error:', e);\n  }\n})();</script>\n"
    if '</body>' in s:
        return s.replace('</body>', ep_script + '</body>')
    return s + ep_script
RISK_INFO = {'BOLA': {'title': 'API1:2023 - Broken Object Level Authorization', 'description': 'APIs often expose object identifiers such as user IDs or document IDs within request paths or parameters. If proper authorization checks are not implemented, attackers can modify these identifiers to access data that does not belong to them. This leads to unauthorized access or data leakage. The risk is especially high in RESTful APIs where object references are part of the URL structure.', 'recommendation': '- Implement object-level authorization checks on every request\n- Use unpredictable IDs (UUID) instead of sequential integers\n- Verify the requester has ownership/access rights for each object\n- Centralize authorization logic\n- Log and alert on failed authorization attempts'}, 'BrokenAuth': {'title': 'API2:2023 - Broken Authentication', 'description': 'Authentication mechanisms that are poorly designed or misconfigured allow attackers to compromise tokens, bypass login flows, or hijack user sessions. This includes flaws in token generation, session expiration, credential storage, or password reset logic. The impact can range from unauthorized access to full account takeover.', 'recommendation': '- Use MFA for sensitive actions\n- Work with short-lived, cryptographically signed tokens\n- Secure password/token recovery flows\n- Temporarily lock accounts after too many failed attempts\n- Never expose credentials in URLs or error messages'}, 'Property': {'title': 'API3:2023 - Broken Object Property Level Authorization', 'description': "APIs that expose internal object properties without proper access control allow clients to view or manipulate data they shouldn't have access to. This includes over-sharing in API responses and accepting unexpected or sensitive fields in client submissions, known as mass assignment vulnerabilities. Attackers can exploit this to alter read-only or admin-level fields.", 'recommendation': '- Explicitly define which fields are visible/editable per role\n- Validate request and response payloads with schemas\n- Filter sensitive fields server-side before sending\n- Use different DTOs for different access levels\n- Strictly separate public and private properties'}, 'Resource': {'title': 'API4:2023 - Unrestricted Resource Consumption', 'description': 'Lack of proper resource management allows attackers to overload the system with excessive requests, large payloads, or expensive operations. This can lead to denial of service (DoS), service degradation, or increased operational costs. APIs that allow unlimited requests, nested queries, or unbounded filters are particularly vulnerable.', 'recommendation': '- Implement rate limiting and quotas\n- Set maximum payload sizes\n- Use pagination or partial responses\n- Monitor abnormal consumption\n- Cache expensive operations where possible'}, 'AdminAccess': {'title': 'API5:2023 - Broken Function Level Authorization', 'description': 'APIs may expose administrative or privileged operations without enforcing strict access control. Attackers can escalate privileges by calling hidden or undocumented functions. These issues often stem from complex role hierarchies, inconsistent policy enforcement, or a lack of centralized authorization checks.', 'recommendation': '- Use RBAC or ABAC with deny-by-default\n- Centralize authorization logic\n- Thoroughly test ALL admin functions\n- Require step-up authentication for critical actions\n- Document and encrypt sensitive admin flows'}, 'BusinessFlows': {'title': 'API6:2023 - Unrestricted Access to Sensitive Business Flows', 'description': 'APIs that expose key business processes such as financial transactions, bookings, or account changes are attractive targets for abuse. If such flows lack business logic validation or abuse protection (e.g. rate limiting, anomaly detection), they may be exploited through automation, leading to financial loss or fraud.', 'recommendation': '- Add business context validations (e.g. balance, limits)\n- Use CAPTCHA/rate limiting against bots\n- Detect and block abnormal patterns\n- Require step-up authentication for risky actions\n- Monitor critical flows in real-time'}, 'SSRF': {'title': 'API7:2023 - Server Side Request Forgery', 'description': 'If an API accepts URLs or user-defined targets and then performs server-side requests, attackers may exploit this functionality to access internal services, scan the network, or retrieve sensitive metadata. SSRF can also be used as a pivot point in multi-stage attacks against internal infrastructure or cloud metadata endpoints.', 'recommendation': "- Validate & sanitize all provided URLs\n- Use an allow-list of permitted domains\n- Don't follow redirects or limit the number of hops\n- Segment internal networks; block outgoing requests where possible\n- Apply egress firewall rules"}, 'Misconfig': {'title': 'API8:2023 - Security Misconfiguration', 'description': 'Misconfigured HTTP headers, CORS policies, verbose error messages, and leftover debug endpoints are common in APIs and can be exploited to gain insight into backend systems or bypass protections. Misconfigurations may also lead to data exposure, unauthorized access, or weakened transport security.', 'recommendation': '- Harden systems according to security baselines\n- Disable unnecessary HTTP methods\n- Remove debug/test endpoints in production\n- Set strict CORS policies\n- Regularly review & patch configurations'}, 'Inventory': {'title': 'API9:2023 - Improper Inventory Management', 'description': "Organizations often lose track of API versions, staging/test environments, and undocumented endpoints. These shadow or zombie APIs may be exposed to the internet and remain unprotected. Without proper inventory, you can't assess security posture, enforce updates, or manage deprecations effectively.", 'recommendation': '- Maintain an up-to-date inventory of all endpoints\n- Carefully deprecate & remove old versions\n- Document each endpoint with purpose & owner\n- Implement clear versioning strategy\n- Proactively scan for undocumented APIs'}, 'UnsafeConsumption': {'title': 'API10:2023 - Unsafe Consumption of APIs', 'description': 'Trusting third-party or upstream APIs without proper validation introduces significant risks. These include injection attacks, unexpected responses, and business logic flaws. If these dependencies are not handled defensively, they can cause data corruption, denial of service, or unauthorized access to internal systems.', 'recommendation': '- Validate & sanitize all data from third-party APIs\n- Set time limits & retries\n- Fail safely: handle external errors gracefully\n- Keep third-party credentials secret & rotate regularly\n- Continuously monitor external service behavior'}, 'Authentication': {'title': 'Authentication & Transport Security', 'description': 'This finding indicates weaknesses in authentication- or transport-related controls, such as HTTP endpoints reachable without HTTPS redirection or exposure of sensitive files supporting authentication (e.g. .env with secrets). These issues can lead to credential theft, session hijacking or manipulation of traffic in transit.', 'recommendation': '- Enforce HTTPS for all API endpoints; redirect HTTP to HTTPS\n- Use HSTS (HTTP Strict Transport Security) for public domains\n- Never expose .env or other config files over HTTP\n- Store secrets only in secure vaults, not in web root\n- Regularly test authentication and TLS configuration with automated scanners'}}
_RISK_INFO_ALIASES = {
    # OWASP 2023 labels → interne keys
    "API1:2023 - Broken Object Level Authorization": "BOLA",
    "API2:2023 - Broken Authentication": "BrokenAuth",
    "API3:2023 - Broken Object Property Level Authorization": "Property",
    "API4:2023 - Unrestricted Resource Consumption": "Resource",
    "API5:2023 - Broken Function Level Authorization": "AdminAccess",
    "API6:2023 - Unrestricted Access to Sensitive Business Flows": "BusinessFlows",
    "API7:2023 - Server Side Request Forgery": "SSRF",
    "API8:2023 - Security Misconfiguration": "Misconfig",
    "API9:2023 - Improper Inventory Management": "Inventory",
    "API10:2023 - Unsafe Consumption of APIs": "UnsafeConsumption",

    # Short/human variants → interne keys
    "Unsafe Consumption of APIs": "UnsafeConsumption",
    "UnsafeConsumption": "UnsafeConsumption",
    "API10": "UnsafeConsumption",
}


def _risk_info_lookup(key: str):
    k = (key or "").strip()
    k = _RISK_INFO_ALIASES.get(k, k)
    return RISK_INFO.get(k)

_HTTP0_ALLOWED_KINDS = {'secure_transport', 'tls', 'hsts', 'cipher', 'hostname', 'dns', 'timeout'}
_PII_IBAN_NL = re.compile('\\bNL[0-9]{2}[A-Z]{4}[0-9]{10}\\b', re.I)
_PII_IBAN_GENERIC = re.compile('\\b[A-Z]{2}[0-9]{2}[\\sA-Z0-9]{10,30}\\b', re.I)
_PII_EMAIL = re.compile('\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b')


#================funtion _is_valid_bsn _is_valid_bsn =============
def _is_valid_bsn(bsn_str: str) -> bool:
    if not bsn_str.isdigit() or len(bsn_str) not in (8, 9):
        return False
    if len(bsn_str) == 8:
        bsn_str = '0' + bsn_str
    if len(bsn_str) != 9:
        return False
    try:
        digits = [int(d) for d in bsn_str]
        total = 9 * digits[0] + 8 * digits[1] + 7 * digits[2] + 6 * digits[3] + 5 * digits[4] + 4 * digits[5] + 3 * digits[6] + 2 * digits[7] - digits[8]
        return total % 11 == 0
    except Exception:
        return False
_PII_BSN = re.compile('\\b(?:BSN\\D*)?(\\d{8,9})\\b', re.I)


#================funtion _luhn_check _luhn_check =============
def _luhn_check(card_number: str) -> bool:

    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10 == 0
_PII_CREDITCARD = re.compile('\\b(?:\\d[ -]*?){13,19}\\b')
_SECRET_JWT = re.compile('\\beyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*\\b')
_SECRET_API_KEY = re.compile('\\b(?:api[_-]?key|access[_-]?token|bearer)\\s*[:=]\\s*[\\\'\\"]?([A-Za-z0-9_\\-\\.]{10,50})[\\\'\\"]?', re.I)
_SECRET_AWS_KEY = re.compile('\\bAKIA[0-9A-Z]{16}\\b')


#================funtion _has_duplicate_params _has_duplicate_params =============
def _has_duplicate_params(url: str) -> bool:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        return any((len(values) > 1 for values in query_params.values()))
    except Exception:
        return False
_VERBOSE_ERROR_RE = re.compile('(stack\\s*trace|traceback|errorDTO|exception\\s+details|at\\s+[A-Za-z0-9_.]+\\(|java\\.|python\\.|node\\.)', re.I)


#================funtion _status_int _status_int =============
def _status_int(it: dict) -> int | None:
    s = it.get('response', {}).get('status')
    try:
        return int(s) if s not in (None, '', '0') else None
    except Exception:
        return None


#================funtion _txt_body _txt_body =============
def _txt_body(it: dict) -> str:
    b = it.get('response', {}).get('body', '')
    return b if isinstance(b, str) else ''


#================funtion _txt_hdrs _txt_hdrs =============
def _txt_hdrs(it: dict) -> str:
    h = it.get('response', {}).get('headers', '')
    return h if isinstance(h, str) else ''


#================funtion _detect_risk_signals _detect_risk_signals =============
def _detect_risk_signals(item: dict) -> list[str]:
    signals: list[str] = []

    category = (item.get("category") or "").lower()
    risk_key = (item.get("risk_key") or "").lower()

    if any(kind in category or kind in risk_key for kind in _HTTP0_ALLOWED_KINDS):
        signals.append("transport")
    response_body = _txt_body(item)
    response_headers = _txt_hdrs(item)
    request_headers = item.get("request", {}).get("headers", "") or ""
    request_body = item.get("request", {}).get("body", "") or ""
    endpoint = item.get("endpoint", "") or ""
    all_text = " ".join([str(response_body), str(response_headers), str(request_headers), str(request_body), str(endpoint)])
    all_lower = all_text.lower()
    if _PII_IBAN_NL.search(all_text):
        signals.append("IBAN")
    if _PII_IBAN_GENERIC.search(all_text):
        signals.append("IBAN-generic")

    bsn_matches = _PII_BSN.findall(all_text)
    for bsn in bsn_matches:
        if _is_valid_bsn(bsn):
            signals.append("BSN")
            break
    if _PII_EMAIL.search(all_text):
        signals.append("email")
    cleaned = all_text.replace(" ", "").replace("-", "")
    cc_matches = _PII_CREDITCARD.findall(cleaned)
    for cc in cc_matches:
        if _luhn_check(cc):
            signals.append("creditcard")
            break
    if _SECRET_JWT.search(all_text):
        signals.append("JWT")
    if _SECRET_API_KEY.search(all_text):
        signals.append("API-key")
    if _SECRET_AWS_KEY.search(all_text):
        signals.append("AWS-key")

    if _has_duplicate_params(endpoint):
        signals.append("dup-params")

    if _VERBOSE_ERROR_RE.search(all_text):
        signals.append("verbose-error")
    hdr_lower = response_headers.lower()
    if "access-control-allow-origin: *" in hdr_lower:
        signals.append("cors-wildcard")
    if "access-control-allow-headers" in hdr_lower and "authorization" in hdr_lower:
        signals.append("cors-authorization")
    if (
        "crapi-identity:" in all_lower
        or re.search(r"\b[a-z0-9-]+\.(svc|cluster\.local)\b", all_lower)
        or re.search(r"\b[a-z0-9-]+:\d{2,5}\b", all_lower)  
    ):
        
        if any(x in all_lower for x in ("svc", "cluster.local", "crapi-", "identity", "internal")):
            signals.append("internal-host-leak")

    status = _status_int(item)
    if status in (400, 414, 431):
        if "server: openresty" in all_lower or "server: nginx" in all_lower:
            signals.append("proxy-reject")
        if "<h1>400 bad request</h1>" in all_lower or "400 bad request" in all_lower:
            signals.append("proxy-reject")
    if status == 405:
        if "allow:" in hdr_lower:
            signals.append("method-enforced")
        if "not allowed" in all_lower and "method" in all_lower:
            signals.append("method-enforced")
    if status and status >= 500:
        user_input_indicators = ("input", "parameter", "query", "body", "form", "json", "payload")
        request_text = (request_headers + " " + request_body).lower()
        if any(ind in request_text for ind in user_input_indicators):
            signals.append("5xx-input")

    return signals

#================funtion _has_http0_allowlist_kind _has_http0_allowlist_kind =============
def _has_http0_allowlist_kind(item: dict) -> bool:
    category = (item.get('category') or '').lower()
    risk_key = (item.get('risk_key') or '').lower()
    return any((kind in category or kind in risk_key for kind in _HTTP0_ALLOWED_KINDS))
_BASELINE = {'BOLA': 'high', 'Insecure Direct Object Reference': 'high', 'Insecure Direct Object Reference (IDOR)': 'high', 'Broken Object Level Authorization': 'high', 'AdminAccess': 'high', 'Property': 'medium', 'Inventory': 'info', 'SQL Injection': 'critical', 'SQLi': 'critical', 'Command Injection': 'critical', 'Template Injection': 'high', 'SSRF': 'high', 'Resource': 'info', 'Resource Consumption': 'info', 'Misconfig': 'medium', 'Security Misconfiguration': 'medium', 'XSS': 'medium', 'CSRF': 'medium', 'Secure Transport': 'medium', 'TLS': 'medium', 'HSTS': 'medium', 'DNS': 'info', 'Timeout': 'info'}
_DB_ERR_RE = re.compile('(sql|postgres|mysql|sqlite|oracle).*(error|syntax|exception|trace)', re.I | re.S)
_STACK_RE = re.compile('(stack trace|Traceback|^\\s*at\\s+[A-Za-z0-9_.]+\\()', re.I | re.M)
_BOLA_RE = re.compile('\\b(BOLA|IDOR|Direct Object)\\b', re.I)
_SQLI_RE = re.compile('\\b(SQL.?Injection|SQLi)\\b', re.I)


#================funtion _canon_cat _canon_cat =============
def _canon_cat(rk_or_cat: str) -> str:
    rk = (rk_or_cat or '').strip()
    if not rk:
        return ''
    if 'BOLA' in rk or 'Direct Object' in rk:
        return 'BOLA'
    if 'SQL' in rk and 'Inject' in rk:
        return 'SQL Injection'
    if 'Resource' in rk:
        return 'Resource'
    if 'Misconfig' in rk:
        return 'Misconfig'
    if 'Inventory' in rk:
        return 'Inventory'
    if 'SSRF' in rk:
        return 'SSRF'
    if any((tc in rk.lower() for tc in _HTTP0_ALLOWED_KINDS)):
        if any((t in rk.lower() for t in ['secure_transport', 'tls', 'hsts'])):
            return 'Secure Transport'
        return rk.title()
    return rk


#================funtion _reclassify _reclassify =============
def _reclassify(it: dict) -> str:
    cat = _canon_cat(it.get('risk_key') or it.get('category') or '')

    raw_sev = (it.get('severity') or 'info').strip().lower()
    base_sev = _BASELINE.get(cat, 'info')

    _rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    def _max_sev(a: str, b: str) -> str:
        return a if _rank.get(a, 0) >= _rank.get(b, 0) else b

    if raw_sev not in _rank:
        sev = base_sev
    else:
        relax_min = cat in ('Misconfig', 'Inventory', 'Resource', 'Secure Transport', 'DNS', 'Timeout')
        sev = raw_sev if relax_min else _max_sev(raw_sev, base_sev)

    st = _status_int(it)
    bod = _txt_body(it)
    title = (it.get('title') or '') + ' ' + (it.get('category') or '')
    signals = it.get('signals', [])

    if any((kind in cat.lower() for kind in ['secure_transport', 'tls', 'hsts', 'cipher'])):
        if sev in ('info', 'low'):
            sev = 'medium'

    pii_indicators = {'IBAN', 'IBAN-generic', 'BSN', 'email', 'creditcard', 'JWT', 'API-key', 'AWS-key'}
    if any((signal in signals for signal in pii_indicators)):
        if sev in ('info', 'low'):
            sev = 'medium'
        if 'BSN' in signals and sev == 'medium':
            sev = 'high'

    if 'dup-params' in signals and sev == 'low':
        sev = 'medium'

    if st and st >= 500:
        if _STACK_RE.search(bod) or _DB_ERR_RE.search(bod) or 'verbose-error' in signals or ('5xx-input' in signals):
            if sev in ('info', 'low', 'medium'):
                sev = 'high'

    if 'verbose-error' in signals and sev in ('info', 'low'):
        sev = 'medium'

    if st and 400 <= st < 500:
        if not (_SQLI_RE.search(title) or _BOLA_RE.search(title) or _DB_ERR_RE.search(bod) or signals):
            if sev not in ('high', 'critical'):
                sev = 'info'

    return sev

_FP_4XX = {400, 401, 403, 404, 405, 409, 410, 415, 422, 429}
_FP_TITLE_RE = re.compile('(missing|invalid|not found|forbidden|bad request|method not allowed|unauthorized|required field)', re.I)
_FP_BODY_RE = re.compile('(validation failed|failed to convert|type mismatch|cannot (parse|deserialize)|invalid (json|value)|unsupported media type|no permission|token required|bad request)', re.I)


#================funtion _is_false_positive _is_false_positive =============
def _is_false_positive(item: dict) -> bool:
    if item.get('signals') or _has_http0_allowlist_kind(item):
        return False
    try:
        st = int(item.get('response', {}).get('status') or 0)
    except Exception:
        st = 0
    title = f"{item.get('title') or ''} {item.get('description') or ''}".strip()
    body = (item.get('response', {}) or {}).get('body') or ''
    cat = (item.get('category') or item.get('risk_key') or '').lower()
    if st in _FP_4XX and 'bola' not in cat:
        if _FP_TITLE_RE.search(title) or _FP_BODY_RE.search(body):
            return True
    if 'sql' in title.lower() or 'injection' in title.lower():
        if 'possible' in title.lower():
            low = body.lower()
            if not any((x in low for x in ('syntax error', 'sql', 'traceback', 'exception'))):
                if 200 <= st < 300:
                    return True
    if cat in ('xss', 'ssrf', 'csrf') and (st in _FP_4XX or not str(body).strip()):
        return True
    tlow = title.lower()
    if tlow.startswith('no issues') or 'no vulnerability' in tlow:
        return True
    return False


def _postprocess_review_html_for_info(html: str) -> str:
    if not html:
        return html

    html = html.replace('const order = ["critical", "high", "medium", "low"];',
                        'const order = ["critical", "high", "medium", "low", "info"];')

    html = html.replace('low: "LOW"',
                        'low: "LOW",\n        info: "INFO"')

    html = html.replace('const bySev = { critical: 0, high: 0, medium: 0, low: 0 };',
                        'const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };')

    html = html.replace(' | Low " + bySev.low;',
                        ' | Low " + bySev.low +\n        " | Info " + bySev.info;')

    if '.sev-pill[data-sev="info"]' not in html:
        css_rule = '.sev-pill[data-sev="info"] { background: #f3f4f6; border-color: #d1d5db; color: #374151; }\n'
        low_rule = '.sev-pill[data-sev="low"] {'
        pos = html.find(low_rule)
        if pos != -1:
            end = html.find('}', pos)
            if end != -1:
                html = html[:end+1] + '\n' + css_rule + html[end+1:]
        else:
            pos2 = html.find('.sev-pill[data-sev="medium"]')
            if pos2 != -1:
                end2 = html.find('}', pos2)
                if end2 != -1:
                    html = html[:end2+1] + '\n' + css_rule + html[end2+1:]
                else:
                    html = css_rule + html
            else:
                html = css_rule + html

    return html


#================funtion build_review build_review =============
def build_review(db_path: Path, out_path: Path, template: Path | None=None, run_id: str | None=None) -> Path:
    from datetime import datetime
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    items = _db_items_for_template(db_path, run_id=run_id)
    endpoints = _db_endpoints(db_path, run_id=run_id)

    def _is_unknown_status(val):
        return val in (None, '', 0, '0')
    filtered_items = []
    for it in items:
        status_unknown = _is_unknown_status(it.get('response', {}).get('status'))
        category = (it.get('category') or '').lower()
        if 'ai-owasp' in category or 'ai' in category:
            filtered_items.append(it)
            continue
        signals = _detect_risk_signals(it)
        it['signals'] = signals
        try:
            st = int(it.get('response', {}).get('status') or 0)
        except Exception:
            st = 0
        if st == 404 and not signals:
            continue
        if not status_unknown or _has_http0_allowlist_kind(it) or signals:
            filtered_items.append(it)
    items = filtered_items
    ALLOWED_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
    items = [it for it in items if it.get('severity') in ALLOWED_SEVERITIES]
    for it in items:
        it['severity'] = _reclassify(it)
    items = [_normalize_for_ui(it) for it in items if not _is_false_positive(it)]
    RISK_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
    items = [it for it in items if it.get('severity') in RISK_SEVERITIES]
    if not items:
        items = [{'id': 0, 'title': 'No findings', 'description': '...', 'endpoint': '/', 'url': '/', 'method': 'GET', 'category': 'Info', 'severity': 'info', 'status': 'confirmed', 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'request': {'headers': '', 'body': ''}, 'response': {'status': '', 'headers': '', 'body': ''}, 'risk_key': '', 'signals': []}]
    tpl = _load_template(template)
    html_out = _inject_two_payloads(tpl, items, endpoints)
    html_out = _postprocess_review_html_for_info(html_out)
    out_path.write_text(html_out, encoding='utf-8')
    try:
        combined_path = out_path.parent / 'combined_report.html'
        if combined_path.resolve() != out_path.resolve():
            combined_path.write_text(html_out, encoding='utf-8')
    except Exception:
        pass
    print(f'[build_review] Wrote: {out_path} (items: {len(items)})')
    return out_path


#================funtion _cli _cli =============
def _cli() -> int:
    p = argparse.ArgumentParser(description='Generate review.html from scan.db')
    p.add_argument('--db', required=True, help='Path to scan.db')
    p.add_argument('--out', required=False, default='review.html', help='Output HTML path')
    p.add_argument('--template', required=False, default=None, help='Path to template_scan_en.html')
    p.add_argument('--run-id', required=False, default=None, help='Filter by run_id')
    p.add_argument('--open', action='store_true', help='Open in default browser')
    a = p.parse_args()
    db_path = Path(a.db)
    out_path = Path(a.out)
    template = Path(a.template) if a.template else None
    out = build_review(db_path=db_path, out_path=out_path, template=template, run_id=a.run_id)
    if a.open:
        try:
            webbrowser.open_new_tab(out.as_uri())
        except Exception:
            webbrowser.open(str(out))
    return 0
if __name__ == '__main__':
    raise SystemExit(_cli())
