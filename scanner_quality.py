"""Shared request validation, evidence classification and scan coverage."""
import json
import re
import severity_rules
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit, quote


def normalize_endpoint(endpoint, base_url, values=None):
    if isinstance(endpoint, dict):
        endpoint = endpoint.get('url') or endpoint.get('path') or ''
    if isinstance(endpoint, tuple):
        endpoint = endpoint[0]
    endpoint = str(endpoint or '').strip()
    if not endpoint:
        raise ValueError('Empty endpoint')
    def substitute(match):
        name = match.group(1)
        if name not in (values or {}):
            raise ValueError('Unresolved path parameter: ' + name)
        return quote(str(values[name]), safe='')
    endpoint = re.sub(r'\{([^}]+)\}', substitute, endpoint)
    url = urljoin(base_url.rstrip('/') + '/', endpoint)
    parsed, base = urlsplit(url), urlsplit(base_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Endpoint must have an HTTP(S) scheme and host')
    if parsed.username or parsed.password:
        raise ValueError('Credentials in endpoint URL are not allowed')
    if (parsed.scheme, parsed.netloc.lower()) != (base.scheme, base.netloc.lower()):
        raise ValueError('Endpoint outside configured target origin')
    return url


def path_values(spec, overrides=None):
    values = {}
    from openapi_universal import iter_operations
    for operation in iter_operations(spec):
        for param in operation.get('parameters', []):
            if not isinstance(param, dict) or param.get('in') != 'path' or not param.get('name'):
                continue
            schema = param.get('schema') or param
            value = param.get('example', schema.get('example', schema.get('default')))
            if value is None and schema.get('enum'):
                value = schema['enum'][0]
            if value is None:
                if schema.get('format') == 'uuid':
                    value = '00000000-0000-4000-8000-000000000001'
                elif schema.get('type') in ('integer', 'number'):
                    value = max(1, schema.get('minimum', 1))
                else:
                    # Unknown string IDs require explicit input rather than fabricated ownership.
                    continue
            values.setdefault(param['name'], value)
    values.update(getattr(spec, "path_parameter_values", {}))
    values.update(overrides or {})
    return values


def coverage_summary(coverage, telemetry):
    result = dict(coverage)
    result['diagnostics'] = len(telemetry)
    result['diagnostic_types'] = dict(Counter(str(x.get('issue', 'Unknown')) for x in telemetry))
    result['state'] = 'incomplete' if result.get('failed', 0) or result.get('untested', 0) or result.get('skipped', 0) or result.get('skipped_tasks', 0) or telemetry else 'completed'
    if not result.get('started', 0) and result.get('not_applicable', 0) and not telemetry and not result.get('failed', 0):
        result['state'] = 'not_applicable'
    result['note'] = 'not_applicable tasks were excluded before scheduling; untested tasks could not start because the baseline or request input was unusable; skipped_tasks stopped under request policy and may contain partial probes; failed tasks raised execution errors. Counts describe scheduled API10 test tasks, not all possible tests or absence of vulnerabilities.'
    return result


def cors_observation_severity(headers):
    if isinstance(headers, str):
        headers = dict(line.split(':', 1) for line in headers.splitlines() if ':' in line)
    if isinstance(headers, list):
        headers = dict(headers)
    headers = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    origin = headers.get('access-control-allow-origin', '')
    credentials = headers.get('access-control-allow-credentials', '').lower() == 'true'
    # Reflection plus credentials still requires proof of protected data and browser access.
    return 'low' if origin and origin != '*' and credentials else 'info'


def filtering_observation(text):
    text = str(text or '').lower()
    return any(marker in text for marker in (
        'input filtering detected', 'waf detected:', 'waf/input filtering detected',
        'strict input validation', 'template parameter filtering',
        'strong input validation/waf present'))


def evidence_severity(item):
    if item.get('title') == 'Broad CORS policy' or item.get('description') == 'Broad CORS policy':
        headers = item.get('response', {}).get('headers') or item.get('response_headers') or {}
        return cors_observation_severity(headers)
    text = (str(item.get('title', '')) + ' ' + str(item.get('description', ''))).lower()
    if filtering_observation(text):
        return 'info'
    if 'no rate-limiting on auth endpoint' in text:
        return 'info'
    if 'missing security headers' in text:
        return 'low' if 'text/html' in str(item.get('response', {}).get('headers', '')).lower() else 'info'
    markers = ('observation:', 'no throttling at', 'no rate-limiting after',
               'req/min (no throttling)', 'method override to',
               'shinyhunters guest user', 'quantum adversary',
               "shor's algorithm", 'post-quantum readiness')
    if 'weak rsa certificate key' in text:
        return None
    if any(marker in text for marker in markers):
        return 'info'
    return None


def export_scan(items, out_dir, run_id=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = []
    diagnostics = []
    telemetry = []
    for telemetry_path in sorted((out_dir / 'log').glob('telemetry_*.json')):
        for record in json.loads(telemetry_path.read_text(encoding='utf-8')):
            diagnostic = dict(record)
            diagnostic['source'] = str(record.get('audit', 'API10')) + ' telemetry'
            diagnostic['evidence_status'] = 'diagnostic'
            diagnostic.setdefault('execution_status', 'failed' if diagnostic.get('error') else 'inconclusive')
            telemetry.append(diagnostic)
    origins = set()
    for record in telemetry:
        parsed = urlsplit(str(record.get('url') or record.get('target') or ''))
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            origins.add(parsed.scheme + '://' + parsed.netloc)
    for item in items:
        parsed = urlsplit(str(item.get('url') or item.get('endpoint') or ''))
        if parsed.scheme in ('http', 'https') and parsed.netloc:
            origins.add(parsed.scheme + '://' + parsed.netloc)
    hosts = {urlsplit(origin).netloc.lower() for origin in origins}
    canonical_origin = next((origin for origin in sorted(origins) if origin.startswith('https://')),
                            next(iter(sorted(origins)), ''))
    for source in items:
        item = dict(source)
        item['audit'] = item.get('risk_key') or item.get('category')
        item['test_name'] = item.get('title') or item.get('description')
        raw_url = str(item.get('url') or item.get('endpoint') or '')
        if raw_url.startswith('/') and len(hosts) == 1:
            item['url'] = urljoin(canonical_origin, raw_url)
        if item.get('title') == 'Request smuggling test borderline/timeout':
            item['execution_status'] = 'inconclusive'
            item['evidence_status'] = 'diagnostic'
            diagnostics.append(item)
            continue
        override = evidence_severity(item)
        item['confidence'] = 'low' if override else 'unassessed'
        item['evidence_status'] = 'observation' if override == 'info' else 'requires_review'
        item['execution_status'] = 'response_received' if item.get('response', {}).get('status') else 'no_http_response'
        item['reported_severity'] = item.get('severity')
        if override:
            item['severity'] = override
        severity_rules.apply(item)
        findings.append(item)
    coverage = [json.loads(p.read_text(encoding='utf-8'))
                for p in sorted((out_dir / 'log').glob('coverage_*.json'))]
    manifest_file = out_dir / 'log' / 'scan_modules.json'
    modules = json.loads(manifest_file.read_text(encoding='utf-8')) if manifest_file.exists() else None
    path = out_dir / 'all_audit_findings.json'
    path.write_text(json.dumps({'schema_version': 1, 'run_id': run_id,
                              'findings': findings, 'diagnostics': diagnostics + telemetry, 'coverage': coverage, 'modules': modules},
                              indent=2, ensure_ascii=False), encoding='utf-8')
    return path


def write_module_manifest(output_dir, selected, summary):
    labels = {1:'BOLA',2:'Authentication',3:'Property-Level Auth',4:'Resource Consumption',
              5:'Admin Access',6:'Business Flows',7:'SSRF',8:'Misconfiguration',
              9:'Inventory',10:'Unsafe Consumption',11:'AI-OWASP'}
    modules = []
    for number, label in labels.items():
        state = 'completed_unmeasured' if label in summary else 'not_tested'
        if number not in selected:
            state = 'not_selected'
        coverage_path = Path(output_dir)/'log'/f'coverage_api{number}.json'
        if number in selected and coverage_path.exists():
            state = json.loads(coverage_path.read_text(encoding='utf-8')).get('state','unknown')
        telemetry_path = Path(output_dir)/'log'/f'telemetry_api{number}.json'
        if number in selected and telemetry_path.exists():
            records = json.loads(telemetry_path.read_text(encoding='utf-8'))
            if any(record.get('error') for record in records):
                state = 'incomplete'
        modules.append(dict(audit=f'API{number}',state=state,findings=summary.get(label)))
    path = Path(output_dir)/'log'/'scan_modules.json'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(dict(selected=list(selected),modules=modules,
        note='completed_unmeasured describes module return, not verified request coverage.'),indent=2),encoding='utf-8')
    return path


def write_execution_diagnostics(output_dir, audit, coverage, diagnostics):
    directory = Path(output_dir)/'log'
    directory.mkdir(parents=True,exist_ok=True)
    (directory/f'coverage_{audit.lower()}.json').write_text(json.dumps(coverage,indent=2),encoding='utf-8')
    (directory/f'telemetry_{audit.lower()}.json').write_text(json.dumps(diagnostics,indent=2,default=str),encoding='utf-8')
