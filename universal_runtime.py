"""Shared request fixtures and measured HTTP execution, independent of target API."""
import json
import threading
from pathlib import Path
from api10_support import load_request_data
from scanner_quality import path_values

class ScanSpec(dict):
    """Runtime attributes stay outside the serializable OpenAPI document."""

def attach_verified_login(spec, args):
    """Add observed JSON login fields; actual values stay outside exported OpenAPI."""
    from urllib.parse import urlsplit
    from copy import deepcopy
    request = getattr(args, '_apiscan_login_request', None)
    if not isinstance(request, dict) or not isinstance(request.get('json'), dict):
        return
    target = urlsplit(args.url)
    login = urlsplit(request.get('url', ''))
    if (login.scheme, login.netloc) != (target.scheme, target.netloc):
        return
    path = login.path or '/'
    body = request['json']
    properties = {}
    for name, value in body.items():
        if isinstance(value, str): typ = 'string'
        elif isinstance(value, bool): typ = 'boolean'
        elif isinstance(value, int): typ = 'integer'
        elif isinstance(value, float): typ = 'number'
        else: continue
        properties[name] = {'type': typ}
    if not properties:
        return
    op = spec.setdefault('paths', {}).setdefault(path, {}).setdefault('post', {})
    op['requestBody'] = {'required': True, 'content': {'application/json': {
        'schema': {'type': 'object', 'properties': properties}}}}
    op['x-discovery-state'] = 'observed-login'
    op.setdefault('responses', {}).setdefault('200', {'description': 'Successful JSON login observed'})
    spec.request_data.setdefault('POST '+path, {'json': deepcopy(body)})

def configure_spec(spec, ids=None, data_file=None):
    result = ScanSpec(spec)
    operations = list(__import__('openapi_universal').iter_operations(result))
    resolved = {'paths': {str(i): {'get': {'parameters':op['parameters']}} for i,op in enumerate(operations)}}
    result.path_parameter_values = path_values(resolved, ids or {})
    result.request_data = load_request_data(data_file) if data_file else {}
    declared = {op['method']+' '+op['path'] for op in __import__('openapi_universal').iter_operations(result)}
    unknown = set(result.request_data)-declared
    if unknown:
        raise ValueError('Request fixtures are missing from the API specification: '+', '.join(sorted(unknown)))
    return result

class ModuleCoverage:
    """Observe only this session; do not alter requests, status handling or credentials."""
    def __init__(self, session, output_dir, audit):
        self.session, self.output_dir, self.audit = session, Path(output_dir), audit
        self.lock = threading.Lock()
        self.metrics = {'started':0, 'completed':0, 'failed':0, 'status_counts':{}}
    def observe(self, client, kind='isolated'):
        with self.lock:
            if any(entry[0] is client for entry in getattr(self,'clients',[])): return
            override = 'send' in client.__dict__
            previous = client.__dict__.get('send')
            self.clients.append((client,override,previous))
        original = client.send
        def measured(request, **kwargs):
            with self.lock:
                self.metrics['started'] += 1
                counts = self.metrics.setdefault('sessions', {})
                counts[kind] = counts.get(kind,0)+1
            try:
                response = original(request, **kwargs)
            except Exception:
                with self.lock: self.metrics['failed'] += 1
                raise
            with self.lock:
                self.metrics['completed'] += 1
                key = str(response.status_code)
                counts = self.metrics['status_counts']
                counts[key] = counts.get(key,0)+1
            return response
        client.send = measured

    def __enter__(self):
        self.clients = []
        self.previous_observer = getattr(self.session, '_apiscan_coverage', None)
        self.session._apiscan_coverage = self
        self.observe(self.session,'primary')
        return self

    def __exit__(self, kind, value, traceback):
        for client, override, previous in self.clients:
            if override: client.send = previous
            else: client.__dict__.pop('send',None)
        if self.previous_observer is None:
            self.session.__dict__.pop('_apiscan_coverage',None)
        else: self.session._apiscan_coverage = self.previous_observer
        log = self.output_dir/'log'; log.mkdir(parents=True,exist_ok=True)
        self.metrics['scope'] = 'HTTP send calls on primary and registered isolated scanner sessions; redirects count separately. Adapter retries, TLS socket and non-HTTP checks are excluded.'
        # Keep detailed module test coverage authoritative, separate transport measurements.
        path = log/('coverage_'+self.audit.lower()+'.json')
        existing = {}
        if path.exists():
            try: existing = json.loads(path.read_text(encoding='utf-8'))
            except (ValueError,OSError): pass
        if not isinstance(existing,dict): existing = {}
        if not existing:
            existing = {'audit':self.audit,'state':'incomplete' if kind or self.metrics['failed'] else 'completed_unmeasured',
                        'scope_limited':True,'note':'HTTP execution measured; test completeness and vulnerability absence are not established.'}
        existing['http_execution'] = self.metrics
        if kind:
            existing['module_error'] = kind.__name__
            existing['state'] = 'incomplete'
        path.write_text(json.dumps(existing,indent=2),encoding='utf-8')
        return False

def isolated_session(source):
    """Transport options only; no ambient credentials, cookies, netrc or client certificate."""
    import requests
    target = requests.Session()
    target.verify = getattr(source,'verify',True)
    target.proxies = dict(getattr(source,'proxies',{}))
    target.trust_env = False
    observer = getattr(source, '_apiscan_coverage', None)
    if observer is not None: observer.observe(target)
    return target

def anonymous_request(req, spec=None):
    import copy
    out = copy.deepcopy(req)
    headers = out.setdefault('headers',{})
    blocked = {'authorization','proxy-authorization','cookie','x-api-key','x-auth-token'}
    schemes = (spec or {}).get('securityDefinitions',{})
    schemes = dict(schemes, **(spec or {}).get('components',{}).get('securitySchemes',{}))
    for scheme in schemes.values():
        if scheme.get('type') == 'apiKey':
            name = scheme.get('name')
            if scheme.get('in') == 'header' and name: blocked.add(name.lower())
            if scheme.get('in') == 'query': out.get('params',{}).pop(name,None)
    out['headers'] = {k:v for k,v in headers.items() if k.lower() not in blocked}
    out.pop('cookies',None); out.pop('auth',None)
    return out


def write_operation_inputs(spec, base_url, output_dir):
    """Record request preparation, without bodies or credential headers."""
    from openapi_universal import iter_operations, build_request
    records = []
    for operation in iter_operations(spec):
        record = {'method':operation['method'], 'path':operation['path']}
        raw = spec.get('paths', {}).get(operation['path'], {}).get(operation['method'].lower(), {})
        route_key = operation['method'].upper()+' '+operation['path']
        if raw.get('x-requires-request-data') and route_key not in getattr(spec,'request_data', {}):
            record.update(state='needs_input', reason='Discovered request body depends on runtime data; provide --request-data-file')
            records.append(record)
            continue
        try:
            request = build_request(spec, base_url, operation)
            record.update(state='prepared', url=request['url'])
            if raw.get('x-discovery-state')=='unverified':
                record['context']='Inferred JavaScript request; server acceptance and business values unverified'
            if raw.get('x-discovered-header-names'):
                record['header_names']=raw['x-discovered-header-names']
        except (ValueError, KeyError, TypeError) as exc:
            record.update(state='needs_input', reason=str(exc))
        records.append(record)
    result = {'operations':records,
              'needs_input':sum(record['state']=='needs_input' for record in records),
              'note':'Prepared means a request can be built; server acceptance and valid application data are unverified. Bodies and headers are excluded.'}
    path = Path(output_dir)/'log'/'operation_inputs.json'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result
