"""Operation-aware request context and bounded rejection handling for API4/API10."""
import copy
import json
import re
import threading
from collections import Counter
from urllib.parse import urlsplit, parse_qsl
import requests
from openapi_universal import iter_operations, build_request

SKIP_REASONS = frozenset(('Method not declared for operation', 'Write probe outside declared operations', 'Method rejected by server (HTTP 405)', 'Missing valid request context', 'Repeated request validation rejection', 'Repeated unavailable operation', 'Repeated transport failure', 'Repeated server error'))

class ProbeSkipped(requests.RequestException):
    pass

class ProbePolicySession:
    def __init__(self, source, spec, base_url, rejection_limit=3):
        self.source, self.spec, self.base_url = source, spec or {}, base_url
        self.limit = max(1,int(rejection_limit))
        self.lock = threading.Lock()
        self.blocked_methods = set()
        self.rejections = Counter()
        self.unavailable = Counter()
        self.transport_failures = Counter()
        # Consecutive 5xx per route; any other status resets the streak.
        self.server_error_streak = Counter()
        self.server_error_limit = max(10, self.limit * 3)
        self.skipped = Counter()
        self.records = {}
        self.operations = []
        prefix = urlsplit(base_url).path.rstrip('/')
        for op in iter_operations(self.spec):
            path = prefix+'/'+op['path'].lstrip('/')
            expression = re.escape(path)
            expression = re.sub(r'\\\{[^}]+\\\}', '[^/]+', expression)
            self.operations.append((re.compile('^'+expression+'/?$'),op))
    def __getattr__(self, name):
        return getattr(self.source,name)
    def matching(self,url):
        path=urlsplit(url).path
        matches = [op for pattern,op in self.operations if pattern.fullmatch(path)]
        if not matches:
            return []
        # A static route wins over a sibling parameter template.
        specificity = min(op['path'].count('{') for op in matches)
        return [op for op in matches if op['path'].count('{') == specificity]
    def _skip(self,reason,key):
        with self.lock:
            self.skipped[reason]+=1
            if len(self.records)<100:
                self.records.setdefault((reason,key),{'reason':reason,'method':key[0],'path':key[1]})
        raise ProbeSkipped(reason)
    def request(self,method,url,*args,**kwargs):
        method=method.upper(); path=urlsplit(url).path; key=(method,path)
        matches=self.matching(url); declared={op['method'] for op in matches}
        if declared and method not in declared and method not in ('HEAD','OPTIONS'):
            return self._skip('Method not declared for operation',key)
        if self.spec and not matches and method not in ('GET','HEAD','OPTIONS'):
            return self._skip('Write probe outside declared operations',key)
        with self.lock: blocked=key in self.blocked_methods
        if blocked:return self._skip('Method rejected by server (HTTP 405)',key)
        op=next((op for op in matches if op['method']==method),None)
        kwargs=dict(kwargs)
        if op:
            try: baseline=build_request(self.spec,self.base_url,op)
            except ValueError: return self._skip('Missing valid request context',key)
            existing_query=dict(parse_qsl(urlsplit(url).query,keep_blank_values=True))
            for field in ('headers','params','cookies'):
                defaults=dict(baseline.get(field) or {})
                if field=='params':defaults={k:v for k,v in defaults.items() if k not in existing_query}
                if defaults:
                    supplied = kwargs.get(field) or {}
                    if field == 'params' and isinstance(supplied,(list,tuple)):
                        names = {name for name,value in supplied}
                        kwargs[field] = [(name,value) for name,value in defaults.items() if name not in names] + list(supplied)
                    else:
                        defaults.update(supplied);kwargs[field]=defaults
            if method not in ('GET','HEAD','OPTIONS') and not any(k in kwargs and kwargs[k] is not None for k in ('json','data','files')):
                for field in ('json','data','files'):
                    if field in baseline:kwargs[field]=copy.deepcopy(baseline[field])
        params = kwargs.get('params') or {}
        param_names = set(params) if isinstance(params,dict) else {name for name,value in params}
        shape=(method,path,tuple(sorted(param_names | set(dict(parse_qsl(urlsplit(url).query,keep_blank_values=True))))),
               'json' if 'json' in kwargs else 'files' if 'files' in kwargs else 'data' if 'data' in kwargs else 'none',
               tuple(sorted(kwargs.get('json',{}))) if isinstance(kwargs.get('json'),dict) else ())
        # SQL body/error probes retain their own controls and evidence processing.
        sql_probe=any(k.lower()=='x-apiscan-run' for k in (kwargs.get('headers') or {}))
        with self.lock: rejected=self.rejections[shape]>=self.limit
        if rejected and not sql_probe:return self._skip('Repeated request validation rejection',key)
        with self.lock:
            unavailable = self.unavailable[key] >= self.limit
            transport_failed = self.transport_failures[key] >= self.limit
        if unavailable and not sql_probe:
            return self._skip('Repeated unavailable operation', key)
        if transport_failed:
            return self._skip('Repeated transport failure', key)
        with self.lock:
            broken = self.server_error_streak[key] >= self.server_error_limit
        if broken and not sql_probe:
            return self._skip('Repeated server error', key)
        try:
            response=self.source.request(method,url,*args,**kwargs)
        except requests.RequestException:
            with self.lock: self.transport_failures[key] += 1
            raise
        if response.status_code in (401,403,404):
            with self.lock: self.unavailable[key] += 1
        with self.lock:
            if response.status_code >= 500:
                self.server_error_streak[key] += 1
            else:
                self.server_error_streak[key] = 0

        if response.status_code==405:
            with self.lock:self.blocked_methods.add(key)
        if response.status_code in (400,415,422):
            body=(response.text or '')[:20000].lower()
            interesting=any(marker in body for marker in ('sql','database','postgres','ora-','mongo','traceback','exception','stack trace','root:x:'))
            if not interesting:
                with self.lock:self.rejections[shape]+=1
        return response
    def get(self,url,**kwargs):return self.request('GET',url,**kwargs)
    def post(self,url,**kwargs):return self.request('POST',url,**kwargs)
    def put(self,url,**kwargs):return self.request('PUT',url,**kwargs)
    def patch(self,url,**kwargs):return self.request('PATCH',url,**kwargs)
    def delete(self,url,**kwargs):return self.request('DELETE',url,**kwargs)
    def head(self,url,**kwargs):return self.request('HEAD',url,**kwargs)
    def options(self,url,**kwargs):return self.request('OPTIONS',url,**kwargs)
    def summary(self):
        with self.lock:
            return {'skipped_requests':sum(self.skipped.values()),'reasons':dict(self.skipped),
                    'blocked_methods':len(self.blocked_methods),'rejection_limit':self.limit,
                    'unavailable_operation_limit':self.limit,'transport_failure_limit':self.limit,
                    'server_error_streak_limit':self.server_error_limit,
                    'note':'Skipped probe attempts are not server responses. SQL error/body probes retain independent controls.'}
    def diagnostics(self,audit):
        with self.lock:return [dict(record,audit=audit,execution_status='skipped') for record in self.records.values()]
