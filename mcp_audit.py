"""Bounded MCP Streamable HTTP discovery and explicit tool-call auditing.
Supports the 2025-03-26, 2025-06-18 and 2025-11-25 protocol revisions.
Server metadata is untrusted evidence, never executable scanner instructions.
"""
from __future__ import annotations
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
import requests
from requests.adapters import HTTPAdapter

VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26')
MAX_BYTES = 1024 * 1024
MAX_ITEMS = 1000

class MCPError(Exception):
    pass

class MCPDenied(MCPError):
    pass

class MCPMethodUnavailable(MCPError):
    pass

class MCPAuditor:
    def __init__(self, session, url, *, timeout=5, version=VERSIONS[0], max_pages=10):
        parsed = urlsplit(url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError('MCP requires a complete HTTP(S) endpoint URL without credentials, query or fragment')
        if version not in VERSIONS or not 0 < timeout <= 600 or not 1 <= max_pages <= 100:
            raise ValueError('Invalid MCP protocol version, timeout or page limit')
        self.session, self.url = session, url
        self.timeout, self.version, self.max_pages = timeout, version, max_pages
        self.session_id = None
        self.next_id = 0
        self.issues, self.diagnostics = [], []
        self.inventory = dict(transport='streamable-http',tools=[],resources=[],resourceTemplates=[],prompts=[])
        self.coverage = dict(audit='MCP',started=0,completed=0,failed=0,skipped=0,scope_limited=True,
            checks={},tool_calls=0,unsupported_tests=['stdio','legacy HTTP+SSE','2026 protocol revisions',
                'SSE reconnection','automatic tool fuzzing','cross-user tool authorization','token audience/signature verification','prompt injection with AI client'],
            note='Counts describe HTTP POST requests. Discovery and transport/auth observations; explicit tool calls only. Tool metadata cannot prove implementation safety.')
        for scheme in ('http://','https://'):
            self.session.mount(scheme,HTTPAdapter(max_retries=0))

    def _diagnostic(self, phase, error):
        self.diagnostics.append(dict(audit='MCP',url=self.url,phase=phase,error=str(error),execution_status='failed'))

    def _issue(self, description, severity='Info', **extra):
        # No request credentials or raw tool results are retained in findings.
        self.issues.append(dict(endpoint=self.url,url=self.url,method='POST',description=description,
            severity=severity,status_code=200,confidence='low' if severity=='Info' else 'medium',extra=extra))

    def _headers(self, overrides=None):
        headers = {'Accept':'application/json, text/event-stream','Content-Type':'application/json'}
        if self.session_id:
            headers['Mcp-Session-Id'] = self.session_id
        if self.next_id > 1:
            headers['MCP-Protocol-Version'] = self.version
        headers.update(overrides or {})
        return headers

    @staticmethod
    def _validate_message(message, request_id):
        if not isinstance(message,dict) or message.get('jsonrpc')!='2.0':
            raise MCPError('Invalid JSON-RPC message')
        if 'method' in message:
            # Capabilities advertised by this client are empty. Never execute server requests.
            if 'id' in message:
                raise MCPError('Unsupported server-to-client request')
            return None
        if message.get('id') != request_id or type(message.get('id')) is not type(request_id):
            raise MCPError('JSON-RPC response ID mismatch')
        if ('result' in message) == ('error' in message):
            raise MCPError('Response must contain exactly one result or error')
        if 'error' in message:
            error=message['error']
            if isinstance(error,dict) and error.get('code')==-32601:
                raise MCPMethodUnavailable('JSON-RPC method unavailable')
            raise MCPError('JSON-RPC error code: '+str(error.get('code') if isinstance(error,dict) else 'invalid error'))
        if not isinstance(message['result'],dict):
            raise MCPError('Expected an object result')
        return message['result']

    def _read_result(self, response, request_id):
        ctype=response.headers.get('Content-Type','').split(';',1)[0].strip().lower()
        if ctype not in ('application/json','text/event-stream'):
            raise MCPError('Endpoint did not return MCP JSON or SSE')
        deadline=time.monotonic()+self.timeout
        total=0; buf=bytearray(); data=[]
        for chunk in response.iter_content(chunk_size=1 if ctype=='text/event-stream' else 4096):
            if time.monotonic()>deadline:
                raise MCPError('MCP response exceeded total read deadline')
            total+=len(chunk)
            if total>MAX_BYTES:
                raise MCPError('MCP response exceeds 1 MiB limit')
            buf.extend(chunk)
            if ctype=='text/event-stream' and chunk==b'\n':
                line=bytes(buf).decode('utf-8').rstrip('\r\n');buf.clear()
                if line.startswith('data:'):
                    data.append(line[5:].lstrip(' '))
                elif not line and data:
                    event='\n'.join(data);data=[]
                    if not event.strip():
                        continue
                    result=self._validate_message(json.loads(event),request_id)
                    if result is not None:
                        return result
        if ctype=='application/json':
            return self._validate_message(json.loads(bytes(buf).decode('utf-8')),request_id)
        raise MCPError('SSE ended before the matching JSON-RPC response; resumable streams not supported')

    def rpc(self, method, params=None, *, notification=False, headers=None, allow_denied=False, optional_method=False):
        self.next_id+=1
        payload=dict(jsonrpc='2.0',method=method)
        if not notification:
            payload['id']=self.next_id
        if params is not None:
            payload['params']=params
        self.coverage['started']+=1
        try:
            response=self.session.post(self.url,json=payload,headers=self._headers(headers),
                timeout=self.timeout,allow_redirects=False,stream=True)
            try:
                if allow_denied and response.status_code in (401,403):
                    result={'denied':True,'status':response.status_code}
                elif notification:
                    if response.status_code!=202:
                        raise MCPError('Initialized notification requires HTTP 202; received '+str(response.status_code))
                    result={}
                else:
                    if response.status_code!=200:
                        raise MCPError('MCP request returned HTTP '+str(response.status_code)+'; redirects are not followed')
                    result=self._read_result(response,payload['id'])
                    if method=='initialize':
                        sid=response.headers.get('Mcp-Session-Id')
                        if sid and (len(sid)>1024 or not re.fullmatch(r'[\x21-\x7e]+',sid)):
                            raise MCPError('Invalid MCP session identifier')
                        self.session_id=sid
            finally:
                response.close()
        except Exception as exc:
            if optional_method and isinstance(exc,MCPMethodUnavailable):
                self.coverage['completed']+=1
                return {'unsupported':True}
            self.coverage['failed']+=1
            self._diagnostic(method,type(exc).__name__+': '+str(exc) if isinstance(exc,MCPError) else type(exc).__name__)
            raise MCPError('MCP '+method+' failed') from exc
        self.coverage['completed']+=1
        return result

    def initialize(self, *, allow_denied=False):
        result=self.rpc('initialize',dict(protocolVersion=self.version,capabilities={},
            clientInfo={'name':'APIScan','version':'5.5.0'}),allow_denied=allow_denied)
        if result.get('denied'):
            return result
        if result.get('protocolVersion') not in VERSIONS:
            raise MCPError('Server negotiated an unsupported protocol version')
        self.version=result['protocolVersion']
        if not isinstance(result.get('capabilities'),dict) or not isinstance(result.get('serverInfo'),dict):
            raise MCPError('Missing initialization capabilities or serverInfo')
        for capability in ('tools','resources','prompts'):
            if capability in result['capabilities'] and not isinstance(result['capabilities'][capability],dict):
                raise MCPError('Invalid advertised capability')
        self.inventory['protocolVersion']=self.version
        self.inventory['serverInfo']=result['serverInfo']
        self.inventory['capabilities']=result['capabilities']
        self.rpc('notifications/initialized',notification=True)
        return result

    def _list(self, method, key, allow_denied=False):
        cursor=None;seen=set();items=[]
        for page in range(self.max_pages):
            result=self.rpc(method,{'cursor':cursor} if cursor else {},allow_denied=allow_denied,optional_method=method=='resources/templates/list')
            if result.get('denied'):
                raise MCPDenied('Discovery requires authentication')
            if result.get('unsupported'):
                self.coverage['checks'][method]='not_applicable'
                return []
            batch=result.get(key)
            if not isinstance(batch,list) or any(not isinstance(item,dict) for item in batch):
                raise MCPError('Invalid '+key+' list')
            items.extend(batch)
            if len(items)>MAX_ITEMS:
                raise MCPError('Discovery exceeds 1000 item limit')
            self.inventory[key]=items
            cursor=result.get('nextCursor')
            if not cursor:
                return items
            if not isinstance(cursor,str) or cursor in seen:
                raise MCPError('Repeated or invalid pagination cursor')
            seen.add(cursor)
        raise MCPError('Discovery page limit reached; inventory is incomplete')

    def discover(self,allow_denied=False):
        caps=self.inventory['capabilities']
        for capability,method,key in [('tools','tools/list','tools'),('resources','resources/list','resources'),
                ('resources','resources/templates/list','resourceTemplates'),('prompts','prompts/list','prompts')]:
            if capability in caps:
                self._list(method,key,allow_denied)
        names=set()
        for tool in self.inventory['tools']:
            name=tool.get('name')
            if not isinstance(name,str) or not name or name in names or not isinstance(tool.get('inputSchema'),dict):
                raise MCPError('Invalid or duplicate tool definition')
            names.add(name)
        self.coverage['checks']['discovery']='completed'

    def _probe_client(self, invalid_token=False):
        session=requests.Session()
        session.trust_env=False  # prevent netrc credentials during an anonymous probe
        session.verify=getattr(self.session,'verify',True)
        session.proxies.update(getattr(self.session,'proxies',{}))
        if invalid_token:
            session.headers['Authorization']='Bearer apiscan-invalid-token'
        return MCPAuditor(session,self.url,timeout=self.timeout,version=self.version,max_pages=self.max_pages)

    def authentication_checks(self):
        for label,invalid in [('anonymous_discovery',False),('invalid_bearer',True)]:
            probe=self._probe_client(invalid)
            try:
                init=probe.initialize(allow_denied=True)
                if init.get('denied'):
                    self.coverage['checks'][label]='rejected'
                else:
                    probe.discover(allow_denied=True)
                    count=len(probe.inventory['tools'])
                    self.coverage['checks'][label]='discovery_accessible'
                    self._issue('Observation: MCP discovery accessible '+('with an invalid bearer token' if invalid else 'without authentication')+
                        '; public-access policy and per-tool permissions are unverified.',tool_count=count)
            except MCPDenied:
                self.coverage['checks'][label]='rejected'
            except MCPError:
                self.coverage['checks'][label]='inconclusive'
            finally:
                self.coverage['started']+=probe.coverage['started']
                self.coverage['completed']+=probe.coverage['completed']
                self.coverage['failed']+=probe.coverage['failed']
                self.diagnostics.extend(probe.diagnostics)
                if self.coverage['checks'].get(label)=='inconclusive' and not probe.diagnostics:
                    self._diagnostic(label,'Incomplete authentication probe')
                probe.session.close()

    def origin_check(self):
        try:
            self.rpc("ping")
            result=self.rpc('ping',headers={'Origin':'https://apiscan-untrusted.invalid'},allow_denied=True)
            if result.get('denied'):
                self.coverage['checks']['origin']='rejected' if result['status']==403 else 'inconclusive'
                if result['status']!=403:
                    self._diagnostic('origin','Origin probe denied by authentication; Origin validation unverified')
            else:
                self.coverage['checks']['origin']='accepted'
                self._issue('MCP accepted a ping from an untrusted Origin; review Origin allowlisting and DNS-rebinding protection.','Low')
        except MCPError:
            self.coverage['checks']['origin']='inconclusive'

    def call_selected(self,calls):
        from jsonschema import Draft202012Validator
        from referencing import Registry
        def deny_external_reference(uri):
            raise MCPError('External JSON Schema retrieval is disabled')
        registry=Registry(retrieve=deny_external_reference)
        tools={tool['name']:tool for tool in self.inventory['tools']}
        # Validate the whole plan before executing the first call.
        for call in calls:
            if call['name'] not in tools:
                raise MCPError('Selected tool was not discovered')
            schema=tools[call['name']]['inputSchema']
            pending=[schema]
            while pending:
                node=pending.pop()
                if isinstance(node,dict):
                    for key,value in node.items():
                        if key in ('$ref','$dynamicRef') and isinstance(value,str) and not value.startswith('#'):
                            raise MCPError('Remote JSON Schema references are not fetched')
                        pending.append(value)
                elif isinstance(node,list):
                    pending.extend(node)
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema,registry=registry).validate(call['arguments'])
        for call in calls:
            result=self.rpc('tools/call',call)
            if not isinstance(result.get('content'),list) or ('isError' in result and not isinstance(result['isError'],bool)):
                raise MCPError('Invalid tools/call result')
            self.coverage['tool_calls']+=1
            self._issue('Observation: explicitly selected MCP tool '+call['name']+' returned '+
                ('an application error' if result.get('isError') else 'a result')+'; authorization and side effects require review.')
            # Never retain tool output: it may contain secrets or executable-looking instructions.

    def scan(self,calls=None):
        try:
            self.initialize()
            self.discover()
        except Exception as exc:
            if not self.diagnostics:
                self._diagnostic('discovery',type(exc).__name__+': '+str(exc))
        else:
            if urlsplit(self.url).scheme=='http':
                self._issue('MCP endpoint uses plaintext HTTP; transport confidentiality is absent.','Medium')
            self.origin_check()
            self.authentication_checks()
            if calls:
                try:
                    self.call_selected(calls)
                except Exception as exc:
                    self._diagnostic('selected_tool_calls',type(exc).__name__)
        self.coverage['tools_discovered']=len(self.inventory['tools'])
        self.coverage['diagnostics']=len(self.diagnostics)
        self.coverage['state']='incomplete' if self.diagnostics else 'completed'
        if not calls:
            self.coverage['unsupported_tests'].append('tool execution not selected')
        return self.issues

    def save(self,directory):
        directory=Path(directory);(directory/'log').mkdir(parents=True,exist_ok=True)
        for name,data in [('mcp_inventory.json',self.inventory),('log/coverage_mcp.json',self.coverage),
                          ('log/telemetry_mcp.json',self.diagnostics)]:
            (directory/name).write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')


def load_calls(path):
    if not path:
        return None
    path=Path(path)
    if path.stat().st_size>65536:
        raise ValueError('MCP calls file exceeds 64 KiB')
    calls=json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(calls,list) or not 1<=len(calls)<=20:
        raise ValueError('MCP calls file must contain 1 to 20 explicit calls')
    for call in calls:
        if not isinstance(call,dict) or set(call)!={'name','arguments'} or not isinstance(call['name'],str) or not isinstance(call['arguments'],dict):
            raise ValueError('Every MCP call requires name and arguments only')
    return calls


def run_mcp_mode(args,session,directory,db,run_id):
    from report_utils import HTMLReportGenerator
    from build_review import build_review
    if db is None:
        raise MCPError('Evidence database is required to generate MCP review and coverage')
    calls=load_calls(getattr(args,'mcp_calls_file',None))
    if calls:
        print('Executing '+str(len(calls))+' explicitly selected MCP tool calls; arguments and results will not be exported.')
    auditor=MCPAuditor(session,args.url,timeout=args.timeout,version=args.mcp_version,max_pages=args.mcp_max_pages)
    issues=auditor.scan(calls)
    auditor.save(directory)
    manifest=dict(selected=['MCP'],modules=[dict(audit='MCP',state=auditor.coverage['state'],findings=len(issues))],
                  note=auditor.coverage['note'])
    (Path(directory)/'log'/'scan_modules.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    HTMLReportGenerator(issues=issues,scanner='MCP Streamable HTTP audit',base_url=args.url).save(Path(directory)/'api_mcp_report.html')
    (Path(directory)/'module_reports.html').write_bytes((Path(directory)/'api_mcp_report.html').read_bytes())
    db.store_issues('MCP',issues,base_url=args.url)
    build_review(db_path=db.path,out_path=Path(directory)/'review.html',run_id=run_id)
    print('MCP '+auditor.coverage['state']+' - '+str(len(issues))+' findings; '+str(auditor.coverage['tools_discovered'])+' tools discovered')
    print('MCP requests: '+str(auditor.coverage['completed'])+'/'+str(auditor.coverage['started'])+' completed; diagnostics: '+str(auditor.coverage['diagnostics']))
    for diagnostic in auditor.diagnostics[:3]:
        print('MCP diagnostic: '+str(diagnostic.get('phase',''))+' - '+str(diagnostic.get('error',''))[:240])
    print('MCP inventory: '+str(Path(directory)/'mcp_inventory.json'))
    print('Review: '+str(Path(directory)/'review.html'))
    print('Combined report: '+str(Path(directory)/'combined_report.html'))
    return auditor.coverage['state']=='completed'
