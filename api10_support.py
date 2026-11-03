"""Bounded local request fixtures shared by the API modules. Legacy module name retained."""
import base64, copy, json
from pathlib import Path
PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jK1sAAAAASUVORK5CYII=')
def load_request_data(path):
    p=Path(path)
    if p.stat().st_size>262144:raise ValueError('Request data file exceeds 256 KiB')
    data=json.loads(p.read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict):raise ValueError('Request data file must map METHOD /path to request objects')
    result={}
    for route,fixture in data.items():
        if not isinstance(route,str) or ' ' not in route or not route.split(' ',1)[1].startswith('/'):
            raise ValueError('Request fixture keys must be METHOD /OpenAPI/path')
        method=route.split(' ',1)[0].upper()
        if method not in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'):raise ValueError('Invalid fixture method')
        if not isinstance(fixture,dict) or set(fixture)-{'params','headers','json','data','files'}:raise ValueError('Invalid fixture fields')
        fixture=copy.deepcopy(fixture)
        for key in ('params','headers','data'):
            if key in fixture and not isinstance(fixture[key],dict):raise ValueError(key+' fixture must be an object')
        if 'headers' in fixture and any(not isinstance(v,str) or '\r' in v or '\n' in v for v in fixture['headers'].values()):raise ValueError('Invalid fixture header')
        if 'files' in fixture:
            if not isinstance(fixture['files'],dict):raise ValueError('files fixture must be an object')
            files={}
            for name,file in fixture['files'].items():
                if not isinstance(file,dict) or set(file)-{'path','content_type'} or 'path' not in file:raise ValueError('File requires path and optional content_type')
                fp=Path(file['path'])
                if not fp.is_absolute():fp=p.parent/fp
                if fp.stat().st_size>10485760:raise ValueError('Fixture file exceeds 10 MiB')
                content_type=file.get('content_type','application/octet-stream')
                if not isinstance(content_type,str) or '\r' in content_type or '\n' in content_type:raise ValueError('Invalid file content type')
                files[name]=(fp.name,fp.read_bytes(),content_type)
            fixture['files']=files
        result[method+' '+route.split(' ',1)[1]]=fixture
    return result

def prepare_sql_request(req, op, overrides, run_id):
    req=copy.deepcopy(req)
    content=(op.get('requestBody') or {}).get('content',{})
    multipart=content.get('multipart/form-data')
    if multipart:
        schema=multipart.get('schema') or {}
        form=req.setdefault('data',{})
        if not isinstance(form,dict):form={};req['data']=form
        for name,prop in schema.get('properties',{}).items():
            if prop.get('format')=='binary' or prop.get('type')=='file':
                form.pop(name,None)
                req.setdefault('files',{})[name]=(f'apiscan-{run_id}.png',PNG,'image/png')
        # Multipart needs a boundary even for forms without a binary property.
        if not req.get('files'):
            req['files']={name:(None,str(value)) for name,value in form.items()}
            req.pop('data',None)
    fixture=overrides.get(op['method'].upper()+' '+op['path'],{})
    for key,value in fixture.items():
        if key=='headers':req.setdefault('headers',{}).update(copy.deepcopy(value))
        else:req[key]=copy.deepcopy(value)
    if 'json' in fixture:
        req.pop('data',None);req.pop('files',None)
    if 'files' in req:
        req.pop('json',None)
        req.setdefault('headers',{})['Content-Type']=None
    return req

def write_record(req,response,run_id,stage):
    if req['method'].upper() not in ('POST','PUT','PATCH','DELETE'):return None
    ids={}
    try:
        body=response.json()
        if isinstance(body,dict):
            for key,value in body.items():
                if (key.lower()=='id' or key.lower().endswith('_id')) and isinstance(value,(str,int)):
                    ids[key]=str(value)[:160]
    except (ValueError,TypeError):pass
    return {'run_marker':run_id,'method':req['method'],'url':req['url'],
            'stage':stage,'status':response.status_code,'returned_ids':ids,
            'cleanup':'Not performed; returned IDs alone do not establish ownership or a safe delete route'}
