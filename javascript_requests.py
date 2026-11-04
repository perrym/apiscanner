"""Bounded, static request hints. No JavaScript execution or dynamic ID guessing."""
import os
import re

DYNAMIC_ROUTES = os.getenv('APISCAN_CRAWL_DYNAMIC', '1').strip().lower() not in ('0', 'false', 'no', 'off')
STRING = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)'''

def _param_name(expression):
    names = re.findall(r'[A-Za-z_][\w]*', expression)
    names = [n for n in names if n not in ('this', 'const', 'let', 'var')]
    if not names:
        return 'param'
    name = names[-1]
    if name.lower() == 'id' and len(names) > 1:
        name = names[-2] + 'Id'
    return name


def _string(token):
    return token[1:-1].replace(r'\/', '/')

def _resolve(expression, context, seen=None):
    seen = set(seen or ())
    if len(seen) > 5:
        return None
    parts = re.split(r'\s*\+\s*(?=(?:[^\"\']*[\"\'][^\"\']*[\"\'])*[^\"\']*$)', expression.strip())
    result = ''
    for part in parts:
        part = part.strip()
        if re.fullmatch(STRING, part):
            value = _string(part)
            if '${' in value:
                def template(match):
                    resolved = _resolve(match.group(1), context, seen)
                    return resolved if resolved is not None else '{dynamic:' + _param_name(match.group(1)) + '}'
                value = re.sub(r'\$\{([^}]+)\}', template, value)
                # Unknown server origin can yield a root-relative candidate; dynamic IDs become path parameters.
                if value.startswith('{dynamic:') and re.match(r'\$\{[^}]*\b(?:hostServer|origin)\}', _string(part)):
                    value = value[value.index('}') + 1:]
            result += value
        elif re.fullmatch(r'(?:this\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*', part):
            if part in seen:
                return None
            alias = r'(?:this\.)?' + re.escape(part[5:]) if part.startswith('this.') else re.escape(part)
            assignments = list(re.finditer(r'(?<![\w$])'+alias+r'\s*=\s*([^;,{}]+)', context))
            value = _resolve(assignments[-1].group(1), context[:assignments[-1].start()], seen | {part}) if assignments else None
            if value is None:
                # Unknown origin before a root-relative path is harmless; unknown IDs are not.
                if not result:
                    continue
                if '?' in result:
                    continue  # Preserve the declared query key with an empty example.
                if result.endswith('/') and DYNAMIC_ROUTES:
                    result += '{dynamic:' + _param_name(part) + '}'
                    continue
                return None
            result += value
        else:
            if '?' in result:
                continue
            return None
    if '?' in result:
        path,query=result.split('?',1)
        result=path+'?'+re.sub(r'\{dynamic:[^}]*\}','',query)
    relative = re.fullmatch(r'[A-Za-z0-9_.-]+/[^\s]+',result)
    if '{dynamic:' in result:
        # A dynamic segment becomes an OpenAPI path parameter, but only after a literal path.
        if not DYNAMIC_ROUTES or not result.startswith('/') or result.startswith('/{dynamic:'):
            return None
        result = re.sub(r'\{dynamic:([^}]*)\}', r'{\1}', result)
    return result if (result.startswith(('/', 'http://', 'https://')) or relative) else None


def _parts(text, delimiter=',', stop_call=False):
    """Split only at the outer level, respecting nested objects and quoted strings."""
    parts, start, depth, quote, escaped = [], 0, [], None, False
    for i, char in enumerate(text[:8192]):
        if quote:
            if escaped: escaped=False
            elif char=='\\': escaped=True
            elif char==quote: quote=None
            continue
        if char in ('"', "'", '`'): quote=char; continue
        if char in '([{': depth.append(char); continue
        if char in ')]}':
            if not depth:
                if stop_call or char==')':
                    parts.append(text[start:i].strip());return parts
            else: depth.pop()
        if char==delimiter and not depth:
            parts.append(text[start:i].strip());start=i+1
    parts.append(text[start:8192].strip())
    return parts

def _value(expression, context, depth=0):
    expression=expression.strip()
    if depth>6:return expression
    wrap=re.match(r'^(?:JSON\.stringify|new\s+URLSearchParams)\s*\((.*)\)\s*$',expression,re.S)
    if wrap:return _value(_parts(wrap.group(1))[0],context,depth+1)
    if re.fullmatch(r'(?:this\.)?[\w$]+',expression):
        alias=r'(?:this\.)?'+re.escape(expression[5:]) if expression.startswith('this.') else re.escape(expression)
        assignments=list(re.finditer(r'(?<![\w$])'+alias+r'\s*=\s*',context))
        if assignments:
            found=assignments[-1]
            value=_parts(context[found.end():],delimiter=';')[0]
            # Class fields and comma-separated declarations end at the outer comma.
            value=_parts(value)[0]
            return _value(value,context[:found.start()],depth+1)
    return expression

def _object(expression,context):
    expression=_value(expression,context)
    if not (expression.startswith('{') and expression.endswith('}')):return {}
    out={}
    for item in _parts(expression[1:-1]):
        pair=_parts(item,':')
        key=pair[0].strip().strip('"\'')
        if not re.fullmatch(r'[A-Za-z_$][\w$-]*',key):continue
        out[key]=':'.join(pair[1:]).strip() if len(pair)>1 else key
    return out

def _schema(expression,context,depth=0):
    if depth>6:return {'x-inferred-type':True}
    expression=_value(expression,context)
    if expression.startswith('{'):
        obj=_object(expression,context)
        return {'type':'object','properties':{key:_schema(value,context,depth+1) for key,value in obj.items()}}
    if expression.startswith('[') and expression.endswith(']'):
        items=_parts(expression[1:-1])
        return {'type':'array','items':_schema(items[0],context,depth+1) if items and items[0] else {}}
    if re.fullmatch(STRING,expression):return {'type':'string'}
    if expression in ('true','false'):return {'type':'boolean'}
    if re.fullmatch(r'-?\d+',expression):return {'type':'integer'}
    if re.fullmatch(r'-?\d+\.\d+',expression):return {'type':'number'}
    return {'type':'string','x-inferred-type':True}

def extract_requests(code, include_unresolved=False):
    results=[]
    calls=re.finditer(r'(?:\b(fetch)|\baxios\s*(?=\()|\.(get|post|put|patch|delete|head|options|request|ajax))\s*\(\s*',code,re.I)
    for call in calls:
        if re.search(r'(?:localStorage|sessionStorage)\.$',code[max(0,call.start()-30):call.start()+1]):continue
        args=_parts(code[call.end():call.end()+8192],stop_call=True)
        if not args:continue
        context=code[max(0,call.start()-16000):call.start()]
        method=(call.group(2) or 'get').lower()
        is_fetch=bool(call.group(1))
        config_call=method in ('request','ajax') or (not call.group(1) and not call.group(2))
        if config_call:
            options_expression=args[0]
        elif is_fetch or method in ('get','head','options'):
            options_expression=args[1] if len(args)>1 else '{}'
        else:
            options_expression=args[2] if len(args)>2 else '{}'
        options=_object(options_expression,context)
        if is_fetch or config_call:
            method=options.get('method','"GET"').strip('"\'').lower()
        if method not in ('get','post','put','patch','delete','head','options'):
            if include_unresolved:results.append({'url':None,'method':'unknown','reason':'HTTP method depends on runtime values'})
            continue
        expression=options.get('url','') if config_call else args[0]
        url=_resolve(expression,context)
        if not url:
            if include_unresolved:results.append({'url':None,'method':method,'reason':'URL depends on unresolved runtime values'})
            continue
        if config_call and options.get('baseURL'):
            base=_resolve(options['baseURL'],context)
            if base and not url.startswith(('http://','https://')):url=base.rstrip('/')+'/'+url.lstrip('/')
        elif call.group(2):
            receiver=re.search(r'([A-Za-z_$][\w$]*)$',code[max(0,call.start()-100):call.start()])
            if receiver:
                clients=list(re.finditer(r'(?<![\w$])'+re.escape(receiver.group(1))+r'\s*=\s*axios\.create\s*\(',context))
                if clients:
                    config_args=_parts(context[clients[-1].end():],stop_call=True)
                    config=_object(config_args[0],context[:clients[-1].start()]) if config_args else {}
                    base=_resolve(config.get('baseURL',''),context)
                    if base and not url.startswith(('http://','https://')):url=base.rstrip('/')+'/'+url.lstrip('/')
        body=options.get('body' if is_fetch else 'data','') if is_fetch or config_call else (args[1] if method in ('post','put','patch') and len(args)>1 else '')
        schema=_schema(body,context) if body else None
        headers=_object(options.get('headers','{}'),context)
        content_type=next((_string(value).lower() for key,value in headers.items() if key.lower()=='content-type' and re.fullmatch(STRING,value)),None)
        encoding=content_type or 'application/json'
        if 'URLSearchParams' in body or content_type=='application/x-www-form-urlencoded':encoding='application/x-www-form-urlencoded'
        elif body and is_fetch and 'JSON.stringify' not in body and content_type!='application/json':encoding=content_type or None
        params=_object(options.get('params','{}'),context)
        results.append({'url':url,'method':method,'fields':list((schema or {}).get('properties',{})),
                        'body_schema':schema,'content_type':encoding,
                        'query_parameters':{name:_schema(value,context) for name,value in params.items()},
                        'header_names':list(headers),
                        'requires_body':bool(body) and (encoding not in ('application/json','application/x-www-form-urlencoded') or not (schema or {}).get('properties'))})
    return results
