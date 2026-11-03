"""Bounded differential checks. No application-specific routes or JS execution."""
import copy
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urljoin
import requests


def json_signature(response):
    if not 200 <= response.status_code < 300:
        return None
    if 'json' not in response.headers.get('Content-Type', '').lower():
        return None
    if len(response.content) > 262144:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, (dict, list)):
        return None
    # Deliberately retain timestamps and echoed input: unstable/reflected replies
    # cannot satisfy this conservative comparison.
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def boolean_sql(send, request, baseline, field, before_send=lambda: None):
    """Two distinct true/false pairs plus a repeated baseline; GET query only."""
    result = {'field': field, 'state': 'not_applicable', 'requests': 0,
              'responses': 0, 'failures': 0, 'response_statuses': [], 'reason': 'Requires stable GET JSON baseline'}
    signature = json_signature(baseline)
    if request['method'].upper() != 'GET' or signature is None:
        return result
    original = request.get('params', {}).get(field)
    if isinstance(original, bool) or not isinstance(original, (str, int, float)):
        return result

    def probe(value):
        candidate = copy.deepcopy(request)
        candidate['params'][field] = value
        before_send()
        result['requests'] += 1
        try:
            response = send(**candidate)
        except requests.RequestException:
            result['failures'] += 1
            raise
        result['responses'] += 1
        result['response_statuses'].append(response.status_code)
        return json_signature(response)

    try:
        if probe(original) != signature:
            result.update(state='inconclusive', reason='Unstable baseline')
            return result
        # String and numeric contexts; bounded, read-only statements.
        comparable = False
        for suffix in ("' AND {condition}-- ", ' AND {condition}-- '):
            samples = [probe(str(original) + suffix.format(condition=condition))
                       for condition in ('17=17', '17=18', '23=23', '23=24')]
            if any(value is None for value in samples):
                continue
            comparable = True
            if samples[0] == samples[2] == signature and samples[1] == samples[3] != signature:
                result.update(state='candidate', status_code=result['response_statuses'][-4], reason='Two true predicates match stable baseline; two false predicates agree and differ')
                return result
        result.update(state='completed' if comparable else 'inconclusive',
                      reason='No repeatable boolean differential' if comparable else 'Probe responses unsuitable for structured comparison')
    except requests.RequestException:
        result.update(state='incomplete', reason='Probe transport or request policy failure')
    return result


def pointer(data, path):
    if path == '':
        return data
    if not isinstance(path, str) or not path.startswith('/'):
        raise ValueError('Expected a JSON pointer')
    for part in path[1:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


def login_sql(send, request, before_send=lambda: None):
    """Observed JSON login only: invalid credentials and paired OR predicates."""
    result={'state':'not_applicable','requests':0,'responses':0,'failures':0,'response_statuses':[],
            'reason':'Requires observed flat JSON credentials'}
    body=request.get('json',{})
    if request['method'].upper()!='POST' or not isinstance(body,dict):return result
    usernames=[k for k in body if k.lower() in ('email','username','user','login') and isinstance(body[k],str)]
    passwords=[k for k in body if k.lower() in ('password','passwd','pass') and isinstance(body[k],str)]
    if len(usernames)!=1 or len(passwords)!=1:return result
    import uuid
    username,password=usernames[0],passwords[0]
    invalid='apiscan_'+uuid.uuid4().hex+'@invalid.example'
    def probe(value):
        candidate=copy.deepcopy(request)
        candidate['json'][username]=value
        candidate['json'][password]=uuid.uuid4().hex
        before_send();result['requests']+=1
        try:response=send(**candidate)
        except requests.RequestException:
            result['failures']+=1;raise
        result['responses']+=1
        result['response_statuses'].append(response.status_code)
        if response.status_code in (401,403):return False
        if json_signature(response) is None:return None
        def token(data,depth=0):
            if not isinstance(data,dict) or depth>4:return False
            for key,value in data.items():
                if key.lower() in ('access_token','accesstoken','token','jwt') and isinstance(value,str) and len(value)>=16:
                    return True
                if isinstance(value,dict) and token(value,depth+1):return True
            return False
        return token(response.json())
    try:
        control=probe(invalid)
        if control is not False:
            result.update(state='inconclusive',reason='Invalid credential control returns token or unsuitable response');return result
        responses=[probe(invalid+"' OR "+condition+'-- ') for condition in ('17=17','17=18','23=23','23=24')]
        if responses==[True,False,True,False]:
            result.update(state='candidate',status_code=result['response_statuses'][1],reason='Two true OR predicates return tokens; invalid credentials and false predicates do not')
        elif any(value is None for value in responses):
            result.update(state='inconclusive',reason='Login probe responses unsuitable for comparison')
        else:result.update(state='completed',reason='No repeatable SQL login differential')
    except requests.RequestException:
        result.update(state='incomplete',reason='Login probe request failed')
    return result


def load_authorization_cases(filename, base_url, spec):
    path = Path(filename)
    if path.stat().st_size > 262144:
        raise ValueError('Authorization cases file exceeds 256 KiB')
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict):raise ValueError('Authorization cases must be a JSON object')
    accounts, cases = data.get('accounts', {}), data.get('cases', [])
    if not isinstance(accounts,dict) or set(accounts) != {'a', 'b'} or not isinstance(cases, list) or not 1 <= len(cases) <= 50:
        raise ValueError('Supply accounts a and b and 1-50 private-object cases')
    def local_path(value):
        if not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or any(c in value for c in ('?', '#', '\\', '\r', '\n')):
            raise ValueError('Expected same-origin absolute path without query or fragment')
        return value
    for account in accounts.values():
        if not isinstance(account,dict):raise ValueError('Account must be an object')
        headers = account.get('headers', {})
        if not isinstance(headers, dict) or not headers or any(not isinstance(k,str) or not isinstance(v,str) or not k or '\r' in k+v or '\n' in k+v for k,v in headers.items()):
            raise ValueError('Each account requires valid credential headers')
        if any(k.lower() in ('host','proxy-authorization') for k in headers):
            raise ValueError('Host and proxy credential overrides are excluded')
        identity = account['identity']
        local_path(identity['path'])
        if not isinstance(identity.get('subject'), (str,int)) or isinstance(identity['subject'],bool):
            raise ValueError('Identity requires a string or numeric expected subject')
        if not isinstance(identity.get('pointer'),str) or not identity['pointer'].startswith('/'):
            raise ValueError('Identity requires a JSON subject pointer')
    if accounts['a']['identity']['subject'] == accounts['b']['identity']['subject']:
        raise ValueError('Accounts must represent different subjects')
    from openapi_universal import iter_operations
    declared = {op['path'] for op in iter_operations(spec) if op['method'].upper() == 'GET'}
    from scanner_quality import normalize_endpoint
    origin = urlsplit(base_url)
    for case in cases:
        if not isinstance(case,dict):raise ValueError('Private-object case must be an object')
        if case.get('owner') not in accounts or case.get('private') is not True:
            raise ValueError('Case requires owner a/b and explicit private=true')
        local_path(case['path'])
        if case['path'] not in declared:
            raise ValueError('Private-object case must reference a declared GET operation')
        ids=case.get('path_values',{})
        if not isinstance(ids,dict) or any(name not in ids or not isinstance(ids[name],(str,int)) or isinstance(ids[name],bool) or str(ids[name])==''
            for name in re.findall(r'\{([^}]+)\}',case['path'])):
            raise ValueError('Supply explicit existing path_values for every object parameter')
        if not isinstance(case.get('object_pointer'),str) or not case['object_pointer'].startswith('/') or 'object_value' not in case:
            raise ValueError('Case requires object_pointer and object_value')
        case['url'] = normalize_endpoint(case['path'], base_url, case.get('path_values', {}))
        resolved = urlsplit(case['url'])
        if (resolved.scheme,resolved.netloc) != (origin.scheme,origin.netloc):
            raise ValueError('Authorization case leaves target origin')
    return data


def compare_accounts(source, config, base_url, timeout=5):
    """GET only; credentials isolated, redirects disabled, no response bodies exported."""
    from universal_runtime import isolated_session
    clients = {name: isolated_session(source) for name in ('a','b','anonymous')}
    report = {'state':'incomplete', 'identity_verified':False, 'cases':[], 'findings':[]}
    def read(client, path):
        return client.get(urljoin(base_url, path), timeout=timeout, allow_redirects=False)
    def matches(response, path, expected):
        if json_signature(response) is None:
            return False
        try:
            return pointer(response.json(),path) == expected
        except (ValueError,KeyError,TypeError,IndexError):
            return False
    try:
        subjects = []
        for name in ('a','b'):
            account = config['accounts'][name]
            clients[name].headers.update(account['headers'])
            identity = account['identity']
            if not matches(read(clients[name],identity['path']),identity['pointer'],identity['subject']):
                report['reason']='Account identity check failed; object comparisons not started'
                return report
            subjects.append(identity['subject'])
        if subjects[0] == subjects[1]:
            report['reason']='Distinct account identities required'
            return report
        report['identity_verified']=True
        for case in config['cases']:
            record = {'path':case['path'], 'owner':case['owner'], 'state':'inconclusive'}
            report['cases'].append(record)
            try:
                owner, other = case['owner'], 'b' if case['owner']=='a' else 'a'
                own = read(clients[owner],case['url'])
                record['owner_status']=own.status_code
                if not matches(own,case['object_pointer'],case['object_value']):
                    record['reason']='Owner baseline does not identify expected object';continue
                anonymous = read(clients['anonymous'],case['url'])
                record['anonymous_status']=anonymous.status_code
                if anonymous.status_code not in (401,403,404):
                    record['reason']='Anonymous access not demonstrably denied; public/shared resource excluded';continue
                probes = [read(clients[other],case['url']) for _ in range(2)]
                record['other_statuses']=[r.status_code for r in probes]
                if all(matches(r,case['object_pointer'],case['object_value']) for r in probes):
                    record.update(state='candidate',reason='Other verified account repeatedly receives configured private object')
                    report['findings'].append({'method':'GET','url':case['url'],'endpoint':case['url'],
                        'description':'Possible BOLA: second account reads configured private object',
                        'severity':'High','status_code':probes[0].status_code,'confidence':'medium',
                        'true_positive':False,'cross_user':True,
                        'evidence':dict(record), 'note':'Privacy/ownership expectation supplied by operator; review authorization rules'})
                elif all(r.status_code in (401,403,404) for r in probes):
                    record.update(state='completed',reason='Cross-account reads denied')
                else:
                    record['reason']='Other-account response does not prove access or denial'
            except requests.RequestException:
                record.update(state='incomplete',reason='Request failed')
        report['state']='completed' if all(r['state'] in ('completed','candidate') for r in report['cases']) else 'incomplete'
        return report
    except requests.RequestException:
        report['reason']='Identity request failed'
        return report
    finally:
        for client in clients.values():
            client.close()
