# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
from __future__ import annotations
import base64
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
import requests
import urllib3
from tqdm import tqdm
from report_utils import ReportGenerator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _headers_to_list(hdrs) -> List[Tuple[str, str]]:
    if hasattr(hdrs, 'getlist'):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items()) if hdrs else []

class AuthorizationAuditor:

    def __init__(self, base_url: str, swagger_data: Optional[Dict[str, Any]]=None, session: Optional[requests.Session]=None, roles_config: Optional[Dict[str, Dict[str, Any]]]=None, request_templates: Optional[Dict[str, Any]]=None) -> None:
        if isinstance(swagger_data, requests.Session):
            session, swagger_data = (swagger_data, None)
        parsed_url = urlparse(base_url)
        if not parsed_url.scheme:
            self.base_url = f'https://{base_url}'.rstrip('/') + '/'
        else:
            self.base_url = base_url.rstrip('/') + '/'
        self.session = session or self._make_session()
        self.swagger_data = swagger_data
        self.authz_issues: List[Dict[str, Any]] = []
        self.discovered_endpoints = self._parse_swagger_data() if swagger_data else self._discover_endpoints()
        self.roles: Dict[str, Dict[str, Any]] = roles_config or {'anonymous': {'token': None}, 'user': {'username': 'testuser', 'password': 'testpass', 'token': None}, 'admin': {'username': 'admin', 'password': 'adminpass', 'token': None}}
        self.request_templates = request_templates or self._default_request_templates()
        self._get_all_tokens()

    def _default_request_templates(self) -> Dict[str, Any]:
        return {'login': {'method': 'POST', 'path': '/api/auth/login', 'headers': {'Content-Type': 'application/json'}, 'body': {'username': '{username}', 'password': '{password}'}}, 'forget-password': {'method': 'POST', 'path': '/identity/api/auth/forget-password', 'headers': {'Content-Type': 'application/json'}, 'body': {'email': 'test@example.com'}}, 'user_profile': {'method': 'GET', 'path': '/api/users/{userId}', 'headers': {}}, 'admin_config': {'method': 'GET', 'path': '/api/admin/config', 'headers': {}}}

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({'User-Agent': 'APISecurityScanner/2.1', 'Accept': 'application/json'})
        s.verify = False
        return s

    def _parse_swagger_data(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(self.swagger_data, dict):
            return out
        for path, verbs in self.swagger_data.get('paths', {}).items():
            for verb, meta in verbs.items():
                if verb.upper() not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
                    continue
                sensitive = self._is_sensitive(meta, path)
                security = meta.get('security', [])
                parameters = meta.get('parameters', [])
                request_body = None
                if 'requestBody' in meta:
                    request_body = meta['requestBody']
                out.append({'url': urljoin(self.base_url, path), 'methods': [verb.upper()], 'sensitive': sensitive, 'security': security, 'parameters': parameters, 'path': path, 'operation_id': meta.get('operationId', ''), 'request_body': request_body})
        return out

    def _discover_endpoints(self) -> List[Dict[str, Any]]:
        common_paths = ['/api/admin', '/api/users', '/admin', '/users', '/api/v1/users', '/api/v1/admin', '/api/auth', '/auth', '/api/config', '/config', '/api/settings', '/settings', '/identity/api/auth/forget-password', '/identity/api/auth/login', '/workshop/api/shop/orders']
        discovered = []
        for p in common_paths:
            methods = ['GET']
            if 'auth' in p or 'login' in p or 'forget-password' in p:
                methods = ['POST']
            elif 'orders' in p:
                methods = ['GET', 'POST', 'PUT']
            discovered.append({'url': urljoin(self.base_url, p), 'methods': methods, 'sensitive': any((keyword in p for keyword in ['admin', 'config', 'settings', 'auth', 'orders'])), 'security': [], 'parameters': [], 'path': p, 'operation_id': ''})
        return discovered

    def _is_sensitive(self, meta: Dict[str, Any], path: str='') -> bool:
        indicators = ('admin', 'delete', 'write', 'internal', 'config', 'settings', 'password', 'secret', 'key', 'orders')
        tags = ' '.join(meta.get('tags', [])).lower()
        if any((indicator in tags for indicator in indicators)):
            return True
        operation_id = meta.get('operationId', '').lower()
        if any((indicator in operation_id for indicator in indicators)):
            return True
        if any((indicator in path.lower() for indicator in indicators)):
            return True
        for field in ['summary', 'description']:
            if field in meta and any((indicator in meta[field].lower() for indicator in indicators)):
                return True
        return False

    def _get_all_tokens(self) -> None:
        for role, cfg in self.roles.items():
            if role == 'anonymous':
                continue
            token = self._authenticate(cfg.get('username'), cfg.get('password'), cfg.get('auth_endpoint', '/api/auth/login'))
            if token:
                cfg['token'] = token
                if role == 'user':
                    self.session.headers.update({'Authorization': f'Bearer {token}'})

    def _authenticate(self, username: Optional[str], password: Optional[str], auth_endpoint: str) -> Optional[str]:
        if not username or not password:
            return None
        try:
            auth_url = urljoin(self.base_url, auth_endpoint)
            payload = {'username': username, 'password': password}
            response = self.session.post(auth_url, json=payload, timeout=10, verify=False)
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    if 'token' in json_response:
                        return json_response['token']
                    elif 'access_token' in json_response:
                        return json_response['access_token']
                    elif 'accessToken' in json_response:
                        return json_response['accessToken']
                    elif 'jwt' in json_response:
                        return json_response['jwt']
                    elif 'authorization' in response.headers:
                        auth_header = response.headers['authorization']
                        if auth_header.startswith('Bearer '):
                            return auth_header[7:]
                except (json.JSONDecodeError, KeyError):
                    pass
            response = self.session.post(auth_url, data={'username': username, 'password': password}, timeout=10, verify=False)
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    if 'token' in json_response:
                        return json_response['token']
                except (json.JSONDecodeError, KeyError):
                    pass
        except (requests.RequestException, ValueError):
            pass
        return None

    def _prepare_request_data(self, endpoint: Dict[str, Any], method: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        json_data = None
        form_data = None
        endpoint_path = endpoint.get('path', '')
        template_found = False
        for template_name, template in self.request_templates.items():
            if template['path'] in endpoint_path:
                if 'body' in template:
                    json_data = template['body'].copy()
                    for key, value in json_data.items():
                        if isinstance(value, str) and '{username}' in value and ('user' in self.roles):
                            json_data[key] = value.replace('{username}', self.roles['user']['username'])
                        if isinstance(value, str) and '{password}' in value and ('user' in self.roles):
                            json_data[key] = value.replace('{password}', self.roles['user']['password'])
                template_found = True
                break
        if not template_found and endpoint.get('request_body'):
            content = endpoint['request_body'].get('content', {})
            if 'application/json' in content:
                schema = content['application/json'].get('schema', {})
                json_data = self._generate_example_from_schema(schema)
        if method.upper() == 'GET':
            return (None, None)
        return (json_data, form_data)

    def _generate_example_from_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        example = {}
        if 'properties' in schema:
            for prop_name, prop_schema in schema['properties'].items():
                prop_type = prop_schema.get('type', 'string')
                if prop_type == 'string':
                    if 'format' in prop_schema and prop_schema['format'] == 'email':
                        example[prop_name] = 'test@example.com'
                    elif 'format' in prop_schema and prop_schema['format'] == 'date-time':
                        example[prop_name] = datetime.now().isoformat()
                    else:
                        example[prop_name] = f'test_{prop_name}'
                elif prop_type == 'number':
                    example[prop_name] = 123.45
                elif prop_type == 'integer':
                    example[prop_name] = 123
                elif prop_type == 'boolean':
                    example[prop_name] = True
                elif prop_type == 'array':
                    example[prop_name] = ['item1', 'item2']
        return example

    def test_authorization(self, show_progress: bool=True) -> List[Dict[str, Any]]:
        endpoints = self.discovered_endpoints or []
        if not endpoints:
            print('Warning: No endpoints discovered for testing')
            return []
        iterator = tqdm(endpoints, desc='Testing endpoints', unit='endpoint') if show_progress else endpoints
        for ep in iterator:
            url = ep.get('url')
            methods = ep.get('methods', ['GET'])
            if show_progress:
                tqdm.write(f'Testing {methods} {url}')
            self._test_endpoint(ep)
        return self._filtered_issues()

    def _test_endpoint(self, ep: Dict[str, Any]) -> None:
        for verb in ep.get('methods', ['GET']):
            self._do_request(ep, verb, role='anonymous', should_access=not ep.get('sensitive', False))
            if 'user' in self.roles:
                self._do_request(ep, verb, role='user', should_access=not ep.get('sensitive', False))
            if 'admin' in self.roles:
                self._do_request(ep, verb, role='admin', should_access=True)

    def _do_request(self, ep: Dict[str, Any], verb: str, role: str, should_access: bool) -> None:
        headers = {'User-Agent': 'APISecurityScanner/2.1', 'Accept': 'application/json'}
        if role != 'anonymous' and self.roles[role].get('token'):
            headers['Authorization'] = f"Bearer {self.roles[role]['token']}"
        json_data, form_data = self._prepare_request_data(ep, verb)
        try:
            r = self.session.request(method=verb, url=ep['url'], headers=headers, json=json_data, data=form_data, timeout=10, verify=False)
            allowed = 200 <= r.status_code < 400
            if r.status_code in (400, 404):
                return
            if allowed != should_access:
                desc = 'Unauthorized access' if allowed else 'Access denied'
                sev = 'High' if allowed else 'Medium'
                self._log_issue(url=ep['url'], description=f'{desc} - {verb} as {role} (expected: {should_access})', severity=sev, details={'method': verb, 'role': role, 'expected_access': should_access}, response_obj=r)
        except requests.Timeout:
            self._log_issue(url=ep['url'], description=f'Request timeout - {verb} as {role}', severity='Low', details={'method': verb, 'role': role})
        except requests.ConnectionError:
            self._log_issue(url=ep['url'], description=f'Connection error - {verb} as {role}', severity='Low', details={'method': verb, 'role': role})
        except Exception as exc:
            self._log_issue(url=ep['url'], description=f'Request error - {verb} as {role}: {exc}', severity='Low', details={'method': verb, 'role': role})

    def _filtered_issues(self) -> List[Dict[str, Any]]:
        seen: Set[Tuple[str, str, str, int]] = set()
        unique_issues = []
        for issue in self.authz_issues:
            if not issue.get('status_code'):
                continue
            key = (issue['endpoint'], issue['method'], issue['description'], issue['status_code'])
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        return unique_issues

    def _log_issue(self, url: str, description: str, severity: str, details: Optional[Dict[str, Any]]=None, response_obj: Optional[requests.Response]=None) -> None:
        details = details or {}
        status_code = getattr(response_obj, 'status_code', None)
        if status_code is None or status_code == 0 or status_code in (400, 404):
            return
        entry: Dict[str, Any] = {'url': url, 'endpoint': urlparse(url).path, 'method': details.get('method', 'GET'), 'description': description, 'severity': severity, 'status_code': status_code, 'timestamp': datetime.now().isoformat(), 'request_headers': {}, 'response_headers': {}, 'request_cookies': {}, 'response_cookies': {}, 'request_body': None, 'response_body': None}
        if response_obj is not None:
            entry['response_headers'] = dict(response_obj.headers)
            entry['response_body'] = response_obj.text[:2048]
            entry['response_cookies'] = response_obj.cookies.get_dict()
            if response_obj.request is not None:
                entry['request_headers'] = dict(response_obj.request.headers)
                entry['request_body'] = response_obj.request.body[:1024] if response_obj.request.body and isinstance(response_obj.request.body, (str, bytes)) else response_obj.request.body
                entry['request_cookies'] = self.session.cookies.get_dict()
        for k, v in details.items():
            if k not in entry:
                entry[k] = v
        self.authz_issues.append(entry)

    def generate_report(self, fmt: str='html') -> str:
        issues = self._filtered_issues()
        gen = ReportGenerator(issues, scanner='Authorization', base_url=self.base_url)
        return gen.generate_html() if fmt == 'html' else gen.generate_markdown()

    def save_report(self, path: str, fmt: str='html') -> None:
        issues = self._filtered_issues()
        ReportGenerator(issues, scanner='Authorization', base_url=self.base_url).save(path, fmt=fmt)
