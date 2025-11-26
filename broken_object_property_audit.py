########################################################
# APISCAN - API Security Scanner                       #
# Licensed under AGPL-V3.0                             #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.0  26-11--2025                             #
########################################################


from __future__ import annotations
import logging
import requests
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from copy import deepcopy
from typing import List, Dict, Any, Optional, Set, Tuple
from tqdm import tqdm
import random
import string
import base64
from report_utils import ReportGenerator
try:
    import jwt
except Exception:
    jwt = None
from openapi_universal import iter_operations as oas_iter_ops, build_request as oas_build_request, SecurityConfig as OASSecurityConfig

#================funtion _headers_to_list _headers_to_list =============
def _headers_to_list(hdrs):
    if hasattr(hdrs, 'getlist'):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())

class ObjectPropertyAuditor:

    #================funtion _b64url _b64url =============
    def _b64url(self, s: str) -> bytes:
        if not isinstance(s, str):
            return b''
        pad = '=' * (-len(s) % 4)
        try:
            return base64.urlsafe_b64decode(s + pad)
        except Exception:
            return b''

    #================funtion _jwt_segments _jwt_segments =============
    def _jwt_segments(self, token: str):
        parts = token.split('.')
        return parts if len(parts) == 3 else None

    #================funtion _jwt_cheap_checks _jwt_cheap_checks =============
    def _jwt_cheap_checks(self, token: str):
        parts = self._jwt_segments(token)
        if not parts:
            return (False, 'not a JWS (header.payload.signature)')
        h_raw = self._b64url(parts[0]).decode('utf-8', 'replace') or '{}'
        try:
            hdr = json.loads(h_raw)
        except Exception:
            hdr = {}
        alg = str(hdr.get('alg', '')).upper()
        if alg == 'NONE':
            return (False, 'alg none')
        if parts[2] == '' or len(parts[2]) == 0:
            return (False, 'empty signature')
        if not self._b64url(parts[2]):
            return (False, 'bad b64 signature')
        return (True, {'alg': alg, 'kid': hdr.get('kid')})

    #================funtion _jwks _jwks =============
    def _jwks(self):
        if not self.jwks_url or not jwt:
            return None
        try:
            import time, requests as _rq
            if not self._jwks_cache or time.time() - self._jwks_loaded_at > 300:
                resp = _rq.get(self.jwks_url, timeout=5)
                resp.raise_for_status()
                self._jwks_cache = resp.json()
                self._jwks_loaded_at = time.time()
            return self._jwks_cache
        except Exception:
            return None

    #================funtion _get_key_for_kid _get_key_for_kid =============
    def _get_key_for_kid(self, kid: str):
        if not jwt:
            return None
        jwks = self._jwks()
        if not jwks:
            return None
        try:
            for k in jwks.get('keys', []):
                if k.get('kid') == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        except Exception:
            return None
        return None

    #================funtion _verify_jwt _verify_jwt =============
    def _verify_jwt(self, token: str, alg: str, kid: Optional[str]):
        if not self.jwt_verify:
            return (None, 'verification disabled')
        if not jwt:
            return (None, 'PyJWT not available')
        try:
            if alg.startswith('HS'):
                if not self.jwt_shared_secret:
                    return (None, 'no shared secret')
                claims = jwt.decode(token, key=self.jwt_shared_secret, algorithms=[alg], audience=self.jwt_expected_audience, issuer=self.jwt_expected_issuer, options={'require': ['exp'], 'verify_signature': True}, leeway=60)
                return (True, claims)
            else:
                key = self._get_key_for_kid(kid) if kid else None
                if not key:
                    jwks = self._jwks()
                    if jwks and jwks.get('keys'):
                        try:
                            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
                        except Exception:
                            key = None
                if not key:
                    return (None, 'signing key not found')
                claims = jwt.decode(token, key=key, algorithms=[alg], audience=self.jwt_expected_audience, issuer=self.jwt_expected_issuer, options={'require': ['exp'], 'verify_signature': True}, leeway=60)
                return (True, claims)
        except jwt.ExpiredSignatureError:
            return (False, 'expired')
        except jwt.InvalidAudienceError:
            return (False, 'aud mismatch')
        except jwt.InvalidIssuerError:
            return (False, 'iss mismatch')
        except Exception as e:
            return (False, str(e))

    #================funtion _extract_jwts_from_text _extract_jwts_from_text =============
    def _extract_jwts_from_text(self, text: str):
        pat = self.SENSITIVE_PATTERNS.get('jwt')
        if not pat:
            return []
        tokens = re.findall(pat, text or '', flags=re.IGNORECASE)
        out = []
        for tok in tokens:
            tok = tok.strip()
            if tok.count('.') == 2 and len(tok) > 80:
                out.append(tok)
        return list(dict.fromkeys(out))

    #================funtion _scan_data_for_jwts _scan_data_for_jwts =============
    def _scan_data_for_jwts(self, data):
        found = []

        #================funtion _walk _walk =============
        def _walk(x):
            if isinstance(x, dict):
                for v in x.values():
                    _walk(v)
            elif isinstance(x, list):
                for i in x:
                    _walk(i)
            elif isinstance(x, str):
                for t in self._extract_jwts_from_text(x):
                    found.append(t)
        _walk(data)
        return list(dict.fromkeys(found))

    #================funtion _check_and_log_jwt _check_and_log_jwt =============
    def _check_and_log_jwt(self, token: str, endpoint: dict, response):
        ok, meta = self._jwt_cheap_checks(token)
        if not ok:
            self._log_issue(endpoint['url'], 'JWT Missing/Invalid Signature', f'{meta}', 'High', {'token_sample': token[:32] + '...'}, response=response, request_payload=None)
            return
        alg = meta.get('alg', '')
        kid = meta.get('kid')
        if self.jwt_expected_algs and alg not in self.jwt_expected_algs:
            self._log_issue(endpoint['url'], 'JWT Unexpected alg', f'alg={alg} not in {self.jwt_expected_algs}', 'Medium', {'token_alg': alg}, response=response, request_payload=None)
            return
        verified, detail = self._verify_jwt(token, alg, kid)
        if verified is False:
            self._log_issue(endpoint['url'], 'JWT Invalid Signature', str(detail), 'High', {'token_alg': alg, 'kid': kid}, response=response, request_payload=None)
        elif verified is None and self.jwt_verify:
            self._log_issue(endpoint['url'], 'JWT Verification Skipped', str(detail), 'Low', {'token_alg': alg, 'kid': kid}, response=response, request_payload=None)
    SENSITIVE_FIELDS = ['password', 'token', 'secret', 'api_key', 'credit_card', 'ssn', 'email', 'is_admin', 'role', 'permissions', 'auth_token', 'session', 'key', 'credential', 'private', 'certificate', 'signature', 'jwt', 'bearer', 'oauth', 'access', 'refresh', 'authorization', 'client_secret', 'identity', 'personal', 'birthdate', 'address', 'phone', 'bank', 'account', 'salary', 'income', 'tax', 'health', 'medical', 'insurance', 'biometric']
    SENSITIVE_PATTERNS = {'email': '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', 'credit_card': '\\b(?:\\d{4}[- ]?){3}\\d{4}\\b', 'ssn': '\\b\\d{3}-\\d{2}-\\d{4}\\b', 'jwt': '\\beyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*\\b', 'api_key': '\\b[a-fA-F0-9]{32,}\\b', 'auth_token': '\\b[a-fA-F0-9]{64,}\\b'}

    #================funtion __init__ __init__ =============
    def __init__(self, base_url: str, session: Optional[requests.Session]=None, *, show_progress: bool=True, test_user_id: Optional[str]=None, test_admin_id: Optional[str]=None, swagger_spec: Optional[dict]=None, security_config: Optional[OASSecurityConfig]=None, jwt_verify: bool=False, jwks_url: Optional[str]=None, jwt_expected_issuer: Optional[str]=None, jwt_expected_audience: Optional[str]=None, jwt_expected_algs: Optional[list]=None, jwt_shared_secret: Optional[str]=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.issues: List[Dict[str, Any]] = []
        self.show_progress = show_progress
        self.test_user_id = test_user_id or '1001'
        self.test_admin_id = test_admin_id or '9999'
        self.tested_endpoints: Set[str] = set()
        self.jwt_verify = bool(jwt_verify)
        self.jwks_url = jwks_url
        self.jwt_expected_issuer = jwt_expected_issuer
        self.jwt_expected_audience = jwt_expected_audience
        self.jwt_expected_algs = jwt_expected_algs or ['RS256', 'ES256', 'HS256']
        self.jwt_shared_secret = jwt_shared_secret
        self._jwks_cache = None
        self._jwks_loaded_at = 0.0
        self.swagger_spec = swagger_spec
        self.security_config = security_config
        self._op_index = {}
        try:
            if self.swagger_spec:
                for _op in oas_iter_ops(self.swagger_spec):
                    key = (_op['method'].upper(), _op['path'])
                    self._op_index[key] = _op
        except Exception:
            self._op_index = {}

    #================funtion _ptype_fmt_def_ex _ptype_fmt_def_ex =============
    def _ptype_fmt_def_ex(self, p: dict):
        sch = p.get('schema') or {}
        return (sch.get('type', p.get('type', 'string')), sch.get('format', p.get('format', '')), sch.get('default', p.get('default')), sch.get('example', p.get('example')))

    #================funtion _sample_for_param _sample_for_param =============
    def _sample_for_param(self, pname: str, ptype: str='string', pformat: str='', default=None, example=None):
        if example is not None:
            return example
        if default is not None:
            return default
        n = (pname or '').lower()
        if ptype in ('integer', 'number'):
            return 1
        if ptype == 'boolean':
            return True
        if 'email' in n:
            return 'user@example.com'
        if 'uuid' in n or 'guid' in n or pformat == 'uuid':
            return '550e8400-e29b-41d4-a716-446655440000'
        if n.endswith('id') or n == 'id':
            return 1
        if 'token' in n or 'key' in n:
            return 'test_token_123'
        if 'role' in n:
            return 'user'
        if 'name' in n:
            return 'test_name'
        if 'phone' in n:
            return '+31600000000'
        return 'test_value'

    #================funtion test_object_properties test_object_properties =============
    def test_object_properties(self, endpoints: List[Dict[str, Any]]):
        unique_endpoints = []
        seen_endpoints = set()
        for endpoint in endpoints:
            norm_ep = self._normalize_endpoint(endpoint)
            if not norm_ep:
                continue
            identifier = f"{norm_ep['method']}:{norm_ep['url']}"
            if identifier not in seen_endpoints:
                seen_endpoints.add(identifier)
                unique_endpoints.append(norm_ep)
        iterator = unique_endpoints
        if self.show_progress:
            iterator = tqdm(unique_endpoints, desc='Broken Object Property tests', unit='endpoint')
        for endpoint in iterator:
            self._test_mass_assignment(endpoint)
            self._test_idor(endpoint)
            self._test_property_manipulation(endpoint)
            self._test_data_exposure(endpoint)
            self._test_insecure_direct_reference(endpoint)
        return self.issues

    #================funtion _normalize_endpoint _normalize_endpoint =============
    def _normalize_endpoint(self, endpoint):
        if 'url' in endpoint and 'method' in endpoint:
            return endpoint
        if 'path' in endpoint and 'method' in endpoint:
            test_obj = self._create_test_object(endpoint)
            m = endpoint['method'].upper()
            pth = endpoint['path']
            op = None
            try:
                op = self._op_index.get((m, pth))
            except Exception:
                op = None
            return {'url': pth, 'method': m, 'test_object': test_obj, 'original_endpoint': endpoint, 'op': op}
        logging.warning(f'Invalid endpoint format: {list(endpoint.keys())}')
        return None

    #================funtion _create_test_object _create_test_object =============
    def _create_test_object(self, endpoint):
        test_obj = {}
        if 'parameters' in endpoint:
            for param in endpoint['parameters']:
                loc = (param.get('in') or '').lower()
                if loc in ('path', 'query', 'body'):
                    ptype, pformat, pdef, pex = self._ptype_fmt_def_ex(param)
                    test_obj[param['name']] = self._sample_for_param(param.get('name'), ptype, pformat, pdef, pex)
        path = endpoint.get('path', '')
        if '{id}' in path and 'id' not in test_obj:
            test_obj['id'] = self.test_user_id
        if '{userId}' in path and 'userId' not in test_obj:
            test_obj['userId'] = self.test_user_id
        if '{adminId}' in path and 'adminId' not in test_obj:
            test_obj['adminId'] = self.test_admin_id
        return test_obj

    #================funtion _generate_test_value _generate_test_value =============
    def _generate_test_value(self, param):
        if 'schema' in param and 'type' in param['schema']:
            param_type = param['schema']['type']
            if param_type == 'integer':
                return random.randint(1000, 9999)
            if param_type == 'string':
                if 'format' in param['schema'] and param['schema']['format'] == 'email':
                    return 'test.user@example.com'
                if 'format' in param['schema'] and param['schema']['format'] == 'date':
                    return '2023-01-15'
                return f"test_{param['name']}_{random.randint(100, 999)}"
            if param_type == 'boolean':
                return True
        return 'test_value'

    #================funtion _test_data_exposure _test_data_exposure =============
    def _test_data_exposure(self, endpoint):
        url = self._build_url(endpoint['url'], endpoint.get('test_object', {}))
        try:
            response = self._send_request(endpoint['method'], url, endpoint=endpoint)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                sensitive_fields = []
                pattern_matches = []
                if isinstance(data, (dict, list)):
                    sensitive_fields = self._find_sensitive_fields(data)
                    pattern_matches = self._find_pattern_exposure(response.text)
                if sensitive_fields or pattern_matches:
                    try:
                        tokens = []
                        if isinstance(data, (dict, list)):
                            tokens.extend(self._scan_data_for_jwts(data))
                        tokens.extend(self._extract_jwts_from_text(response.text or ''))
                        tokens = list(dict.fromkeys(tokens))
                        for tok in tokens[:5]:
                            self._check_and_log_jwt(tok, endpoint, response)
                    except Exception:
                        pass
                    self._log_issue(endpoint['url'], 'Excessive Data Exposure', f"Sensitive fields in response: {', '.join(sensitive_fields)}. Pattern matches: {', '.join(pattern_matches)}", 'High', {'exposed_fields': sensitive_fields, 'pattern_matches': pattern_matches, 'response_sample': data}, response=response, request_payload=None)
        except Exception as e:
            logging.error(f'Error testing data exposure on {url}: {e}')

    #================funtion _test_mass_assignment _test_mass_assignment =============
    def _test_mass_assignment(self, endpoint):
        if endpoint['method'] not in ['POST', 'PUT', 'PATCH']:
            return
        malicious_fields = {'is_admin': True, 'role': 'administrator', 'password': 'H4cked!123', 'permissions': 'all', 'isActive': True, 'isVerified': True, 'accountType': 'premium', 'balance': 999999, 'emailVerified': True, 'twoFactorEnabled': False}
        original_obj = endpoint.get('test_object', {})
        malicious_obj = deepcopy(original_obj)
        malicious_obj.update(malicious_fields)
        url = self._build_url(endpoint['url'], original_obj)
        try:
            response = self._send_request(endpoint['method'], url, endpoint=endpoint, json=malicious_obj)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                if isinstance(data, dict):
                    changed = []
                    for field, expected_value in malicious_fields.items():
                        if field in data and data[field] == expected_value:
                            changed.append(field)
                    if changed:
                        self._log_issue(endpoint['url'], 'Mass Assignment', f"Modified restricted fields: {', '.join(changed)}", 'Critical', {'sent': malicious_obj, 'received': data}, response=response, request_payload=malicious_obj)
        except Exception as e:
            logging.error(f'Error testing mass assignment on {url}: {e}')
            self._log_issue(endpoint['url'], 'Test Error', str(e), 'Low')

    #================funtion _test_property_manipulation _test_property_manipulation =============
    def _test_property_manipulation(self, endpoint):
        if endpoint['method'] not in ['PUT', 'PATCH']:
            return
        original_obj = endpoint.get('test_object', {})
        legit_obj = deepcopy(original_obj)
        malicious_obj = deepcopy(original_obj)
        fields_to_test = {'email': 'attacker@example.com', 'role': 'admin', 'permissions': 'all', 'isAdmin': True, 'accountType': 'premium', 'balance': 999999, 'userId': self.test_admin_id, 'ownerId': self.test_admin_id}
        for field, malicious_value in fields_to_test.items():
            if field in malicious_obj or field.lower() in malicious_obj:
                malicious_obj[field] = malicious_value
        url = self._build_url(endpoint['url'], original_obj)
        try:
            legit_resp = self._send_request(endpoint['method'], url, endpoint=endpoint, json=legit_obj)
            malicious_resp = self._send_request(endpoint['method'], url, endpoint=endpoint, json=malicious_obj)
            if legit_resp.status_code == 200 and malicious_resp.status_code == 200:
                legit_data = self._safe_json(legit_resp)
                malicious_data = self._safe_json(malicious_resp)
                if isinstance(legit_data, dict) and isinstance(malicious_data, dict):
                    changed = []
                    for field, malicious_value in fields_to_test.items():
                        legit_value = legit_data.get(field)
                        malicious_value_received = malicious_data.get(field)
                        if legit_value != malicious_value_received and malicious_value_received == malicious_value:
                            changed.append(field)
                    if changed:
                        self._log_issue(endpoint['url'], 'Property Manipulation', f"Unauthorized changes to: {', '.join(changed)}", 'High', {'original': legit_data, 'malicious': malicious_data, 'changed_fields': changed}, response=malicious_resp, request_payload=malicious_obj)
        except Exception as e:
            logging.error(f'Error testing property manipulation on {url}: {e}')
            self._log_issue(endpoint['url'], 'Test Error', str(e), 'Low')

    #================funtion _test_idor _test_idor =============
    def _test_idor(self, endpoint):
        self._test_idor_improved(endpoint)

    #================funtion _test_idor_improved _test_idor_improved =============
    def _test_idor_improved(self, endpoint):
        if endpoint['method'] not in ['GET', 'PUT', 'DELETE', 'PATCH']:
            return
        original_obj = endpoint.get('test_object', {})
        path_params = re.findall('\\{(\\w+)\\}', endpoint['url'])
        if not path_params:
            return
        for param_name in path_params:
            self._test_single_parameter_idor(endpoint, param_name, original_obj)
        self._test_all_parameters_idor(endpoint, path_params, original_obj)

    #================funtion _test_single_parameter_idor _test_single_parameter_idor =============
    def _test_single_parameter_idor(self, endpoint, param_name, original_obj):
        original_value = original_obj.get(param_name)
        if not original_value:
            return
        test_ids = self._get_context_aware_test_ids(param_name, original_value)
        for test_id in test_ids:
            test_obj = deepcopy(original_obj)
            test_obj[param_name] = test_id
            test_url = self._build_url(endpoint['url'], test_obj)
            self._execute_idor_test(endpoint, test_url, test_obj, param_name, test_id)

    #================funtion _test_all_parameters_idor _test_all_parameters_idor =============
    def _test_all_parameters_idor(self, endpoint, path_params, original_obj):
        test_obj = deepcopy(original_obj)
        changed_params = {}
        for param_name in path_params:
            original_value = original_obj.get(param_name)
            if original_value:
                test_ids = self._get_context_aware_test_ids(param_name, original_value)
                if test_ids:
                    test_obj[param_name] = test_ids[0]
                    changed_params[param_name] = test_ids[0]
        if changed_params:
            test_url = self._build_url(endpoint['url'], test_obj)
            self._execute_idor_test(endpoint, test_url, test_obj, 'multiple', changed_params)

    #================funtion _get_context_aware_test_ids _get_context_aware_test_ids =============
    def _get_context_aware_test_ids(self, param_name, original_value):
        param_lower = param_name.lower()
        if original_value and str(original_value).isdigit():
            original_num = int(original_value)
            return [str(original_num + 1), str(original_num - 1), str(original_num + 100), '0', '-1', '999999999']
        elif original_value and re.match('^[0-9a-f-]{36}$', str(original_value)):
            return ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff', '550e8400-e29b-41d4-a716-446655440000']
        else:
            return ['admin', 'root', 'test', 'null', 'undefined', '../../etc/passwd', '../../../etc/passwd']

    #================funtion _execute_idor_test _execute_idor_test =============
    def _execute_idor_test(self, endpoint, test_url, test_obj, param_name, test_id):
        try:
            original_obj = endpoint.get('test_object', {})
            baseline_url = self._build_url(endpoint['url'], original_obj)
            baseline_response = self._send_request(endpoint['method'], baseline_url, endpoint=endpoint)
            if baseline_response.status_code not in [200, 201, 204]:
                return
            baseline_data = self._safe_json(baseline_response)
            test_response = self._send_request(endpoint['method'], test_url, endpoint=endpoint)
            if test_response.status_code in [200, 201, 204]:
                test_data = self._safe_json(test_response)
                is_different, diff_description = self._compare_responses_improved(baseline_data, test_data, endpoint)
                if is_different:
                    self._log_idor_issue(endpoint, test_url, param_name, test_id, baseline_data, test_data, test_response, is_critical=True)
                elif test_response.status_code == 200:
                    self._log_idor_issue(endpoint, test_url, param_name, test_id, baseline_data, test_data, test_response, is_critical=False)
        except Exception as e:
            logging.error(f'Error executing IDOR test on {test_url}: {e}')

    #================funtion _compare_responses_improved _compare_responses_improved =============
    def _compare_responses_improved(self, resp1, resp2, endpoint):
        if type(resp1) != type(resp2):
            return (True, 'Different types')
        if resp1 is None or resp2 is None:
            return (True, 'One response is None')
        if isinstance(resp1, dict) and isinstance(resp2, dict):
            return self._compare_dicts_improved(resp1, resp2, endpoint)
        elif isinstance(resp1, list) and isinstance(resp2, list):
            return self._compare_lists_improved(resp1, resp2, endpoint)
        else:
            return (resp1 != resp2, 'Different primitive values')

    #================funtion _compare_dicts_improved _compare_dicts_improved =============
    def _compare_dicts_improved(self, dict1, dict2, endpoint):
        differences = []
        keys1 = set(dict1.keys())
        keys2 = set(dict2.keys())
        if keys1 != keys2:
            missing = keys1 - keys2
            extra = keys2 - keys1
            if missing:
                differences.append(f'Missing keys: {missing}')
            if extra:
                differences.append(f'Extra keys: {extra}')
        common_keys = keys1.intersection(keys2)
        volatile_fields = {'created_at', 'updated_at', 'timestamp', 'last_modified', 'last_login'}
        for key in common_keys:
            if key in volatile_fields:
                continue
            val1 = dict1[key]
            val2 = dict2[key]
            if val1 != val2:
                if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                    if abs(val1 - val2) < 0.01:
                        continue
                differences.append(f"Field '{key}': {val1} != {val2}")
        return (len(differences) > 0, '; '.join(differences))

    #================funtion _compare_lists_improved _compare_lists_improved =============
    def _compare_lists_improved(self, list1, list2, endpoint):
        if len(list1) != len(list2):
            return (True, f'Different lengths: {len(list1)} vs {len(list2)}')
        differences = []
        for i in range(min(len(list1), len(list2))):
            is_diff, diff_desc = self._compare_responses_improved(list1[i], list2[i], endpoint)
            if is_diff:
                differences.append(f'Index {i}: {diff_desc}')
        return (len(differences) > 0, '; '.join(differences))

    #================funtion _log_idor_issue _log_idor_issue =============
    def _log_idor_issue(self, endpoint, test_url, param_name, test_id, baseline_data, response_data, response, is_critical=True):
        issue_type = 'Insecure Direct Object Reference (IDOR)'
        severity = 'Critical' if is_critical else 'Medium'
        description = f'Unauthorized access to resource using {param_name}={test_id}'
        if param_name == 'multiple' and isinstance(test_id, (dict, list)):
            req_payload = test_id
        else:
            req_payload = {param_name: test_id}
        self._log_issue(endpoint['url'], issue_type, description, severity, {'parameter_tested': param_name, 'test_value': test_id, 'baseline_sample': baseline_data, 'response_sample': response_data, 'response_code': response.status_code}, response=response, request_payload=req_payload)

    #================funtion _test_insecure_direct_reference _test_insecure_direct_reference =============
    def _test_insecure_direct_reference(self, endpoint):
        if endpoint['method'] not in ['GET', 'POST']:
            return
        url = self._build_url(endpoint['url'], endpoint.get('test_object', {}))
        try:
            response = self._send_request(endpoint['method'], url, endpoint=endpoint)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                internal_refs = self._find_internal_references(data)
                if internal_refs:
                    self._log_issue(endpoint['url'], 'Insecure Direct Object Reference', f"Internal references exposed: {', '.join(internal_refs)}", 'Medium', {'internal_references': internal_refs}, response=response, request_payload=None)
        except Exception as e:
            logging.error(f'Error testing insecure direct reference on {url}: {e}')

    #================funtion _send_request _send_request =============
    def _send_request(self, method, url, endpoint=None, **kwargs):
        headers = kwargs.pop('headers', {}) or {}
        try:
            hdrs_lower = {k.lower(): v for k, v in headers.items()} if headers else {}
            auth = hdrs_lower.get('authorization') or ''
            if auth.lower().startswith('bearer '):
                pass
        except Exception:
            pass
        try:
            if self.swagger_spec and isinstance(endpoint, dict) and endpoint.get('op'):
                try:
                    req = oas_build_request(self.swagger_spec, self.base_url, endpoint['op'], self.security_config)
                except TypeError:
                    req = oas_build_request(self.swagger_spec, self.base_url, endpoint['op'])
                req_headers = dict(req.get('headers') or {})
                req_params = dict(req.get('params') or {})
                req_cookies = dict(req.get('cookies') or {})
                req_json = req.get('json', None)
                req_data = req.get('data', None)
                m = req.get('method', method) or method
                merged_headers = dict(req_headers)
                merged_headers.update(headers)
                headers = merged_headers
                final_url = url or req.get('url')
                json_payload = kwargs.pop('json', None)
                data_payload = kwargs.pop('data', None)
                if json_payload is None and data_payload is None:
                    json_payload = req_json
                    data_payload = req_data
                if json_payload is not None and 'content-type' not in {k.lower() for k in headers.keys()}:
                    headers['Content-Type'] = headers.get('Content-Type', 'application/json')
                resp = self.session.request(method=m, url=final_url, headers=headers, params=req_params, cookies=req_cookies, json=json_payload, data=data_payload, timeout=15)
                return resp
        except Exception as _e:
            logging.debug(f'Universal request build failed, falling back: {_e}')
        if kwargs.get('json') is not None and 'content-type' not in {k.lower() for k in headers.keys()}:
            headers['Content-Type'] = 'application/json'
        resp = self.session.request(method=method, url=url, headers=headers, timeout=15, **kwargs)
        return resp

    #================funtion _safe_json _safe_json =============
    def _safe_json(self, response):
        try:
            return response.json()
        except Exception:
            try:
                text = response.text.strip()
                if text.startswith('[') and text.endswith(']'):
                    return json.loads(text)
            except:
                pass
            return {}

    #================funtion _build_url _build_url =============
    def _build_url(self, template, params):
        url = template
        for k, v in params.items():
            url = url.replace(f'{{{k}}}', str(v))
        if not url.startswith(('http://', 'https://')):
            url = urljoin(f'{self.base_url}/', url.lstrip('/'))
        return url

    #================funtion _find_sensitive_fields _find_sensitive_fields =============
    def _find_sensitive_fields(self, data):
        sensitive = []

        #================funtion _scan _scan =============
        def _scan(obj, path=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    field_lower = k.lower()
                    for sensitive_field in self.SENSITIVE_FIELDS:
                        if sensitive_field in field_lower:
                            sensitive.append(f'{path}{k}')
                            break
                    _scan(v, f'{path}{k}.')
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f'{path}[{i}].')
        _scan(data)
        return sensitive

    #================funtion _find_pattern_exposure _find_pattern_exposure =============
    def _find_pattern_exposure(self, text):
        matches = []
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern_name)
        return matches

    #================funtion _find_internal_references _find_internal_references =============
    def _find_internal_references(self, data):
        internal_refs = []

        #================funtion _scan _scan =============
        def _scan(obj, path=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_lower = k.lower()
                    if any((term in key_lower for term in ['internal', 'db', 'database', 'ref', '_id'])):
                        if isinstance(v, (str, int)) and v:
                            internal_refs.append(f'{path}{k}: {v}')
                    _scan(v, f'{path}{k}.')
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f'{path}[{i}].')
        _scan(data)
        return internal_refs

    #================funtion _log_issue _log_issue =============
    def _log_issue(self, endpoint, issue_type, description, severity, data=None, response=None, request_payload=None):
        entry = {}
        if response is not None:
            try:
                req_body = request_payload
                if req_body is None and getattr(response, 'request', None) is not None:
                    body = response.request.body
                    if body:
                        if isinstance(body, bytes):
                            try:
                                req_body = body.decode('utf-8', errors='replace')
                            except Exception:
                                req_body = str(body)
                        else:
                            req_body = body
                if req_body is None:
                    try:
                        q = urlparse(response.url).query
                        if q:
                            req_body = f'?{q}'
                    except Exception:
                        pass
                entry = {'method': response.request.method if response.request else '', 'url': response.url, 'status_code': response.status_code, 'request_headers': _headers_to_list(response.request.headers) if response.request else [], 'request_body': req_body, 'response_headers': _headers_to_list(response.headers), 'response_body': response.text[:4096], 'request_cookies': self.session.cookies.get_dict(), 'response_cookies': response.cookies.get_dict()}
            except Exception as e:
                logging.error(f'Error logging issue details: {e}')
        issue_record = {'endpoint': endpoint, 'type': issue_type, 'description': description, 'severity': severity, 'timestamp': datetime.now().isoformat(), 'data': data or {}}
        issue_record.update(entry)
        self.issues.append(issue_record)

    #================funtion generate_report generate_report =============
    def generate_report(self, fmt='markdown'):
        gen = ReportGenerator(issues=self.issues, scanner='ObjectProperty (API03)', base_url=self.base_url)
        return gen.generate_markdown() if fmt == 'markdown' else gen.generate_json()

    #================funtion save_report save_report =============
    def save_report(self, path: str, fmt: str='html'):
        ReportGenerator(self.issues, scanner='ObjectProperty (API03)', base_url=self.base_url).save(path, fmt=fmt)
