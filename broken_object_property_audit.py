##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
import logging
import requests
import json
from datetime import datetime
from urllib.parse import urljoin
from copy import deepcopy
from report_utils import ReportGenerator

def _headers_to_list(hdrs):
    # Set-Cookie
    if hasattr(hdrs, "getlist"):  # urllib3.HTTPHeaderDict
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())


class ObjectPropertyAuditor:
    """Test Broken Object Property Level Authorization (API3:2023)"""
    
    SENSITIVE_FIELDS = [
        'password', 'token', 'secret', 
        'api_key', 'credit_card', 'ssn',
        'email', 'is_admin', 'role',
        'permissions', 'auth_token'
    ]
    
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.issues = []
        logging.debug(f"Initialized auditor for {self.base_url}")

    def test_object_properties(self, endpoints):
        """
        Test endpoints for property level authorization issues
        Accepts both formats:
        - {'url':..., 'method':..., 'test_object':...}
        - {'path':..., 'method':..., 'parameters':...} (Swagger format)
        """
        logging.debug(f"Testing {len(endpoints)} endpoints")
        
        for endpoint in endpoints:
            # Normalize endpoint format
            norm_ep = self._normalize_endpoint(endpoint)
            if not norm_ep:
                continue
                
            print(f"Testing endpoint: {norm_ep['method']} {norm_ep['url']}")
            
            # Run tests
            self._test_data_exposure(norm_ep)
            self._test_mass_assignment(norm_ep)
            self._test_property_manipulation(norm_ep)
        
        return self.issues

    def _normalize_endpoint(self, endpoint):
        """Convert endpoint to standardized format"""
        # Already in correct format
        if 'url' in endpoint and 'method' in endpoint:
            return endpoint
            
        # Swagger format
        if 'path' in endpoint and 'method' in endpoint:
            test_obj = self._create_test_object(endpoint)
            return {
                'url': endpoint['path'],
                'method': endpoint['method'].upper(),
                'test_object': test_obj,
                'original_endpoint': endpoint
            }
            
        logging.warning(f"Invalid endpoint format: {endpoint.keys()}")
        return None

    def _create_test_object(self, endpoint):
        """Create test object from Swagger parameters"""
        test_obj = {}
        
        # Path parameters
        if 'parameters' in endpoint:
            for param in endpoint['parameters']:
                if param.get('in') == 'path':
                    test_obj[param['name']] = self._generate_test_value(param)
        
        # Add default ID if no parameters but path has {id}
        if not test_obj and '{id}' in endpoint['path']:
            test_obj['id'] = 1
            
        return test_obj

    def _generate_test_value(self, param):
        """Generate test value based on parameter schema"""
        if 'schema' in param and 'type' in param['schema']:
            param_type = param['schema']['type']
            if param_type == 'integer':
                return 12345
            elif param_type == 'string':
                return f"test_{param['name']}"
        return 1  # Default

    def _test_data_exposure(self, endpoint):
        """Test for sensitive data exposure in responses"""
        url = self._build_url(endpoint['url'], endpoint.get('test_object', {}))
        
        try:
            logging.debug(f"Testing data exposure: {endpoint['method']} {url}")
            response = self._send_request(endpoint['method'], url)
            
            if response.status_code == 200:
                data = response.json()
                sensitive = self._find_sensitive_fields(data)
                if sensitive:
                    self._log_issue(
                        endpoint['url'],
                        "Excessive Data Exposure",
                        f"Sensitive fields in response: {', '.join(sensitive)}",
                        "High",
                        {"exposed_fields": sensitive, "response_sample": data},
                        response=response,
                        request_payload=None
                    )
        except Exception as e:
            logging.error(f"Data exposure test failed: {e}")
            self._log_issue(endpoint['url'], "Test Error", str(e), "Low")

    def _test_mass_assignment(self, endpoint):
        """Test for mass assignment vulnerabilities"""
        if endpoint['method'] not in ['POST', 'PUT', 'PATCH']:
            return
            
        original_obj = endpoint.get('test_object', {})
        malicious_obj = deepcopy(original_obj)
        
        # Add malicious fields
        malicious_obj.update({
            'is_admin': True,
            'role': 'administrator',
            'password': 'H4cked!123'
        })
        
        url = self._build_url(endpoint['url'], original_obj)
        
        try:
            logging.debug(f"Testing mass assignment: {endpoint['method']} {url}")
            response = self._send_request(
                endpoint['method'], 
                url,
                json=malicious_obj
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                changed = [
                    f for f in ['is_admin', 'role', 'password'] 
                    if data.get(f) == malicious_obj[f]
                ]
                if changed:
                    self._log_issue(
                        endpoint['url'],
                        "Mass Assignment",
                        f"Modified restricted fields: {', '.join(changed)}",
                        "Critical",
                        {"sent": malicious_obj, "received": data},
                        response=response,
                        request_payload=malicious_obj
                    )
        except Exception as e:
            logging.error(f"Mass assignment test failed: {e}")
            self._log_issue(endpoint['url'], "Test Error", str(e), "Low")

    def _test_property_manipulation(self, endpoint):
        """Test for unauthorized property manipulation"""
        if endpoint['method'] not in ['PUT', 'PATCH']:
            return
            
        original_obj = endpoint.get('test_object', {})
        legit_obj = deepcopy(original_obj)
        malicious_obj = deepcopy(original_obj)
        
        # Modify sensitive fields
        if 'email' in malicious_obj:
            malicious_obj['email'] = 'attacker@example.com'
        if 'role' in malicious_obj:
            malicious_obj['role'] = 'admin'
            
        url = self._build_url(endpoint['url'], original_obj)
        
        try:
            logging.debug(f"Testing property manipulation: {endpoint['method']} {url}")
            
            # Send legit request
            legit_resp = self._send_request(
                endpoint['method'],
                url,
                json=legit_obj
            )
            
            # Send malicious request
            malicious_resp = self._send_request(
                endpoint['method'],
                url,
                json=malicious_obj
            )
            
            if legit_resp.status_code == 200 and malicious_resp.status_code == 200:
                legit_data = legit_resp.json()
                malicious_data = malicious_resp.json()
                
                changed = [
                    f for f in ['email', 'role']
                    if malicious_data.get(f) != legit_data.get(f)
                    and malicious_data.get(f) == malicious_obj.get(f)
                ]
                
                if changed:
                    self._log_issue(
                        endpoint['url'],
                        "Property Manipulation",
                        f"Unauthorized changes to: {', '.join(changed)}",
                        "High",
                        {
                            "original": legit_data,
                            "malicious": malicious_data,
                            "changed_fields": changed
                        },
                        response=malicious_resp,
                        request_payload=malicious_obj
                    )
        except Exception as e:
            logging.error(f"Property manipulation test failed: {e}")
            self._log_issue(endpoint['url'], "Test Error", str(e), "Low")

    def _send_request(self, method, url, **kwargs):
        """Wrapper for sending requests with logging"""
        logging.debug(f"Sending {method} request to {url}")
        if kwargs.get('json'):
            logging.debug(f"Request payload: {json.dumps(kwargs['json'], indent=2)}")
        
        response = self.session.request(
            method=method,
            url=url,
            timeout=10,
            **kwargs
        )
        
        logging.debug(f"Response status: {response.status_code}")
        if response.text:
            logging.debug(f"Response sample: {response.text[:200]}...")
        
        return response

    def _build_url(self, template, params):
        """Build complete URL from template and parameters"""
        url = template
        for k, v in params.items():
            url = url.replace(f"{{{k}}}", str(v))
        
        if not url.startswith(('http://', 'https://')):
            url = urljoin(f"{self.base_url}/", url.lstrip('/'))
        
        return url

    def _find_sensitive_fields(self, data):
        """Recursively find sensitive fields in response data"""
        sensitive = []
        
        def _scan(obj, path=''):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower() in self.SENSITIVE_FIELDS:
                        sensitive.append(f"{path}{k}")
                    _scan(v, f"{path}{k}.")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f"{path}[{i}].")
        
        _scan(data)
        return sensitive

    def _log_issue(self, endpoint, issue_type, description, severity,
                   data=None, response=None, request_payload=None):
        """Record a finding and add request/response context to the report."""

        entry = {}
        if response is not None:
            try:
                entry = {
                    'method': response.request.method if response.request else '',
                    'url': response.url,
                    'status_code': response.status_code,
                    'request_headers': _headers_to_list(response.request.headers) if response.request else [],
                    'request_body': request_payload,
                    'response_headers': _headers_to_list(response.raw.headers),
                    'response_body': response.text[:2048],
                    'request_cookies': self.session.cookies.get_dict(),
                    'response_cookies': response.cookies.get_dict(),
                }
            except Exception as exc:
                logging.error(f"Failed to capture HTTP context: {exc}")

        issue_record = {
            'endpoint': endpoint,
            'type': issue_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'data': data or {}
        }
        issue_record.update(entry)
        self.issues.append(issue_record)
        logging.warning(f"Found issue: {issue_type} at {endpoint} ({severity})")
    def generate_report(self, fmt="markdown"):
        gen = ReportGenerator(
            issues=self.issues,
            scanner="ObjectProperty (API03)",
            base_url=self.base_url
        )
        return gen.generate_markdown() if fmt == "markdown" else gen.generate_json()
    
    def save_report(self, path: str, fmt: str = "html"):
        ReportGenerator(self.issues, scanner="ObjectProperty (API03)", base_url=self.base_url).save(path, fmt=fmt)


