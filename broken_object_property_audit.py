##############################################
# APISCAN - API Security Scanner             #
# Licensed under the MIT License             #
# Author: Perry Mertens (2025)               #
##############################################

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


from report_utils import ReportGenerator


def _headers_to_list(hdrs):
    if hasattr(hdrs, "getlist"):
        return [(k, v) for k in hdrs for v in hdrs.getlist(k)]
    return list(hdrs.items())


class ObjectPropertyAuditor:
    # Uitgebreide lijst met gevoelige velden
    SENSITIVE_FIELDS = [
        "password", "token", "secret", "api_key", "credit_card", "ssn",
        "email", "is_admin", "role", "permissions", "auth_token", "session",
        "key", "credential", "private", "certificate", "signature", "jwt",
        "bearer", "oauth", "access", "refresh", "authorization", "client_secret",
        "identity", "personal", "birthdate", "address", "phone", "bank", "account",
        "salary", "income", "tax", "health", "medical", "insurance", "biometric"
    ]
    
    # Pattern voor gevoelige data detectie
    SENSITIVE_PATTERNS = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "jwt": r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b',
        "api_key": r'\b[a-fA-F0-9]{32,}\b',
        "auth_token": r'\b[a-fA-F0-9]{64,}\b'
    }

    def __init__(self, base_url: str, session: Optional[requests.Session] = None, *, 
                 show_progress: bool = True, test_user_id: Optional[str] = None,
                 test_admin_id: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.issues: List[Dict[str, Any]] = []
        self.show_progress = show_progress
        self.test_user_id = test_user_id or "1001"
        self.test_admin_id = test_admin_id or "9999"
        self.tested_endpoints: Set[str] = set()

    def _ptype_fmt_def_ex(self, p: dict):
        sch = (p.get("schema") or {})
        return (
            sch.get("type", p.get("type", "string")),
            sch.get("format", p.get("format", "")),
            sch.get("default", p.get("default")),
            sch.get("example", p.get("example")),
        )

    def _sample_for_param(self, pname: str, ptype: str = "string", pformat: str = "", default=None, example=None):
        if example is not None:
            return example
        if default is not None:
            return default

        n = (pname or "").lower()
       
        if ptype in ("integer", "number"):
            return 1
        if ptype == "boolean":
            return True
        if "email" in n:
            return "user@example.com"
        if "uuid" in n or "guid" in n or pformat == "uuid":
            return "550e8400-e29b-41d4-a716-446655440000"
        if n.endswith("id") or n == "id":
            return 1
        if "token" in n or "key" in n:
            return "test_token_123"
        if "role" in n:
            return "user"
        if "name" in n:
            return "test_name"
        if "phone" in n:
            return "+31600000000"
        return "test_value"


    def test_object_properties(self, endpoints: List[Dict[str, Any]]):
        # Filter duplicaten op basis van method + url
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
            iterator = tqdm(unique_endpoints, desc="API3 endpoints", unit="endpoint")

        for endpoint in iterator:
            self._test_data_exposure(endpoint)
            self._test_mass_assignment(endpoint)
            self._test_property_manipulation(endpoint)
            self._test_idor(endpoint)
            self._test_insecure_direct_reference(endpoint)
        return self.issues

    def _normalize_endpoint(self, endpoint):
        if "url" in endpoint and "method" in endpoint:
            return endpoint
        if "path" in endpoint and "method" in endpoint:
            test_obj = self._create_test_object(endpoint)
            return {
                "url": endpoint["path"],
                "method": endpoint["method"].upper(),
                "test_object": test_obj,
                "original_endpoint": endpoint,
            }
        logging.warning(f"Invalid endpoint format: {list(endpoint.keys())}")
        return None

    def _create_test_object(self, endpoint):
        test_obj = {}
        # parameters uit swagger (path, query, body)
        if "parameters" in endpoint:
            for param in endpoint["parameters"]:
                loc = (param.get("in") or "").lower()
                if loc in ("path", "query", "body"):
                    ptype, pformat, pdef, pex = self._ptype_fmt_def_ex(param)
                    test_obj[param["name"]] = self._sample_for_param(
                        param.get("name"), ptype, pformat, pdef, pex
                    )

        # standaard ID-velden indien aanwezig in het pad
        path = endpoint.get("path", "")
        if "{id}" in path and "id" not in test_obj:
            test_obj["id"] = self.test_user_id
        if "{userId}" in path and "userId" not in test_obj:
            test_obj["userId"] = self.test_user_id
        if "{adminId}" in path and "adminId" not in test_obj:
            test_obj["adminId"] = self.test_admin_id

        return test_obj



    def _generate_test_value(self, param):
        if "schema" in param and "type" in param["schema"]:
            param_type = param["schema"]["type"]
            if param_type == "integer":
                return random.randint(1000, 9999)
            if param_type == "string":
                # Gebruik een meer realistische testwaarde
                if "format" in param["schema"] and param["schema"]["format"] == "email":
                    return "test.user@example.com"
                if "format" in param["schema"] and param["schema"]["format"] == "date":
                    return "2023-01-15"
                return f"test_{param['name']}_{random.randint(100, 999)}"
            if param_type == "boolean":
                return True
        return "test_value"

    def _test_data_exposure(self, endpoint):
        url = self._build_url(endpoint["url"], endpoint.get("test_object", {}))
        try:
            response = self._send_request(endpoint["method"], url)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                sensitive_fields = []
                pattern_matches = []
                
                if isinstance(data, (dict, list)):
                    sensitive_fields = self._find_sensitive_fields(data)
                    pattern_matches = self._find_pattern_exposure(response.text)
                
                if sensitive_fields or pattern_matches:
                    self._log_issue(
                        endpoint["url"], "Excessive Data Exposure",
                        f"Sensitive fields in response: {', '.join(sensitive_fields)}. "
                        f"Pattern matches: {', '.join(pattern_matches)}",
                        "High",
                        {
                            "exposed_fields": sensitive_fields,
                            "pattern_matches": pattern_matches,
                            "response_sample": data
                        },
                        response=response, 
                        request_payload=None
                    )
        except Exception as e:
            logging.error(f"Error testing data exposure on {url}: {e}")
            self._log_issue(endpoint["url"], "Test Error", str(e), "Low")

    def _test_mass_assignment(self, endpoint):
        if endpoint["method"] not in ["POST", "PUT", "PATCH"]:
            return
        
        # Uitgebreide lijst met kwaadaardige velden
        malicious_fields = {
            "is_admin": True, 
            "role": "administrator", 
            "password": "H4cked!123",
            "permissions": "all",
            "isActive": True,
            "isVerified": True,
            "accountType": "premium",
            "balance": 999999,
            "emailVerified": True,
            "twoFactorEnabled": False
        }
        
        original_obj = endpoint.get("test_object", {})
        malicious_obj = deepcopy(original_obj)
        malicious_obj.update(malicious_fields)
        
        url = self._build_url(endpoint["url"], original_obj)
        try:
            response = self._send_request(endpoint["method"], url, json=malicious_obj)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                if isinstance(data, dict):
                    changed = []
                    for field, expected_value in malicious_fields.items():
                        if field in data and data[field] == expected_value:
                            changed.append(field)
                    
                    if changed:
                        self._log_issue(
                            endpoint["url"], "Mass Assignment",
                            f"Modified restricted fields: {', '.join(changed)}",
                            "Critical",
                            {"sent": malicious_obj, "received": data},
                            response=response, 
                            request_payload=malicious_obj
                        )
        except Exception as e:
            logging.error(f"Error testing mass assignment on {url}: {e}")
            self._log_issue(endpoint["url"], "Test Error", str(e), "Low")

    def _test_property_manipulation(self, endpoint):
        if endpoint["method"] not in ["PUT", "PATCH"]:
            return
        
        original_obj = endpoint.get("test_object", {})
        legit_obj = deepcopy(original_obj)
        malicious_obj = deepcopy(original_obj)
        
        # Meer velden om te testen
        fields_to_test = {
            "email": "attacker@example.com",
            "role": "admin",
            "permissions": "all",
            "isAdmin": True,
            "accountType": "premium",
            "balance": 999999,
            "userId": self.test_admin_id,  # Probeer user ID te wijzigen
            "ownerId": self.test_admin_id  # Probeer eigenaar ID te wijzigen
        }
        
        for field, malicious_value in fields_to_test.items():
            if field in malicious_obj or field.lower() in malicious_obj:
                malicious_obj[field] = malicious_value
        
        url = self._build_url(endpoint["url"], original_obj)
        try:
            legit_resp = self._send_request(endpoint["method"], url, json=legit_obj)
            malicious_resp = self._send_request(endpoint["method"], url, json=malicious_obj)
            
            if legit_resp.status_code == 200 and malicious_resp.status_code == 200:
                legit_data = self._safe_json(legit_resp)
                malicious_data = self._safe_json(malicious_resp)
                
                if isinstance(legit_data, dict) and isinstance(malicious_data, dict):
                    changed = []
                    for field, malicious_value in fields_to_test.items():
                        legit_value = legit_data.get(field)
                        malicious_value_received = malicious_data.get(field)
                        
                        if (legit_value != malicious_value_received and 
                            malicious_value_received == malicious_value):
                            changed.append(field)
                    
                    if changed:
                        self._log_issue(
                            endpoint["url"], "Property Manipulation",
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
            logging.error(f"Error testing property manipulation on {url}: {e}")
            self._log_issue(endpoint["url"], "Test Error", str(e), "Low")

    def _test_idor(self, endpoint):
        """Test Insecure Direct Object References"""
        if endpoint["method"] not in ["GET", "PUT", "DELETE", "PATCH"]:
            return
            
        original_obj = endpoint.get("test_object", {})
        url = self._build_url(endpoint["url"], original_obj)
        
        # Test met verschillende IDs die niet van de huidige gebruiker zijn
        test_ids = [
            self.test_admin_id,  # Admin ID
            "12345",             
            "0",                 
            "-1",                
            "9999999999"
        ]
        
        for test_id in test_ids:
            # Vervang ID-gerelateerde parameters in URL en body
            test_obj = deepcopy(original_obj)
            test_url = url
            
            # Vervang ID parameters in URL
            for param_name in ["id", "userId", "userid", "user_id", "accountId"]:
                if f"{{{param_name}}}" in test_url and param_name in test_obj:
                    original_id = test_obj[param_name]
                    test_obj[param_name] = test_id
                    test_url = test_url.replace(f"{{{param_name}}}", str(test_id))
            
            try:
                response = self._send_request(endpoint["method"], test_url, json=test_obj)
                
                # Als we toegang krijgen tot resources die niet van ons zijn
                if response.status_code in [200, 201, 204]:
                    self._log_issue(
                        endpoint["url"], "Insecure Direct Object Reference (IDOR)",
                        f"Access to resource {test_id} possible with user {self.test_user_id}",
                        "High",
                        {
                            "requested_id": test_id,
                            "user_id": self.test_user_id,
                            "response_code": response.status_code
                        },
                        response=response,
                        request_payload=test_obj
                    )
            except Exception as e:
                logging.error(f"Error testing IDOR on {test_url}: {e}")

    def _test_insecure_direct_reference(self, endpoint):
        """Test op onveilige directe objectreferenties in responses"""
        if endpoint["method"] not in ["GET", "POST"]:
            return
            
        url = self._build_url(endpoint["url"], endpoint.get("test_object", {}))
        try:
            response = self._send_request(endpoint["method"], url)
            if response.status_code in [200, 201]:
                data = self._safe_json(response)
                
                # Zoek naar interne IDs in de response
                internal_refs = self._find_internal_references(data)
                if internal_refs:
                    self._log_issue(
                        endpoint["url"], "Insecure Direct Object Reference",
                        f"Internal references exposed: {', '.join(internal_refs)}",
                        "Medium",
                        {"internal_references": internal_refs},
                        response=response,
                        request_payload=None
                    )
        except Exception as e:
            logging.error(f"Error testing insecure direct reference on {url}: {e}")

    def _send_request(self, method, url, **kwargs):
        # Voeg standaard headers toe indien nodig
        headers = kwargs.get('headers', {})
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        kwargs['headers'] = headers
        
        response = self.session.request(method=method, url=url, timeout=15, **kwargs)
        return response

    def _safe_json(self, response):
        try:
            return response.json()
        except Exception:
            # Probeer verschillende JSON formaten
            try:
                # Mogelijk is het een JSON array
                text = response.text.strip()
                if text.startswith('[') and text.endswith(']'):
                    return json.loads(text)
            except:
                pass
            return {}

    def _build_url(self, template, params):
        url = template
        for k, v in params.items():
            url = url.replace(f"{{{k}}}", str(v))
        if not url.startswith(("http://", "https://")):
            url = urljoin(f"{self.base_url}/", url.lstrip("/"))
        return url

    def _find_sensitive_fields(self, data):
        sensitive = []
        def _scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Controleer op gevoelige veldnamen
                    field_lower = k.lower()
                    for sensitive_field in self.SENSITIVE_FIELDS:
                        if sensitive_field in field_lower:
                            sensitive.append(f"{path}{k}")
                            break
                    _scan(v, f"{path}{k}.")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f"{path}[{i}].")
        _scan(data)
        return sensitive

    def _find_pattern_exposure(self, text):
        """Zoek naar gevoelige data patterns in response text"""
        matches = []
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern_name)
        return matches

    def _find_internal_references(self, data):
        """Zoek naar interne referenties die niet blootgesteld zouden moeten worden"""
        internal_refs = []
        
        def _scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_lower = k.lower()
                    # Zoek naar interne IDs en referenties
                    if any(term in key_lower for term in ['internal', 'db', 'database', 'ref', '_id']):
                        if isinstance(v, (str, int)) and v:
                            internal_refs.append(f"{path}{k}: {v}")
                    _scan(v, f"{path}{k}.")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _scan(item, f"{path}[{i}].")
        
        _scan(data)
        return internal_refs

    def _log_issue(self, endpoint, issue_type, description, severity, data=None, response=None, request_payload=None):
        entry = {}
        if response is not None:
            try:
                entry = {
                    "method": response.request.method if response.request else "",
                    "url": response.url,
                    "status_code": response.status_code,
                    "request_headers": _headers_to_list(response.request.headers) if response.request else [],
                    "request_body": request_payload,
                    "response_headers": _headers_to_list(response.headers),
                    "response_body": response.text[:4096],  # Verhoogde limiet
                    "request_cookies": self.session.cookies.get_dict(),
                    "response_cookies": response.cookies.get_dict(),
                }
            except Exception as e:
                logging.error(f"Error logging issue details: {e}")
        
        issue_record = {
            "endpoint": endpoint,
            "type": issue_type,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "data": data or {},
        }
        issue_record.update(entry)
        self.issues.append(issue_record)

    def generate_report(self, fmt="markdown"):
        gen = ReportGenerator(issues=self.issues, scanner="ObjectProperty (API03)", base_url=self.base_url)
        return gen.generate_markdown() if fmt == "markdown" else gen.generate_json()

    def save_report(self, path: str, fmt: str = "html"):
        ReportGenerator(self.issues, scanner="ObjectProperty (API03)", base_url=self.base_url).save(path, fmt=fmt)