##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
import json
import re
import sys
import requests
from urllib.parse import urljoin
from pathlib import Path
from typing import  Any, List, Dict, Optional
import logging
from dataclasses import dataclass
import time
from urllib.parse import urlparse
from datetime import datetime
from report_utils import ReportGenerator
from requests import Request




def classify_risk(status_code: int, response_body: str = "") -> str:
    if status_code == 200:
        return "High"            # Ongeautoriseerde data-toegang
    elif 500 <= status_code < 600:
        return "Low"             # Server-error, minder urgent
    elif status_code == 403:
        return "Medium"          # Correct geweigerd
    elif status_code == 400:
        return "Low"
    elif status_code == 404:
        return "Low"
    elif status_code == 0:
        return "Ignore" 
    else:
        return "Low"


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    test_case: str
    method: str
    url: str
    status_code: int
    response_time: float
    is_vulnerable: bool
    response_sample: Optional[str] = None
    request_sample: Optional[str] = None
    params: Optional[dict] = None
    headers: Optional[dict] = None
    error: Optional[str] = None
    timestamp: Optional[str] = None
    response_headers: Optional[dict] = None  

    def to_dict(self):
        return {
            "method": self.method,
            "url": self.url,
            "endpoint": self.url,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "description": self.test_case,
            "severity": classify_risk(self.status_code, self.response_sample),
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "request_parameters": self.params or {},
            "request_headers": self.headers or {},
            "request_body": self.request_sample,
            "response_headers": self.response_headers or {},
            "response_body": (str(self.response_sample) if self.response_sample else "")
        }


class BOLAAuditor:
    def __init__(self, session: requests.Session):
        self.session = session
        self.object_key_patterns = [
            r'id$', r'uuid$', r'_id$', r'key$',
            r'email$', r'token$', r'name$', r'slug$',
            r'user', r'account', r'profile'
        ]
        self.sensitive_data_patterns = [
            r'email', r'password', r'token',
            r'admin', r'credit.?card', r'phone',
            r'secret', r'private', r'personal'
        ]
        self.test_delay = 0.5  # Delay between tests

    def load_swagger(self, swagger_path: str) -> Optional[Dict]:
        """Load Swagger/OpenAPI file including remote references"""
        try:
            path = Path(swagger_path)
            if not path.exists():
                logger.error(f"Swagger file not found: {swagger_path}")
                return None
            content = path.read_text(encoding='utf-8')
            spec = json.loads(content)
            logger.info(f"Swagger successfully loaded: {len(spec.get('paths', {}))} endpoints gevonden")
            return spec
        except Exception as e:
            logger.error(f"Error loading Swagger: {e}", exc_info=True)
            return None

    def get_endpoints(self) -> List[Dict]:
            return getattr(self, "_last_endpoints", [])

    def run_audit(self, base_url: str, swagger_path: str) -> List[Dict[str, Any]]:
        print("→ BOLA audit gestart")
        self.base_url = base_url
        spec = self.load_swagger(swagger_path)
        if not spec:
            return []
        endpoints = self.get_object_endpoints(spec)
        self._last_endpoints = endpoints
        all_results = []
        for ep in endpoints:
            all_results.extend(self.test_endpoint(base_url, ep))  # ✅ juiste call
        self.issues = [r.to_dict() for r in all_results]
        return self.issues

       
    def get_object_endpoints(self, swagger_spec: Dict) -> List[Dict]:
        """Identify all endpoints with object references"""
        endpoints = []
        paths = swagger_spec.get('paths', {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_params = path_item.get('parameters', [])
            for method, operation in path_item.items():
                if method.lower() not in ['get','post','put','delete','patch'] or not isinstance(operation, dict):
                    continue
                all_params = path_params + operation.get('parameters', [])
                object_params = self._find_object_params(all_params)
                # body parameters
                rb = operation.get('requestBody', {})
                content = rb.get('content', {})
                if 'application/json' in content:
                    schema = content['application/json'].get('schema', {})
                    for prop, prop_schema in schema.get('properties', {}).items():
                        if any(re.search(pat, prop.lower()) for pat in self.object_key_patterns):
                            object_params.append({
                                'name': prop,
                                'in': 'body',
                                'required': prop in schema.get('required', []),
                                'type': prop_schema.get('type','string'),
                                'format': prop_schema.get('format',''),
                                'description': prop_schema.get('description','')
                            })
                if object_params:
                    endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'parameters': object_params,
                        'operation_id': operation.get('operationId',''),
                        'summary': operation.get('summary',''),
                        'description': operation.get('description',''),
                        'security': operation.get('security',[])
                    })
        logger.info(f"Totaal object endpoints gevonden: {len(endpoints)}")
        return endpoints

    def _find_object_params(self, parameters: List[Dict]) -> List[Dict]:
        """Find parameters that may be object references"""
        obj = []
        for param in parameters:
            if not isinstance(param, dict):
                continue
            name = param.get('name','').lower()
            if any(re.search(pat,name) for pat in self.object_key_patterns):
                schema = param.get('schema',{})
                obj.append({
                    'name': param['name'],
                    'in': param.get('in',''),
                    'required': param.get('required',False),
                    'type': schema.get('type','string'),
                    'format': schema.get('format',''),
                    'description': param.get('description','')
                })
        return obj

    def _generate_test_values(self, parameters: List[Dict]) -> Dict[str,Dict]:
        base_values = {
            'valid':'1','other_user':'2','string':'testuser',
            'injection':'" OR "1"="1--",', 'non_existent':'99999',
            'random_uuid':'550e8400-e29b-41d4-a716-446655440000',
            'admin_user':'admin','high_value':'1000000'
        }
        type_vals = {
            'integer':{'negative':'-1','zero':'0','large':'2147483647'},
            'string':{'long':'A'*1000,'special_chars':'!@#$%^&*()'}
        }
        cases={}
        for n,v in base_values.items(): cases[n] = {p['name']:v for p in parameters}
        for p in parameters:
            if p['type'] in type_vals:
                for n,v in type_vals[p['type']].items():
                    cname=f"{p['type']}_{n}"
                    cases[cname]={q['name']: (v if q['type']==p['type'] else base_values['valid']) for q in parameters}
        return cases

    def test_endpoint(self, base_url:str, endpoint:Dict)->List[TestResult]:
        #Test a single endpoint with various test cases for BOLA vulnerabilities
        results=[]
        if not endpoint.get('parameters'): return results
        for name,vals in self._generate_test_values(endpoint['parameters']).items():
            time.sleep(self.test_delay)
            print(f"→ Testing {endpoint['method']} {endpoint['path']} [{name}]")
            results.append(self._test_object_access(base_url,endpoint,name,vals))
        return results

        from datetime import datetime
    from requests import Request

    def _test_object_access(self,base_url: str,endpoint: dict,name: str,vals: dict) -> TestResult:
        """
        Stuur één request naar het opgegeven endpoint en retourneer
        een TestResult-object met alle relevante gegevens.

        Parameters
        ----------
        base_url : root-URL van de API (b.v. https://api.example.com)
        endpoint : dict met ten minste keys: path, method, parameters
        name     : beschrijving van deze test-case (b.v. 'leeg_id')
        vals     : mapping parameter-naam → test-waarde
        """

        # -------- 1. Request samenstellen --------
        url = urljoin(base_url, endpoint["path"])

        query_params: dict[str, str] = {}
        json_body: dict[str, str] = {}
        headers: dict[str, str] = {"User-Agent": "APISecurityScanner/1.0"}

        for prm in endpoint.get("parameters", []):
            pname   = prm["name"]
            loc     = prm.get("in", "query")
            value   = vals.get(pname, "1")

            if loc == "path":
                url = url.replace(f"{{{pname}}}", str(value))
            elif loc == "query":
                query_params[pname] = value
            elif loc == "header":
                headers[pname] = value
            else:                       # body / cookie / form-data → treat as JSON body
                json_body[pname] = value

        req = Request(
            method=endpoint["method"],
            url=url,
            headers=headers,
            params=query_params,
            json=json_body or None          # None voorkomt onnodige 'null' body
        )
        prepared = self.session.prepare_request(req)

        # -------- 2. Verzenden & meten --------
        start = time.time()
        try:
            resp = self.session.send(
                prepared,
                timeout=10,
                allow_redirects=False
            )
            resp_time = time.time() - start
            error_msg = None
        except Exception as exc:            # netwerk-timeout, DNS-fout, …
            resp = None
            resp_time = time.time() - start
            error_msg = str(exc)

        # -------- 3. Analyse --------
        status_code = resp.status_code if resp else 0
        body_text   = resp.text if resp else ""
        sample      = self._sanitize_response(body_text)

        contains_sensitive = any(
            re.search(pat, body_text, re.I)
            for pat in self.sensitive_data_patterns
        )
        large_body = len(body_text) > 10_000

        is_vuln = status_code == 200 and (contains_sensitive or large_body)

        # -------- 4. Resultaat teruggeven --------
        return TestResult(
            test_case=name,
            method=prepared.method,
            url=prepared.url,
            status_code=status_code,
            response_time=resp_time,
            is_vulnerable=is_vuln,
            response_sample=sample,
            request_sample=(
                prepared.body.decode()
                if isinstance(prepared.body, (bytes, bytearray))
                else (prepared.body or "")
            ),
            params=query_params,
            headers=dict(prepared.headers),
            response_headers=dict(resp.headers) if resp else {},
            error=error_msg,
            timestamp=datetime.now().isoformat()
        )
      
    

    def _sanitize_response(self,text:str,max_length:int=200)->str:
        if not text: return ''
        sanitized=re.sub(r'(password|token|secret)"?\s*:\s*"[^"]+"',r'\1":"*****"',text,flags=re.I)
        return (sanitized[:max_length]+'...') if len(sanitized)>max_length else sanitized

    def generate_report(self, fmt: str = "markdown") -> str:
        # Skip alle requests die nooit een HTTP-antwoord kregen
        clean_issues = [i for i in self.issues if i.get("status_code") != 0]
        return ReportGenerator(clean_issues, scanner="Bola", base_url=self.base_url).generate_html()
        
    def _get_base_url(self, results):
        if not results:
            return "N/A"
        parsed = urlparse(results[0].url)
        return f"{parsed.scheme}://{parsed.netloc}"
            
    def save_report(self, path: str, fmt: str = "markdown"):
        clean_issues = [i for i in self.issues if i.get("status_code") != 0]
        ReportGenerator(clean_issues, scanner="Bola", base_url=self.base_url).save(path, fmt="html")



