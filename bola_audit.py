# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
import json
import re
import requests
from urllib.parse import urljoin
from pathlib import Path
from typing import List, Dict, Optional
import logging
from dataclasses import dataclass
import time
from urllib.parse import urlparse
from datetime import datetime
timestamp=datetime.now().isoformat()

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
        results=[]
        if not endpoint.get('parameters'): return results
        for name,vals in self._generate_test_values(endpoint['parameters']).items():
            time.sleep(self.test_delay)
            results.append(self._test_object_access(base_url,endpoint,name,vals))
        return results

    def _test_object_access(self, base_url, endpoint, name, vals)->TestResult:
        try:
            url = urljoin(base_url,endpoint['path'])
            params,body,headers = {},{}, {'User-Agent':'APISecurityScanner/1.0'}
            for p in endpoint['parameters']:
                val=vals.get(p['name'],'1')
                if p['in']=='path': url=url.replace(f"{{{p['name']}}}",str(val))
                elif p['in']=='query': params[p['name']]=val
                elif p['in']=='header': headers[p['name']]=val
                else: body[p['name']]=val
            start=time.time()
            resp=self.session.request(endpoint['method'],url,params=params,headers=headers,json=body or None,timeout=10,allow_redirects=False)
            rt=time.time()-start
            vuln = (resp.status_code==200 and (any(re.search(pat,resp.text.lower()) for pat in self.sensitive_data_patterns) or len(resp.content)>10000))
            return TestResult(name,endpoint['method'],url,resp.status_code,vuln,rt,params,headers,self._sanitize_response(resp.text),str(body))
        except Exception as e:
            return TestResult(name,endpoint['method'],base_url+endpoint['path'],error=str(e))

    def _sanitize_response(self,text:str,max_length:int=200)->str:
        if not text: return ''
        sanitized=re.sub(r'(password|token|secret)"?\s*:\s*"[^"]+"',r'\1":"*****"',text,flags=re.I)
        return (sanitized[:max_length]+'...') if len(sanitized)>max_length else sanitized

    def generate_report(self, results: List['TestResult']) -> str:
        SENSITIVE_PATTERNS = {
            "token_leak": re.compile(r'"access[_-]?token"\s*:\s*"[A-Za-z0-9\-_.]{15,}"', re.IGNORECASE),
            "password_leak": re.compile(r'"password"\s*:\s*".{6,}"', re.IGNORECASE),
            "pii_leak": re.compile(r'("ssn|social_security|credit_card)"\s*:\s*"\d{3}-\d{2}-\d{4}"', re.IGNORECASE)
        }

        CVSS_SCORES = {
            "token_leak": 7.5,
            "password_leak": 9.0,
            "pii_leak": 9.1,
            "200_ok_no_auth": 5.3,
            "error_only": 2.5,
            "unknown": 3.0
        }

        FALSE_POSITIVE_PATTERNS = [
            re.compile(r'test(user|email|password)@example\.com', re.IGNORECASE),
            re.compile(r'\b(test|demo|example)\b', re.IGNORECASE)
        ]

        findings = {"🚨 Critical": [], "🛑 High": [], "⚠️ Medium": [], "ℹ️ Low": []}

        for result in results:
            result.cvss_score = CVSS_SCORES["unknown"]  # default
            if not result.is_vulnerable:
                if result.error or result.status_code >= 400:
                    result.cvss_score = CVSS_SCORES["error_only"]
                    findings["ℹ️ Low"].append(result)
                continue

            response_text = ""
            try:
                if result.response_sample:
                    response_text = json.dumps(result.response_sample) if isinstance(result.response_sample, dict) else str(result.response_sample)
            except Exception:
                pass

            is_false_positive = any(fp.search(response_text) for fp in FALSE_POSITIVE_PATTERNS)
            matched_patterns = []

            for name, pattern in SENSITIVE_PATTERNS.items():
                if pattern.search(response_text):
                    matched_patterns.append(name)
                    result.response_sample = pattern.sub(r'\1: "[REDACTED]"', response_text)

            if not is_false_positive and matched_patterns:
                result.metadata = {
                    "matched_patterns": matched_patterns,
                    "response_preview": result.response_sample[:1000] +
                    ("..." if len(result.response_sample) > 1000 else "")
                }

                if "token_leak" in matched_patterns and "password_leak" in matched_patterns:
                    result.cvss_score = max(CVSS_SCORES["token_leak"], CVSS_SCORES["password_leak"]) + 0.5
                    findings["🚨 Critical"].append(result)
                else:
                    result.cvss_score = max(CVSS_SCORES.get(pat, 7.0) for pat in matched_patterns)
                    findings["🛑 High"].append(result)
            elif result.status_code == 200 and not is_false_positive:
                result.cvss_score = CVSS_SCORES["200_ok_no_auth"]
                findings["⚠️ Medium"].append(result)
            else:
                result.cvss_score = CVSS_SCORES["error_only"]
                findings["ℹ️ Low"].append(result)

        report = [
            "# API Security Assessment - BOLA Report",
            "## Executive Summary",
            f"- **Target**: {self._get_base_url(results)}",
            f"- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "### Risk Distribution",
            "| Severity | Count | Description |",
            "|----------|-------|-------------|",
            "| 🚨 Critical | {} | Multiple sensitive items exposed |".format(len(findings["🚨 Critical"])),
            "| 🛑 High | {} | Single sensitive item exposed |".format(len(findings["🛑 High"])),
            "| ⚠️ Medium | {} | 200 OK on unprotected endpoint |".format(len(findings["⚠️ Medium"])),
            "| ℹ️ Low | {} | Errors or minor issues |".format(len(findings["ℹ️ Low"])),
            "\n## Detailed Findings"
        ]

        for severity in ["🚨 Critical", "🛑 High", "⚠️ Medium", "ℹ️ Low"]:
            items = findings[severity]
            if not items:
                continue

            report.append(f"\n### {severity} Risk Findings")
            for idx, result in enumerate(items, 1):
                report.extend([
                    f"#### Finding {idx}: {result.test_case}",
                    "| Metric | Value |",
                    "|--------|-------|",
                    f"| CVSS Score | {result.cvss_score:.1f} |",
                    f"| Endpoint | `{result.method} {result.url}` |",
                    f"| Status Code | {result.status_code} |",
                    f"| Response Time | {result.response_time:.2f}s |",
                    f"| Timestamp | {getattr(result, 'timestamp', 'N/A')} |"
                ])

                if hasattr(result, 'metadata'):
                    report.extend([
                        "\n**Matched Patterns**:",
                        "- " + "\n- ".join(result.metadata["matched_patterns"]),
                        "\n**Response Preview**:",
                        f"```json\n{result.metadata['response_preview']}\n```"
                    ])

                if result.params:
                    report.append("\n**Request Parameters:**")
                    report.append(f"```json\n{json.dumps(result.params, indent=2)}\n```")

                report.append("---")

        report.extend([
            "\n## Remediation Recommendations",
            "1. **Access Control**",
            "   - Implement role-based access control (RBAC)",
            "   - Validate ownership for object access\n",
            "2. **Data Protection**",
            "   - Encrypt sensitive data at rest and in transit",
            "   - Use UUIDs instead of sequential IDs\n",
            "3. **Monitoring**",
            "   - Log all authorization attempts",
            "   - Implement anomaly detection for bulk access\n",
            "\n## Scan Details",
            f"- Total Endpoints Tested: {len({(r.method, r.url) for r in results})}",
            f"- Total Test Cases Executed: {len(results)}",
            "- Scan Configuration:",
            f"  - Sensitive Data Patterns: {len(SENSITIVE_PATTERNS)}",
            f"  - False Positive Filters: {len(FALSE_POSITIVE_PATTERNS)}"
        ])

        return "\n".join(report)

    def _get_base_url(self, results):
        if not results:
            return "N/A"
        parsed = urlparse(results[0].url)
        return f"{parsed.scheme}://{parsed.netloc}"
            
    def save_report(self, results: List[TestResult], path: str):
        Path(path).write_text(self.generate_report(results), encoding='utf-8')

if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Run BOLA audit based on Swagger/OpenAPI spec")
    parser.add_argument('--swagger','-s',required=True,help='Path to Swagger/OpenAPI JSON file')
    parser.add_argument('--base-url','-b',required=True,help='Base URL of the API')
    parser.add_argument('--output','-o',default='audit_report.md',help='Output file')
    args = parser.parse_args()
    session = requests.Session()
    auditor = BOLAAuditor(session)
    spec = auditor.load_swagger(args.swagger)
    if spec is None:
        import sys; sys.exit("❌ Swagger cannot be loaded.")
    endpoints = auditor.get_object_endpoints(spec)
    if not endpoints:
        logger.warning("No object endpoints found.")
    results = []
    for ep in endpoints:
        results.extend(auditor.test_endpoint(args.base_url, ep))
    report = auditor.generate_report(results)
    print(report)
    auditor.save_report(results, args.output)
    print(f"\nReport saved: {args.output}")
