import json
import re
import requests
from urllib.parse import urljoin
from pathlib import Path
from typing import List, Dict, Optional
import logging
from dataclasses import dataclass
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    test_case: str
    method: str
    url: str
    status_code: int = 0
    is_vulnerable: bool = False
    response_time: float = 0.0
    params: Optional[Dict] = None
    headers: Optional[Dict] = None
    error: Optional[str] = None
    response_sample: Optional[str] = None
    request_sample: Optional[str] = None

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
        """Laad Swagger/OpenAPI bestand inclusief remote referenties"""
        try:
            path = Path(swagger_path)
            if not path.exists():
                logger.error(f"Swagger bestand niet gevonden: {swagger_path}")
                return None
            content = path.read_text(encoding='utf-8')
            spec = json.loads(content)
            logger.info(f"Swagger succesvol geladen: {len(spec.get('paths', {}))} endpoints gevonden")
            return spec
        except Exception as e:
            logger.error(f"Fout bij laden Swagger: {e}", exc_info=True)
            return None

    def get_object_endpoints(self, swagger_spec: Dict) -> List[Dict]:
        """Identificeer alle endpoints met objectreferenties"""
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
        """Vind parameters die objectreferenties kunnen zijn"""
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

    def generate_report(self, results: List[TestResult]) -> str:
        # Lijst van unieke gescande endpoints
        scanned = sorted({(r.method, r.url.split('?')[0]) for r in results})
        # Groepeer testresultaten per endpoint
        eps = {}
        for r in results:
            key = f"{r.method} {r.url.split('?')[0]}"
            eps.setdefault(key, []).append(r)

        report = [
            '# API Security Audit - BOLA Test Results',
            f"**Totaal gescande endpoints**: {len(scanned)}",
            f"**Totaal testcases**: {len(results)}", 
            f"**Kwetsbaarheden gevonden**: {sum(r.is_vulnerable for r in results)}",
        ]
        report.append('\n## Gescande Endpoints')
        for method, url in scanned:
            report.append(f"- {method} {url}")

        report.append('\n## Kwetsbare Endpoints')
        for ep, tests in eps.items():
            if not any(t.is_vulnerable for t in tests):
                continue
            status = "⚠️ **KWETSBAAR**"
            report.extend([
                f"\n### {ep}",
                f"**Status**: {status}",
                f"**Aantal testcases**: {len(tests)}", 
                f"**Kwetsbaarheden**: {sum(t.is_vulnerable for t in tests)}\n",
                '#### Testresultaten:'
            ])
            for t in sorted(tests, key=lambda x: x.is_vulnerable, reverse=True):
                icon = "🔴" if t.is_vulnerable else "🟢"
                line = f"{icon} **{t.test_case}**: HTTP {t.status_code} | {t.response_time:.2f}s"
                if t.is_vulnerable:
                    line += " | **BOLA GEDETECTEERD**"
                if t.params:
                    line += f" | Params: {t.params}"
                report.append(line)
                if t.error:
                    report.append(f"  - Fout: `{t.error}`")
                if t.request_sample:
                    report.append(f"  - Request: `{t.request_sample}`")
                if t.response_sample:
                    report.append(f"  - Response sample:\n```\n{t.response_sample}\n```")

        report.extend([
            '\n## Samenvatting',
            f"- **Kwetsbare endpoints**: {sum(any(t.is_vulnerable for t in vs) for vs in eps.values())}/{len(scanned)}",
            '- **Aanbevolen acties**:',
            '  - Implementeer proper authorization checks',
            '  - Gebruik unpredictable identifiers',
            '  - Log en monitor access patterns'
        ])
        return '\n'.join(report)

    def save_report(self, results: List[TestResult], path: str):
        Path(path).write_text(self.generate_report(results), encoding='utf-8')

if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Run BOLA audit based on Swagger/OpenAPI spec")
    parser.add_argument('--swagger','-s',required=True,help='Pad naar Swagger/OpenAPI JSON bestand')
    parser.add_argument('--base-url','-b',required=True,help='Base URL van de API')
    parser.add_argument('--output','-o',default='audit_report.md',help='Output bestand')
    args = parser.parse_args()
    session = requests.Session()
    auditor = BOLAAuditor(session)
    spec = auditor.load_swagger(args.swagger)
    if spec is None:
        import sys; sys.exit("❌ Swagger kan niet geladen worden.")
    endpoints = auditor.get_object_endpoints(spec)
    if not endpoints:
        logger.warning("Geen object endpoints gevonden.")
    results = []
    for ep in endpoints:
        results.extend(auditor.test_endpoint(args.base_url, ep))
    report = auditor.generate_report(results)
    print(report)
    auditor.save_report(results, args.output)
    print(f"\nRapport opgeslagen: {args.output}")
