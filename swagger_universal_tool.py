########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the MIT License                       #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.1 14-12-2025                               #
########################################################
import argparse
import json
import re
import sys
import urllib3
import pickle
import time
import random
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import requests
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient

logging.getLogger("urllib3").setLevel(logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JSON_CT_HINTS = (
    "application/json",
    "application/problem+json",
    "application/vnd.api+json",
    "application/x-ndjson",
    "text/json",
)

API_CT_HINTS = JSON_CT_HINTS + (
    "application/xml",
    "text/xml",
)

class UltimateSwaggerGenerator:
    #================funtion __init__ initialize generator, session and swagger skeleton ##########
    def __init__(self, base_url: str, delay: float = 0.0, aggressive: bool = False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.delay = delay
        self.aggressive = aggressive
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/140.0',
            'Accept': 'application/json, text/html, application/xml;q=0.9, */*;q=0.8',
            'Accept-Encoding': 'gzip, deflate'
        })
        self.swagger = {
            "openapi": "3.0.0",
            "info": {
                "title": f"API Documentation for {base_url}",
                "version": "1.0.0"
            },
            "servers": [{"url": base_url}],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        }
        self.visited: Set[str] = set()
        self.lock = threading.Lock()
        self.api_patterns = [
            r'(?i)/api/',
            r'(?i)/v[0-9]+/',
            r'(?i)\.(json|xml)$',
            r'(?i)/graphql',
            r'(?i)/rest/',
            r'(?i)/restapi/',
            r'(?i)/service(s)?/',
            r'(?i)/data/',
            r'(?i)/swagger',
            r'(?i)/openapi',
            r'(?i)/endpoints?',
            r'(?i)/rpc/',
            r'(?i)/jsonrpc',
            r'(?i)/soap/',
            r'(?i)/ws/',
            r'(?i)/wss/',
            r'(?i)/socket\.io',
            r'(?i)/sockjs',
            r'(?i)/_ah/api',
            r'(?i)/_api',
            r'(?i)/ajax/',
            r'(?i)/async/',
            r'(?i)/backend/',
            r'(?i)/v2/',
            r'(?i)/v3/',
        ]
        self.auth_tokens = {}
        self.login_url = None
        self.login_data = None
        self.custom_headers = {}
        self.log_path = "scan_log.ndjson"

                                                               
    #================funtion _mark_visited track visited URLs to avoid repeats ##########
    def _mark_visited(self, url: str) -> bool:
        with self.lock:
            if url in self.visited:
                return False
            self.visited.add(url)
            return True

    #================funtion _same_host check if URL shares host with base ##########
    def _same_host(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    #================funtion _is_api_response detect API content via Content-Type ##########
    def _is_api_response(self, response: requests.Response) -> bool:
        ct = response.headers.get("Content-Type", "").lower()
        return any(vt in ct for vt in API_CT_HINTS)

    #================funtion _is_json_like detect JSON even with wrong Content-Type ##########
    def _is_json_like(self, response: requests.Response) -> bool:
        ct = response.headers.get("Content-Type", "").lower()
        if any(vt in ct for vt in JSON_CT_HINTS):
            return True
                                                                        
        try:
            _ = response.json()
            return True
        except Exception:
            return False

    #================funtion _normalise_path normalize path by replacing IDs ##########
    def _normalise_path(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if "#" in path:
            path = path.split("#", 1)[0]
                             
        path = re.sub(r"/\d+", "/{id}", path)
                                  
        path = re.sub(r"/[a-f0-9]{24}", "/{objectId}", path, flags=re.I)
                                             
        path = re.sub(r"/([^/]*_?[iI][dD])", r"/{\1}", path)
        return path

    #================funtion _make_request http request with retry and backoff ##########
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
                                            
        retries = 0
        while True:
            if self.delay:
                time.sleep(self.delay)
            try:
                _timeout = kwargs.pop("timeout", 10)
                resp = self.session.request(method, url, timeout=_timeout, **kwargs)
            except requests.RequestException as e:
                if retries < 2:
                    retries += 1
                    time.sleep(min(2**retries, 5))
                    continue
                raise
            if self._handle_rate_limiting(resp):
                retries += 1
                if retries > 5:
                    return resp
                                                 
                sleep_for = min(2**retries + random.random(), 60)
                time.sleep(sleep_for)
                continue
            return resp

    #================funtion _update_swagger_security_schemes update securitySchemes based on auth used ##########
    def _update_swagger_security_schemes(self):
        if isinstance(self.session.auth, HTTPBasicAuth):
            self.swagger["components"]["securitySchemes"]["basicAuth"] = {
                "type": "http",
                "scheme": "basic"
            }
        for header in self.session.headers:
            if header.lower() in ['x-api-key', 'api-key']:
                self.swagger["components"]["securitySchemes"]["apiKeyAuth"] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": header
                }

    #================funtion save_session persist session cookies to file ##########
    def save_session(self, filename: str):
        with open(filename, 'wb') as f:
            pickle.dump(self.session.cookies, f)

    #================funtion load_session load session cookies from file ##########
    def load_session(self, filename: str):
        with open(filename, 'rb') as f:
            self.session.cookies.update(pickle.load(f))

    #================funtion set_basic_auth enable HTTP Basic auth on session ##########
    def set_basic_auth(self, username: str, password: str):
        self.session.auth = HTTPBasicAuth(username, password)
        self._update_swagger_security_schemes()

    #================funtion set_token_auth set bearer/API token header ##########
    def set_token_auth(self, token: str, header_name: str = "Authorization"):
        self.session.headers.update({header_name: f"Bearer {token}"})
        self.auth_tokens[header_name] = f"Bearer {token}"
        self._update_swagger_security_schemes()

    #================funtion set_custom_header add arbitrary header to session ##########
    def set_custom_header(self, header_name: str, header_value: str):
        self.session.headers.update({header_name: header_value})
        self.custom_headers[header_name] = header_value
        self._update_swagger_security_schemes()

    #================funtion set_login_form configure login form endpoint and data ##########
    def set_login_form(self, url: str, data: Dict[str, str]):
        self.login_url = url
        self.login_data = data

    #================funtion authenticate execute form login and extract token ##########
    def authenticate(self):
        if self.login_url and self.login_data:
            try:
                response = self._make_request('POST', self.login_url, data=self.login_data, timeout=10)
                if response.status_code == 200:
                    print("[+] Successfully logged in via form")
                    try:
                        json_data = response.json()
                        token = json_data.get('token') or json_data.get('access_token') or json_data.get('jwt')
                        if token:
                            self.set_token_auth(token)
                    except Exception:
                        token = response.headers.get('Authorization', '').replace('Bearer ', '')
                        if token:
                            self.set_token_auth(token)
            except Exception as e:
                print(f"[-] Login failed: {str(e)}")

    #================funtion _handle_rate_limiting handle HTTP 429 with retry-after/backoff ##########
    def _handle_rate_limiting(self, response: requests.Response) -> bool:
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    time.sleep(int(retry_after))
                except Exception:
                    time.sleep(5)
            return True
        return False

                                                                
    #================funtion crawl crawl base URL and discover APIs ##########
    def crawl(self, max_depth: int = 3, aggressive: bool = False):
        self.aggressive = aggressive or self.aggressive
        self.authenticate()
        self._crawl_page(self.base_url, max_depth)

        if self.aggressive:
            self._bruteforce_common_endpoints()
            self._check_common_headers()

    #================funtion _should_crawl decide if a URL should be crawled ##########
    def _should_crawl(self, url: str) -> bool:
        if not self._same_host(url):
            return False
        if url.startswith(('mailto:', 'tel:', 'javascript:')):
            return False
        skip_exts = ['.jpg', '.png', '.css', '.pdf', '.ico', '.svg']
                                                            
        if not self.aggressive:
            skip_exts.append('.js')
        if any(url.lower().endswith(ext) for ext in skip_exts):
            return False
        with self.lock:
            return url not in self.visited

    #================funtion _crawl_page fetch page, parse links/forms/scripts ##########
    def _crawl_page(self, url: str, depth: int):
        if depth < 0:
            return
        if not self._mark_visited(url):
            return

        try:
            print(f"[*] Crawling ({depth}): {url}")
            response = self._make_request('GET', url, timeout=10)
            content_type = response.headers.get('Content-Type', '')

            if 'text/html' in content_type or (self.aggressive and 'text/' in content_type):
                soup = BeautifulSoup(response.text, 'html.parser')

                       
                links = []
                for link in soup.find_all(['a', 'link'], href=True):
                    new_url = urljoin(url, link['href'])
                    if self._should_crawl(new_url):
                        links.append(new_url)

                                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self._crawl_page, link, depth - 1) for link in links]
                    for _ in as_completed(futures):
                        pass

                       
                for form in soup.find_all('form'):
                    self._process_form(url, form)

                           
                for script in soup.find_all('script'):
                    if script.string:
                        self._find_js_apis(script.string, url)
                        self._find_websockets(script.string, url)
                        self._find_graphql(script.string, url)

                             
                if self.aggressive:
                    for script in soup.find_all('script', src=True):
                        script_url = urljoin(url, script['src'])
                        if not self._same_host(script_url):
                            continue
                        try:
                            script_response = self._make_request('GET', script_url, timeout=5)
                            if script_response.status_code == 200:
                                self._find_js_apis(script_response.text, script_url)
                                self._find_websockets(script_response.text, script_url)
                                self._find_graphql(script_response.text, script_url)
                        except Exception as e:
                            print(f"[!] Error fetching JS: {script_url} - {str(e)}")

                                                  
                for tag in soup.find_all():
                    for attr, val in tag.attrs.items():
                        if attr.startswith("data-") and isinstance(val, str) and "http" in val:
                            self._process_possible_api(val)

                                
            if url.lower().endswith((".json", ".yaml", ".yml")):
                try:
                    resp = self._make_request('GET', url, timeout=5)
                    if resp.status_code == 200 and ("swagger" in resp.text or "openapi" in resp.text):
                        print(f"[+] Swagger/OpenAPI file: {url}")
                        self.swagger['externalDocs'] = {"url": url, "description": "External Swagger/OpenAPI spec"}
                except Exception as e:
                    print(f"[!] Swagger detection error on {url}: {str(e)}")

            if self._is_api_endpoint(url) or (self.aggressive and self._is_json_like(response)):
                self._process_api_response(url, response)

        except Exception as e:
            print(f"[!] Error at {url}: {str(e)}")

                                                                      
    #================funtion _check_common_headers probe with JSON-leaning headers ##########
    def _check_common_headers(self):
        headers_to_check = [
            ('Accept', 'application/json'),
            ('X-Requested-With', 'XMLHttpRequest'),
            ('Content-Type', 'application/json')
        ]
        print("[*] Aggressive: checking headers...")
        for url in list(self.visited):
            for header, value in headers_to_check:
                try:
                    headers = {header: value}
                    resp = self._make_request('GET', url, headers=headers, timeout=5 )
                    if resp.status_code == 200 and self._is_json_like(resp):
                        print(f"[+] API found with header {header}: {value} - {url}")
                        self._process_api_response(url, resp)
                except Exception as e:
                    print(f"[!] Header check error {url} {header}: {str(e)}")

    #================funtion _bruteforce_common_endpoints probe a list of common API endpoints ##########
    def _bruteforce_common_endpoints(self):
        common_endpoints = [
            '/api/v1/users', '/api/users', '/users',
            '/api/v1/products', '/api/products', '/products',
            '/api/v1/data', '/api/data', '/data',
            '/graphql', '/graphql/v1', '/api/graphql', '/api/v1/graphql',
            '/rest', '/rest/v1', '/api/rest', '/api/v1/rest',
            '/rpc', '/jsonrpc', '/api/soap', '/api/v1/soap',
            '/ws', '/health', '/status', '/metrics',
            '/v1', '/v2', '/v3',
            '/oauth2/token', '/.well-known/openid-configuration',
            '/swagger-ui', '/openapi.json', '/api-docs',
        ]
        print("[*] Aggressive: brute forcing common endpoints...")
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = []
            for endpoint in common_endpoints:
                url = urljoin(self.base_url, endpoint)
                if self._same_host(url) and url not in self.visited:
                    futures.append(executor.submit(self._process_possible_api, url))
            for _ in as_completed(futures):
                pass

                                                             
    #================funtion _classify_endpoint classify endpoint type (auth/public/data) ##########
    def _classify_endpoint(self, url: str) -> str:
        lower = url.lower()
        if any(x in lower for x in ["login", "logout", "auth", "token", "session", "wachtwoord"]):
            return "auth"
        elif any(x in lower for x in ["health", "status", "ping", "info"]):
            return "public"
        else:
            return "data"

    #================funtion _looks_like_api decide if response smells like API ##########
    def _looks_like_api(self, response: requests.Response) -> bool:
        if self._is_api_response(response) or self._is_json_like(response):
            return True
        headers = {k.lower(): v for k, v in response.headers.items()}
        signal_headers = ["x-api-version", "x-request-id", "x-total-count"]
        return any(h in headers for h in signal_headers)

    #================funtion _is_api_endpoint regex/heuristics to spot API path ##########
    def _is_api_endpoint(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        query = urlparse(url).query.lower()
        if any(re.search(pattern, path) for pattern in self.api_patterns):
            return True
        return (
            'api' in path or
            path.endswith('.json') or
            'json' in path or
            'xml' in path or
            'data' in path or
            'v1' in path or
            'v2' in path or
            'graphql' in path or
            'token=' in query or
            'auth=' in query or
            'bearer' in self.session.headers.get("Authorization", "").lower() or
            any(param in query for param in ['format=json', 'type=api', 'output=json'])
        )

    #================funtion _discover_methods discover allowed HTTP methods ##########
    def _discover_methods(self, url: str) -> List[str]:
        methods = set()
                                        
        try:
            r = self._make_request("OPTIONS", url, timeout=5)
            allow = r.headers.get("Allow", "")
            for m in allow.split(","):
                m = m.strip().lower()
                if m:
                    methods.add(m)
        except Exception:
            pass
                                          
        methods.add("get")
                                
        if self.aggressive:
            methods.update(["post", "put", "patch", "delete"])
        return sorted(methods)

    #================funtion _process_possible_api inspect URL and add to swagger ##########
    def _process_possible_api(self, url: str):
        if not url:
            return
        if not self._same_host(url):
            return
        if not self._mark_visited(url):
            return

                                   
        if url.lower().endswith(("swagger", "swagger.json", "swagger.yaml",
                                 "openapi", "openapi.json", "openapi.yaml")):
            self.swagger.setdefault("externalDocs", {})["url"] = url
            self.swagger["externalDocs"]["description"] = "External Swagger/OpenAPI file"
            print(f"[~] Skipped static Swagger file: {url}")
            return

        try:
                                              
            head = None
            try:
                head = self._make_request("HEAD", url, timeout=5)
            except Exception:
                pass
            resp = self._make_request("GET", url, timeout=10)

            if not self._looks_like_api(resp):
                print(f"[~] Ignored (non-API): {url}")
                return

            clean_path = self._normalise_path(url)
            classification = self._classify_endpoint(url)
            self.swagger["paths"].setdefault(clean_path, {})["x-classification"] = classification
            print(f"[+] API endpoint ({classification}): {clean_path}")

                           
            with open(self.log_path, "a", encoding="utf-8") as log:
                log.write(json.dumps({
                    "url": url,
                    "path": clean_path,
                    "status": resp.status_code,
                    "ct": resp.headers.get("Content-Type", ""),
                    "classification": classification
                }) + "\n")

                                                                     
            methods = self._discover_methods(url)
                                                             
            self._process_api_response(url, resp, method="get")
            for m in methods:
                if m == "get":
                    continue
                                                                   
                if self.aggressive:
                    try:
                        probe = self._make_request(m.upper(), url, timeout=5)
                        self._process_api_response(url, probe, method=m)
                    except Exception:
                                                                      
                        self._ensure_operation_exists(url, m, status="default")
                else:
                    self._ensure_operation_exists(url, m, status="default")

        except Exception as e:
            print(f"[!] Error processing API {url}: {str(e)}")

                                                                    
    #================funtion _ensure_operation_exists create operation shell in swagger ##########
    def _ensure_operation_exists(self, url: str, method: str, status: str = "default"):
        swagger_path = self._normalise_path(url)
        op = self.swagger["paths"].setdefault(swagger_path, {}).setdefault(method, {})
        if "responses" not in op:
            op["responses"] = {}
        op["responses"].setdefault(status, {"description": "Auto-discovered (no sample response)"})

    #================funtion _process_api_response extract params and response schema ##########
    def _process_api_response(self, url: str, response: requests.Response, method: str = "get"):
        if not self._looks_like_api(response):
            return
        parsed = urlparse(url)
        path = parsed.path

                      
        query_params = []
        for name, values in parse_qs(parsed.query).items():
            query_params.append({
                "name": name,
                "in": "query",
                "schema": {"type": "string"},
                "example": values[0]
            })

        swagger_path = self._normalise_path(url)

                         
        ct = response.headers.get('Content-Type', 'application/json')
        schema: Dict[str, Any] = {"type": "string"}
        if self._is_json_like(response):
            try:
                data = response.json()
                schema = self._generate_schema(data)
                                          
                if isinstance(data, dict):
                    for link_key in ['_links', 'links', 'related', 'href']:
                        if link_key in data:
                            links = data[link_key]
                            if isinstance(links, dict):
                                for _, link in links.items():
                                    if isinstance(link, str):
                                        self._process_possible_api(urljoin(url, link))
                                    elif isinstance(link, dict) and 'href' in link:
                                        self._process_possible_api(urljoin(url, link['href']))
            except Exception:
                pass

        security = []
        if self.session.auth:
            security.append({"basicAuth": []})
        if self.auth_tokens:
            security.append({"bearerAuth": []})

        if swagger_path not in self.swagger['paths']:
            self.swagger['paths'][swagger_path] = {}

        operation = self.swagger['paths'][swagger_path].setdefault(method, {})
        operation.setdefault('summary', f'Auto-discovered {method.upper()} endpoint')
                      
        existing_params = operation.setdefault('parameters', [])
        names = {p.get("name") for p in existing_params}
        for p in query_params:
            if p["name"] not in names:
                existing_params.append(p)
        if security:
            operation['security'] = security

        operation.setdefault('responses', {})
        operation['responses'][str(response.status_code)] = {
            'description': 'Auto-discovered response',
            'content': {
                ct: {'schema': schema}
            }
        }

    #================funtion _generate_schema infer JSON schema from example data ##########
    def _generate_schema(self, data: Any) -> Dict[str, Any]:
                    
        if data is None:
            return {'type': 'null'}
        if isinstance(data, bool):
            return {'type': 'boolean'}
        if isinstance(data, int):
            return {'type': 'integer'}
        if isinstance(data, float):
            return {'type': 'number'}
        if isinstance(data, str):
                                  
            if re.match(r'^\d{4}-\d{2}-\d{2}(T.*)?$', data):
                return {'type': 'string', 'format': 'date-time'}
            if re.match(r'^[0-9a-fA-F-]{36}$', data):
                return {'type': 'string', 'format': 'uuid'}
            return {'type': 'string'}

                
        if isinstance(data, list):
            if not data:
                return {'type': 'array', 'items': {'type': 'string'}}
            return {'type': 'array', 'items': self._generate_schema(data[0])}

                 
        if isinstance(data, dict):
            properties: Dict[str, Any] = {}
            required: List[str] = []
            for k, v in list(data.items())[:200]:                           
                properties[k] = self._generate_schema(v)
                if k in ['id', 'name', 'email', 'username', 'title', 'description']:
                    required.append(k)
            schema: Dict[str, Any] = {'type': 'object', 'properties': properties}
            if required:
                schema['required'] = required
            return schema

                  
        return {'type': 'string'}

                                                                
    #================funtion _process_form convert HTML form to OpenAPI operation ##########
    def _process_form(self, base_url: str, form):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        url = urljoin(base_url, action)

        if not self._is_api_endpoint(url) and not any(x in url.lower() for x in ("login", "auth")):
            return

                                               
        try:
            head_resp = self._make_request("HEAD", url, timeout=5)
        except Exception:
            head_resp = None

        clean_path = self._normalise_path(url)
                       
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            if inp.name == "select":
                fields[name] = inp.get("value") or "string"
            else:
                fields[name] = inp.get("value") or "string"

                                                 
        if clean_path not in self.swagger["paths"]:
            self.swagger["paths"][clean_path] = {}
        op = self.swagger["paths"][clean_path].setdefault(method, {})
        op["summary"] = op.get("summary") or "Auto-discovered form endpoint"
        op["responses"] = op.get("responses") or {"200": {"description": "Successful form submission"}}

                                     
        op["requestBody"] = {
            "required": True,
            "content": {
                "application/x-www-form-urlencoded": {
                    "schema": {
                        "type": "object",
                        "properties": {k: {"type": "string", "example": v} for k, v in fields.items()}
                    }
                }
            }
        }

    #================funtion _find_js_apis extract API URLs from JS ##########
    def _find_js_apis(self, js_code: str, base_url: str):
                                                                    
        patterns = [
            (r'fetch\(["\'](.*?)["\']', 1),
            (r'axios\.(get|post|put|delete|patch)\(["\'](.*?)["\']', 2),
            (r'\.(get|post|put|delete|patch)\(["\'](.*?)["\']', 2),
            (r'api(?:Url|Base|Endpoint)\s*[:=]\s*["\'](.*?)["\']', 1),
            (r'new\s+XMLHttpRequest\(\)[^;]+\.open\(["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']', 1),
            (r'endpoint\s*[:=]\s*["\'](.*?)["\']', 1),
            (r'url\s*[:=]\s*["\'](.*?)["\']', 1),
        ]
        for pat, group_idx in patterns:
            for m in re.finditer(pat, js_code, re.DOTALL | re.IGNORECASE):
                path = (m.group(group_idx) or "").strip()
                if not path or '%s' in path or '{' in path or '}' in path:
                    continue
                api_url = urljoin(base_url, path)
                if self._should_inspect(api_url):
                    print(f"[+] JS API found: {api_url}")
                    self._process_possible_api(api_url)

    #================funtion _find_websockets extract websocket endpoints from code ##########
    def _find_websockets(self, text: str, base_url: str):
        patterns = [
            r'new\s+WebSocket\(["\'](wss?://[^"\']+)["\']',
            r'\.connect\(["\'](wss?://[^"\']+)["\']',
            r'socket\.io\(["\']([^"\']+)["\']'
        ]
        for pat in patterns:
            for m in re.finditer(pat, text, re.DOTALL | re.IGNORECASE):
                ws_url = urljoin(base_url, m.group(1))
                if 'wsServers' not in self.swagger:
                    self.swagger['wsServers'] = []
                if {"url": ws_url} not in self.swagger['wsServers']:
                    self.swagger['wsServers'].append({"url": ws_url})
                    print(f"[+] WebSocket found: {ws_url}")

    #================funtion _find_graphql extract GraphQL endpoints from code ##########
    def _find_graphql(self, text: str, base_url: str):
        patterns = [
            r'graphqlUrl:\s*["\']([^"\']+)["\']',
            r'uri:\s*["\']([^"\']+/graphql)["\']',
            r'fetch\(["\']([^"\']+/graphql)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, text, re.DOTALL | re.IGNORECASE):
                gql_url = urljoin(base_url, m.group(1))
                if self._should_inspect(gql_url):
                    print(f"[+] GraphQL endpoint found: {gql_url}")
                    self._process_possible_api(gql_url)

    #================funtion _should_inspect filter URLs before inspection ##########
    def _should_inspect(self, url: str) -> bool:
        if not self._same_host(url):
            return False
        if any(x in url for x in ['google-analytics', 'facebook', 'twitter', 'linkedin', 'youtube']):
            return False
        if any(url.lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif']):
            return False
        with self.lock:
            return url not in self.visited

                                                              

    #================funtion _prune_non_json_paths remove paths without JSON-ish responses ##########
    def _prune_non_json_paths(self):
        bad = []
        for path, ops in self.swagger["paths"].items():
            any_jsonish = False
                                                                               
            for key, op in ops.items():
                if not isinstance(op, dict):
                    continue
                if key.lower() not in {"get","post","put","delete","patch","options","head"}:
                    continue
                for resp in (op.get("responses") or {}).values():
                    if not isinstance(resp, dict):
                        continue
                    content = resp.get("content") or {}
                    if any(ct for ct in content.keys() if any(h in ct for h in JSON_CT_HINTS)):
                        any_jsonish = True
                        break
                if any_jsonish:
                    break
            if not any_jsonish:
                bad.append(path)
        for p in bad:
            del self.swagger["paths"][p]

    #================funtion save_swagger write swagger file and print stats ##########
    def save_swagger(self, filename: str):
        with open(filename, 'w', encoding="utf-8") as f:
            json.dump(self.swagger, f, indent=2, ensure_ascii=False)
        print(f"[+] Swagger saved as {filename}")
        print(f"[+] Total endpoints found: {len(self.swagger['paths'])}")
        print(f"[+] Security schemes: {list(self.swagger['components']['securitySchemes'].keys())}")
        if 'wsServers' in self.swagger:
            print(f"[+] WebSocket servers found: {len(self.swagger['wsServers'])}")

                                                           
#================funtion configure_authentication build requests session with chosen auth ##########
def configure_authentication(args) -> requests.Session:
    sess = requests.Session()
    sess.verify = not getattr(args, 'insecure', False)
    if not sess.verify:
        print("[!] SSL verification disabled")
    if args.token:
        sess.headers['Authorization'] = f"Bearer {args.token}"
        print("[+] Bearer token set")
    if args.basic_auth:
        try:
            user, pwd = args.basic_auth.split(':', 1)
            sess.auth = HTTPBasicAuth(user, pwd)
            print("[+] Basic auth set")
        except ValueError:
            print("[-] Invalid basic auth format. Use 'username:password'")
            sys.exit(1)
    if args.ntlm:
        try:
            match = re.match(r"(.+)\\(.+):(.+)", args.ntlm)
            if match:
                domain, user, pwd = match.groups()
                sess.auth = HttpNtlmAuth(f"{domain}\\{user}", pwd)
                print("[+] NTLM auth set")
            else:
                raise ValueError("Invalid NTLM format")
        except Exception as e:
            print(f"[-] NTLM auth error: {str(e)}")
            sys.exit(1)
    if args.apikey:
        header = args.apikey_header or "X-API-Key"
        sess.headers[header] = args.apikey
        print(f"[+] API Key set in header '{header}'")
                               
    if getattr(args, "flow", None) == "client" and args.client_id and args.client_secret and args.token_url:
        try:
            client = BackendApplicationClient(client_id=args.client_id)
            oauth = OAuth2Session(client=client)
            token = oauth.fetch_token(
                token_url=args.token_url,
                client_id=args.client_id,
                client_secret=args.client_secret
            )
            sess = oauth
            print("[+] OAuth2 Client Credentials set")
        except Exception as e:
            print(f"[-] OAuth2 error: {str(e)}")
            sys.exit(1)
    return sess

                                                   
#================funtion main CLI entry point ##########
def main():
    parser = argparse.ArgumentParser(description="Ultimate Swagger Generator (Improved v2)")
    parser.add_argument("--url", required=True, help="Base URL to scan")
    parser.add_argument("--output", default="swagger.json", help="Output file path")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--aggressive", action='store_true', help="Enable aggressive scanning")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay (in seconds) between requests)")

          
    auth = parser.add_argument_group('Authentication')
    auth.add_argument("--header", action='append', help="Custom header (format: 'Header-Name: value')", default=[])
    auth.add_argument("--token", help="Bearer token for authentication")
    auth.add_argument("--basic-auth", help="Basic auth in format user:password")
    auth.add_argument("--ntlm", help="NTLM auth in format domain\\user:password")
    auth.add_argument("--apikey", help="API key value")
    auth.add_argument("--apikey-header", help="Header name for API key")
    auth.add_argument("--flow", choices=["client"], help="OAuth2 flow type")
    auth.add_argument("--client-id", help="OAuth2 client ID")
    auth.add_argument("--client-secret", help="OAuth2 client secret")
    auth.add_argument("--token-url", help="OAuth2 token URL")

             
    session = parser.add_argument_group('Session')
    session.add_argument("--save-session", help="File to save session cookies")
    session.add_argument("--load-session", help="File to load session cookies from")

         
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")

    args = parser.parse_args()

    try:
        generator = UltimateSwaggerGenerator(args.url, delay=args.delay, aggressive=args.aggressive)
        generator.session = configure_authentication(args)

        if args.load_session:
            generator.load_session(args.load_session)

        for header in args.header:
            try:
                name, value = header.split(':', 1)
                generator.set_custom_header(name.strip(), value.strip())
            except ValueError:
                print(f"[-] Invalid header format: {header}")
                sys.exit(1)

        generator.crawl(args.depth, args.aggressive)
        generator._prune_non_json_paths()

        if args.save_session:
            generator.save_session(args.save_session)

        generator.save_swagger(args.output)

    except Exception as e:
        print(f"[-] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
