# Ultimate Swagger Generator
##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
# pamsniffer@gmail.com                               #
##################################
import argparse
import json
import re
import sys
import urllib3
import pickle
import time
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import requests
import logging
import threading
from queue import Queue
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient, WebApplicationClient
from concurrent.futures import ThreadPoolExecutor, as_completed


logging.getLogger("urllib3").setLevel(logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UltimateSwaggerGenerator:
    def __init__(self, base_url: str, delay: float = 0.0):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.delay = delay
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/140.0',
            'Accept': 'application/json, text/html, application/xml',
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
        self.api_patterns = [
            r'(?i)/api/',
            r'(?i)/v[0-9]+/',
            r'(?i)\.(json|xml)$',
            r'(?i)/graphql',
            r'(?i)/rest/',
            r'(?i)/data/',
            r'(?i)/swagger',
            r'(?i)/openapi',
            r'(?i)/endpoints',
            r'(?i)/services/',
            r'(?i)/rpc/',
            r'(?i)/jsonrpc',
            r'(?i)/soap/',
            r'(?i)/ws/',
            r'(?i)/wss/',
            r'(?i)/socket.io',
            r'(?i)/sockjs',
            r'(?i)/_ah/api',
            r'(?i)/_api',
            r'(?i)/ajax/',
            r'(?i)/async/',
            r'(?i)/backend/',
            r'(?i)/v2/',
            r'(?i)/v3/',
        ]
        self.param_patterns = [
            r'id=[^&]+',
            r'page=\d+',
            r'limit=\d+',
            r'search=[^&]+',
            r'filter=[^&]+',
            r'sort=[^&]+,'
        ]
        self.auth_tokens = {}
        self.login_url = None
        self.login_data = None
        self.custom_headers = {}

    
    # ------------------------------------------------------------------
    # Helper: normalise a URL so it becomes a valid OpenAPI path
    # ------------------------------------------------------------------
    def _is_api_response(self, response):
        content_type = response.headers.get("Content-Type", "").lower()
        valid_types = [
            "application/json",
            "application/xml",
            "text/xml",
            "application/x-ndjson",
            "application/vnd.api+json",
        ]
        return any(vt in content_type for vt in valid_types)

    
    def _normalise_path(self, url):
        parsed = urlparse(url)
        path = parsed.path or "/"

        # verwijder fragment
        if "#" in path:
            path = path.split("#", 1)[0]

        # numerieke id-s /123  -> /{id}
        path = re.sub(r"/\d+", "/{id}", path)

        # Mongo-achtige 24-hex ids -> /{objectId}
        path = re.sub(r"/[a-f0-9]{24}", "/{objectId}", path, flags=re.I)

        # alles wat eindigt op XxxId of _id  -> placeholder
        path = re.sub(r"/([^/]*_?[iI][dD])", r"/{\1}", path)

        return path
    
    def _make_request(self, method, url, **kwargs):
        while True:
            if self.delay:
                time.sleep(self.delay)
            response = self.session.request(method, url, **kwargs)
            
            if not self._handle_rate_limiting(response):  # Retourneert False als niet geretryd hoeft
                return response
        
 
    
    def _update_swagger_security_schemes(self):
        """Update Swagger security schemes based on active authentication"""
        if isinstance(self.session.auth, HTTPBasicAuth):
            self.swagger["components"]["securitySchemes"]["basicAuth"] = {
                "type": "http",
                "scheme": "basic"
            }
        
        # For API keys
        for header in self.session.headers:
            if header.lower() in ['x-api-key', 'api-key']:
                self.swagger["components"]["securitySchemes"]["apiKeyAuth"] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": header
                }

    def save_session(self, filename: str):
        """Save session cookies for reuse"""
        with open(filename, 'wb') as f:
            pickle.dump(self.session.cookies, f)
    
    def load_session(self, filename: str):
        """Load saved session cookies"""
        with open(filename, 'rb') as f:
            self.session.cookies.update(pickle.load(f))

    def set_basic_auth(self, username: str, password: str):
        """Configure basic authentication"""
        self.session.auth = HTTPBasicAuth(username, password)
        self._update_swagger_security_schemes()

    def set_token_auth(self, token: str, header_name: str = "Authorization"):
        """Configure token authentication"""
        self.session.headers.update({header_name: f"Bearer {token}"})
        self.auth_tokens[header_name] = f"Bearer {token}"
        self._update_swagger_security_schemes()

    def set_custom_header(self, header_name: str, header_value: str):
        """Set custom headers that might be required for API access"""
        self.session.headers.update({header_name: header_value})
        self.custom_headers[header_name] = header_value
        self._update_swagger_security_schemes()

    def set_login_form(self, url: str, data: Dict[str, str]):
        """Configure form-based login"""
        self.login_url = url
        self.login_data = data

    def authenticate(self):
        """Perform authentication if configured"""
        if self.login_url and self.login_data:
            try:
                response = self._make_request(
                   'POST',
                    self.login_url,
                    data=self.login_data,
                    timeout=10
                )
                if response.status_code == 200:
                    print("[+] Successfully logged in via form")
                    # Try to extract JWT token from response
                    try:
                        json_data = response.json()
                        token = json_data.get('token') or json_data.get('access_token') or json_data.get('jwt')
                        if token:
                            self.set_token_auth(token)
                    except:
                        # Check for token in headers
                        token = response.headers.get('Authorization', '').replace('Bearer ', '')
                        if token:
                            self.set_token_auth(token)
            except Exception as e:
                print(f"[-] Login failed: {str(e)}")

    def _handle_rate_limiting(self, response):
        """Handle rate limiting headers"""
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"[!] Rate limited - waiting {retry_after} seconds")
            time.sleep(retry_after)
            return True
        return False

    def crawl(self, max_depth: int = 3, aggressive: bool = False):
        """Improved crawler with aggressive mode"""
        self.authenticate()
        self._crawl_page(self.base_url, max_depth, aggressive)

        if aggressive:
            self._bruteforce_common_endpoints()
            self._check_common_headers()

    def _check_common_headers(self):
        """Check for APIs that might be hidden behind specific headers"""
        headers_to_check = [
            ('Accept', 'application/json'),
            ('X-Requested-With', 'XMLHttpRequest'),
            ('Content-Type', 'application/json')
        ]
        
        print("[*] Aggressive scan: checking headers...")
        for url in list(self.visited):
            for header, value in headers_to_check:
                try:
                    headers = {header: value}
                    response = self._make_request('GET', url, headers=headers, timeout=5 )
                                       
                    if response.status_code == 200 and self._looks_like_api(response):
                        print(f"[+] API found with header {header}: {value} - {url}")
                        self._process_api_response(url, response)
                except Exception as e:
                    print(f"[!] Error checking {url} with header {header}: {str(e)}")
                    continue

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

        print("[*] Aggressive scan: checking common endpoints...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for endpoint in common_endpoints:
                url = urljoin(self.base_url, endpoint)
                if url not in self.visited:
                    futures.append(executor.submit(self._process_possible_api, url))
            for _ in as_completed(futures):
                pass


    def _crawl_page(self, url: str, depth: int, aggressive: bool):
        if depth < 0 or url in self.visited:
            return

        try:
            print(f"[*] Crawling ({depth}): {url}")
            self.visited.add(url)
            response = self._make_request('GET', url, timeout=10)
            
            content_type = response.headers.get('Content-Type', '')

            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Verzamel te crawlen links
                links = []
                for link in soup.find_all(['a', 'link'], href=True):
                    new_url = urljoin(url, link['href'])
                    if self._should_crawl(new_url):
                        links.append(new_url)

                # Crawl links parallel
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self._crawl_page, link, depth - 1, aggressive) for link in links]
                    for _ in as_completed(futures):
                        pass

                # Analyseer formulieren
                for form in soup.find_all('form'):
                    self._process_form(url, form)

                # Inline JS
                for script in soup.find_all('script'):
                    if script.string:
                        self._find_js_apis(script.string, url)
                        self._find_websockets(script.string, url)
                        self._find_graphql(script.string, url)

                # Externe JS-bestanden
                for script in soup.find_all('script', src=True):
                    script_url = urljoin(url, script['src'])
                    if urlparse(script_url).netloc != urlparse(self.base_url).netloc:
                        continue  # skip externe domeinen
                    try:
                        script_response = self._make_request('GET', script_url, timeout=5)
                        if script_response.status_code == 200:
                            self._find_js_apis(script_response.text, script_url)
                            self._find_websockets(script_response.text, script_url)
                            self._find_graphql(script_response.text, script_url)
                    except Exception as e:
                        print(f"[!] Fout bij ophalen extern JS: {script_url} - {str(e)}")

                # Meta en data-attributen
                for meta in soup.find_all("meta"):
                    content = meta.get("content", "")
                    if any(api in content.lower() for api in ["api", "endpoint"]):
                        self._process_possible_api(urljoin(url, content))

                for tag in soup.find_all():
                    for attr, val in tag.attrs.items():
                        if attr.startswith("data-") and isinstance(val, str) and "http" in val:
                            self._process_possible_api(val)

                # HTML-comments met API hints
                for comment in soup.find_all(string=lambda text: isinstance(text, str) and "api" in text.lower()):
                    self._find_hidden_apis(comment, url)
                woorden = [
                    "login", "logout", "register", "status", "user", "users", "account", "accounts", "profile", "profiles",
                    "search", "query", "filter", "config", "settings", "setup", "system", "health", "metrics", "info",
                    "auth", "authenticate", "authorization", "token", "session", "password", "reset", "forgot", "validate",
                    "admin", "dashboard", "panel", "report", "reports", "data", "export", "import", "backup", "restore",
                    "product", "products", "item", "items", "order", "orders", "invoice", "billing", "payment", "checkout",
                    "cart", "wishlist", "notification", "notifications", "message", "messages", "chat", "support",
                    "upload", "download", "file", "files", "document", "documents", "image", "images", "media", "attachment",
                    # Nederlandse varianten
                    "inloggen", "uitloggen", "registreren", "status", "gebruiker", "gebruikers", "profiel", "profielen",
                    "zoeken", "filteren", "instellingen", "configuratie", "systeem", "gezondheid", "informatie",
                    "machtiging", "sessie", "wachtwoord", "herstellen", "vergeten", "valideren",
                    "beheer", "dashboard", "rapport", "rapporten", "gegevens", "exporteren", "importeren", "back-up", "herstel",
                    "product", "producten", "item", "items", "bestelling", "bestellingen", "factuur", "betaling", "afrekenen",
                    "winkelwagen", "verlanglijst", "melding", "meldingen", "bericht", "berichten", "ondersteuning",
                    "uploaden", "downloaden", "bestand", "bestanden", "document", "documenten", "afbeelding", "media", "bijlage"
                ]
                for word in woorden:
                    for prefix in ["/api/", "/v1/", "/v2/", "/", ""]:
                        guess_url = urljoin(self.base_url, f"{prefix}{word}")
                        if guess_url not in self.visited:
                            self._process_possible_api(guess_url)

            # Swagger autodetectie
            if url.endswith(".json") or url.endswith(".yaml"):
                try:
                    resp = self._make_request('GET', url, timeout=5)
                    if self.delay:
                        time.sleep(self.delay)
                    if resp.status_code == 200 and ("swagger" in resp.text or "openapi" in resp.text):
                        print(f"[+] Swagger of OpenAPI bestand gevonden: {url}")
                        self.swagger['externalDocs'] = {"url": url, "description": "External Swagger/OpenAPI spec"}
                except Exception as e:
                    print(f"[!] Fout bij Swagger-detectie op {url}: {str(e)}")

            if self._is_api_endpoint(url) or ('application/json' in content_type and aggressive):
                self._process_api_response(url, response)

        except Exception as e:
            print(f"[!] Error at {url}: {str(e)}")
                
                               
 

    def _classify_endpoint(self, url: str) -> str:
        lower = url.lower()
        if any(x in lower for x in ["login", "logout", "auth", "token", "session", "wachtwoord"]):
            return "auth"
        elif any(x in lower for x in ["health", "status", "ping", "info"]):
            return "public"
        else:
            return "data"
    
        
    def _process_possible_api(self, url):
        """
        Probe a candidate URL, decide whether it is an API endpoint,
        and record the result in the Swagger model.
        """
        if not url:
            return

        # Deduplicate across threads
        if url in self.visited:
            return
        self.visited.add(url)

        # Same host only
        if urlparse(url).netloc != urlparse(self.base_url).netloc:
            return

        # Skip static Swagger/OpenAPI files early
        if url.lower().endswith(
            ("swagger", "swagger.json", "swagger.yaml",
             "openapi", "openapi.json", "openapi.yaml")
        ):
            # Treat as external documentation
            self.swagger.setdefault("externalDocs", {})["url"] = url
            self.swagger["externalDocs"]["description"] = "External Swagger/OpenAPI file"
            print(f"[~] Skipped static Swagger file: {url}")
            return

        try:
            resp = self._make_request("GET", url, timeout=5)

            if not self._is_api_response(resp):
                print(f"[~] Ignored (non-API format): {url}")
                return

            clean_path = self._normalise_path(url)

            if resp.status_code in {200, 204, 401, 403, 405} \
               and self._looks_like_api(resp):

                classification = self._classify_endpoint(url)
                self.swagger["paths"].setdefault(
                    clean_path, {})["x-classification"] = classification
                print(f"[+] API endpoint ({classification}): {clean_path}")

                with open("scan_log.txt", "a", encoding="utf-8") as log:
                    log.write(f"[{classification}] {clean_path}\n")

            else:
                print(f"[~] Not a valid API (status={resp.status_code}): {clean_path}")

        except Exception as e:
            print(f"[!] Error processing API {url}: {str(e)}")


    def _looks_like_api(self, response):
        if self._is_api_response(response):
            return True

        headers = {k.lower(): v for k, v in response.headers.items()}
        signal_headers = ["x-api-version", "x-request-id", "x-total-count"]

        return any(h in headers for h in signal_headers)

    def _find_hidden_apis(self, text: str, base_url: str):
        """Search for API endpoints in comments and metadata"""
        patterns = [
            r'https?://[^\s"\']+/api/[^\s"\']+',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'apiUrl:\s*["\']([^"\']+)["\']',
            r'baseUrl:\s*["\']([^"\']+)["\']',
            r'serviceUrl:\s*["\']([^"\']+)["\']',
            r'backendUrl:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                api_url = urljoin(base_url, match.group(0 if pattern == patterns[0] else 1))
                if api_url not in self.visited:
                    print(f"[+] Hidden API found: {api_url}")
                    self._process_possible_api(api_url)

    def _process_form(self, base_url, form):
        """
        Inspect an HTML <form>.  If the target URL looks like an API that
        returns JSON, describe it as an operation in the Swagger model.
        """

        # 1. Resolve the form action to an absolute URL
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        url = urljoin(base_url, action)

        # 2. Skip if the URL is clearly not an API and not auth related
        if not self._is_api_endpoint(url) and not any(
            x in url.lower() for x in ("login", "auth")
        ):
            return

        # 3. Quick HEAD request to verify the endpoint returns JSON
        try:
            head_resp = self._make_request("HEAD", url, timeout=5)
        except Exception:
            # Some servers forbid HEAD; fall back to a small GET
            head_resp = self._make_request("GET", url, timeout=5)

        if not self._is_api_response(head_resp):
            return  # ignore forms whose action is not JSON

        # 4. Normalise the path so it is a valid OpenAPI key
        clean_path = self._normalise_path(url)

        # 5. Collect form parameters
        parameters = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            param = {
                "name": name,
                "in": "formData",
                "required": inp.get("required") is not None,
                "schema": {
                    "type": inp.get("type", "string"),
                },
            }
            if inp.get("value"):
                param["schema"]["example"] = inp.get("value")
            parameters.append(param)

        # 6. Build the operation object
        operation = {
            "summary": f"Auto-discovered {method.upper()} form endpoint",
            "responses": {
                "200": {"description": "Successful form submission"}
            },
        }
        if parameters:
            operation["parameters"] = parameters

        # 7. Insert into the Swagger model
        if clean_path not in self.swagger["paths"]:
            self.swagger["paths"][clean_path] = {}

        self.swagger["paths"][clean_path][method] = operation


    def _find_js_apis(self, js_code: str, base_url: str):
        """Extended JavaScript API detection"""
        patterns = [
            r'(fetch|axios|ajax)\(["\'](.+?)["\']',
            r'\.(get|post|put|delete|patch)\(["\'](.+?)["\']',
            r'api(?:Url|Base|Endpoint)\s*[:=]\s*["\'](.+?)["\']',
            r'fetch\(["\'](.+?)["\']',
            r'axios\.(get|post|put|delete|patch)\(["\'](.+?)["\']',
            r'url\s*[:=]\s*["\'](.+?)["\']',
            r'endpoint\s*[:=]\s*["\'](.+?)["\']',
            r'new\s+XMLHttpRequest\(\)[^;]+\.open\(["\'](GET|POST)["\'],\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_code, re.DOTALL):
                if 'fetch' in pattern or 'XMLHttpRequest' in pattern:
                    path = match.group(2).strip()
                    if not path or '%s' in path or 'concat' in path or '{' in path or '}' in path:
                        continue
                    api_url = urljoin(base_url, path)
                    #if not re.match(r'^/[\w\-/]+$', path):
                    #    continue
                else:
                    api_url = urljoin(base_url, match.group(1))
                
                if self._should_inspect(api_url):
                    print(f"[+] JS API found: {api_url}")
                    self._process_possible_api(api_url)

    def _find_websockets(self, text: str, base_url: str):
        """Find WebSocket connections in JavaScript"""
        patterns = [
            r'new\s+WebSocket\(["\'](wss?://[^"\']+)["\']',
            r'\.connect\(["\'](wss?://[^"\']+)["\']',
            r'socket\.io\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.DOTALL):
                ws_url = urljoin(base_url, match.group(1))
                if ws_url not in self.visited:
                    print(f"[+] WebSocket found: {ws_url}")
                    # Add to Swagger as a separate servers entry
                    if 'wsServers' not in self.swagger:
                        self.swagger['wsServers'] = []
                    if ws_url not in self.swagger['wsServers']:
                        self.swagger['wsServers'].append({"url": ws_url})

    def _find_graphql(self, text: str, base_url: str):
        """Find GraphQL endpoints"""
        patterns = [
            r'graphqlUrl:\s*["\']([^"\']+)["\']',
            r'uri:\s*["\']([^"\']+/graphql)["\']',
            r'fetch\(["\']([^"\']+/graphql)["\']',
            r'operationName:\s*["\']([^"\']+)["\']',
            r'query\s*{\s*[^}]*}\s*,\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.DOTALL):
                gql_url = urljoin(base_url, match.group(1))
                if gql_url not in self.visited:
                    print(f"[+] GraphQL endpoint found: {gql_url}")
                    self._process_possible_api(gql_url)


    def _prune_non_json_paths(self):
        bad_paths = []
        for path, ops in self.swagger["paths"].items():
            first_op = next(iter(ops.values()), {})
            first_resp_code = next(iter(first_op.get("responses", {})), None)
            if not first_resp_code:
                bad_paths.append(path)
                continue

            first_resp = first_op["responses"][first_resp_code]
            ctypes = first_resp.get("content", {}).keys()

            if not any(
                ct.startswith("application/json") or ct in (
                    "application/xml",
                    "text/xml",
                    "application/x-ndjson",
                    "application/vnd.api+json",
                )
                for ct in ctypes
            ):
                bad_paths.append(path)

        for p in bad_paths:
            del self.swagger["paths"][p]



    def _process_api_response(self, url: str, response):
        """Improved API response handling"""
        if not self._is_api_response(response):
            return
        parsed = urlparse(url)
        path = parsed.path
        method = 'get'
        
        # Detect parameters
        query_params = []
        for name, values in parse_qs(parsed.query).items():
            query_params.append({
                'name': name,
                'in': 'query',
                'schema': {'type': 'string'},
                'example': values[0]
            })
        
        # Path parameters
        path_params = re.findall(
            r"/(\d+|[a-f0-9]{24}|[^/]+_[iI][dD]|[^/]+[iI]d)/",
            path,
            re.IGNORECASE,
        )
        swagger_path = self._normalise_path(url)
        for param in path_params:
            swagger_path = swagger_path.replace(param, f'{{{param}}}')
        
        # Response schema
        schema = {'type': 'string'}
        if 'application/json' in response.headers.get('Content-Type', ''):
            try:
                data = response.json()
                schema = self._generate_schema(data)
                
                # If it's a list, try to get schema from first item
                if isinstance(data, list) and data:
                    schema = {
                        'type': 'array',
                        'items': self._generate_schema(data[0])
                    }
                
                # Check for HATEOAS links in JSON responses
                if isinstance(data, dict):
                    # Follow common HATEOAS link patterns
                    for link_key in ['_links', 'links', 'related', 'href']:
                        if link_key in data:
                            links = data[link_key]
                            if isinstance(links, dict):
                                for name, link in links.items():
                                    if isinstance(link, str):
                                        self._process_possible_api(urljoin(url, link))
                                    elif isinstance(link, dict) and 'href' in link:
                                        self._process_possible_api(urljoin(url, link['href']))
            except:
                pass
        
        # Security requirements
        security = []
        if self.session.auth:
            security.append({"basicAuth": []})
        if self.auth_tokens:
            security.append({"bearerAuth": []})
        
        # Add to Swagger
        if swagger_path not in self.swagger['paths']:
            self.swagger['paths'][swagger_path] = {}
            
        operation = {
            'summary': f'Auto-discovered {method.upper()} endpoint',
            'responses': {
                str(response.status_code): {
                    'description': 'Auto-discovered response',
                    'content': {
                        response.headers.get('Content-Type', 'application/json'): {
                            'schema': schema
                        }
                    }
                }
            }
        }
        
        if query_params:
            operation['parameters'] = query_params
        if security:
            operation['security'] = security
            
        self.swagger['paths'][swagger_path][method] = operation

    def _generate_schema(self, data: Any) -> Dict:
        """Generate JSON schema from data"""
        if isinstance(data, dict):
            properties = {}
            required = []
            for k, v in data.items():
                properties[k] = self._generate_schema(v)
                if k in ['id', 'name', 'email', 'username', 'title', 'description']:  # Mark common required fields
                    required.append(k)
            
            schema = {
                'type': 'object',
                'properties': properties
            }
            if required:
                schema['required'] = required
            return schema
        elif isinstance(data, list) and data:
            return {
                'type': 'array',
                'items': self._generate_schema(data[0])
            }
        else:
            return {'type': type(data).__name__.lower()}

    def _should_crawl(self, url: str) -> bool:
        """Determine if a URL should be crawled"""
        parsed = urlparse(url)
        return (
            parsed.netloc == urlparse(self.base_url).netloc and
            not any(ext in url for ext in ['.jpg', '.png', '.css', '.js', '.pdf', '.ico', '.svg']) and
            url not in self.visited and
            not url.startswith('mailto:') and
            not url.startswith('tel:') and
            not url.startswith('javascript:')
        )

    def _should_inspect(self, url: str) -> bool:
        """Determine if a URL should be inspected"""
        return (
            urlparse(url).netloc == urlparse(self.base_url).netloc and
            url not in self.visited and
            not any(x in url for x in ['google-analytics', 'facebook', 'twitter', 'linkedin', 'youtube']) and
            not any(ext in url for ext in ['.css', '.js', '.png', '.jpg', '.gif'])
        )

    def _is_api_endpoint(self, url: str) -> bool:
        """Determine if a URL is an API endpoint"""
        path = urlparse(url).path.lower()
        query = urlparse(url).query.lower()
        return (
            any(re.search(pattern, path) for pattern in self.api_patterns) or
            'api' in path or
            path.endswith('.json') or
            'json' in path or
            'xml' in path or
            'data' in path or
            'v1' in path or
            'v2' in path or
            'token=' in query or 
            'auth=' in query or
            'bearer' in self.session.headers.get("Authorization", "").lower() or
            any(param in query for param in ['format=json', 'type=api', 'output=json'])
        )

    def save_swagger(self, filename: str):
        """Save the Swagger specification"""
        with open(filename, 'w') as f:
            json.dump(self.swagger, f, indent=2)
        print(f"[+] Swagger saved as {filename}")
        print(f"[+] Total endpoints found: {len(self.swagger['paths'])}")
        print(f"[+] Authentication methods: {list(self.swagger['components']['securitySchemes'].keys())}")
        if 'wsServers' in self.swagger:
            print(f"[+] WebSocket servers found: {len(self.swagger['wsServers'])}")


def configure_authentication(args) -> requests.Session:
        """Configure authentication based on command line arguments"""
        sess = requests.Session()

        # SSL verification
        sess.verify = not getattr(args, 'insecure', False)
        if not sess.verify:
            print("[!] Warning: SSL certificate verification is disabled")

        # Bearer Token Authentication
        if args.token:
            sess.headers['Authorization'] = f"Bearer {args.token}"
            print("[+] Configured Bearer token authentication")

        # Basic Authentication
        if args.basic_auth:
            try:
                user, pwd = args.basic_auth.split(':', 1)
                sess.auth = HTTPBasicAuth(user, pwd)
                print("[+] Configured Basic authentication")
            except ValueError:
                print("[-] Invalid basic auth format. Use 'username:password'")
                sys.exit(1)

        # NTLM Authentication
        if args.ntlm:
            try:
                match = re.match(r"(.+)\\\\(.+):(.+)", args.ntlm)
                if match:
                    domain, user, pwd = match.groups()
                    sess.auth = HttpNtlmAuth(f"{domain}\\{user}", pwd)
                    print("[+] Configured NTLM authentication")
                else:
                    raise ValueError("Invalid NTLM format")
            except Exception as e:
                print(f"[-] NTLM authentication error: {str(e)}")
                sys.exit(1)

        # API Key Header Authentication
        if args.apikey:
            header = args.apikey_header or "X-API-Key"
            sess.headers[header] = args.apikey
            print(f"[+] Configured API Key authentication in header '{header}'")

        # OAuth2 Client Credentials Flow
        if getattr(args, "flow", None) == "client" and args.client_id and args.client_secret and args.token_url:
            try:
                client = BackendApplicationClient(client_id=args.client_id)
                oauth = OAuth2Session(client=client)
                token = oauth.fetch_token(
                    token_url=args.token_url,
                    client_id=args.client_id,
                    client_secret=args.client_secret
                )
                sess = oauth  # use the OAuth session
                print("[+] Configured OAuth2 Client Credentials authentication")
            except Exception as e:
                print(f"[-] OAuth2 authentication error: {str(e)}")
                sys.exit(1)

        return sess
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate Swagger Generator by Perry Mertens 2025")
    parser.add_argument("--url", required=True, help="Base URL to scan")
    parser.add_argument("--output", default="swagger.json", help="Output file path")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--aggressive", action='store_true', help="Enable aggressive scanning")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay (in seconds) between requests")
    # Authentication options
    auth = parser.add_argument_group('Authentication')
    auth.add_argument("--header", action='append', 
                     help="Custom header (format: 'Header-Name: value')", 
                     default=[])
    auth.add_argument("--token", help="Bearer token for authentication")
    auth.add_argument("--basic-auth", help="Basic auth in format user:password")
    auth.add_argument("--ntlm", help="NTLM auth in format domain\\user:password")
    auth.add_argument("--apikey", help="API key value")
    auth.add_argument("--apikey-header", help="Header name for API key")
    
    # Session options
    session = parser.add_argument_group('Session')
    session.add_argument("--save-session", help="File to save session cookies")
    session.add_argument("--load-session", help="File to load session cookies from")
    auth.add_argument("--flow", choices=["client"], help="OAuth2 flow type")
    auth.add_argument("--client-id", help="OAuth2 client ID")
    auth.add_argument("--client-secret", help="OAuth2 client secret")
    auth.add_argument("--token-url", help="OAuth2 token URL")
    
    # SSL options
    parser.add_argument("--insecure", action="store_true", 
                       help="Disable SSL certificate verification")

    args = parser.parse_args()

    try:
        generator = UltimateSwaggerGenerator(args.url, delay=args.delay)
        
        # Configure authentication
        generator.session = configure_authentication(args)
        
        # Load session if requested
        if args.load_session:
            generator.load_session(args.load_session)
        
        # Process custom headers
        for header in args.header:
            try:
                name, value = header.split(':', 1)
                generator.set_custom_header(name.strip(), value.strip())
            except ValueError:
                print(f"[-] Invalid header format: {header}")
                sys.exit(1)
        
        # Run crawler
        generator.crawl(args.depth, args.aggressive)
        generator._prune_non_json_paths()
        # Save session if requested
        if args.save_session:
            generator.save_session(args.save_session)
        
        # Save Swagger documentation
        generator.save_swagger(args.output)
        
    except Exception as e:
        print(f"[-] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)