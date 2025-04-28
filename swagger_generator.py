#!/usr/bin/env python3
"""
Ultimate Swagger Generator - Met geavanceerde authenticatie en endpoint detectie
Enhanced version with better API detection capabilities
"""

import argparse
import json
import re
import sys
import urllib3
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from version import __version__

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UltimateSwaggerGenerator:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) UltimateSwaggerGenerator/3.0',
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
            r'(?i)/async/'
        ]
        self.param_patterns = [
            r'id=[^&]+',
            r'page=\d+',
            r'limit=\d+',
            r'search=[^&]+',
            r'filter=[^&]+',
            r'sort=[^&]+'
        ]
        self.auth_tokens = {}
        self.login_url = None
        self.login_data = None
        self.custom_headers = {}

    def set_basic_auth(self, username: str, password: str):
        """Stel basisauthenticatie in"""
        self.session.auth = (username, password)
        self.swagger["components"]["securitySchemes"]["basicAuth"] = {
            "type": "http",
            "scheme": "basic"
        }

    def set_token_auth(self, token: str, header_name: str = "Authorization"):
        """Stel tokenauthenticatie in"""
        self.session.headers.update({header_name: f"Bearer {token}"})
        self.auth_tokens[header_name] = f"Bearer {token}"

    def set_custom_header(self, header_name: str, header_value: str):
        """Set custom headers that might be required for API access"""
        self.session.headers.update({header_name: header_value})
        self.custom_headers[header_name] = header_value

    def set_login_form(self, url: str, data: Dict[str, str]):
        """Configureer formuliergebaseerde login"""
        self.login_url = url
        self.login_data = data

    def authenticate(self):
        """Voer authenticatie uit indien geconfigureerd"""
        if self.login_url and self.login_data:
            try:
                response = self.session.post(
                    self.login_url,
                    data=self.login_data,
                    timeout=10
                )
                if response.status_code == 200:
                    print("[+] Succesvol ingelogd via formulier")
                    # Probeer JWT token uit response te extraheren
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
                print(f"[-] Login mislukt: {str(e)}")

    def crawl(self, max_depth: int = 3, aggressive: bool = False):
        """Verbeterde crawler met agressieve modus"""
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
        
        print("[*] Agressieve scan: controleer headers...")
        for url in list(self.visited):
            for header, value in headers_to_check:
                try:
                    headers = {header: value}
                    response = self.session.get(url, headers=headers, timeout=5)
                    if response.status_code == 200 and self._looks_like_api(response):
                        print(f"[+] API gevonden met header {header}: {value} - {url}")
                        self._process_api_response(url, response)
                except:
                    continue

    def _bruteforce_common_endpoints(self):
        """Probeer veelvoorkomende API endpoints"""
        common_endpoints = [
            '/api/v1/users',
            '/api/users',
            '/users',
            '/api/v1/products',
            '/api/products',
            '/products',
            '/api/v1/data',
            '/api/data',
            '/data',
            '/graphql',
            '/graphql/v1',
            '/api/graphql',
            '/api/v1/graphql',
            '/rest',
            '/rest/v1',
            '/api/rest',
            '/api/v1/rest',
            '/rpc',
            '/jsonrpc',
            '/api/soap',
            '/api/v1/soap',
            '/ws',
            '/wss',
            '/socket.io',
            '/sockjs'
        ]
        
        print("[*] Agressieve scan: controleer standaard endpoints...")
        for endpoint in common_endpoints:
            url = urljoin(self.base_url, endpoint)
            if url not in self.visited:
                self._process_possible_api(url)

    def _crawl_page(self, url: str, depth: int, aggressive: bool):
        if depth < 0 or url in self.visited:
            return

        try:
            print(f"[*] Crawling ({depth}): {url}")
            self.visited.add(url)
            
            response = self.session.get(url, timeout=10)
            content_type = response.headers.get('Content-Type', '')

            # HTML-pagina's analyseren
            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 1. Links crawlen
                for link in soup.find_all(['a', 'link'], href=True):
                    new_url = urljoin(url, link['href'])
                    if self._should_crawl(new_url):
                        self._crawl_page(new_url, depth - 1, aggressive)
                
                # 2. Forms analyseren (nu met meer methodes)
                for form in soup.find_all('form'):
                    self._process_form(url, form)
                
                # 3. JavaScript analyseren (uitgebreid)
                for script in soup.find_all('script'):
                    if script.string:
                        self._find_js_apis(script.string, url)
                        self._find_websockets(script.string, url)
                        self._find_graphql(script.string, url)
                
                # 4. API links in HTML comments
                for comment in soup.find_all(string=lambda text: isinstance(text, str) and "api" in text.lower()):
                    self._find_hidden_apis(comment, url)
            
            # Directe API-endpoints verwerken
            if self._is_api_endpoint(url) or ('application/json' in content_type and aggressive):
                self._process_api_response(url, response)
                
        except Exception as e:
            print(f"[!] Fout bij {url}: {str(e)}")

    def _process_possible_api(self, url: str):
        """Controleer een mogelijke API URL"""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200 and self._looks_like_api(response):
                print(f"[+] Mogelijk API endpoint gevonden: {url}")
                self._process_api_response(url, response)
        except:
            pass

    def _looks_like_api(self, response) -> bool:
        """Bepaal of een response op een API lijkt"""
        content_type = response.headers.get('Content-Type', '').lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for common API headers
        api_headers = [
            'x-api-version',
            'x-ratelimit-limit',
            'x-request-id',
            'x-powered-by-api',
            'x-total-count',
            'etag',
            'last-modified'
        ]
        
        return (
            'application/json' in content_type or
            'application/xml' in content_type or
            ('{' in response.text and '}' in response.text and '"' in response.text) or
            any(header in headers for header in api_headers) or
            'api' in headers.get('server', '').lower() or
            'api' in headers.get('via', '').lower()
        )

    def _find_hidden_apis(self, text: str, base_url: str):
        """Zoek naar API endpoints in comments en metadata"""
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
                    print(f"[+] Verborgen API gevonden: {api_url}")
                    self._process_possible_api(api_url)

    def _process_form(self, base_url: str, form):
        """Verbeterde formulieranalyse"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        url = urljoin(base_url, action)
        
        if not self._is_api_endpoint(url) and not any(x in url for x in ['login', 'auth']):
            return
            
        parameters = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            if inp.get('name'):
                param = {
                    'name': inp.get('name'),
                    'in': 'formData',
                    'required': inp.get('required') is not None,
                    'schema': {
                        'type': inp.get('type', 'text'),
                        'example': inp.get('value', '')
                    }
                }
                parameters.append(param)
        
        if url not in self.swagger['paths']:
            self.swagger['paths'][url] = {}
            
        operation = {
            'summary': f'Auto-discovered {method.upper()} endpoint',
            'responses': {
                '200': {
                    'description': 'Successful form submission'
                }
            }
        }
        
        if parameters:
            operation['parameters'] = parameters
        
        self.swagger['paths'][url][method] = operation

    def _find_js_apis(self, js_code: str, base_url: str):
        """Uitgebreide JavaScript API detectie"""
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
                    api_url = urljoin(base_url, match.group(2))
                else:
                    api_url = urljoin(base_url, match.group(1))
                
                if self._should_inspect(api_url):
                    print(f"[+] JS API gevonden: {api_url}")
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
                    print(f"[+] WebSocket gevonden: {ws_url}")
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
                    print(f"[+] GraphQL endpoint gevonden: {gql_url}")
                    self._process_possible_api(gql_url)

    def _process_api_response(self, url: str, response):
        """Verbeterde API response verwerking"""
        parsed = urlparse(url)
        path = parsed.path
        method = 'get'
        
        # Parameters detecteren
        query_params = []
        for name, values in parse_qs(parsed.query).items():
            query_params.append({
                'name': name,
                'in': 'query',
                'schema': {'type': 'string'},
                'example': values[0]
            })
        
        # Path parameters
        path_params = re.findall(r'/(\d+|[a-f0-9]{24}|[^/]+Id)/', path)
        swagger_path = path
        for param in path_params:
            swagger_path = swagger_path.replace(param, f'{{{param}}}')
        
        # Response schema
        schema = {'type': 'string'}
        if 'application/json' in response.headers.get('Content-Type', ''):
            try:
                data = response.json()
                schema = self._generate_schema(data)
                
                # Als het een lijst is, probeer dan een item te vinden
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
        
        # Toevoegen aan Swagger
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
        """Genereer JSON-schema van data"""
        if isinstance(data, dict):
            properties = {}
            required = []
            for k, v in data.items():
                properties[k] = self._generate_schema(v)
                if k in ['id', 'name', 'email', 'username', 'title', 'description']:  # Markeer veelvoorkomende required velden
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
        """Bepaal of een URL gecrawld moet worden"""
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
        """Bepaal of een URL geïnspecteerd moet worden"""
        return (
            urlparse(url).netloc == urlparse(self.base_url).netloc and
            url not in self.visited and
            not any(x in url for x in ['google-analytics', 'facebook', 'twitter', 'linkedin', 'youtube']) and
            not any(ext in url for ext in ['.css', '.js', '.png', '.jpg', '.gif'])
        )

    def _is_api_endpoint(self, url: str) -> bool:
        """Bepaal of een URL een API-endpoint is"""
        path = urlparse(url).path.lower()
        query = urlparse(url).query.lower()
        return (
            any(re.search(pattern, path) for pattern in self.api_patterns) or
            'api' in path or
            'json' in path or
            'xml' in path or
            'data' in path or
            'v1' in path or
            'v2' in path or
            any(param in query for param in ['format=json', 'type=api', 'output=json'])
        )

    def save_swagger(self, filename: str):
        """Sla de Swagger-specificatie op"""
        with open(filename, 'w') as f:
            json.dump(self.swagger, f, indent=2)
        print(f"[+] Swagger opgeslagen als {filename}")
        print(f"[+] Totaal endpoints gevonden: {len(self.swagger['paths'])}")
        print(f"[+] Authenticatie methodes: {list(self.swagger['components']['securitySchemes'].keys())}")
        if 'wsServers' in self.swagger:
            print(f"[+] WebSocket servers gevonden: {len(self.swagger['wsServers'])}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="URL Swagger Generator by Perry Mertens 2024")
    parser.add_argument("--url", required=True, help="Basis-URL ")
    parser.add_argument("--output", default="swagger.json", help="Output file")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--aggressive", action='store_true', help="Agressieve modus ")
    parser.add_argument("--username", help="Basic auth username")
    parser.add_argument("--password", help="Basic auth password")
    parser.add_argument("--token", help="Bearer token for authenticatie")
    parser.add_argument("--token-header", default="Authorization", help="Header naam for token")
    parser.add_argument("--login-url", help="Login form URL")
    parser.add_argument("--login-data", help="Login form data  JSON string")
    parser.add_argument("--header", action='append', help="Custom header (format: Header-Name:value)", default=[])
    
    args = parser.parse_args()

    generator = UltimateSwaggerGenerator(args.url)
    
    # Authenticatie configureren
    if args.username and args.password:
        generator.set_basic_auth(args.username, args.password)
    
    if args.token:
        generator.set_token_auth(args.token, args.token_header)
    
    if args.login_url and args.login_data:
        try:
            login_data = json.loads(args.login_data)
            generator.set_login_form(args.login_url, login_data)
        except json.JSONDecodeError:
            print("[-] Ongeldige login data (moet JSON string zijn)")
            sys.exit(1)
    
    # Custom headers verwerken
    for header in args.header:
        try:
            name, value = header.split(':', 1)
            generator.set_custom_header(name.strip(), value.strip())
        except ValueError:
            print(f"[-] Ongeldig header formaat: {header}")
    
    # Crawl uitvoeren
    generator.crawl(args.depth, args.aggressive)
    generator.save_swagger(args.output)