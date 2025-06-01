# APISCAN
# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
from __future__ import annotations

import argparse
import json
import sys
import logging
import time
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urljoin
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from doc_generator import create_audit_report
from bola_audit import BOLAAuditor
from broken_auth_audit import AuthAuditor
from broken_object_property_audit import ObjectPropertyAuditor
from resource_consumption_audit import ResourceConsumptionAuditor as ResourceAuditor
from authorization_audit import AuthorizationAuditor
from business_flow_audit import BusinessFlowAuditor
from ssrf_audit import SSRFAuditor
from misconfiguration_audit import MisconfigurationAuditorPro as MisconfigurationAuditor
from inventory_audit import InventoryAuditor
from safe_consumption_audit import SafeConsumptionAuditor
from version import __version__
from auth_utils import configure_authentication
logger = logging.getLogger("apiscan")

# Verbeterde console-outputfunctie
def styled_print(message: str, status: str = "info"):
    symbols = {
        "info": "Info:",
        "ok": "OK:",
        "warn": "WARNING:",
        "fail": "FAIL:",
        "run": "->",
        "done": "✓"
    }
    colors = {
        "info": "\033[94m",    # blauw
        "ok": "\033[92m",      # groen
        "warn": "\033[93m",    # geel
        "fail": "\033[91m",    # rood
        "run": "\033[96m",     # cyaan
        "done": "\033[92m"     # groen
    }
    reset = "\033[0m"
    symbol = symbols.get(status, "")
    color = colors.get(status, "")
    print(f"{color}{symbol} {message}{reset}")

MAX_THREADS = 20 

def validate_swagger_path(path: str) -> Path:
    p = Path(path).resolve()
    if not p.exists():
        raise ValueError("Swagger path does not exist")
    return p

# Onderdruk logging van externe modules
def check_api_reachable(url: str, session: requests.Session, retries: int = 3, delay: int = 3):
     #  Controleert API-bereikbaarheid met retry-logica   Args: url: Te testen URL     session: Requests sessie     retries: Aantal herpogingen      delay: Wachttijd tussen pogingen (seconden)
    for attempt in range(1, retries + 1):
        try:
            print(f"Checking connection to {url} (attempt {attempt}/{retries})...")
            resp = session.get(url, timeout=5)

            print(f"Response status code: {resp.status_code}")
            #print(f"Response headers:\n{json.dumps(dict(resp.headers), indent=2)}")
            #print(f"Response content (truncated):\n{resp.text[:1000]}")

            if not resp.content:
                print("Empty response body — possible backend crash or misconfigured handler.")

            if resp.status_code == 200 and any(
                hint in resp.text.lower() for hint in ["unauthorized", "access denied", "login", "authentication required"]
            ):
                print("Received 200 OK but response suggests access is denied. Check token or credentials.")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Response content: {resp.text[:500]}")
                sys.exit(2)

            if resp.status_code in (401, 403):
                print(f"Authentication failed with status {resp.status_code}. Check token or credentials.")
                sys.exit(2)

            elif resp.status_code < 400:
                print(f"Connection successful to {url} (status: {resp.status_code})")
                return
            else:
                print(f"Server responded with status {resp.status_code} at {url}")
                return

        except requests.exceptions.ReadTimeout:
            print(f"ReadTimeout: Server took too long to respond at {url} — possible crash or backend hang.")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            logger.error(f"Attempt {attempt} failed: {e}")
            if attempt < retries:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"ERROR: Cannot connect to {url} after {retries} attempts.")
                sys.exit(1)


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def create_output_directory(base_url: str) -> Path:
    clean = base_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    date = datetime.now().strftime("%Y-%m-%d")
    out_dir = Path(f"audit_{clean}_{date}")
    out_dir.mkdir(exist_ok=True)
    return out_dir


# Tijdelijk base_url uit CLI halen voor logpad
temp_url = sys.argv[sys.argv.index("--url") + 1] if "--url" in sys.argv else "unknown"
def main() -> None:
    parser = argparse.ArgumentParser(description=f"APISCAN {__version__} API Security Scanner Perry Mertens 2025 (c)")
    parser.add_argument("--url", required=True, help="Base URL of the API")
    parser.add_argument("--swagger", help="Path to Swagger/OpenAPI-JSON")
    parser.add_argument("--token", help="Bearer-token of auth-token")
    parser.add_argument("--basic-auth", help="Basic auth in de vorm gebruiker:password")
    parser.add_argument("--apikey", help="API key voor toegang tot API")
    parser.add_argument("--apikey-header", default="X-API-Key", help="Headernaam voor de API key")
    parser.add_argument("--ntlm", help="NTLM auth in de vorm domein\\gebruiker:pass")
    parser.add_argument("--client-cert", help="Pad naar client certificaat (PEM)")
    parser.add_argument("--client-key", help="Pad naar private key voor client certificaat (PEM)")
    parser.add_argument("--client-id")
    parser.add_argument("--client-secret")
    parser.add_argument("--token-url")
    parser.add_argument("--auth-url")
    parser.add_argument("--redirect-uri")
    parser.add_argument("--flow", help="Authentication flow to use: token, client, basic, ntlm")
    parser.add_argument("--scope", help="OAuth2 scope(s), space-separated (optional for --flow client)")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--cert-password", help="Wachtwoord voor client certificaat")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    # Voeg API selectie argumenten toe
    for i in range(1, 11):
        parser.add_argument(f"--api{i}", action="store_true", help=f"Voer alleen API{i}-audit uit")

    args = parser.parse_args()
    
    # Controleer of er API's zijn geselecteerd, anders scan alle API's
    selected_apis = [i for i in range(1, 11) if getattr(args, f"api{i}")] or list(range(1, 11))
    
    args.url = normalize_url(args.url)
    
    # Create output and log directory
    output_dir = create_output_directory(args.url)
    log_dir = output_dir / "log"
    log_dir.mkdir(exist_ok=True)
    LOGFILE = log_dir / f"apiscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    # Setup logging
    file_handler = logging.FileHandler(LOGFILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    root_logger = logging.getLogger()
    root_logger.handlers = []  # remove any existing handlers
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

    logger = logging.getLogger("apiscan")
    logger.propagate = False

    # Verwijder dubbele directory creatie
    output_dir = create_output_directory(args.url)
    log_dir = output_dir / "log"
    log_dir.mkdir(exist_ok=True)

    sess = configure_authentication(args)
    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=3)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    check_api_reachable(args.url, sess)

    # Swagger verwerking
    if not args.swagger and args.postman:
        print(f"[+] Generating OpenAPI from Postman collection: {args.postman}")
        builder = SwaggerBuilder(postman_path=args.postman)
        args.swagger = builder.build_and_save("converted_from_postman.json")
        
    if args.swagger:
        try:
            swagger_path = Path(args.swagger).resolve()
            if not swagger_path.exists():
                raise FileNotFoundError(f"Swagger bestand niet gevonden: {swagger_path}")
            if not swagger_path.is_file():
                raise ValueError(f"Pad is geen bestand: {swagger_path}")
            if not swagger_path.stat().st_size > 0:
                raise ValueError("Swagger bestand is leeg")

            logger.info(f"Loading Swagger from: {swagger_path}")
            styled_print(f"Loading validated Swagger file: {swagger_path}", "info")

            bola = BOLAAuditor(sess)
            spec = bola.load_swagger(swagger_path)
            
            if not spec:
                raise ValueError("Swagger kon niet worden geparsed - ongeldig formaat")
                
            endpoints = bola.get_object_endpoints(spec)
            logger.debug(f"Swagger succesvol geladen - {len(endpoints)} endpoints gedetecteerd")
            styled_print(f"Swagger geladen – {len(endpoints)} endpoints gevonden", "ok")

        except Exception as e:
            logger.critical(f"Swagger verwerking mislukt: {str(e)}", exc_info=True)
            sys.exit(f"FATALE FOUT: {str(e)}")
    else:
        logger.error("Geen Swagger bestand opgegeven")
        sys.exit("Geen Swagger specificatie opgegeven - gebruik --swagger")

      
    output_dir = create_output_directory(args.url)
    logger.info(f"Output directory: {output_dir}")
    print(f"[+] Results saved to: {output_dir}")

    # Full scanning logic per API
    if 1 in selected_apis:
        print(f" API1 – BOLA tests ({args.threads} threads)")
        logger.info("Running API1 – BOLA")
        bola_results = []

        bola = BOLAAuditor(sess)
        spec = bola.load_swagger(args.swagger)
        endpoints = bola.get_object_endpoints(spec)

        with ThreadPoolExecutor(max_workers=min(args.threads, MAX_THREADS)) as ex:
            futures = []
            for ep in endpoints:
                print(f"-> Testing {ep['method']} {ep['path']}")
                futures.append(ex.submit(bola.test_endpoint, args.url, ep))
            for fut in futures:
                try:
                    bola_results.extend(fut.result())
                except Exception as e:
                    logger.error(f"BOLA test error: {e}")

        bola.issues = [r.to_dict() for r in bola_results]
        bola.base_url = args.url  # ✅ Fix hier
        report = bola.generate_report()
        (output_dir / "api_bola_report.txt").write_text(report, "utf-8")

        found = sum(1 for r in bola_results if getattr(r, 'is_vulnerable', False))
        styled_print(f"API1 complete – {found} vulnerabilities found", "done")


    if 2 in  selected_apis:
        print(" API2 – Broken Authentication")
        logger.info("Running API2 – Broken Authentication")
        aa = AuthAuditor(args.url, sess)
        auth_issues = aa.test_authentication_mechanisms([])
        for issue in auth_issues:
            print(f"->Auth issue found: {issue.get('description', 'Unknown')} at {issue.get('endpoint', '')}")
            #print(f"-> Authentication issue found: {issue.get('description', 'Unknown problem')}")
            logger.info(f"Auth issue found: {issue.get('description', 'Unknown')} at {issue.get('endpoint', '')}")
        report = aa.generate_report()
        (output_dir / "api_broken_auth_report.txt").write_text(report, encoding="utf-8")
        styled_print(f"API2 complete – {len(auth_issues)} issues", "done")

    if 3 in  selected_apis:
        print(" API3 – Property-level Authorization")
        logger.info("Running API3 – Property-level Authorization")
        prop_eps = [{"url": ep["path"], "method": ep["method"], "test_object": {p["name"]: 1 for p in ep.get("parameters", []) if p["in"] == "path"}} for ep in endpoints]
        pa = ObjectPropertyAuditor(args.url, sess)
        prop_issues = pa.test_object_properties(prop_eps)
        for issue in prop_issues:
            print(f"-> Property issue found: {issue.get('description', 'Unknown')} @ {issue.get('endpoint', 'Unknown')}")
        report = pa.generate_report()
        (output_dir / "api_property_report.txt").write_text(report, "utf-8")
        styled_print(f"API3 complete – {len(prop_issues)} issues", "done")

    if 4 in  selected_apis:
        print(" API4 – Resource Consumption")
        logger.info("Running API4 – Resource Consumption")
        rc = ResourceAuditor(args.url, sess)
        resource_eps = [{"url": ep["path"], "method": ep["method"]} for ep in endpoints]
        for ep in resource_eps:
            print(f"-> Testing {ep['method']} {ep['url']}")
        res_issues = rc.test_resource_consumption(resource_eps)
        (output_dir / "api_resource_report.txt").write_text(rc.generate_report(res_issues), "utf-8")
        styled_print(f"API4 complete – {len(res_issues)} issues", "done")

    if 5 in  selected_apis:
        print(" API5 – Function-level Authorization")
        logger.info("Running API5 – Function-level Authorization")
        za = AuthorizationAuditor(args.url, sess)
        authz_issues = za.test_authorization()
        for issue in authz_issues:
            print(f"-> Authorization issue: {issue.get('description', 'Unknown')}")
        (output_dir / "api_admin_access_report.txt").write_text(za.generate_report(), "utf-8")
        styled_print(f"API5 complete – {len(authz_issues)} issues", "done")

    if 6 in  selected_apis:
        print(" API6 – Sensitive Business Flows")
        logger.info("Running API6 – Sensitive Business Flows")
        bf = BusinessFlowAuditor(args.url, sess)
        business_eps = [{"name": ep.get("operation_id", f"{ep['method']} {ep['path']}").replace(" ", "_"), "url": ep["path"], "method": ep["method"], "body": {}} for ep in endpoints if ep["method"] in {"POST", "PUT", "PATCH"}]
        for ep in business_eps:
            print(f"-> Testing business flow {ep['method']} {ep['url']}")
        biz_issues = bf.test_business_flows(business_eps)
        (output_dir / "api_business_flows_report.txt").write_text(bf.generate_report(), "utf-8")
        styled_print(f"API6 complete – {len(biz_issues)} issues", "done")

    if 7 in  selected_apis:
        print(" API7 – SSRF")
        logger.info("Running API7 – SSRF")
        ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger)
        if ss_eps:
            for ep in ss_eps:
                print(f"-> Testing SSRF {ep['method']} {ep['url']}")
            ss = SSRFAuditor(args.url, sess)
            ssrf_issues = ss.test_endpoints(ss_eps)
            (output_dir / "api_ssrf_report.txt").write_text(ss.generate_report(), "utf-8")
            styled_print(f"API7 complete – {len(ssrf_issues)} issues", "done")
        else:
            styled_print("No SSRF endpoints found", "warn")

    if 8 in  selected_apis:
        print(" API8 – Security Misconfiguration")
        logger.info("Running API8 – Security Misconfiguration")
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            for ep in misconf_eps:
                print(f"-> Testing misconfiguration {ep['method']} {ep['path']}")
            mc = MisconfigurationAuditor(args.url, sess)
            misconf_issues = mc.test_endpoints(misconf_eps)
            (output_dir / "api_misconfig_report.txt").write_text(mc.generate_report(), "utf-8")
            styled_print(f"API8 complete – {len(misconf_issues)} issues", "done")
        else:
            styled_print("No misconfiguration endpoints found", "warn")

    if 9 in  selected_apis:
        print(" API9 – Improper Inventory Management")
        logger.info("Running API9 – Improper Inventory Management")
        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger)
        if inv_eps:
            for ep in inv_eps:
                print(f"-> Inventory check {ep}")
            inv = InventoryAuditor(args.url, sess)
            inv_issues = inv.test_inventory(inv_eps)
            (output_dir / "api_inventory_report.txt").write_text(inv.generate_report(), "utf-8")
            styled_print(f"API9 complete – {len(inv_issues)} issues", "done")
        else:
            styled_print("No inventory endpoints found", "warn")

    if 10 in  selected_apis:
        print(" API10 – Safe Consumption of 3rd-Party APIs")
        logger.info("Running API10 – Safe Consumption")
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        for ep in safe_eps:
            print(f"-> Safe API consumption check {ep}")
        sc = SafeConsumptionAuditor(base_url=args.url, session=sess)
        safe_issues = sc.test_endpoints(safe_eps)
        (output_dir / "api_safe_consumption_report.txt").write_text(sc.generate_report(), "utf-8")
        styled_print(f"API10 complete – {len(safe_issues)} issues", "done")

    summary = {
        "BOLA": sum(1 for x in bola_results if getattr(x, "is_vulnerable", False)) if 'bola_results' in locals() else 0,
        "Auth": len(auth_issues) if 'auth_issues' in locals() else 0,
        "Property": len(prop_issues) if 'prop_issues' in locals() else 0,
        "Resource": len(res_issues) if 'res_issues' in locals() else 0,
        "AdminAccess": len(authz_issues) if 'authz_issues' in locals() else 0,
        "BusinessFlows": len(biz_issues) if 'biz_issues' in locals() else 0,
        "SSRF": len(ssrf_issues) if 'ssrf_issues' in locals() else 0,
        "Misconfiguration": len(misconf_issues) if 'misconf_issues' in locals() else 0,
        "Inventory": len(inv_issues) if 'inv_issues' in locals() else 0,
        "UnsafeConsumption": len(safe_issues) if 'safe_issues' in locals() else 0
    }
    (output_dir / "api_summary_report.txt").write_text(json.dumps(summary, indent=2), "utf-8")

    total_vulns = sum(summary.values())
    print("Summary of vulnerabilities found")
    print("---------------------------------------")
    for k, v in summary.items():
        print(f"• {k:18}: {v}")
    print("---------------------------------------")
    print(f"  Total found       : {total_vulns}")
    styled_print("Scan complete. All results and logs saved.", "ok")

    
    styled_print("Building DOCX Report …", "info")
    try:
        create_audit_report(output_dir)
    except Exception as exc:
        styled_print(f"DOCX report failed: {exc}", "fail")

    styled_print(f"All reports saved in : {output_dir}", "ok")
    
    
if __name__ == "__main__":
    main()