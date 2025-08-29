##############################################
# APISCAN - API Security Scanner             #
# Licensed under the MIT License             #
# Author: Perry Mertens pamsniffer@gmail.com #
##############################################
""""
APISCAN is a private and proprietary API security tool,
developed independently for internal use and research purposes. 
It supports OWASP API Security Top 10 (2023) testing, OpenAPI-based analysis, active scanning, and multi-format reporting.
Redistribution is not permitted without explicit permission. 
"""
from __future__ import annotations
import builtins
import logging
import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any
from urllib.parse import urljoin
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import urllib3
import requests
from requests.adapters import HTTPAdapter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
from report_utils import ReportGenerator, HTMLReportGenerator, RISK_INFO
from doc_generator import generate_combined_html
from swagger_utils import extract_variables, write_variables_file, enable_dummy_mode


manual_file_map = {
    'BOLA': 'bola',
    'BrokenAuth': 'broken_auth',
    'Property': 'property',
    'Resource': 'resource',
    'AdminAccess': 'admin_access',
    'BusinessFlows': 'business_flows',
    'SSRF': 'ssrf',
    'Misconfig': 'misconfig',
    'Inventory': 'inventory',
    'UnsafeConsumption': 'unsafe_consumption'
}

def save_html_report(issues, risk_key, url, output_dir):
    html_report = HTMLReportGenerator(
        issues=issues,
        scanner=RISK_INFO[risk_key]['title'],
        base_url=url
    )
    filename = f"api_{manual_file_map[risk_key]}_report.html"
    html_report.save(output_dir / filename)



logger = logging.getLogger("apiscan")

MAX_THREADS = 20

def styled_print(message: str, status: str = "info"):
    symbols = {
        "info": "Info:", "ok": "OK:", "warn": "WARNING:", "fail": "FAIL:",
        "run": "->", "done": "Done"
    }
    colors = {
        "info": "\033[94m", "ok": "\033[92m", "warn": "\033[93m",
        "fail": "\033[91m", "run": "\033[96m", "done": "\033[92m"
    }
    reset = "\033[0m"
    print(f"{colors.get(status, '')}{symbols.get(status, '')} {message}{reset}")

def normalize_url(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "http://" + url

def create_output_directory(base_url: str) -> Path:
    clean = base_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%d-%m-%Y_%H%M%S")
    out_dir = Path(f"audit_{clean}_{timestamp}")
    out_dir.mkdir(exist_ok=True)
    return out_dir

def check_api_reachable(url: str, session: requests.Session, retries: int = 3, delay: int = 3):
    for attempt in range(1, retries + 1):
        try:
            print(f"APIscan By Perry Mertens 2025 (C) pamsniffer@gmail.com. \nChecking connection to {url} (attempt {attempt}/{retries})...")
            resp = session.get(url, timeout=5)
            print(f"Response status code: {resp.status_code}")

            if not resp.content:
                print("Empty response body  possible backend crash or misconfigured handler.")

            if resp.status_code == 200 and any(                word in resp.text.lower()
                for word in ["unauthorized", "access denied", "login", "authentication required"]
                ):
                print("Received 200 OK but access denied content detected. Check credentials.")
                logger.debug(resp.text[:500])
                sys.exit(2)

            if resp.status_code in (401, 403):
                print(f"Authentication failed with status {resp.status_code}.")
                sys.exit(2)

            if resp.status_code < 400:
                print(f"Connection successful to {url} (status: {resp.status_code})")
                return
            else:
                print(f"Unexpected response from server: {resp.status_code}")
                return

        except requests.exceptions.RequestException as e:
            logger.error(f"Attempt {attempt} failed: {e}")
            if attempt < retries:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"ERROR: Cannot connect to {url} after {retries} attempts.")
                sys.exit(1)


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
    parser.add_argument("--api11", action="store_true", help="Run AI-based OWASP Top 10 analysis using AI or other ")
    parser.add_argument("--dummy", action="store_true", help="Gebruik dummy data voor alle request bodies en parameters")
    parser.add_argument("--export-vars",metavar="PATH", help="Export a variables template (YAML if .yml/.yaml + PyYAML, else JSON) and exit")

    # API selection
    for i in range(1, 11):
        parser.add_argument(f"--api{i}", action="store_true", help=f"Voer alleen API{i}-audit uit")

    args = parser.parse_args()
    
    #enable debug mode logging
    builtins.debug_mode = args.debug
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[DEBUG] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='[INFO] %(message)s')
        
    # Controleer of er API's zijn geselecteerd, anders scan alle API's
    if args.api11:
        selected_apis = [11]
    else:
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
    log_dir = output_dir / "log"
    log_dir.mkdir(exist_ok=True)

    sess = configure_authentication(args)
    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=3)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    check_api_reachable(args.url, sess)

    # Swagger verwerking
    if args.swagger:
        try:
            swagger_path = Path(args.swagger).resolve()
            if not swagger_path.exists():
                raise FileNotFoundError(f"Swagger file not found: {swagger_path}")
            if not swagger_path.is_file():
                raise ValueError(f"Path is not a file: {swagger_path}")
            if not swagger_path.stat().st_size > 0:
                raise ValueError("Swagger file is empty")

            logger.info(f"Loading Swagger from: {swagger_path}")
            styled_print(f"Loading validated Swagger file: {swagger_path}", "info")

            bola = BOLAAuditor(sess)
            spec = bola.load_swagger(swagger_path)

            if not spec:
                raise ValueError("Failed to parse Swagger - invalid format")

            endpoints = bola.get_object_endpoints(spec)
            ai_endpoints = [
                {"path": ep["path"], "method": ep["method"]}
                for ep in endpoints if ep.get("path") and ep.get("method")
            ]
            logger.debug(f"Swagger successfully loaded - {len(endpoints)} endpoints detected")
            styled_print(f"Swagger loaded - {len(endpoints)} endpoints found", "ok")
           
                        
        except (FileNotFoundError, ValueError) as e:
            logger.error(f"Swagger processing failed: {e}")
            styled_print(f"FAIL: {e}", "fail")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error during Swagger parsing: {e}")
            styled_print(f"FAIL: Unexpected error during Swagger parsing", "fail")
            sys.exit(1)
    else:
        logger.error("No Swagger file provided")
        styled_print("FAIL: No Swagger specification provided - use --swagger", "fail")
        sys.exit(1)

    
    if args.dummy:
        enable_dummy_mode(True)
    
    if args.export_vars:
        try:
            vars_doc = extract_variables(spec)
            out_file = write_variables_file(vars_doc, args.export_vars)
            styled_print(f"Variables template written to {out_file}", "ok")
            sys.exit(0)
        except Exception as e:
            styled_print(f"FAIL exporting variables: {e}", "fail")
            sys.exit(1)

      
    output_dir = create_output_directory(args.url)
    logger.info(f"Output directory: {output_dir}")
    print(f"[+] Results saved to: {output_dir}")

    # Full scanning logic per API
    if 1 in selected_apis:
        print(f" API1 - BOLA tests ({args.threads} threads)")
        logger.info("Running API1 - BOLA")
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

        bola.issues = [r.to_dict() for r in bola_results if r.status_code != 0]
        bola.base_url = args.url  
        report = bola.generate_report()
       
        found = sum(1 for r in bola_results if getattr(r, 'is_vulnerable', False))
        save_html_report(bola.issues, 'BOLA', args.url, output_dir)
        styled_print(f"API1 complete - {found} vulnerabilities found", "done")


    if 2 in selected_apis:
        print(" API2 - Broken Authentication")
        logger.info("Running API2 - Broken Authentication")
        norm_eps: list[dict[str, str]] = []
        for ep in endpoints:                   # endpoints already built earlier
            rel_path = ep["path"]
            verb     = ep["method"].upper()
            full_url = urljoin(args.url.rstrip("/") + "/", rel_path.lstrip("/"))
            norm_eps.append({
                "url": full_url,
                "methods": verb,               # expected by AuthAuditor
                "path": rel_path,
                "method": verb,
            })
        aa = AuthAuditor(args.url, sess)
        auth_issues = aa.test_authentication_mechanisms(norm_eps)
        for issue in auth_issues:
            desc = issue.get("description", "Unknown")
            ep   = issue.get("endpoint", "")
            print(f"-> Auth issue found: {desc} at {ep}")
            logger.info(f"Auth issue found: {desc} at {ep}")

        html_report = HTMLReportGenerator(
            issues=auth_issues,
            scanner="API2:2023 - Broken Authentication",
            base_url=args.url,
        )
        save_html_report(auth_issues, "BrokenAuth", args.url, output_dir)
        styled_print(f"API2 complete - {len(auth_issues)} issues", "done")

    if 3 in  selected_apis:
        print(" API3 - Property-level Authorization")
        logger.info("Running API3 - Property-level Authorization")
        prop_eps = [{"url": ep["path"], "method": ep["method"], "test_object": {p["name"]: 1 for p in ep.get("parameters", []) if p["in"] == "path"}} for ep in endpoints]
        pa = ObjectPropertyAuditor(args.url, sess)
        prop_issues = pa.test_object_properties(prop_eps)
        for issue in prop_issues:
            print(f"-> Property issue found: {issue.get('description', 'Unknown')} @ {issue.get('endpoint', 'Unknown')}")
        report = pa.generate_report()
        html_report = HTMLReportGenerator(
            issues=prop_issues,
            scanner="API3:2023 - Broken Object Property Level Authorization",
            base_url=args.url
        )
        save_html_report(prop_issues, 'Property', args.url, output_dir)
        styled_print(f"API3 complete - {len(prop_issues)} issues", "done")

    if 4 in  selected_apis:
        print(" API4 - Resource Consumption")
        logger.info("Running API4 - Resource Consumption")
        rc = ResourceAuditor(args.url, sess)
        resource_eps = [{"url": ep["path"], "method": ep["method"]} for ep in endpoints]
        for ep in resource_eps:
            print(f"-> Testing {ep['method']} {ep['url']}")
        res_issues = rc.test_resource_consumption(resource_eps)
        save_html_report(res_issues, 'Resource', args.url, output_dir)
        styled_print(f"API4 complete - {len(res_issues)} issues", "done")

    if 5 in  selected_apis:
        print(" API5 - Function-level Authorization")
        logger.info("Running API5 - Function-level Authorization")
        za = AuthorizationAuditor(args.url, sess)
        authz_issues = za.test_authorization()
        for issue in authz_issues:
            print(f"-> Authorization issue: {issue.get('description', 'Unknown')}")
        save_html_report( authz_issues, 'AdminAccess', args.url, output_dir)
        styled_print(f"API5 complete - {len(authz_issues)} issues", "done")

    if 6 in  selected_apis:
        print(" API6 - Sensitive Business Flows")
        logger.info("Running API6 - Sensitive Business Flows")
        bf = BusinessFlowAuditor(args.url, sess)
        business_eps = [{"name": ep.get("operation_id", f"{ep['method']} {ep['path']}").replace(" ", "_"), "url": ep["path"], "method": ep["method"], "body": {}} for ep in endpoints if ep["method"] in {"POST", "PUT", "PATCH"}]
        for ep in business_eps:
            print(f"-> Testing business flow {ep['method']} {ep['url']}")
        biz_issues = bf.test_business_flows(business_eps)
        save_html_report(biz_issues, 'BusinessFlows', args.url, output_dir)
        styled_print(f"API6 complete - {len(biz_issues)} issues", "done")

   
    if 7 in selected_apis:
        print(" API7 - SSRF")
        logger.info("Running API7 - SSRF")
        ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger)
        if ss_eps:
            for ep in ss_eps:
                print(f"-> Testing SSRF {ep['method']} {ep['url']}")
            ss = SSRFAuditor(args.url, sess)
            ss.test_endpoints(ss_eps)  
            styled_print(f"API7 complete - {len(ss._issues)} issues", "done")
            save_html_report(ss._issues, 'SSRF', args.url, output_dir)      
        else:
            styled_print("No SSRF endpoints found", "warn")

    if 8 in  selected_apis:
        print(" API8 - Security Misconfiguration")
        logger.info("Running API8 - Security Misconfiguration")
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            for ep in misconf_eps:
                print(f"-> Testing misconfiguration {ep['method']} {ep['path']}")
            mc = MisconfigurationAuditor(args.url, sess)
            misconf_issues = mc.test_endpoints(misconf_eps)
            styled_print(f"API8 complete - {len(misconf_issues)} issues", "done")
            save_html_report( misconf_issues, 'Misconfig', args.url, output_dir)
        else:
            styled_print("No misconfiguration endpoints found", "warn")

    if 9 in  selected_apis:
        print(" API9 - Improper Inventory Management")
        logger.info("Running API9 - Improper Inventory Management")
        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger)
        if inv_eps:
            for ep in inv_eps:
                print(f"-> Inventory check {ep}")
            inv = InventoryAuditor(args.url, sess)
            inv_issues = inv.test_inventory(inv_eps)
            save_html_report(inv_issues, 'Inventory', args.url, output_dir)
            styled_print(f"API9 complete - {len(inv_issues)} issues", "done")
        else:
            styled_print("No inventory endpoints found", "warn")

    if 10 in  selected_apis:
        print(" API10 - Safe Consumption of 3rd-Party APIs")
        logger.info("Running API10 - Safe Consumption")
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        for ep in safe_eps:
            print(f"-> Safe API consumption check {ep}")
        sc = SafeConsumptionAuditor(base_url=args.url, session=sess)
        safe_issues = sc.test_endpoints(safe_eps)
        sc._dump_raw_issues(log_dir)    
        sc._filter_issues() 
        sc._dedupe_issues()  
        save_html_report(safe_issues, 'UnsafeConsumption', args.url, output_dir)
        styled_print(f"API10 complete - {len(safe_issues)} issues", "done")



    if 11 in selected_apis:
        styled_print("API11  AI-assisted OWASP analysis (Azure GPT-4o)", "info")
        logger.info("Running API11  GPT-4o audit")

        try:
            # import pas hier, zodat de check pas gebeurt bij api11
            from ai_client import analyze_endpoints_with_gpt, save_ai_summary

            # GPT-4o-run met live probe
            ai_results = analyze_endpoints_with_gpt(
                ai_endpoints,
                live_base_url=args.url,         # base-URL voor live probes
                print_results=True
            )
            save_ai_summary(ai_results, output_dir / "AI-api11_scanresults.json")
            styled_print(f"API11 complete  {len(ai_results)} endpoints analyzed", "done")

        except Exception as e:
            styled_print(f"AI analysis failed: {e}", "fail")
            logger.exception("AI analysis exception")


    
    
    summary = {
        "BOLA": sum(1 for x in bola_results if getattr(x, "is_vulnerable", False)) if 'bola_results' in locals() else 0,
        "Auth": len(auth_issues) if 'auth_issues' in locals() else 0,
        "Property": len(prop_issues) if 'prop_issues' in locals() else 0,
        "Resource": len(res_issues) if 'res_issues' in locals() else 0,
        "AdminAccess": len(authz_issues) if 'authz_issues' in locals() else 0,
        "BusinessFlows": len(biz_issues) if 'biz_issues' in locals() else 0,
        "SSRF": len(ss._issues) if 'ss' in locals() and hasattr(ss, "_issues") else 0,
        "Misconfiguration": len(misconf_issues) if 'misconf_issues' in locals() else 0,
        "Inventory": len(inv_issues) if 'inv_issues' in locals() else 0,
        "UnsafeConsumption": len(safe_issues) if 'safe_issues' in locals() else 0
    }
    
    total_vulns = sum(summary.values())
    print("Summary of vulnerabilities found")
    print("---------------------------------------")
    for k, v in summary.items():
        print(f" {k:18}: {v}")
    print("---------------------------------------")
    print(f"  Total found       : {total_vulns}")
    styled_print("Scan complete. All results and logs saved.", "ok")
        
    html_files = sorted(str(f) for f in output_dir.glob("api_*_report.html"))
 
    if not html_files:
        styled_print("Geen HTML-rapporten om te combineren  stap over.", "info")
    else:
        styled_print("Combining HTML reports ", "info")
        try:
            generate_combined_html(
                output=str(output_dir / "combined_report.html"),
                files=html_files
            )
            styled_print("Combined HTML report saved.", "ok")
        except Exception as exc:
            styled_print(f"Combined HTML report failed: {exc}", "fail")


       
    
if __name__ == "__main__":
    main()