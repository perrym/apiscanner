##############################################
# APISCAN - API Security Scanner             #
# Licensed under the MIT License             #
# Author: Perry Mertens pamsniffer@gmail.com #
##############################################
""""
APISCAN is a private and proprietary API security tool, developed independently for internal use and research purposes.
It supports OWASP API Security Top 10 (2023) testing, OpenAPI-based analysis, active scanning, and multi-format reporting.
Redistribution is not permitted without explicit permission.
Important: Testing with APISCAN is only permitted on systems and APIs for which you have explicit authorization. 
Unauthorized testing is strictly prohibited.
"""
from __future__ import annotations

import argparse
import builtins
import json
import logging
import queue
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3
from colorama import Fore, Style
from requests.adapters import HTTPAdapter
from tqdm import tqdm

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
from report_utils import HTMLReportGenerator, RISK_INFO
from doc_generator import generate_combined_html
from swagger_utils import enable_dummy_mode, extract_variables, write_variables_file

manual_file_map = {
    "BOLA": "bola",
    "BrokenAuth": "broken_auth",
    "Property": "property",
    "Resource": "resource",
    "AdminAccess": "admin_access",
    "BusinessFlows": "business_flows",
    "SSRF": "ssrf",
    "Misconfig": "misconfig",
    "Inventory": "inventory",
    "UnsafeConsumption": "unsafe_consumption",
}

logger = logging.getLogger("apiscan")
MAX_THREADS = 20


def styled_print(message: str, status: str = "info") -> None:
    symbols = {"info": "Info:", "ok": "OK:", "warn": "WARNING:", "fail": "FAIL:", "run": "->", "done": "Done"}
    colors = {"info": "\033[94m", "ok": "\033[92m", "warn": "\033[93m", "fail": "\033[91m", "run": "\033[96m", "done": "\033[92m"}
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


def save_html_report(issues, risk_key: str, url: str, output_dir: Path) -> None:
    html_report = HTMLReportGenerator(issues=issues, scanner=RISK_INFO[risk_key]["title"], base_url=url)
    filename = f"api_{manual_file_map[risk_key]}_report.html"
    html_report.save(output_dir / filename)


def check_api_reachable(url: str, session: requests.Session, retries: int = 3, delay: int = 3) -> None:
    for attempt in range(1, retries + 1):
        try:
            print(f"APISCAN by Perry Mertens pamsniffer@gmail.com(2025)\nChecking connection to {url} (attempt {attempt}/{retries})...")
            resp = session.get(url, timeout=5)
            print(f"Response status code: {resp.status_code}")
            if not resp.content:
                print("Empty response body detected.")
            if resp.status_code == 200 and any(w in resp.text.lower() for w in ["unauthorized", "access denied", "login", "authentication required"]):
                print("Received 200 OK but access denied content detected.")
                sys.exit(2)
            if resp.status_code in (401, 403):
                print(f"Authentication failed with status {resp.status_code}.")
                sys.exit(2)
            if resp.status_code < 400:
                print(f"Connection successful to {url} (status: {resp.status_code})")
                return
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
    parser = argparse.ArgumentParser(description=f"APISCAN {__version__} - API Security Scanner")
    parser.add_argument("--url", required=True, help="Base URL of the API to scan")
    parser.add_argument("--swagger", required=True, help="Path to Swagger/OpenAPI JSON file")
    parser.add_argument("--flow",
        choices=["none","token","client","basic","ntlm","auth"],
        default="none",
        help="Authentication flow: none, token (Bearer), client (OAuth2 Client Credentials), "
            "basic (Basic Auth), ntlm (Windows NTLM), auth (OAuth2 Authorization Code)"
    )
    parser.add_argument("--token", help="Bearer token value (used with --flow token)")
    parser.add_argument("--basic-auth", help="Basic auth in the form user:password (used with --flow basic)")
    parser.add_argument("--apikey", help="API key value (sent in header specified by --apikey-header)")
    parser.add_argument("--apikey-header", default="X-API-Key",help="Header name for API key (default: X-API-Key)")
    parser.add_argument("--ntlm", help="NTLM credentials in the form DOMAIN\\user:password (used with --flow ntlm)")
    parser.add_argument("--client-cert", help="Path to client certificate file (PEM, used for mTLS)")
    parser.add_argument("--client-key", help="Path to private key file (PEM, used for mTLS)")
    parser.add_argument("--cert-password", help="Password for client certificate private key (if encrypted)")
    parser.add_argument("--insecure", action="store_true",help="Disable TLS certificate validation (DANGEROUS, use only for testing)")
    parser.add_argument("--client-id", help="OAuth2 Client ID (for --flow client or auth)")
    parser.add_argument("--client-secret", help="OAuth2 Client Secret (for --flow client or auth)")
    parser.add_argument("--token-url", help="OAuth2 Token endpoint URL (for --flow client or auth)")
    parser.add_argument("--auth-url", help="OAuth2 Authorization endpoint URL (for --flow auth)")
    parser.add_argument("--redirect-uri", help="Redirect URI for OAuth2 Authorization Code flow")
    parser.add_argument("--scope", help="OAuth2 scope(s), space-separated")
    parser.add_argument("--threads", type=int, default=2, help="Number of concurrent threads to use")
    parser.add_argument("--debug", action="store_true", help="Enable debug output (verbose logging)")
    parser.add_argument("--api11", action="store_true", help="Run AI-assisted OWASP Top 10 analysis")
    parser.add_argument("--dummy", action="store_true", help="Use dummy data for request bodies and parameters")
    parser.add_argument("--export_vars", metavar="PATH", help="Export variables template (YAML if .yml/.yaml else JSON) and exit")


    for i in range(1, 11):
        parser.add_argument(f"--api{i}", action="store_true", help=f"Run only API{i} audit")

    args = parser.parse_args()

    builtins.debug_mode = args.debug
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="[DEBUG] %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="[INFO] %(message)s")

    selected_apis = [11] if args.api11 else [i for i in range(1, 11) if getattr(args, f"api{i}")] or list(range(1, 11))

    args.url = normalize_url(args.url)
    output_dir = create_output_directory(args.url)
    log_dir = output_dir / "log"
    log_dir.mkdir(exist_ok=True)
    logfile = log_dir / f"apiscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)

    logger = logging.getLogger("apiscan")
    logger.propagate = False

    sess = configure_authentication(args)
    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=3)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    check_api_reachable(args.url, sess)

    try:
        swagger_path = Path(args.swagger).resolve()
        if not swagger_path.exists():
            raise FileNotFoundError(f"Swagger file not found: {swagger_path}")
        if not swagger_path.is_file():
            raise ValueError(f"Path is not a file: {swagger_path}")
        if swagger_path.stat().st_size == 0:
            raise ValueError("Swagger file is empty")

        logger.info(f"Loading Swagger from: {swagger_path}")
        styled_print(f"Loading validated Swagger file: {swagger_path}", "info")

        with swagger_path.open("r", encoding="utf-8") as f:
            spec = json.load(f)

        bola = BOLAAuditor(sess)      # geen spec in constructor
        bola.spec = spec              # spec hier aan de auditor hangen
        endpoints = bola.get_object_endpoints(spec)   # <-- GEEF spec MEE

        ai_endpoints = [
            {"path": ep["path"], "method": ep["method"]}
            for ep in endpoints if ep.get("path") and ep.get("method")
        ]

        logger.debug(f"Swagger loaded - {len(endpoints)} endpoints")
        styled_print(f"Swagger loaded - {len(endpoints)} endpoints found", "ok")

    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Swagger processing failed: {e}")
        styled_print(str(e), "fail")  # geen extra "FAIL:" prefix hier
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during Swagger parsing: {e}")
        styled_print("Unexpected error during Swagger parsing", "fail")  # voorkom "FAIL: FAIL:"
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

    # --------------------------- API1: BOLA ---------------------------
    if 1 in selected_apis:
        tqdm.write(f"{Fore.CYAN}[API1] Starting BOLA (threads={args.threads}){Style.RESET_ALL}")
        logger.info("Running API1 - BOLA")

        bola_results = []

        bola = BOLAAuditor(sess)
        bola.session = sess
        bola.base_url = args.url
        bola.spec = spec

        endpoints = bola.get_object_endpoints(spec) or []   # <-- GEEF spec MEE

        max_workers = max(1, min(args.threads, MAX_THREADS))
        if max_workers == 1:
            for ep in tqdm(endpoints, desc="BOLA endpoints", unit="endpoint"):
                try:
                    res = bola.test_endpoint(args.url, ep)
                    if res:
                        bola_results.extend(res)
                except Exception as e:
                    tqdm.write(f"{Fore.RED}[API1][ERR] {ep.get('method')} {ep.get('path')}: {e}{Style.RESET_ALL}")
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(bola.test_endpoint, args.url, ep): ep for ep in endpoints}
                for fut in tqdm(as_completed(futures), total=len(futures), desc="BOLA endpoints", unit="endpoint"):
                    ep = futures[fut]
                    try:
                        res = fut.result()
                        if res:
                            bola_results.extend(res)
                    except Exception as e:
                        tqdm.write(f"{Fore.RED}[API1][ERR] {ep.get('method')} {ep.get('path')}: {e}{Style.RESET_ALL}")

        bola.issues = [r.to_dict() for r in bola_results if getattr(r, "status_code", 0) != 0]
        try:
            report = bola.generate_report()
        except Exception as e:
            tqdm.write(f"{Fore.RED}[API1][ERR] report generation failed: {e}{Style.RESET_ALL}")

        found = sum(1 for r in bola_results if getattr(r, "is_vulnerable", False))
        msg = (
            f"{Fore.GREEN}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}" if found == 0 else
            f"{Fore.YELLOW}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}" if found < 5 else
            f"{Fore.RED}API1 complete - {found} vulnerabilities found{Style.RESET_ALL}"
        )
        save_html_report(bola.issues, "BOLA", args.url, output_dir)
        styled_print(msg, "done")


    # --------------------- API2: Broken Authentication ----------------
    if 2 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API2 - Broken Authentication{Style.RESET_ALL}")
        logger.info("Running API2 - Broken Authentication")
        norm_eps = []
        for ep in endpoints:
            try:
                path = ep["path"]
                method = ep["method"].upper()
                norm_eps.append({"path": path, "method": method})
            except KeyError:
                continue
        aa = AuthAuditor(args.url, sess, show_progress=True)
        auth_issues = aa.test_authentication_mechanisms(norm_eps)
        for issue in auth_issues:
            desc = issue.get("description", "Unknown")
            ep   = issue.get("endpoint", issue.get("url", ""))
            sev  = issue.get("severity", "Info")
            tqdm.write(f"-> Auth issue [{sev}]: {desc} @ {ep}")
        save_html_report(auth_issues, "BrokenAuth", args.url, output_dir)
        styled_print(f"API2 complete - {len(auth_issues)} issues", "done")

    # --------- API3: Property-level Authorization (Object Property) ---
    if 3 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API3 - Property-level Authorization{Style.RESET_ALL}")
        logger.info("Running API3 - Property-level Authorization")
        pa = ObjectPropertyAuditor(args.url, sess, show_progress=True)
        prop_issues = pa.test_object_properties(endpoints)
        for issue in prop_issues:
            tqdm.write(
                f"-> Property issue: {issue.get('description','Unknown')} @ {issue.get('endpoint','Unknown')}"
            )
        save_html_report(prop_issues, "Property", args.url, output_dir)
        styled_print(f"API3 complete - {len(prop_issues)} issues", "done")


    # ---------------------- API4: Resource Consumption ----------------
    if 4 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API4 - Resource Consumption{Style.RESET_ALL}")
        logger.info("Running API4 - Resource Consumption")
        rc = ResourceAuditor(args.url, sess, show_progress=True)
        resource_eps = [{"path": ep["path"], "method": ep["method"]} for ep in endpoints]
        res_issues = rc.test_resource_consumption(resource_eps)
        save_html_report(res_issues, "Resource", args.url, output_dir)
        styled_print(f"API4 complete - {len(res_issues)} issues", "done")

    # ------------------ API5: Function-level Authorization ------------
    if 5 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API5 - Function-level Authorization{Style.RESET_ALL}")
        logger.info("Running API5 - Function-level Authorization")
        za = AuthorizationAuditor(args.url, sess)
        za.discovered_endpoints = [
            {"url": urljoin(args.url.rstrip("/") + "/", ep["path"].lstrip("/")),
            "methods": [ep["method"].upper()],
            "sensitive": "admin" in ep["path"].lower()}
            for ep in endpoints
        ]
        authz_issues = za.test_authorization(show_progress=True)
        for issue in authz_issues:
            tqdm.write(f"-> Authorization issue: {issue.get('description','Unknown')} @ {issue.get('endpoint','Unknown')}")
        save_html_report(authz_issues, "AdminAccess", args.url, output_dir)
        styled_print(f"API5 complete - {len(authz_issues)} issues", "done")


    # --------------------- API6: Sensitive Business Flows -------------
    if 6 in selected_apis:
        print(" API6 - Sensitive Business Flows")
        logger.info("Running API6 - Sensitive Business Flows")
        bf = BusinessFlowAuditor(args.url, sess)
        business_eps = [{"name": ep.get("operation_id", f"{ep['method']} {ep['path']}").replace(" ", "_"), "url": ep["path"], "method": ep["method"], "body": {}} for ep in endpoints if ep["method"] in {"POST", "PUT", "PATCH"}]
        biz_issues = bf.test_business_flows(business_eps)
        save_html_report(biz_issues, "BusinessFlows", args.url, output_dir)
        styled_print(f"API6 complete - {len(biz_issues)} issues", "done")

    # ------------------------------- API7: SSRF -----------------------
    if 7 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API7 - SSRF{Style.RESET_ALL}")
        logger.info("Running API7 - SSRF")

        ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger, default_base=args.url)
        if ss_eps:
            ss = SSRFAuditor(args.url, sess, show_progress=True)
            ssrf_issues = ss.test_endpoints(ss_eps)
            save_html_report(ssrf_issues, 'SSRF', args.url, output_dir)
            styled_print(f"API7 complete - {len(ssrf_issues)} issues", "done")
        else:
            styled_print("No SSRF endpoints found", "warn")
    # ------------------- API8: Security Misconfiguration --------------
    if 8 in selected_apis:
        tqdm.write(f"{Fore.CYAN} API8 - Security Misconfiguration{Style.RESET_ALL}")
        logger.info("Running API8 - Security Misconfiguration")
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            mc = MisconfigurationAuditor(args.url, sess, show_progress=True, debug=args.debug)
            misconf_issues = mc.test_endpoints(misconf_eps)
            save_html_report(misconf_issues, 'Misconfig', args.url, output_dir)
            styled_print(f"API8 complete - {len(misconf_issues)} issues", "done")
        else:
            styled_print("No misconfiguration endpoints found", "warn")
    # --------------- API9: Improper Inventory Management --------------
    if 9 in selected_apis:
        print(" API9 - Improper Inventory Management")
        logger.info("Running API9 - Improper Inventory Management")
        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger)
        if inv_eps:
            inv = InventoryAuditor(args.url, sess)
            inv_issues = inv.test_inventory(inv_eps)
            save_html_report(inv_issues, "Inventory", args.url, output_dir)
            styled_print(f"API9 complete - {len(inv_issues)} issues", "done")
        else:
            styled_print("No inventory endpoints found", "warn")

    # ---------- API10: Safe Consumption of 3rd-Party APIs -------------
    if 10 in selected_apis:
        print(" API10 - Safe Consumption of 3rd-Party APIs")
        logger.info("Running API10 - Safe Consumption")
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        for ep in safe_eps:
            print(f"-> Safe API consumption check {ep}")
        sc = SafeConsumptionAuditor(base_url=args.url, session=sess)
        safe_issues = sc.test_endpoints(safe_eps)
        sc._dump_raw_issues(output_dir / "log")
        sc._filter_issues()
        sc._dedupe_issues()
        save_html_report(safe_issues, "UnsafeConsumption", args.url, output_dir)
        styled_print(f"API10 complete - {len(safe_issues)} issues", "done")

    # --------------------- API11: AI-assisted analysis ----------------
    if 11 in selected_apis:
        styled_print("API11 - AI-assisted OWASP analysis", "info")
        logger.info("Running API11 - AI-assisted audit")
        try:
            from ai_client import analyze_endpoints_with_gpt, save_ai_summary
            ai_results = analyze_endpoints_with_gpt(ai_endpoints, live_base_url=args.url, print_results=True)
            save_ai_summary(ai_results, output_dir / "AI-api11_scanresults.json")
            styled_print(f"API11 complete - {len(ai_results)} endpoints analyzed", "done")
        except Exception as e:
            styled_print(f"AI analysis failed: {e}", "fail")
            logger.exception("AI analysis exception")

        # Generate vulnerability summary
    vulnerability_summary = {
        "BOLA": sum(1 for result in bola_results if getattr(result, "is_vulnerable", False)) if 'bola_results' in locals() else 0,
        "Authentication": len(auth_issues) if 'auth_issues' in locals() else 0,
        "Property-Level Auth": len(prop_issues) if 'prop_issues' in locals() else 0,
        "Resource Consumption": len(res_issues) if 'res_issues' in locals() else 0,
        "Admin Access": len(authz_issues) if 'authz_issues' in locals() else 0,
        "Business Flows": len(biz_issues) if 'biz_issues' in locals() else 0,
        "SSRF": len(getattr(ss, "_issues", [])) if 'ss' in locals() else 0,
        "Misconfiguration": len(misconf_issues) if 'misconf_issues' in locals() else 0,
        "Inventory": len(inv_issues) if 'inv_issues' in locals() else 0,
        "Unsafe Consumption": len(safe_issues) if 'safe_issues' in locals() else 0,
    }
    
    total_vulnerabilities = sum(vulnerability_summary.values())
    
    # Print formatted summary
    print("\n" + "="*50)
    print("VULNERABILITY SCAN SUMMARY".center(50))
    print("="*50)
    
    for category, count in vulnerability_summary.items():
        color = Fore.GREEN if count == 0 else Fore.YELLOW if count < 5 else Fore.RED
        print(f" {category:<22}: {color}{count:>3}{Style.RESET_ALL}")
    
    print("-"*50)
    total_color = Fore.GREEN if total_vulnerabilities == 0 else Fore.YELLOW if total_vulnerabilities < 10 else Fore.RED
    print(f" {'TOTAL VULNERABILITIES':<22}: {total_color}{total_vulnerabilities:>3}{Style.RESET_ALL}")
    print("="*50)
    
    # Add risk assessment
    if total_vulnerabilities == 0:
        risk_level = "LOW RISK"
        risk_color = Fore.GREEN
    elif total_vulnerabilities < 10:
        risk_level = "MEDIUM RISK"
        risk_color = Fore.YELLOW
    else:
        risk_level = "HIGH RISK"
        risk_color = Fore.RED
        
      
    styled_print("Scan complete. All results and logs have been saved.", "ok")

    html_files = sorted(str(f) for f in output_dir.glob("api_*_report.html"))
    if not html_files:
        styled_print("No HTML reports to combine, skipping.", "info")
    else:
        styled_print("Combining HTML reports", "info")
        try:
            generate_combined_html(output=str(output_dir / "combined_report.html"), files=html_files)
            styled_print("Combined HTML report saved.", "ok")
        except Exception as exc:
            styled_print(f"Combined HTML report failed: {exc}", "fail")


if __name__ == "__main__":
    main()
