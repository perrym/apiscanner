from __future__ import annotations
"""

"""


import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
import urllib3
import requests
import logging
import time
# Logging & warnings
logging.getLogger("urllib3").setLevel(logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Externe modules (project-intern)
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



def check_api_reachable(url: str, session: requests.Session, retries: int = 3, delay: int = 3):
    """Check if the API is reachable with retry attempts."""
    for attempt in range(1, retries + 1):
        try:
            print(f"\n🔍 Checking connection to {url} (attempt {attempt}/{retries})...")
            resp = session.get(url, timeout=5)
            if resp.status_code < 400:
                print(f" Connection successful to {url} (status: {resp.status_code})")
                return  # << Als connectie gelukt is, GA VERDER
            else:
                print(f" Warning: Server responded with status {resp.status_code} at {url}")
                return  # << Server leeft, dus ook verder gaan
        except requests.exceptions.RequestException as e:
            print(f" Attempt {attempt} failed: {e}")
            if attempt < retries:
                print(f"** Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"❌ ERROR: Cannot connect to {url} after {retries} attempts.")
                sys.exit(1)  # << Alleen na alle retries stoppen

def normalize_url(url: str) -> str:
    """Ensure the URL has a schema (http or https)."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def create_output_directory(base_url: str) -> Path:
    clean = base_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    date = datetime.now().strftime("%Y-%m-%d")
    out_dir = Path(f"audit_{clean}_{date}")
    out_dir.mkdir(exist_ok=True)
    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=f"APISCAN {__version__} API Security Scanner Perry Mertens 2025")
    parser.add_argument("--url", required=True, help="Basis-URL van de API")
    parser.add_argument("--swagger", required=True, help="Path to Swagger/OpenAPI-JSON")
    parser.add_argument("--token", help="Bearer-token or auth-token")
    parser.add_argument("--threads", type=int, default=2, help="Threads ")
    for i in range(1, 11):
        parser.add_argument(f"--api{i}", action="store_true", help=f"Alleen API{i}-audit uitvoeren")
    args = parser.parse_args()
    args.url = normalize_url(args.url)

    sess = requests.Session()
    sess.verify = False
    check_api_reachable(args.url, sess)
    if args.token:
        sess.headers.update({"Authorization": f"Bearer {args.token}"})
    adapter = HTTPAdapter(pool_connections=args.threads * 4, pool_maxsize=args.threads * 4, max_retries=3)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)

    print(f"\n Lade Swagger: {args.swagger}")
    bola = BOLAAuditor(sess)
    spec = bola.load_swagger(args.swagger)
    if not spec:
        sys.exit("Swagger kan niet worden geladen of is leeg.")
    endpoints = bola.get_object_endpoints(spec)
    print(f" Swagger geladen – {len(endpoints)} endpoints gevonden")

    selected = [i for i in range(1, 11) if getattr(args, f"api{i}")]
    if not selected:
        selected = list(range(1, 11))

    output_dir = create_output_directory(args.url)
    print(f"\nOutput-directory: {output_dir}")

    bola_results, auth_issues = [], []
    prop_issues, res_issues = [], []
    authz_issues, biz_issues = [], []
    ssrf_issues, misconf_issues = [], []
    inv_issues, safe_issues = [], []

    if 1 in selected:
        print(f"\n API1 – BOLA-tests ({args.threads} threads)")
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = []
            for ep in endpoints:
                print(f"➡️ Testing {ep['method']} {ep['path']}")
                futures.append(ex.submit(bola.test_endpoint, args.url, ep))
            for fut in futures:
                try:
                    bola_results.extend(fut.result())
                except Exception as e:
                    print(f" BOLA fout: {e}")
        report = bola.generate_report(bola_results)
        (output_dir / "api_bola_report.txt").write_text(report, "utf-8")
        print(f"✅ API1 klaar – {sum(1 for r in bola_results if getattr(r, 'is_vulnerable', False))} kwetsbaarheden")

    if 2 in selected:
        print("\n🔐 API2 – Broken Authentication")
        aa = AuthAuditor(args.url, sess)
        auth_issues = aa.test_authentication_mechanisms([])
        for issue in auth_issues:
            print(f"➡️ Authentication issue gevonden: {issue.get('description', 'Onbekend probleem')}")
        (output_dir / "api_broken_auth_report.txt").write_text(aa.generate_report(), "utf-8")
        print(f"✅ API2 klaar – {len(auth_issues)} issues")

    if 3 in selected:
        print("\n🔒 API3 – Property-level Authorization")
        prop_eps = [{"url": ep["path"], "method": ep["method"],
                     "test_object": {p["name"]: 1 for p in ep.get("parameters", []) if p["in"] == "path"}}
                    for ep in endpoints]
        pa = ObjectPropertyAuditor(args.url, sess)
        prop_issues = pa.test_object_properties(prop_eps)
        for issue in prop_issues:
            print(f"➡️ Property issue gevonden: {issue.get('description', 'Onbekend probleem')} @ {issue.get('endpoint', 'Onbekend endpoint')}")
        (output_dir / "api_property_report.txt").write_text(pa.generate_report(), "utf-8")
        print(f"✅ API3 klaar – {len(prop_issues)} issues")

    if 4 in selected:
        print("\n🚀 API4 – Resource Consumption")
        rc = ResourceAuditor(args.url, sess)
        resource_eps = [{"url": ep["path"], "method": ep["method"]} for ep in endpoints]
        for ep in resource_eps:
            print(f"➡️ Testing {ep['method']} {ep['url']}")
        res_issues = rc.test_resource_consumption(resource_eps)
        (output_dir / "api_resource_report.txt").write_text(rc.generate_report(res_issues), "utf-8")
        print(f"✅ API4 klaar – {len(res_issues)} issues")

    if 5 in selected:
        print("\n🛡️ API5 – Function-level Authorization")
        za = AuthorizationAuditor(args.url, sess)
        authz_issues = za.test_authorization()
        for issue in authz_issues:
            print(f"➡️ Authorization issue: {issue.get('description', 'Onbekend probleem')}")
        (output_dir / "api_admin_access_report.txt").write_text(za.generate_report(), "utf-8")
        print(f"✅ API5 klaar – {len(authz_issues)} issues")

    if 6 in selected:
        print("\n💸 API6 – Sensitive Business Flows")
        bf = BusinessFlowAuditor(args.url, sess)
        business_eps = [{"name": ep.get("operation_id", f"{ep['method']} {ep['path']}").replace(" ", "_"),
                         "url": ep["path"], "method": ep["method"], "body": {}}
                        for ep in endpoints if ep["method"] in {"POST", "PUT", "PATCH"}]
        for ep in business_eps:
            print(f"➡️ Testing business flow {ep['method']} {ep['url']}")
        biz_issues = bf.test_business_flows(business_eps)
        (output_dir / "api_business_flow_report.txt").write_text(bf.generate_report(), "utf-8")
        print(f"✅ API6 klaar – {len(biz_issues)} issues")

    if 7 in selected:
        print("\n🌐 API7 – SSRF")
        ss_eps = SSRFAuditor.endpoints_from_swagger(args.swagger)
        if ss_eps:
            for ep in ss_eps:
                print(f"➡️ Testing SSRF {ep['method']} {ep['url']}")
            ss = SSRFAuditor(args.url, sess)
            ssrf_issues = ss.test_endpoints(ss_eps)
            (output_dir / "api_ssrf_report.txt").write_text(ss.generate_report(), "utf-8")
            print(f"✅ API7 klaar – {len(ssrf_issues)} issues")
        else:
            print("ℹ️ Geen SSRF endpoints gevonden")

    if 8 in selected:
        print("\n🛠️ API8 – Security Misconfiguration")
        misconf_eps = MisconfigurationAuditor.endpoints_from_swagger(args.swagger)
        if misconf_eps:
            for ep in misconf_eps:
                print(f"➡️ Testing misconfiguration {ep['method']} {ep['path']}")
            mc = MisconfigurationAuditor(args.url, sess)
            misconf_issues = mc.test_endpoints(misconf_eps)
            (output_dir / "api_misconfig_report.txt").write_text(mc.generate_report(), "utf-8")
        print(f"✅ API8 klaar – {len(misconf_issues)} issues")

    if 9 in selected:
        print("\n📦 API9 – Improper Inventory Management")
        inv_eps = InventoryAuditor.endpoints_from_swagger(args.swagger)
        if inv_eps:
            for ep in inv_eps:
                print(f"➡️ Inventory check {ep}")
            inv = InventoryAuditor(args.url, sess)
            inv_issues = inv.test_inventory(inv_eps)
            (output_dir / "api_inventory_report.txt").write_text(inv.generate_report(), "utf-8")
        print(f"✅ API9 klaar – {len(inv_issues)} issues")

    if 10 in selected:
        print("\n🔗 API10 – Safe Consumption of 3rd-Party APIs")
        safe_eps = SafeConsumptionAuditor.endpoints_from_swagger(args.swagger)
        for ep in safe_eps:
            print(f"➡️ Safe API consumption check {ep}")
        sc = SafeConsumptionAuditor(sess)
        safe_issues = sc.test_endpoints(safe_eps)
        (output_dir / "api_safe_consumption_report.txt").write_text(sc.generate_report("markdown"), "utf-8")
        print(f"✅ API10 klaar – {len(safe_issues)} issues")

    summary = {
        "BOLA": sum(1 for x in bola_results if getattr(x, "is_vulnerable", False)),
        "Auth": len(auth_issues),
        "Property": len(prop_issues),
        "Resource": len(res_issues),
        "AdminAccess": len(authz_issues),
        "BusinessFlows": len(biz_issues),
        "SSRF": len(ssrf_issues),
        "Misconfiguration": len(misconf_issues),
        "Inventory": len(inv_issues),
        "UnsafeConsumption": len(safe_issues)
    }
    (output_dir / "api_summary_report.txt").write_text(json.dumps(summary, indent=2), "utf-8")

    print("\n Audits done – vulnerbilities:")
    total_vulns = sum(summary.values())
    print("\n Summary of vulnerabilities found")
    print("---------------------------------------")
    for k, v in summary.items():
        print(f"• {k:15}: {v}")
    print("---------------------------------------")
    print(f"  Totaal found : {total_vulns}\n")

    print("\n Building DOCX Report …")
    try:
        create_audit_report(output_dir)
    except Exception as exc:
        print(f" DOCX report failed: {exc}")

    print(f"\n All reports saved in : {output_dir}")


if __name__ == "__main__":
    main()
