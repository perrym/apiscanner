########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.2 1-4-2026                                 #
########################################################
import argparse
import glob
import re
from pathlib import Path
from typing import List, Tuple
from bs4 import BeautifulSoup, Tag

# ---------------------- RISK INFO DEFINITIONS ----------------------
RISK_INFO = {
    "BOLA": {
        "title": "API1:2023 - Broken Object Level Authorization",
        "description": (
            "APIs often expose object identifiers such as user IDs or document IDs within request paths or parameters. "
            "If proper authorization checks are not implemented, attackers can modify these identifiers to access data "
            "that does not belong to them. This leads to unauthorized access or data leakage. The risk is especially high "
            "in RESTful APIs where object references are part of the URL structure."
        ),
        "recommendation": """- Implement object-level authorization checks on every request
- Use unpredictable IDs (UUID) instead of sequential integers
- Verify the requester has ownership/access rights for each object
- Centralize authorization logic
- Log and alert on failed authorization attempts"""
    },
    "BrokenAuth": {
        "title": "API2:2023 - Broken Authentication",
        "description": (
            "Authentication mechanisms that are poorly designed or misconfigured allow attackers to compromise tokens, "
            "bypass login flows, or hijack user sessions. This includes flaws in token generation, session expiration, "
            "credential storage, or password reset logic. The impact can range from unauthorized access to full account takeover."
        ),
        "recommendation": """- Use MFA for sensitive actions
- Work with short-lived, cryptographically signed tokens
- Secure password/token recovery flows
- Temporarily lock accounts after too many failed attempts
- Never expose credentials in URLs or error messages"""
    },
    "Property": {
        "title": "API3:2023 - Broken Object Property Level Authorization",
        "description": (
            "APIs that expose internal object properties without proper access control allow clients to view or manipulate data "
            "they shouldn't have access to. This includes over-sharing in API responses and accepting unexpected or sensitive fields "
            "in client submissions, known as mass assignment vulnerabilities. Attackers can exploit this to alter read-only or admin-level fields."
        ),
        "recommendation": """- Explicitly define which fields are visible/editable per role
- Validate request and response payloads with schemas
- Filter sensitive fields server-side before sending
- Use different DTOs for different access levels
- Strictly separate public and private properties"""
    },
    "Resource": {
        "title": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "Lack of proper resource management allows attackers to overload the system with excessive requests, large payloads, "
            "or expensive operations. This can lead to denial of service (DoS), service degradation, or increased operational costs. "
            "APIs that allow unlimited requests, nested queries, or unbounded filters are particularly vulnerable."
        ),
        "recommendation": """- Implement rate limiting and quotas
- Set maximum payload sizes
- Use pagination or partial responses
- Monitor abnormal consumption
- Cache expensive operations where possible"""
    },
    "AdminAccess": {
        "title": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "APIs may expose administrative or privileged operations without enforcing strict access control. "
            "Attackers can escalate privileges by calling hidden or undocumented functions. These issues often stem from "
            "complex role hierarchies, inconsistent policy enforcement, or a lack of centralized authorization checks."
        ),
        "recommendation": """- Use RBAC or ABAC with deny-by-default
- Centralize authorization logic
- Thoroughly test ALL admin functions
- Require step-up authentication for critical actions
- Document and encrypt sensitive admin flows"""
    },
    "BusinessFlows": {
        "title": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs that expose key business processes such as financial transactions, bookings, or account changes are attractive targets "
            "for abuse. If such flows lack business logic validation or abuse protection (e.g. rate limiting, anomaly detection), "
            "they may be exploited through automation, leading to financial loss or fraud."
        ),
        "recommendation": """- Add business context validations (e.g. balance, limits)
- Use CAPTCHA/rate limiting against bots
- Detect and block abnormal patterns
- Require step-up authentication for risky actions
- Monitor critical flows in real-time"""
    },
    "SSRF": {
        "title": "API7:2023 - Server Side Request Forgery",
        "description": (
            "If an API accepts URLs or user-defined targets and then performs server-side requests, attackers may exploit this "
            "functionality to access internal services, scan the network, or retrieve sensitive metadata. SSRF can also be used as "
            "a pivot point in multi-stage attacks against internal infrastructure or cloud metadata endpoints."
        ),
        "recommendation": """- Validate & sanitize all provided URLs
- Use an allow-list of permitted domains
- Don't follow redirects or limit the number of hops
- Segment internal networks; block outgoing requests where possible
- Apply egress firewall rules"""
    },
    "Misconfig": {
        "title": "API8:2023 - Security Misconfiguration",
        "description": (
            "Misconfigured HTTP headers, CORS policies, verbose error messages, and leftover debug endpoints are common in APIs "
            "and can be exploited to gain insight into backend systems or bypass protections. Misconfigurations may also lead to "
            "data exposure, unauthorized access, or weakened transport security."
        ),
        "recommendation": """- Harden systems according to security baselines
- Disable unnecessary HTTP methods
- Remove debug/test endpoints in production
- Set strict CORS policies
- Regularly review & patch configurations"""
    },
    "Inventory": {
        "title": "API9:2023 - Improper Inventory Management",
        "description": (
            "Organizations often lose track of API versions, staging/test environments, and undocumented endpoints. "
            "These shadow or zombie APIs may be exposed to the internet and remain unprotected. Without proper inventory, "
            "you can't assess security posture, enforce updates, or manage deprecations effectively."
        ),
        "recommendation": """- Maintain an up-to-date inventory of all endpoints
- Carefully deprecate & remove old versions
- Document each endpoint with purpose & owner
- Implement clear versioning strategy
- Proactively scan for undocumented APIs"""
    },
    "UnsafeConsumption": {
        "title": "API10:2023 - Unsafe Consumption of APIs",
        "description": (
            "Trusting third-party or upstream APIs without proper validation introduces significant risks. These include injection attacks, "
            "unexpected responses, and business logic flaws. If these dependencies are not handled defensively, they can cause "
            "data corruption, denial of service, or unauthorized access to internal systems."
        ),
        "recommendation": """- Validate & sanitize all data from third-party APIs
- Set time limits & retries
- Fail safely: handle external errors gracefully
- Keep third-party credentials secret & rotate regularly
- Continuously monitor external service behavior"""
    },
}

# ------------------------------------------------------------------
INTRO_HTML = """
<div class="intro">
<p>Hello there, API scanner!</p>
<p>You are looking at the front door to my trusty sidekick, <strong>APIScan</strong>. Think of it as a polite but relentless bouncer for your endpoints: it checks every route on the guest list, asks awkward questions, and refuses entry to anything shady.</p>

<h2>What it does</h2>
<ol>
  <li>Fires a barrage of requests at your API and notes every weird response.</li>
  <li>Maps those quirks onto the OWASP API Top Ten, so you instantly spot classics like Broken Object Level Authorization or sneaky Server-Side Request Forgery.</li>
  <li>Packs the evidence into clear, human-readable reports with risk levels, timestamps, and ready-made advice.</li>
</ol>

<h2>Why you will love it</h2>
<ul>
  <li>Saves you the thrill of manual testing at three in the morning.</li>
  <li>Fits nicely into CI or a quick weekend audit with equal charm.</li>
  <li>Gives developers concrete steps instead of vague hand-waving.</li>
  <li>Lets auditors (hi, that is me) sign off with confidence and maybe even a grin.</li>
</ul>

<h2>How to use it</h2>
<p>Point it at a base URL, grab a coffee, and watch the findings roll in. High risks rise to the top, harmless noise slips to the bottom. Copy the tips, fix the code, rerun, repeat until your logs are greener than a fresh avocado.</p>

<p>Sure, security is serious business, but a little humor keeps the bits flowing. So enjoy the scan, patch those holes, and sleep better knowing your API is wearing a proper suit of armor. No capes required.</p>

<h2>Greetings Perry Mertens 2025 (c) pamsniffer@gmail.com</h2>
</div>
""".strip()

ALIASES = {
    # Numeric patterns
    r"api1": "BOLA",
    r"api2": "BrokenAuth",
    r"api3": "Property",
    r"api4": "Resource",
    r"api5": "AdminAccess",
    r"api6": "BusinessFlows",
    r"api7": "SSRF",
    r"api8": "Misconfig",
    r"api9": "Inventory",
    r"api10": "UnsafeConsumption",

    # Textual patterns
    r"bola": "BOLA",
    r"broken[_-]?auth": "BrokenAuth",
    r"property": "Property",
    r"resource": "Resource",
    r"admin[_-]?access": "AdminAccess",
    r"business[_-]?flows?": "BusinessFlows",
    r"ssrf": "SSRF",
    r"misconfig": "Misconfig",
    r"inventory": "Inventory",
    r"unsafe[_-]?consumption": "UnsafeConsumption",
}

# ---------------------- UTILITIES ---------------------------------

def discover_files(pattern: str) -> List[str]:
    paths = glob.glob(pattern)
    paths.sort()
    return paths

def insert_intro(html_text: str) -> str:
    soup: BeautifulSoup = BeautifulSoup(html_text, "html.parser")
    header: Tag | None = soup.body.find("h1") if soup.body else None

    if header is None:
        raise ValueError("No <h1> header found in the provided HTML document.")

    header.insert_after(BeautifulSoup(INTRO_HTML, "html.parser"))
    return str(soup)

#----------Infer risk key from filename ---------------------
def infer_risk_key(filename: str) -> str:
    
    lower = filename.lower()

    
    num_match = re.search(r"api(\d+)", lower)
    if num_match:
        num_map = {
            "1": "BOLA",
            "2": "BrokenAuth",
            "3": "Property",
            "4": "Resource",
            "5": "AdminAccess",
            "6": "BusinessFlows",
            "7": "SSRF",
            "8": "Misconfig",
            "9": "Inventory",
            "10": "UnsafeConsumption",
        }
        n = num_match.group(1).lstrip("0")
        if n in num_map:
            return num_map[n]

    for regex, key in ALIASES.items():
        if re.search(regex, lower):
            return key

    raise ValueError(f"Cannot determine risk key for '{filename}'. Update ALIASES or rename file.")


def extract_styles(soup: BeautifulSoup) -> Tuple[List[Tag], List[Tag]]:
    style_tags = soup.find_all("style")
    link_tags = soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower())
    for tag in style_tags + link_tags:
        tag.extract()
    return style_tags, link_tags


def add_back_links(section: Tag):
    factory = BeautifulSoup("", "html.parser")
    for hdr in section.find_all(["h2", "h3", "h4", "h5", "h6"]):
        if hdr.get_text(strip=True).lower().startswith("finding"):
            link = factory.new_tag("a", href="#top", **{"class": "back-to-index"})
            link.string = "- Back to index"
            hdr.insert_after(link)

# ---------------------- HTML HELPERS -------------------------------

def build_index(keys: List[str]) -> str:
    """Clickable table of contents - full OWASP titles, no numbering."""
    soup = BeautifulSoup(features="html.parser")
    ul = soup.new_tag("ul")

    for idx, key in enumerate(keys, start=1):
        li = soup.new_tag("li")
        a = soup.new_tag("a", href=f"#rapport{idx}")
        a.string = RISK_INFO[key]["title"]          
        li.append(a)
        ul.append(li)

    return str(ul)



def build_header(idx: int, risk_key: str) -> Tag:
    """Header with full OWASP title and - back-to-index link."""
    info = RISK_INFO[risk_key]
    soup = BeautifulSoup(features="html.parser")

    header_div = soup.new_tag(
        "div", **{"class": "rapport-header", "id": f"rapport{idx}"}
    )

    # ----- Title
    h1 = soup.new_tag("h1")
    h1.string = info["title"]             
    header_div.append(h1)

    # ---- Back to index
    link_top = soup.new_tag("a", href="#top", **{"class": "back-to-index"})
    link_top.string = "- Back to index"
    header_div.append(link_top)

    # ----- Description
    p_desc = soup.new_tag("p")
    p_desc.string = info["description"]
    header_div.append(p_desc)

    # ----- Recommendations
    details = soup.new_tag("details")
    summary = soup.new_tag("summary")
    summary.string = "Recommendations"
    details.append(summary)
    for line in info["recommendation"].splitlines():
        if line.strip().startswith("-"):
            li = soup.new_tag("li")
            li.string = line.lstrip("-").strip()
            details.append(li)
    header_div.append(details)

    return header_div


def build_headerold(idx: int, risk_key: str) -> Tag:
    info = RISK_INFO[risk_key]
    soup = BeautifulSoup(features="html.parser")
    header_div = soup.new_tag(
        "div", **{"class": "rapport-header", "id": f"rapport{idx}"}
    )

    h1 = soup.new_tag("h1")
    h1.string = info["title"]  
    header_div.append(h1)

    p_desc = soup.new_tag("p")
    p_desc.string = info["description"]
    header_div.append(p_desc)

    details = soup.new_tag("details")
    summary = soup.new_tag("summary")
    summary.string = "Recommendations"
    details.append(summary)
    for line in info["recommendation"].splitlines():
        if line.strip().startswith("-"):
            li = soup.new_tag("li")
            li.string = line.lstrip("-").strip()
            details.append(li)
    header_div.append(details)

    return header_div

# ---------------------- MERGE LOGIC --------------------------------
def generate_combined_html(output: str, files: List[str]):
    if not files:
        raise ValueError("No files found matching the pattern.")

    files_sorted = sorted(
        files,
        key=lambda fp: int(
            re.search(
                r"API(\d+)", RISK_INFO[infer_risk_key(Path(fp).name)]["title"]
            ).group(1)
        ),
    )

    risk_keys: list[str] = []
    sections_html: list[str] = []
    collected_styles: list[str] = []

# -----------  index ---------------------------
    for idx, path in enumerate(files_sorted, start=1):
        risk_key = infer_risk_key(Path(path).name)
        risk_keys.append(risk_key)

        soup = BeautifulSoup(Path(path).read_text(encoding="utf-8"), "html.parser")

        style_tags, link_tags = extract_styles(soup)
        collected_styles.extend(map(str, style_tags + link_tags))

        wrapper = soup.new_tag("section", **{"class": "rapport"})
        wrapper.append(build_header(idx, risk_key))

        body_src = soup.body or soup
        for child in list(body_src.children):
            wrapper.append(child)

        add_back_links(wrapper)
        sections_html.append(str(wrapper))

# ------------- CSS dedupliceed -----------------------------------------------------
    unique_styles: list[str] = []
    seen: set[str] = set()
    for raw in collected_styles:
        css = raw.strip()
        if css not in seen:
            seen.add(css)
            unique_styles.append(css)

    # -- End-HTML ----------------------------------------------
    nav_html = build_index(risk_keys)

    final_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Combined API Reports by Perry Mertens (c) pamsniffer@gmail.com</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; }}
nav ul {{ list-style: none; padding: 0; }}
nav li {{ margin-bottom: 0.4em; }}
.rapport {{ margin-top: 3em; border-top: 1px solid #ccc; padding-top: 2em; }}
.rapport-header details {{ margin-top: 1em; }}
.back-to-index {{ display: inline-block; margin: 0.5em 0; font-size: 0.9em; }}
</style>
{''.join(unique_styles)}
</head>
<body>
<a id="top"></a>
<h1 style="font-size: 28px;">API Report Overview - APIScan by Perry Mertens (c) pamsniffer@gmail.com</h1>
<nav>
{nav_html}
</nav>
{''.join(sections_html)}
</body>
</html>"""

    final_html = insert_intro(final_html)
    Path(output).write_text(final_html, encoding="utf-8")
    print(f"Merged into {output} - processed {len(files)} reports.")



# ---------------------- CLI ---------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Combine API HTML reports into one file with index, OWASP headers, and back link."
    )
    parser.add_argument("-o", "--output", default="combined.html", help="Output file")
    parser.add_argument("-p", "--pattern", default="api_*.html", help="Glob pattern for report files")
    args = parser.parse_args()

    files = discover_files(args.pattern)
    merge(args.output, files)


