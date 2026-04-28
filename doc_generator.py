########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 4.0 26-04-2026                              #
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
<div class="intro-card">
<h2>What APIScan does</h2>
<ol>
  <li>Fires a barrage of requests at your API and notes every unusual response.</li>
  <li>Maps those findings onto the OWASP API Top 10, covering everything from Broken Object Level Authorization to Server-Side Request Forgery.</li>
  <li>Packages the evidence into structured, human-readable reports with risk levels, timestamps, and actionable remediation steps.</li>
</ol>
<h2>How to read this report</h2>
<p>Each section below corresponds to one OWASP API Top 10 category. Findings are ranked by severity: Critical, High, Medium, Low, Info. Use the sidebar to jump directly to a category.</p>
<h2>Author</h2>
<p>Perry Mertens &mdash; pamsniffer@gmail.com &copy; 2025</p>
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
    # Insert after .combined-banner if present, else after first h1
    banner = soup.find(class_="combined-banner")
    if banner:
        banner.insert_after(BeautifulSoup(INTRO_HTML, "html.parser"))
    else:
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
    """Sidebar navigation list with OWASP API numbers and full titles."""
    items = []
    for idx, key in enumerate(keys, start=1):
        title = RISK_INFO[key]["title"]
        # Extract API number (e.g. "API1") and the rest
        m = re.match(r"(API\d+:\d{4})\s*-\s*(.*)", title)
        if m:
            num_part  = m.group(1).split(":")[0]   # "API1"
            name_part = m.group(2)                   # "Broken Object Level Authorization"
        else:
            num_part  = str(idx)
            name_part = title
        items.append(
            f'<li><a href="#rapport{idx}">'
            f'<span class="nav-num">{num_part}</span>'
            f'{name_part}</a></li>'
        )
    return "<ul>" + "".join(items) + "</ul>"



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

    BASE_CSS = """
:root {
  --bg:      #0d1117; --bg2: #161b27; --bg3: #1c2333;
  --border:  #21293a; --text: #e2e8f0; --muted: #7d93ad;
  --accent:  #0ea5e9; --accent2: #22d3ee;
  --c-crit:  #ef4444; --c-high: #f97316; --c-med: #22c55e;
  --c-low:   #60a5fa; --c-info: #94a3b8;
  --radius:  10px;
}
*, *::before, *::after { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0; min-height: 100%;
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.6;
  font-size: 14px;
}
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

/* ── Page layout ── */
.combined-layout { display: flex; min-height: 100vh; }

/* ── Sidebar nav ── */
.combined-sidebar {
  width: 260px; flex-shrink: 0;
  background: var(--bg2); border-right: 1px solid var(--border);
  position: sticky; top: 0; height: 100vh; overflow-y: auto;
  display: flex; flex-direction: column;
}
.sidebar-brand {
  padding: 20px 16px 14px;
  border-bottom: 1px solid var(--border);
}
.sidebar-logo {
  display: flex; align-items: center; gap: 10px; margin-bottom: 6px;
}
.sidebar-logo-icon {
  width: 34px; height: 34px; border-radius: 9px;
  background: linear-gradient(135deg, #0ea5e9, #22d3ee);
  display: grid; place-items: center;
  font-size: 15px; font-weight: 800; color: #fff; flex-shrink: 0;
}
.sidebar-logo-text { font-size: 14px; font-weight: 700; color: var(--text); }
.sidebar-logo-sub  { font-size: 11px; color: var(--muted); }
.sidebar-nav { padding: 12px 0; flex: 1; }
.sidebar-nav-label {
  font-size: 10px; font-weight: 700; letter-spacing: .1em;
  color: var(--muted); text-transform: uppercase;
  padding: 6px 16px 4px;
}
.sidebar-nav ul { list-style: none; margin: 0; padding: 0; }
.sidebar-nav li  { margin: 0; }
.sidebar-nav a {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 7px 16px; color: var(--muted); text-decoration: none;
  font-size: 12.5px; border-left: 3px solid transparent;
  transition: background 0.12s, color 0.12s, border-color 0.12s;
  line-height: 1.4;
}
.sidebar-nav a:hover {
  background: var(--bg3); color: var(--text);
  border-left-color: var(--accent);
}
.sidebar-nav a .nav-num {
  min-width: 18px; font-weight: 700; color: var(--accent);
  font-size: 11px; margin-top: 2px;
}
.sidebar-footer {
  padding: 12px 16px; border-top: 1px solid var(--border);
  font-size: 10px; color: var(--muted); line-height: 1.5;
}

/* ── Main content ── */
.combined-main {
  flex: 1; min-width: 0;
  padding: 0 40px 60px;
  max-width: 960px;
}

/* ── Top banner ── */
.combined-banner {
  padding: 28px 0 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 32px;
}
.combined-banner h1 {
  margin: 0 0 6px; font-size: 22px; font-weight: 700; color: var(--text);
}
.combined-banner p {
  margin: 0; font-size: 13px; color: var(--muted);
}

/* ── Intro card ── */
.intro-card {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 22px 26px;
  margin-bottom: 36px;
}
.intro-card h2 {
  font-size: 13px; font-weight: 700; color: var(--accent);
  text-transform: uppercase; letter-spacing: .06em;
  margin: 18px 0 6px;
}
.intro-card h2:first-child { margin-top: 0; }
.intro-card p, .intro-card li { font-size: 13px; color: var(--muted); margin: 4px 0; }
.intro-card ol, .intro-card ul { padding-left: 18px; }

/* ── Section / rapport ── */
.rapport {
  margin-bottom: 52px; scroll-margin-top: 20px;
}
.rapport-header {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 20px 24px; margin-bottom: 20px;
  border-left: 4px solid var(--accent);
}
.rapport-header h1 {
  margin: 0 0 10px; font-size: 17px; font-weight: 700; color: var(--text);
}
.rapport-header p {
  margin: 0 0 12px; font-size: 13px; color: var(--muted); line-height: 1.6;
}
.rapport-header details {
  margin-top: 10px;
}
.rapport-header details summary {
  cursor: pointer; font-size: 12px; font-weight: 600; color: var(--accent);
  user-select: none; list-style: none; display: flex; align-items: center; gap: 6px;
}
.rapport-header details summary::before { content: "▶"; font-size: 9px; }
details[open] summary::before { content: "▼"; }
.rapport-header details li {
  font-size: 12.5px; color: var(--muted); padding: 3px 0 3px 14px;
  border-left: 2px solid var(--border);
}

/* ── Back links ── */
.back-to-index, .back-link {
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 11.5px; color: var(--muted); text-decoration: none;
  padding: 3px 10px; border: 1px solid var(--border);
  border-radius: 999px; transition: color .12s, border-color .12s;
  margin: 8px 0;
}
.back-to-index:hover, .back-link:hover {
  color: var(--accent); border-color: var(--accent);
}

/* ── Section divider ── */
.rapport + .rapport { border-top: none; }

/* ── Override report inner styles ── */
body > .combined-layout .rapport table.summary { margin-top: 16px; }
</style>"""

    READABLE_CSS = """
:root {
  --bg: #f6f8fb;
  --bg2: #ffffff;
  --bg3: #eef4fb;
  --panel: #ffffff;
  --text: #172033;
  --muted: #4b5f78;
  --border: #d7e0ea;
  --code-bg: #f1f5f9;
  --code-ink: #172033;
  --accent: #0b5cad;
  --accent2: #0b5cad;
  --crit: #b42318;
  --high: #b54708;
  --med: #2f6b2f;
  --low: #0b5cad;
  --info: #475467;
  --ok: #2f6b2f;
}
html, body {
  background: var(--bg) !important;
  color: var(--text) !important;
}
body {
  max-width: none !important;
  margin: 0 !important;
  padding: 0 !important;
}
.combined-sidebar,
.intro-card,
.rapport-header,
.finding,
.request,
.response {
  background: var(--panel) !important;
  color: var(--text) !important;
  border-color: var(--border) !important;
}
.combined-sidebar {
  box-shadow: 1px 0 0 rgba(16, 24, 40, 0.04);
}
.combined-main {
  max-width: 1040px;
}
.sidebar-logo-icon {
  background: #0b5cad !important;
}
.sidebar-nav a,
.sidebar-logo-sub,
.sidebar-footer,
.combined-banner p,
.intro-card p,
.intro-card li,
.rapport-header p,
.rapport-header details li,
.report-meta,
.back-link,
.back-to-index,
table.summary th,
td[style*="var(--muted)"],
small[style*="var(--muted)"] {
  color: var(--muted) !important;
}
.sidebar-nav a:hover {
  background: var(--bg3) !important;
  color: var(--text) !important;
}
.sidebar-nav a .nav-num,
.intro-card h2,
.rapport-header details summary,
.back-to-index:hover,
.back-link:hover {
  color: var(--accent) !important;
}
.rapport-header {
  border-left-color: var(--accent) !important;
}
pre {
  background: var(--code-bg) !important;
  color: var(--code-ink) !important;
  border-color: var(--border) !important;
}
table.summary {
  background: var(--panel) !important;
  border-color: var(--border) !important;
}
table.summary th,
table.summary td {
  border-color: var(--border) !important;
}
.badge,
.bar {
  color: #ffffff !important;
  box-shadow: none !important;
}
.badge.critical,
.bar.critical,
.finding.critical::before { background: var(--crit) !important; }
.badge.high,
.bar.high,
.finding.high::before { background: var(--high) !important; }
.badge.medium,
.bar.medium,
.finding.medium::before { background: var(--med) !important; color: #ffffff !important; }
.badge.low,
.bar.low,
.finding.low::before { background: var(--low) !important; }
.badge.info,
.bar.info,
.finding.info::before { background: var(--info) !important; }
"""

    final_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APISCAN — Combined Security Report</title>
<style>{BASE_CSS}</style>
{''.join(unique_styles)}
<style>{READABLE_CSS}</style>
</head>
<body>
<a id="top"></a>
<div class="combined-layout">

  <!-- Sidebar -->
  <aside class="combined-sidebar">
    <div class="sidebar-brand">
      <div class="sidebar-logo">
        <div class="sidebar-logo-icon">A</div>
        <div>
          <div class="sidebar-logo-text">APISCAN</div>
          <div class="sidebar-logo-sub">Combined Security Report</div>
        </div>
      </div>
    </div>
    <nav class="sidebar-nav">
      <div class="sidebar-nav-label">OWASP API Top 10</div>
      {nav_html}
    </nav>
    <div class="sidebar-footer">
      Perry Mertens &copy; 2025<br>pamsniffer@gmail.com
    </div>
  </aside>

  <!-- Main -->
  <main class="combined-main">
    <div class="combined-banner">
      <h1>API Security Report Overview</h1>
      <p>APIScan &mdash; OWASP API Top 10 audit results</p>
    </div>

    {''.join(sections_html)}
  </main>

</div>
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


