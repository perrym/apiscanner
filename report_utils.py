###################################
# APISCAN - API Security Scanner  #
# Licensed under the MIT License  #
# Author: Perry Mertens, 2025     #
###################################
from __future__ import annotations
from datetime import datetime
import html
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Union, Iterable
import json, html, re
from bs4 import BeautifulSoup

# ---------------- Constants from legacy ----------------
RISK_INFO = {
    "BOLA": {"title": "API1:2023 - Broken Object Level Authorization"},
    "BrokenAuth": {"title": "API2:2023 - Broken Authentication"},
    "Property": {"title": "API3:2023 - Property-Level Authorization"},
    "Resource": {"title": "API4:2023 - Resource Consumption"},
    "AdminAccess": {"title": "API5:2023 - Admin Access Control"},
    "BusinessFlows": {"title": "API6:2023 - Sensitive Business Flows"},
    "SSRF": {"title": "API7:2023 - Server Side Request Forgery"},
    "Misconfig": {"title": "API8:2023 - Security Misconfiguration"},
    "Inventory": {"title": "API9:2023 - Improper Inventory Management"},
    "UnsafeConsumption": {"title": "API10:2023 - Unsafe 3rd-Party API Consumption"},
}

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
    "UnsafeConsumption": "safe_consumption",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# report_utils.py  (boven in het bestand, na de imports)
def _iter_headers(hdrs):
    """
    Genereer (key, value) paren uit zowel dicts als list-of-tuples.
    """
    if not hdrs:                       # None of leeg - niets yielden
        return
    if isinstance(hdrs, dict):
        yield from hdrs.items()
    else:                              # aannemen: Iterable[Tuple[str, str]]
        yield from hdrs


class EnhancedReportGenerator:
    def __init__(self, issues, scanner: str, base_url: str = "", **kwargs) -> None:
        self.issues = issues
        self.scanner = scanner
        self.base_url = base_url or "-"
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _format_request_html(self, issue: Dict[str, Any]) -> str:
        method = issue.get("method", "GET").upper()
        url = issue.get("endpoint", "-")
        #headers = "\n".join(f"{k}: {v}" for k, v in (issue.get("request_headers") or {}).items())
        req_hdrs = issue.get("request_headers")
        headers = "\n".join(f"{k}: {v}" for k, v in _iter_headers(req_hdrs))
        body = issue.get("payload") or issue.get("request") or issue.get("request_body") or ""
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="replace")
        
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2)
        elif isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
                json_obj = json.loads(body)
                body = json.dumps(json_obj, indent=2)
            except Exception:
                body = body.decode("utf-8", errors="replace")
        elif isinstance(body, str):
            try:
                json_obj = json.loads(body)
                body = json.dumps(json_obj, indent=2)
            except Exception:
                pass

            
        return f"""
            <div class="request">
                <h4>{html.escape(method)} {html.escape(url)}</h4>
                <div class="headers">
                    <h5>Headers</h5>
                    <pre>{html.escape(headers) if headers else html.escape("No headers")}</pre>
                </div>
                <div class="body">
                    <h5>Body</h5>
                    <pre>{html.escape(
                        body.decode("utf-8", errors="replace") if isinstance(body, bytes)
                        else (str(body) if str(body).strip() else "[empty]")
                    )}</pre>
                </div>
            </div>
            """


    def generate_markdown(self) -> str:
        if not self.issues:
            return "# No vulnerabilities found\n\n"
        
        markdown = [f"# {self.scanner} Report\n"]
        markdown.append(f"- Base URL: {self.base_url}")
        markdown.append(f"- Timestamp: {self.timestamp}")
        markdown.append(f"- Total issues: {len(self.issues)}\n")
        
        for issue in self.issues:
            markdown.append(f"## {issue.get('description', 'Finding')}")
            markdown.append(f"- **Method**: {issue.get('method')}")
            markdown.append(f"- **URL**: {issue.get('url')}")
            markdown.append(f"- **Status Code**: {issue.get('status_code')}")
            markdown.append(f"- **Severity**: {issue.get('severity')}\n")
        
        return "\n".join(markdown)
       
    # Vervang de _format_response_html functie door deze versie
    def _format_response_html(self, issue: Dict[str, Any]) -> str:
        status = issue.get("status_code", "-")
        # -- headers -------------------------------------------------------
        hdr_pairs = _iter_headers(issue.get("response_headers"))
        headers = "\n".join(f"{k}: {v}" for k, v in hdr_pairs)
        # -- cookies -------------------------------------------------------
        resp_cookies = issue.get("response_cookies") or {}
        cookies_html = ""
        if resp_cookies:
            cookie_lines = "; ".join(f"{k}={v}" for k, v in resp_cookies.items())
            cookies_html = (
                '<div class="cookies">'
                '<h5>Cookies</h5>'
                f"<pre>{html.escape(cookie_lines)}</pre>"
                "</div>"
            )
        # -- body / error --------------------------------------------------
        body = issue.get("response_body")
        error = issue.get("error")
        error_html = (
            f'<div class="error"><h5>Error</h5><pre>{html.escape(str(error))}</pre></div>'
            if error
            else ""
        )
        body_html = ""
        if body:
            body_str = (
                body.decode("utf-8", errors="replace")
                if isinstance(body, (bytes, bytearray))
                else str(body)
            )
            body_html = (
                '<div class="body">'
                "<h5>Body</h5>"
                f"<pre>{html.escape(body_str)}</pre>"
                "</div>"
            )

        # -- eind-HTML -----------------------------------------------------
        return (
            '<div class="response">'
            f"<h4>HTTP {status}</h4>"
            '<div class="headers">'
            "<h5>Headers</h5>"
            f"<pre>{html.escape(headers) if headers else 'No headers'}</pre>"
            "</div>"
            f"{cookies_html}"
            f"{error_html}"
            f"{body_html}"
            "</div>"
        )

    def generate_html(self) -> str:
        if not self.issues:
            return self._generate_no_findings_html()

        grouped = {s: [] for s in ("Critical", "High", "Medium", "Low", "Info")}
        for issue in self.issues:
            sev = str(issue.get("severity", "Info")).capitalize()
            if sev not in grouped:
                sev = "Info"  # fallback
            grouped[sev].append(issue)

        findings_html = []
        for lvl in ("Critical", "High", "Medium", "Low", "Info"):
            if not grouped[lvl]:
                continue
                
            findings_html.append(self._generate_severity_section(lvl, grouped[lvl]))

        #summary_table = self._generate_summary_table(grouped)
        #return self._generate_full_html(summary_table, "".join(findings_html))
        # -- nieuw: maak echt een count-dict -----------------------------
        counts = {sev: len(grouped.get(sev, [])) for sev in ("Critical", "High", "Medium", "Low" , "Info")}
        summary_table = self._generate_summary_table(counts)
        return self._generate_full_html(summary_table, "".join(findings_html))



    def _generate_no_findings_html(self) -> str:
        return f"""
        <!DOCTYPE html>
        <html>
        {self._generate_html_head()}
        <body>
            {self._generate_header()}
            <div class="no-findings">
                <h2>No Security Issues Found</h2>
                <p>The scan completed successfully but no security issues were detected.</p>
            </div>
        </body>
        </html>
        """

    def _generate_severity_section(self, severity: str, issues: List[Dict[str, Any]]) -> str:
        severity_styles = {
            "Critical": "border-left: 4px solid #d32f2f; background-color: #ffebee;",
             "High":     "border-left: 4px solid #ffa000; background-color: #fff8e1;",
            "Medium":   "border-left: 4px solid #ffc107; background-color: #fffde7;",
            "Low":      "border-left: 4px solid #2196f3; background-color: #e3f2fd;",
            "Info":     "border-left: 4px solid #777; background-color: #f0f0f0;",
        }

        issues_html = []
        for idx, issue in enumerate(issues, 1):
            method = issue.get("method", "GET").upper()
            url = issue.get("endpoint", "-")
            
            issues_html.append(f"""
            <div class="finding" style="{severity_styles[severity]} margin-bottom: 20px; padding: 15px; border-radius: 4px;">
                <h3 style="margin-top: 0;">
                    Finding {idx}: {method} {url}
                    <small>(HTTP {issue.get('status_code', '-')})</small>
                </h3>
                <div class="meta" style="margin-bottom: 15px;">
                    <p><strong>Description:</strong> {issue.get('description', 'No description provided')}</p>
                    <p><strong>Status Code:</strong> <span class="status-code">{issue.get('status_code', '-')}</span></p>
                    <p><strong>Timestamp:</strong> {issue.get('timestamp', self.timestamp)}</p>
                </div>
                <div class="request-response" style="display: flex; gap: 20px; margin-top: 15px;">
                    {self._format_request_html(issue)}
                    {self._format_response_html(issue)}
                </div>
                <!-- NEW: back-to-index link -->
                <div style="text-align: right; margin-top: 10px;">
                    <a href="#report-nav" style="color:#555;text-decoration:none;">- Back to index</a>
                </div>
            </div>
            """)

        return f"""
        <div class="severity-section">
             <h2 id="{severity.lower()}-section"
                style="color: #333; margin-top: 30px; padding-bottom: 5px; border-bottom: 1px solid #eee;">
                {severity} Risk Findings ({len(issues)})
             </h2>
            {"".join(issues_html)}
        </div>
        """

    def old_generate_summary_table(self, grouped: Dict[str, List[Dict[str, Any]]]) -> str:
        return f"""
        <div class="summary">
            <h2>Scan Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="color: #d32f2f;">Critical</td>
                        <td>{len(grouped['Critical'])}</td>
                        <td>Multiple sensitive items exposed</td>
                    </tr>
                    <tr>
                        <td style="color: #ffa000;">High</td>
                        <td>{len(grouped['High'])}</td>
                        <td>Single sensitive item exposed</td>
                    </tr>
                    <tr>
                        <td style="color: #ffc107;">Medium</td>
                        <td>{len(grouped['Medium'])}</td>
                        <td>200 OK on unprotected endpoint</td>
                    </tr>
                    <tr>
                        <td style="color: #2196f3;">Low</td>
                        <td>{len(grouped['Low'])}</td>
                        <td>Errors or minor issues</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """
        
     # ------------------------------------------------------------------
    #   S U M M A R Y   T A B L E
    # ------------------------------------------------------------------
    def _generate_summary_table(self, counts: dict[str, int]) -> str:
        """
        Bouwt de -Scan Summary--tabel.

        Parameters
        ----------
        counts : dict
            {"Critical": 3, "High": 2, "Medium": 15, "Low": 0}

        Returns
        -------
        html : str
        """
        row_tpl = (
            '<tr>'
            '  <td style="padding:6px 12px;color:{color};">'
            '    <a href="#{anchor}-section" style="color:inherit;text-decoration:none;font-weight:600;">'
            '      {sev}'
            '    </a>'
            '  </td>'
            '  <td style="padding:6px 12px;text-align:right;">{cnt}</td>'
            '  <td style="padding:6px 12px;">{desc}</td>'
            '</tr>'
        )

        severity_meta = [
            ("Critical", "#d32f2f", "Multiple sensitive items exposed"),
            ("High",     "#ffa000", "Single sensitive item exposed"),
            ("Medium",   "#ffc107", "200 OK on unprotected endpoint"),
            ("Low",      "#2196f3", "Errors or minor issues"),
            ("Info",     "#777",    "Informational finding (e.g. 405 Method Not Allowed)"),
        ]

        html = (
            '<h2 style="margin-top:30px;">Scan Summary</h2>'
            '<table style="border-collapse:collapse;font-family:Arial, sans-serif;font-size:14px;">'
            '<thead><tr>'
            '  <th style="text-align:left;padding:6px 12px;">Severity</th>'
            '  <th style="text-align:right;padding:6px 12px;">Count</th>'
            '  <th style="text-align:left;padding:6px 12px;">Description</th>'
            '</tr></thead><tbody>'
        )

        for sev, color, desc in severity_meta:
            html += row_tpl.format(
                color=color,
                anchor=sev.lower(),
                sev=sev,
                cnt=counts.get(sev, 0),
                desc=desc,
            )

        html += "</tbody></table>"
        return html

    
    def _generate_html_head(self) -> str:
        return f"""
        <head>
            <title>API Security Report - {self.scanner} By Perry Mertens pamsniffer@gmail.com (c)2025</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1, h2, h3, h4, h5 {{
                    color: #2c3e50;
                }}
                h1 {{
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                }}
                pre {{
                    background-color: #f5f5f5;
                    padding: 10px;
                    border-radius: 4px;
                    overflow-x: auto;
                    font-family: Consolas, Monaco, 'Andale Mono', monospace;
                    white-space: pre-wrap;
                    margin: 5px 0;
                }}
                .request, .response {{
                    flex: 1;
                    min-width: 0;
                    background: white;
                    padding: 10px;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                .headers, .body {{
                    margin-bottom: 10px;
                }}
                .status-code {{
                    font-weight: bold;
                    color: #388e3c;
                }}
                .no-findings {{
                    background-color: #e8f5e9;
                    padding: 20px;
                    border-radius: 4px;
                    text-align: center;
                }}
                @media (max-width: 768px) {{
                    .request-response {{
                        flex-direction: column;
                    }}
                }}
            </style>
        </head>
        """
   
    def _generate_header(self) -> str:
        return f"""
        <header style="margin-bottom: 30px;">
            <h1 style="margin-bottom: 5px;">API Security Report - By Perry Mertens pamsniffer@gmail.com (c)2025</h1>
            <div class="report-meta" style="color: #666;">
                <p><strong>Scanner:</strong> {self.scanner}</p>
                <p><strong>Base URL:</strong> {self.base_url}</p>
                <p><strong>Timestamp:</strong> {self.timestamp}</p>
            </div>
        </header>
        """

    def _generate_full_html(self, summary: str, findings: str) -> str:
        return f"""
        <!DOCTYPE html>
        <html>
        {self._generate_html_head()}
        <body>
            <a id="report-nav"></a>   <!-- - BACK-TO-TOP ANKER -->
            {self._generate_header()}
            {summary}
            <div class="findings">
                <h2 style="color: #333; border-bottom: 1px solid #eee; padding-bottom: 5px;">Detailed Findings</h2>
                {findings}
            </div>
        </body>
        </html>
        """

    def save(self, path: Union[str, Path]):
        html_content = self.generate_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

ReportGenerator = EnhancedReportGenerator
HTMLReportGenerator = EnhancedReportGenerator

def combine_html_reports(output_dir: Path):
    """Combine reports while preserving all findings and original structure"""
    from bs4 import BeautifulSoup
    import html

    # Base template with improved styling
    combined_html = f"""<!DOCTYPE html>
    <html>
    <head>
        <title>Combined API Security Report - By Perry Mertens pamsniffer@gmail.com (c)2025</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            .nav-menu {{
                background: #2c3e50;
                padding: 15px;
                margin: -20px -20px 20px -20px;
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            .nav-links {{
                display: flex;
                gap: 15px;
                list-style: none;
                padding: 0;
                margin: 0;
            }}
            .nav-links a {{
                color: white;
                text-decoration: none;
                font-weight: 500;
            }}
            .report-section {{
                margin-bottom: 40px;
                padding-bottom: 20px;
                border-bottom: 1px solid #eee;
            }}
            .finding {{
                page-break-inside: avoid;
                margin-bottom: 30px;
            }}
            /* Preserve original report styles */
            {EnhancedReportGenerator()._generate_html_head().split('<style>')[1].split('</style>')[0]}
        </style>
    </head>
    <body>
        <div class="nav-menu">
            <h1 style="color:white;margin:0 0 10px 0;">Combined API Security Report - By Perry Mertens pamsniffer@gmail.com (c)2025</h1>
            <ul class="nav-links" id="report-nav">
                <!-- Navigation links will be added here -->
            </ul>
        </div>
        <p><strong>Generated:</strong> {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
    """

    # Process each report file
    html_files = sorted(output_dir.glob("api_*_report.html"))
    reports = []
    
    for file in html_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
                if not content.strip():
                    continue
                    
                soup = BeautifulSoup(content, 'html.parser')
                title = soup.title.string if soup.title else file.stem.replace('_', ' ').title()
                report_id = file.stem.replace("api_", "").replace("_report", "")
                reports.append((report_id, title, soup))
        except Exception as e:
            print(f"Error processing {file.name}: {str(e)}")
            continue

    # Add navigation links
    nav_links = []
    for i, (report_id, title, _) in enumerate(reports, 1):
        nav_links.append(f'<li><a href="#section-{i}">{html.escape(title)}</a></li>')
    
    combined_html += f"""
    <script>
        document.getElementById('report-nav').innerHTML = `{"".join(nav_links)}`;
    </script>
    """

    # Add report sections with all findings
    for i, (report_id, title, soup) in enumerate(reports, 1):
        body = soup.body
        if not body:
            continue
            
        combined_html += f"""
        <section id="section-{i}" class="report-section">
            <h2>{html.escape(title)}</h2>
        """
        
        # Add all relevant content sections
        for element in body.find_all(['div', 'section'], recursive=False):
            if 'findings' in element.get('class', []) or \
               'severity-section' in element.get('class', []) or \
               'summary' in element.get('class', []):
                combined_html += element.decode_contents()
        
        combined_html += """
            <div style="text-align: right; margin-top: 20px;">
                <a href="#report-nav" style="color: #666; text-decoration: none;">- Back to top</a>
            </div>
        </section>
        """

    # Add smooth scrolling and finalize
    combined_html += """
    <script>
        document.querySelectorAll('.nav-links a').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
    </body>
    </html>
    """
    
    # Save the combined report
    combined_path = output_dir / "combined_report.html"
    try:
        combined_path.write_text(combined_html, encoding='utf-8')
        print(f"Successfully created comprehensive combined report at: {combined_path}")
    except Exception as e:
        print(f"Failed to save combined report: {str(e)}")