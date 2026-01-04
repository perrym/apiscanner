########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 3.2 1-4-2026                                 #
########################################################                                   
from __future__ import annotations
from datetime import datetime
import html
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Union, Iterable
import json, html, re
from bs4 import BeautifulSoup

                                                         
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

#================funtion _extract_status extract integer HTTP status from issue dict ##########
def _extract_status(issue: dict) -> int | None:
    for k in ("status_code", "res_status", "status", "http_status"):
        v = issue.get(k)
        if v in (None, "", "-"):
            continue
        try:
            return int(v)
        except (ValueError, TypeError):
            continue
    return None

#================funtion _iter_headers iterate headers from dict or list of tuples ##########
def _iter_headers(hdrs):
    if not hdrs:                       
        return
    if isinstance(hdrs, dict):
        yield from hdrs.items()
    else:                              
        yield from hdrs


class EnhancedReportGenerator:
    #================funtion __init__ initialize report generator and preprocess issues ##########
    def __init__(self, issues, scanner: str, base_url: str = "", **kwargs) -> None:
        self.issues = issues
        self.scanner = scanner
        self.base_url = base_url or "-"
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        drop_http0 = kwargs.get("drop_http0", True)
        _issues = issues or []
        if drop_http0:
            _issues = [i for i in _issues if (_extract_status(i) or -1) > 0]
        self.issues = _issues

    #================funtion _format_request_html render HTTP request panel in HTML ##########
    def _format_request_html(self, issue: Dict[str, Any]) -> str:
        method = issue.get("method", "GET").upper()
        url = issue.get("endpoint", "-")
                                                                                                  
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
                <details open class="headers">
                    <summary>Headers</summary>
                    <pre>{html.escape(headers) if headers else html.escape("No headers")}</pre>
                </details>
                <details open class="body">
                    <summary>Body</summary>
                    <pre>{html.escape(
                        body.decode("utf-8", errors="replace") if isinstance(body, bytes)
                        else (str(body) if str(body).strip() else "[empty]")
                    )}</pre>
                </details>
            </div>
            """


    #================funtion generate_markdown produce simple Markdown report ##########
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
       
    
    #================funtion _format_response_html render HTTP response panel in HTML ##########
    def _format_response_html(self, issue: Dict[str, Any]) -> str:
        status = issue.get("status_code", "-")
                                                                            
        hdr_pairs = _iter_headers(issue.get("response_headers"))
        headers = "\n".join(f"{k}: {v}" for k, v in hdr_pairs)
                                                                            
        resp_cookies = issue.get("response_cookies") or {}
        cookies_html = ""
        if resp_cookies:
            cookie_lines = "; ".join(f"{k}={v}" for k, v in resp_cookies.items())
            cookies_html = (
                '<details open class="cookies">'
                '<summary>Cookies</summary>'
                f"<pre>{html.escape(cookie_lines)}</pre>"
                "</details>"
            )
                                                                            
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
                '<details open class="body">'
                '<summary>Body</summary>'
                f"<pre>{html.escape(body_str)}</pre>"
                "</details>"
            )

                                                                            
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

    #================funtion generate_html build grouped HTML report with summary ##########
    def generate_html(self) -> str:
        if not self.issues:
            return self._generate_no_findings_html()

        issues = [i for i in self.issues if int(i.get('status_code') or 0) != 404]
        self.issues = issues

        grouped = {s: [] for s in ("Critical", "High", "Medium", "Low", "Info")}
        for issue in self.issues:
            sev = str(issue.get("severity", "Info")).capitalize()
            if sev not in grouped:
                sev = "Info"            
            grouped[sev].append(issue)

        findings_html = []
        for lvl in ("Critical", "High", "Medium", "Low", "Info"):
            if not grouped[lvl]:
                continue
                
            findings_html.append(self._generate_severity_section(lvl, grouped[lvl]))

       
                                                                          
        counts = {sev: len(grouped.get(sev, [])) for sev in ("Critical", "High", "Medium", "Low" , "Info")}
        summary_table = self._generate_summary_table(counts)
        return self._generate_full_html(summary_table, "".join(findings_html))



    #================funtion _generate_no_findings_html render HTML page for zero findings ##########
    def _generate_no_findings_html(self) -> str:
        parts = []
        parts.append("\n        <!DOCTYPE html>\n")
        parts.append("        <html>\n")
        parts.append(self._generate_html_head())
        parts.append("        <body>\n")
        parts.append("            " + self._generate_header() + "\n")
        parts.append("            <div class=\"no-findings\">\n")
        parts.append("                <h2>No Security Issues Found</h2>\n")
        parts.append("                <p>The scan completed successfully but no security issues were detected.</p>\n")
        parts.append("            </div>\n")
        parts.append("        </body>\n")
        parts.append("        </html>\n")
        return "".join(parts)


    #================funtion _generate_severity_section render severity group section ##########
    def _generate_severity_section(self, severity: str, issues: List[Dict[str, Any]]) -> str:
        sev_class = severity.lower()
        out = []
        out.append("\n        <div class=\"severity-section\">\n")
        out.append("            <h2 id=\"" + sev_class + "-section\"><span class=\"badge " + sev_class + "\">" + html.escape(severity) + "</span> Risk Findings (" + str(len(issues)) + ")</h2>\n")
        for idx, issue in enumerate(issues, 1):
            method = str(issue.get("method", "GET")).upper()
            url = issue.get("endpoint") or issue.get("url") or "-"
            status = issue.get("status_code", "-")
            ts = issue.get("timestamp", self.timestamp)
            desc = issue.get("description", "No description provided")
            out.append("            <div class=\"finding " + sev_class + "\">\n")
            out.append("                <h3 style=\"margin:0 0 8px 0;\">\n")
            out.append("                    <span class=\"badge " + sev_class + "\">" + html.escape(severity) + "</span>\n")
            out.append("                    <span style=\"margin-left:10px;\">Finding " + str(idx) + ": " + html.escape(method) + " " + html.escape(url) + "</span>\n")
            out.append("                    <small style=\"color:var(--muted);\"> (HTTP " + html.escape(str(status)) + ")</small>\n")
            out.append("                </h3>\n")
            out.append("                <div class=\"meta\" style=\"margin-bottom:10px;\">\n")
            out.append("                    <p style=\"margin:.2em 0;\"><strong>Description:</strong> " + html.escape(str(desc)) + "</p>\n")
            out.append("                    <p style=\"margin:.2em 0;\"><strong>Status Code:</strong> <span class=\"status-code\">" + html.escape(str(status)) + "</span></p>\n")
            out.append("                    <p style=\"margin:.2em 0;\"><strong>Timestamp:</strong> " + html.escape(str(ts)) + "</p>\n")
            out.append("                </div>\n")
            out.append("                <div class=\"request-response\" style=\"display:flex; gap:16px; margin-top:8px;\">\n")
            out.append(                     self._format_request_html(issue) + "\n")
            out.append(                     self._format_response_html(issue) + "\n")
            out.append("                </div>\n")
            out.append("                <div style=\"text-align:right; margin-top:10px;\">\n")
            out.append("                    <a class=\"back-link\" href=\"#report-nav\">- Back to index</a>\n")
            out.append("                </div>\n")
            out.append("            </div>\n")
        out.append("        </div>\n")
        return "".join(out)


    #================funtion old_generate_summary_table legacy summary table renderer ##########
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
        
                                                                         
                                 
                                                                        

    #================funtion _generate_summary_table build compact summary table ##########
    def _generate_summary_table(self, counts: dict[str, int]) -> str:
        severity_meta = [
            ("Critical", "critical", "Multiple sensitive items exposed"),
            ("High",     "high",     "Single sensitive item exposed"),
            ("Medium",   "medium",   "200 OK on unprotected endpoint"),
            ("Low",      "low",      "Errors or minor issues"),
            ("Info",     "info",     "Informational finding (e.g. 405 Method Not Allowed)"),
        ]
        total = max(1, sum(counts.get(k, 0) for k, _, _ in severity_meta))

        html_out = (
            '<h2 style="margin-top:20px;">Scan Summary</h2>'
            '<table class="summary"><thead><tr>'
            '<th>Severity</th><th style="text-align:right;">Count</th><th>Description</th>'
            '</tr></thead><tbody>'
        )

        for label, css, desc in severity_meta:
            cnt = int(counts.get(label, 0))
            html_out += (
                '<tr>'
                f'<td><a href="#{css}-section" style="text-decoration:none;"><span class="badge {css}">{label}</span></a></td>'
                f'<td style="text-align:right;">{cnt}</td>'
                f'<td style="color:var(--muted);">{desc}</td>'
                '</tr>'
            )

        html_out += '</tbody></table>'

        return html_out

    #================funtion _generate_html_head emit HTML <head> with styles ##########
    def _generate_html_head(self) -> str:
        parts = []
        parts.append("\n        <head>\n")
        parts.append("            <title>API Security Report - " + html.escape(str(self.scanner)) + " (c)2025</title>\n")
        parts.append("            <meta charset=\"UTF-8\">\n")
        parts.append("            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
        parts.append("            <style>\n")
        parts.append("                :root {\n")
        parts.append("                  --bg: #0f172a; --panel:#111827; --text:#e5e7eb; --muted:#9ca3af;\n")
        parts.append("                  --border:#1f2937; --code-bg:#0b1220; --code-ink:#e2e8f0;\n")
        parts.append("                  --crit:#dc2626; --high:#facc15; --med:#f97316; --low:#22c55e; --info:#d1d5db;\n")
        parts.append("                  --ok:#22c55e;\n")
        parts.append("                }\n")
        parts.append("                @media (prefers-color-scheme: light) {\n")
        parts.append("                  :root {\n")
        parts.append("                    --bg:#f8fafc; --panel:#ffffff; --text:#0f172a; --muted:#475569; --border:#e5e7eb;\n")
        parts.append("                    --code-bg:#f5f7fb; --code-ink:#0f172a;\n")
        parts.append("                  }\n")
        parts.append("                }\n")
        parts.append("\n")
        parts.append("                html, body { background: var(--bg); color: var(--text); }\n")
        parts.append("                body {\n")
        parts.append("                   font-family: 'Inter','Segoe UI',Tahoma,Arial,sans-serif;\n")
        parts.append("                   line-height:1.6; max-width:1200px; margin:0 auto; padding:24px;\n")
        parts.append("                }\n")
        parts.append("                h1, h2, h3, h4, h5 { color: var(--text); margin: .6em 0 .4em; }\n")
        parts.append("                h1 { border-bottom:1px solid var(--border); padding-bottom:10px; letter-spacing:.2px; }\n")
        parts.append("                a { color: inherit; }\n")
        parts.append("\n")
        parts.append("                .request, .response { flex:1; min-width:0; background:var(--panel); color:var(--text);\n")
        parts.append("                   border:1px solid var(--border); padding:12px; border-radius:10px; }\n")
        parts.append("                .headers, .body { margin-bottom:10px; }\n")
        parts.append("                pre { background: var(--code-bg); color: var(--code-ink); padding:10px; border-radius:8px;\n")
        parts.append("                     overflow-x:auto; white-space:pre-wrap; border:1px solid var(--border); margin:6px 0;\n")
        parts.append("                     font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }\n")
        parts.append("                .status-code { font-weight:800; color: var(--ok); }\n")
        parts.append("\n")
        parts.append("                /* badges */\n")
        parts.append("                .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; color:#fff; }\n")
        parts.append("                .badge.critical { background: var(--crit); }\n")
        parts.append("                .badge.high     { background: var(--high); }\n")
        parts.append("                .badge.medium   { background: var(--med); color:#1e293b; }\n")
        parts.append("                .badge.low      { background: var(--low); }\n")
        parts.append("                .badge.info     { background: var(--info); }\n")
        parts.append("\n")
        parts.append("                /* findings with colored rail */\n")
        parts.append("                .finding { position:relative; margin-bottom:20px; padding:16px; border-radius:12px;\n")
        parts.append("                           background:var(--panel); border:1px solid var(--border); }\n")
        parts.append("                .finding::before { content:\"\"; position:absolute; left:0; top:0; bottom:0; width:6px; border-top-left-radius:12px; border-bottom-left-radius:12px; }\n")
        parts.append("                .finding.critical::before { background: var(--crit); }\n")
        parts.append("                .finding.high::before     { background: var(--high); }\n")
        parts.append("                .finding.medium::before   { background: var(--med); }\n")
        parts.append("                .finding.low::before      { background: var(--low); }\n")
        parts.append("                .finding.info::before     { background: var(--info); }\n")
        parts.append("\n")
        parts.append("                /* summary table + bars */\n")
        parts.append("                table.summary { border-collapse:collapse; width:100%; border:1px solid var(--border); border-radius:12px; overflow:hidden; }\n")
        parts.append("                table.summary th, table.summary td { padding:10px 12px; border-bottom:1px solid var(--border); }\n")
        parts.append("                table.summary th { text-align:left; color:var(--muted); font-weight:600; }\n")
        parts.append("                .bars { margin-top:12px; }\n")
        parts.append("                .bar { color:#fff; padding:6px 10px; margin:6px 0; border-radius:8px; font-weight:700; box-shadow: inset 0 0 4px rgba(0,0,0,.3); letter-spacing:.3px; }\n")
        parts.append("                .bar.critical { background: var(--crit); }\n")
        parts.append("                .bar.high     { background: var(--high); }\n")
        parts.append("                .bar.medium   { background: var(--med); color:#1e293b; font-weight:800; }\n")
        parts.append("                .bar.low      { background: var(--low); }\n")
        parts.append("                .bar.info     { background: var(--info); }\n")
        parts.append("\n")
        parts.append("                .report-meta { color:var(--muted); }\n")
        parts.append("                .back-link { color:var(--muted); text-decoration:none; font-size:13px; }\n")
        parts.append("                @media (max-width:768px) { .request-response { flex-direction:column; } }\n")
        parts.append("            </style>\n")
        parts.append("        </head>\n")
        return "".join(parts)

    #================funtion _generate_header emit report header block ##########
    def _generate_header(self) -> str:
        parts = []
        parts.append("\n        <header style=\"margin-bottom: 30px;\">\n")
        parts.append("            <h1 style=\"margin-bottom: 5px;\">API Security Report - By Perry Mertens (c)2025</h1>\n")
        parts.append("            <div class=\"report-meta\">\n")
        parts.append("                <p><strong>Scanner:</strong> " + html.escape(str(self.scanner)) + "</p>\n")
        parts.append("                <p><strong>Base URL:</strong> " + html.escape(str(self.base_url)) + "</p>\n")
        parts.append("                <p><strong>Timestamp:</strong> " + html.escape(str(self.timestamp)) + "</p>\n")
        parts.append("            </div>\n")
        parts.append("        </header>\n")
        return "".join(parts)


    #================funtion _generate_full_html assemble full HTML document ##########
    def _generate_full_html(self, summary: str, findings: str) -> str:
        parts = []
        parts.append("\n        <!DOCTYPE html>\n")
        parts.append("        <html>\n")
        parts.append(self._generate_html_head())
        parts.append("        <body>\n")
        parts.append("            <a id=\"report-nav\"></a>   <!-- - BACK-TO-TOP ANKER -->\n")
        parts.append("            " + self._generate_header() + "\n")
        parts.append("            " + summary + "\n")
        parts.append("            <div class=\"findings\">\n")
        parts.append("                <h2 style=\"border-bottom:1px solid var(--border); padding-bottom: 5px;\">Detailed Findings</h2>\n")
        parts.append("                " + findings + "\n")
        parts.append("            </div>\n")
        parts.append("        </body>\n")
        parts.append("        </html>\n")
        return "".join(parts)


    #================funtion save write HTML report to disk ##########
    def save(self, path: Union[str, Path]):
        html_content = self.generate_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

#================funtion generate_dashboard_report generate HTML dashboard from template_scan_en.html ============
def generate_dashboard_report(db_path: Union[str, Path],
                              out_path: Union[str, Path],
                              template_path: Optional[Union[str, Path]] = None,
                              run_id: Optional[str] = None,
                              open_in_browser: bool = False) -> Path:
    """
    Generate the interactive findings dashboard (template-based) as HTML.

    This uses the same JSON-injection approach as build_review.py and is meant for:
    - Opening in a browser
    - Printing / "Save as PDF" via the browser print dialog

    Args:
        db_path: Path to the APISCAN sqlite database.
        out_path: Output HTML path.
        template_path: Optional path to template_scan_en.html.
        run_id: Optional run_id filter.
        open_in_browser: If True, opens the resulting HTML in the default browser.

    Returns:
        Path to the generated HTML file.
    """
    from pathlib import Path as _Path
    import webbrowser as _webbrowser

    db_path_p = _Path(db_path)
    out_path_p = _Path(out_path)
    out_path_p.parent.mkdir(parents=True, exist_ok=True)
    from build_review import build_review as _build_review
    out_file = _build_review(db_path_p, out_path_p, template=_Path(template_path) if template_path else None, run_id=run_id)

    if open_in_browser:
        try:
            _webbrowser.open(out_file.resolve().as_uri())
        except Exception:
            pass
    try:
        combined_path = out_file.parent / 'combined_report.html'
        if combined_path.resolve() != out_file.resolve():
            combined_path.write_text(out_file.read_text(encoding='utf-8', errors='ignore'), encoding='utf-8')
    except Exception:
        pass

    return out_file

ReportGenerator = EnhancedReportGenerator
HTMLReportGenerator = EnhancedReportGenerator
#================funtion generate_dashboard_report generate HTML dashboard from template_scan_en.html ============
def generate_dashboard_report(db_path: Union[str, Path],
                              out_path: Union[str, Path],
                              template_path: Optional[Union[str, Path]] = None,
                              run_id: Optional[str] = None,
                              open_in_browser: bool = False) -> Path:
    """
    Generate the interactive findings dashboard (template-based) as HTML.

    This uses the same JSON-injection approach as build_review.py and is meant for:
    - Opening in a browser
    - Printing / "Save as PDF" via the browser print dialog

    Args:
        db_path: Path to the APISCAN sqlite database.
        out_path: Output HTML path.
        template_path: Optional path to template_scan_en.html.
        run_id: Optional run_id filter.
        open_in_browser: If True, opens the resulting HTML in the default browser.

    Returns:
        Path to the generated HTML file.
    """
    from pathlib import Path as _Path
    import webbrowser as _webbrowser

    db_path_p = _Path(db_path)
    out_path_p = _Path(out_path)
    out_path_p.parent.mkdir(parents=True, exist_ok=True)
    from build_review import build_review as _build_review

    out_file = _build_review(db_path_p, out_path_p, template=_Path(template_path) if template_path else None, run_id=run_id)

    if open_in_browser:
        try:
            _webbrowser.open(out_file.resolve().as_uri())
        except Exception:
            pass

    try:
        combined_path = out_file.parent / 'combined_report.html'
        if combined_path.resolve() != out_file.resolve():
            combined_path.write_text(out_file.read_text(encoding='utf-8', errors='ignore'), encoding='utf-8')
    except Exception:
        pass

    return out_file

ReportGenerator = EnhancedReportGenerator

#================funtion combine_html_reports merge multiple HTML reports into one ##########
def combine_html_reports(output_dir: Path):
    from bs4 import BeautifulSoup
    import html

    
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

   
    nav_links = []
    for i, (report_id, title, _) in enumerate(reports, 1):
        nav_links.append(f'<li><a href="#section-{i}">{html.escape(title)}</a></li>')
    
    combined_html += f"""
    <script>
        document.getElementById('report-nav').innerHTML = `{"".join(nav_links)}`;
    </script>
    """

    
    for i, (report_id, title, soup) in enumerate(reports, 1):
        body = soup.body
        if not body:
            continue
            
        combined_html += f"""
        <section id="section-{i}" class="report-section">
            <h2>{html.escape(title)}</h2>
        """
        
       
        for element in body.find_all(['div', 'section'], recursive=False):
            if 'findings' in element.get('class', []) or\
               'severity-section' in element.get('class', []) or\
               'summary' in element.get('class', []):
                combined_html += element.decode_contents()
        
        combined_html += """
            <div style="text-align: right; margin-top: 20px;">
                <a href="#report-nav" style="color: #666; text-decoration: none;">- Back to top</a>
            </div>
        </section>
        """
   
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
    
                                                              
    combined_path = output_dir / "combined_report.html"
    try:
        combined_path.write_text(combined_html, encoding='utf-8')
        print(f"Successfully created comprehensive combined report at: {combined_path}")
    except Exception as e:
        print(f"Failed to save combined report: {str(e)}")