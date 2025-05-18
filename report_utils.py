import json
from datetime import datetime
from typing import List, Dict, Optional, Any

class ReportGenerator:
    def __init__(self, 
                 issues: List[Dict[str, Any]], 
                 scanner: str = "Generic",
                 base_url: Optional[str] = None):
        self.issues = issues
        self.scanner = scanner
        self.base_url = base_url or "-"
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_markdown(self) -> str:
        if not self.issues:
            return f"No issues found by {self.scanner} scanner."

        grouped = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for issue in self.issues:
            sev = issue.get("severity", "Low")
            grouped.setdefault(sev, []).append(issue)

        severity_descriptions = {
            "Critical": "Multiple sensitive items exposed",
            "High": "Single sensitive item exposed",
            "Medium": "200 OK on unprotected endpoint",
            "Low": "Errors or minor issues"
        }

        severity_emojis = {
            "Critical": "🚨",
            "High": "🛑",
            "Medium": "⚠️",
            "Low": "ℹ️"
        }

        lines = [
            f"## API Security Audit Report by Perry Mertens 2025 (c)",
            f"Scanner: {self.scanner}",
            f"Scan Time: {self.timestamp}",
            f"Base URL: {self.base_url}",
            "\n### Summary",
            "| Severity | Count | Description |",
            "|----------------|-------|-------------------------------|"
        ]
        for level in ["Critical", "High", "Medium", "Low"]:
            emoji = severity_emojis.get(level, "")
            desc = severity_descriptions.get(level, "")
            lines.append(f"| {emoji} {level:<10} | {len(grouped[level])} | {desc} |")

        lines.append("\n### Detailed Findings")
        for level in ["Critical", "High", "Medium", "Low"]:
            if not grouped[level]:
                continue
            lines.append(f"\n{severity_emojis.get(level, '')} **{level} Risk Findings**")
            for i, issue in enumerate(grouped[level], 1):
                title = issue.get('flow') or issue.get('name') or issue.get('issue', 'Unnamed')
                lines.append(f"\n{i}. **{title}**")
                if issue.get('endpoint'):
                    lines.append(f"   - Endpoint: `{issue['endpoint']}`")
                if issue.get('status_code'):
                    lines.append(f"   - Status Code: {issue['status_code']}")
                if issue.get('response_time'):
                    lines.append(f"   - Response Time: {issue['response_time']}s")
                lines.append(f"   - Timestamp: {issue.get('timestamp', self.timestamp)}")
                if issue.get('description'):
                    lines.append(f"   - Description: {issue['description']}")
                if issue.get('payload'):
                    lines.append(f"   - Payload:\n     ```text\n     {issue['payload']}\n     ```")
                if issue.get('response') or issue.get('response_sample'):
                    val = issue.get('response') or issue.get('response_sample')
                    lines.append(f"   - Response:\n     ```text\n     {val}\n     ```")
                if issue.get('request'):
                    request_str = issue['request']
                    if isinstance(request_str, (dict, list)):
                        request_str = json.dumps(request_str, indent=2)
                    lines.append(f"   - Request Parameters:\n     ```json\n     {request_str}\n     ```")
                if issue.get('response_headers'):
                    lines.append(f"   - Response Headers:\n     ```json\n     {json.dumps(issue['response_headers'], indent=2)}\n     ```")
                if issue.get('response_body'):
                    lines.append(f"   - Response Body:\n     ```\n     {issue['response_body'][:2000]}\n     ```")

        lines.append("\n### Recommendations")
        lines.append("1. Validate all input properly.")
        lines.append("2. Use access controls and minimize sensitive exposure.")
        lines.append("3. Enable rate limiting where applicable.")
        lines.append("4. Disable unused endpoints and introspection features.")

        return "\n".join(lines)

    def generate_json(self) -> str:
        return json.dumps({
            "scanner": self.scanner,
            "timestamp": self.timestamp,
            "base_url": self.base_url,
            "findings": self.issues
        }, indent=2)

    def save(self, path: str, fmt: str = "markdown"):
        content = self.generate_markdown() if fmt == "markdown" else self.generate_json()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
