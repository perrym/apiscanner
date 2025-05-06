# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
# broken_auth_audit.py
import requests
import json
import re
from datetime import datetime, timedelta

class AuthAuditor:
    """Test Broken Authentication according to OWASP API2:2023"""
    
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.auth_issues = []
    
    def test_authentication_mechanisms(self, auth_endpoints):
        """Test all authentication mechanisms"""
        # Discover defaults als geen endpoints doorgegeven
        if not auth_endpoints:
            auth_endpoints = self._discover_auth_endpoints()
        for endpoint in auth_endpoints:
            self._test_auth_endpoint(endpoint)
        return self.auth_issues
    
    def _discover_auth_endpoints(self):
        """Automatic detection of auth endpoints"""
        common_auth_endpoints = [
            '/auth/login', '/oauth/token',
            '/api/login', '/user/authenticate'
        ]
        discovered = []
        for ep in common_auth_endpoints:
            url = f"{self.base_url}{ep}"
            try:
                resp = self.session.options(url, timeout=3)
                if resp.status_code < 500:
                    discovered.append({'url': url, 'methods': resp.headers.get('Allow', 'POST')})
            except Exception:
                continue
        return discovered or [
            {'url': f"{self.base_url}/auth/login", 'methods': 'POST'},
            {'url': f"{self.base_url}/oauth/token", 'methods': 'POST'}
        ]
    
    def _test_auth_endpoint(self, endpoint):
        """Execute all auth tests"""
        tests = [
            self._test_weak_credentials,
            self._test_token_security,
            self._test_rate_limiting,
            self._test_jwt_issues
        ]
        for test in tests:
            try:
                test(endpoint)
            except Exception as e:
                self._log_issue(endpoint['url'], f"Test error: {e}", severity="Medium")
    
    def _test_weak_credentials(self, endpoint):
        """Test for common weak credentials"""
        weak_creds = [('admin','admin'),('user','password'),('test','test123'),('','')]
        for u, p in weak_creds:
            data = {'username': u, 'password': p}
            resp = self.session.post(endpoint['url'], json=data, timeout=3)
            if resp.status_code == 200:
                self._log_issue(
                    endpoint['url'],
                    f"Weak credentials accepted: {u}/{p}",
                    severity="High",
                    request_data=data,
                    response=resp.text[:200]
                )
    
    def _test_token_security(self, endpoint):
        """Test JWT/OAuth token security"""
        valid_resp = self.session.post(endpoint['url'], json={'username':'test','password':'validpass'}, timeout=3)
        if valid_resp.status_code != 200:
            return
        token = valid_resp.json().get('access_token') or valid_resp.json().get('token')
        if not token:
            return
        # Test: lange levensduur
        long_resp = self.session.post(
            endpoint['url'],
            json={'username':'test','password':'validpass','expires_in':999999},
            timeout=3
        )
        if long_resp.status_code == 200:
            self._log_issue(
                endpoint['url'],
                "Tokens can be given extremely long lifetimes",
                severity="Medium",
                request_data={'expires_in':999999}
            )
        # Test: revoke/logout
        logout_url = endpoint['url'].replace('login','logout')
        revoke_resp = self.session.post(logout_url, headers={'Authorization': f"Bearer {token}"}, timeout=3)
        if revoke_resp.status_code >= 400:
            self._log_issue(
                endpoint['url'],
                "Tokens cannot be revoked",
                severity="Medium"
            )
    
    def _test_rate_limiting(self, endpoint):
        """Test brute-force protection (rate limiting)"""
        for i in range(10):
            resp = self.session.post(
                endpoint['url'],
                json={'username':f"attacker{i}", 'password':'wrong'},
                timeout=3
            )
            if resp.status_code == 429:
                return
        self._log_issue(
            endpoint['url'],
            "No rate limiting on auth endpoints",
            severity="High"
        )
    
    def _test_jwt_issues(self, endpoint):
        """Test common JWT issues"""
        resp = self.session.post(endpoint['url'], json={'username':'test','password':'validpass'}, timeout=3)
        if resp.status_code != 200:
            return
        token = resp.json().get('access_token')
        if not token:
            return
        # Test signature verificatie
        modified = token[:-5] + 'aaaaa'
        check_resp = self.session.get(
            f"{self.base_url}/api/protected",
            headers={'Authorization': f"Bearer {modified}"},
            timeout=3
        )
        if check_resp.status_code == 200:
            self._log_issue(
                endpoint['url'],
                "JWT signature is not verified",
                severity="Critical"
            )
    
    def _log_issue(self, endpoint, description, severity, request_data=None, response=None):
        """Add a security issue to the list"""
        self.auth_issues.append({
            'endpoint': endpoint,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'request': request_data,
            'response': response
        })
    
    def generate_report(self, output_format='markdown'):
        """Generate a security report in Markdown or JSON."""
        if not self.auth_issues:
            return "No broken-authentication issues found. 🎉"
        if output_format == 'json':
            return json.dumps(self.auth_issues, indent=2)
        return self._generate_markdown_report()
    
    def _generate_markdown_report(self):
        """Generate a clean Markdown report"""
        report = [
            "# API2: Broken Authentication Audit",
            f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Base URL**: `{self.base_url}`",
            "",
            "**Legend**: 🟢 No issues | 🔴 Issue detected",
            "",
            "## Summary",
            f"- 🛑 **Total issues**: {len(self.auth_issues)}",
            f"- 🔴 **Critical**: {len([i for i in self.auth_issues if i['severity']=='Critical'])}",
            f"- 🔶 **High**: {len([i for i in self.auth_issues if i['severity']=='High'])}",
            f"- ⚠️ **Medium**: {len([i for i in self.auth_issues if i['severity']=='Medium'])}",
            f"- ✅ **Low**: {len([i for i in self.auth_issues if i['severity']=='Low'])}",
            "",
            "## Detailed Findings by Severity",]
        by_sev = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for issue in self.auth_issues:
            by_sev[issue['severity']].append(issue)
        for severity, issues in by_sev.items():
            if not issues:
                continue
            report.append(f"\n### {severity} Risks")
            for issue in issues:
                report.append(f"#### `{issue['endpoint']}`")
                report.append(f"- 🔴 **Description**: {issue['description']}")
                report.append(f"- ⏱️ **Timestamp**: {issue['timestamp']}")
                if issue.get('request'):
                    report.append("- 📥 **Request payload**:")
                    report.append(f"  ```json\n{json.dumps(issue['request'], indent=2)}\n  ```")
                if issue.get('response'):
                    report.append("- 📤 **Response snippet**:")
                    report.append(f"  ```\n{issue['response']}\n  ```")
        return "\n".join(report)

# Einde broken_auth_audit.py
