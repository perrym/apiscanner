---
title: APISCAN v1.0  AI-Aware OWASP API Security Scanner by Perry Mertens
description: Free and open-source API security scanner built in Python with AI support, multi-auth, and rich reporting.
---
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">
[![View on GitHub](https://img.shields.io/badge/GitHub-View%20Repository-blue?logo=github)](https://github.com/perrym/apiscanner)

# APISCAN v1.0  OWASP API Security Scanner

APISCAN is a free and extensible API security auditing framework built in Python, that targets the **OWASP API Security Top 10 (2023)**.  
It supports **OpenAPI/Swagger specs**, performs **active scans** on endpoints, and produces clean HTML and Markdown reports.

---

## What's New in v1.0

- Expanded authentication (`--flow none|token|client|basic|ntlm|auth`, OAuth2, NTLM, mTLS).
- Smart Swagger integration: safer `--dummy` mode and `--export_vars` (YAML/JSON).
- Richer reports: per risk HTML, combined report, logs per run.
- Faster: threadpool concurrency with `--threads` (max 20).
- AIassisted module (API11) with `AI-api11_scanresults.json` output.
- Connectivity guard: preflight checks and clearer TLS/auth error exits.

---

## Supported Risks

| OWASP API Risk | APISCAN Coverage | Module |
|:--|:--|:--|
| API1: Broken Object Level Authorization | Access control bypass | `bola_audit.py` |
| API2: Broken Authentication | Weak login protections, token misuse | `broken_auth_audit.py` |
| API3: Property Level Authorization | Unauthorized property manipulation | `broken_object_property_audit.py` |
| API4: Unrestricted Resource Consumption | Abuse via large/batch requests | `resource_consumption_audit.py` |
| API5: Function Level Authorization | Role misuse checks | `authorization_audit.py` |
| API6: Sensitive Business Logic | Business logic flaws | `business_flow_audit.py` |
| API7: SSRF | External call risks | `ssrf_audit.py` |
| API8: Security Misconfiguration | Headers/config issues | `misconfiguration_audit.py` |
| API9: Improper Inventory Management | Exposed docs/endpoints | `inventory_audit.py` |
| API10: Unsafe Consumption of 3rdParty APIs | Injection via external APIs | `safe_consumption_audit.py` |
| API11: AI-assisted Security Analysis | AI-based review | `ai_client.py` |

---

## Example Usage

```bash
# Scan with token auth
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --flow token --token <BEARER>

# Dummy mode
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --flow token --token <BEARER> --dummy

# Export variable template
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --export_vars vars_template.yml
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## License

MIT License  Perry Mertens

## Disclaimer
## APISCAN is a private and proprietary API security tool, developed independently for internal use and research purposes.
## It supports OWASP API Security Top 10 (2023) testing, OpenAPI-based analysis, active scanning, and multi-format reporting.
## Redistribution is not permitted without explicit permission.

## Important: Testing with APISCAN is only permitted on systems and APIs for which you have explicit authorization. 
## Unauthorized testing is strictly prohibited.


---

## Contact

 [pamsniffer@gmail.com](mailto:pamsniffer@gmail.com)  
 [GitHub](https://github.com/perrym/apiscanner)
