# APISCAN – OWASP API Security Scanner

**Version:** 2.0‑beta  
**Author:** Perry Mertens ([pamsniffer@gmail.com](mailto:pamsniffer@gmail.com))  
**License:** MIT

APISCAN is an extensible, AI‑aware API security scanner targeting the **OWASP API Security Top 10 (2023)**. It understands Swagger/OpenAPI, supports multiple authentication flows, and produces clean HTML reports.

---

## Key Features

- OpenAPI‑aware active scanning (real requests)
- Coverage for API1..API10 + **API11: AI‑assisted review**
- Authentication: bearer token, OAuth2 client credentials, basic, NTLM, mTLS
- **Dummy mode**: schema‑aware fake values for safe testing
- **Variables export**: generate a fill‑in template from your OpenAPI
- Reports: per‑risk HTML + combined report

---

## Supported Risks

| ID    | Description                                       | Module                           |
|-------|---------------------------------------------------|----------------------------------|
| API1  | Broken Object Level Authorization                 | `bola_audit.py`                  |
| API2  | Broken Authentication                             | `broken_auth_audit.py`           |
| API3  | Property Level Authorization                      | `broken_object_property_audit.py`|
| API4  | Unrestricted Resource Consumption                 | `resource_consumption_audit.py`  |
| API5  | Function Level Authorization                      | `authorization_audit.py`         |
| API6  | Sensitive Business Logic                          | `business_flow_audit.py`         |
| API7  | SSRF (Server‑Side Request Forgery)                | `ssrf_audit.py`                  |
| API8  | Security Misconfiguration                         | `misconfiguration_audit.py`      |
| API9  | Improper Inventory Management                     | `inventory_audit.py`             |
| API10 | Unsafe Consumption of 3rd‑Party APIs              | `safe_consumption_audit.py`      |
| API11 | AI‑assisted Security Analysis                     | `ai_client.py`                   |

---

## Install

```bash
python -m venv .venv && . .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
```

> Python 3.11+ recommended.

---

## Quick Start

```bash
# Real mode (production/test data)
python apiscan.py \
  --url https://api.example.com \
  --swagger openapi.json \
  --flow token \
  --token <BEARER>

# Dummy mode (schema‑aware fake values)
python apiscan.py \
  --url https://api.example.com \
  --swagger openapi.json \
  --flow token \
  --token <BEARER> \
  --dummy
```

---

## NEW: Export Variables Template

Generate a YAML/JSON template with **all fill‑in values** detected from your OpenAPI (path/query/header/cookie params, request body fields, server variables, security schemes). This file is meant for **manual editing** before running scans.

```bash
# YAML (requires PyYAML; otherwise JSON will be written even if .yml is used)
python apiscan.py \
  --url https://api.example.com \
  --swagger openapi.json \
  --export-vars vars_template.yml

# JSON
python apiscan.py \
  --url https://api.example.com \
  --swagger openapi.json \
  --export-vars vars_template.json
```

**Notes**
- If `PyYAML` is not installed and you pass a `.yml`/`.yaml` path, APISCAN will fall back to JSON.
- The template includes `_servers`, `_security`, and an `operations` map keyed by `METHOD /path`.

---

## Swagger/OpenAPI Crawler (optional)

```bash
python swaggergenerator.py \
  --url https://api.example.com \
  --output openapi.json \
  --depth 3 \
  --aggressive
```

---

## Outputs

- `api_*.html` – one per risk
- `combined_report.html` – merged view (when multiple risks run)
- `AI-api11_scanresults.json` – AI output for API11
- Logs under: `audit_*/log/*.log`

---

## CLI Arguments (summary)

```
--url                 Base API URL
--swagger             Path to OpenAPI/Swagger JSON
--token               Bearer token (use with --flow token)
--basic-auth          user:pass
--apikey / --apikey-header
--ntlm                domain\user:pass
--client-cert / --client-key (PEM)
--flow                token | client | basic | ntlm
--threads             Parallelism (default: 2)
--dummy               Enable dummy payloads
--export-vars PATH    Write a fill‑in template and exit
--api1 .. --api11     Run specific audit modules
--debug               Verbose logging
```

---

## Disclaimer

> Use only on systems you are authorized to test. Unauthorized scanning is prohibited.

---

## Contact

- 📧 [pamsniffer@gmail.com](mailto:pamsniffer@gmail.com)
- 🌍 GitHub: <https://github.com/perrym/apiscanner>
