# APIScan (AI-Aware) OWASP APIScanner by Perry Mertens pamsniffer@gmail.com

**Version:** 2.0-beta
**Author:** Perry Mertens ([pamsniffer@gmail.com](mailto:pamsniffer@gmail.com))
**License:** MIT

## Overview

**APISCAN** is an extensible, advanced Python-based API security testing framework targeting the [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/). It supports Swagger/OpenAPI specifications, performs active vulnerability scanning, and generates comprehensive reports in various formats.

## Key Features

* Active scanning based on Swagger/OpenAPI specifications
* Covers all OWASP API Top 10 (2023) risks
* Support for real requests, dummy fuzzing, and AI-based review
* Multiple authentication modes: token, OAuth2, NTLM, basic, mTLS
* Reports: HTML

## Supported Risks

| OWASP API Risk ID | Description                                | Module                            |
| ----------------- | ------------------------------------------ | --------------------------------- |
| API1              | Broken Object Level Authorization          | `bola_audit.py`                   |
| API2              | Broken Authentication                      | `broken_auth_audit.py`            |
| API3              | Broken Object Property Level Authorization | `broken_object_property_audit.py` |
| API4              | Unrestricted Resource Consumption          | `resource_consumption_audit.py`   |
| API5              | Broken Function Level Authorization        | `authorization_audit.py`          |
| API6              | Sensitive Business Logic                   | `business_flow_audit.py`          |
| API7              | SSRF (Server-Side Request Forgery)         | `ssrf_audit.py`                   |
| API8              | Security Misconfiguration                  | `misconfiguration_audit.py`       |
| API9              | Improper Inventory Management              | `inventory_audit.py`              |
| API10             | Unsafe Consumption of 3rd-Party APIs       | `safe_consumption_audit.py`       |
| API11             | AI-assisted Security Analysis              | `ai_client.py`                    |

---
## Example CLI Usage

```bash
# Real mode (production or test data)
python apiscan.py --url https://api.example.com \
                  --swagger openapi.json \
                  --token eyJhbGciOi... \
                  --flow token

# Dummy mode (auto-generated fake values for fuzzing)
python apiscan.py --url https://api.example.com \
                  --swagger openapi.json \
                  --token eyJhbGciOi... \
                  --flow token \
                  --dummy
```

 `--dummy` enables safe testing using auto-generated, schema-aware dummy values.

---

## Swagger Crawler (optional)

```bash
python swaggergenerator.py --url https://api.example.com --output openapi.json --depth 3 --aggressive
```

---

## Output Files

* `api_*.html` (one per API risk)
* `combined_report.html` (if >1 risk enabled)
* `AI-api11_scanresults.json` (if --api11 used)
* Raw logs: `audit_*/log/*.log`

---

## Requirements

```bash
pip install -r requirements.txt
```

---

## Disclaimer

> This tool is intended for authorized security testing and research. Unauthorized scanning is strictly prohibited.

---

## Contact

📧 [pamsniffer@gmail.com](mailto:pamsniffer@gmail.com)
🌍 [https://github.com/perrym/apiscanner](https://github.com/perrym/apiscanner)

---

## Command-Line Arguments (summary)

```
--url                API base URL
--swagger            Path to OpenAPI JSON
--dummy              Enable dummy mode (auto fuzzed values)
--token              Bearer token
--basic-auth         Basic auth user:pass
--apikey             API key
--apikey-header      Header name for key
--ntlm               NTLM domain\user:pass
--client-cert/key    mTLS support
--flow               Auth flow: token, client, basic, ntlm
--api1 .. --api11    Run specific OWASP audit(s)
--threads            Parallelism (default: 2)
--debug              Enable debug mode
```

---

## AI-Driven Audit (API11)

Use AI to review endpoints, infer risks, and suggest abuse/test scenarios. Supports:

* OpenAI GPT-4o (cloud)

```bash
python apiscan.py --url https://api.example.com --swagger openapi.json --api11
```

**Output:**

* `AI-api11_scanresults.json` per endpoint
* AI-detected OWASP categories, risks, attack vectors
