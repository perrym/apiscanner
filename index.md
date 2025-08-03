---
title: APIScan (AI-Aware) OWASP APIScanner by Perry Mertens pamsniffer@gmail.com
description: Free and open-source API security scanner built in Python...
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">
---

[![View on GitHub](https://img.shields.io/badge/GitHub-View%20Repository-blue?logo=github)](https://github.com/perrym/apiscanner)

---

# APISCAN apiscanner 2.0-beta - is a free and extensible API security auditing framework, built in Python, that targets the **OWASP API Security Top 10**.  
# It supports **OpenAPI/Swagger specs**, performs **active scans** on endpoints, and produces nice reports.
## OWASP based (REST) API Security Assessment Tool (by Perry Mertens April 2025)

APISCAN is an extensible, modular security auditing framework for REST APIs, based on the OWASP API Security Top 10 (2023) risks.

1. Summary
APISCAN is an extensible and modular Python-based security scanner for REST APIs. 
It automates the detection of vulnerabilities based on the OWASP API Security Top 10 (2023) standard. 
APISCAN parses OpenAPI/Swagger specifications, runs active tests against API endpoints, and produces clear reports in Markdown, JSON, and CSV formats. It focuses on realistic attack simulation techniques, evidence-based findings, and extensibility for future expansion.

2. OWASP API Security Top 10 Coverage
OWASP API Risk	APISCAN.PY Coverage	Module

| OWASP API Risk | APISCAN Coverage | Module |
|:--|:--|:--|
| API1: Broken Object Level Authorization | Access control bypass via object ID manipulation | `bola_audit.py` |
| API2: Broken Authentication | Weak login protections, session handling flaws, token misuse | `broken_auth_audit.py` |
| API3: Broken Object Property Level Authorization | Mass assignment, unauthorized property manipulation | `broken_object_property_audit.py` |
| API4: Unrestricted Resource Consumption | Abuse of API endpoints through large/batch requests | `resource_consumption_audit.py` |
| API5: Broken Function Level Authorization | Partial coverage via role misuse checks | `authorization_audit.py` *(partial)* |
| API6: Mass Assignment | Partially tested through property injection | `broken_object_property_audit.py` |
| API7: Security Misconfiguration | Missing security headers, server misconfiguration detection | `misconfiguration_audit.py` |
| API8: Injection | Partially tested via authentication and external API tests | `broken_auth_audit.py`, `safe_consumption_audit.py` |
| API9: Improper Inventory Management | Exposed API documentation and debug endpoints | `inventory_audit.py` |
| API10: Unsafe Consumption of 3rd-Party APIs | Injection and SSRF risks through external APIs | `safe_consumption_audit.py` |
| API11: AI-assisted Security Analysis  | `ai_client.py`  |

3. Module Descriptions
Each APISCAN module targets specific OWASP API risks with realistic attack simulations. The tests include fuzzing, timing analysis, authorization bypass attempts, response reflection analysis, security header evaluation, and concurrency stress tests.


---

### 3. Extra Features (Nieuw)

**Authenticatie-ondersteuning**  
APISCAN ondersteunt verschillende authenticatievormen via CLI-argumenten:
- `--token`: Bearer tokens
- `--basic-auth gebruiker:wachtwoord`
- `--apikey` + `--apikey-header`: API Key-authenticatie
- `--ntlm domein\gebruiker:pass`: NTLM-authenticatie
- `--client-cert` + `--client-key`: mTLS met client-certificaten
- `--OAuth2 ` 
-`--client-id`,
-`--client-secret`,
-`--token-url`,
-`--auth-url`, 
-`--redirect-uri`

**Rapportage**
- Automatische directory aanmaak per scan (`audit_<api-url>_<datum>/`)
- Per API-kwetsbaarheid een apart rapport in `.html`
- Samenvattend rapport `api_combined_report.txt`

**Gebruiksvriendelijke CLI**
- Automatische validatie van Swagger-bestanden
- Herbruikbare sessieconfiguratie met threading-optimalisatie

**Documentatieformaten**
- HTML

---

###  Voorbeeldgebruik

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --token eyJhbGciOi... \
  --threads 5
  --flow token 
```

# Dummy mode (auto-generated fake values for fuzzing)
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --token eyJhbGciOi... \
  --flow token \
  --dummy
```
`--dummy` enables safe testing using auto-generated, schema-aware dummy values.


**Extra authenticatievoorbeelden:**

```bash
--apikey abcdef123456 --apikey-header X-API-Key
--basic-auth admin:password
--ntlm DOMAIN\\user:pass
--client-cert cert.pem --client-key key.pem
--client-id myapp --client-secret s3cr3t --token-url https://login/token --auth-url https://login/auth --redirect-uri http://localhost
```


4. Conclusion and Future Enhancements
APISCAN currently provides strong coverage for the most critical API security risks. Future enhancements could include more in-depth Injection testing (SQL, SSTI), advanced function-level authorization validation, and fuzzing based on OpenAPI schemas.

APISCAN supports OpenAPI/Swagger specification parsing, advanced payload generation, concurrent testing, and evidence-based reporting.
## Install first  python requirements
pip install -r requirements.txt

## Start scanner without or with token 
python apiscan.py --url http://sample.com --token eyJhbGciOiJSUzI1NiJ9JvbGUiOiJ1c2VyIn0XzR --swagger openapi-spec.json --flow token

APISCAN 2.0.0-Beta API Security Scanner Perry Mertens 2025

options:
  -h, --help            show this help message and exit
  --url URL             Base URL of the API
  --swagger SWAGGER     Path to Swagger/OpenAPI-JSON
  --postman POSTMAN     Path to Postman Collection v2.1 JSON
  --token TOKEN         Bearer-token of auth-token
  --basic-auth BASIC_AUTH
                        Basic auth in de vorm gebruiker:password
  --apikey APIKEY       API key voor toegang tot API
  --apikey-header APIKEY_HEADER
                        Headernaam voor de API key
  --ntlm NTLM           NTLM auth in de vorm domein\gebruiker:pass
  --client-cert CLIENT_CERT
                        Pad naar client certificaat (PEM)
  --client-key CLIENT_KEY
                        Pad naar private key voor client certificaat (PEM)
  --client-id CLIENT_ID
  --client-secret CLIENT_SECRET
  --token-url TOKEN_URL
  --auth-url AUTH_URL
  --redirect-uri REDIRECT_URI
  --threads THREADS
  --cert-password CERT_PASSWORD
  --dummy
                        Wachtwoord voor client certificaat
  --debug               Enable debug output
  --api1                Voer alleen API1-audit uit
  --api2                Voer alleen API2-audit uit
  --api3                Voer alleen API3-audit uit
  --api4                Voer alleen API4-audit uit
  --api5                Voer alleen API5-audit uit
  --api6                Voer alleen API6-audit uit
  --api7                Voer alleen API7-audit uit
  --api8                Voer alleen API8-audit uit
  --api9                Voer alleen API9-audit uit
  --api10               Voer alleen API10-audit uit
  --api11 

# AI-Driven Audit (API11)

Use AI to review endpoints, infer risks, and suggest abuse/test scenarios. Supports:

* OpenAI GPT-4o (cloud)

```bash
python apiscan.py --url https://api.example.com --swagger openapi.json --api11
```

**Output:**

* `AI-api11_scanresults.json` per endpoint
* AI-detected OWASP categories, risks, attack vectors



# When you are missing a swagger file without or with token 
python swagger_generator.py --url https://sample.com  --output api_spec.json --depth 3 --aggressive        

URL Swagger Generator by Perry Mertens 2024

options:
  -h, --help            show this help message and exit
  --url URL             Base URL
  --output OUTPUT       Output file
  --depth DEPTH         Crawl depth
  --aggressive          Aggressive mode
  --username USERNAME   Basic auth username
  --password PASSWORD   Basic auth password
  --token TOKEN         Bearer token for authentication
  --token-header TOKEN_HEADER
                        Header name for token
  --login-url LOGIN_URL
                        Login form URL
  --login-data LOGIN_DATA
                        Login form data as JSON string
  --header HEADER       Custom header (format: Header-Name:value)


## Features
- Modular structure per OWASP risk category
- Realistic attack simulation (fuzzing, timing attacks, header tampering)
- Clear Markdown, JSON, and txten docx output formats
- Designed for both developers and security auditors

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Disclaimer
**This tool is intended for educational and authorized security testing purposes only.**
**Always ensure you have permission before scanning, crawling, or testing any target systems.**

## Contact
For any questions, feedback, or responsible disclosure, please contact: pamsniffer@gmail.com

