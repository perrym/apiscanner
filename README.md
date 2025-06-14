# APISCAN - OWASP API Security Scanner

**Version:** 0.8.9-alpha  
**Author:** Perry Mertens  
**License:** MIT

## Overview

**APISCAN** is a free, extensible API security auditing tool built in Python that targets the [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/). It supports Swagger/OpenAPI specifications, performs active vulnerability scans, and generates clear reports in multiple formats.

## Features

- Active scanning of REST APIs using OpenAPI/Swagger definitions.
- Realistic vulnerability detection (e.g., fuzzing, timing, injection, SSRF).
- Modular audits for each OWASP API Top 10 risk.
- CLI with extensive authentication support.
- Output in DOCX, Markdown, JSON, and TXT.

## Supported Risks

| OWASP API Risk ID | Description | Module |
|------------------|-------------|--------|
| API1             | Broken Object Level Authorization | `bola_audit.py` |
| API2             | Broken Authentication | `broken_auth_audit.py` |
| API3             | Broken Object Property Level Authorization | `broken_object_property_audit.py` |
| API4             | Unrestricted Resource Consumption | `resource_consumption_audit.py` |
| API5             | Broken Function Level Authorization | `authorization_audit.py` |
| API6             | Sensitive Business Logic | `business_flow_audit.py` |
| API7             | SSRF (Server-Side Request Forgery) | `ssrf_audit.py` |
| API8             | Security Misconfiguration | `misconfiguration_audit.py` |
| API9             | Improper Inventory Management | `inventory_audit.py` |
| API10            | Unsafe Consumption of 3rd-Party APIs | `safe_consumption_audit.py` |

## Example Usage

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --token eyJhbGciOi... \
  --threads 4
```

### Authentication Options

- `--token` (Bearer token)
- `--basic-auth` (username:password)
- `--apikey` + `--apikey-header`
- `--ntlm` (domain\user:password)
- `--client-cert` + `--client-key` (mTLS)
- `--client-id`, `--client-secret`, `--token-url`, `--auth-url`, `--redirect-uri` (OAuth2)

### Swagger Generation (optional)

```bash
python swaggergenerator.py --url https://api.example.com --output openapi.json --depth 3 --aggressive
```

## Output

- Individual text files per OWASP test
- Summary: `api_summary_report.txt`
- Professional DOCX report
- Logs in the `log/` directory

## Requirements

```bash
pip install -r requirements.txt
```

## License

MIT License - see LICENSE file.

## Disclaimer

This tool is intended for educational and authorized security testing only. Unauthorized use is prohibited.

## Contact

📧 pamsniffer@gmail.com  
🌍 https://github.com/perrym/apiscanner

## Command-Line Parameters

- `--url`: Base URL of the API
- `--swagger`, `help="Path to Swagger/OpenAPI-JSON`: Path to Swagger/OpenAPI-JSON
- `--token`, `help="Bearer-token of auth-token`: Bearer-token of auth-token
- `--basic-auth`: Basic auth in de vorm gebruiker:password
- `--apikey`: API key voor toegang tot API
- `--apikey-header`, `default="X-API-Key`: Headernaam voor de API key
- `--ntlm`: NTLM auth in de vorm domein\\gebruiker:pass
- `--client-cert`: 
- `--client-key`: 
- `--client-id`: 
- `--client-secret`: 
- `--token-url`: 
- `--auth-url`: 
- `--redirect-uri`: 
- `--flow`: Authentication flow to use: token, client, basic, ntlm
- `--scope`: 
- `--threads`: 
- `--cert-password`: Wachtwoord voor client certificaat
- `--debug`: Enable debug output
- `f"--api{i}`, `help=f"Voer alleen API{i}-audit uit`: