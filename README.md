# APISCAN - OWASP API Security Scanner

**Version:** 0.9.0-beta  
**Author:** Perry Mertens email:pamsniffer@gmail.com
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
| API11            | AI-assisted Security Analysis         | `ai_client.py`              |

## Example Usage

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --token eyJhbGciOi... \
  --flow token 
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

combined_report.html

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


## 🧠 API11 – AI-assisted Security Review

**Module:** `ai_client.py`  
**Nieuw:** Ondersteuning voor *zowel lokale Ollama* als *OpenAI API (GPT-4o)*

Deze optionele module voert AI-gedreven endpoint-analyse uit op basis van de OWASP API Top 10. Het ondersteunt nu twee modi:

### 1. OpenAI GPT-4o (cloud)

Gebruik deze modus wanneer je een echte API key hebt van OpenAI:

```bash
export OPENAI_API_KEY=sk-...
python apiscan.py --url https://api.example.com --swagger openapi.json --api11
```

De module gebruikt `https://api.openai.com/v1/chat/completions` en het `gpt-4o` model standaard, maar je kunt dit aanpassen via de argumenten in `analyze_endpoints_with_gpt()`.

### 2. Lokale LLM via Ollama (optioneel)

Als je een lokale LLM hebt draaien (zoals `mistral`, `deepseek`, etc. via Ollama), kun je deze blijven gebruiken:

```bash
python apiscan.py --url https://api.example.com --swagger openapi.json --api11
```

Gebruik de `--port` parameter om over te schakelen van 11434 (Ollama) naar een andere lokale service. Deze modus vereist geen internetverbinding of OpenAI key.

### Output

- `ai_analysis_output.json`: JSON-bestand met samenvattingen per endpoint
- Bevat voor elk endpoint:
  - OWASP-risico’s
  - Abuse scenario's
  - Teststrategieën
  - Risicobeoordeling
