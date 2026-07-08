<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">

**APISCAN OWASP 5.0 APIscanner by Perry Mertens**

**Author:** Perry Mertens (pamsniffer@gmail.com)  
**Year:**  2026 Perry Mertens  
**Version:** 5.0.0 (Release)  
**License:** GNU Affero General Public License v3.0 (AGPL-v3.0)

APISCAN is an API vulnerability scanner that proactively identifies security risks by testing against the OWASP API Security Top 10 (2023).
It uses your OpenAPI/Swagger specification to generate realistic attack payloads and detect issues such as Broken Object Level Authorization (BOLA),
Broken Authentication, Excessive Data Exposure, and other critical API vulnerabilities.
It understands OpenAPI/Swagger, supports multiple authentication flows, provides a plan/verify workflow, includes a generic sanitizer/rewrites, and writes HTML artifacts.

**APISCAN: AI-assisted API security for specialists.**
APISCAN is not a scanner that guesses; it proves.
It tests. It observes. Then models explain the risk with evidence attached.
That’s how you make **AI** useful in security.

## License

APISCAN is licensed under the AGPL-v3.0.

If you modify APISCAN and make it available as a hosted service, you must make the complete corresponding source code available under the same license.

## What is APISCAN

APISCAN focuses on API-specific risks instead of generic web scanning.  
It is built for testing APIs against the OWASP API Security Top 10 (2023), with one module per risk area and HTML reporting suitable for auditors and developers.

## What's New in v5.0.0
![APISCAN v5.0.0 GUI](./APISCAN-mainmenu%20v5.0.0.jpg)

- **Auto Form-Login** — Automatic login form detection for crAPI, Juice Shop, and custom apps. HTML form parsing, JSON API detection, token auto-extraction. Use `--flow form --login-username ... --login-password ...` or the GUI Auto-Detect button.
- **Crawl Validator** — Smart endpoint validation filters fake paths. `--crawl-validate` (on), `--no-crawl-validate`, `--crawl-validate-mode balanced|strict`, `--crawl-validate-workers N`. From 71→4 endpoints on Juice Shop.
- **Deep Scan Mode** — `APISCAN_DEEP_SCAN=1` auto-switches to full payloads, high intensity, no quick mode. All injection types including SSTI, LDAP, XXE, RCE with `injection_payloads.json`.
- **Expanded Quick Scan** — Default scan now covers 9 base tests + 6 injection types (SQL, Path, XSS, NoSQL, LFI, SSTI). Endpoint cap raised from 20→30.
- **Business Logic Testing** — Detects negative prices, excessive discounts, admin role assignment, and privilege escalation via deep scan mode.
- **Production Ready** — Tested against Juice Shop and crAPI. Crash-free: dedup fix for dict payloads, session retry fix for 500 responses, HTML response skip in form detection, error spam suppression.
- **GUI** — Cross-platform Tkinter interface (`python apiscan_gui.py`) with Target, Authentication, Form Login (Auto-Detect), and Advanced tabs. Crawl validate controls built in.
- **Chain Mode** — Auto-escalates BOLA findings by extracting leaked data (tokens, user IDs, emails, roles) and re-injecting it into other endpoints. `--chain-mode` with optional `--chain-depth 1-3` for recursive privilege escalation chains. Generates `api_chain_escalation_report.html`.
- **Real-World Attack Patterns** — Detects real-world threat actor TTPs: **ShinyHunters** unauthenticated data exposure (UNC6040), **Salesforce** enumeration & Data Loader bulk exfiltration, plus many more attack patterns.

## Install

```
python -m venv .venv
source .venv/bin/activate     # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

## Setup and environment

Before running APISCAN, configure your environment and optional AI tooling.

### Environment setup
```
python setup.py
# Validates Python dependencies and environment
# Creates/updates .env.example and requirements.txt
```

### LLM / AI providers (optional)
```
python llmsetup.py
# Configure Ollama / OpenAI / Anthropic / DeepSeek
# Saves settings and writes apiscan_env.sh / apiscan_env.ps1 helper scripts
```

## Quick start

```
python apiscan.py --url https://api.example.com --swagger openapi.json --flow token --token "<ACCESS_TOKEN>" --verify-plan
```

## Quick mode and full scan

API10 (Unsafe Consumption of APIs) runs in quick mode by default. This keeps normal scans fast by limiting Phase 2 to the most promising endpoints and capping quick SQL testing.

Defaults:
- `APISCAN_API10_QUICK=1`
- `APISCAN_API10_QUICK_MAX_ENDPOINTS=30`
- `APISCAN_API10_QUICK_SQL_MAX_TESTS=10`
- `APISCAN_API10_QUICK_DIRTRAV_MAX_TESTS=8`
- `APISCAN_API10_QUICK_HPP_MAX_PARAMS=3`
- `APISCAN_API10_QUICK_REDIRECT_MAX_TESTS=6`
- `APISCAN_RATE_LIMIT=0`

| Mode | Endpoints | Tests/endpoint | Totaal | Tijd |
|---|---|---|---|---|
| Quick (default) | 30 | ~15 | ~450 | ~3-5 min |
| Deep scan | 15 | ~26 | ~390 | ~25-35 min |

> Deep scan: `APISCAN_DEEP_SCAN=1` + optioneel `APISCAN_DEEP_MAX_ENDPOINTS=15` (default).

PowerShell:
```
# Default quick mode
$env:APISCAN_API10_QUICK="1"

# Optional quick tuning
$env:APISCAN_API10_QUICK_MAX_ENDPOINTS="30"
$env:APISCAN_API10_QUICK_SQL_MAX_TESTS="10"

# Full API10 scan
$env:APISCAN_API10_QUICK="0"

# Deep scan, slower and more intensive
$env:APISCAN_DEEP_SCAN="1"
```

Bash/Linux/macOS:
```
# Default quick mode
export APISCAN_API10_QUICK=1

# Optional quick tuning
export APISCAN_API10_QUICK_MAX_ENDPOINTS=30
export APISCAN_API10_QUICK_SQL_MAX_TESTS=10

# Full API10 scan
export APISCAN_API10_QUICK=0

# Deep scan, slower and more intensive
export APISCAN_DEEP_SCAN=1
```

## Usage examples

### Bearer token
```
python apiscan.py --url https://api.example.com --swagger openapi.json --flow token --token "<ACCESS_TOKEN>"
```

### API key
```
python apiscan.py --url https://api.example.com --swagger openapi.json --flow none --apikey "<KEY>" --apikey-header "X-API-Key"
```

### OAuth2 Client Credentials
```
python apiscan.py --url https://api.example.com --swagger openapi.json --flow client --client-id "<ID>" --client-secret "<SECRET>" --token-url "https://idp/token"
```

### Proxy / Burp
```
python apiscan.py --url https://api.example.com --swagger openapi.json --flow token --token "<TOKEN>" --proxy 127.0.0.1:8080 --insecure
```

### Plan-only
```
python apiscan.py --url https://api.example.com --swagger openapi.json --plan-only
```

## Advanced usage

### Extra headers
```
--extra-header "x-tenant-id: acc"
--extra-header "x-feature-flag: beta"
```

### IDs file
```
--ids-file ids.json
```

### Sanitizer and rewrites
```
--no-sanitize
--rewrite "/identity/api/v2=>/identity/api/v7/"
--normalize-version
```

### AI-assisted analysis
```
export LLM_PROVIDER=openai_compat
export LLM_MODEL=gpt-4o-mini
export LLM_API_KEY=sk-...

python apiscan.py --url https://api.example.com --swagger openapi.json --api11
```

## Output and reports

- review.html  
- combined_report.html  
- Per-risk HTML reports  
- SQLite database `results.db`  
- Logs `apiscan_*.log`

## Notes

- Only test APIs you are authorized to test.
- Start with `--plan-only` to avoid accidental traffic.
- Use retry options for unstable endpoints.

## Links

- Medium article: https://medium.com/@PerryPM/apiscan-a-practical-approach-to-api-security-testing-by-perry-mertens-96b5e676c071
- GitHub: https://github.com/perrym/apiscanner
- Contact: pamsniffer@gmail.com

---
© 2026 Perry Mertens pamsniffer@gmail.com. Released under the AGPL-v3.0 License.

---
