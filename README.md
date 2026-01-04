<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">
# APISCAN OWASP APIscanner by Perry Mertens

**Author:** Perry Mertens (pamsniffer@gmail.com)  
**Year:**  2026 Perry Mertens  
**Version:** 3.2 (Release)  
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

## What is new in v3.2
![APISCAN v3.01 dashboard](./apiscan_v3_dashboard.jpg)

- Beter scanner and new reporting
- Generic sanitizer  
- Universal header overrides  
- ID and sample generation  
- Improved planning and verification workflow  
- Adaptive retry logic  
- SQLite evidence database  
- Optional AI-assisted analysis (API11)

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