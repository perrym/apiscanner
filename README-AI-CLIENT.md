# APISCAN AI Client 4.0 release by Perry Mertens pamsniffer@gmail.com 2026 (C)
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">
AI-assisted analysis module for the OWASP API Top 10, used by APISCAN for API11-style risk classification.

The AI client:
- Sends real HTTP requests (optional live probing)
- Collects evidence (status codes, headers, bodies, timing)
- Asks a Large Language Model (LLM) to classify risk based on the **OWASP API Security Top 10 (2023)**
- Returns a structured JSON-like result that can be stored in SQLite and rendered into HTML / review dashboards.

**APISCAN is not a scanner that guesses; it proves.**  
It tests. It observes. Then the model explains the risk with evidence attached.

---

## Architecture

The module is structured around a few core classes:

- `LLMClient`  
  Handles all communication with LLM providers (OpenAI, OpenAI-compatible, Azure OpenAI, Anthropic, DeepSeek, Mistral, Gemini, OpenRouter, Ollama).  
  Provides `chat()` and `chat_json()` helpers with retry, caching and provider-specific formatting.

- `APIScanner`  
  Orchestrates live API probing and AI analysis per endpoint.  
  Produces `ScanResult` objects with:
  - `endpoint` (method, path, params, headers, body)
  - `probe` (observed HTTP response)
  - `analysis` (AI result mapped to OWASP API Top 10)
  - `error` / `skipped` flags

- `AIReportGenerator`  
  Converts results to:
  - HTML reports (via `EnhancedReportGenerator` from `report_utils`, with simple HTML fallback)
  - SQLite (`ai_scan.db`) for dashboards and `build_review.py`
  - Full review HTML (`ai_review.html`) using the existing reporting pipeline.

Dataclasses and typed dicts keep the interface explicit and stable:
- `ProbeResult`
- `ScanResult`
- `AnalysisResult`
- `EndpointDefinition`
- `ScanConfig`

---

## Supported LLM providers

`LLMClient` is configured via environment variables (typically written by `llmsetup.py`).  
Supported providers include:

- `openai` / `openai_compat`
- `azure_openai`
- `anthropic`
- `deepseek`
- `mistral`
- `gemini`
- `openrouter`
- `ollama` (local / offline)

The provider is selected via:

```bash
export LLM_PROVIDER=openai_compat
export LLM_MODEL=gpt-4o-mini
export LLM_API_BASE=https://your-openai-compatible-endpoint/v1
export LLM_API_KEY=sk-...
```

Ollama example:

```bash
export LLM_PROVIDER=ollama
export LLM_MODEL=llama3.2
export OLLAMA_HOST=http://localhost:11434
```

OpenAI example:

```bash
export LLM_PROVIDER=openai
export LLM_MODEL=gpt-4.1
export OPENAI_API_KEY=sk-...
```

OpenRouter example:

```bash
export LLM_PROVIDER=openrouter
export LLM_MODEL=openai/gpt-4o-mini
export OPENROUTER_API_KEY=sk-or-...
export OPENROUTER_X_TITLE=APISCAN
```

---

## Configuration

Most settings are read from environment variables through `LLMConfig`.

Typical variables:

| Variable                | Description                                       |
|-------------------------|---------------------------------------------------|
| `LLM_PROVIDER`          | `openai_compat`, `azure_openai`, `ollama`, etc.  |
| `LLM_MODEL`             | Model or deployment name                         |
| `LLM_API_KEY`           | Generic API key for OpenAI-compatible providers |
| `LLM_API_BASE`          | Custom base URL (for gateways / shims)           |
| `LLM_API_PORT`          | Custom port if needed                            |
| `LLM_TEMPERATURE`       | Sampling temperature                             |
| `LLM_TOP_P`             | Nucleus sampling                                 |
| `LLM_MAX_TOKENS`        | Max tokens to generate                           |
| `LLM_VERIFY_SSL`        | `true` / `false`                                 |
| `LLM_CONNECT_TIMEOUT`   | Connect timeout seconds                          |
| `LLM_READ_TIMEOUT`      | Read timeout seconds                             |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint                            |
| `AZURE_OPENAI_AUTH_TYPE` | `api_key` or `entra`                            |
| `AZURE_OPENAI_API_KEY`  | Azure OpenAI key when using API-key auth         |
| `AZURE_OPENAI_AD_TOKEN` | Optional Entra bearer token                      |
| `AZURE_OPENAI_TOKEN_SCOPE` | Token scope, default `https://cognitiveservices.azure.com/.default` |
| `AZURE_OPENAI_API_VERSION` | Azure API version                            |
| `OPENAI_API_KEY`        | Official OpenAI API key                          |
| `ANTHROPIC_API_KEY`     | Anthropic API key                                |
| `DEEPSEEK_API_KEY`      | DeepSeek API key                                 |
| `MISTRAL_API_KEY`       | Mistral API key                                  |
| `GEMINI_API_KEY`        | Gemini API key                                   |
| `OPENROUTER_API_KEY`    | OpenRouter API key                               |

These can be generated safely by running:

```bash
python llmsetup.py
```

which writes `.env`, `apiscan_env.*` and `test_env.py` for validation.

### Azure OpenAI

Azure OpenAI uses `LLM_PROVIDER=azure_openai`. For Azure, `LLM_MODEL` is the **deployment name**, not necessarily the base model name.

API-key authentication:

```bash
export LLM_PROVIDER=azure_openai
export LLM_MODEL=my-gpt-4o-deployment
export AZURE_OPENAI_ENDPOINT=https://my-resource.openai.azure.com
export AZURE_OPENAI_AUTH_TYPE=api_key
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_API_VERSION=2024-08-01-preview
```

Microsoft Entra authentication:

```bash
export LLM_PROVIDER=azure_openai
export LLM_MODEL=my-gpt-4o-deployment
export AZURE_OPENAI_ENDPOINT=https://my-resource.openai.azure.com
export AZURE_OPENAI_AUTH_TYPE=entra
export AZURE_OPENAI_API_VERSION=2024-08-01-preview
```

With Entra auth, APISCAN first uses `AZURE_OPENAI_AD_TOKEN` / `AZURE_OPENAI_ENTRA_TOKEN` if set. Otherwise it uses `azure.identity.DefaultAzureCredential`, so `az login`, managed identity, workload identity, and similar Azure identity flows can work when `azure-identity` is installed.

```bash
pip install azure-identity
az login
```

The default token scope is:

```bash
https://cognitiveservices.azure.com/.default
```

---

## Risk model and analysis output

The AI output is normalized into an `AnalysisResult` with:

- `risk`            – `Informal`, `Low`, `Medium`, `High`
- `explanation`     – short description (max ±3 sentences)
- `owasp_category`  – exact OWASP API Top 10 label (e.g. `API1: Broken Object Level Authorization`)
- `recommendation`  – secure coding / control improvement
- `reasoning`       – short step-by-step reasoning
- `confidence`      – 0.0–1.0
- `cvss_score`      – optional CVSS (0.0–10.0)

The prompt used is fixed in `SYSTEM_PROMPT` and is focused on OWASP API Top 10 (2023), not generic vulnerability lists.

---

## Using the legacy helpers (APISCAN 3.x compatibility)

### `chat_json()`

```python
from ai_client import chat_json

messages = [
    {"role": "user", "content": "Return a JSON object: {'hello': 'world'}"}
]

result = chat_json(messages)
print(result)
```

### `live_probe()`

```python
from ai_client import live_probe

probe_result = live_probe()
print(probe_result)
```

### `analyze_endpoints_with_llm()`

This wrapper keeps the old APISCAN 3.x integration working and optionally generates an HTML report.

```python
from ai_client import analyze_endpoints_with_llm

endpoints = [
    {
        "path": "/api/users/1",
        "method": "GET",
        "allow_unsafe": False,
        "headers": {"Accept": "application/json"}
    }
]

results = analyze_endpoints_with_llm(
    endpoints,
    live_base_url="https://api.example.com",
    print_results=True,
    generate_report=True,
    report_output="ai_scan_report.html"
)
```

The returned list is in the older “legacy” format (`path`, `method`, `analysis`, etc.), but under the hood it uses the new `APIScanner` and `ScanResult` objects.

---

## Using the new scanner directly

### Python usage

```python
from ai_client import APIScanner

scanner = APIScanner()

endpoints = [
    {
        "path": "/api/users/{id}",
        "method": "GET",
        "path_params": {"id": "1"},
        "headers": {"Accept": "application/json"},
        "allow_unsafe": False
    }
]

scan_config = {
    "base_url": "https://api.example.com",
    "enable_live_scan": True,
    "safe_mode": True,
    "compare_auth": True,
    "timeout": (5, 30),
    "max_response_size": 1024 * 1024
}

results = scanner.scan(endpoints, scan_config)

for r in results:
    if r.analysis:
        print(r.endpoint.get("method"), r.endpoint.get("path"), "->", r.analysis["risk"], r.analysis["owasp_category"])
```

### Generating reports

`APIScanner.generate_report()` supports three formats:

- `html`   – HTML summary, using `EnhancedReportGenerator` when available
- `review` – Full review report flow, via `build_review.py` and SQLite
- `sqlite` – Only write `ai_scan.db` (for separate dashboard/report steps)

```python
report_path = scanner.generate_report(
    results=results,
    format="html",
    output_path="ai_scan_report.html",
    base_url="https://api.example.com"
)
```

Or in one call:

```python
results, report_path = scanner.scan_with_report(
    endpoints=endpoints,
    scan_config=scan_config,
    report_format="review",
    output_path="ai_review_output"
)
```

This will create:
- `ai_scan.db` (SQLite evidence store)
- `ai_review.html` (if `build_review.py` is available)

---

## CLI usage

The module can also be used from the command line.

### Simple chat

```bash
export LLM_PROVIDER=openai_compat
export LLM_API_KEY=sk-...

python ai_client.py   --system "You are a JSON-only assistant."   --message "Return a JSON object: {'ok': true}"
```

### Scan endpoints from file

`endpoints.json`:

```json
[
  {
    "path": "/api/users/1",
    "method": "GET",
    "headers": {
      "Accept": "application/json"
    }
  }
]
```

Run scan + HTML report:

```bash
python ai_client.py   --scan   --endpoints endpoints.json   --base-url https://api.example.com   --report   --output ai_scan_report.html
```

This will:
- Perform live probing (if `--base-url` is set)
- Ask the model to classify risk per endpoint
- Write an HTML report to `ai_scan_report.html`

---

## SQLite + review integration

All AI findings can be stored in SQLite using:

```python
from ai_client import AIReportGenerator

AIReportGenerator.save_to_sqlite(results, "ai_scan.db")
```

or implicitly via:

```python
AIReportGenerator.generate_review_report(
    scan_results=results,
    output_dir="ai_review_output"
)
```

The schema is compatible with the existing `build_review.py` flow so AI results appear next to other APISCAN evidence and findings.

---

## Notes

- Live scanning is controlled by `enable_live_scan` and `base_url`.  
  In `safe_mode`, unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) are skipped unless `allow_unsafe=True` is set per endpoint.
- Secrets (Authorization headers, cookies, API keys) are masked in stored request/response headers.
- SSL verification can be disabled for local testing by setting `LLM_VERIFY_SSL=false` (not recommended in production).
- The module is licensed under **AGPL-v3.0** and must remain open when used as a hosted service.
