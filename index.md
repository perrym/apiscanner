---
title: APISCAN v3.2 – AI‑enhanced OWASP APIScanner by Perry Mertens (AGPL-v3.0)
description: Free and open-source APIscanner built in Python with multi-auth, OpenAPI/Swagger support, sanitizer/rewrites, and rich CSV/HTML reporting.
---

<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">

[![GitHub](https://img.shields.io/badge/GitHub-perrym%2Fapiscanner-0ea5e9?logo=github)](https://github.com/perrym/apiscanner)
[![Medium](https://img.shields.io/badge/Medium-Article-black?logo=medium)](https://medium.com/@PerryPM/apiscan-a-practical-approach-to-api-security-testing-by-perry-mertens-96b5e676c071)

APIscan is an API vulnerability scanner that proactively identifies security risks by testing against the OWASP API Security Top 10 (2023).
It uses your OpenAPI/Swagger specification to generate realistic attack payloads and detect issues such as Broken Object Level Authorization (BOLA), Broken Authentication, Excessive Data Exposure, and other critical API vulnerabilities.
It understands **OpenAPI/Swagger**, supports **multiple authentication flows**, provides a **plan/verify workflow**, includes a **generic sanitizer/rewrites**, and writes **CSV/HTML** artifacts.

This page is the generic, customer-agnostic documentation corresponding to the v3.0 GitHub Pages landing (`index.html`).

![APISCAN v3.2 dashboard](./apiscan_v3_dashboard.jpg)

---

## License

APISCAN is released as free and open-source software under the **GNU Affero General Public License v3.0 (AGPL‑3.0)**.

If you modify APISCAN and make it available as a network service (SaaS, hosted scanner, web UI, etc.), you must publish the complete corresponding source code of your modified version under the same license.

Use APISCAN only on systems and APIs for which you have explicit authorization.

---

## What’s new in v3.2

v3.2 focuses on better planning, headers, and robustness for enterprise scans:

- **Generic sanitizer (no hardcodes)**  
  Collapses duplicate path segments, normalizes `/vN` → `/vN.00`, trims trailing slashes.  
  Control with:
  - `--no-sanitize` to disable sanitizer  
  - `--rewrite "pat=>rep"` for targeted rewrites  

- **Universal header overrides**  
  One unified model for headers:  
  - `--flow token --token "<JWT>"`  
  - `--apikey --apikey-header`  
  - `--extra-header "X-Header: value"` (repeatable)  
  - `--headers-file headers.json` for JSON-based headers  
  OpenAPI `example`/`default` values are auto-applied where possible.

- **IDs & samples for path variables**  
  - `--ids-file ids.json` to control `{param}` values  
  - Fallback generator for names like `*id`, `code`, `uuid`, `email`, `date`.

- **Improved planning & verification**  
  - Better `requestBody` sampling order  
  - Accurate JSON detection (`application/json; charset=UTF-8`)  
  - `--verify-plan` to actually send planned requests  
  - `--success-codes "200-299,304"` to define acceptable responses.

- **Adaptive retry**  
  - `--retry500 N` for automatic retries on HTTP 5xx errors  
  - `--no-retry-500` to disable this behaviour.

---

## Install

Use Python **3.11+** where possible.

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

---


## Setup helpers (setup.py & llmsetup.py)

Two helper scripts are included to make environment and LLM configuration easier and repeatable.

### Environment & dependencies: `setup.py`

`setup.py` can:
- Create or update `requirements.txt` and `.env.example`
- Install or verify Python dependencies
- Perform basic environment checks (Python version, venv, OS)
- Print a short summary with next steps

Typical usage:

```bash
# Run full setup (create venv, install deps, show summary)
python setup.py

# Skip dependency installation, only check config and files
python setup.py --skip-deps

# Minimal mode without the extended quickstart text
python setup.py --minimal
```

### LLM & AI configuration: `llmsetup.py`

`llmsetup.py` configures one or more AI providers (Ollama, OpenAI, Anthropic, DeepSeek) and writes a ready-to-use `.env` plus shell helpers.

It can:
- Ask which providers you want to enable
- Store API keys / base URLs in `.env`
- Generate shell helpers like `apiscan_env.ps1` / `apiscan_env.sh`
- Create a `test_env.py` helper to validate your configuration

Typical flow:

```bash
# Start interactive LLM setup
python llmsetup.py

# After running the wizard:
# 1) Load the generated env helper in your shell
# 2) Run the environment test
python test_env.py
```

After that, you can run `apiscan.py` as usual with your configured LLM(s).

## Quick start

### Verify with Bearer token

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --flow token --token "<BEARER>" \
  --verify-plan
```

### Plan + Verify + CSV

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --flow token --token "<BEARER>" \
  --plan-only --verify-plan \
  --success-codes "200-299,304"
```

### Proxy & self-signed lab

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --flow token --token "<BEARER>" \
  --proxy http://127.0.0.1:8080 \
  --insecure \
  --plan-only --verify-plan
```

### With version normalization + retries

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --flow token --token "<BEARER>" \
  --normalize-version \
  --retry500 \
  --verify-plan
```

---

## Headers (generic)

### Bearer

```bash
--flow token --token "<JWT>"    # -> Authorization: Bearer <JWT>
```

### API key header

```bash
--apikey "secret" --apikey-header X-API-Key
```

### Multiple custom headers

```bash
--extra-header "X-JWT-Header: secret..." \
--extra-header "X-Tenant-ID: acc"
```

### From JSON file

`headers.json`:

```json
{
  "X-JWT-Header": "secret...",
  "X-Tenant-ID": "acc"
}
```

CLI:

```bash
--headers-file headers.json
```

OpenAPI header parameters with `example`/`default` are auto-filled.  
`Content-Length` is never set manually.

---

## Sanitizer & rewrites

The built-in sanitizer (enabled by default):

- Collapses `//` (excluding the scheme)
- Normalizes `/v2` → `/v2.00` (if not already dotted)
- Folds repeats (`/A/A` → `/A`, `/A/B/A` → `/A/B`)
- Removes trailing slash (except root)

Control:

```bash
--no-sanitize
--rewrite '/identity/api/v2(?=/)/=>/identity/api/v7/'
--normalize-version
```

PowerShell tip: use **single quotes** around the rewrite string so `>` is not interpreted.

Optional debug trace in `_apply_rewrites`:

```python
new_url = re.sub(pat, rep, full_url)
if new_url != full_url:
    print(f"[rewrite] {pat!r} => {rep!r} :: {full_url} -> {new_url}")
```

---

## Path variables & IDs

`ids.json` example:

```json
{ "userId": "me", "orderId": 1, "vin": "11119401" }
```

CLI:

```bash
--ids-file ids.json
```

Fallbacks when not provided:

- `uuid/guid` → `00000000-0000-4000-8000-000000000000`
- `*id/number/no/seq/version` → `1`
- `code` → `C123`
- `email` → `user@example.com`
- `date` → `2025-01-01`
- other → generic sample values

---

## Plan & Verify

```bash
--plan-only                                 # write apiscan-plan.csv (no requests)
--plan-then-scan                            # build plan first, then perform scan
--verify-plan --success-codes "200-299,304" # live requests -> apiscan-verify.csv
--method-filter GET POST                    # limit HTTP methods
--retry500                                  # adaptive retries on HTTP 5xx
--no-retry-500                              # disable adaptive retries
```

CSV formats:

- **Plan**: `method,url,content_type,body_len,as_json`
- **Verify**: `method,url,status,ms,result`

---

## Recipes

### crAPI exact paths (no sanitizer)

```bash
python apiscan.py --url http://127.0.0.1:8888 \
  --swagger ./archive/crapi-openapi-spec.json \
  --flow token --token "<JWT/refresh>" \
  --no-sanitize \
  --plan-only --verify-plan \
  --proxy http://127.0.0.1:8080
```

### Spec with dotted versions (sanitizer on)

```bash
python apiscan.py --url https://api.acc.example.com \
  --swagger esfinal.json \
  --flow token --token "<JWT>" \
  --normalize-version \
  --plan-only --verify-plan
```

### Rewrite to fix inconsistent spec path

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --rewrite '/v2(?!\.)=>/v2.00' \
  --verify-plan
```

### Customer headers without code changes

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --extra-header "X-JWT-Header: secret...." \
  --extra-header "X-Tenant-ID: acc" \
  --verify-plan
```

### With adaptive retries

```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --flow token --token "<BEARER>" \
  --retry500 \
  --verify-plan
```

---

## Prerequisite: OpenAPI/Swagger file

APISCAN works from an **OpenAPI/Swagger** specification to plan and verify calls.

- If you already have a spec (e.g. `openapi.json`, `swagger.yaml`), pass it to `--swagger`.
- If you only have a **Postman collection**, convert it first.

Example conversion:

```bash
python postman-to-swagger.py \
  --input ./MyCollection.postman_collection.json \
  --output ./openapi.json
```

Then run APISCAN:

```bash
python apiscan.py \
  --url https://api.example.com \
  --swagger ./openapi.json \
  --plan-only --verify-plan
```

---

## Links & Contact

- GitHub: <https://github.com/perrym/apiscanner>  
- Medium: <https://medium.com/@PerryPM/apiscan-a-practical-approach-to-api-security-testing-by-perry-mertens-96b5e676c071>  
- Mail: <mailto:pamsniffer@gmail.com>
