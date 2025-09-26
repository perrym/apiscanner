# APISCAN  OWASP API Security Scanner by Perry Mertens pamsniffer@gmail.com 2025 (c)
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">

**Version:** 1.1 (Release)  
**Author:** Perry Mertens ([pamsniffer@gmail.com](mailto:pamsniffer@gmail.com))  
**License:** MIT


[![GitHub](https://img.shields.io/badge/GitHub-perrym%2Fapiscanner-0ea5e9?logo=github)](https://github.com/perrym/apiscanner)
[![Medium](https://img.shields.io/badge/Medium-Article-black?logo=medium)](https://medium.com/@PerryPM/apiscan-a-practical-approach-to-api-security-testing-by-perry-mertens-96b5e676c071)

APISCAN is a free, extensible scanner for the **OWASP API Security Top 10 (2023)**. It understands **OpenAPI/Swagger**, supports **multiauth**, offers a **plan/verify** workflow, **generic sanitizer/rewrites**, and writes **CSV/HTML** artifacts. This is the **generic**, customeragnostic documentation.

---

## Whats New in v1.1
- **Generic sanitizer** (no hardcodes): collapse duplicate segments, normalize `/vN  /vN.00`, trim trailing slash. Toggle with `--no-sanitize`; refine with `--rewrite "pat=>rep"`.
- **Universal header overrides**: `--flow token --token`, `--apikey --apikey-header`, `--extra-header`, `--headers-file headers.json`. Spec `example/default` values are autoapplied.
- **IDs & path variables**: `--ids-file ids.json` to control `{param}`; robust fallbacks for uuid/id/code/email/date when missing.
- **Plan/Verify**: `--plan-only`  `apiscan-plan.csv`; `--verify-plan`  sends real requests and writes `apiscan-verify.csv`.
- **Method filter**: `--method-filter GET POST` to limit the set.
- **Rewrite trace (tip)**: add a small print in `_apply_rewrites` to see exactly which URLs changed during debugging.

---

##  Install
```bash
python -m venv .venv && . .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
```

---

##  Quick Start
```bash
# Verify with Bearer token
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --flow token --token <BEARER> --verify-plan

# Plan + Verify + CSV
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --flow token --token <BEARER> \
  --plan-only --verify-plan --success-codes "200-299,304"

# Proxy & self-signed lab
python apiscan.py --url https://api.example.com \
  --swagger openapi.json --flow token --token <BEARER> \
  --proxy 127.0.0.1:8080 --insecure --plan-only --verify-plan
```

---

##  Headers (generic)
```bash
# Bearer
--flow token --token "<JWT>"   # -> Authorization: Bearer <JWT>

# API key header
--apikey "secret" --apikey-header x-api-key

# Multiple custom headers (repeatable)
--extra-header "x-jwt-header: secret..." \
--extra-header "x-tenant-id: acc"

# From JSON file
# headers.json => { "x-jwt-header":"secret...", "x-tenant-id":"acc" }
--headers-file headers.json
```
> Spec header parameters with `example/default` are auto-filled. `Content-Length` is never set manually.

---

##  Sanitizer & Rewrites
Builtin sanitizer (enabled by default) will:
- collapse `//` (excluding scheme),
- normalize `/v2`  `/v2.00` (if not dotted),
- fold repeats (`/A/A``/A`, `/A/B/A``/A/B`),
- remove trailing slash (except root).

Control it:
```bash
--no-sanitize                              # exact paths (e.g., crAPI)
--rewrite '/identity/api/v2(?=/)/=>/identity/api/v7/'  # targeted path change
```
**PowerShell tip:** use **single quotes** around the rewrite string to avoid `>` being interpreted.

Optional debug trace (during development), in `_apply_rewrites`:
```python
new_url = re.sub(pat, rep, full_url)
if new_url != full_url:
    print(f"[rewrite] {pat!r} => {rep!r} :: {full_url} -> {new_url}")
```

---

##  Path Variables & IDs
```bash
# ids.json
{ "userId":"me", "orderId":1, "vin":"11119401" }

--ids-file ids.json
```
Fallbacks (when not provided):
- `uuid/guid`  `00000000-0000-4000-8000-000000000000`
- `*id/number/no/seq/version`  `1`
- `code`  `C123`
- `email`  `user@example.com`
- `date`  `2025-01-01`
- other  `sample`

---

##  Plan & Verify
```bash
--plan-only                                 # write apiscan-plan.csv (no requests)
--verify-plan --success-codes "200-299,304" # live requests  apiscan-verify.csv
--method-filter GET POST                    # limit methods
```
**CSV formats**
- Plan: `method,url,content_type,body_len,as_json`
- Verify: `method,url,status,ms,result`

---

##  Recipes
**crAPI exact paths (no sanitizer):**
```bash
python apiscan.py --url http://127.0.0.1:8888 \
  --swagger ./archive/crapi-openapi-spec.json \
  --flow token --token "<JWT/refresh>" \
  --no-sanitize --plan-only --verify-plan \
  --proxy 127.0.0.1:8080
```

**Spec with dotted versions (sanitizer ON):**
```bash
python apiscan.py --url https://api.acc.example.com \
  --swagger openai.json \
  --flow token --token "<JWT>" \
  --plan-only --verify-plan
```

**Rewrite to fix inconsistent spec path:**
```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --rewrite '/v2(?!\.)=>/v2.00' \
  --verify-plan
```

**Customer headers without code changes:**
```bash
python apiscan.py --url https://api.example.com \
  --swagger openapi.json \
  --extra-header "x-jwt-header: secret...." \
  --extra-header "x-tenant-id: acc" \
  --verify-plan
```

---

##  Troubleshooting
- **404 everywhere**  `--no-sanitize` or add pathspecific `--rewrite`. Verify final paths in your proxy.
- **401 / 403**  expired/invalid token or missing headers. Confirm headers via proxy.
- **400 / 422**  invalid body; ensure `requestBody` `example` exists so APISCAN builds a valid payload.
- **Rewrite not applied**  single quotes in PowerShell; use pathspecific pattern; enable the trace snippet above.

---
## Disclaimer

## APISCAN is a private and proprietary API security tool, developed independently for internal use and research purposes.
## It supports OWASP API Security Top 10 (2023) testing, OpenAPI-based analysis, active scanning, and multi-format reporting.
## Redistribution is not permitted without explicit permission.

## Important: Testing with APISCAN is only permitted on systems and APIs for which you have explicit authorization. Unauthorized testing is strictly prohibited.

---

##  Links
- GitHub: <https://github.com/perrym/apiscanner>  
- Medium: <https://medium.com/@PerryPM/apiscan-a-practical-approach-to-api-security-testing-by-perry-mertens-96b5e676c071>  
- Contact: <mailto:pamsniffer@gmail.com>

>Perry Mertens 2025 (C)