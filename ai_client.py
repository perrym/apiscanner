"""
AI OWASP Scanner Client using OpenAI ChatCompletion with API key authentication only.

Environment variables expected:
  OPENAI_API_KEY  - your OpenAI secret key (required)
  OPENAI_MODEL    - model name, defaults to "gpt-4o"
  OPENAI_API_BASE - custom base URL (optional, default https://api.openai.com/v1)

The script analyses a list of REST endpoints against the OWASP API Security Top 10.
It outputs structured JSON assessments per endpoint.
"""
from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

import openai
import requests

# ---------------------------------------------------------------------------
# OpenAI configuration- API-key only
# ---------------------------------------------------------------------------
API_KEY = "sk-..."  
MODEL_NAME = "gpt-4o"
API_BASE = "https://api.openai.com/v1"
openai.api_key = API_KEY
# ---------------------------------------------------------------------------
# Scanner settings
# ---------------------------------------------------------------------------
OWASP_TOP_10 = [
    "API1: Broken Object Level Authorization",
    "API2: Broken Authentication",
    "API3: Broken Object Property Level Authorization",
    "API4: Unrestricted Resource Consumption",
    "API5: Broken Function Level Authorization",
    "API6: Unrestricted Access to Sensitive Business Flows",
    "API7: Server Side Request Forgery",
    "API8: Security Misconfiguration",
    "API9: Improper Inventory Management",
    "API10: Unsafe Consumption of APIs",
]

SYSTEM_PROMPT = f"""You are an API security expert specialised in the OWASP API Security Top 10.
Evaluate the following REST endpoint for vulnerabilities and assign **ONE** risk label.

**Risk levels**
Informal - No security implications
Low      - Minor vulnerability with limited impact
Medium   - Significant vulnerability requiring attention
High     - Critical vulnerability needing immediate remediation

**OWASP categories to consider**
{chr(10).join(OWASP_TOP_10)}

**Required analysis components**
1. Risk assessment
2. Brief explanation (max 3 sentences)
3. Relevant OWASP category (exact name)
4. Secure coding recommendation
5. Concise reasoning steps (your thought process)

Answer **ONLY** in **valid JSON**:
{{
  "risk": "<Informal|Low|Medium|High>",
  "explanation": "",
  "owasp_category": "",
  "recommendation": "",
  "reasoning": ""
}}
""".strip()

LIVE_BASE_URL: Optional[str] = None  # Injected by caller if live probing is desired
LIVE_TIMEOUT = 4
MAX_WORKERS = 5

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Utility regex helpers
# ---------------------------------------------------------------------------
_JSON_RE = re.compile(r"""```json\s*({[\s\S]*?})\s*```""", re.IGNORECASE)

def extract_json_block(text: str) -> str:
    """Return the JSON block from an LLM response or the raw text when parsing fails."""
    m = _JSON_RE.search(text)
    return m.group(1).strip() if m else text.strip()

# ---------------------------------------------------------------------------
# Live probe helper (optional)
# ---------------------------------------------------------------------------

def _live_probe(ep: Dict[str, str]) -> Dict[str, object]:
    if LIVE_BASE_URL is None:
        return {"text": "no live probe"}

    method = ep.get("method", "GET").upper()
    path = re.sub(r"\{[^/]+\}", "1", ep.get("path", "/"))
    url = LIVE_BASE_URL.rstrip("/") + path

    headers = {
        "Accept": "application/json",
        "User-Agent": "apiscan-client",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.request(method, url, timeout=LIVE_TIMEOUT, headers=headers, verify=False)
        status = resp.status_code
        size = len(resp.content)

        try:
            body_text = resp.text
            body_snippet = body_text[:200].replace("\n", " ").replace("\r", "")
        except Exception:
            body_text = "[[BINARY OR NON-UTF8 RESPONSE]]"
            body_snippet = body_text

        text_summary = (
            f"{method} {status} ({size} B)\n"
            f"Request headers: {'; '.join(f'{k}: {v}' for k, v in headers.items())}\n"
            f"Response headers: {'; '.join(f'{k}: {v}' for k, v in resp.headers.items())}\n"
            f"Response body (truncated): {body_snippet}"
        )

        return {
            "text": text_summary,
            "request_headers": headers,
            "response_headers": dict(resp.headers),
            "response_body_snippet": body_snippet,
            "response_body_full": body_text,
        }

    except requests.RequestException as exc:
        return {
            "text": f"{method} ERROR ({exc.__class__.__name__})",
            "request_headers": headers,
            "response_headers": {},
            "response_body_snippet": "",
            "response_body_full": "",
        }

# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(ep: Dict[str, str], live: str) -> str:
    return (
        SYSTEM_PROMPT
        + f"\n\n### Endpoint\nMethod: {ep['method']}\nPath: {ep['path']}\nLive probe: {live}"
    )

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EndpointAnalysis:
    path: str
    method: str
    risk: str
    explanation: str
    owasp_category: str
    recommendation: str
    reasoning: str
    request_headers: Optional[Dict[str, str]] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body_snippet: Optional[str] = None
    response_body_full: Optional[str] = None
    false_positive_likelihood: Optional[str] = None

    @classmethod
    def from_gpt(cls, ep: Dict[str, str], obj: Dict[str, Union[str, dict, list]]) -> "EndpointAnalysis":
        def _to_str(v):
            if isinstance(v, dict):
                return v.get("level") or v.get("value") or json.dumps(v)
            if isinstance(v, (list, tuple)):
                return ", ".join(map(str, v))
            return str(v) if v is not None else "Unknown"

        fp_likelihood = obj.get("false_positive_likelihood")

        return cls(
            path=ep["path"],
            method=ep["method"],
            risk=_to_str(obj.get("risk")),
            explanation=_to_str(obj.get("explanation")),
            owasp_category=_to_str(obj.get("owasp_category")),
            recommendation=_to_str(obj.get("recommendation")),
            reasoning=_to_str(obj.get("reasoning")),
            request_headers=obj.get("request_headers"),
            response_headers=obj.get("response_headers"),
            response_body_snippet=obj.get("response_body_snippet"),
            response_body_full=obj.get("response_body_full"),
            false_positive_likelihood=fp_likelihood,
        )

# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------

def _analyse_one(ep: Dict[str, str]) -> EndpointAnalysis:
    print(f"\U0001F50E Scanning: {ep['method']} {ep['path']}")

    live_info = _live_probe(ep)
    prompt = _build_prompt(ep, live_info["text"])

    resp = openai.ChatCompletion.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are ChatGPT."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=512,
        request_timeout=60,
    )

    content = resp["choices"][0]["message"]["content"]

    try:
        data = json.loads(extract_json_block(content))
    except json.JSONDecodeError:
        logger.warning("GPT returned non-JSON for %s %s", ep["method"], ep["path"])
        data = {}

    data.update({
        "request_headers": live_info.get("request_headers"),
        "response_headers": live_info.get("response_headers"),
        "response_body_snippet": live_info.get("response_body_snippet"),
        "response_body_full": live_info.get("response_body_full"),
    })

    explanation_text = data.get("explanation", "").lower()
    fp_keywords = ["appears to", "may", "possibly", "could", "unclear", "not confirmed"]

    if any(k in explanation_text for k in fp_keywords) and data.get("risk", "").lower() in ["medium", "low"]:
        data["false_positive_likelihood"] = "possible"

    return EndpointAnalysis.from_gpt(ep, data)

# ---------------------------------------------------------------------------
# Helper functions for multi-endpoint scans
# ---------------------------------------------------------------------------

def _lvl(val):
    return str(val).lower()

def _print_progress(r: EndpointAnalysis):
    logger.info("[%-4s] %-55s => %-8s | %s", r.method, r.path, r.risk, r.owasp_category)

def _print_final(res: List[EndpointAnalysis]):
    hi = sum(1 for r in res if _lvl(r.risk).startswith("high"))
    med = sum(1 for r in res if _lvl(r.risk).startswith("medium"))
    lo = len(res) - hi - med
    logger.info("Finished- High: %d  Medium: %d  Low: %d", hi, med, lo)

def analyze_endpoints_with_gpt(
    endpoints: List[Dict[str, str]],
    *,
    live_base_url: Optional[str] = None,
    print_results: bool = True,
) -> List[EndpointAnalysis]:
    """Scan endpoints concurrently and return EndpointAnalysis objects."""
    global LIVE_BASE_URL
    if live_base_url:
        LIVE_BASE_URL = live_base_url.rstrip("/")

    results: List[EndpointAnalysis] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(_analyse_one, ep): ep for ep in endpoints}
        for fut in as_completed(futs):
            results.append(fut.result())
            if print_results:
                _print_progress(results[-1])

    if print_results:
        _print_final(results)
    return results

def save_ai_summary(results: List[EndpointAnalysis], file_path: str | Path):
    """Save the analysis list as pretty-printed JSON."""
    with open(file_path, "w", encoding="utf-8") as fp:
        json.dump([asdict(r) for r in results], fp, indent=2)
    logger.info("Saved AI summary  %s", file_path)

# ---------------------------------------------------------------------------
# __main__ helper- simple CLI example
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, sys, textwrap

    parser = argparse.ArgumentParser(
        description="Scan REST endpoints for OWASP API Top 10 risks using OpenAI GPT-4o.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Example usage:
              export OPENAI_API_KEY=sk-
              python ai_client_api_key.py \
                 --endpoints '{"method": "GET", "path": "/users/{id}"}' \
                 --live-base-url https://api.example.com
            """,
        ),
    )
    parser.add_argument("--endpoints", required=True, help="JSON list or file with endpoint dicts")
    parser.add_argument("--live-base-url", help="Base URL for live probing")
    parser.add_argument("--out", default="ai_summary.json", help="Output JSON file path")
    args = parser.parse_args()

    # Load endpoints from JSON string or file path
    if os.path.isfile(args.endpoints):
        with open(args.endpoints, "r", encoding="utf-8") as fh:
            endpoints = json.load(fh)
    else:
        endpoints = json.loads(args.endpoints)

    results = analyze_endpoints_with_gpt(endpoints, live_base_url=args.live_base_url)
    save_ai_summary(results, args.out)
    sys.exit(0)
