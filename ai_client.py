##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################

"""
AI OWASP Scanner Client using OpenAI chat completions with API key authentication only.

Environment variables expected:
  OPENAI_API_KEY  - your OpenAI secret key (required)
  OPENAI_MODEL    - model name, defaults to "gpt-4o"
  OPENAI_API_BASE - custom base URL (optional, default https://api.openai.com/v1)

The script analyses a list of REST endpoints against the OWASP API Security Top 10.
It outputs structured JSON assessments per endpoint.
"""

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union
import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# OpenAI configuration
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("OPENAI_API_KEY")
MODEL_NAME = os.environ.get("OPENAI_MODEL", "gpt-4o")
API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

if not API_KEY:
    raise RuntimeError("Environment variable OPENAI_API_KEY is not set")

client = OpenAI(api_key=API_KEY, base_url=API_BASE)

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
Evaluate the following REST endpoint for vulnerabilities and assign ONE risk label.

Risk levels:
Informal - No security implications
Low      - Minor vulnerability with limited impact
Medium   - Significant vulnerability requiring attention
High     - Critical vulnerability needing immediate remediation

OWASP categories to consider:
{chr(10).join(OWASP_TOP_10)}

Required analysis components:
1. Risk assessment
2. Brief explanation (max 3 sentences)
3. Relevant OWASP category (exact name)
4. Secure coding recommendation
5. Concise reasoning steps

Answer ONLY in valid JSON:
{{
  "risk": "<Informal|Low|Medium|High>",
  "explanation": "",
  "owasp_category": "",
  "recommendation": "",
  "reasoning": ""
}}
""".strip()

LIVE_BASE_URL: Optional[str] = None
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
    m = _JSON_RE.search(text)
    return m.group(1).strip() if m else text.strip()

# ---------------------------------------------------------------------------
# Live probe helper
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
        body_text = resp.text[:200].replace("\n", " ").replace("\r", "")
        return {
            "text": f"{method} {status} ({size} B)\nRequest headers: {headers}\nResponse headers: {dict(resp.headers)}\nResponse body (truncated): {body_text}",
            "request_headers": headers,
            "response_headers": dict(resp.headers),
            "response_body_snippet": body_text,
            "response_body_full": resp.text
        }
    except requests.RequestException as exc:
        return {
            "text": f"{method} ERROR ({exc.__class__.__name__})",
            "request_headers": headers,
            "response_headers": {},
            "response_body_snippet": "",
            "response_body_full": ""
        }

# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------
def _build_prompt(ep: Dict[str, str], live: str) -> str:
    return SYSTEM_PROMPT + f"\n\n### Endpoint\nMethod: {ep['method']}\nPath: {ep['path']}\nLive probe: {live}"

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
            false_positive_likelihood=obj.get("false_positive_likelihood")
        )

# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------
def _analyse_one(self, ep: dict, base_url: str) -> Optional[EndpointAnalysis]:
    """Analyse one endpoint with GPT, now using streaming output."""
    try:
        prompt = self._build_prompt(ep, base_url)
        print(f"\n[SCAN] {ep['method']} {ep['path']}")
        print("=" * 60)

        collected_text = ""

        # Streaming GPT output
        with self.client.chat.completions.stream(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an API security expert specialized in OWASP API Top 10 (2023)."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0,
            top_p=0.05,
            max_tokens=800
        ) as stream:
            for event in stream:
                if event.type == "message.delta" and event.delta.content:
                    print(event.delta.content, end="", flush=True)
                    collected_text += event.delta.content
                elif event.type == "message.completed":
                    print("\n" + "-" * 60)

        # Probeer JSON te extraheren
        try:
            analysis_json = json.loads(extract_json_block(collected_text))
        except json.JSONDecodeError:
            analysis_json = {"raw_text": collected_text.strip()}

        return EndpointAnalysis(
            endpoint=ep,
            analysis=analysis_json,
            timestamp=datetime.utcnow().isoformat()
        )

    except Exception as e:
        print(f"[ERROR] Streaming analysis failed: {e}")
        return EndpointAnalysis(
            endpoint=ep,
            analysis={"error": str(e)},
            timestamp=datetime.utcnow().isoformat()
        )


def analyze_endpoints_with_gpt(endpoints: List[Dict[str, str]], *, live_base_url: Optional[str] = None, print_results: bool = True) -> List[EndpointAnalysis]:
    global LIVE_BASE_URL
    if live_base_url:
        LIVE_BASE_URL = live_base_url.rstrip("/")
    results: List[EndpointAnalysis] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(_analyse_one, ep): ep for ep in endpoints}
        for fut in as_completed(futs):
            results.append(fut.result())
            if print_results:
                logger.info("[%-4s] %-55s => %-8s | %s", results[-1].method, results[-1].path, results[-1].risk, results[-1].owasp_category)
    return results

def save_ai_summary(results: List[EndpointAnalysis], file_path: str | Path):
    with open(file_path, "w", encoding="utf-8") as fp:
        json.dump([asdict(r) for r in results], fp, indent=2)
    logger.info("Saved AI summary %s", file_path)

