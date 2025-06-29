##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################

import json, requests, time, os
from pathlib import Path
from typing import List, Dict, Any, Optional


def analyze_endpoints_with_gpt(
    endpoints: List[Dict[str, Any]],
    model: str = "gpt-4o",
    temperature: float = 0.5,
    timeout: int = 60,
    port: Optional[int] = None,          # ← NIEUW
    debug: bool = True,
    api_key: Optional[str] = None,          # ← NIEUW
) -> List[Dict[str, Any]]:
    """
    Analyseer een lijst endpoints met ChatGPT.

    Parameters
    ----------
    endpoints : list[dict]
        Elke dict bevat minimaal 'path' en 'method'.
    api_key : str | None
        Optioneel. Als None wordt OPENAI_API_KEY uit de omgeving gebruikt.
    """
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Geen API-sleutel gevonden. "
            "Geef `api_key=` door of zet OPENAI_API_KEY in je environment."
        )

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    summaries: List[Dict[str, Any]] = []
    total = len(endpoints)

    for i, ep in enumerate(endpoints, 1):
        if debug:
            print(f"\n[{i}/{total}] Analyzing: {ep['method']} {ep['path']}")

        prompt = generate_prompt(ep)
        if debug:
            print(prompt.strip())

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert in API security testing and the OWASP "
                        "API Top-10. Your answers are concise and actionable."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }

        try:
            start = time.time()
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            if debug:
                print(content.strip())
            summaries.append({"endpoint": ep, "analysis": content})
        except Exception as exc:
            summaries.append({"endpoint": ep, "analysis": f"[ERROR] {exc}"})

    return summaries

def generate_prompt(endpoint: dict) -> str:
    """
    Generates a prompt to analyze a single API endpoint.
    """
    return f"""
Analyze this API endpoint for OWASP API Top 10 risks such as BOLA, Broken Authentication, Excessive Data Exposure, etc.

Path: {endpoint.get('path')}
Method: {endpoint.get('method')}

Describe:
1. Potential vulnerabilities
2. Abuse scenario
3. Test strategies
4. Risk score (informal / Low / Medium / High)
5. How do you come to this conclusion
"""


def save_ai_summary(summary: list, output_dir, filename: str = "ai_analysis_output.json"):
    output_dir = Path(output_dir)
    output_path = output_dir / filename
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

# Test standalone
if __name__ == "__main__":
    with open("swagger_endpoints.json") as f:
        eps = json.load(f)
    result = analyze_endpoints_with_gpt(eps, model="gpt-4o", debug=True)
    save_ai_summary(result, "./", filename="ai_test_result.json")
