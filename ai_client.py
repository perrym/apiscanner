##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
"""
AI-powered API security scanner focused on OWASP API Top 10 vulnerabilities

Main features:
- Uses GPT-4o as default model with OWASP-focused prompts
- Comprehensive error handling with exponential backoff
- Threaded parallel processing
- Detailed vulnerability mapping
"""

import os
import json
import time
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Configure logging
logger = logging.getLogger("apiscan_ai")
logger.setLevel(logging.INFO)

# Enhanced OWASP-focused prompt
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
    "API10: Unsafe Consumption of APIs"
]
# Enhanced OWASP-focused prompt with reasoning guidance
SYSTEM_PROMPT = f"""You are an API security expert specialized in OWASP API Security Top 10. 
Evaluate this REST endpoint for vulnerabilities and assign ONE risk label:

**Risk levels:**
• Informal - No security implications
• Low      - Minor vulnerability with limited impact
• Medium   - Significant vulnerability requiring attention
• High     - Critical vulnerability needing immediate remediation

**OWASP API Top 10 categories to consider:**
{chr(10).join(OWASP_TOP_10)}

**Required analysis components:**
1. Risk assessment
2. Brief explanation (max 3 sentences)
3. Relevant OWASP category (specify exact category name)
4. Secure coding recommendation
5. Concise reasoning steps (explain your thought process)

**Reasoning approach:**
a) Identify endpoint characteristics
b) Map to OWASP categories
c) Consider exploit potential
d) Evaluate impact severity
e) Determine risk level

Answer **ONLY** in valid JSON format:
{{
  "risk": "<Informal|Low|Medium|High>",
  "explanation": "...",
  "owasp_category": "<Exact OWASP category name>",
  "recommendation": "...",
  "reasoning": "Step-by-step analysis..."
}}
"""


@dataclass
class EndpointAnalysis:
    path: str
    method: str
    prompt: str
    response: str
    risk: str
    owasp_category: str
    recommendation: str
    reasoning: str  # Add this new field

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _call_openai(
    endpoint: Dict[str, Any],
    model: str,
    api_key: str,
    timeout: int = 30,
    max_retries: int = 5
) -> EndpointAnalysis:
    """Perform OpenAI API call with OWASP-focused analysis"""
    user_prompt = f"Analyze endpoint: {endpoint.get('method')} {endpoint.get('path')}"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,  # Lower for more deterministic security analysis
        "response_format": {"type": "json_object"}
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    for attempt in range(max_retries):
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            
            # Process response
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            answer = json.loads(content)
            
            return EndpointAnalysis(
                path=endpoint.get("path", ""),
                method=endpoint.get("method", ""),
                prompt=user_prompt,
                response=content,
                risk=answer.get("risk", "Unknown"),
                owasp_category=answer.get("owasp_category", "Not identified"),
                recommendation=answer.get("recommendation", "")
                reasoning=answer.get("reasoning", "")  
            )
            
        except (requests.exceptions.RequestException, json.JSONDecodeError, KeyError) as e:
            wait_time = 2 ** attempt
            if attempt < max_retries - 1:
                logger.warning(f"Retry {attempt+1}/{max_retries} in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
            else:
                logger.error(f"API call failed after {max_retries} attempts: {str(e)}")
                return EndpointAnalysis(
                    path=endpoint.get("path", ""),
                    method=endpoint.get("method", ""),
                    prompt=user_prompt,
                    response="",
                    risk="Error",
                    owasp_category="",
                    recommendation=""
                )

def analyze_endpoints_with_gpt(
    endpoints: List[Dict[str, Any]],
    *,
    model: str = "gpt-4o",
    api_key: Optional[str] = None,
    max_workers: int = 5,
    timeout: int = 45
) -> List[EndpointAnalysis]:
    """Analyze endpoints using OWASP-focused GPT model"""
    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key is required")
    
    logger.info(f"Starting OWASP analysis of {len(endpoints)} endpoints with {model}")
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(
            _call_openai,
            endpoint=ep,
            model=model,
            api_key=api_key,
            timeout=timeout
        ): ep for ep in endpoints}
        
        for future in as_completed(futures):
            ep = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.info(f"Completed: {result.method} {result.path} => {result.risk}")
            except Exception as e:
                logger.error(f"Analysis failed for {ep.get('method')} {ep.get('path')}: {str(e)}")
    
    logger.info(f"Completed AI analysis of {len(results)} endpoints")
    return results

def save_ai_summary(
    analyses: Sequence[EndpointAnalysis],
    output_dir: Path,
    filename: str = "ai_analysis_report.json"
) -> Path:
    """Save OWASP-focused analysis results"""
    output_path = output_dir / filename
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in analyses], f, indent=2, ensure_ascii=False)
    
    logger.info(f"Saved OWASP analysis report to {output_path}")
    return output_path