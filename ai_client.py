##############################################
# APISCAN - API Security Scanner             #
# Licensed under the AGPL-V3.0 License             #
# Author: Perry Mertens (C)                  #
##############################################                                              
                                              
import os
import json
import time
import ssl
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urljoin, urlencode, urlparse
import requests
from pathlib import Path
import argparse

"""
# Using a local model on port 1123
export LLM_PROVIDER=local
export LLM_API_BASE=http://localhost
export LLM_API_PORT=1123
export LLM_MODEL=my-local-model

# Using a custom API on a specific port
export LLM_PROVIDER=custom
export LLM_API_BASE=http://api.mycompany.com
export LLM_API_PORT=8080
export LLM_MODEL=company-model
export LLM_API_KEY=your_api_key

# Using DeepSeek with a proxy on a custom port
export LLM_PROVIDER=deepseek
export LLM_API_BASE=https://proxy.example.com
export LLM_API_PORT=8443
export LLM_API_KEY=your_deepseek_api_key
export LLM_MODEL=deepseek-chat

# Using a local Ollama instance
export LLM_PROVIDER=local
export LLM_API_BASE=http://localhost
export LLM_API_PORT=11434
export LLM_MODEL=llama2
"""

                                  
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

SYSTEM_PROMPT = f"""
You are an API security expert specialized in the OWASP API Security Top 10.

Your task is to analyze the given REST endpoint and:
- Identify potential vulnerabilities
- Assign exactly ONE overall risk level

Risk levels:
- Informal = No security implications
- Low      = Minor vulnerability with limited impact
- Medium   = Significant vulnerability requiring attention
- High     = Critical vulnerability needing immediate remediation

Consider only these OWASP API Top 10 categories:
{chr(10).join(OWASP_TOP_10)}

Provide your answer ONLY as valid JSON with these fields:
{{
  "risk": "<Informal|Low|Medium|High>",
  "explanation": "<max 3 sentences, clear and concise>",
  "owasp_category": "<exact OWASP category name>",
  "recommendation": "<secure coding recommendation>",
  "reasoning": "<short step-by-step reasoning>"
}}
""".strip()

             
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai_compat").strip().lower()
MODEL_NAME = os.getenv("LLM_MODEL", "gpt-4o-mini")
API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("DEEPSEEK_API_KEY") or os.getenv("MISTRAL_API_KEY")
API_BASE = os.getenv("LLM_API_BASE", "").rstrip("/")
API_PORT = os.getenv("LLM_API_PORT", "").strip()
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
VERIFY_SSL = os.getenv("LLM_VERIFY_SSL", "true").strip().lower() not in ("0", "false", "no")
CONNECT_TIMEOUT = float(os.getenv("LLM_CONNECT_TIMEOUT", "10"))
READ_TIMEOUT = float(os.getenv("LLM_READ_TIMEOUT", "60"))
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
DEFAULT_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.0"))
DEFAULT_TOP_P = float(os.getenv("LLM_TOP_P", "0.95"))
DEFAULT_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1024"))
USER_AGENT = os.getenv("LLM_USER_AGENT", "apiscan-ai-client/1.0")

                         
PROVIDER_CONFIGS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini"
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat"
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest"
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-3-opus-20240229"
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "default_model": "llama2"
    },
    "azure_openai": {
        "base_url": "",
        "default_model": "gpt-4",
        "api_version": "2024-08-01-preview"
    },
    "openai_compat": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini"
    }
}

def _mask_headers(h: Dict[str, str]) -> Dict[str, str]:
    def mask(v: str) -> str:
        if not v:
            return v
        return (v[:6] + "…") if len(v) > 6 else "…"
    out = {}
    for k, v in h.items():
        lk = k.lower()
        if lk in ("authorization", "cookie", "set-cookie", "x-api-key"):
            out[k] = mask(v)
        else:
            out[k] = v
    return out

def _headers_json(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if extra:
        h.update(extra)
    return h

def _requests_session() -> requests.Session:
    s = requests.Session()
    if not VERIFY_SSL:
        s.verify = False
                              
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s

def _normalize_openai_messages(messages: List[Dict[str, str]], system: Optional[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return messages, system

def _normalize_anthropic_messages(messages: List[Dict[str, str]], system: Optional[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    norm = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            continue
        if role not in ("user", "assistant"):
            role = "user" if role == "tool" else "user"
        norm.append({"role": role, "content": m.get("content", "")})
    return norm, system or ""

def _is_ollama_base(url: str) -> bool:
    return ":11434" in url or url.endswith(":11434")

# ----------------------- Funtion _build_base_url ----------------------------#
def _build_base_url() -> str:
    if LLM_PROVIDER == "azure_openai":
        return AZURE_OPENAI_ENDPOINT
    
                         
    provider_config = PROVIDER_CONFIGS.get(LLM_PROVIDER, PROVIDER_CONFIGS["openai_compat"])
    base_url = provider_config.get("base_url", API_BASE)
    
    if not base_url:
        
        if LLM_PROVIDER == "ollama":
            base_url = "http://localhost:11434"
        elif LLM_PROVIDER == "anthropic":
            base_url = "https://api.anthropic.com"
        else:
            base_url = "https://api.openai.com/v1"
    
    
    if API_PORT and not any(f":{API_PORT}" in base_url for base_url in [base_url, API_BASE]):
       
        parsed = urlparse(base_url)
        if not parsed.port:  
            netloc = f"{parsed.hostname}:{API_PORT}" if parsed.hostname else f":{API_PORT}"
            base_url = base_url.replace(parsed.netloc, netloc)
    
    return base_url.rstrip("/")

# ----------------------- Funtion _openai_compat_chat ----------------------------#
def _openai_compat_chat(messages: List[Dict[str, str]], system: Optional[str], model: str, temperature: float, top_p: float, max_tokens: int) -> str:
    base = _build_base_url()
    endpoint = "chat/completions"
    
                                     
    if LLM_PROVIDER in ["deepseek", "mistral"]:
        endpoint = "chat/completions"
    elif LLM_PROVIDER == "ollama":
        endpoint = "api/chat"
    
    url = urljoin(base + "/", endpoint)
    
                                       
    if LLM_PROVIDER == "ollama":
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": top_p
            }
        }
    else:
        payload = {
            "model": model, 
            "messages": messages, 
            "temperature": temperature, 
            "top_p": top_p, 
            "max_tokens": max_tokens
        }
    
                                       
    headers = _headers_json()
    if LLM_PROVIDER in ["openai", "openai_compat", "deepseek", "mistral"]:
        headers["Authorization"] = f"Bearer {API_KEY}"
    elif LLM_PROVIDER == "anthropic":
        headers["x-api-key"] = API_KEY
        headers["anthropic-version"] = "2023-06-01"
    elif LLM_PROVIDER == "azure_openai":
        headers["api-key"] = API_KEY
    
    with _requests_session() as s:
        r = s.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=VERIFY_SSL)
        r.raise_for_status()
        data = r.json()
    
    
    if LLM_PROVIDER == "ollama":
        return data.get("message", {}).get("content", "") or ""
    elif LLM_PROVIDER == "anthropic":
        content = data.get("content", [])
        if content and isinstance(content, list):
            for part in content:
                if part.get("type") == "text" and "text" in part:
                    return part["text"]
        return ""
    else:
        return data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""

# ----------------------- Funtion _azure_openai_chat ----------------------------#
def _azure_openai_chat(messages: List[Dict[str, str]], system: Optional[str], model: str, temperature: float, top_p: float, max_tokens: int) -> str:
    if not AZURE_OPENAI_ENDPOINT:
        raise RuntimeError("AZURE_OPENAI_ENDPOINT not set")
    
    base = AZURE_OPENAI_ENDPOINT.rstrip("/")
    qs = urlencode({"api-version": AZURE_OPENAI_API_VERSION})
    url = f"{base}/openai/deployments/{model}/chat/completions?{qs}"
    
    payload = {
        "messages": messages, 
        "temperature": temperature, 
        "top_p": top_p, 
        "max_tokens": max_tokens
    }
    
    headers = _headers_json({"api-key": API_KEY} if API_KEY else None)
    
    with _requests_session() as s:
        r = s.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=VERIFY_SSL)
        r.raise_for_status()
        data = r.json()
    
    return data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""

# ----------------------- Funtion _anthropic_chat ----------------------------#
def _anthropic_chat(messages: List[Dict[str, str]], system: Optional[str], model: str, temperature: float, top_p: float, max_tokens: int) -> str:
    base = _build_base_url()
    url = urljoin(base + "/", "v1/messages")
    
    norm_msgs, sys_prompt = _normalize_anthropic_messages(messages, system)
    
    headers = _headers_json({
        "x-api-key": API_KEY or "",
        "anthropic-version": "2023-06-01"
    })
    
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": sys_prompt or "",
        "messages": norm_msgs
    }
    
    with _requests_session() as s:
        r = s.post(url, headers=headers, json=payload, timeout=TIMEOUT, verify=VERIFY_SSL)
        r.raise_for_status()
        data = r.json()
    
    content = data.get("content", [])
    if content and isinstance(content, list):
        for part in content:
            if part.get("type") == "text" and "text" in part:
                return part["text"]
    return ""

# ----------------------- Funtion _ollama_chat ----------------------------#
def _ollama_chat(messages: List[Dict[str, str]], system: Optional[str], model: str, temperature: float, top_p: float, max_tokens: int) -> str:
    return _openai_compat_chat(messages, system, model, temperature, top_p, max_tokens)

# ----------------------- Funtion _extract_json ----------------------------#
def _extract_json(text: str) -> Any:
    if not text:
        return None
    
    t = text.strip()
    
    
    if "```" in t:
        parts = t.split("```")
        for segment in reversed(parts):
            seg = segment.strip()
            if seg.startswith("json"):
                seg = seg[4:].strip()
            
            if seg.startswith("{") and seg.endswith("}"):
                try:
                    return json.loads(seg)
                except Exception:
                    pass
    
  
    try:
        start = t.index("{")
        end = t.rindex("}") + 1
        candidate = t[start:end]
        return json.loads(candidate)
    except Exception:
        pass
    
    
    if t.startswith("{") and t.endswith("}"):
        try:
            return json.loads(t)
        except Exception:
            pass
    
    return None

# ----------------------- Funtion chat_json ----------------------------#
def chat_json(messages: List[Dict[str, str]], system: Optional[str] = None, model: Optional[str] = None, temperature: Optional[float] = None, top_p: Optional[float] = None, max_tokens: Optional[int] = None) -> Any:
    m = model or MODEL_NAME
    temp = DEFAULT_TEMPERATURE if temperature is None else float(temperature)
    tp = DEFAULT_TOP_P if top_p is None else float(top_p)
    mt = DEFAULT_MAX_TOKENS if max_tokens is None else int(max_tokens)

    if LLM_PROVIDER == "azure_openai":
        text = _azure_openai_chat(messages, system, m, temp, tp, mt)
    elif LLM_PROVIDER == "anthropic":
        text = _anthropic_chat(messages, system, m, temp, tp, mt)
    elif LLM_PROVIDER == "ollama":
        text = _ollama_chat(messages, system, m, temp, tp, mt)
    else:
        text = _openai_compat_chat(messages, system, m, temp, tp, mt)

    obj = _extract_json(text)
    return obj if obj is not None else {"raw": text}

# ----------------------- Funtion live_probe ----------------------------#
def live_probe() -> Dict[str, Any]:
    base = _build_base_url()
    info = {
        "provider": LLM_PROVIDER, 
        "base_url": base, 
        "model": MODEL_NAME, 
        "verify_ssl": VERIFY_SSL, 
        "timeout": TIMEOUT
    }
    
    try:
        if LLM_PROVIDER == "azure_openai":
            qs = urlencode({"api-version": AZURE_OPENAI_API_VERSION})
            url = f"{base}/openai/deployments/{MODEL_NAME}/chat/completions?{qs}"
            headers = _headers_json({"api-key": API_KEY or ""})
            body = {"messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}
        elif LLM_PROVIDER == "anthropic":
            url = urljoin(base + "/", "v1/messages")
            headers = _headers_json({
                "x-api-key": API_KEY or "", 
                "anthropic-version": "2023-06-01"
            })
            body = {
                "model": MODEL_NAME, 
                "messages": [{"role": "user", "content": "ping"}], 
                "max_tokens": 1
            }
        elif LLM_PROVIDER == "ollama":
            url = urljoin(base.rstrip("/") + "/", "api/chat")
            headers = _headers_json()
            body = {
                "model": MODEL_NAME, 
                "messages": [{"role": "user", "content": "ping"}], 
                "stream": False
            }
        else:
            url = urljoin(base.rstrip("/") + "/", "chat/completions")
            headers = _headers_json({"Authorization": f"Bearer {API_KEY}"} if API_KEY else None)
            body = {
                "model": MODEL_NAME, 
                "messages": [{"role": "user", "content": "ping"}], 
                "max_tokens": 1
            }

        with _requests_session() as s:
            r = s.post(url, headers=headers, json=body, timeout=TIMEOUT, verify=VERIFY_SSL)
            ok = r.ok
            data = {}
            try:
                data = r.json()
            except Exception:
                data = {"text": r.text[:500]}
            
            return {
                "ok": ok,
                "status_code": r.status_code,
                "url": url,
                "request_headers": _mask_headers(headers),
                "response_headers": _mask_headers(dict(r.headers)),
                "data": data
            }
    except Exception as ex:
        return {"ok": False, "error": str(ex), "info": info}

# ----------------------- Funtion analyze_endpoints_with_llm ----------------------------#
def analyze_endpoints_with_llm(endpoints, live_base_url: str = "", print_results: bool = False, model: str = None):
    results = []
    for ep in endpoints:
        path = ep.get("path", "")
        method = ep.get("method", "").upper()
        user_msg = (
            f"Evaluate endpoint for OWASP API Top 10 risks. "
            f"Base URL: {live_base_url} | Method: {method} | Path: {path}. "
            f"Return a single concise JSON object as specified in the system prompt."
        )
        msgs = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]
        try:
            obj = chat_json(msgs, model=model)  
            if print_results:
                print(f"{method} {path} -> {obj}")
            results.append({"path": path, "method": method, "analysis": obj})
        except Exception as ex:
            results.append({"path": path, "method": method, "error": str(ex)})
    return results

# ----------------------- Funtion save_ai_summary ----------------------------#
def save_ai_summary(results, out_path):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(p)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--system", default="", help="System prompt")
    parser.add_argument("--message", default="Return a JSON object: {\"hello\":\"world\"}", help="User message")
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    msgs = []
    if args.system:
        msgs.append({"role": "system", "content": args.system})
    msgs.append({"role": "user", "content": args.message})
    result = chat_json(msgs, system=args.system, model=args.model)
    print(json.dumps(result, ensure_ascii=False, indent=2))
