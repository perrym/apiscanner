########################################################
# APISCAN - AI Security Scanner Module                 #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 3.2.2 - Enhanced with structured classes     #
########################################################

import os
import json
import time
import re
import html
import logging
import asyncio
import aiohttp
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple, Optional, Literal, TypedDict, Union
from urllib.parse import urljoin, urlencode, urlparse
import requests
from pathlib import Path
import argparse
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import warnings
import sqlite3


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if os.getenv("LLM_VERIFY_SSL", "true").strip().lower() in ("0", "false", "no"):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ==================== ENUMERATIONS ====================

class RiskLevel(str, Enum):
    INFORMAL = "Informal"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

class LLMProvider(str, Enum):
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    MISTRAL = "mistral"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"
    OLLAMA = "ollama"
    AZURE_OPENAI = "azure_openai"
    OPENAI_COMPAT = "openai_compat"
    LOCAL = "local"
    CUSTOM = "custom"

# ==================== TYPED DICT MODELS ====================

class AnalysisResult(TypedDict):
    risk: RiskLevel
    explanation: str
    owasp_category: str
    recommendation: str
    reasoning: str
    confidence: Optional[float]
    cvss_score: Optional[float]

class EndpointDefinition(TypedDict, total=False):
    path: str
    method: HTTPMethod
    params: Optional[Dict[str, Any]]
    json: Optional[Any]
    headers: Optional[Dict[str, str]]
    path_params: Optional[Dict[str, str]]
    allow_unsafe: bool
    description: Optional[str]
    tags: Optional[List[str]]

class ScanConfig(TypedDict, total=False):
    base_url: str
    enable_live_scan: bool
    safe_mode: bool
    compare_auth: bool
    rate_limit: Optional[float]
    timeout: Optional[float]
    follow_redirects: bool
    max_response_size: int
    max_workers: int

# ==================== DATA CLASSES ====================

@dataclass
class ProbeResult:
    url: str
    method: str
    status_code: int
    elapsed_ms: int
    request_headers: Dict[str, str]
    response_headers: Dict[str, str]
    response_text: str
    response_size: int
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

@dataclass
class ScanResult:
    endpoint: EndpointDefinition
    analysis: Optional[AnalysisResult]
    probe: Optional[ProbeResult]
    probes_auth_comparison: Optional[List[ProbeResult]]
    error: Optional[str]
    skipped: bool = False
    skip_reason: Optional[str] = None
    scan_duration: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)

# ==================== CONSTANTS ====================

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
- Provide a confidence score (0.0-1.0)
- Optional CVSS score if applicable

Risk levels:
- Informal = No security implications
- Low = Minor vulnerability with limited impact
- Medium = Significant vulnerability requiring attention
- High = Critical vulnerability needing immediate remediation

Consider only these OWASP API Top 10 categories:
{chr(10).join(OWASP_TOP_10)}

Provide your answer ONLY as valid JSON with these fields:
{{
  "risk": "<Informal|Low|Medium|High>",
  "explanation": "<max 3 sentences, clear and concise>",
  "owasp_category": "<exact OWASP category name>",
  "recommendation": "<secure coding recommendation>",
  "reasoning": "<short step-by-step reasoning>",
  "confidence": <float between 0.0 and 1.0>,
  "cvss_score": <optional float between 0.0 and 10.0>
}}
""".strip()

# ==================== CONFIGURATION CLASSES ====================

class LLMConfig:
    """Configuration for LLM connections"""
    
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "openai_compat").strip().lower()
        self.model = os.getenv("LLM_MODEL", "gpt-4o")
        self.api_key = self._collect_api_key()
        self.api_base = os.getenv("LLM_API_BASE", "").rstrip("/")
        self.api_port = os.getenv("LLM_API_PORT", "").strip()
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.0"))
        self.top_p = float(os.getenv("LLM_TOP_P", "0.95"))
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "1024"))
        self.prompt_header_chars = int(os.getenv("LLM_PROMPT_HEADER_CHARS", "1200"))
        self.prompt_body_chars = int(os.getenv("LLM_PROMPT_BODY_CHARS", "2000"))
        self.prompt_noauth_chars = int(os.getenv("LLM_PROMPT_NOAUTH_CHARS", "1000"))
        self.prompt_max_chars = int(os.getenv("LLM_PROMPT_MAX_CHARS", "4500"))
        self.timeout_connect = float(os.getenv("LLM_CONNECT_TIMEOUT", "10"))
        self.timeout_read = float(os.getenv("LLM_READ_TIMEOUT", "20"))
        self.verify_ssl = os.getenv("LLM_VERIFY_SSL", "true").strip().lower() not in ("0", "false", "no")
        self.user_agent = os.getenv("LLM_USER_AGENT", "apiscan-ai-client/4.0")
        self.azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
        self.azure_api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "2"))
        self.cache_ttl = 300  # 5 minutes
    
    def _collect_api_key(self):
        """Collect API key from various environment variables"""
        env_vars = [
            "LLM_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AZURE_OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "MISTRAL_API_KEY",
            "GEMINI_API_KEY",
            "OPENROUTER_API_KEY"
        ]
        
        for env_var in env_vars:
            key = os.getenv(env_var)
            if key:
                return key
        return None
    
    @property
    def timeout(self) -> Tuple[float, float]:
        return (self.timeout_connect, self.timeout_read)
#############################################################
# change code by your self , when you have beter LLM models #
#############################################################
PROVIDER_CONFIGS = {
    LLMProvider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "endpoint": "chat/completions"
    },
    LLMProvider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "endpoint": "chat/completions"
    },
    LLMProvider.MISTRAL: {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest",
        "endpoint": "chat/completions"
    },
    LLMProvider.ANTHROPIC: {
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-3-7-sonnet-latest",
        "endpoint": "v1/messages"
    },
    LLMProvider.GEMINI: {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.5-flash",
        "endpoint": "chat/completions"
    },
    LLMProvider.OPENROUTER: {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o",
        "endpoint": "chat/completions"
    },
    LLMProvider.OLLAMA: {
        "base_url": "http://localhost:11434",
        "default_model": "llama3.2",
        "endpoint": "api/chat"
    },
    LLMProvider.OPENAI_COMPAT: {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "endpoint": "chat/completions"
    }
}

MODEL_ALIASES = {
    # Common aliases users type for ChatGPT 4o
    "chatgpt 4o": "gpt-4o",
    "chatgpt-4o": "gpt-4o",
    "gpt4o": "gpt-4o",
    "gpt 4o": "gpt-4o",
    # Common aliases users type for GPT-5.3
    "chatgpt 53": "gpt-5.3",
    "chatgpt-53": "gpt-5.3",
    "gpt53": "gpt-5.3",
    "gpt-53": "gpt-5.3",
    "gpt 53": "gpt-5.3",
    # Common aliases users type for DeepSeek
    "deepseek": "deepseek-chat",
    "deepseek chat": "deepseek-chat",
    "deepseek-chat": "deepseek-chat",
    "deepseek v3": "deepseek-chat",
    "deepseek-v3": "deepseek-chat",
    "deepseek r1": "deepseek-reasoner",
    "deepseek-r1": "deepseek-reasoner",
    "r1": "deepseek-reasoner",
}

# ==================== CORE CLASSES ====================

class LLMClient:
    """Client for interacting with various LLM providers"""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.cache = TTLCache(maxsize=100, ttl=self.config.cache_ttl) if self.config.cache_ttl > 0 else None
        self._thread_local = threading.local()
        self._cache_lock = threading.RLock()
        self._async_session = None
        
    def _get_session(self) -> requests.Session:
        """Get or create a thread-local requests session."""
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            if not self.config.verify_ssl:
                session.verify = False
            self._thread_local.session = session
        return session

    @staticmethod
    def _normalize_model_name(model: str) -> str:
        """Normalize user-friendly model aliases to provider model IDs."""
        if not model:
            return model
        normalized = model.strip()
        key = normalized.lower()
        return MODEL_ALIASES.get(key, normalized)
    
    def _build_base_url(self) -> str:
        """Build the base URL for API requests"""
        if self.config.provider == "azure_openai":
            return self.config.azure_endpoint

        try:
            provider_enum = LLMProvider(self.config.provider)
        except ValueError:
            provider_enum = LLMProvider.OPENAI_COMPAT
        
        provider_config = PROVIDER_CONFIGS.get(
            provider_enum,
            PROVIDER_CONFIGS[LLMProvider.OPENAI_COMPAT]
        )
        
        base_url = self.config.api_base or provider_config.get("base_url", "")
        
        if not base_url:
            # Set default based on provider
            if self.config.provider == "ollama":
                base_url = "http://localhost:11434"
            elif self.config.provider == "anthropic":
                base_url = "https://api.anthropic.com"
            else:
                base_url = "https://api.openai.com/v1"
        
        # Add port if specified
        if self.config.api_port:
            parsed = urlparse(base_url)
            if not parsed.port:
                netloc = f"{parsed.hostname}:{self.config.api_port}" if parsed.hostname else f":{self.config.api_port}"
                base_url = base_url.replace(parsed.netloc, netloc)
        
        return base_url.rstrip("/")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API request"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": self.config.user_agent
        }
        
        if self.config.api_key:
            if self.config.provider == "azure_openai":
                headers["api-key"] = self.config.api_key
            elif self.config.provider == "anthropic":
                headers["x-api-key"] = self.config.api_key
                headers["anthropic-version"] = "2023-06-01"
            elif self.config.provider in ["openai", "openai_compat", "deepseek", "mistral", "gemini", "openrouter"]:
                headers["Authorization"] = f"Bearer {self.config.api_key}"

        # Optional metadata headers recommended by OpenRouter.
        if self.config.provider == "openrouter":
            referer = os.getenv("OPENROUTER_HTTP_REFERER", "").strip()
            title = os.getenv("OPENROUTER_X_TITLE", "").strip()
            if referer:
                headers["HTTP-Referer"] = referer
            if title:
                headers["X-Title"] = title
        
        return headers
    
    def _get_endpoint_url(self, model: str) -> str:
        """Get the endpoint URL for the API request"""
        base_url = self._build_base_url()
        
        if self.config.provider == "azure_openai":
            endpoint = f"openai/deployments/{model}/chat/completions"
            qs = urlencode({"api-version": self.config.azure_api_version})
            return f"{base_url}/{endpoint}?{qs}"
        elif self.config.provider == "anthropic":
            return f"{base_url}/v1/messages"
        elif self.config.provider == "ollama":
            return f"{base_url}/api/chat"
        else:
            return f"{base_url}/chat/completions"
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type((requests.exceptions.ConnectionError,
                                      requests.exceptions.Timeout))
    )
    def chat(self, messages: List[Dict[str, str]], system: Optional[str] = None,
             model: Optional[str] = None, temperature: Optional[float] = None,
             top_p: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
        """
        Send a chat request to the LLM
        """
        model = self._normalize_model_name(model or self.config.model)
        temperature = self.config.temperature if temperature is None else temperature
        top_p = self.config.top_p if top_p is None else top_p
        max_tokens = self.config.max_tokens if max_tokens is None else max_tokens
        
        # Create cache key
        cache_key = None
        if self.cache is not None:
            cache_data = {
                "messages": messages,
                "system": system,
                "model": model,
                "temperature": temperature,
                "top_p": top_p,
                "max_tokens": max_tokens
            }
            cache_key = hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()

            with self._cache_lock:
                if cache_key in self.cache:
                    logger.debug("Cache hit for LLM request")
                    return self.cache[cache_key]
        
        url = self._get_endpoint_url(model)
        headers = self._get_headers()
        
        # Prepare payload based on provider
        if self.config.provider == "ollama":
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature, "top_p": top_p}
            }
        elif self.config.provider == "anthropic":
            payload = {
                "model": model,
                "messages": messages,
                "system": system or "",
                "max_tokens": max_tokens,
                "temperature": temperature
            }
        else:
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "top_p": top_p,
                "max_tokens": max_tokens
            }
            
            if system and self.config.provider != "anthropic":
                payload["messages"] = [{"role": "system", "content": system}] + messages
        
        session = self._get_session()
        try:
            response = session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            response.raise_for_status()
            data = response.json()
            
            # Extract response based on provider
            if self.config.provider == "ollama":
                result = data.get("message", {}).get("content", "") or ""
            elif self.config.provider == "anthropic":
                content = data.get("content", [])
                if content and isinstance(content, list):
                    for part in content:
                        if part.get("type") == "text" and "text" in part:
                            result = part["text"]
                            break
                    else:
                        result = ""
                else:
                    result = ""
            else:
                result = data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""

                # Fallback for non-standard OpenAI-compatible providers.
                if not result:
                    result = data.get("output_text", "") or ""
            
            # Cache result
            if cache_key and self.cache is not None:
                with self._cache_lock:
                    self.cache[cache_key] = result
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"LLM request failed: {e}")
            raise
    
    def chat_json(self, messages: List[Dict[str, str]], system: Optional[str] = None,
                  model: Optional[str] = None, temperature: Optional[float] = None,
                  top_p: Optional[float] = None, max_tokens: Optional[int] = None) -> Any:
        """
        Send chat request and parse JSON response
        """
        response = self.chat(messages, system, model, temperature, top_p, max_tokens)
        return self._parse_json_response(response)
    
    def _parse_json_response(self, text: str) -> Any:
        """Parse JSON from LLM response text"""
        if not text:
            return None
        
        text = text.strip()
        
        
        if "```" in text:
            parts = text.split("```")
            for segment in reversed(parts):
                seg = segment.strip()
                if seg.startswith("json"):
                    seg = seg[4:].strip()
                if seg.startswith("{") and seg.endswith("}"):
                    try:
                        return json.loads(seg)
                    except json.JSONDecodeError:
                        continue
        
        
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            candidate = text[start:end]
            return json.loads(candidate)
        except (ValueError, json.JSONDecodeError):
            pass
        
       
        if text.startswith("{") and text.endswith("}"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        
        return {"raw": text}
    
    def test_connection(self) -> Dict[str, Any]:
        base_url = self._build_base_url()
        info = {
            "provider": self.config.provider,
            "base_url": base_url,
            "model": self.config.model,
            "verify_ssl": self.config.verify_ssl,
            "timeout": self.config.timeout
        }

        try:
            if self.config.provider == "ollama":
                session = self._get_session()
                response = session.get(
                    f"{base_url}/api/tags",
                    timeout=(self.config.timeout_connect, 10),
                    verify=self.config.verify_ssl
                )
                response.raise_for_status()
                return {
                    "ok": True,
                    "response": "Ollama API reachable",
                    "info": info
                }

            messages = [{"role": "user", "content": "ping"}]
            response = self.chat(messages, max_tokens=10)

            return {
                "ok": True,
                "response": response[:100] if response else "",
                "info": info
            }
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                "ok": False,
                "error": str(e),
                "info": info
            }

# ==================== REPORT GENERATOR CLASS ====================

class AIReportGenerator:
    """Generate reports from AI scan results using the existing report system"""
    
    @staticmethod
    def convert_to_legacy_format(scan_results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Convert ScanResult objects to legacy format for report_utils"""
        legacy_results = []
        
        for result in scan_results:
            if result.skipped:
                continue
                
            # Build basic issue dict
            issue = {
                "method": result.endpoint.get("method", "GET"),
                "endpoint": result.endpoint.get("path", ""),
                "url": result.probe.url if result.probe else result.endpoint.get("path", ""),
                "description": result.analysis.get("explanation", "") if result.analysis else "No analysis available",
                "category": result.analysis.get("owasp_category", "") if result.analysis else "",
                "risk_key": result.analysis.get("owasp_category", "").split(":")[0] if result.analysis and ":" in result.analysis.get("owasp_category", "") else "",
            }
            
            
            risk_map = {
                "Informal": "Info",
                "Low": "Low", 
                "Medium": "Medium",
                "High": "Critical" 
            }
            
            if result.analysis:
                ai_risk = result.analysis.get("risk", "Informal")
                issue["severity"] = risk_map.get(ai_risk, "Info")
            else:
                issue["severity"] = "Info"
            
            
            if result.probe:
                issue.update({
                    "status_code": result.probe.status_code,
                    "request_headers": result.probe.request_headers,
                    "response_headers": result.probe.response_headers,
                    "response_body": result.probe.response_text,
                    "timestamp": result.timestamp.isoformat(),
                })
                
                
                request_data = {
                    "method": result.endpoint.get("method", "GET"),
                    "url": result.probe.url,
                    "headers": result.probe.request_headers,
                }
                
               
                if result.endpoint.get("json"):
                    request_data["body"] = json.dumps(result.endpoint.get("json"), indent=2)
                
                issue["request"] = request_data
            
           
            if result.analysis:
                issue["analysis_details"] = dict(result.analysis)
                issue["recommendation"] = result.analysis.get("recommendation", "")
                issue["confidence"] = result.analysis.get("confidence", 0.0)
            
            legacy_results.append(issue)
        
        return legacy_results
    
    @staticmethod
    def generate_html_report(scan_results: List[ScanResult], scanner_name: str = "AI Security Scanner", 
                           base_url: str = "", output_path: Union[str, Path] = None) -> str:
        """Generate HTML report using EnhancedReportGenerator"""
        
        try:
            
            from report_utils import EnhancedReportGenerator
                       
            legacy_issues = AIReportGenerator.convert_to_legacy_format(scan_results)
                      
            filtered_issues = [issue for issue in legacy_issues]
            
            report_gen = EnhancedReportGenerator(
                issues=filtered_issues,
                scanner=scanner_name,
                base_url=base_url,
                drop_http0=False  
            )
            
            
            html_report = report_gen.generate_html()
            
            
            if output_path:
                output_path = Path(output_path)
                report_gen.save(output_path)
                logger.info(f"HTML report saved to {output_path}")
            
            return html_report
            
        except ImportError as e:
            logger.error(f"Could not import EnhancedReportGenerator: {e}")
            
            return AIReportGenerator._generate_simple_html(scan_results, scanner_name, base_url, output_path)
    
    @staticmethod
    def _generate_simple_html(scan_results: List[ScanResult], scanner_name: str, 
                            base_url: str, output_path: Union[str, Path] = None) -> str:
        """Fallback simple HTML generator"""
        esc = lambda v: html.escape(str(v), quote=True)

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{esc(scanner_name)} Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .risk-high {{ background-color: #ffebee; border-left: 5px solid #f44336; }}
                .risk-medium {{ background-color: #fff3e0; border-left: 5px solid #ff9800; }}
                .risk-low {{ background-color: #e8f5e8; border-left: 5px solid #4caf50; }}
                .risk-info {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; }}
                .meta {{ color: #666; font-size: 0.9em; }}
                pre {{ background: #f5f5f5; padding: 10px; overflow: auto; }}
            </style>
        </head>
        <body>
            <h1>{esc(scanner_name)} Report</h1>
            <p><strong>Base URL:</strong> {esc(base_url or 'N/A')}</p>
            <p><strong>Generated:</strong> {esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
            <p><strong>Total Findings:</strong> {len(scan_results)}</p>
        """
        
        for result in scan_results:
            if result.skipped:
                continue
                
            risk_class = "risk-info"
            if result.analysis:
                risk = result.analysis.get("risk", "Informal").lower()
                if risk == "high":
                    risk_class = "risk-high"
                elif risk == "medium":
                    risk_class = "risk-medium"
                elif risk == "low":
                    risk_class = "risk-low"
            
            html_content += f"""
            <div class="finding {risk_class}">
                <h3>{esc(result.endpoint.get('method', 'GET'))} {esc(result.endpoint.get('path', ''))}</h3>
                <div class="meta">
                    <p><strong>Status:</strong> {esc(result.probe.status_code if result.probe else 'N/A')}</p>
                    <p><strong>Risk:</strong> {esc(result.analysis.get('risk', 'N/A') if result.analysis else 'N/A')}</p>
                    <p><strong>OWASP Category:</strong> {esc(result.analysis.get('owasp_category', 'N/A') if result.analysis else 'N/A')}</p>
                </div>
                <p><strong>Explanation:</strong> {esc(result.analysis.get('explanation', 'No analysis') if result.analysis else 'No analysis')}</p>
                <p><strong>Recommendation:</strong> {esc(result.analysis.get('recommendation', 'N/A') if result.analysis else 'N/A')}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        if output_path:
            output_path = Path(output_path)
            output_path.write_text(html_content, encoding='utf-8')
            logger.info(f"Simple HTML report saved to {output_path}")
        
        return html_content
    
    @staticmethod
    def save_to_sqlite(scan_results: List[ScanResult], db_path: Union[str, Path], 
                      run_id: str = None) -> Path:
        """Save AI scan results to SQLite database for use with build_review.py"""
        
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        if run_id is None:
            run_id = f"ai_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS finding (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    risk_key TEXT,
                    title TEXT,
                    description TEXT,
                    category TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'open',
                    method TEXT,
                    endpoint TEXT,
                    req_headers TEXT,
                    req_body TEXT,
                    res_headers TEXT,
                    res_body TEXT,
                    res_status INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS endpoint (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    method TEXT,
                    url TEXT,
                    max_severity TEXT,
                    last_status INTEGER,
                    last_ms INTEGER,
                    count_ok INTEGER DEFAULT 0,
                    count_fail INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP
                )
            """)
            
            
            for result in scan_results:
                if result.skipped:
                    continue
                
               
                method = result.endpoint.get("method", "GET")
                endpoint_path = result.endpoint.get("path", "")
                title = f"{method} {endpoint_path}"
                
                if result.analysis:
                    description = result.analysis.get("explanation", "")
                    category = result.analysis.get("owasp_category", "")
                    
                    
                    risk_map = {
                        "Informal": "info",
                        "Low": "low", 
                        "Medium": "medium",
                        "High": "critical"
                    }
                    ai_risk = result.analysis.get("risk", "Informal")
                    severity = risk_map.get(ai_risk, "info")
                    
                    risk_key = category.split(":")[0] if ":" in category else ""
                else:
                    description = "No analysis available"
                    category = "Unknown"
                    severity = "info"
                    risk_key = ""
                
                
                req_headers = json.dumps(result.probe.request_headers) if result.probe else "{}"
                res_headers = json.dumps(result.probe.response_headers) if result.probe else "{}"
                res_body = result.probe.response_text[:10000] if result.probe else ""  # Limit size
                res_status = result.probe.status_code if result.probe else 0
                
               
                conn.execute("""
                    INSERT INTO finding 
                    (run_id, risk_key, title, description, category, severity, status, 
                     method, endpoint, req_headers, req_body, res_headers, res_body, res_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id, risk_key, title, description, category, severity, 'confirmed',
                    method, endpoint_path, req_headers, "", res_headers, res_body, res_status
                ))
                
               
                if result.probe:
                    url = result.probe.url
                    is_success = 200 <= result.probe.status_code < 300
                    
                    # Check if endpoint exists
                    cursor = conn.execute(
                        "SELECT * FROM endpoint WHERE run_id = ? AND method = ? AND url = ?",
                        (run_id, method, url)
                    )
                    
                    if cursor.fetchone():
                        
                        if is_success:
                            conn.execute("""
                                UPDATE endpoint 
                                SET last_status = ?, last_ms = ?, count_ok = count_ok + 1,
                                    max_severity = CASE
                                        WHEN (CASE max_severity
                                            WHEN 'critical' THEN 4
                                            WHEN 'medium' THEN 3
                                            WHEN 'low' THEN 2
                                            ELSE 1
                                        END) >= (CASE ?
                                            WHEN 'critical' THEN 4
                                            WHEN 'medium' THEN 3
                                            WHEN 'low' THEN 2
                                            ELSE 1
                                        END)
                                        THEN max_severity
                                        ELSE ?
                                    END,
                                    last_seen = CURRENT_TIMESTAMP
                                WHERE run_id = ? AND method = ? AND url = ?
                            """, (res_status, result.probe.elapsed_ms, severity, severity, run_id, method, url))
                        else:
                            conn.execute("""
                                UPDATE endpoint 
                                SET last_status = ?, last_ms = ?, count_fail = count_fail + 1,
                                    max_severity = CASE
                                        WHEN (CASE max_severity
                                            WHEN 'critical' THEN 4
                                            WHEN 'medium' THEN 3
                                            WHEN 'low' THEN 2
                                            ELSE 1
                                        END) >= (CASE ?
                                            WHEN 'critical' THEN 4
                                            WHEN 'medium' THEN 3
                                            WHEN 'low' THEN 2
                                            ELSE 1
                                        END)
                                        THEN max_severity
                                        ELSE ?
                                    END,
                                    last_seen = CURRENT_TIMESTAMP
                                WHERE run_id = ? AND method = ? AND url = ?
                            """, (res_status, result.probe.elapsed_ms, severity, severity, run_id, method, url))
                    else:
                        
                        conn.execute("""
                            INSERT INTO endpoint 
                            (run_id, method, url, max_severity, last_status, last_ms, 
                             count_ok, count_fail, first_seen, last_seen)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (
                            run_id, method, url, severity, res_status, result.probe.elapsed_ms,
                            1 if is_success else 0, 0 if is_success else 1
                        ))
            
            conn.commit()
        
        logger.info(f"AI scan results saved to SQLite database: {db_path}")
        return db_path
    
    @staticmethod
    def generate_review_report(scan_results: List[ScanResult], output_dir: Union[str, Path],
                             template_path: Union[str, Path] = None, run_id: str = None) -> Path:
        """Generate complete review report using build_review.py system"""
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        db_path = output_dir / "ai_scan.db"
        AIReportGenerator.save_to_sqlite(scan_results, db_path, run_id)
        try:
            from build_review import build_review
            
            html_path = output_dir / "ai_review.html"
            html_path = build_review(
                db_path=db_path,
                out_path=html_path,
                template=template_path,
                run_id=run_id
            )
            
            logger.info(f"Review report generated: {html_path}")
            return html_path
            
        except ImportError as e:
            logger.error(f"Could not import build_review: {e}")
            logger.info("Falling back to direct HTML generation")
            html_path = output_dir / "ai_report.html"
            base_url = scan_results[0].probe.url if scan_results and scan_results[0].probe else ""
            html_content = AIReportGenerator.generate_html_report(
                scan_results, 
                scanner_name="AI Security Scanner",
                base_url=base_url
            )
            
            html_path.write_text(html_content, encoding='utf-8')
            return html_path

# ==================== MAIN SCANNER CLASS ====================

class APIScanner:
    """Main API security scanner class"""
    
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self._scan_cache = TTLCache(maxsize=50, ttl=3600)  
        self.report_generator = AIReportGenerator()  
    
    def _mask_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive headers in output"""
        def mask(value: str) -> str:
            if not value:
                return value
            if len(value) > 8:
                return value[:4] + "..." + value[-4:]
            return "***"
        
        masked = {}
        sensitive_keys = ["authorization", "cookie", "set-cookie", "x-api-key", "api-key"]
        
        for key, value in headers.items():
            if key.lower() in sensitive_keys:
                masked[key] = mask(value)
            else:
                masked[key] = value
        
        return masked
    
    def _parse_headers_env(self) -> Dict[str, str]:
        """Parse headers from environment variables"""
        headers = {}
        
        # JSON headers
        json_headers = os.getenv("APISCAN_HEADERS_JSON", "").strip()
        if json_headers:
            try:
                obj = json.loads(json_headers)
                if isinstance(obj, dict):
                    headers.update({str(k): str(v) for k, v in obj.items()})
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse APISCAN_HEADERS_JSON: {e}")
        
        # Bearer token
        bearer = os.getenv("APISCAN_AUTH_BEARER", "").strip()
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"
        
        # API key
        api_key = os.getenv("APISCAN_API_KEY", "").strip()
        if api_key and "x-api-key" not in {k.lower() for k in headers}:
            headers["x-api-key"] = api_key
        
        return headers

    @staticmethod
    def _example_from_parameter(param: Dict[str, Any]) -> Optional[str]:
        """Extract a concrete path value from Swagger/OpenAPI parameter metadata."""
        schema = param.get("schema") or {}
        candidates = [
            param.get("example"),
            schema.get("example"),
            schema.get("default"),
        ]
        enum_values = schema.get("enum") or param.get("enum") or []
        if enum_values:
            candidates.append(enum_values[0])

        for candidate in candidates:
            if candidate is not None:
                return str(candidate)

        ptype = str(schema.get("type") or param.get("type") or "string").lower()
        pformat = str(schema.get("format") or param.get("format") or "").lower()
        if ptype == "integer":
            return "1"
        if ptype == "number":
            return "1.0"
        if ptype == "boolean":
            return "true"
        if pformat == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return None

    def _resolve_path_params(self, endpoint: EndpointDefinition) -> Dict[str, str]:
        """Resolve path params from explicit endpoint data or Swagger/OpenAPI parameters."""
        resolved: Dict[str, str] = {}

        explicit = endpoint.get("path_params")
        if explicit:
            resolved.update({str(key): str(value) for key, value in explicit.items()})

        parameters = endpoint.get("parameters")
        if isinstance(parameters, list):
            for param in parameters:
                if not isinstance(param, dict) or param.get("in") != "path":
                    continue
                name = str(param.get("name") or "").strip()
                if not name or name in resolved:
                    continue
                value = self._example_from_parameter(param)
                if value is not None:
                    resolved[name] = value

        return resolved
    
    def _fill_path_params(self, path: str, placeholders: Optional[Dict[str, str]] = None) -> str:
        """Fill path parameters with safe values"""
        if not path or "{" not in path:
            return path
        
        defaults = {
            "id": "1",
            "userId": "1",
            "accountId": "1",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "token": "test_token",
            "slug": "test-slug",
            "name": "test"
        }
        
        if placeholders:
            defaults.update(placeholders)
        
        def replace(match):
            key = match.group(1)
            return defaults.get(key, "1")
        
        return re.sub(r"\{([^}]+)\}", replace, path)
    
    def _is_unsafe_method(self, method: str) -> bool:
        """Check if HTTP method is potentially unsafe"""
        unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
        return method.upper() in unsafe_methods
    
    def probe_endpoint(self, session: requests.Session, base_url: str, method: str,
                       path: str, headers: Optional[Dict[str, str]] = None,
                       params: Optional[Dict[str, Any]] = None,
                       json_body: Optional[Any] = None,
                       timeout: Optional[Tuple[float, float]] = None,
                       max_size: int = 10 * 1024 * 1024) -> ProbeResult:
        """Probe a single endpoint"""
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        
        req_headers = {"User-Agent": self.llm.config.user_agent}
        if headers:
            req_headers.update(headers)
        
        start_time = time.time()
        
        try:
            response = session.request(
                method=method.upper(),
                url=url,
                headers=req_headers if req_headers else None,
                params=params,
                json=json_body,
                timeout=timeout or self.llm.config.timeout,
                allow_redirects=False,
                verify=self.llm.config.verify_ssl
            )
            
           
            response_text = ""
            if response.content:
                if len(response.content) > max_size:
                    response_text = f"[Response too large: {len(response.content)} bytes, truncated]"
                else:
                    response_text = response.text[:max_size]
            
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            return ProbeResult(
                url=url,
                method=method.upper(),
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                request_headers=self._mask_headers(dict(response.request.headers)),
                response_headers=self._mask_headers(dict(response.headers)),
                response_text=response_text,
                response_size=len(response.content) if response.content else 0
            )
            
        except requests.exceptions.RequestException as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Probe failed for {method} {url}: {e}")
            
            return ProbeResult(
                url=url,
                method=method.upper(),
                status_code=0,
                elapsed_ms=elapsed_ms,
                request_headers=self._mask_headers(req_headers),
                response_headers={},
                response_text=str(e),
                response_size=0
            )
    
    def analyze_endpoint(self, endpoint: EndpointDefinition,
                        scan_config: ScanConfig) -> ScanResult:
        """
        Analyze a single endpoint for security vulnerabilities
        """
        start_time = time.time()
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        path_params = self._resolve_path_params(endpoint)
        filled_path = self._fill_path_params(path, path_params)
        endpoint_label = self._format_endpoint_label(endpoint)

        logger.info(f"AI scanning endpoint: {endpoint_label}")

        if (scan_config.get("safe_mode", True) and 
            self._is_unsafe_method(method) and 
            not endpoint.get("allow_unsafe", False)):
            
            return ScanResult(
                endpoint=endpoint,
                analysis=None,
                probe=None,
                probes_auth_comparison=None,
                error=None,
                skipped=True,
                skip_reason="safe_mode_blocked_unsafe_method",
                scan_duration=time.time() - start_time
            )
        env_headers = self._parse_headers_env()
        endpoint_headers = endpoint.get("headers")
        if endpoint_headers is None:
            endpoint_headers = {}
        merged_headers = {**env_headers, **endpoint_headers}
        
        probes = []
        probes_auth_comparison = []
        error = None
       
        if scan_config.get("enable_live_scan", True) and scan_config.get("base_url"):
            try:
                session = self.llm._get_session()
                probe = self.probe_endpoint(
                    session=session,
                    base_url=scan_config["base_url"],
                    method=method,
                    path=filled_path,
                    headers=merged_headers if merged_headers else None,
                    params=endpoint.get("params"),
                    json_body=endpoint.get("json"),
                    timeout=scan_config.get("timeout")
                )
                probes.append(probe)
                compare_auth = scan_config.get("compare_auth")
                if compare_auth is None:
                    compare_auth = os.getenv("APISCAN_COMPARE_AUTH", "false").strip().lower() in ("1", "true", "yes")

                if compare_auth and merged_headers:
                    stripped_headers = dict(merged_headers)
                    sensitive = ["authorization", "cookie", "x-api-key", "api-key"]
                    
                    for key in list(stripped_headers.keys()):
                        if key.lower() in sensitive:
                            stripped_headers.pop(key, None)
                    
                    if len(stripped_headers) < len(merged_headers):
                        probe_noauth = self.probe_endpoint(
                            session=session,
                            base_url=scan_config["base_url"],
                            method=method,
                            path=filled_path,
                            headers=stripped_headers if stripped_headers else None,
                            params=endpoint.get("params"),
                            json_body=endpoint.get("json"),
                            timeout=scan_config.get("timeout")
                        )
                        probes_auth_comparison.append(probe_noauth)
                
            except Exception as e:
                error = f"Probe failed: {str(e)}"
                logger.error(f"Probe failed for {method} {path}: {e}")
        
        analysis = None
        if not error:
            try:
                user_prompt = self._build_analysis_prompt(
                    endpoint, 
                    probes[0] if probes else None,
                    probes_auth_comparison[0] if probes_auth_comparison else None,
                    scan_config
                )
                
                messages = [
                    {"role": "user", "content": user_prompt}
                ]
                
                result = self.llm.chat_json(messages, system=SYSTEM_PROMPT)
                if isinstance(result, dict):
                    analysis = self._validate_analysis_result(result)
                
            except Exception as e:
                error = f"Analysis failed: {str(e)}"
                logger.error(f"Analysis failed for {method} {path}: {e}")
        
        return ScanResult(
            endpoint=endpoint,
            analysis=analysis,
            probe=probes[0] if probes else None,
            probes_auth_comparison=probes_auth_comparison,
            error=error,
            scan_duration=time.time() - start_time
        )

    def _format_endpoint_label(self, endpoint: EndpointDefinition) -> str:
        """Create a short readable label for progress and logs."""
        method = str(endpoint.get("method", "GET") or "GET").upper()
        path = self._fill_path_params(
            str(endpoint.get("path", "") or ""),
            self._resolve_path_params(endpoint)
        )
        return f"{method} {path}".strip()
    
    def _build_analysis_prompt(self, endpoint: EndpointDefinition,
                              probe: Optional[ProbeResult],
                              probe_noauth: Optional[ProbeResult],
                              scan_config: ScanConfig) -> str:
        """Build analysis prompt for LLM"""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        base_url = scan_config.get("base_url", "")
        
        if probe:
            # Provider-agnostic truncation to keep prompts within model context budgets.
            header_limit = max(200, self.llm.config.prompt_header_chars)
            body_limit = max(200, self.llm.config.prompt_body_chars)
            noauth_limit = max(120, self.llm.config.prompt_noauth_chars)
            total_limit = max(1000, self.llm.config.prompt_max_chars)

            compact_headers = json.dumps(probe.response_headers, indent=2)[:header_limit]

            prompt_prefix = [
                "Analyze this observed API interaction for OWASP API Top 10 (2023) risks.",
                "Use evidence only. If evidence is insufficient, say so explicitly.",
                "",
                f"Method: {method}",
                f"Path: {path}",
                f"URL: {probe.url}",
                f"Status: {probe.status_code}",
                f"Response Time: {probe.elapsed_ms}ms",
                f"Response Size: {probe.response_size} bytes",
                "",
                "Response Headers:",
                compact_headers,
                "",
                "Response Body (truncated):",
            ]

            prompt_static = "\n".join(prompt_prefix)
            remaining = max(240, total_limit - len(prompt_static) - 16)

            if probe_noauth:
                body_budget = max(160, int(remaining * 0.7))
                noauth_budget = max(80, remaining - body_budget)
            else:
                body_budget = remaining
                noauth_budget = 0

            body_text = probe.response_text[:min(body_limit, body_budget)]

            prompt = prompt_prefix + [body_text]
            
            if probe_noauth:
                noauth_text = probe_noauth.response_text[:min(noauth_limit, noauth_budget)]
                prompt.extend([
                    "",
                    "=== AUTHENTICATION COMPARISON ===",
                    f"Status without auth: {probe_noauth.status_code}",
                    f"Response without auth (truncated):",
                    noauth_text
                ])

            final_prompt = "\n".join(prompt)
            if len(final_prompt) > total_limit:
                final_prompt = final_prompt[:total_limit]

            return final_prompt
        else:
            return (
                f"Evaluate endpoint for OWASP API Top 10 (2023) risks. "
                f"Base URL: {base_url} | Method: {method} | Path: {path}. "
                f"Provide a security analysis based on common vulnerabilities for this type of endpoint."
            )
    
    def _validate_analysis_result(self, result: Dict[str, Any]) -> Optional[AnalysisResult]:
        """Validate and normalize analysis result from LLM"""
        try:
            required = ["risk", "explanation", "owasp_category", "recommendation", "reasoning"]
            
            for field in required:
                if field not in result:
                    logger.warning(f"Missing required field in analysis: {field}")
                    return None
            valid_risks = [r.value for r in RiskLevel]
            if result["risk"] not in valid_risks:
                risk_lower = result["risk"].lower()
                for valid in valid_risks:
                    if valid.lower() == risk_lower:
                        result["risk"] = valid
                        break
                else:
                    result["risk"] = RiskLevel.LOW.value  # Default
            
            # Ensure OWASP category is valid
            valid_categories = OWASP_TOP_10
            if result["owasp_category"] not in valid_categories:
                # Find closest match
                for category in valid_categories:
                    if category.lower() in result["owasp_category"].lower():
                        result["owasp_category"] = category
                        break
            
            # Validate confidence
            confidence = result.get("confidence")
            if confidence is not None:
                try:
                    confidence = float(confidence)
                    if confidence < 0 or confidence > 1:
                        confidence = 0.5
                    result["confidence"] = confidence
                except (ValueError, TypeError):
                    result["confidence"] = 0.5
            
            # Validate CVSS score
            cvss = result.get("cvss_score")
            if cvss is not None:
                try:
                    cvss = float(cvss)
                    if cvss < 0 or cvss > 10:
                        cvss = None
                    result["cvss_score"] = cvss
                except (ValueError, TypeError):
                    result["cvss_score"] = None
            
            return AnalysisResult(**result)
            
        except Exception as e:
            logger.error(f"Failed to validate analysis result: {e}")
            return None
    
    def scan(self, endpoints: List[EndpointDefinition],
            scan_config: ScanConfig) -> List[ScanResult]:
        """
        Scan multiple endpoints
        """
        results = []
        
        
        rate_limit = scan_config.get("rate_limit")
        if rate_limit is not None:
            try:
                rate_limit = float(rate_limit)
                if rate_limit <= 0:
                    logger.warning("Invalid rate_limit <= 0 provided; disabling rate limiting")
                    rate_limit = None
            except (ValueError, TypeError):
                logger.warning("Invalid rate_limit value provided; disabling rate limiting")
                rate_limit = None
        # change this for faster device 
        max_workers = scan_config.get("max_workers", int(os.getenv("APISCAN_MAX_WORKERS", "1")))
        try:
            max_workers = int(max_workers)
        except (ValueError, TypeError):
            logger.warning("Invalid max_workers value provided; falling back to 1")
            max_workers = 1
        if max_workers < 1:
            max_workers = 1
        
        try:
            from tqdm import tqdm
            show_progress = True
        except ImportError:
            show_progress = False
            logger.info("Starting AI scan...")

        # Default path: keep deterministic single-thread flow.
        if max_workers == 1:
            progress_iter = (
                tqdm(endpoints, desc="AI Scanning", unit="endpoint") if show_progress else endpoints
            )
            for index, endpoint in enumerate(progress_iter):
                if show_progress and hasattr(progress_iter, "set_postfix_str"):
                    progress_iter.set_postfix_str(self._format_endpoint_label(endpoint), refresh=True)
                if rate_limit and index > 0:
                    time.sleep(1.0 / rate_limit)
                result = self.analyze_endpoint(endpoint, scan_config)
                results.append(result)
            return results

        logger.info(f"Using multithreaded scan with max_workers={max_workers}")

        indexed_results: List[Optional[ScanResult]] = [None] * len(endpoints)
        progress = tqdm(total=len(endpoints), desc="AI Scanning", unit="endpoint") if show_progress else None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {}
            for index, endpoint in enumerate(endpoints):
                if rate_limit and index > 0:
                    time.sleep(1.0 / rate_limit)
                future = executor.submit(self.analyze_endpoint, endpoint, scan_config)
                future_to_index[future] = index

            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    indexed_results[index] = future.result()
                except Exception as e:
                    ep = endpoints[index]
                    method = ep.get("method", "GET")
                    path = ep.get("path", "")
                    logger.error(f"Unhandled scan error for {method} {path}: {e}")
                    indexed_results[index] = ScanResult(
                        endpoint=ep,
                        analysis=None,
                        probe=None,
                        probes_auth_comparison=None,
                        error=f"Unhandled scan error: {e}",
                        skipped=False
                    )
                if progress is not None:
                    progress.update(1)

        if progress is not None:
            progress.close()

        results = [r for r in indexed_results if r is not None]
        
        return results
    
    def generate_report(self, results: List[ScanResult], format: str = "html", 
                       output_path: Optional[Union[str, Path]] = None,
                       base_url: str = "") -> Union[str, Path]:
        """
        Generate report from scan results
        
        Args:
            results: List of ScanResult objects
            format: Report format ("html", "review", or "sqlite")
            output_path: Path to save report (optional)
            base_url: Base URL for the report
            
        Returns:
            Report content as string or path to saved file
        """
        if not results:
            logger.warning("No results to generate report from")
            return ""
        
        if format.lower() == "html":
            # Generate HTML using EnhancedReportGenerator
            scanner_name = "AI Security Scanner v4.0"
            
            if not base_url and results[0].probe:
                # Extract base URL from first probe
                from urllib.parse import urlparse
                parsed = urlparse(results[0].probe.url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            html_content = AIReportGenerator.generate_html_report(
                results, scanner_name, base_url
            )
            
            if output_path:
                output_path = Path(output_path)
                output_path.write_text(html_content, encoding='utf-8')
                return output_path
            return html_content
            
        elif format.lower() == "review":
            # Generate full review report with build_review.py
            if not output_path:
                output_path = Path.cwd() / "ai_review_output"
            
            return AIReportGenerator.generate_review_report(
                scan_results=results,
                output_dir=output_path,
                template_path=None,  # Use default template
                run_id=f"ai_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
        elif format.lower() == "sqlite":
            # Just save to SQLite database
            if not output_path:
                output_path = Path.cwd() / "ai_scan.db"
            
            return AIReportGenerator.save_to_sqlite(
                results, output_path
            )
            
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def scan_with_report(self, endpoints: List[EndpointDefinition],
                        scan_config: ScanConfig,
                        report_format: str = "html",
                        output_path: Optional[Union[str, Path]] = None) -> Tuple[List[ScanResult], Union[str, Path]]:
        """
        Scan endpoints and generate report in one call
        
        Returns:
            Tuple of (scan_results, report_path_or_content)
        """
        # Perform scan
        scan_results = self.scan(endpoints, scan_config)
        
        # Generate report
        report = self.generate_report(
            results=scan_results,
            format=report_format,
            output_path=output_path,
            base_url=scan_config.get("base_url", "")
        )
        
        return scan_results, report

# ==================== UTILITY FUNCTIONS ====================

def save_report(report: Union[Dict[str, Any], str], output_path: str):
    """Save report to file"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    if isinstance(report, dict):
        content = json.dumps(report, ensure_ascii=False, indent=2)
    else:
        content = str(report)
    
    path.write_text(content, encoding='utf-8')
    logger.info(f"Report saved to {output_path}")

# ==================== BACKWARDS COMPATIBILITY ====================
########################################################
# BACKWARDS COMPATIBILITY FOR EXISTING APISCAN SETUP
# This keeps older code working with the new architecture
########################################################

# Singletons
_default_llm = LLMClient()
_default_scanner = APIScanner(_default_llm)


def live_probe():
    """Backwards compatible LLM connection test."""
    return _default_llm.test_connection()


def chat_json(messages, system=None, model=None, temperature=None, top_p=None, max_tokens=None):
    """Legacy wrapper so old imports still work."""
    return _default_llm.chat_json(
        messages,
        system=system,
        model=model,
        temperature=temperature,
        top_p=top_p,
        max_tokens=max_tokens,
    )


def analyze_endpoints_with_llm(
    endpoints,
    live_base_url=None,
    print_results=False,
    model=None,
    enable_live_scan=True,
    safe_mode=True,
    compare_auth=True,
    generate_report=False,
    report_output=None
):
    """
    Legacy wrapper for APISCAN v3.x / v3.1 compatibility.
    Now includes optional report generation.
    """
    scan_config = {
        "base_url": live_base_url or "",
        "enable_live_scan": enable_live_scan and bool(live_base_url),
        "safe_mode": safe_mode,
        "compare_auth": compare_auth,
        "max_workers": int(os.getenv("APISCAN_MAX_WORKERS", "6")),
    }

    # Normalize endpoints
    items = []
    for ep in endpoints:
        method = ep.get("method", "GET")
        path_params = ep.get("path_params")
        parameters = ep.get("parameters")
        items.append({
            "path": ep.get("path"),
            "method": method,
            "allow_unsafe": ep.get("allow_unsafe", False),
            "headers": ep.get("headers", {}),  # Changed from None to {}
            "params": ep.get("params", None),
            "json": ep.get("json", None),
            "path_params": path_params if isinstance(path_params, dict) else None,
            "parameters": parameters if isinstance(parameters, list) else None,
        })

    results = _default_scanner.scan(items, scan_config)

    output = []
    for r in results:
        legacy = {
            "path": r.endpoint.get("path"),
            "method": r.endpoint.get("method"),
            "analysis": dict(r.analysis) if r.analysis else None,
            "error": r.error,
            "skipped": r.skipped,
        }
        if print_results:
            risk = (legacy.get("analysis") or {}).get("risk")
            print(f"[AI] {legacy['method']} {legacy['path']} -> {risk or 'n/a'}")
        output.append(legacy)
    
    # Generate report if requested
    if generate_report:
        if not report_output:
            report_output = Path.cwd() / "ai_scan_report.html"
        
        report_path = _default_scanner.generate_report(
            results=results,
            format="html",
            output_path=report_output,
            base_url=live_base_url or ""
        )
        
        if print_results:
            print(f"[AI] Report generated: {report_path}")

    return output


def save_ai_summary(results, output_path):
    """Legacy-format report writer"""
    from pathlib import Path

    if isinstance(output_path, Path):
        output_path = str(output_path)

    report = {
        "scan_date": str(datetime.now()),
        "count": len(results),
        "results": results,
    }

    save_report(report, output_path)
    
    return output_path


# ==================== MAIN ENTRY POINT ====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--system", default="", help="System prompt")
    parser.add_argument("--message", default="Return a JSON object: {\"hello\":\"world\"}", help="User message")
    parser.add_argument("--model", default=None)
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument("--output", default="ai_report.html", help="Output file for report")
    parser.add_argument("--scan", action="store_true", help="Perform actual scan")
    parser.add_argument("--endpoints", default="endpoints.json", help="JSON file with endpoints to scan")
    parser.add_argument("--base-url", default="", help="Base URL for scanning")
    args = parser.parse_args()
    
    if args.scan:
        # Perform actual scan
        try:
            with open(args.endpoints, 'r') as f:
                endpoints_data = json.load(f)
            
            scanner = APIScanner()
            scan_config = {
                "base_url": args.base_url,
                "enable_live_scan": bool(args.base_url),
                "safe_mode": True,
                "compare_auth": os.getenv("APISCAN_COMPARE_AUTH", "false").strip().lower() in ("1", "true", "yes"),
                "max_workers": int(os.getenv("APISCAN_MAX_WORKERS", "6"))
            }
            
            results = scanner.scan(endpoints_data, scan_config)
            
            if args.report:
                report_path = scanner.generate_report(
                    results=results,
                    format="html",
                    output_path=args.output,
                    base_url=args.base_url
                )
                print(f"Scan completed. Report generated: {report_path}")
            else:
                print(f"Scan completed. {len(results)} endpoints analyzed.")
                for result in results:
                    if result.analysis:
                        print(f"{result.endpoint.get('method')} {result.endpoint.get('path')}: {result.analysis.get('risk')} - {result.analysis.get('owasp_category')}")
                    
        except Exception as e:
            print(f"Error during scan: {e}")
            import traceback
            traceback.print_exc()
    
    else:
        # Simple chat mode
        msgs = []
        msgs.append({"role": "user", "content": args.message})
        
        result = chat_json(msgs, system=args.system, model=args.model)
        
        if args.report:
            # For demo: maak een dummy scan resultaat
            dummy_result = ScanResult(
                endpoint={"path": "/test", "method": "GET"},
                analysis={
                    "risk": "Medium",
                    "explanation": "Test vulnerability found",
                    "owasp_category": "API1: Broken Object Level Authorization",
                    "recommendation": "Implement proper authorization checks",
                    "reasoning": "Test reasoning",
                    "confidence": 0.8
                },
                probe=ProbeResult(
                    url="http://example.com/test",
                    method="GET",
                    status_code=200,
                    elapsed_ms=150,
                    request_headers={"User-Agent": "test"},
                    response_headers={"Content-Type": "application/json"},
                    response_text='{"test": "data"}',
                    response_size=100
                ),
                error=None,
                skipped=False
            )
            
            scanner = APIScanner()
            scanner.generate_report(
                results=[dummy_result],
                format="html",
                output_path=args.output
            )
            print(f"Demo report generated: {args.output}")
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))

