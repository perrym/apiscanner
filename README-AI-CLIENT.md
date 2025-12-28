# APISCAN AI Client 3.1 release by Perry Mertens pamsniffer@gmail.com 2025 (C)
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">
APISCAN sends real requests to your API, gathers evidence, and uses an AI model to classify risks based on the OWASP API Top 10. 
It’s built for security specialists who need verifiable, evidence-based findings rather than theoretical guesses.

Supports:

- **OpenAI-compatible APIs** (`/chat/completions`)
- **Azure OpenAI**
- **Anthropic Claude**
- **Ollama** (local models)

---

## Features

- Works with multiple LLM providers using the same interface  
- Lightweight — no heavy SDKs, only `requests`  
- JSON in → JSON out (safe for automation pipelines)  
- Secrets masked in logs, TLS and timeouts configurable  

---

## Installation

Clone the repository and place `ai_client.py` in your project:

```bash
pip install requests
```

No other dependencies required.

---

## Configuration

Set environment variables to select a provider and credentials:

| Variable                     | Description                                  | Default                 |
|------------------------------|----------------------------------------------|--------------------------|
| `LLM_PROVIDER`               | `openai_compat`, `azure_openai`, `anthropic`, `ollama` | `openai_compat` |
| `LLM_MODEL`                  | Model/deployment name                         | `gpt-4o-mini`            |
| `LLM_API_KEY`                | API key (or `OPENAI_API_KEY`, `AZURE_OPENAI_API_KEY`, etc.) | — |
| `LLM_API_BASE`               | Custom base URL (optional)                   | —                        |
| `LLM_API_PORT`               | Optional port to append to base              | —                        |
| `AZURE_OPENAI_ENDPOINT`      | Azure endpoint                               | —                        |
| `AZURE_OPENAI_API_VERSION`   | Azure API version                            | `2024-08-01-preview`     |
| `LLM_VERIFY_SSL`              | Verify TLS certs (`true` / `false`)          | `true`                   |
| `LLM_CONNECT_TIMEOUT`        | Connection timeout seconds                   | `10`                     |
| `LLM_READ_TIMEOUT`            | Read timeout seconds                         | `60`                     |

---

## Usage

**Python**
```python
from ai_client import chat_json

messages = [
    {"role": "system", "content": "You are a JSON-only assistant."},
    {"role": "user", "content": "Return a JSON object: {\"hello\": \"world\"}"}
]

result = chat_json(messages)
print(result)
# -> {'hello': 'world'}
```

**CLI**
```bash
export LLM_PROVIDER=openai_compat
export LLM_API_KEY=sk-...

python ai_client.py \
  --system "You are a JSON-only assistant." \
  --message "Return a JSON object: {\"hello\": \"world\"}"
```

**Output**
```json
{
  "hello": "world"
}
```

---

## Connectivity probe

Use `live_probe()` to test your credentials and endpoint:

```python
from ai_client import live_probe
print(live_probe())
```

Returns status code, headers (masked), and a truncated response.

---

## Notes

- Compatible with any OpenAI-compatible server (OpenAI, Groq, DeepSeek, Mistral shims, etc.)
- For **Ollama**, set `LLM_PROVIDER=ollama` and `LLM_API_BASE=http://localhost:11434`
- No streaming output (by design for simplicity and reliability)

###############################################
# GLOBAL DEFAULTS (applies to all providers)
###############################################
LLM_PROVIDER=openai_compat       # openai | openai_compat | azure_openai | anthropic | ollama | mistral | deepseek
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=                      # your API key (OpenAI/Azure/Anthropic)
LLM_API_BASE=                     # custom API base (if needed)
LLM_API_PORT=                     # custom port (if needed)
LLM_VERIFY_SSL=true
LLM_CONNECT_TIMEOUT=10
LLM_READ_TIMEOUT=60

###############################################
# AZURE OPENAI (use with LLM_PROVIDER=azure_openai)
###############################################
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_API_VERSION=2024-08-01-preview
# Note: LLM_MODEL must be the deployment name (not the model id)

###############################################
# ANTHROPIC (use with LLM_PROVIDER=anthropic)
###############################################
# Example model: claude-3-7-sonnet-20250219
# Set LLM_API_KEY to your Anthropic API key

###############################################
# OLLAMA LOCAL (use with LLM_PROVIDER=ollama)
###############################################
LLM_API_BASE=http://localhost:11434
LLM_MODEL=llama3
LLM_VERIFY_SSL=false

###############################################
# OPENAI (use with LLM_PROVIDER=openai or openai_compat)
###############################################
# LLM_API_BASE=https://api.openai.com/v1
# LLM_MODEL=gpt-4o-mini
# LLM_API_KEY=sk-...

