"""
Core phishing-detection logic ported from Phish-Ai.
Supports: Claude (Anthropic), Gemini, Groq, OpenRouter.
"""

import os, json, re, yaml
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException

try:
    import anthropic as _anthropic
except ImportError:
    _anthropic = None

try:
    from groq import Groq as _Groq
except ImportError:
    _Groq = None

import httpx

# ── Load prompt.yml ────────────────────────────────────────────────────────────
_PROMPT_PATH = os.getenv("PROMPT_YML_PATH", "./prompt.yml")
with open(_PROMPT_PATH, "r") as _f:
    _PROMPT_CONFIG = yaml.safe_load(_f)

MAX_TOKENS  = _PROMPT_CONFIG.get("max_tokens", 3000)
_SYS_TMPL   = _PROMPT_CONFIG["system"]
_USER_TMPL  = _PROMPT_CONFIG["user"]

# ── Supported models ───────────────────────────────────────────────────────────
SUPPORTED_MODELS: dict[str, str] = {
    "claude-sonnet-4-6":         "anthropic",
    "claude-opus-4-7":           "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    "gemini-2.0-flash":          "gemini",
    "gemini-1.5-pro":            "gemini",
    "gemini-1.5-flash":          "gemini",
    "llama-3.3-70b-versatile":   "groq",
    "llama-3.1-8b-instant":      "groq",
    "mixtral-8x7b-32768":        "groq",
    "openrouter":                "openrouter",
}


def get_provider(model: str) -> str:
    if model in SUPPORTED_MODELS:
        return SUPPORTED_MODELS[model]
    if "/" in model:
        return "openrouter"
    raise ValueError(
        f"Unknown model: '{model}'. "
        "Use a known model name or 'org/model' format for OpenRouter."
    )


def build_messages(url: str, domain: str) -> tuple[str, str]:
    today  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    system = (
        _SYS_TMPL
        .replace("{{URL}}", url)
        .replace("{{DOMAIN}}", domain)
        .replace("{{CURRENT_DATE}}", today)
    )
    user = (
        _USER_TMPL
        .replace("{{URL}}", url)
        .replace("{{DOMAIN}}", domain)
        .replace("{{CURRENT_DATE}}", today)
    )
    return system, user


def extract_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()
    analysis_keys = {"url", "score", "verdict", "status"}
    candidates: list[dict] = []
    i = 0
    while i < len(text):
        start = text.find("{", i)
        if start == -1:
            break
        depth, j = 0, start
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : j + 1])
                        if isinstance(obj, dict):
                            candidates.append(obj)
                    except json.JSONDecodeError:
                        pass
                    break
            j += 1
        i = start + 1
    if not candidates:
        raise ValueError("No JSON object found in model response")
    for obj in reversed(candidates):
        if analysis_keys.issubset(obj.keys()):
            return obj
    return max(candidates, key=lambda x: len(str(x)))


def _handle_provider_error(provider: str, status: int, err: dict):
    msg = str(err)
    if status in (402, 429) or any(
        k in msg.lower() for k in ("quota", "credit", "billing", "rate limit", "insufficient", "exhausted")
    ):
        raise HTTPException(402, f"{provider}: quota or credits exhausted. Detail: {msg}")
    if status in (401, 403) or any(k in msg.lower() for k in ("api_key", "unauthorized", "forbidden")):
        raise HTTPException(401, f"{provider}: API key invalid or expired. Detail: {msg}")
    if "token" in msg.lower() and any(k in msg.lower() for k in ("limit", "length")):
        raise HTTPException(422, f"{provider}: context/token limit exceeded. Detail: {msg}")
    raise HTTPException(502, f"{provider} error {status}: {msg}")


async def call_anthropic(model: str, system: str, user: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "ANTHROPIC_API_KEY not set")
    if _anthropic is None:
        raise HTTPException(500, "anthropic package not installed")
    client = _anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return msg.content[0].text


async def call_gemini(model: str, system: str, user: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "GEMINI_API_KEY not set")
    endpoint = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": f"{system}\n\n{user}"}]}],
        "generationConfig": {"maxOutputTokens": MAX_TOKENS, "temperature": 0.1},
    }
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(endpoint, json=payload)
    if r.status_code != 200:
        _handle_provider_error("Gemini", r.status_code, r.json())
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


async def call_groq(model: str, system: str, user: str) -> str:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "GROQ_API_KEY not set")
    if _Groq is None:
        raise HTTPException(500, "groq package not installed")
    client = _Groq(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        max_tokens=MAX_TOKENS,
        temperature=0.1,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    )
    return resp.choices[0].message.content


async def call_openrouter(model: str, system: str, user: str) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(400, "OPENROUTER_API_KEY not set")
    payload = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer":  "https://securelint.app",
                "X-Title":       "SecureLint Phishing Detector",
            },
        )
    if r.status_code != 200:
        _handle_provider_error("OpenRouter", r.status_code, r.json())
    return r.json()["choices"][0]["message"]["content"]


async def run_scan(url: str, domain: str, model: str) -> dict:
    """Run a full phishing scan and return the parsed analysis dict."""
    try:
        provider = get_provider(model)
    except ValueError as e:
        raise HTTPException(400, str(e))

    system, user = build_messages(url, domain)

    raw = ""
    try:
        if provider == "anthropic":
            raw = await call_anthropic(model, system, user)
        elif provider == "gemini":
            raw = await call_gemini(model, system, user)
        elif provider == "groq":
            raw = await call_groq(model, system, user)
        elif provider == "openrouter":
            raw = await call_openrouter(model, system, user)
        else:
            raise HTTPException(400, f"Provider '{provider}' not implemented")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Model call failed: {str(e)}")

    try:
        return extract_json(raw)
    except Exception as e:
        raise HTTPException(422, detail={
            "error": f"Model returned non-JSON: {str(e)}",
            "raw_response": raw[:2000],
        })
