# backend/app/services/llm_service.py
#
# Centralized LLM Service — single gateway for all LLM calls.
#
# Provider controlled via LLM_PROVIDER env var:
#   "groq"   → Groq Cloud API  (PRIMARY — set GROQ_API_KEY)
#   "ollama" → Local Ollama    (FALLBACK — no key needed)
#
# Usage:
#   from app.services.llm_service import call_llm, parse_llm_json, LLMError

import os
import json
import logging

logger = logging.getLogger("llm_service")


# ─────────────────────────────────────────────────────────────────
# Custom exception
# ─────────────────────────────────────────────────────────────────

class LLMError(Exception):
    """Raised when an LLM call fails for any reason."""
    pass


# ─────────────────────────────────────────────────────────────────
# JSON parsing utility  (shared — avoids per-agent duplication)
# ─────────────────────────────────────────────────────────────────

def parse_llm_json(raw_text: str, fallback=None):
    """
    Parse LLM output that should be JSON.
    Strips markdown code fences and handles common formatting issues.
    Returns parsed object or `fallback` on failure.
    """
    if not raw_text or not raw_text.strip():
        logger.warning("[LLMService] parse_llm_json received empty text")
        return fallback

    try:
        text = raw_text.strip()

        # Strip markdown code fences  (```json ... ``` or ``` ... ```)
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[-1].strip() == "```":
                text = "\n".join(lines[1:-1])
            else:
                text = "\n".join(lines[1:])
            text = text.strip()

        return json.loads(text)

    except json.JSONDecodeError as e:
        logger.warning(
            f"[LLMService] JSON parse failed: {e}. "
            f"Raw (first 300 chars): {raw_text[:300]}"
        )
        return fallback
    except Exception as e:
        logger.error(f"[LLMService] Unexpected parse error: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────
# Provider: Groq  (PRIMARY)
# ─────────────────────────────────────────────────────────────────

def _call_groq(messages: list) -> str:
    """
    Call Groq Cloud API using the official SDK.
    Tries PRIMARY model first, falls back to FALLBACK model.
    Raises LLMError on complete failure.
    """
    from app.config import GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK, GROQ_API_KEY

    api_key = GROQ_API_KEY or os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise LLMError(
            "GROQ_API_KEY is not set. "
            "Add it to your .env file or switch to LLM_PROVIDER=ollama for local dev."
        )

    temperature = float(os.getenv("GROQ_TEMPERATURE", "0.2"))

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
    except ImportError:
        raise LLMError("groq package is not installed. Run: pip install groq")
    except Exception as e:
        raise LLMError(f"Failed to initialise Groq client: {e}")

    # Rough token estimate — 1 token ≈ 4 chars
    estimated_tokens = sum(len(m.get("content", "")) for m in messages) // 4
    if estimated_tokens > 6000:
        logger.warning(f"[LLM] Prompt too large (~{estimated_tokens} tokens), truncating not supported — using fallback")
        raise LLMError(f"Prompt too large (~{estimated_tokens} tokens). Reduce endpoint count.")

    for model in [GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK]:
        try:
            logger.info(f"[LLM] Attempting Groq call with model: {model}")
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=8192,
            )
            content = response.choices[0].message.content
            if not content or not content.strip():
                raise ValueError("Groq returned empty response")
            logger.info(f"[LLM] Groq success with model: {model}")
            return content
        except Exception as e:
            logger.warning(f"[LLM] Groq model {model} failed: {e}")

    raise LLMError(
        "[LLM] All Groq models failed. "
        "Check GROQ_API_KEY and model availability at console.groq.com."
    )


# ─────────────────────────────────────────────────────────────────
# Provider: Ollama  (FALLBACK — local / offline dev)
# ─────────────────────────────────────────────────────────────────

def _call_ollama(messages: list) -> str:
    """
    Call local Ollama instance via HTTP.
    Raises LLMError on any failure.
    """
    import requests as _requests

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model      = os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b")
    timeout    = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    try:
        response = _requests.post(
            f"{ollama_url}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        if not content:
            raise LLMError(f"Ollama returned empty response for model '{model}'")
        logger.info(f"[LLM] Ollama success with model: {model}")
        return content

    except _requests.ConnectionError:
        raise LLMError(
            f"Cannot connect to Ollama at {ollama_url}. "
            "Is Ollama running? Start with: ollama serve"
        )
    except _requests.Timeout:
        raise LLMError(f"Ollama request timed out after {timeout}s")
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(f"Ollama call failed: {e}")

def _call_gemini(messages: list) -> str:
    """
    Call Google Gemini API using the new google-genai SDK.
    Free tier via AI Studio — 1,500 requests/day.
    """
    from google import genai
    from google.genai import types

    api_key = os.getenv("GOOGLE_API_KEY", "")
    if not api_key:
        raise LLMError(
            "GOOGLE_API_KEY is not set. "
            "Get a free key at aistudio.google.com."
        )

    try:
        client = genai.Client(api_key=api_key)
    except Exception as e:
        raise LLMError(f"Failed to initialise Gemini client: {e}")

    # Separate system message from conversation
    system_msg = ""
    prompt = ""
    for m in messages:
        if m["role"] == "system":
            system_msg = m["content"]
        else:
            prompt += m["content"]

    if system_msg:
        prompt = f"{system_msg}\n\n{prompt}"

    try:
        response = client.models.generate_content(
            model="gemini-1.5-flash-latest",
            contents=prompt,
        )
        content = response.text
        if not content:
            raise LLMError("Gemini returned empty response")
        logger.info("[LLM] Gemini gemini-2.0-flash success")
        return content

    except Exception as e:
        raise LLMError(f"Gemini call failed: {e}")

def call_llm(messages: list) -> str:
    provider = os.getenv("LLM_PROVIDER", "groq").lower().strip()

    if provider == "groq":
        # Try Groq first, auto-fallback to Gemini if rate limited
        try:
            return _call_groq(messages)
        except LLMError as e:
            google_key = os.getenv("GOOGLE_API_KEY", "")
            if google_key and (
                "rate_limit" in str(e).lower() or
                "429" in str(e) or
                "all groq models failed" in str(e).lower()
            ):
                logger.warning(f"[LLM] Groq rate limited, falling back to Gemini: {e}")
                return _call_gemini(messages)
            raise

    elif provider == "gemini":
        return _call_gemini(messages)

    elif provider == "ollama":
        return _call_ollama(messages)

    else:
        raise LLMError(
            f"Unknown LLM_PROVIDER '{provider}'. "
            "Supported values: 'groq' (default), 'gemini', 'ollama'."
        )