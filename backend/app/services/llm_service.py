# backend/app/services/llm_service.py
#
# Centralized LLM Service — single gateway for all LLM calls in the platform.
#
# Provider is controlled via the LLM_PROVIDER env var:
#   "groq"   → Groq Cloud API (PRIMARY, production default)
#   "ollama" → Local Ollama instance (development / offline fallback)
#
# Usage:
#   from app.services.llm_service import call_llm, parse_llm_json, LLMError

import os
import json
import requests
import logging

logger = logging.getLogger("llm_service")

# ─────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────

class LLMError(Exception):
    """Raised when an LLM call fails for any reason."""
    pass


# ─────────────────────────────────────────────────────────────────
# JSON Parsing (shared utility — replaces per-agent duplication)
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

        # Strip markdown code fences (```json ... ``` or ``` ... ```)
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first line (```json or ```) and last line (```)
            if lines[-1].strip() == "```":
                text = "\n".join(lines[1:-1])
            else:
                text = "\n".join(lines[1:])
            text = text.strip()

        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(f"[LLMService] JSON parse failed: {e}. Raw (first 300 chars): {raw_text[:300]}")
        return fallback
    except Exception as e:
        logger.error(f"[LLMService] Unexpected parse error: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────
# Provider: Groq (PRIMARY)
# ─────────────────────────────────────────────────────────────────

def _call_groq(messages: list[dict]) -> str:
    """
    Call Groq Cloud API using the official SDK.
    Raises LLMError on any failure.
    """
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise LLMError(
            "GROQ_API_KEY is not set. "
            "Set GROQ_API_KEY in your environment or switch to LLM_PROVIDER=ollama for local development."
        )

    model = os.getenv("GROQ_MODEL", "llama3-70b-8192")
    temperature = float(os.getenv("GROQ_TEMPERATURE", "0.2"))

    try:
        from groq import Groq

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
        )
        content = response.choices[0].message.content
        if not content:
            raise LLMError(f"Groq returned empty response for model '{model}'")
        return content

    except ImportError:
        raise LLMError(
            "groq package is not installed. Run: pip install groq"
        )
    except LLMError:
        raise  # Re-raise our own errors
    except Exception as e:
        raise LLMError(f"Groq API call failed: {e}")


# ─────────────────────────────────────────────────────────────────
# Provider: Ollama (FALLBACK — dev / offline)
# ─────────────────────────────────────────────────────────────────

def _call_ollama(messages: list[dict]) -> str:
    """
    Call local Ollama instance via HTTP.
    Raises LLMError on any failure.
    """
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_DEFAULT_MODEL", "llama3.1:8b")
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    try:
        response = requests.post(
            f"{ollama_url}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        if not content:
            raise LLMError(f"Ollama returned empty response for model '{model}'")
        return content

    except requests.ConnectionError:
        raise LLMError(
            f"Cannot connect to Ollama at {ollama_url}. "
            "Is Ollama running? Start with: ollama serve"
        )
    except requests.Timeout:
        raise LLMError(f"Ollama request timed out after {timeout}s")
    except LLMError:
        raise  # Re-raise our own errors
    except Exception as e:
        raise LLMError(f"Ollama call failed: {e}")


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def call_llm(messages: list[dict]) -> str:
    """
    Send a chat-completion request to the configured LLM provider.

    Args:
        messages: List of message dicts, e.g.:
            [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]

    Returns:
        str: The LLM's response text.

    Raises:
        LLMError: If the LLM call fails for any reason (network, auth, empty response, etc.).
                  Callers should catch this and fall back to rule-based logic or gracefully degrade.
    """
    provider = os.getenv("LLM_PROVIDER", "groq").lower().strip()

    if provider == "groq":
        return _call_groq(messages)
    elif provider == "ollama":
        return _call_ollama(messages)
    else:
        raise LLMError(
            f"Unknown LLM_PROVIDER '{provider}'. "
            "Supported values: 'groq' (default), 'ollama'"
        )
