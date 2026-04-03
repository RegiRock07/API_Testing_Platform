# backend/app/config.py
#
# Single source of truth for LLM model configuration.
# All agents import from here — no hardcoded model strings anywhere else.

import os
import logging

logger = logging.getLogger(__name__)

# ── Groq models ───────────────────────────────────────────────────
# Primary: best reasoning, true successor to the deprecated llama3-70b-8192
# Fallback: used automatically if primary is unavailable
GROQ_MODEL_PRIMARY  = "llama-3.3-70b-versatile"
GROQ_MODEL_FALLBACK = "llama-3.1-8b-instant"

# Allow override via env var (e.g. for testing a specific model)
GROQ_MODEL  = os.getenv("GROQ_MODEL", GROQ_MODEL_PRIMARY)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

logger.info(f"[Config] LLM provider : {os.getenv('LLM_PROVIDER', 'groq')}")
logger.info(f"[Config] Groq model   : {GROQ_MODEL}")