# backend/app/config.py
#
# Single source of truth for LLM model configuration.
# All agents import from here — no hardcoded model strings anywhere else.
#
# Model names are env-overridable so a provider retiring a model is a
# config change, not a code change. To see which Groq models your key can
# use:  curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"

import os
import logging

logger = logging.getLogger(__name__)

# ── Groq models ───────────────────────────────────────────────────
# Primary: strongest general model on Groq (checked 2026-11-24).
# Fallback: smaller and faster; used automatically if the primary fails.
# (llama-3.3-70b-versatile / llama-3.1-8b-instant were retired by Groq.)
_DEFAULT_GROQ_PRIMARY  = "openai/gpt-oss-120b"
_DEFAULT_GROQ_FALLBACK = "openai/gpt-oss-20b"

GROQ_MODEL_PRIMARY = (
    os.getenv("GROQ_MODEL_PRIMARY")
    or os.getenv("GROQ_MODEL")          # legacy name, still honoured
    or _DEFAULT_GROQ_PRIMARY
)
GROQ_MODEL_FALLBACK = os.getenv("GROQ_MODEL_FALLBACK") or _DEFAULT_GROQ_FALLBACK
GROQ_MODEL          = GROQ_MODEL_PRIMARY  # back-compat alias
GROQ_API_KEY        = os.getenv("GROQ_API_KEY", "")

# ── Gemini ────────────────────────────────────────────────────────
# Current stable Flash model (gemini-1.5/2.0 Flash are shut down).
GEMINI_MODEL = os.getenv("GEMINI_MODEL") or "gemini-3.8-flash"

logger.info(f"[Config] LLM provider : {os.getenv('LLM_PROVIDER', 'groq')}")
logger.info(f"[Config] Groq models  : primary={GROQ_MODEL_PRIMARY} fallback={GROQ_MODEL_FALLBACK}")
logger.info(f"[Config] Gemini model : {GEMINI_MODEL}")
