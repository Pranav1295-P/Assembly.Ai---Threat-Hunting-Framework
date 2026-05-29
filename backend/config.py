"""Central runtime configuration."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# --- Paths ---
UPLOAD_DIR      = BASE_DIR / "uploads"
REPORT_DIR      = BASE_DIR / "reports_out"
ML_MODELS_DIR   = BASE_DIR / "ml_models"
MODEL_PATH      = ML_MODELS_DIR / "malware_classifier.pkl"
ANALYSIS_CACHE  = BASE_DIR / "analyses"
FRONTEND_DIR    = BASE_DIR.parent / "frontend"

for p in (UPLOAD_DIR, REPORT_DIR, ML_MODELS_DIR, ANALYSIS_CACHE):
    p.mkdir(parents=True, exist_ok=True)

# --- Server ---
FLASK_HOST    = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT    = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG   = bool(int(os.getenv("FLASK_DEBUG", "0")))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "64"))

# --- Database ---
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://aisecops:aisecops@localhost:5432/aisecops",
).strip()
DB_ALLOW_SQLITE_FALLBACK = bool(int(os.getenv("DB_ALLOW_SQLITE_FALLBACK", "1")))
SQLITE_FALLBACK_URL = f"sqlite:///{BASE_DIR / 'aisecops_fallback.db'}"

# --- Provider selection ---
# Order of preference: explicit LLM_PROVIDER → first key found.
# Supported: anthropic | openai | groq | openrouter | together | ollama | heuristic
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "").strip().lower()

# --- Anthropic Claude ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

# --- OpenAI ---
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL    = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "").strip()  # optional override

# --- Groq (FREE — fast Llama / Mixtral) ---
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL   = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

# --- OpenRouter (FREE tier with Llama / Mistral free models) ---
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL",
                               "meta-llama/llama-3.2-3b-instruct:free")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# --- Together AI ---
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY", "").strip()
TOGETHER_MODEL   = os.getenv("TOGETHER_MODEL",
                             "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free")
TOGETHER_BASE_URL = "https://api.together.xyz/v1"

# --- Ollama (FREE — fully local; no key needed) ---
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "").strip()      # e.g. http://127.0.0.1:11434/v1
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "llama3.1:8b")


def llm_provider() -> str:
    """Return the active provider key, falling back to a deterministic heuristic."""
    if LLM_PROVIDER:
        return LLM_PROVIDER
    if ANTHROPIC_API_KEY.startswith("sk-ant"):
        return "anthropic"
    if GROQ_API_KEY.startswith("gsk_"):
        return "groq"
    if OPENROUTER_API_KEY.startswith("sk-or-"):
        return "openrouter"
    if TOGETHER_API_KEY:
        return "together"
    if OPENAI_API_KEY.startswith("sk-"):
        return "openai"
    if OLLAMA_BASE_URL:
        return "ollama"
    return "heuristic"
