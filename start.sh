#!/usr/bin/env bash
# Assembly.AI launcher (macOS / Linux)
set -euo pipefail
cd "$(dirname "$0")/backend"

PY=${PYTHON:-python3}

if [ ! -d venv ]; then
  echo "[setup] creating venv …"
  "$PY" -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

if [ ! -f .venv_ready ]; then
  echo "[setup] installing dependencies (one-time) …"
  pip install --upgrade pip wheel >/dev/null
  pip install -r requirements.txt
  touch .venv_ready
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[setup] created .env — edit it and add your ANTHROPIC_API_KEY (or OPENAI_API_KEY)."
fi

exec python run.py
