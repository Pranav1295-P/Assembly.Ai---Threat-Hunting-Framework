@echo off
REM Assembly.AI launcher (Windows)
cd /d "%~dp0backend"

if not exist venv (
  echo [setup] creating venv ...
  python -m venv venv
)

call venv\Scripts\activate

if not exist .venv_ready (
  echo [setup] installing dependencies ^(one-time^) ...
  python -m pip install --upgrade pip wheel
  pip install -r requirements.txt
  type nul > .venv_ready
)

if not exist .env (
  copy .env.example .env
  echo [setup] created .env -- edit it and add your ANTHROPIC_API_KEY ^(or OPENAI_API_KEY^).
)

python run.py
