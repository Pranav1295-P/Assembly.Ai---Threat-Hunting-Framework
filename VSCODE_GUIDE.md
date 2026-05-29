# Assembly.AI in VS Code — Step-by-Step Guide

This guide walks you from a fresh VS Code install to a fully running
Assembly.AI server with a free Llama-based LLM. It assumes you have:

- **Python 3.10 or newer** installed (`python --version` should print `3.10+`)
- **Visual Studio Code**
- **Git** (only if you'll clone the project)

If Python isn't installed yet, grab it from <https://python.org/downloads/>.
On Windows, tick **"Add python.exe to PATH"** during install.

---

## 1. Open the project in VS Code

```
File → Open Folder…  →  select the assembly.ai folder
```

The folder you open should be the one that contains `backend/`, `frontend/`,
`start.sh`, `start.bat`, and the `.vscode/` directory. That folder becomes
your *workspace root*.

When VS Code opens, it should pop a banner offering to install the
**Recommended extensions** (Python, Pylance, Debugpy, Live Server,
Prettier). Click **Install All**. They are listed in
`.vscode/extensions.json`.

---

## 2. Open the integrated terminal

```
View → Terminal     (or press   Ctrl+`   /   ⌃`   on macOS)
```

Make sure the terminal's current folder is the workspace root (not
`backend/`). Run:

### 2a. Create a virtual environment

```bash
# Linux / macOS
python3 -m venv backend/venv

# Windows (Command Prompt)
python -m venv backend\venv

# Windows (PowerShell)
python -m venv backend\venv
```

### 2b. Activate it

```bash
# Linux / macOS
source backend/venv/bin/activate

# Windows (Command Prompt)
backend\venv\Scripts\activate.bat

# Windows (PowerShell)
backend\venv\Scripts\Activate.ps1
```

Your prompt should now have `(venv)` at the front.

> If PowerShell complains about execution policy, run
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` first.

### 2c. Install dependencies

```bash
pip install --upgrade pip wheel
pip install -r backend/requirements.txt
```

This pulls in Flask, scikit-learn, ReportLab, pefile, matplotlib, networkx,
the OpenAI SDK (used for free providers too) and Anthropic SDK.

---

## 3. Pick the Python interpreter VS Code should use

Press **`Ctrl+Shift+P`** (`⌘⇧P` on macOS) → type **"Python: Select Interpreter"**
→ pick the one inside `backend/venv` (it shows a `(venv)` label).

`./.vscode/settings.json` already pins the default interpreter path, so
this step usually auto-resolves the first time you open a Python file.

---

## 4. Configure a free LLM (recommended)

Copy the env template:

```bash
# Linux / macOS
cp backend/.env.example backend/.env

# Windows
copy backend\.env.example backend\.env
```

Open `backend/.env` in VS Code and fill **one** of the options below.

### Option A — Groq (fastest, totally free, recommended)

1. Go to <https://console.groq.com> and sign up (Google login works).
2. Click **API Keys → Create API Key**, copy the key (starts with `gsk_`).
3. Paste into `backend/.env`:
   ```
   GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   GROQ_MODEL=llama-3.3-70b-versatile
   ```
4. Save.

That's it. Llama 3.3 70B will be used for the AI investigation step. Free
tier limits are generous (30 req/min as of writing).

### Option B — OpenRouter (also free)

1. <https://openrouter.ai> → sign up → **Keys** → create key (`sk-or-…`).
2. In `.env`:
   ```
   OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxxxxxxxxx
   OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
   ```

### Option C — Ollama (no key, runs entirely on your machine)

1. Download Ollama from <https://ollama.com> and install.
2. Pull a model:
   ```bash
   ollama pull llama3.1:8b
   ```
3. Start Ollama (it usually starts automatically; if not, run `ollama serve`).
4. In `.env`:
   ```
   OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
   OLLAMA_MODEL=llama3.1:8b
   ```

> No internet? No API key? This is the option for you. Slower than Groq
> but has no rate limit and no data leaves your laptop.

### Option D — Skip the LLM entirely

Leave every key blank. The pipeline still runs, the static + ML +
heuristic engines produce a complete report, and the AI section is filled
by the deterministic fallback. Useful for offline demos.

---

## 5. Train the ML classifier (one-time, ~15 s)

Two ways:

**a) From the terminal:**
```bash
python backend/ml_models/train_model.py
```

**b) From VS Code's Run panel** (the play-button on the left sidebar):
Pick `Assembly.AI · Train ML model` → press the green ► button.

You should see `[+] Saved model → backend/ml_models/malware_classifier.pkl`.

> `run.py` will auto-train on first launch if the .pkl is missing — so this
> step is optional, but doing it explicitly lets you confirm the AUC.

---

## 6. Launch the server

### Easiest — VS Code Run panel

1. Click the **Run and Debug** icon on the left (or press `Ctrl+Shift+D`).
2. Pick **Assembly.AI · Run server** in the dropdown.
3. Press the green ► button (`F5`).

Watch the **Debug Console** / terminal — when you see
`[ready] Assembly.AI listening on http://127.0.0.1:5000`, the server is up.

### Or from the terminal

```bash
python backend/run.py
```

### Or use the helper scripts (no VS Code needed)

```bash
./start.sh        # macOS / Linux
start.bat         # Windows
```

---

## 7. Use the app

Open <http://127.0.0.1:5000> in your browser. The header should say
**LLM: groq** (or whichever provider you chose).

Drop a sample on the dropzone or browse to a file. Real-world samples to
test with:

- **MalwareBazaar** — <https://bazaar.abuse.ch/browse/> — daily samples,
  free password is `infected`. Always extract on a VM.
- **VirusTotal** — paste a hash and use the *Behaviour* tab to compare
  against Assembly.AI's findings.

The PDF report opens in a new tab and is also persisted under
`backend/reports_out/<analysis_id>.pdf`.

---

## 8. Debugging tips

- **Set a breakpoint** by clicking left of a line number in any backend
  Python file, then run with `F5`. Execution pauses on hit.
- **Hot-reload during development** — pick the `Flask debug (auto-reload)`
  launch config; saving any `.py` file restarts the server.
- **Inspect the JSON dossier** — every analysis is cached at
  `backend/analyses/<id>.json`; open one in VS Code for the raw data.
- **Logs** — anything `print()`-ed in Python lands in the integrated
  terminal. The Werkzeug request log lives there too.
- **Frontend tweaks** — edit `frontend/css/style.css` and reload the
  browser; no server restart needed.

---

## 9. Common errors & fixes

| Symptom                                                    | Fix                                                                                     |
|------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `ModuleNotFoundError: No module named 'flask'`             | venv not activated. Re-run `source backend/venv/bin/activate` (or Windows equivalent).  |
| `pefile` install fails on Windows                          | `pip install pefile==2024.8.26 --upgrade`. If still fails, install Visual C++ Build Tools. |
| Header shows **LLM: heuristic**                            | `.env` not picked up. Confirm file is `backend/.env`, key prefix matches the example.   |
| `groq.AuthenticationError`                                 | Wrong/expired key. Regenerate at console.groq.com.                                      |
| `openai.RateLimitError` on free tier                       | Wait 60 s or switch to Ollama for unlimited local inference.                            |
| Ollama hangs or times out                                  | `ollama list` in terminal — if empty, run `ollama pull llama3.1:8b`.                    |
| Port 5000 already in use                                   | Change `FLASK_PORT` in `.env`, e.g. to `5050`.                                          |
| ReportLab font errors on first run                         | First run downloads matplotlib font cache (~10 s) — re-try.                             |

---

## 10. What to do next

- Replace the synthetic ML corpus with real **EMBER-2018** features for a
  production-grade classifier (`backend/ml_models/train_model.py` is
  designed to be a drop-in replacement target).
- Add **YARA** rule scanning — `pip install yara-python` and call
  `yara.compile()` inside `static_analyzer.py`.
- Hook **VirusTotal hash lookup** into `ai_analyzer.py` so the LLM gets
  community AV verdicts as additional context.
- Wrap everything in a **Docker** container for reproducible class demos.

Happy hunting.
