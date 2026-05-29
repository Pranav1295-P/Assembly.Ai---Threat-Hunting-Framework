# Assembly.AI — AI-Sec-Ops

**AI-Powered Malware Analysis & Threat Hunting Framework**

Assembly.AI (AI-Sec-Ops) is a research-grade malware analyzer that performs hybrid
analysis on uploaded artifacts (PE/ELF/Office/PDF/script/binary). It combines:

- **Static Analysis** — hashing, entropy, magic-bytes, PE header parsing, suspicious
  imports/APIs, embedded strings, packer hints.
- **ML Classification** — gradient-boosted classifier trained on PE feature vectors
  (auto-trained on first run with a synthetic-but-realistic malware feature corpus
  derived from public EMBER-style schema).
- **AI/LLM Investigation** — sends the structured analysis context to Claude / OpenAI,
  asks for an attack chain reconstruction, MITRE ATT&CK technique mapping, IOC
  validation and severity grading.
- **Automated PDF Report** — Executive summary, attack flow, process-tree diagram,
  MITRE matrix, IOC tables, recommendations.

> Inspired by the Garuda Threat Hunting Framework demo (DEF CON).

---

## Architecture

```
ai-sec-ops/
├── backend/
│   ├── app.py                     # Flask API
│   ├── config.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── run.py                     # bootstrapper (trains ML model if missing)
│   ├── analyzers/
│   │   ├── static_analyzer.py
│   │   ├── ai_analyzer.py
│   │   ├── ml_classifier.py
│   │   ├── ioc_extractor.py
│   │   └── mitre_mapper.py
│   ├── reports/
│   │   └── pdf_generator.py
│   ├── utils/
│   │   └── file_utils.py
│   └── ml_models/
│       └── train_model.py
├── frontend/
│   ├── index.html
│   ├── analysis.html
│   ├── css/style.css
│   ├── js/app.js
│   └── assets/logo.svg
├── start.sh                       # Linux/macOS launcher
├── start.bat                      # Windows launcher
└── README.md
```

---

## Running in VS Code

A complete walkthrough — venv, free-LLM setup, debugging, troubleshooting — is in
[`VSCODE_GUIDE.md`](./VSCODE_GUIDE.md). The repository ships with `.vscode/`
launch configurations so you can pick **"Assembly.AI · Run server"** from the
Run-and-Debug panel and press F5.

## Quick Start

### 1. Clone & install

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Add your LLM API key (free options supported)

```bash
cp .env.example .env
```

Open `.env` and fill **one** of the providers:

| Provider     | Cost        | Model                             | Where to get a key                |
|--------------|-------------|-----------------------------------|-----------------------------------|
| **Groq**     | Free        | `llama-3.3-70b-versatile`         | <https://console.groq.com>        |
| **OpenRouter** | Free tier | `meta-llama/llama-3.2-3b-instruct:free` | <https://openrouter.ai>     |
| **Together** | Free credits| `Llama-3.3-70B-Instruct-Turbo-Free` | <https://together.ai>           |
| **Ollama**   | 100% local  | `llama3.1:8b` (or any pulled)     | <https://ollama.com> (no key)     |
| Anthropic    | Paid        | `claude-sonnet-4-5`               | <https://console.anthropic.com>   |
| OpenAI       | Paid        | `gpt-4o-mini`                     | <https://platform.openai.com>     |

The analyzer auto-detects whichever key is present. If none is set, a
deterministic heuristic narrative is used so the pipeline still produces a
complete report.

### 3. Train the ML classifier (first run only)

```bash
python ml_models/train_model.py
```

This generates `ml_models/malware_classifier.pkl` (~1 MB). It is also trained
automatically on first launch via `run.py`.

### 4. Launch

```bash
# from repo root
./start.sh                        # Windows: start.bat
```

The Flask API serves on `http://127.0.0.1:5000` and also serves the frontend at
`http://127.0.0.1:5000/`.

---

## API Endpoints

| Method | Path                       | Description                                   |
|--------|----------------------------|-----------------------------------------------|
| GET    | `/`                        | Serves frontend index                         |
| GET    | `/api/health`              | Health probe                                  |
| POST   | `/api/analyze`             | Multipart file upload → returns JSON analysis |
| GET    | `/api/report/<analysis_id>`| Streams the generated PDF report              |
| GET    | `/api/analysis/<id>`       | Returns cached JSON analysis                  |

---

## Testing With Real Samples

The intended workflow:

1. Pull a sample from **MalwareBazaar** (`https://bazaar.abuse.ch/`) or
   **VirusTotal** (research API).
2. Upload via the web UI or:
   ```bash
   curl -F file=@suspicious.exe http://127.0.0.1:5000/api/analyze
   ```
3. Open the generated PDF report from the UI or `/api/report/<id>`.

> Always handle live malware in an isolated VM. Assembly.AI performs **static
> and AI-driven** analysis only — it does not detonate samples.

---

## Footer

> *Proudly Designed And Developed At B.M.S. College Of Engineering, Bengaluru, India.*
