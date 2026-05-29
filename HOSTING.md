# Free Hosting — Assembly.AI

**Recommendation: Render.com.** It's the only mainstream free tier that
gives you both a Python web service AND a PostgreSQL database in the
same dashboard, with a built-in deploy-from-GitHub flow.

The repo already includes everything Render needs:

- `Procfile` — start command (gunicorn)
- `render.yaml` — Render Blueprint (declares web + DB)
- `runtime.txt` — pins Python 3.12
- `backend/requirements.txt` — includes `gunicorn`
- `backend/app.py` — auto-trains the ML model on first boot
- `backend/config.py` — already reads `DATABASE_URL` from env

You don't change a single line of code to deploy.

---

## Step 1 — Push to GitHub (5 min)

In a terminal, from the project root (`~/Documents/AssemblyAI`):

```bash
cd ~/Documents/AssemblyAI

# initialize git
git init
git add .
git commit -m "initial commit — Assembly.AI"

# create a GitHub repo (use the GitHub CLI if you have it):
gh repo create assemblyai --public --source=. --remote=origin --push
# OR manually:  go to https://github.com/new, create the repo, then:
git remote add origin https://github.com/<your-username>/assemblyai.git
git branch -M main
git push -u origin main
```

Make sure these are in `.gitignore` so you don't push secrets / build
artefacts (the bundled `.gitignore` already covers them):

```
backend/.env
backend/venv/
backend/uploads/
backend/reports_out/
backend/analyses/
backend/aisecops_fallback.db*
backend/ml_models/*.pkl
```

---

## Step 2 — Sign up at Render

<https://render.com> → **Sign in with GitHub**. Free, no credit card.

---

## Step 3 — One-click Blueprint deploy

1. Click **New +** → **Blueprint**.
2. Connect / pick the `assemblyai` repository you just pushed.
3. Render reads `render.yaml`, shows it'll create:
   - **assemblyai-web** — a free Python web service
   - **assemblyai-db** — a free PostgreSQL database
4. Click **Apply**.

The first deploy takes ~5 minutes (installs deps + trains the ML model).

---

## Step 4 — Add your free Llama key

In the Render dashboard:

1. Go to **assemblyai-web** → **Environment** tab.
2. Under **Environment Variables**, find `GROQ_API_KEY` (already declared
   in render.yaml; just empty).
3. Paste your `gsk_…` key from <https://console.groq.com>. Save.
4. Render auto-redeploys with the new key. Wait ~30 seconds.

`DATABASE_URL` is already wired up automatically by the Blueprint —
nothing for you to configure on that side.

---

## Step 5 — Open your live URL

Render gives you a URL like:

```
https://assemblyai-web-xxxx.onrender.com
```

Click it. You should see the Assembly.AI landing page. Drop a file,
analyze it, check the History tab — everything persists in real
PostgreSQL now.

Health probe: `https://your-url/api/health` should return:

```json
{
  "status": "ok",
  "provider": "groq",
  "db": { "dialect": "postgresql", ... }
}
```

---

## Important caveats of the free tier

| Thing                    | Behaviour                                                   |
|--------------------------|-------------------------------------------------------------|
| **Cold starts**          | Service sleeps after 15 min of no traffic; first request after a sleep takes 30-60 s to wake up. |
| **RAM**                  | 512 MB. Heavy concurrent uploads can OOM. For demos, fine.  |
| **Free Postgres expires**| 90 days. After that, upgrade to the $7/mo plan or rotate.   |
| **Disk is ephemeral**    | Uploads & generated PDFs vanish on each redeploy. The DB persists; old reports can be regenerated from the cached JSON dossier. |
| **Build minutes**        | 500 free build minutes per month. Each redeploy uses ~3 min.|

---

## Other free hosts (if Render doesn't fit)

### Railway.app
- $5/month free credit (≈ enough for one small always-on app).
- Simpler UX than Render, same flow: connect GitHub → deploy.
- Add Postgres via *New → Database → PostgreSQL*; Railway injects
  `DATABASE_URL` automatically.
- Use the same `Procfile`. No `render.yaml` needed.

### Fly.io
- 3 small VMs free + 3 GB volume. Always-on (no cold starts).
- More involved: install `flyctl`, run `fly launch`, answer prompts.
- Provision Postgres separately via `fly pg create`.

### PythonAnywhere
- Truly free forever, *.pythonanywhere.com URL, no cold starts.
- No Postgres on free tier — you get MySQL or SQLite. Set
  `DATABASE_URL=sqlite:///aisecops.db` and you're set.
- Manual upload via web UI (no GitHub integration on free).

### Hugging Face Spaces
- Free, ML-demo focused. Best if you wrap the analyzer as a Gradio app
  rather than the Flask UI we built.

---

## Reality check on hosting a malware analysis tool publicly

Most cloud providers' AUPs explicitly prohibit hosting public services
that process malware samples. **For a college demo / portfolio piece**
using harmless test files (the synthetic samples we tested with, dummy
PEs, etc.), this is fine. Don't publicly accept arbitrary uploads from
strangers — you'll get suspended.

If you need a "real" malware-handling deployment, consider:
- Self-hosting on a home server / lab VM
- Cloudflare Tunnel + a dedicated VPS (DigitalOcean droplet, $4/mo)
- Adding authentication so only you / authorized users can upload

For the BMS demo, Render's free tier with public access is perfect.

---

## Local-first alternative — share with `ngrok`

If you don't want to deploy at all, run locally and tunnel:

```bash
brew install ngrok          # one-time
python run.py               # in your venv
# in a separate terminal:
ngrok http 5000
```

ngrok gives you a `https://random-name.ngrok-free.app` URL that
forwards to your local server. Closes when you stop it. Zero
deployment, zero cost, perfect for a one-off demo to professors.
