/* Assembly.AI front-end logic. */
(() => {
  /* ------------- Health probe (header indicator) ------------- */
  async function probeHealth() {
    const dot  = document.querySelector(".status-dot");
    const text = document.getElementById("health-text");
    if (!dot || !text) return;
    try {
      const r = await fetch("/api/health");
      const j = await r.json();
      dot.style.background = j.status === "ok" ? "#34D399" : "#F59E0B";
      text.textContent = `LLM: ${j.provider}`;
    } catch {
      dot.style.background = "#EF4444";
      text.textContent = "Offline";
    }
  }
  probeHealth();

  /* ------------- Index page (upload) ------------- */
  const dz = document.getElementById("dropzone");
  if (dz) {
    const input    = document.getElementById("file-input");
    const pickInfo = document.getElementById("file-pick");
    const analyze  = document.getElementById("analyze-btn");
    const reset    = document.getElementById("reset-btn");
    const loader   = document.getElementById("loader");
    const errorBox = document.getElementById("error");
    const stepEls  = [...document.querySelectorAll("#steps .step")];
    let chosen = null;

    function setFile(f) {
      chosen = f;
      if (!f) {
        pickInfo.textContent = "Any binary, document, archive, or script.";
        analyze.disabled = true; reset.disabled = true;
        return;
      }
      pickInfo.textContent = `${f.name} · ${(f.size/1024).toFixed(1)} KB`;
      analyze.disabled = false; reset.disabled = false;
    }
    setFile(null);

    input.addEventListener("change", e => setFile(e.target.files[0] || null));

    ["dragenter","dragover"].forEach(ev =>
      dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave","drop"].forEach(ev =>
      dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("drag"); }));
    dz.addEventListener("drop", e => {
      const f = e.dataTransfer.files?.[0]; if (f) setFile(f);
    });

    reset.addEventListener("click", () => { input.value = ""; setFile(null);
      errorBox.style.display = "none"; });

    function setStep(now, done) {
      stepEls.forEach(el => {
        el.classList.remove("now", "done");
        const k = el.dataset.step;
        if (done.includes(k)) el.classList.add("done");
        else if (k === now)   el.classList.add("now");
      });
    }

    analyze.addEventListener("click", async () => {
      if (!chosen) return;
      errorBox.style.display = "none";
      analyze.disabled = true; reset.disabled = true;
      loader.classList.add("visible");

      // animate steps optimistically while server processes
      const order = ["hash","static","ml","ai","report"];
      let idx = 0; setStep(order[0], []);
      const pulse = setInterval(() => {
        idx = Math.min(idx + 1, order.length - 1);
        setStep(order[idx], order.slice(0, idx));
      }, 1500);

      try {
        const fd = new FormData();
        fd.append("file", chosen);
        const r = await fetch("/api/analyze", { method: "POST", body: fd });
        const j = await r.json();
        clearInterval(pulse);
        if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);

        // stash and navigate
        sessionStorage.setItem("aisecops:last", JSON.stringify(j));
        sessionStorage.setItem("aisecops:lastId", j.analysis_id);
        location.href = `/analysis.html?id=${j.analysis_id}`;
      } catch (err) {
        clearInterval(pulse);
        loader.classList.remove("visible");
        errorBox.textContent = "Analysis failed: " + err.message;
        errorBox.style.display = "block";
        analyze.disabled = false; reset.disabled = false;
      }
    });
  }

  /* ------------- Analysis page ------------- */
  window.renderAnalysisPage = async function () {
    const params = new URLSearchParams(location.search);
    const id = params.get("id") || sessionStorage.getItem("aisecops:lastId");
    if (!id) {
      document.getElementById("file-title").textContent = "No analysis selected.";
      return;
    }

    let data;
    const cached = sessionStorage.getItem("aisecops:last");
    if (cached) {
      try { data = JSON.parse(cached); } catch { /* ignore */ }
    }
    if (!data || data.analysis_id !== id) {
      try {
        const r = await fetch(`/api/analysis/${id}`);
        if (!r.ok) throw new Error("not found");
        data = await r.json();
      } catch (e) {
        document.getElementById("file-title").textContent = "Analysis not found.";
        return;
      }
    }

    const { static: stat, ml, ai, mitre, iocs } = data;
    const reportUrl = `/api/report/${id}`;
    document.getElementById("download-pdf").href = reportUrl;
    document.getElementById("report-link").href  = reportUrl;

    document.getElementById("file-title").textContent = stat.filename;
    document.getElementById("file-sub").textContent =
      `Analysis ID ${id} · ${stat.filetype} · ${stat.size_bytes.toLocaleString()} bytes · ${data.elapsed_seconds}s`;

    // Verdict cells
    const cells = [
      ["Verdict",        (ai.verdict || "unknown").toUpperCase(),
                         "v-" + (ai.verdict || "")],
      ["Severity",       (ai.severity || "unknown").toUpperCase(),
                         "v-" + (ai.severity || "")],
      ["Confidence",     `${Math.round((ai.confidence || 0) * 100)}%`, ""],
      ["Static Risk",    `${stat.static_risk_score || 0}/100`, ""],
      ["ML Probability", ml.malicious_probability == null
                          ? "n/a"
                          : `${Math.round(ml.malicious_probability * 100)}%`, ""],
    ];
    const vg = document.getElementById("verdict-grid");
    vg.innerHTML = cells.map(([lab, val, cls]) =>
      `<div class="verdict-cell"><div class="label">${lab}</div>
       <div class="value ${cls}">${escapeHtml(val)}</div></div>`).join("");

    // Exec summary
    document.getElementById("exec-summary").textContent =
      ai.executive_summary || "—";

    // Wire up the AI Analyst chat for this analysis
    initChat(id);

    // File KV
    const h = stat.hashes || {};
    document.getElementById("file-kv").innerHTML = kvRows([
      ["Filename", stat.filename],
      ["Type",     stat.filetype],
      ["Size",     stat.size_bytes.toLocaleString() + " bytes"],
      ["Entropy",  stat.entropy + " / 8.0"],
      ["MD5",      h.md5  || ""],
      ["SHA-1",    h.sha1 || ""],
      ["SHA-256",  h.sha256 || ""],
      ["AI Provider", ai._provider || "n/a"],
      ["Malware family", ai.malware_family || "—"],
    ]);

    // Suspicious APIs
    const apis = stat.suspicious_apis || [];
    if (apis.length) {
      document.getElementById("apis-block").innerHTML =
        `<table class="table"><thead><tr><th>API</th><th>Reason</th></tr></thead>
         <tbody>${apis.map(a =>
            `<tr><td>${escapeHtml(a.api)}</td><td>${escapeHtml(a.reason)}</td></tr>`
          ).join("")}</tbody></table>`;
    }

    // ML KV
    const mf = ml.features || {};
    const mm = ml.metrics  || {};
    const pct = v => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
    document.getElementById("ml-kv").innerHTML = kvRows([
      ["Algorithm",       ml.model_algorithm || "—"],
      ["Model version",   ml.model_version   || "—"],
      ["Label",           ml.label           || "—"],
      ["Malicious prob.", pct(ml.malicious_probability)],
      ["Anomaly score",   pct(ml.anomaly_score) + (ml.is_anomaly ? "  ⚠ outlier" : "")],
      ["Fused score",     pct(ml.fused_score)],
      ["Test AUC",        mm.test_auc == null ? "—" : mm.test_auc.toFixed(4)],
      ["Anomaly AUC",     mm.anomaly_test_auc == null ? "—" : mm.anomaly_test_auc.toFixed(4)],
      ["Suspicious APIs", mf.suspicious_api_count ?? "—"],
      ["Max sec. entropy", mf.max_section_entropy ?? "—"],
      ["Network APIs", mf.has_network_apis ? "yes" : "no"],
      ["Inject APIs",  mf.has_inject_apis  ? "yes" : "no"],
      ["Crypto APIs",  mf.has_crypto_apis  ? "yes" : "no"],
    ]);

    // Attack chain
    const chain = ai.attack_chain || [];
    if (chain.length) {
      document.getElementById("chain-block").innerHTML =
        `<table class="table">
          <thead><tr><th>#</th><th>Stage</th><th>Action</th><th>Evidence</th></tr></thead>
          <tbody>${chain.map(c =>
            `<tr>
              <td>${c.step ?? ""}</td>
              <td><span class="pill pill-stage">${escapeHtml(c.stage || "")}</span></td>
              <td>${escapeHtml(c.action || "")}</td>
              <td>${escapeHtml(c.evidence || "")}</td>
            </tr>`).join("")}
          </tbody></table>`;
    }

    // Process tree (ASCII rendering)
    const tree = ai.process_tree || [];
    if (tree.length) {
      const childrenOf = {}, all = new Set();
      tree.forEach(e => {
        if (!e.parent || !e.child) return;
        (childrenOf[e.parent] ??= []).push({ name: e.child, via: e.via || "" });
        all.add(e.parent); all.add(e.child);
      });
      const children = new Set(tree.map(e => e.child));
      const roots = [...all].filter(n => !children.has(n));
      const lines = [];
      const walk = (node, depth = 0) => {
        lines.push("  ".repeat(depth) + (depth ? "└─ " : "● ") + node);
        for (const c of (childrenOf[node] || [])) {
          if (c.via) lines.push("  ".repeat(depth + 1) + "│  via " + c.via);
          walk(c.name, depth + 1);
        }
      };
      roots.forEach(r => walk(r));
      document.getElementById("tree-block").textContent = lines.join("\n");
    }

    // MITRE
    if (mitre && mitre.length) {
      document.getElementById("mitre-block").innerHTML =
        `<table class="table">
          <thead><tr><th>Tactic</th><th>ID</th><th>Technique</th><th>Evidence</th></tr></thead>
          <tbody>${mitre.map(m =>
            `<tr>
              <td><span class="pill pill-tactic">${escapeHtml(m.tactic || "")}</span></td>
              <td><a href="https://attack.mitre.org/techniques/${(m.id||"").replace(".", "/")}/"
                     target="_blank" rel="noopener">${escapeHtml(m.id || "")}</a></td>
              <td>${escapeHtml(m.name || "")}</td>
              <td>${escapeHtml(m.evidence || "")}</td>
            </tr>`).join("")}
          </tbody></table>`;
    }

    // IOCs
    const iocLabels = {
      urls: "URLs", domains: "Domains", ipv4: "IPv4 Addresses",
      emails: "Email Addresses", btc: "Bitcoin", eth: "Ethereum",
      registry: "Registry Keys", filepaths: "File Paths", mutexes: "Mutexes",
    };
    const iocBlock = document.getElementById("iocs-block");
    let any = false; iocBlock.innerHTML = "";
    for (const k of Object.keys(iocLabels)) {
      const items = iocs?.[k] || [];
      if (!items.length) continue;
      any = true;
      const div = document.createElement("div");
      div.className = "ioc-group";
      div.innerHTML = `<h3>${iocLabels[k]} (${items.length})</h3>
        <ul>${items.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`;
      iocBlock.appendChild(div);
    }
    if (!any) iocBlock.innerHTML = `<p class="muted">No IOCs extracted.</p>`;

    // PE sections
    const sections = stat.pe?.sections || [];
    if (sections.length) {
      document.getElementById("sections-block").innerHTML =
        `<table class="table mono">
          <thead><tr><th>Name</th><th class="right">Virtual Size</th>
          <th class="right">Raw Size</th><th class="right">Entropy</th>
          <th>Characteristics</th></tr></thead>
          <tbody>${sections.map(s =>
            `<tr><td>${escapeHtml(s.name)}</td>
              <td class="right">${s.virtual_size.toLocaleString()}</td>
              <td class="right">${s.raw_size.toLocaleString()}</td>
              <td class="right">${s.entropy}</td>
              <td>${s.characteristics}</td></tr>`).join("")}
          </tbody></table>`;
    }

    // Recommendations
    const recs = ai.recommendations || [];
    document.getElementById("recs").innerHTML =
      recs.length ? recs.map(r => `<li>${escapeHtml(r)}</li>`).join("")
                  : `<li class="muted">No recommendations.</li>`;

    // Raw JSON toggle
    document.getElementById("raw").textContent = JSON.stringify(data, null, 2);
    document.getElementById("toggle-raw").addEventListener("click", () => {
      const r = document.getElementById("raw");
      r.style.display = r.style.display === "none" ? "block" : "none";
    });
  };

  /* ------------- History page ------------- */
  window.renderHistoryPage = async function () {
    const tbl  = document.getElementById("history-table");
    const grid = document.getElementById("stats-grid");
    const meta = document.getElementById("db-meta");
    let currentVerdict = "";

    async function load() {
      tbl.innerHTML = `<p class="muted">Loading…</p>`;
      try {
        const url = "/api/history" + (currentVerdict ? `?verdict=${currentVerdict}` : "");
        const r = await fetch(url);
        const j = await r.json();

        // stats
        const s = j.stats || {};
        const cells = [
          ["Total",       s.total ?? 0,       ""],
          ["Malicious",   s.malicious ?? 0,   "v-malicious"],
          ["Suspicious",  s.suspicious ?? 0,  "v-suspicious"],
          ["Benign",      s.benign ?? 0,      "v-benign"],
          ["Unknown",     s.unknown ?? 0,     ""],
        ];
        grid.innerHTML = cells.map(([lab, val, cls]) =>
          `<div class="verdict-cell"><div class="label">${lab}</div>
           <div class="value ${cls}">${val}</div></div>`).join("");

        meta.textContent = `Backend: ${j.db?.dialect || "?"} · ${j.db?.url_redacted || "?"}`;

        // table
        if (!j.items || !j.items.length) {
          tbl.innerHTML = `<p class="muted">No analyses recorded yet. Run one from the home page.</p>`;
          return;
        }
        tbl.innerHTML = `<table class="table">
          <thead><tr>
            <th>Time</th><th>File</th><th>Type</th><th>SHA-256</th>
            <th>Verdict</th><th>Severity</th><th>ML</th><th>MITRE</th><th>IOCs</th><th></th>
          </tr></thead>
          <tbody>${j.items.map(it => `
            <tr>
              <td><span class="muted" style="font-size:12px;">${new Date(it.created_at).toLocaleString()}</span></td>
              <td>${escapeHtml(it.filename)}</td>
              <td>${escapeHtml(it.filetype || "")}</td>
              <td style="font-family:var(--mono); font-size:11px;">${(it.sha256 || "").slice(0, 16)}…</td>
              <td><span class="value v-${it.verdict || ""}" style="font-size:13px; font-weight:600;">${(it.verdict || "?").toUpperCase()}</span></td>
              <td><span class="value v-${it.severity || ""}" style="font-size:13px; font-weight:600;">${(it.severity || "?").toUpperCase()}</span></td>
              <td>${it.ml_probability == null ? "—" : Math.round(it.ml_probability * 100) + "%"}</td>
              <td>${it.mitre_count}</td>
              <td>${it.ioc_total}</td>
              <td>
                <a class="btn outline" style="padding:4px 10px; font-size:12px;"
                   href="/analysis.html?id=${encodeURIComponent(it.analysis_id)}">Open</a>
              </td>
            </tr>`).join("")}
          </tbody></table>`;
      } catch (e) {
        tbl.innerHTML = `<div class="error-box">Failed to load history: ${escapeHtml(e.message)}</div>`;
      }
    }

    document.querySelectorAll("[data-verdict]").forEach(btn => {
      btn.addEventListener("click", () => {
        currentVerdict = btn.dataset.verdict;
        load();
      });
    });
    document.getElementById("refresh").addEventListener("click", load);

    load();
  };

  /* ------------- AI Analyst chat ------------- */
  function initChat(analysisId) {
    const win    = document.getElementById("chat-window");
    const empty  = document.getElementById("chat-empty");
    const form   = document.getElementById("chat-form");
    const text   = document.getElementById("chat-text");
    const send   = document.getElementById("chat-send");
    const clear  = document.getElementById("chat-clear");
    const badge  = document.getElementById("chat-provider");
    if (!win || !form) return;

    let busy = false;

    function addBubble(role, content, provider) {
      if (empty) empty.style.display = "none";
      const wrap = document.createElement("div");
      wrap.className = `chat-msg chat-${role}`;
      const who = role === "user" ? "You"
                : role === "assistant" ? "AI Analyst" : "System";
      wrap.innerHTML =
        `<div class="chat-meta">${who}${provider ? ` · ${escapeHtml(provider)}` : ""}</div>
         <div class="chat-body">${renderMarkdown(content)}</div>`;
      win.appendChild(wrap);
      win.scrollTop = win.scrollHeight;
      return wrap;
    }

    function setBusy(b) {
      busy = b;
      send.disabled = b;
      text.disabled = b;
      send.textContent = b ? "…" : "Send";
    }

    async function loadHistory() {
      try {
        const r = await fetch(`/api/chat/${analysisId}`);
        const j = await r.json();
        if (j.messages && j.messages.length) {
          j.messages.forEach(m => addBubble(m.role, m.content, m.provider));
        }
      } catch { /* ignore */ }
    }

    async function ask(question) {
      if (busy || !question.trim()) return;
      addBubble("user", question);
      text.value = "";
      autoGrow();
      setBusy(true);

      const thinking = addBubble("assistant", "_Analyzing…_", "");
      thinking.classList.add("chat-thinking");

      try {
        const r = await fetch(`/api/chat/${analysisId}`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ message: question }),
        });
        const j = await r.json();
        thinking.remove();
        if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
        addBubble("assistant", j.response, j.provider);
        if (badge && j.provider) badge.textContent = j.provider;
      } catch (err) {
        thinking.remove();
        addBubble("assistant", `⚠️ ${err.message}`, "error");
      } finally {
        setBusy(false);
        text.focus();
      }
    }

    function autoGrow() {
      text.style.height = "auto";
      text.style.height = Math.min(text.scrollHeight, 140) + "px";
    }

    // suggestion chips
    document.querySelectorAll("#chat-suggestions .chip").forEach(chip => {
      chip.addEventListener("click", () => ask(chip.dataset.q));
    });

    // submit
    form.addEventListener("submit", e => { e.preventDefault(); ask(text.value); });
    text.addEventListener("input", autoGrow);
    text.addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(text.value); }
    });

    // clear
    clear.addEventListener("click", async () => {
      if (busy) return;
      if (!confirm("Clear this conversation?")) return;
      try { await fetch(`/api/chat/${analysisId}`, { method: "DELETE" }); } catch {}
      win.querySelectorAll(".chat-msg").forEach(n => n.remove());
      if (empty) empty.style.display = "";
    });

    loadHistory();
  }

  /* Minimal, safe markdown → HTML for chat bubbles.
     Handles fenced code blocks, inline code, bold, and line breaks. */
  function renderMarkdown(src) {
    if (src == null) return "";
    const blocks = [];
    // pull fenced code blocks out first so we don't escape inside them twice
    let tmp = String(src).replace(/```(\w+)?\n?([\s\S]*?)```/g, (_, lang, code) => {
      const idx = blocks.length;
      blocks.push(
        `<pre class="chat-code" data-lang="${escapeHtml(lang || "")}">` +
        `<code>${escapeHtml(code.replace(/\n$/, ""))}</code></pre>`);
      return ` BLOCK${idx} `;
    });

    tmp = escapeHtml(tmp)
      .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/^\s*[-*]\s+(.*)$/gm, "• $1")
      .replace(/\n/g, "<br/>");

    tmp = tmp.replace(/ BLOCK(\d+) /g, (_, i) => blocks[+i]);
    return tmp;
  }

  /* ------------- helpers ------------- */
  function kvRows(rows) {
    return rows.map(([k, v]) =>
      `<div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(String(v))}</div>`
    ).join("");
  }
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
