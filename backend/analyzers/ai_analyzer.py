"""LLM-driven investigation.

Builds a structured prompt from the static-analysis context, calls the
configured LLM and asks it to return a strict JSON object describing the
attack chain, MITRE techniques, severity, IOC validation, and a process tree.

Supported providers:
  - anthropic  (Claude)
  - openai     (GPT-x)
  - groq       (free Llama 3.3 70B / Mixtral / Gemma)        ← OpenAI-compat
  - openrouter (free Llama / Mistral / Gemma)                ← OpenAI-compat
  - together   (free Llama Turbo)                            ← OpenAI-compat
  - ollama     (local Llama / Mistral / Qwen — no key)       ← OpenAI-compat
  - heuristic  (deterministic fallback when no key is set)

If a call fails the heuristic fallback kicks in and the pipeline still
produces a complete report."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import config

SYSTEM_PROMPT = """You are a senior malware reverse engineer working in a
SOC. You will receive a structured static-analysis dossier of a single file.
Your job is to reconstruct the most likely attack chain, identify MITRE
ATT&CK techniques with high confidence, classify severity, and flag the most
important IOCs.

Return STRICT JSON only — no prose, no markdown fences. Schema:

{
  "executive_summary": "<<=120 word plain-English summary>>",
  "verdict":            "benign" | "suspicious" | "malicious",
  "malware_family":     "<best-guess family or empty string>",
  "severity":           "low" | "medium" | "high" | "critical",
  "confidence":         0.0-1.0,
  "attack_chain": [
    {"step": 1, "stage": "Initial Access" | "Execution" | "Persistence" | "Privilege Escalation" | "Defense Evasion" | "Credential Access" | "Discovery" | "Lateral Movement" | "Collection" | "Exfiltration" | "Command and Control" | "Impact",
     "action": "<short imperative>",
     "evidence": "<concrete evidence from the dossier>"}
  ],
  "mitre": [
    {"id": "Txxxx[.yyy]", "name": "<technique>", "tactic": "<tactic>", "evidence": "<why>"}
  ],
  "ioc_assessment": {
    "high_confidence": ["..."],
    "low_confidence":  ["..."],
    "comments":        "<short>"
  },
  "process_tree": [
    {"parent": "<proc>", "child": "<proc>", "via": "<api or technique>"}
  ],
  "recommendations": ["<short imperative bullet>", "..."]
}
"""


def _build_user_prompt(static: Dict[str, Any], ml: Dict[str, Any], iocs: Dict[str, Any]) -> str:
    pe = static.get("pe") or {}
    trimmed_imports = []
    for entry in pe.get("imports", [])[:25]:
        trimmed_imports.append({
            "dll": entry.get("dll"),
            "functions": entry.get("functions", [])[:30],
        })

    dossier = {
        "filename":          static.get("filename"),
        "filetype":          static.get("filetype"),
        "size_bytes":        static.get("size_bytes"),
        "hashes":            static.get("hashes"),
        "entropy":           static.get("entropy"),
        "static_risk_score": static.get("static_risk_score"),
        "packer_hints":      static.get("packer_hints"),
        "suspicious_apis":   static.get("suspicious_apis"),
        "pe_summary": {
            "is_dll":    pe.get("is_dll"),
            "is_exe":    pe.get("is_exe"),
            "is_driver": pe.get("is_driver"),
            "arch":      pe.get("arch"),
            "sections":  pe.get("sections", [])[:12],
            "imports":   trimmed_imports,
            "exports_sample": (pe.get("exports") or [])[:25],
        } if pe.get("is_pe") else None,
        "iocs":              iocs,
        "ml_classifier":     ml,
        "strings_sample":    static.get("strings_sample", [])[:120],
    }
    return (
        "Analyze the following static-analysis dossier and return JSON per the "
        "schema. Be conservative — do not invent IOCs.\n\n```json\n"
        + json.dumps(dossier, indent=2, default=str)
        + "\n```"
    )


def _extract_json(text: str) -> Dict[str, Any]:
    """Robust JSON extraction tolerant to markdown fences / prose."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last != -1 and last > first:
        text = text[first : last + 1]
    return json.loads(text)


# ---------- Provider implementations ----------

def _call_anthropic(user_prompt: str) -> Dict[str, Any]:
    from anthropic import Anthropic
    client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=2500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    return _extract_json(text)


def _call_openai_compatible(user_prompt: str, *, api_key: str, base_url: str | None,
                            model: str, force_json: bool = True,
                            extra_headers: dict | None = None) -> Dict[str, Any]:
    """Generic caller for any OpenAI-compatible endpoint:
    OpenAI, Groq, OpenRouter, Together, Ollama, vLLM, LM Studio, Azure …"""
    from openai import OpenAI
    kwargs = {"api_key": api_key or "ollama"}  # Ollama needs a non-empty value
    if base_url:
        kwargs["base_url"] = base_url
    if extra_headers:
        kwargs["default_headers"] = extra_headers
    client = OpenAI(**kwargs)

    create_kwargs = {
        "model":       model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
    }
    if force_json:
        # Most providers honour this; Ollama/some Llama variants ignore it
        # but still produce JSON because of the system prompt.
        try:
            create_kwargs["response_format"] = {"type": "json_object"}
        except Exception:
            pass

    try:
        rsp = client.chat.completions.create(**create_kwargs)
    except Exception:
        # retry without response_format for providers that reject it
        create_kwargs.pop("response_format", None)
        rsp = client.chat.completions.create(**create_kwargs)
    return _extract_json(rsp.choices[0].message.content)


# =====================================================================
# Conversational analyst — chat about an already-analysed sample
# =====================================================================

CHAT_SYSTEM_PROMPT = """You are a senior malware reverse engineer assisting an
analyst in a SOC. You have access to a complete static-analysis dossier of a
sample the analyst already uploaded.

Rules:
- Answer questions about THIS sample only, using evidence from the dossier.
- Be technical, concise (<=300 words unless asked for more), and cite specific
  observables (API names, section names, IOCs, hashes).
- If asked to generate a detection rule (YARA, Sigma, Snort, ClamAV, Suricata)
  or a hunting query, output a syntactically valid rule keyed off this sample's
  distinctive characteristics. Wrap it in a fenced code block (```yara, ```sigma, etc.).
- If the dossier cannot answer a question, say so — do not invent IOCs or claims.
- Use markdown for formatting. Use code blocks for any rule / command / regex.
"""


def _trim_dossier(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the most informative fields, drop noise that bloats context."""
    static = dossier.get("static", {}) or {}
    pe     = static.get("pe") or {}
    ai     = dossier.get("ai", {}) or {}

    imports = []
    for entry in pe.get("imports", [])[:18]:
        imports.append({
            "dll":       entry.get("dll"),
            "functions": entry.get("functions", [])[:25],
        })

    return {
        "filename":          static.get("filename"),
        "filetype":          static.get("filetype"),
        "size_bytes":        static.get("size_bytes"),
        "hashes":            static.get("hashes"),
        "entropy":           static.get("entropy"),
        "static_risk_score": static.get("static_risk_score"),
        "suspicious_apis":   static.get("suspicious_apis"),
        "packer_hints":      static.get("packer_hints"),
        "pe": {
            "arch":      pe.get("arch"),
            "is_dll":    pe.get("is_dll"),
            "is_exe":    pe.get("is_exe"),
            "is_driver": pe.get("is_driver"),
            "sections":  pe.get("sections", [])[:12],
            "imports":   imports,
            "exports":   (pe.get("exports") or [])[:25],
        } if pe.get("is_pe") else None,
        "iocs":              dossier.get("iocs"),
        "ml":                dossier.get("ml"),
        "ai_summary":        ai.get("executive_summary"),
        "ai_verdict":        ai.get("verdict"),
        "ai_severity":       ai.get("severity"),
        "attack_chain":      ai.get("attack_chain"),
        "mitre":             dossier.get("mitre"),
        "strings_sample":    static.get("strings_sample", [])[:80],
    }


def chat(dossier: Dict[str, Any],
         history: List[Dict[str, str]]) -> Dict[str, Any]:
    """Continue a conversation about the supplied analysis dossier.

    Args:
        dossier: full analysis payload (the dict returned by /api/analyze).
        history: list of {"role": "user"|"assistant", "content": str};
                 the LAST entry is the new user message.

    Returns:
        {"response": str, "provider": str}
    """
    provider = config.llm_provider()
    trimmed  = _trim_dossier(dossier)

    dossier_block = ("## Sample dossier\n\n```json\n"
                     + json.dumps(trimmed, indent=2, default=str)
                     + "\n```")

    # Inject the dossier as the opening turn so the model has full context.
    primer = [
        {"role": "user", "content":
            dossier_block + "\n\nKeep this dossier in mind for all my "
            "follow-up questions."},
        {"role": "assistant", "content":
            f"Dossier loaded for `{trimmed.get('filename')}`. "
            f"Current verdict: **{(trimmed.get('ai_verdict') or 'unknown').upper()}**. "
            "What would you like to know?"},
    ]
    messages = primer + (history or [])

    try:
        if provider == "anthropic":
            from anthropic import Anthropic
            client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model=config.ANTHROPIC_MODEL,
                max_tokens=1500,
                system=CHAT_SYSTEM_PROMPT,
                messages=messages,
            )
            text = "".join(b.text for b in msg.content
                           if getattr(b, "type", "") == "text")
            return {"response": text, "provider": provider}

        if provider in ("groq", "openrouter", "together", "openai", "ollama"):
            from openai import OpenAI
            extra_headers = None
            if provider == "groq":
                api_key, base_url, model = (config.GROQ_API_KEY,
                                            config.GROQ_BASE_URL, config.GROQ_MODEL)
            elif provider == "openrouter":
                api_key, base_url, model = (config.OPENROUTER_API_KEY,
                                            config.OPENROUTER_BASE_URL,
                                            config.OPENROUTER_MODEL)
                extra_headers = {"HTTP-Referer": "https://assembly.ai-sec-ops.local",
                                 "X-Title": "Assembly.AI"}
            elif provider == "together":
                api_key, base_url, model = (config.TOGETHER_API_KEY,
                                            config.TOGETHER_BASE_URL,
                                            config.TOGETHER_MODEL)
            elif provider == "ollama":
                api_key  = "ollama"
                base_url = config.OLLAMA_BASE_URL or "http://127.0.0.1:11434/v1"
                model    = config.OLLAMA_MODEL
            else:  # openai
                api_key  = config.OPENAI_API_KEY
                base_url = config.OPENAI_BASE_URL or None
                model    = config.OPENAI_MODEL

            kwargs = {"api_key": api_key or "ignored"}
            if base_url:      kwargs["base_url"] = base_url
            if extra_headers: kwargs["default_headers"] = extra_headers
            client = OpenAI(**kwargs)

            rsp = client.chat.completions.create(
                model=model, temperature=0.2,
                messages=[{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + messages,
            )
            return {"response": rsp.choices[0].message.content, "provider": provider}

        # heuristic / no provider configured
        last_user = next((m["content"] for m in reversed(history or [])
                          if m.get("role") == "user"), "")
        return {
            "response": ("AI chat is unavailable because no LLM provider is "
                         "configured. Set `GROQ_API_KEY` (free at "
                         "https://console.groq.com) or `OLLAMA_BASE_URL` in "
                         "`backend/.env`, then restart the server.\n\n"
                         f"Your question was: *{last_user[:160]}*"),
            "provider": "heuristic",
        }
    except Exception as e:                                      # noqa: BLE001
        return {"response": f"LLM call failed: `{e}`",
                "provider": f"{provider}-error"}


def _heuristic_fallback(static: Dict[str, Any], ml: Dict[str, Any]) -> Dict[str, Any]:
    apis = [a["api"] for a in static.get("suspicious_apis", [])]
    score = static.get("static_risk_score", 0)
    ml_p  = (ml or {}).get("malicious_probability", 0.0) or 0.0

    if score >= 60 or ml_p >= 0.85:
        verdict, sev = "malicious", "high"
    elif score >= 35 or ml_p >= 0.6:
        verdict, sev = "suspicious", "medium"
    else:
        verdict, sev = "benign", "low"

    chain = []
    if "URLDownloadToFileA" in apis or static.get("ioc_count", 0):
        chain.append({"step": len(chain) + 1, "stage": "Command and Control",
                      "action": "Reach out to remote host",
                      "evidence": "Downloader API or external URL detected"})
    if any(a in apis for a in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")):
        chain.append({"step": len(chain) + 1, "stage": "Defense Evasion",
                      "action": "Inject code into another process",
                      "evidence": "Process-injection API combination present"})
    if "RegSetValueExA" in apis or "RegCreateKeyExA" in apis:
        chain.append({"step": len(chain) + 1, "stage": "Persistence",
                      "action": "Establish registry persistence",
                      "evidence": "Registry-write APIs present"})
    if "CryptEncrypt" in apis:
        chain.append({"step": len(chain) + 1, "stage": "Impact",
                      "action": "Encrypt user data (possible ransomware)",
                      "evidence": "Crypto-encryption API present"})
    if not chain:
        chain.append({"step": 1, "stage": "Discovery",
                      "action": "Survey host",
                      "evidence": "No high-confidence behavioural indicators"})

    return {
        "executive_summary":
            f"Heuristic fallback (no LLM key configured). Static-risk score "
            f"{score}/100, ML malicious probability {ml_p:.2f}. "
            f"Verdict: {verdict}.",
        "verdict":        verdict,
        "malware_family": "",
        "severity":       sev,
        "confidence":     0.55,
        "attack_chain":   chain,
        "mitre":          [],
        "ioc_assessment": {
            "high_confidence": [],
            "low_confidence":  [],
            "comments":        "Heuristic mode — no LLM IOC validation performed.",
        },
        "process_tree": [
            {"parent": "explorer.exe", "child": static.get("filename", "sample.bin"),
             "via": "User Execution"},
        ],
        "recommendations": [
            "Detonate the sample in an isolated VM with full Sysmon logging.",
            "Submit hash to VirusTotal / MalwareBazaar for community context.",
            "Block resolved C2 domains at the network egress.",
        ],
        "_provider": "heuristic",
    }


def investigate(static: Dict[str, Any], ml: Dict[str, Any],
                iocs: Dict[str, Any]) -> Dict[str, Any]:
    """Public entry point used by the orchestrator."""
    provider = config.llm_provider()
    user_prompt = _build_user_prompt(static, ml, iocs)

    try:
        if provider == "anthropic":
            result = _call_anthropic(user_prompt)

        elif provider == "groq":
            result = _call_openai_compatible(
                user_prompt,
                api_key=config.GROQ_API_KEY,
                base_url=config.GROQ_BASE_URL,
                model=config.GROQ_MODEL,
            )

        elif provider == "openrouter":
            result = _call_openai_compatible(
                user_prompt,
                api_key=config.OPENROUTER_API_KEY,
                base_url=config.OPENROUTER_BASE_URL,
                model=config.OPENROUTER_MODEL,
                extra_headers={
                    "HTTP-Referer": "https://assembly.ai-sec-ops.local",
                    "X-Title":      "Assembly.AI",
                },
            )

        elif provider == "together":
            result = _call_openai_compatible(
                user_prompt,
                api_key=config.TOGETHER_API_KEY,
                base_url=config.TOGETHER_BASE_URL,
                model=config.TOGETHER_MODEL,
            )

        elif provider == "ollama":
            base_url = config.OLLAMA_BASE_URL or "http://127.0.0.1:11434/v1"
            result = _call_openai_compatible(
                user_prompt,
                api_key="ollama",          # ignored by Ollama
                base_url=base_url,
                model=config.OLLAMA_MODEL,
                force_json=False,          # Ollama may not accept response_format
            )

        elif provider == "openai":
            result = _call_openai_compatible(
                user_prompt,
                api_key=config.OPENAI_API_KEY,
                base_url=config.OPENAI_BASE_URL or None,
                model=config.OPENAI_MODEL,
            )

        else:
            result = _heuristic_fallback(static, ml)

        result.setdefault("_provider", provider)
        return result

    except Exception as e:                      # noqa: BLE001
        fallback = _heuristic_fallback(static, ml)
        fallback["_provider"] = f"{provider}-error"
        fallback["_error"]    = str(e)
        return fallback
