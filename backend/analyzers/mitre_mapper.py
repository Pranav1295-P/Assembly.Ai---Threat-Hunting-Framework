"""Heuristic mapping of static-analysis observables to MITRE ATT&CK techniques.

This is the deterministic mapper. The AI analyzer can extend / refine these
classifications, but this module guarantees we always return *some* coverage
even if the LLM step is skipped."""
from __future__ import annotations

from typing import Any, Dict, List

# Maps an internal observable key → ATT&CK reference
TECHNIQUES = {
    "T1059":      ("Command and Scripting Interpreter",   "Execution"),
    "T1059.001":  ("PowerShell",                          "Execution"),
    "T1059.003":  ("Windows Command Shell",               "Execution"),
    "T1059.005":  ("Visual Basic",                        "Execution"),
    "T1055":      ("Process Injection",                   "Defense Evasion"),
    "T1055.002":  ("Portable Executable Injection",       "Defense Evasion"),
    "T1055.003":  ("Thread Execution Hijacking",          "Defense Evasion"),
    "T1071":      ("Application Layer Protocol",          "Command and Control"),
    "T1071.001":  ("Web Protocols (HTTP/S)",              "Command and Control"),
    "T1095":      ("Non-Application Layer Protocol",      "Command and Control"),
    "T1105":      ("Ingress Tool Transfer",               "Command and Control"),
    "T1129":      ("Shared Modules",                      "Execution"),
    "T1547.001":  ("Registry Run Keys / Startup Folder",  "Persistence"),
    "T1543.003":  ("Windows Service",                     "Persistence"),
    "T1056.001":  ("Keylogging",                          "Collection"),
    "T1486":      ("Data Encrypted for Impact",           "Impact"),
    "T1057":      ("Process Discovery",                   "Discovery"),
    "T1082":      ("System Information Discovery",        "Discovery"),
    "T1622":      ("Debugger Evasion",                    "Defense Evasion"),
    "T1497.003":  ("Time Based Evasion",                  "Defense Evasion"),
    "T1027":      ("Obfuscated Files or Information",     "Defense Evasion"),
    "T1027.002":  ("Software Packing",                    "Defense Evasion"),
    "T1134":      ("Access Token Manipulation",           "Privilege Escalation"),
    "T1548.002":  ("Bypass User Account Control (UAC)",   "Privilege Escalation"),
    "T1218":      ("System Binary Proxy Execution",       "Defense Evasion"),
    "T1204.002":  ("User Execution: Malicious File",      "Execution"),
    "T1566.001":  ("Phishing: Spearphishing Attachment",  "Initial Access"),
}

# API name → list of techniques
API_TO_TECHNIQUES = {
    "VirtualAlloc":             ["T1055"],
    "VirtualAllocEx":           ["T1055.002"],
    "WriteProcessMemory":       ["T1055.002"],
    "CreateRemoteThread":       ["T1055.003"],
    "NtCreateThreadEx":         ["T1055.003"],
    "LoadLibraryA":             ["T1129"],
    "GetProcAddress":           ["T1129"],
    "WinExec":                  ["T1059", "T1059.003"],
    "ShellExecuteA":            ["T1059"],
    "URLDownloadToFileA":       ["T1105"],
    "InternetOpenA":            ["T1071.001"],
    "InternetReadFile":         ["T1071.001"],
    "HttpSendRequestA":         ["T1071.001"],
    "WSAStartup":               ["T1095"],
    "RegSetValueExA":           ["T1547.001"],
    "RegCreateKeyExA":          ["T1547.001"],
    "SetWindowsHookExA":        ["T1056.001"],
    "GetAsyncKeyState":         ["T1056.001"],
    "CryptEncrypt":             ["T1486"],
    "OpenProcess":              ["T1057"],
    "Process32First":           ["T1057"],
    "IsDebuggerPresent":        ["T1622"],
    "CheckRemoteDebuggerPresent": ["T1622"],
    "NtQueryInformationProcess": ["T1622"],
    "GetTickCount":             ["T1497.003"],
    "Sleep":                    ["T1497.003"],
    "AdjustTokenPrivileges":    ["T1134"],
    "OpenSCManagerA":           ["T1543.003"],
    "CreateServiceA":           ["T1543.003"],
}


def map_static(static: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return list of {id, name, tactic, evidence} from static observables."""
    hits: Dict[str, Dict[str, str]] = {}

    # APIs
    for s in static.get("suspicious_apis", []):
        api = s.get("api")
        for tid in API_TO_TECHNIQUES.get(api, []):
            name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
            hits.setdefault(tid, {
                "id": tid, "name": name, "tactic": tactic,
                "evidence": f"Imported / referenced API: {api}",
            })

    # Packing / high entropy
    if static.get("packer_hints"):
        for tid in ("T1027", "T1027.002"):
            name, tactic = TECHNIQUES[tid]
            hits.setdefault(tid, {
                "id": tid, "name": name, "tactic": tactic,
                "evidence": "; ".join(static["packer_hints"][:3]),
            })

    # Office docs that we can identify by filetype
    ftype = (static.get("filetype") or "").lower()
    if "ole" in ftype or "office" in ftype or "ooxml" in ftype:
        hits.setdefault("T1566.001", {
            "id": "T1566.001",
            "name": TECHNIQUES["T1566.001"][0],
            "tactic": TECHNIQUES["T1566.001"][1],
            "evidence": "Office document — common phishing vector",
        })
        hits.setdefault("T1204.002", {
            "id": "T1204.002",
            "name": TECHNIQUES["T1204.002"][0],
            "tactic": TECHNIQUES["T1204.002"][1],
            "evidence": "Document expected to be opened by user",
        })

    return sorted(hits.values(), key=lambda x: (x["tactic"], x["id"]))


def merge(static_hits: List[Dict[str, str]],
          ai_hits:     List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Combine static + LLM-derived MITRE hits, de-duplicating by id."""
    by_id: Dict[str, Dict[str, str]] = {h["id"]: h for h in static_hits}
    for h in ai_hits or []:
        tid = h.get("id")
        if not tid:
            continue
        if tid in by_id:
            existing = by_id[tid]
            ev_existing = existing.get("evidence", "")
            ev_ai       = h.get("evidence", "")
            if ev_ai and ev_ai not in ev_existing:
                existing["evidence"] = f"{ev_existing} | AI: {ev_ai}".strip(" |")
        else:
            # Fill in canonical name/tactic if known
            tid_meta = TECHNIQUES.get(tid)
            if tid_meta:
                h.setdefault("name",   tid_meta[0])
                h.setdefault("tactic", tid_meta[1])
            by_id[tid] = h
    return sorted(by_id.values(), key=lambda x: (x.get("tactic", ""), x["id"]))
