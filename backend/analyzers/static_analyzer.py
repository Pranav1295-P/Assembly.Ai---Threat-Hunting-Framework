"""Static analysis: hashes, filetype, entropy, PE header parsing,
suspicious-API spotting, packer hints."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from utils.file_utils import (
    detect_filetype,
    extract_strings,
    file_entropy,
    file_hashes,
)

# APIs that frequently appear in malware (T1059, T1055, T1106 …).
SUSPICIOUS_APIS = {
    "VirtualAlloc": "Memory allocation often used by shellcode loaders (T1055)",
    "VirtualAllocEx": "Cross-process memory allocation — process injection (T1055.002)",
    "WriteProcessMemory": "Writes into another process memory (T1055.002)",
    "CreateRemoteThread": "Creates remote thread in another process (T1055.003)",
    "NtCreateThreadEx": "Stealthier process injection primitive (T1055.003)",
    "LoadLibraryA": "Dynamic API resolution (T1129)",
    "GetProcAddress": "Dynamic API resolution (T1129)",
    "WinExec": "Process execution primitive (T1059)",
    "ShellExecuteA": "Process execution / payload launch (T1059)",
    "URLDownloadToFileA": "Network downloader (T1105)",
    "InternetOpenA": "Network communication (T1071)",
    "InternetReadFile": "C2 read (T1071)",
    "HttpSendRequestA": "C2 traffic (T1071.001)",
    "WSAStartup": "Raw socket networking (T1095)",
    "RegSetValueExA": "Registry persistence (T1547.001)",
    "RegCreateKeyExA": "Registry persistence (T1547.001)",
    "SetWindowsHookExA": "Keylogger / hook installation (T1056.001)",
    "GetAsyncKeyState": "Keylogging (T1056.001)",
    "CryptEncrypt": "Possible ransomware encryption (T1486)",
    "CryptGenRandom": "Crypto material generation",
    "OpenProcess": "Process tampering (T1057)",
    "Process32First": "Process discovery (T1057)",
    "IsDebuggerPresent": "Anti-debugging (T1622)",
    "CheckRemoteDebuggerPresent": "Anti-debugging (T1622)",
    "NtQueryInformationProcess": "Anti-debugging (T1622)",
    "GetTickCount": "Sandbox-evasion timing check (T1497.003)",
    "Sleep": "Sandbox-evasion timing (T1497.003)",
    "FindResourceA": "Embedded payload extraction",
    "LockResource": "Embedded payload extraction",
    "AdjustTokenPrivileges": "Privilege escalation (T1134)",
    "OpenSCManagerA": "Service install / persistence (T1543.003)",
    "CreateServiceA": "Service install / persistence (T1543.003)",
}

KNOWN_PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".pebundle",
    "Themida", ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".enigma1", ".enigma2", ".petite", ".nsp0", ".nsp1",
    ".mpress1", ".mpress2", ".RLPack", ".boom", ".y0da",
}


def _safe_pe(path: Path) -> Dict[str, Any]:
    """Best-effort PE header parsing. Returns {} for non-PE files."""
    try:
        import pefile  # local import — heavy
    except Exception:
        return {}

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception:
        return {}

    sections = []
    for s in pe.sections:
        try:
            name = s.Name.decode(errors="ignore").rstrip("\x00")
        except Exception:
            name = "?"
        sections.append({
            "name": name,
            "virtual_size": int(s.Misc_VirtualSize),
            "raw_size": int(s.SizeOfRawData),
            "entropy": round(s.get_entropy(), 4),
            "characteristics": hex(s.Characteristics),
        })

    imports: List[Dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else "?"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="ignore"))
            imports.append({"dll": dll, "functions": funcs})

    exports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="ignore"))

    is_dll  = bool(pe.is_dll())
    is_exe  = bool(pe.is_exe())
    is_drv  = bool(pe.is_driver())

    machine = pe.FILE_HEADER.Machine
    arch = {
        0x14c:  "x86",
        0x8664: "x86_64",
        0x1c0:  "ARM",
        0xaa64: "ARM64",
    }.get(machine, hex(machine))

    return {
        "is_pe":            True,
        "arch":             arch,
        "is_dll":           is_dll,
        "is_exe":           is_exe,
        "is_driver":        is_drv,
        "timestamp":        int(pe.FILE_HEADER.TimeDateStamp),
        "image_base":       hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point":      hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "subsystem":        int(pe.OPTIONAL_HEADER.Subsystem),
        "section_count":    len(sections),
        "sections":         sections,
        "imports":          imports,
        "exports":          exports,
        "import_dll_count": len(imports),
        "import_func_count": sum(len(i["functions"]) for i in imports),
    }


def _suspicious_api_hits(pe_info: Dict[str, Any], strings: List[str]) -> List[Dict[str, str]]:
    seen: Dict[str, str] = {}

    # From PE imports
    for entry in pe_info.get("imports", []):
        for fn in entry.get("functions", []):
            if fn in SUSPICIOUS_APIS and fn not in seen:
                seen[fn] = SUSPICIOUS_APIS[fn]

    # From extracted strings (catches dynamically-resolved APIs)
    if not seen:
        for s in strings:
            for api in SUSPICIOUS_APIS:
                if api in s and api not in seen:
                    seen[api] = SUSPICIOUS_APIS[api]
                    if len(seen) >= 32:
                        break
            if len(seen) >= 32:
                break

    return [{"api": k, "reason": v} for k, v in seen.items()]


def _packer_hints(pe_info: Dict[str, Any]) -> List[str]:
    hints: List[str] = []
    for sec in pe_info.get("sections", []):
        if sec["name"] in KNOWN_PACKER_SECTIONS:
            hints.append(f"Packer section detected: {sec['name']}")
        if sec["entropy"] >= 7.2 and sec["raw_size"] > 4096:
            hints.append(f"High-entropy section: {sec['name']} ({sec['entropy']})")
    return hints


def analyze(path: Path) -> Dict[str, Any]:
    path = Path(path)
    out: Dict[str, Any] = {
        "filename":  path.name,
        "size_bytes": path.stat().st_size,
        "filetype":  detect_filetype(path),
        "hashes":    file_hashes(path),
        "entropy":   file_entropy(path),
    }
    strings = extract_strings(path)
    out["strings_sample"] = strings[:200]
    out["string_count"]   = len(strings)

    pe_info = _safe_pe(path)
    out["pe"] = pe_info

    out["suspicious_apis"] = _suspicious_api_hits(pe_info, strings)
    out["packer_hints"]    = _packer_hints(pe_info)

    # Overall static-only risk score (0–100)
    score = 0
    score += min(40, len(out["suspicious_apis"]) * 4)
    score += 15 if out["entropy"] >= 7.2 else 0
    score += 15 if out["packer_hints"] else 0
    if pe_info.get("is_driver"):
        score += 10
    if pe_info.get("is_dll") and len(pe_info.get("exports", [])) == 0:
        score += 5  # DLL with no exports is unusual
    out["static_risk_score"] = min(100, score)

    return out
