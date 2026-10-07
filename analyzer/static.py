"""Static analysis of a suspicious file.

The sample is NEVER executed here — it is only read and parsed, so this module
is safe to run on an ordinary workstation. It extracts hashes, PE structure,
per-section entropy, capability indicators derived from imported APIs, embedded
strings, IOCs, and YARA matches.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import pefile
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False

try:
    import yara
    HAVE_YARA = True
except Exception:
    HAVE_YARA = False


# Imported API -> (capability, MITRE technique id, human description)
SUSPICIOUS_IMPORTS: dict[str, tuple[str, str, str]] = {
    # Cryptography (data encryption for impact)
    "CryptEncrypt": ("crypto", "T1486", "Encrypts data using the Windows crypto API"),
    "CryptDecrypt": ("crypto", "T1486", "Decrypts data using the Windows crypto API"),
    "CryptGenKey": ("crypto", "T1486", "Generates a cryptographic key"),
    "CryptAcquireContext": ("crypto", "T1486", "Acquires a crypto service provider"),
    "CryptImportKey": ("crypto", "T1486", "Imports a cryptographic key"),
    "BCryptEncrypt": ("crypto", "T1486", "Encrypts data using CNG (BCrypt)"),
    "BCryptGenerateSymmetricKey": ("crypto", "T1486", "Generates a symmetric CNG key"),
    # Process injection
    "CreateRemoteThread": ("injection", "T1055", "Creates a thread in another process"),
    "WriteProcessMemory": ("injection", "T1055", "Writes into another process's memory"),
    "VirtualAllocEx": ("injection", "T1055", "Allocates memory in another process"),
    "NtUnmapViewOfSection": ("injection", "T1055.012", "Process hollowing primitive"),
    "SetWindowsHookEx": ("injection", "T1055.001", "Installs a hook (possible injection)"),
    "QueueUserAPC": ("injection", "T1055.004", "APC injection primitive"),
    # Anti-analysis
    "IsDebuggerPresent": ("anti_debug", "T1622", "Checks for a debugger"),
    "CheckRemoteDebuggerPresent": ("anti_debug", "T1622", "Checks for a remote debugger"),
    "NtQueryInformationProcess": ("anti_debug", "T1622", "May query debug status"),
    "GetTickCount": ("anti_analysis", "T1497", "Timing check (possible anti-sandbox)"),
    # Persistence / registry
    "RegSetValueExA": ("persistence", "T1547.001", "Writes a registry value"),
    "RegSetValueExW": ("persistence", "T1547.001", "Writes a registry value"),
    "RegCreateKeyExA": ("persistence", "T1112", "Creates/opens a registry key"),
    "RegCreateKeyExW": ("persistence", "T1112", "Creates/opens a registry key"),
    # Network / C2
    "InternetOpenA": ("network", "T1071", "Opens an internet session (WinINet)"),
    "InternetOpenW": ("network", "T1071", "Opens an internet session (WinINet)"),
    "WinHttpOpen": ("network", "T1071", "Opens an HTTP session (WinHTTP)"),
    "connect": ("network", "T1071", "Opens a network socket connection"),
    "send": ("network", "T1071", "Sends data over a socket"),
    "InternetReadFile": ("network", "T1105", "Downloads content (possible payload)"),
    "URLDownloadToFileA": ("network", "T1105", "Downloads a file from a URL"),
    # Discovery
    "FindFirstFileA": ("file_enum", "T1083", "Enumerates files/directories"),
    "FindFirstFileW": ("file_enum", "T1083", "Enumerates files/directories"),
    "FindNextFileW": ("file_enum", "T1083", "Enumerates files/directories"),
    "WNetEnumResourceW": ("share_enum", "T1135", "Enumerates network shares"),
    "GetLogicalDrives": ("drive_enum", "T1083", "Enumerates logical drives"),
    # Dynamic API resolution (common in packed/obfuscated malware)
    "LoadLibraryA": ("dynamic_api", "T1027", "Loads a library at runtime"),
    "GetProcAddress": ("dynamic_api", "T1027", "Resolves an API at runtime"),
    # File impact
    "MoveFileExW": ("file_ops", "T1486", "Renames/moves files (encryption rename)"),
    "SetFileAttributesW": ("file_ops", "T1222", "Changes file attributes"),
}

# Strings that strongly indicate ransomware behavior
BEHAVIOR_STRING_INDICATORS: list[tuple[str, str, str]] = [
    (r"vssadmin(?:\.exe)?\s+delete\s+shadows", "T1490", "Deletes Volume Shadow Copies"),
    (r"wmic\s+shadowcopy\s+delete", "T1490", "Deletes shadow copies via WMIC"),
    (r"bcdedit.*recoveryenabled\s+no", "T1490", "Disables Windows recovery"),
    (r"wbadmin\s+delete\s+catalog", "T1490", "Deletes the backup catalog"),
    (r"cipher\s+/w", "T1485", "Wipes free space"),
    (r"-ExecutionPolicy\s+Bypass", "T1059.001", "PowerShell execution-policy bypass"),
]

IOC_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>)]{4,}", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "onion": re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", re.I),
    "bitcoin": re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "emails": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
}

RANSOM_NOTE_HINTS = re.compile(
    r"(how[\s_\-]*to[\s_\-]*decrypt|readme|recover[\s_\-]*files?|restore[\s_\-]*files?|"
    r"your[\s_\-]*files?[\s_\-]*(are|have been)[\s_\-]*encrypted|decrypt[\s_\-]*instruction|"
    r"\.onion|ransom|bitcoin|pay(ment)?[\s_\-]*(the|a)?[\s_\-]*ransom)",
    re.I,
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def file_hashes(path: str) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings."""
    out: list[str] = []
    # ASCII
    out += re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    # UTF-16LE (common in Windows binaries)
    out += [s.replace(b"\x00", b"") for s in
            re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len), data)]
    seen, result = set(), []
    for s in out:
        try:
            t = s.decode("ascii", "ignore")
        except Exception:
            continue
        if t and t not in seen:
            seen.add(t)
            result.append(t)
    return result


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    blob = "\n".join(strings)
    iocs: dict[str, list[str]] = {}
    for name, pat in IOC_PATTERNS.items():
        found = sorted(set(m.group(0) for m in pat.finditer(blob)))
        # drop obvious version-number false positives for ipv4
        if name == "ipv4":
            found = [ip for ip in found if not ip.startswith(("0.", "127."))
                     and ip not in ("1.2.3.4",)]
        if found:
            iocs[name] = found[:200]
    return iocs


@dataclass
class Capability:
    api: str
    category: str
    mitre: str
    description: str


@dataclass
class StaticReport:
    path: str
    filename: str
    size: int
    hashes: dict[str, str]
    file_type: str = "unknown"
    overall_entropy: float = 0.0
    is_pe: bool = False
    pe_info: dict[str, Any] = field(default_factory=dict)
    capabilities: list[dict] = field(default_factory=list)
    behavior_indicators: list[dict] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    ransom_note_strings: list[str] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    suspicious_score: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _detect_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE executable (Windows)"
    if data[:4] == b"\x7fELF":
        return "ELF executable (Linux)"
    if data[:4] in (b"PK\x03\x04",):
        return "ZIP/Office archive"
    if data[:5] == b"%PDF-":
        return "PDF document"
    if data[:2] in (b"MZ",):
        return "PE executable"
    return "unknown/data"


def _analyze_pe(path: str, report: StaticReport) -> None:
    if not HAVE_PEFILE:
        report.notes.append("pefile not installed — skipped PE parsing")
        return
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception as e:
        report.notes.append(f"PE parse error: {e}")
        return

    report.is_pe = True
    info: dict[str, Any] = {}
    try:
        info["machine"] = hex(pe.FILE_HEADER.Machine)
        info["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        info["is_dll"] = bool(pe.is_dll())
        info["entrypoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(
            pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    except Exception:
        pass

    # sections + entropy
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", "ignore")
        ent = s.get_entropy()
        sections.append({
            "name": name,
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(ent, 3),
        })
    info["sections"] = sections
    high = [s["name"] for s in sections if s["entropy"] >= 7.2 and s["raw_size"] > 0]
    if high:
        report.notes.append(
            "High-entropy section(s) suggest packing/encryption: " + ", ".join(high))
        report.suspicious_score += 10

    # imports -> capabilities
    imported_apis: set[str] = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imported_apis.add(imp.name.decode("ascii", "ignore"))
    info["import_count"] = len(imported_apis)

    caps: list[Capability] = []
    for api in sorted(imported_apis):
        base = api.rstrip("AW") if api[-1:] in ("A", "W") else api
        meta = SUSPICIOUS_IMPORTS.get(api) or SUSPICIOUS_IMPORTS.get(base)
        if meta:
            caps.append(Capability(api, meta[0], meta[1], meta[2]))
    report.capabilities = [asdict(c) for c in caps]
    report.pe_info = info

    # scoring from categories
    cats = {c.category for c in caps}
    if "crypto" in cats:
        report.suspicious_score += 25
    if "injection" in cats:
        report.suspicious_score += 20
    if "network" in cats:
        report.suspicious_score += 10
    if {"file_enum", "drive_enum", "share_enum"} & cats:
        report.suspicious_score += 10
    if "anti_debug" in cats:
        report.suspicious_score += 10


def _yara_scan(path: str, rules_dir: str, report: StaticReport) -> None:
    if not HAVE_YARA:
        report.notes.append("yara-python not installed — skipped YARA scan")
        return
    if not rules_dir or not os.path.isdir(rules_dir):
        return
    rule_files = {}
    for fn in os.listdir(rules_dir):
        if fn.endswith((".yar", ".yara")):
            rule_files[fn] = os.path.join(rules_dir, fn)
    if not rule_files:
        return
    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(path)
        report.yara_matches = [m.rule for m in matches]
        if report.yara_matches:
            report.suspicious_score += 20 * len(report.yara_matches)
    except Exception as e:
        report.notes.append(f"YARA error: {e}")


def analyze(path: str, rules_dir: str | None = None,
            max_read: int = 64 * 1024 * 1024) -> StaticReport:
    """Run the full static analysis on `path`. Does NOT execute the sample."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(max_read)

    report = StaticReport(
        path=os.path.abspath(path),
        filename=os.path.basename(path),
        size=size,
        hashes=file_hashes(path),
        overall_entropy=_shannon_entropy(data[:4 * 1024 * 1024]),
        file_type=_detect_type(data),
    )

    if data[:2] == b"MZ":
        _analyze_pe(path, report)

    strings = extract_strings(data)
    report.iocs = extract_iocs(strings)
    report.ransom_note_strings = [s for s in strings if RANSOM_NOTE_HINTS.search(s)][:30]
    if report.ransom_note_strings:
        report.suspicious_score += 20

    blob = "\n".join(strings)
    for pat, mitre, desc in BEHAVIOR_STRING_INDICATORS:
        if re.search(pat, blob, re.I):
            report.behavior_indicators.append({"mitre": mitre, "description": desc})
            report.suspicious_score += 15

    if rules_dir is None:
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "yara_rules")
    _yara_scan(path, rules_dir, report)

    # collect MITRE technique ids
    techniques = set()
    for c in report.capabilities:
        techniques.add(c["mitre"])
    for b in report.behavior_indicators:
        techniques.add(b["mitre"])
    report.mitre_techniques = sorted(techniques)

    if report.overall_entropy >= 7.2:
        report.notes.append("Whole-file entropy is very high (packed/encrypted).")

    report.suspicious_score = min(report.suspicious_score, 100)
    return report
