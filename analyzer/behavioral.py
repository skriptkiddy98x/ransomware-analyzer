"""Behavioral observer — watches filesystem and processes during detonation.

Run this inside an ISOLATED analysis VM while a sample executes. It records
filesystem events (with entropy sampling), new processes and suspicious command
lines, correlates them into ransomware-relevant findings, and maps them to
MITRE ATT&CK techniques.

It observes only; it does not stop, kill, or modify anything.
"""

from __future__ import annotations

import math
import os
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, asdict

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except Exception:
    HAVE_WATCHDOG = False
    FileSystemEventHandler = object  # type: ignore

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False


COMMON_EXTS = {
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png",
    ".gif", ".mp3", ".mp4", ".zip", ".exe", ".dll", ".log", ".ini", ".tmp",
    ".dat", ".json", ".xml", ".csv", ".db", "",
}

RANSOM_NOTE_NAME = re.compile(
    r"(read[\s_\-]*me|how[\s_\-]*to[\s_\-]*decrypt|decrypt[\s_\-]*instruction|"
    r"recover|restore[\s_\-]*files?|ransom|unlock)", re.I)

RANSOM_NOTE_BODY = re.compile(
    r"(your files|encrypted|bitcoin|\.onion|decryption key|pay the ransom)", re.I)

SUSPICIOUS_CMDLINES = [
    (re.compile(r"vssadmin.*delete.*shadows", re.I), "T1490", "Deletes Volume Shadow Copies"),
    (re.compile(r"wmic.*shadowcopy.*delete", re.I), "T1490", "Deletes shadow copies via WMIC"),
    (re.compile(r"bcdedit.*recoveryenabled\s+no", re.I), "T1490", "Disables recovery"),
    (re.compile(r"wbadmin.*delete.*catalog", re.I), "T1490", "Deletes backup catalog"),
    (re.compile(r"cipher\s+/w", re.I), "T1485", "Wipes free space"),
    (re.compile(r"powershell.*-enc(odedcommand)?\b", re.I), "T1059.001", "Encoded PowerShell"),
    (re.compile(r"-ExecutionPolicy\s+Bypass", re.I), "T1059.001", "PowerShell policy bypass"),
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class FileEvent:
    ts: float
    action: str          # created / modified / moved / deleted
    path: str
    dest: str = ""
    entropy: float | None = None


@dataclass
class ProcEvent:
    ts: float
    pid: int
    name: str
    cmdline: str
    reason: str = ""     # why it was flagged (if any)


@dataclass
class Finding:
    title: str
    mitre: str
    severity: str        # low / medium / high
    detail: str


@dataclass
class BehaviorReport:
    duration_s: float = 0.0
    watched_paths: list[str] = field(default_factory=list)
    file_events: int = 0
    encrypted_like_files: int = 0
    new_extensions: dict[str, int] = field(default_factory=dict)
    ransom_notes: list[str] = field(default_factory=list)
    suspicious_processes: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    verdict: str = "inconclusive"
    confidence: int = 0
    timeline_sample: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class _FSHandler(FileSystemEventHandler):
    def __init__(self, monitor: "BehaviorMonitor"):
        self.m = monitor

    def _record(self, action: str, path: str, dest: str = ""):
        ent = None
        target = dest or path
        if action in ("created", "modified", "moved") and os.path.isfile(target):
            try:
                with open(target, "rb") as f:
                    ent = round(_entropy(f.read(65536)), 3)
            except OSError:
                ent = None
        ev = FileEvent(ts=time.time(), action=action, path=path, dest=dest, entropy=ent)
        self.m._on_file_event(ev)

    def on_created(self, event):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record("moved", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("deleted", event.src_path)


class BehaviorMonitor:
    """Start before detonation, stop afterwards to get a BehaviorReport."""

    def __init__(self, watch_dirs: list[str], poll_processes: bool = True,
                 baseline_pids: set[int] | None = None):
        self.watch_dirs = [os.path.abspath(d) for d in watch_dirs]
        self.poll_processes = poll_processes and HAVE_PSUTIL
        self._file_events: list[FileEvent] = []
        self._proc_events: list[ProcEvent] = []
        self._lock = threading.Lock()
        self._observer = None
        self._proc_thread = None
        self._stop = threading.Event()
        self._start_t = 0.0
        self._baseline_pids = baseline_pids or set()

    # --- lifecycle ---
    def start(self):
        self._start_t = time.time()
        if HAVE_WATCHDOG:
            self._observer = Observer()
            handler = _FSHandler(self)
            for d in self.watch_dirs:
                os.makedirs(d, exist_ok=True)
                self._observer.schedule(handler, d, recursive=True)
            self._observer.start()
        if self.poll_processes:
            if not self._baseline_pids:
                self._baseline_pids = {p.pid for p in psutil.process_iter()}
            self._proc_thread = threading.Thread(target=self._poll_procs, daemon=True)
            self._proc_thread.start()

    def stop(self) -> BehaviorReport:
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._proc_thread:
            self._proc_thread.join(timeout=3)
        return self._build_report()

    # --- collectors ---
    def _on_file_event(self, ev: FileEvent):
        with self._lock:
            self._file_events.append(ev)

    def _poll_procs(self):
        seen = set(self._baseline_pids)
        while not self._stop.is_set():
            try:
                for p in psutil.process_iter(["pid", "name", "cmdline"]):
                    if p.pid in seen:
                        continue
                    seen.add(p.pid)
                    cmd = " ".join(p.info.get("cmdline") or [])
                    reason = ""
                    for pat, mitre, desc in SUSPICIOUS_CMDLINES:
                        if pat.search(cmd):
                            reason = f"{desc} ({mitre})"
                            break
                    if reason or cmd:
                        with self._lock:
                            self._proc_events.append(ProcEvent(
                                ts=time.time(), pid=p.pid,
                                name=p.info.get("name") or "", cmdline=cmd,
                                reason=reason))
            except Exception:
                pass
            time.sleep(0.5)

    # --- analysis ---
    def _build_report(self) -> BehaviorReport:
        r = BehaviorReport()
        r.duration_s = round(time.time() - self._start_t, 2)
        r.watched_paths = self.watch_dirs
        with self._lock:
            fevents = list(self._file_events)
            pevents = list(self._proc_events)

        r.file_events = len(fevents)
        techniques: set[str] = set()

        # encrypted-like files (high entropy writes)
        enc = [e for e in fevents if e.entropy is not None and e.entropy >= 7.2
               and e.action in ("created", "modified", "moved")]
        r.encrypted_like_files = len({(e.dest or e.path) for e in enc})

        # new extensions on created/moved files
        ext_counter: Counter = Counter()
        for e in fevents:
            tgt = e.dest or e.path
            if e.action in ("created", "moved"):
                ext = os.path.splitext(tgt)[1].lower()
                if ext and ext not in COMMON_EXTS:
                    ext_counter[ext] += 1
        r.new_extensions = dict(ext_counter.most_common(10))

        # ransom notes (by name, and by body for small text files)
        notes = set()
        for e in fevents:
            tgt = e.dest or e.path
            base = os.path.basename(tgt)
            if e.action in ("created", "modified", "moved"):
                if RANSOM_NOTE_NAME.search(base):
                    notes.add(tgt)
                elif os.path.isfile(tgt) and os.path.getsize(tgt) < 65536 \
                        and tgt.lower().endswith((".txt", ".html", ".hta")):
                    try:
                        with open(tgt, "r", errors="ignore") as f:
                            if RANSOM_NOTE_BODY.search(f.read(8192)):
                                notes.add(tgt)
                    except OSError:
                        pass
        r.ransom_notes = sorted(notes)

        # suspicious processes
        r.suspicious_processes = [asdict(p) for p in pevents if p.reason]

        # --- findings + scoring ---
        score = 0
        if r.encrypted_like_files >= 5:
            r.findings.append(asdict(Finding(
                "Mass file encryption detected", "T1486", "high",
                f"{r.encrypted_like_files} files were written with very high entropy "
                f"(encryption-like) during the observation window.")))
            techniques.add("T1486")
            score += 45
        elif r.encrypted_like_files >= 1:
            r.findings.append(asdict(Finding(
                "Some high-entropy file writes", "T1486", "medium",
                f"{r.encrypted_like_files} high-entropy write(s) observed.")))
            techniques.add("T1486")
            score += 20

        if r.new_extensions:
            total = sum(r.new_extensions.values())
            if total >= 5:
                top = max(r.new_extensions, key=r.new_extensions.get)
                r.findings.append(asdict(Finding(
                    "Bulk file-extension change", "T1486", "high",
                    f"{total} files gained uncommon extension(s); most common '{top}'. "
                    f"Typical of ransomware renaming encrypted files.")))
                techniques.add("T1486")
                score += 20

        if r.ransom_notes:
            r.findings.append(asdict(Finding(
                "Ransom note dropped", "T1486", "high",
                f"{len(r.ransom_notes)} ransom-note-like file(s): "
                + ", ".join(os.path.basename(n) for n in r.ransom_notes[:5]))))
            techniques.add("T1486")
            score += 25

        for p in r.suspicious_processes:
            r.findings.append(asdict(Finding(
                "Suspicious command executed", p["reason"].split("(")[-1].rstrip(")") or "T1059",
                "high", f"{p['name']}: {p['cmdline'][:160]}")))
            m = re.search(r"T\d{4}(?:\.\d+)?", p["reason"])
            if m:
                techniques.add(m.group(0))
            score += 15

        total_fs = sum(1 for e in fevents if e.action in ("created", "modified", "moved", "deleted"))
        if total_fs >= 30:
            techniques.add("T1083")

        r.mitre_techniques = sorted(techniques)
        r.confidence = min(score, 100)
        if r.confidence >= 60:
            r.verdict = "ransomware-like (high confidence)"
        elif r.confidence >= 30:
            r.verdict = "suspicious / possibly ransomware"
        else:
            r.verdict = "no strong ransomware indicators"

        # small timeline sample for the report
        r.timeline_sample = [
            {"t": round(e.ts - self._start_t, 2), "action": e.action,
             "path": os.path.basename(e.dest or e.path),
             "entropy": e.entropy}
            for e in fevents[:200]
        ]
        return r
