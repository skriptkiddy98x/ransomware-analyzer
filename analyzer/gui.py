"""Simple, user-friendly GUI for ransomware-analyzer.

By design the GUI performs only SAFE actions: static analysis (the sample is
never executed) and the benign self-test. Real detonation must be done from the
`detonate`/`monitor` CLI commands inside an isolated VM.
"""

from __future__ import annotations

import os
import sys
import threading
import queue
import tempfile
import shutil
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from analyzer import static as static_mod
from analyzer import behavioral as beh_mod
from analyzer import report as report_mod
from analyzer import sim_sample


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.last_html = None

        root.title("Ransomware Analyzer")
        root.geometry("900x660")
        root.minsize(760, 560)

        banner = tk.Label(
            root, bg="#3a1d1d", fg="#ffd7d7", padx=10, pady=6, justify="left",
            text="⚠  Authorized research only. This GUI runs STATIC analysis (safe — the "
                 "sample is never executed) and a BENIGN self-test.\n"
                 "    Real detonation must be done with the CLI inside an isolated VM.")
        banner.pack(fill="x")

        top = ttk.Frame(root)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, text="Sample:").pack(side="left")
        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse…", command=self.pick).pack(side="left")

        btns = ttk.Frame(root)
        btns.pack(fill="x", padx=10)
        self.analyze_btn = ttk.Button(btns, text="🔍  Analyze (static)", command=self.analyze)
        self.analyze_btn.pack(side="left")
        ttk.Button(btns, text="🧪  Run benign self-test", command=self.selftest).pack(side="left", padx=6)
        self.open_btn = ttk.Button(btns, text="📄  Open HTML report", command=self.open_report, state="disabled")
        self.open_btn.pack(side="left")

        self.verdict = tk.StringVar(value="Ready.")
        self.vlabel = tk.Label(root, textvariable=self.verdict, font=("Segoe UI", 13, "bold"),
                               anchor="w", padx=10, pady=4)
        self.vlabel.pack(fill="x")

        mid = ttk.Panedwindow(root, orient="vertical")
        mid.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        capf = ttk.LabelFrame(mid, text="Capabilities / findings")
        self.tree = ttk.Treeview(capf, columns=("a", "b", "c"), show="headings", height=8)
        for cid, txt, w in (("a", "Item", 240), ("b", "MITRE", 90), ("c", "Detail", 460)):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        mid.add(capf, weight=3)

        logf = ttk.LabelFrame(mid, text="Summary")
        self.log = tk.Text(logf, height=8, wrap="word", state="disabled", bg="#111", fg="#ddd")
        self.log.pack(fill="both", expand=True)
        mid.add(logf, weight=2)

        self.root.after(120, self._drain)

    def pick(self):
        p = filedialog.askopenfilename(title="Select a sample to analyze (not executed)")
        if p:
            self.path_var.set(p)

    def _log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.log.configure(state="normal"); self.log.delete("1.0", "end"); self.log.configure(state="disabled")

    def analyze(self):
        p = self.path_var.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("Ransomware Analyzer", "Pick a valid sample file.")
            return
        self._clear(); self.verdict.set("Analyzing (static)…")
        self.analyze_btn.configure(state="disabled")
        threading.Thread(target=self._run_static, args=(p,), daemon=True).start()

    def _run_static(self, p):
        try:
            s = static_mod.analyze(p).to_dict()
            combined = report_mod.build_report(
                s, None, sample_name=os.path.basename(p),
                attribution=report_mod.attribute_family(s, None))
            out = os.path.join(os.path.expanduser("~"), "ransomware-analyzer-reports")
            written = report_mod.save(combined, out)
            self.q.put(("done", (combined, written.get("html"), "static")))
        except Exception as e:
            self.q.put(("error", str(e)))

    def selftest(self):
        self._clear(); self.verdict.set("Running benign self-test…")
        threading.Thread(target=self._run_selftest, daemon=True).start()

    def _run_selftest(self):
        try:
            sandbox = os.path.join(tempfile.gettempdir(), "ransim_gui_sandbox")
            shutil.rmtree(sandbox, ignore_errors=True); os.makedirs(sandbox)
            sim_sample.seed_victim_files(sandbox, 20)
            mon = beh_mod.BehaviorMonitor([sandbox], poll_processes=False)
            mon.start()
            import time as _t; _t.sleep(0.4)
            sim_sample.simulate(sandbox, count=20, seed=False)
            _t.sleep(1.2)
            b = mon.stop().to_dict()
            combined = report_mod.build_report(
                None, b, sample_name="benign-self-test",
                attribution=report_mod.attribute_family(None, b))
            out = os.path.join(os.path.expanduser("~"), "ransomware-analyzer-reports")
            written = report_mod.save(combined, out)
            shutil.rmtree(sandbox, ignore_errors=True)
            self.q.put(("done", (combined, written.get("html"), "selftest")))
        except Exception as e:
            self.q.put(("error", str(e)))

    def _drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "done":
                    self._show(*payload)
                elif kind == "error":
                    messagebox.showerror("Ransomware Analyzer", payload)
                    self.verdict.set("Error.")
                self.analyze_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.root.after(120, self._drain)

    def _show(self, combined, html, mode):
        score = combined["overall_score"]
        color = "#3fb950" if score < 30 else ("#d29922" if score < 60 else "#f85149")
        self.verdict.set(f"{combined['overall_verdict']}   —   score {score}/100   "
                         f"(family: {combined['attribution']['family']})")
        self.vlabel.configure(fg=color)
        self.last_html = html
        self.open_btn.configure(state="normal" if html else "disabled")

        s = combined.get("static")
        if s:
            self._log(f"Type: {s['file_type']} | size {s['size']} B | entropy {s['overall_entropy']}")
            self._log(f"SHA-256: {s['hashes']['sha256']}")
            self._log(f"YARA: {', '.join(s['yara_matches']) or '-'}")
            for c in s["capabilities"]:
                self.tree.insert("", "end", values=(c["api"], c["mitre"], c["description"]))
            if not s["capabilities"]:
                self.tree.insert("", "end", values=("(no suspicious imports)", "", ""))
        b = combined.get("behavior")
        if b:
            self._log(f"Observed {b['file_events']} file events in {b['duration_s']}s · "
                      f"{b['encrypted_like_files']} high-entropy writes")
            for f in b["findings"]:
                self.tree.insert("", "end", values=(f"[{f['severity'].upper()}] {f['title']}",
                                                     f["mitre"], f["detail"]))
        self._log("MITRE: " + ", ".join(t["id"] for t in combined["mitre"]))
        if html:
            self._log(f"HTML report: {html}")

    def open_report(self):
        if self.last_html and os.path.exists(self.last_html):
            webbrowser.open("file://" + os.path.abspath(self.last_html))


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
