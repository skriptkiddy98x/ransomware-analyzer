"""Command-line interface for ransomware-analyzer.

Subcommands:
  static    <sample>   Static analysis only (safe; does not execute the sample).
  monitor              Run the behavioral observer for a while (you launch the
                       sample yourself in the VM). Safest detonation workflow.
  detonate  <sample>   Observe AND launch the sample. ISOLATED VM ONLY.
  simulate             Benign self-test: runs a harmless simulator + observer and
                       produces a full report (no real malware). Great for a demo.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__
from . import static as static_mod
from . import behavioral as beh_mod
from . import report as report_mod

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _c = Console()
    HAVE_RICH = True
except Exception:
    HAVE_RICH = False
    _c = None


def _p(msg=""):
    if HAVE_RICH:
        _c.print(msg)
    else:
        print(msg if isinstance(msg, str) else str(msg))


def _print_verdict(report: dict):
    score = report["overall_score"]
    color = "green" if score < 30 else ("yellow" if score < 60 else "red")
    if HAVE_RICH:
        _c.print(Panel(f"[bold {color}]{report['overall_verdict']}[/]  "
                       f"score [bold]{score}/100[/]\n"
                       f"suspected family: {report['attribution']['family']}",
                       title="Verdict", border_style=color))
    else:
        print(f"\n== {report['overall_verdict']}  (score {score}/100) ==")
        print("suspected family:", report["attribution"]["family"])


def _print_static(s: dict):
    if not s:
        return
    if HAVE_RICH:
        t = Table(title="Static analysis", show_header=False, box=None)
        t.add_row("file type", s["file_type"])
        t.add_row("size", f"{s['size']} bytes")
        t.add_row("entropy", str(s["overall_entropy"]))
        t.add_row("sha256", s["hashes"]["sha256"])
        t.add_row("yara", ", ".join(s["yara_matches"]) or "-")
        t.add_row("mitre", ", ".join(s["mitre_techniques"]) or "-")
        _c.print(t)
        if s["capabilities"]:
            ct = Table(title="Capabilities (from imports)")
            ct.add_column("API"); ct.add_column("Category"); ct.add_column("MITRE")
            for c in s["capabilities"]:
                ct.add_row(c["api"], c["category"], c["mitre"])
            _c.print(ct)
    else:
        print("file type:", s["file_type"], "| entropy:", s["overall_entropy"])
        print("sha256:", s["hashes"]["sha256"])
        print("yara:", s["yara_matches"], "| mitre:", s["mitre_techniques"])


def _print_findings(b: dict):
    if not b:
        return
    if HAVE_RICH:
        t = Table(title=f"Behavioral findings  ({b['verdict']}, {b['confidence']}%)")
        t.add_column("Sev"); t.add_column("Finding"); t.add_column("MITRE"); t.add_column("Detail")
        for f in b["findings"]:
            t.add_row(f["severity"].upper(), f["title"], f["mitre"], f["detail"])
        if not b["findings"]:
            t.add_row("-", "no findings", "-", "-")
        _c.print(t)
    else:
        for f in b["findings"]:
            print(f"  [{f['severity'].upper()}] {f['title']} ({f['mitre']}): {f['detail']}")


def _save_and_report(static_rep, beh_rep, name, out, formats):
    attribution = report_mod.attribute_family(static_rep, beh_rep)
    combined = report_mod.build_report(static_rep, beh_rep, sample_name=name,
                                       attribution=attribution)
    _print_verdict(combined)
    _print_static(static_rep)
    _print_findings(beh_rep)
    if out:
        written = report_mod.save(combined, out, formats=formats)
        for fmt, path in written.items():
            _p(f"[green]Saved {fmt.upper()} report:[/] {path}" if HAVE_RICH
               else f"Saved {fmt} report: {path}")
    return combined


def cmd_static(args):
    rep = static_mod.analyze(args.sample, rules_dir=args.yara).to_dict()
    _save_and_report(rep, None, os.path.basename(args.sample), args.out, args.format.split(","))
    return 0


def cmd_monitor(args):
    watch = args.watch or [os.path.expanduser("~")]
    _p(f"Observing {watch} for {args.timeout}s. Launch the sample now (in the VM)…")
    mon = beh_mod.BehaviorMonitor(watch, poll_processes=not args.no_procs)
    mon.start()
    try:
        time.sleep(args.timeout)
    except KeyboardInterrupt:
        _p("Stopping early…")
    beh = mon.stop().to_dict()
    _save_and_report(None, beh, "monitor-session", args.out, args.format.split(","))
    return 0


def cmd_detonate(args):
    import subprocess
    if not args.yes_run_in_vm:
        _p("[red]Refusing to execute the sample without --yes-run-in-vm.[/]" if HAVE_RICH
           else "Refusing to execute the sample without --yes-run-in-vm.")
        _p("Only ever use --yes-run-in-vm inside an isolated analysis VM.")
        return 2
    static_rep = static_mod.analyze(args.sample, rules_dir=args.yara).to_dict()
    watch = args.watch or [os.path.dirname(os.path.abspath(args.sample)),
                           os.path.expanduser("~")]
    mon = beh_mod.BehaviorMonitor(watch, poll_processes=not args.no_procs)
    mon.start()
    proc = None
    try:
        proc = subprocess.Popen([os.path.abspath(args.sample)])
        t0 = time.time()
        while time.time() - t0 < args.timeout and proc.poll() is None:
            time.sleep(0.5)
    except Exception as e:
        _p(f"launch error: {e}")
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        beh = mon.stop().to_dict()
    _save_and_report(static_rep, beh, os.path.basename(args.sample), args.out,
                     args.format.split(","))
    return 0


def cmd_simulate(args):
    import tempfile
    import shutil
    from . import sim_sample
    sandbox = args.sandbox or os.path.join(tempfile.gettempdir(), "ransim_sandbox")
    shutil.rmtree(sandbox, ignore_errors=True)
    os.makedirs(sandbox)
    _p("[yellow]Running BENIGN simulation (no real malware)…[/]" if HAVE_RICH
       else "Running BENIGN simulation (no real malware)…")
    sim_sample.seed_victim_files(sandbox, args.files)
    mon = beh_mod.BehaviorMonitor([sandbox], poll_processes=False)
    mon.start()
    time.sleep(0.4)
    sim_sample.simulate(sandbox, count=args.files, seed=False)
    time.sleep(1.2)
    beh = mon.stop().to_dict()
    _save_and_report(None, beh, "benign-simulation", args.out, args.format.split(","))
    if not args.keep:
        shutil.rmtree(sandbox, ignore_errors=True)
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="ransomware-analyzer",
        description="Static + behavioral ransomware analysis (authorized research only).")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("-o", "--out", default="reports", help="output directory for reports")
        p.add_argument("--format", default="html,json", help="report formats: html,json")
        p.add_argument("--yara", default=None, help="YARA rules directory")

    s = sub.add_parser("static", help="static analysis only (safe)")
    s.add_argument("sample"); common(s); s.set_defaults(func=cmd_static)

    m = sub.add_parser("monitor", help="run behavioral observer (you launch the sample)")
    m.add_argument("--watch", nargs="*", help="directories to watch")
    m.add_argument("--timeout", type=int, default=60)
    m.add_argument("--no-procs", action="store_true", help="disable process polling")
    common(m); m.set_defaults(func=cmd_monitor)

    d = sub.add_parser("detonate", help="observe AND launch the sample (ISOLATED VM ONLY)")
    d.add_argument("sample")
    d.add_argument("--watch", nargs="*")
    d.add_argument("--timeout", type=int, default=60)
    d.add_argument("--no-procs", action="store_true")
    d.add_argument("--yes-run-in-vm", action="store_true",
                   help="confirm you are inside an isolated analysis VM")
    common(d); d.set_defaults(func=cmd_detonate)

    sim = sub.add_parser("simulate", help="benign self-test + demo report (no real malware)")
    sim.add_argument("--files", type=int, default=20)
    sim.add_argument("--sandbox", default=None)
    sim.add_argument("--keep", action="store_true", help="keep the sandbox afterwards")
    common(sim); sim.set_defaults(func=cmd_simulate)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError:
        _p("Error: sample not found.")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
