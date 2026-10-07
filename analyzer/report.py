"""Combine static + behavioral results into JSON and a readable HTML report."""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

from . import mitre, __version__

try:
    from jinja2 import Template
    HAVE_JINJA = True
except Exception:
    HAVE_JINJA = False


def _overall(static: dict | None, behavior: dict | None) -> tuple[str, int]:
    score = 0
    if static:
        score = max(score, static.get("suspicious_score", 0) // 2)
    if behavior:
        score = max(score, behavior.get("confidence", 0))
        # static corroboration nudges confidence up
        if static and static.get("suspicious_score", 0) >= 50 and behavior.get("confidence", 0) >= 30:
            score = min(100, score + 10)
    if score >= 60:
        verdict = "RANSOMWARE-LIKE (high confidence)"
    elif score >= 30:
        verdict = "SUSPICIOUS (possible ransomware)"
    elif score > 0:
        verdict = "LOW RISK (weak indicators)"
    else:
        verdict = "NO STRONG INDICATORS"
    return verdict, score


def build_report(static: dict | None, behavior: dict | None,
                 sample_name: str = "", attribution: dict | None = None) -> dict:
    tech_ids: set[str] = set()
    if static:
        tech_ids |= set(static.get("mitre_techniques", []))
    if behavior:
        tech_ids |= set(behavior.get("mitre_techniques", []))
    verdict, score = _overall(static, behavior)
    if behavior is not None:
        behavior["ransom_note_names"] = [os.path.basename(n)
                                         for n in behavior.get("ransom_notes", [])]
    return {
        "tool": "ransomware-analyzer",
        "version": __version__,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sample_name": sample_name,
        "overall_verdict": verdict,
        "overall_score": score,
        "attribution": attribution or {"family": "unknown", "confidence": "n/a"},
        "mitre": mitre.describe_all(tech_ids),
        "static": static,
        "behavior": behavior,
    }


def attribute_family(static: dict | None, behavior: dict | None) -> dict:
    """Very small heuristic family attribution. Honest 'unknown' by default."""
    yara_hits = (static or {}).get("yara_matches", [])
    exts = list((behavior or {}).get("new_extensions", {}).keys())
    if yara_hits:
        return {"family": "generic-ransomware (YARA heuristic)",
                "confidence": "low", "basis": ", ".join(yara_hits)}
    if exts:
        return {"family": "unknown", "confidence": "n/a",
                "basis": f"encrypted extension(s): {', '.join(exts)}"}
    return {"family": "unknown", "confidence": "n/a", "basis": ""}


_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Analysis Report — {{ r.sample_name or 'sample' }}</title>
<style>
 :root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;
 --red:#f85149;--amber:#d29922;--green:#3fb950;--blue:#58a6ff;}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px}
 h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:24px 0 8px;color:var(--blue)}
 .mut{color:var(--mut)} .wrap{max-width:980px;margin:0 auto}
 .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:10px 0}
 .verdict{display:flex;align-items:center;gap:16px}
 .score{font-size:40px;font-weight:700} .pill{padding:3px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
 .bar{height:10px;background:#21262d;border-radius:999px;overflow:hidden;margin-top:8px}
 .bar>i{display:block;height:100%}
 table{width:100%;border-collapse:collapse;font-size:13px} td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
 th{color:var(--mut);font-weight:600} code{background:#21262d;padding:1px 5px;border-radius:4px}
 .sev-high{color:var(--red)} .sev-medium{color:var(--amber)} .sev-low{color:var(--green)}
 .tag{display:inline-block;background:#21262d;border:1px solid var(--line);border-radius:6px;padding:2px 7px;margin:2px;font-size:12px}
 a{color:var(--blue);text-decoration:none} .foot{color:var(--mut);font-size:12px;margin-top:24px}
</style></head><body><div class="wrap">
<h1>Ransomware Analysis Report</h1>
<div class="mut">{{ r.sample_name }} · generated {{ r.generated }} · {{ r.tool }} v{{ r.version }}</div>

<div class="card verdict">
  {% set c = r.overall_score %}
  {% set col = 'var(--green)' if c<30 else ('var(--amber)' if c<60 else 'var(--red)') %}
  <div class="score" style="color:{{col}}">{{ c }}</div>
  <div>
    <div style="font-size:18px;font-weight:700;color:{{col}}">{{ r.overall_verdict }}</div>
    <div class="mut">Suspected family: {{ r.attribution.family }}{% if r.attribution.basis %} ({{ r.attribution.basis }}){% endif %}</div>
    <div class="bar"><i style="width:{{c}}%;background:{{col}}"></i></div>
  </div>
</div>

{% if r.behavior %}
<h2>Behavioral findings (detonation)</h2>
<div class="card">
<div class="mut">Observed {{ r.behavior.file_events }} file events over {{ r.behavior.duration_s }}s ·
 {{ r.behavior.encrypted_like_files }} high-entropy writes · verdict: {{ r.behavior.verdict }} ({{ r.behavior.confidence }}%)</div>
<table><tr><th>Severity</th><th>Finding</th><th>MITRE</th><th>Detail</th></tr>
{% for f in r.behavior.findings %}
<tr><td class="sev-{{f.severity}}">{{ f.severity|upper }}</td><td>{{ f.title }}</td>
<td><code>{{ f.mitre }}</code></td><td>{{ f.detail }}</td></tr>
{% endfor %}
{% if not r.behavior.findings %}<tr><td colspan=4 class="mut">No behavioral findings.</td></tr>{% endif %}
</table>
{% if r.behavior.ransom_note_names %}<p class="mut">Ransom notes: {% for n in r.behavior.ransom_note_names %}<span class="tag">{{ n }}</span>{% endfor %}</p>{% endif %}
</div>
{% endif %}

{% if r.static %}
<h2>Static analysis</h2>
<div class="card">
<table>
<tr><th>File type</th><td>{{ r.static.file_type }}{% if r.static.is_pe %} · {{ r.static.pe_info.import_count }} imports{% endif %}</td></tr>
<tr><th>Size</th><td>{{ r.static.size }} bytes</td></tr>
<tr><th>Entropy</th><td>{{ r.static.overall_entropy }}{% if r.static.overall_entropy>=7.2 %} <span class="sev-medium">(packed/encrypted)</span>{% endif %}</td></tr>
<tr><th>SHA-256</th><td><code>{{ r.static.hashes.sha256 }}</code></td></tr>
<tr><th>YARA</th><td>{% for y in r.static.yara_matches %}<span class="tag">{{ y }}</span>{% else %}<span class="mut">no matches</span>{% endfor %}</td></tr>
</table>
{% if r.static.capabilities %}
<p class="mut" style="margin-top:10px">Capabilities from imports:</p>
<table><tr><th>API</th><th>Category</th><th>MITRE</th><th>Description</th></tr>
{% for c in r.static.capabilities %}
<tr><td><code>{{ c.api }}</code></td><td>{{ c.category }}</td><td><code>{{ c.mitre }}</code></td><td>{{ c.description }}</td></tr>
{% endfor %}</table>
{% endif %}
{% if r.static.ransom_note_strings %}<p class="mut">Ransom-note strings found: {{ r.static.ransom_note_strings|length }}</p>{% endif %}
</div>
{% endif %}

<h2>MITRE ATT&CK techniques</h2>
<div class="card">
{% for t in r.mitre %}<a class="tag" href="{{ t.url }}" target="_blank">{{ t.id }} — {{ t.name }} <span class="mut">[{{ t.tactic }}]</span></a>{% else %}<span class="mut">none</span>{% endfor %}
</div>

<div class="foot">For authorized malware research only. This report describes observed/derived
indicators and is not a definitive classification. Detonate samples only in an isolated VM.</div>
</div></body></html>"""


def render_html(report: dict) -> str:
    if not HAVE_JINJA:
        return "<html><body><pre>" + json.dumps(report, indent=2) + "</pre></body></html>"
    return Template(_HTML).render(r=report)


def save(report: dict, out_dir: str, formats=("json", "html")) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    base = (report.get("sample_name") or "report").replace("/", "_").replace("\\", "_")
    written = {}
    if "json" in formats:
        p = os.path.join(out_dir, base + ".json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        written["json"] = p
    if "html" in formats:
        p = os.path.join(out_dir, base + ".html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(report))
        written["html"] = p
    return written
