"""
APKOwl :: modules.reporter
==========================

Phase 12 — synthesise everything in the database into three deliverables:

* ``report.json`` — the full machine-readable result (every finding, evidence,
  endpoint, artifact, scan metadata). Ideal for CI / diffing.
* ``report.md``  — a readable Markdown report for tickets / PRs.
* ``report.html`` — a self-contained, styled HTML report for humans, with a
  severity dashboard, per-finding cards (CVSS, CWE, OWASP, evidence,
  remediation), an endpoints table, a redacted secrets table and an inventory
  of generated artifacts (Frida scripts, patched APK, attack scripts).

The reporter reads exclusively from the :class:`Database`, so it always reflects
the persisted source of truth and can even be re-run standalone against an old
scan.
"""

from __future__ import annotations

import html
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List

from core.db import Database
from core.findings import Severity
from core.logger import log
from signatures.knowledge_base import (
    coverage_summary,
    enrich,
    masvs_for_cwe,
    MASVS_CONTROLS,
)


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_HEX = {
    "CRITICAL": "#ff3b3b",
    "HIGH": "#ff7a18",
    "MEDIUM": "#ffd24a",
    "LOW": "#4ad9ff",
    "INFO": "#7c8aff",
}


@dataclass
class ReportResult:
    json_path: str = ""
    md_path: str = ""
    html_path: str = ""
    summary_path: str = ""


class Reporter:
    def __init__(self, db: Database, output_dir: str, tool_version: str = "1.0.0") -> None:
        self.db = db
        self.output_dir = output_dir
        self.tool_version = tool_version
        os.makedirs(output_dir, exist_ok=True)

    @staticmethod
    def _s(value, default: str = "") -> str:
        """None-safe string coalesce (dict.get returns None for NULL columns)."""
        if value is None:
            return default
        return str(value)

    def run(self) -> ReportResult:
        result = ReportResult()
        data = self._gather()
        result.json_path = self._write_json(data)
        result.md_path = self._write_md(data)
        result.html_path = self._write_html(data)
        result.summary_path = self._write_summary(data)
        log.good("reports written:")
        log.kv("  JSON", result.json_path)
        log.kv("  Markdown", result.md_path)
        log.kv("  HTML", result.html_path)
        log.kv("  Summary", result.summary_path)
        return result

    # -- data gathering ----------------------------------------------------
    def _gather(self) -> Dict:
        scan = self.db.get_scan()
        findings = self.db.get_findings()
        endpoints = self.db.get_endpoints()
        artifacts = self.db.get_artifacts()
        counts = self.db.severity_counts()
        # enrich each finding with MASVS/MASTG/CWE standards data
        for f in findings:
            f["standards"] = enrich(f.get("cwe", ""))
        cwe_ids = [f.get("cwe", "") for f in findings if f.get("cwe")]
        return {
            "scan": scan,
            "findings": findings,
            "endpoints": endpoints,
            "artifacts": artifacts,
            "counts": counts,
            "masvs_coverage": coverage_summary(cwe_ids),
            "meta": {
                "tool": "APKOwl",
                "version": self.tool_version,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "permissions": self.db.get_kv("permissions", []),
                "components": self.db.get_kv("components", []),
                "deeplinks": self.db.get_kv("deeplinks", []),
                "obfuscation": self.db.get_kv("obfuscation_detail", {}),
                "sdks": self.db.get_kv("sdks", {}),
                "native_libs": self.db.get_kv("native_libs", []),
                "certificates": self.db.get_kv("certificates", []),
                "pinning": self.db.get_kv("pinning", []),
                "patch_summary": self.db.get_kv("patch_summary", {}),
                "frida_summary": self.db.get_kv("frida_summary", {}),
                "toolchain": self.db.get_kv("toolchain", []),
                "runtime_config": self.db.get_kv("runtime_config", {}),
                "phase_errors": self.db.get_kv("phase_errors", []),
            },
        }

    @staticmethod
    def _coverage_info(meta: Dict) -> Dict[str, object]:
        toolchain = meta.get("toolchain") or []
        missing = [t.get("tool") for t in toolchain if not t.get("available")]
        runtime = meta.get("runtime_config") or {}
        phase_errors = meta.get("phase_errors") or []
        return {
            "missing_tools": [m for m in missing if m],
            "runtime": runtime,
            "phase_errors": phase_errors,
        }

    def _risk_score(self, counts: Dict[str, int]) -> int:
        """A simple weighted risk score out of 100."""
        weights = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        raw = sum(weights[s] * counts.get(s, 0) for s in weights)
        return min(100, raw)

    def _risk_band(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MODERATE"
        if score > 0:
            return "LOW"
        return "MINIMAL"

    # -- executive summary (plain text) -----------------------------------
    def _write_summary(self, data: Dict) -> str:
        path = os.path.join(self.output_dir, "summary.txt")
        scan = data["scan"]
        counts = data["counts"]
        findings = data["findings"]
        score = self._risk_score(counts)
        band = self._risk_band(score)
        pkg = self._s(scan.get("package_name"), "(unknown package)")

        # top findings by severity then cvss
        ranked = sorted(
            findings,
            key=lambda f: (-int(f.get("severity", 0)),
                           -float(f.get("cvss_score") or 0)),
        )
        top = ranked[: min(5, len(ranked))]

        # narrative
        lines: List[str] = []
        lines.append("=" * 70)
        lines.append("APKOwl EXECUTIVE SUMMARY")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Application : {pkg}")
        lines.append(f"Version     : {self._s(scan.get('version_name'),'?')} "
                     f"({self._s(scan.get('version_code'),'?')})")
        lines.append(f"Analysed    : {data['meta']['generated_at']}")
        lines.append(f"Overall risk: {band}  (weighted score {score}/100)")
        lines.append("")
        total = sum(counts.values())
        lines.append(f"A total of {total} finding(s) were identified: "
                     + ", ".join(f"{counts.get(s,0)} {s.lower()}"
                                 for s in SEVERITY_ORDER if counts.get(s, 0)))
        lines.append("")

        # narrative paragraph driven by what was found
        crit_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        if crit_high:
            lines.append(self._wrap(
                f"The assessment surfaced {crit_high} high-impact issue(s) that "
                "warrant prompt remediation. These typically allow an attacker "
                "to recover secrets, intercept or tamper with traffic, or reach "
                "data and components that should not be externally accessible. "
                "The detailed report lists each with evidence, a CVSS vector and "
                "concrete remediation guidance."
            ))
        else:
            lines.append(self._wrap(
                "No critical or high-severity issues were identified in this "
                "pass. The findings below are lower-severity hardening and "
                "hygiene items; addressing them improves defence in depth."
            ))
        lines.append("")

        lines.append("TOP FINDINGS")
        lines.append("-" * 70)
        for i, f in enumerate(top, 1):
            sev = f.get("severity_label", "INFO")
            cvss = f.get("cvss_score", "0")
            lines.append(f"{i}. [{sev}] {f.get('title','')}  (CVSS {cvss})")
            std = f.get("standards", {})
            if std and std.get("masvs"):
                ctrls = ", ".join(m["id"] for m in std["masvs"])
                lines.append(f"   MASVS: {ctrls}")
        lines.append("")

        # MASVS coverage
        cov = data.get("masvs_coverage", {})
        if cov:
            lines.append("MASVS CONTROL GROUPS WITH FINDINGS")
            lines.append("-" * 70)
            for group in sorted(cov):
                lines.append(f"  MASVS-{group}: {cov[group]} finding(s)")
            lines.append("")

        coverage = self._coverage_info(data["meta"])
        if coverage["missing_tools"] or coverage["phase_errors"] or coverage["runtime"]:
            lines.append("COVERAGE NOTES")
            lines.append("-" * 70)
            runtime = coverage["runtime"]
            if runtime:
                lines.append(f"Device mode       : {'on' if runtime.get('device_mode') else 'off'}")
                lines.append(f"Active HTTP tests : {'on' if runtime.get('allow_active_http') else 'off'}")
            missing = coverage["missing_tools"]
            if missing:
                lines.append("Missing tools     : " + ", ".join(missing))
            errors = coverage["phase_errors"]
            if errors:
                lines.append("Phase errors      : " + "; ".join(errors[:5]))
            lines.append("")

        # endpoints / artifacts headline
        lines.append(f"API endpoints discovered : {len(data['endpoints'])}")
        lines.append(f"Artifacts generated      : {len(data['artifacts'])} "
                     "(Frida scripts, attack scripts, patched APK, etc.)")
        lines.append("")
        lines.append("See report.html for the full interactive report, or "
                     "report.json for machine-readable output.")
        lines.append("=" * 70)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    @staticmethod
    def _wrap(text: str, width: int = 70) -> str:
        import textwrap
        return "\n".join(textwrap.wrap(text, width=width))

    # -- JSON --------------------------------------------------------------
    def _write_json(self, data: Dict) -> str:
        path = os.path.join(self.output_dir, "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        return path

    # -- Markdown ----------------------------------------------------------
    def _write_md(self, data: Dict) -> str:
        path = os.path.join(self.output_dir, "report.md")
        scan = data["scan"]
        counts = data["counts"]
        m = data["meta"]
        lines: List[str] = []
        lines.append(f"# APKOwl Security Report")
        lines.append("")
        lines.append(f"**Package:** `{self._s(scan.get('package_name'),'(unknown)')}`  ")
        lines.append(f"**Version:** {self._s(scan.get('version_name'),'?')} "
                     f"({self._s(scan.get('version_code'),'?')})  ")
        lines.append(f"**SHA-256:** `{self._s(scan.get('apk_sha256'))}`  ")
        lines.append(f"**Generated:** {m['generated_at']} by APKOwl v{m['version']}")
        lines.append("")
        lines.append("## Risk summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for s in SEVERITY_ORDER:
            lines.append(f"| {s} | {counts.get(s,0)} |")
        lines.append(f"\n**Weighted risk score:** {self._risk_score(counts)}/100")
        lines.append("")

        coverage = self._coverage_info(m)
        lines.append("## Coverage notes")
        lines.append("")
        lines.append("| Item | Value |")
        lines.append("|------|-------|")
        runtime = coverage["runtime"]
        if runtime:
            lines.append(f"| Device mode | {'on' if runtime.get('device_mode') else 'off'} |")
            lines.append(f"| Active HTTP tests | {'on' if runtime.get('allow_active_http') else 'off'} |")
        missing = coverage["missing_tools"]
        lines.append(f"| Missing tools | {', '.join(missing) if missing else 'none'} |")
        errors = coverage["phase_errors"]
        if errors:
            lines.append(f"| Phase errors | {'; '.join(errors[:5])} |")
        else:
            lines.append("| Phase errors | none |")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        findings = sorted(
            data["findings"],
            key=lambda f: (-int(f.get("severity", 0)), -float(f.get("cvss_score") or 0)),
        )
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f['title']}")
            lines.append("")
            lines.append(f"- **Severity:** {f.get('severity_label')} "
                         f"(CVSS {f.get('cvss_score','0')})")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {f['cwe']}")
            if f.get("owasp_code") and f["owasp_code"] != "--":
                lines.append(f"- **OWASP:** {f['owasp_code']} — {f.get('owasp_title','')}")
            lines.append(f"- **Module:** {f.get('module')}  |  "
                         f"**Confidence:** {f.get('confidence')}")
            lines.append("")
            lines.append(f"{f.get('description','')}")
            lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("")
                for ev in f["evidence"][:8]:
                    loc = ev.get("file_path", "")
                    ln = ev.get("line_number", 0)
                    locstr = f"`{loc}`" + (f":{ln}" if ln else "")
                    snippet = (ev.get("snippet") or "").strip()
                    lines.append(f"- {locstr}")
                    if snippet:
                        lines.append(f"  ```\n  {snippet}\n  ```")
                lines.append("")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
            lines.append("---")
            lines.append("")

        # endpoints
        if data["endpoints"]:
            lines.append("## Discovered endpoints")
            lines.append("")
            lines.append("| Method | URL | Source |")
            lines.append("|--------|-----|--------|")
            for e in data["endpoints"][:200]:
                lines.append(f"| {e.get('method') or 'GET'} | {e.get('url')} | "
                             f"{e.get('source')} |")
            lines.append("")

        # artifacts
        if data["artifacts"]:
            lines.append("## Generated artifacts")
            lines.append("")
            for a in data["artifacts"]:
                lines.append(f"- **{a.get('kind')}**: `{a.get('path')}` "
                             f"{('— ' + a['note']) if a.get('note') else ''}")
            lines.append("")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    # -- HTML --------------------------------------------------------------
    def _write_html(self, data: Dict) -> str:
        path = os.path.join(self.output_dir, "report.html")
        scan = data["scan"]
        counts = data["counts"]
        m = data["meta"]
        risk = self._risk_score(counts)
        coverage = self._coverage_info(m)
        missing_tools = coverage["missing_tools"]
        phase_errors = coverage["phase_errors"]
        runtime = coverage["runtime"]
        coverage_rows = []
        if runtime:
            coverage_rows.append(
                f"<tr><td>Device mode</td><td>{'on' if runtime.get('device_mode') else 'off'}</td></tr>"
            )
            coverage_rows.append(
                f"<tr><td>Active HTTP tests</td><td>{'on' if runtime.get('allow_active_http') else 'off'}</td></tr>"
            )
        coverage_rows.append(
            f"<tr><td>Missing tools</td><td>{html.escape(', '.join(missing_tools) if missing_tools else 'none')}</td></tr>"
        )
        coverage_rows.append(
            f"<tr><td>Phase errors</td><td>{html.escape('; '.join(phase_errors[:5]) if phase_errors else 'none')}</td></tr>"
        )
        coverage_block = (
            "<h2 class='sec'><span>#</span> Coverage &amp; configuration</h2>"
            "<table><thead><tr><th>Item</th><th>Value</th></tr></thead>"
            f"<tbody>{''.join(coverage_rows)}</tbody></table>"
        )

        findings = sorted(
            data["findings"],
            key=lambda f: (-int(f.get("severity", 0)), -float(f.get("cvss_score") or 0)),
        )

        finding_cards = "\n".join(self._finding_card(f) for f in findings)
        donut = self._donut(counts)
        endpoint_rows = "\n".join(
            f"<tr><td class='mono'>{html.escape(self._s(e.get('method')) or 'GET')}</td>"
            f"<td class='mono url'>{html.escape(self._s(e.get('url')))}</td>"
            f"<td>{html.escape(self._s(e.get('source')))}</td></tr>"
            for e in data["endpoints"][:300]
        ) or "<tr><td colspan='3' class='empty'>No endpoints discovered</td></tr>"

        artifact_rows = "\n".join(
            f"<tr><td>{html.escape(self._s(a.get('kind')))}</td>"
            f"<td class='mono'>{html.escape(os.path.basename(self._s(a.get('path'))))}</td>"
            f"<td>{html.escape(self._s(a.get('note')))}</td></tr>"
            for a in data["artifacts"]
        ) or "<tr><td colspan='3' class='empty'>No artifacts</td></tr>"

        sdk_chips = "".join(
            f"<span class='chip chip-{html.escape(cat)}'>{html.escape(name)}"
            f"<em>{html.escape(cat)}</em></span>"
            for name, cat in sorted(m.get("sdks", {}).items())
        ) or "<span class='empty'>None detected</span>"

        # MASVS coverage: which control groups the findings touch
        cwe_ids = [f.get("cwe", "") for f in findings if f.get("cwe")]
        coverage = coverage_summary(cwe_ids)
        masvs_rows = self._masvs_rows(coverage, cwe_ids)

        counts_cards = "".join(
            f"<div class='sevcard' style='--c:{SEVERITY_HEX[s]}'>"
            f"<div class='sevnum'>{counts.get(s,0)}</div>"
            f"<div class='sevlbl'>{s}</div></div>"
            for s in SEVERITY_ORDER
        )

        page = self._html_template(
            package=html.escape(self._s(scan.get("package_name"), "(unknown)")),
            version=html.escape(f"{self._s(scan.get('version_name'),'?')} "
                                f"({self._s(scan.get('version_code'),'?')})"),
            sha=html.escape(self._s(scan.get("apk_sha256"))),
            generated=html.escape(m["generated_at"]),
            tool_version=html.escape(m["version"]),
            risk=risk,
            total_findings=len(findings),
            counts_cards=counts_cards,
            donut=donut,
            finding_cards=finding_cards,
            endpoint_rows=endpoint_rows,
            artifact_rows=artifact_rows,
            sdk_chips=sdk_chips,
            masvs_rows=masvs_rows,
            obf=html.escape(str(m.get("obfuscation", {}).get("toolchain", "unknown"))),
            pinning=html.escape(", ".join(m.get("pinning", [])) or "none detected"),
            native_count=len(m.get("native_libs", [])),
            perm_count=len(m.get("permissions", [])),
            comp_count=len(m.get("components", [])),
            coverage_block=coverage_block,
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(page)
        return path

    def _finding_card(self, f: Dict) -> str:
        sev = f.get("severity_label", "INFO")
        color = SEVERITY_HEX.get(sev, "#7c8aff")
        evidence_html = ""
        if f.get("evidence"):
            items = []
            for ev in f["evidence"][:8]:
                loc = html.escape(ev.get("file_path", ""))
                ln = ev.get("line_number", 0)
                locstr = loc + (f":{ln}" if ln else "")
                snippet = html.escape((ev.get("snippet") or "").strip())
                block = f"<div class='ev'><div class='evloc mono'>{locstr}</div>"
                if snippet:
                    block += f"<pre class='evsnip'>{snippet}</pre>"
                block += "</div>"
                items.append(block)
            evidence_html = (
                "<div class='evidence'><div class='lbl'>Evidence</div>"
                + "".join(items) + "</div>"
            )
        owasp = ""
        if f.get("owasp_code") and f["owasp_code"] != "--":
            owasp = (f"<span class='tag owasp'>{html.escape(f['owasp_code'])} "
                     f"{html.escape(f.get('owasp_title',''))}</span>")
        cwe = (f"<span class='tag cwe'>{html.escape(f['cwe'])}</span>"
               if f.get("cwe") else "")
        cvss = (f"<span class='tag cvss'>CVSS {f.get('cvss_score','0')}</span>"
                if f.get("cvss_score") else "")
        # MASVS control tags derived from the finding's CWE
        masvs_tags = ""
        if f.get("cwe"):
            for ctrl in masvs_for_cwe(f["cwe"]):
                masvs_tags += f"<span class='tag masvs'>{html.escape(ctrl.id)}</span>"
        remediation = ""
        if f.get("remediation"):
            remediation = (f"<div class='remed'><span class='lbl'>Fix</span>"
                           f"{html.escape(f['remediation'])}</div>")
        return f"""
        <div class="card" data-sev="{sev}" style="--c:{color}">
          <div class="cardhead">
            <span class="sevpill" style="background:{color}">{sev}</span>
            <h3>{html.escape(f.get('title',''))}</h3>
          </div>
          <div class="tags">{cvss}{cwe}{owasp}{masvs_tags}
            <span class="tag mod">{html.escape(f.get('module',''))}</span>
            <span class="tag conf">{html.escape(f.get('confidence',''))}</span>
          </div>
          <p class="desc">{html.escape(f.get('description',''))}</p>
          {evidence_html}
          {remediation}
        </div>"""

    def _masvs_rows(self, coverage: Dict[str, int], cwe_ids: List[str]) -> str:
        """Render a table of MASVS groups with how many findings touch each."""
        # group -> set of control ids actually triggered
        triggered: Dict[str, set] = {}
        for cwe in cwe_ids:
            for ctrl in masvs_for_cwe(cwe):
                triggered.setdefault(ctrl.group, set()).add(ctrl.id)
        all_groups = sorted(
            {c.group for c in MASVS_CONTROLS.values()}
        )
        rows = []
        for group in all_groups:
            n = coverage.get(group, 0)
            ctrls = sorted(triggered.get(group, set()))
            status = "FAIL" if n else "ok"
            color = "#ff7a18" if n else "#3ad29f"
            ctrl_str = ", ".join(ctrls) if ctrls else "—"
            rows.append(
                f"<tr><td class='mono' style='color:{color}'>{status}</td>"
                f"<td>MASVS-{html.escape(group)}</td>"
                f"<td>{n}</td><td class='mono'>{html.escape(ctrl_str)}</td></tr>"
            )
        return "\n".join(rows)

    def _donut(self, counts: Dict[str, int]) -> str:
        total = sum(counts.get(s, 0) for s in SEVERITY_ORDER) or 1
        segments = []
        offset = 0.0
        circumference = 2 * 3.14159 * 52
        for s in SEVERITY_ORDER:
            val = counts.get(s, 0)
            if val == 0:
                continue
            frac = val / total
            length = frac * circumference
            segments.append(
                f"<circle r='52' cx='60' cy='60' fill='none' "
                f"stroke='{SEVERITY_HEX[s]}' stroke-width='16' "
                f"stroke-dasharray='{length:.2f} {circumference - length:.2f}' "
                f"stroke-dashoffset='{-offset:.2f}' transform='rotate(-90 60 60)'/>"
            )
            offset += length
        return (
            f"<svg viewBox='0 0 120 120' class='donut'>"
            f"<circle r='52' cx='60' cy='60' fill='none' stroke='#1c2233' "
            f"stroke-width='16'/>{''.join(segments)}"
            f"<text x='60' y='56' class='dnum'>{total}</text>"
            f"<text x='60' y='74' class='dlbl'>findings</text></svg>"
        )

    def _html_template(self, **k) -> str:
        # NOTE: braces in CSS are doubled for str.format
        return """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>APKOwl Report — {package}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Mono:wght@400;700&display=swap');
:root{{--bg:#0a0d16;--panel:#11151f;--panel2:#161b29;--ink:#e7ecf5;--dim:#8a94a8;--line:#222a3d;--accent:#4ad9ff;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--ink);font-family:'Space Mono',ui-monospace,monospace;line-height:1.55;
background-image:radial-gradient(circle at 15% -10%,rgba(74,217,255,.08),transparent 40%),radial-gradient(circle at 100% 0,rgba(255,122,24,.06),transparent 35%);}}
.wrap{{max-width:1100px;margin:0 auto;padding:48px 24px 96px}}
header.top{{border:1px solid var(--line);background:linear-gradient(180deg,var(--panel2),var(--panel));border-radius:18px;padding:32px 34px;position:relative;overflow:hidden}}
header.top::before{{content:'';position:absolute;inset:0;background:repeating-linear-gradient(90deg,transparent 0 38px,rgba(255,255,255,.012) 38px 39px);pointer-events:none}}
.brand{{display:flex;align-items:center;gap:14px;margin-bottom:18px}}
.owl{{font-size:34px;filter:drop-shadow(0 0 12px rgba(74,217,255,.5))}}
.brand h1{{font-family:'JetBrains Mono';font-size:26px;letter-spacing:-1px}}
.brand .v{{color:var(--accent);font-size:12px;border:1px solid var(--accent);padding:2px 8px;border-radius:20px;margin-left:4px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 28px;margin-top:8px}}
.meta div{{font-size:13px}} .meta .lab{{color:var(--dim);display:block;font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.mono{{font-family:'JetBrains Mono'}} .url{{word-break:break-all}}
.sha{{word-break:break-all;color:var(--accent)}}
.dash{{display:grid;grid-template-columns:160px 1fr;gap:28px;margin:26px 0;align-items:center;
border:1px solid var(--line);background:var(--panel);border-radius:18px;padding:26px 30px}}
.donut{{width:150px;height:150px}} .dnum{{fill:var(--ink);font-size:26px;text-anchor:middle;font-family:'JetBrains Mono';font-weight:700}}
.dlbl{{fill:var(--dim);font-size:8px;text-anchor:middle;text-transform:uppercase;letter-spacing:2px}}
.sevgrid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}
.sevcard{{border:1px solid var(--line);border-top:3px solid var(--c);border-radius:12px;padding:16px;text-align:center;background:var(--panel2)}}
.sevnum{{font-size:30px;font-weight:700;color:var(--c);font-family:'JetBrains Mono'}}
.sevlbl{{font-size:10px;color:var(--dim);letter-spacing:2px;margin-top:4px}}
.riskbar{{margin-top:16px}} .riskbar .track{{height:10px;background:#161b29;border-radius:6px;overflow:hidden;border:1px solid var(--line)}}
.riskbar .fill{{height:100%;width:{risk}%;background:linear-gradient(90deg,#4ad9ff,#ffd24a,#ff7a18,#ff3b3b)}}
.riskbar .lab{{display:flex;justify-content:space-between;font-size:11px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px}}
h2.sec{{font-family:'JetBrains Mono';font-size:18px;margin:42px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--line);letter-spacing:-.5px}}
h2.sec span{{color:var(--accent)}}
.card{{border:1px solid var(--line);border-left:4px solid var(--c);background:var(--panel);border-radius:12px;padding:20px 22px;margin-bottom:16px;transition:transform .15s,box-shadow .15s}}
.card:hover{{transform:translateX(3px);box-shadow:-6px 0 0 -2px var(--c)}}
.cardhead{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
.cardhead h3{{font-size:16px;font-family:'JetBrains Mono';font-weight:700}}
.sevpill{{font-size:10px;font-weight:700;color:#06080f;padding:3px 9px;border-radius:5px;letter-spacing:1px;white-space:nowrap}}
.tags{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}}
.tag{{font-size:10px;padding:3px 8px;border-radius:5px;border:1px solid var(--line);color:var(--dim);letter-spacing:.5px}}
.tag.cvss{{color:#ffd24a;border-color:#3a3320}} .tag.cwe{{color:#ff7a18;border-color:#3a2a1c}}
.tag.owasp{{color:#4ad9ff;border-color:#1c3340}} .tag.mod{{color:#7c8aff;border-color:#222a44}}
.tag.masvs{{color:#3ad29f;border-color:#1c3a30}}
.desc{{color:#c3ccdb;font-size:13.5px;margin-bottom:12px}}
.evidence,.remed{{background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:12px 14px;margin-top:10px}}
.lbl{{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--accent);margin-bottom:6px;margin-right:8px}}
.ev{{margin-bottom:8px}} .evloc{{font-size:11.5px;color:#8fb6c9;word-break:break-all}}
.evsnip{{background:#0a0d16;border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin-top:4px;font-family:'JetBrains Mono';font-size:11.5px;color:#9fe7c4;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.remed{{color:#cfe8d8;font-size:13px}}
table{{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:12px;overflow:hidden;font-size:12.5px}}
th{{background:var(--panel2);text-align:left;padding:11px 14px;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);border-bottom:1px solid var(--line)}}
td{{padding:10px 14px;border-bottom:1px solid var(--line)}} tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(74,217,255,.03)}} .empty{{color:var(--dim);text-align:center;padding:20px}}
.factgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px}}
.fact{{border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:14px 16px}}
.fact .n{{font-size:22px;font-weight:700;font-family:'JetBrains Mono';color:var(--accent)}}
.fact .l{{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:2px}}
.chips{{display:flex;flex-wrap:wrap;gap:8px}}
.chip{{font-size:12px;border:1px solid var(--line);background:var(--panel);border-radius:20px;padding:5px 12px;display:flex;gap:6px;align-items:center}}
.chip em{{font-style:normal;font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}}
.chip-ads em,.chip-analytics em,.chip-attribution em{{color:#ff7a18}}
footer{{margin-top:48px;text-align:center;color:var(--dim);font-size:11px;letter-spacing:1px}}
.filterbar{{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}}
.fbtn{{cursor:pointer;font-size:11px;padding:6px 13px;border-radius:20px;border:1px solid var(--line);background:var(--panel);color:var(--dim);letter-spacing:1px}}
.fbtn.active{{color:#06080f;font-weight:700}}
</style></head><body><div class="wrap">

<header class="top">
  <div class="brand"><span class="owl">&#129417;</span><h1>APKOwl</h1>
    <span class="v">v{tool_version}</span></div>
  <div class="meta">
    <div><span class="lab">Package</span><span class="mono">{package}</span></div>
    <div><span class="lab">Version</span><span class="mono">{version}</span></div>
    <div><span class="lab">Generated</span>{generated}</div>
    <div style="grid-column:1/-1"><span class="lab">SHA-256</span><span class="mono sha">{sha}</span></div>
  </div>
</header>

<div class="dash">
  {donut}
  <div>
    <div class="sevgrid">{counts_cards}</div>
    <div class="riskbar"><div class="lab"><span>Weighted risk</span><span>{risk}/100</span></div>
      <div class="track"><div class="fill"></div></div></div>
  </div>
</div>

<h2 class="sec"><span>#</span> Application profile</h2>
<div class="factgrid">
  <div class="fact"><div class="n">{total_findings}</div><div class="l">Findings</div></div>
  <div class="fact"><div class="n">{perm_count}</div><div class="l">Permissions</div></div>
  <div class="fact"><div class="n">{comp_count}</div><div class="l">Components</div></div>
  <div class="fact"><div class="n">{native_count}</div><div class="l">Native libs</div></div>
</div>
<div class="factgrid">
  <div class="fact"><div class="n" style="font-size:14px">{obf}</div><div class="l">Obfuscation</div></div>
  <div class="fact"><div class="n" style="font-size:14px">{pinning}</div><div class="l">SSL pinning</div></div>
</div>

{coverage_block}

<h2 class="sec"><span>#</span> Findings</h2>
<div class="filterbar" id="filters">
  <span class="fbtn active" data-f="ALL" style="border-color:#4ad9ff;color:#4ad9ff">ALL</span>
  <span class="fbtn" data-f="CRITICAL" style="--c:#ff3b3b">CRITICAL</span>
  <span class="fbtn" data-f="HIGH" style="--c:#ff7a18">HIGH</span>
  <span class="fbtn" data-f="MEDIUM" style="--c:#ffd24a">MEDIUM</span>
  <span class="fbtn" data-f="LOW" style="--c:#4ad9ff">LOW</span>
  <span class="fbtn" data-f="INFO" style="--c:#7c8aff">INFO</span>
</div>
<div id="cards">{finding_cards}</div>

<h2 class="sec"><span>#</span> Discovered endpoints</h2>
<table><thead><tr><th>Method</th><th>URL</th><th>Source</th></tr></thead>
<tbody>{endpoint_rows}</tbody></table>

<h2 class="sec"><span>#</span> Third-party SDKs</h2>
<div class="chips">{sdk_chips}</div>

<h2 class="sec"><span>#</span> OWASP MASVS coverage</h2>
<table><thead><tr><th>Status</th><th>Control group</th><th>Findings</th><th>Controls touched</th></tr></thead>
<tbody>{masvs_rows}</tbody></table>

<h2 class="sec"><span>#</span> Generated artifacts</h2>
<table><thead><tr><th>Kind</th><th>File</th><th>Note</th></tr></thead>
<tbody>{artifact_rows}</tbody></table>

<footer>Generated by APKOwl v{tool_version} &mdash; offline static + dynamic mobile assessment toolkit.<br>
This report is for authorised security testing only.</footer>
</div>
<script>
const btns=document.querySelectorAll('.fbtn');
btns.forEach(b=>b.addEventListener('click',()=>{{
  btns.forEach(x=>{{x.classList.remove('active');x.style.background='';x.style.color=x.dataset.f==='ALL'?'#4ad9ff':(x.style.getPropertyValue('--c')||'#8a94a8');}});
  b.classList.add('active');
  const f=b.dataset.f;
  if(f!=='ALL'){{b.style.background=b.style.getPropertyValue('--c');b.style.color='#06080f';}}
  document.querySelectorAll('.card').forEach(c=>{{
    c.style.display=(f==='ALL'||c.dataset.sev===f)?'block':'none';
  }});
}}));
</script>
</body></html>""".format(**k)
