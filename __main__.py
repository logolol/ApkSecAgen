"""
APKOwl :: __main__
==================

Command-line entrypoint. Wires up the logger, tool runner and database, prints a
capability report for the host, runs the twelve-phase pipeline and prints a
final summary plus the report locations.

Usage
-----
    python -m apkowl TARGET.apk [options]
    apkowl TARGET.xapk --output-dir ./out --no-device
    apkowl app.apk --active-http --verbose

Run ``apkowl --help`` for the full option list.
"""

from __future__ import annotations

import os
import sys
import time

# Ensure the package directory is importable whether invoked as
# `python -m apkowl` from the parent dir, `python __main__.py`, or via an
# installed console-script shim.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

try:
    import click
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "APKOwl requires 'click'. Install with: pip install click rich cryptography\n"
    )
    sys.exit(2)

from core.logger import configure, log
from core.toolrunner import ToolRunner
from core.db import Database
from core.pipeline import Pipeline, PipelineConfig


VERSION = "1.0.0"

BANNER = r"""
    _    ____  _  __ ___           _
   / \  |  _ \| |/ // _ \__      _| |
  / _ \ | |_) | ' /| | | \ \ /\ / / |
 / ___ \|  __/| . \| |_| |\ V  V /| |
/_/   \_\_|   |_|\_\\___/  \_/\_/ |_|   v%s
  autonomous mobile app pentest toolkit
""" % VERSION


def _parse_skip(skip: str):
    out = []
    if not skip:
        return out
    for part in skip.split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", required=False,
                type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output-dir", default="./apkowl-output",
              help="Directory for reports + artifacts (default: ./apkowl-output).")
@click.option("-v", "--verbose", is_flag=True, help="Verbose (debug) logging.")
@click.option("-q", "--quiet", is_flag=True, help="Only warnings and errors.")
@click.option("--no-color", is_flag=True, help="Disable coloured output.")
@click.option("--device/--no-device", "device_mode", default=True,
              help="Enable/disable live device interaction (adb/Frida/proxy). "
                   "Default: enabled (auto-degrades when no device is present).")
@click.option("--active-http", is_flag=True, default=False,
              help="Allow OUTBOUND HTTP requests to discovered endpoints "
                   "(IDOR/SQLi/method-tampering tests). Off by default.")
@click.option("--no-repackage", is_flag=True, default=False,
              help="Plan smali patches but do not rebuild/sign a patched APK.")
@click.option("--inject-seconds", default=20, show_default=True,
              help="Seconds to keep Frida attached when injecting.")
@click.option("--capture-seconds", default=30, show_default=True,
              help="Seconds to capture traffic via mitmproxy when intercepting.")
@click.option("--proxy-port", default=8080, show_default=True,
              help="Local port for the interception proxy.")
@click.option("--skip", default="", help="Comma-separated phase numbers to skip "
              "(e.g. --skip 5,6,7 to skip the active phases).")
@click.option("--list-tools", is_flag=True, help="Print the host tool capability "
              "report and exit.")
@click.version_option(VERSION, "-V", "--version", prog_name="APKOwl")
def main(target, output_dir, verbose, quiet, no_color, device_mode, active_http,
         no_repackage, inject_seconds, capture_seconds, proxy_port, skip,
         list_tools):
    """Run a full autonomous pentest against TARGET (an .apk or .xapk file)."""
    level = "DEBUG" if verbose else ("WARN" if quiet else "INFO")
    configure(level=level, quiet=quiet, no_color=no_color)

    if not no_color and not quiet:
        for line in BANNER.splitlines():
            print(line)

    tools = ToolRunner()

    # capability report
    tool_report = _print_capabilities(tools)
    if list_tools:
        return

    if not target:
        log.error("No TARGET specified. Provide an .apk/.xapk path, or use "
                  "--list-tools. See --help.")
        sys.exit(2)

    target = os.path.abspath(target)
    ext = os.path.splitext(target)[1].lower()
    if ext not in (".apk", ".xapk", ".apks", ".apkm", ".zip"):
        log.warn(f"'{ext}' is an unusual extension; attempting anyway.")

    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    workdir = os.path.join(output_dir, "work")
    os.makedirs(workdir, exist_ok=True)

    db_path = os.path.join(output_dir, "apkowl.db")
    db = Database(db_path)
    db.begin_scan(target, "", VERSION)
    db.set_kv("toolchain", tool_report)
    db.set_kv(
        "runtime_config",
        {
            "device_mode": device_mode,
            "allow_active_http": active_http,
            "enable_repackage": not no_repackage,
            "inject_seconds": inject_seconds,
            "capture_seconds": capture_seconds,
            "proxy_port": proxy_port,
            "skip_phases": _parse_skip(skip),
        },
    )

    log.banner(f"APKOwl scan: {os.path.basename(target)}")
    log.kv("target", target)
    log.kv("output", output_dir)
    log.kv("device mode", "on" if device_mode else "off")
    log.kv("active HTTP", "on" if active_http else "off")

    config = PipelineConfig(
        output_dir=output_dir,
        workdir=workdir,
        device_mode=device_mode,
        allow_active_http=active_http,
        enable_repackage=not no_repackage,
        inject_seconds=inject_seconds,
        capture_seconds=capture_seconds,
        proxy_port=proxy_port,
        skip_phases=_parse_skip(skip),
        tool_version=VERSION,
    )

    pipeline = Pipeline(tools, db, config)
    try:
        ctx = pipeline.run(target)
    except KeyboardInterrupt:
        log.error("interrupted by user")
        db.finish_scan("aborted")
        db.close()
        sys.exit(130)

    # final summary
    counts = db.severity_counts()
    log.banner("Scan complete")
    log.summary_table(counts)

    if ctx.report:
        log.good("Reports:")
        log.kv("  HTML", ctx.report.html_path)
        log.kv("  Summary", ctx.report.summary_path)
        log.kv("  Markdown", ctx.report.md_path)
        log.kv("  JSON", ctx.report.json_path)
    if ctx.package:
        log.kv("package", ctx.package)
    total = sum(counts.values())
    log.kv("total findings", total)

    db.close()

    # exit code reflects worst severity for CI usefulness
    if counts.get("CRITICAL", 0):
        sys.exit(3)
    if counts.get("HIGH", 0):
        sys.exit(2)
    if counts.get("MEDIUM", 0):
        sys.exit(1)
    sys.exit(0)


def _print_capabilities(tools: ToolRunner):
    report = tools.capability_report()
    rows = []
    available = 0
    for entry in report:
        ok = entry["available"]
        available += 1 if ok else 0
        mark = "[+]" if ok else "[-]"
        rows.append((mark, entry["tool"], entry["purpose"]))
    log.kv("host tools available", f"{available}/{len(report)}")
    # use a table if rich is present
    try:
        log.table(
            "Host toolchain",
            ["", "tool", "purpose"],
            rows,
        )
    except Exception:
        for mark, tool, purpose in rows:
            log.info(f"  {mark} {tool:<14} {purpose}")
    # show install hints for the missing essentials
    missing_essential = [e for e in report
                         if not e["available"] and e["tool"] in
                         ("apktool", "jadx", "adb", "apksigner")]
    if missing_essential:
        log.warn("Some core tools are missing; static analysis still runs, but "
                 "install these for full capability:")
        for e in missing_essential:
            log.info(f"  {e['hint']}")
    return report


if __name__ == "__main__":
    main()
