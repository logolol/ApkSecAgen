"""
APKOwl :: core.logger
=====================

A small logging facade built on top of the `rich` library when available, with
a plain-text fallback so the tool still runs in minimal environments.

The logger gives every module a consistent voice: timestamped, colour-coded by
level, with helpers for phase banners, finding announcements, tables and
progress contexts. Modules never import `rich` directly — they go through here,
which means the look and feel can be tuned in one place.
"""

from __future__ import annotations

import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:  # pragma: no cover - exercised implicitly
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich import box

    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False


from core.findings import Finding, Severity


LEVEL_STYLE = {
    "DEBUG": "dim",
    "INFO": "cyan",
    "GOOD": "bold green",
    "WARN": "yellow",
    "ERROR": "bold red",
    "FATAL": "bold white on red",
}

LEVEL_ORDER = {"DEBUG": 10, "INFO": 20, "GOOD": 20, "WARN": 30, "ERROR": 40, "FATAL": 50}


class Logger:
    def __init__(self, level: str = "INFO", quiet: bool = False, no_color: bool = False) -> None:
        self.min_level = LEVEL_ORDER.get(level.upper(), 20)
        self.quiet = quiet
        self.start = time.time()
        if _RICH and not no_color:
            self.console = Console(highlight=False)
            self._rich = True
        else:
            self.console = None
            self._rich = False

    # -- internal ----------------------------------------------------------
    def _ts(self) -> str:
        elapsed = time.time() - self.start
        return f"{elapsed:7.2f}s"

    def _emit(self, level: str, msg: str) -> None:
        if self.quiet and LEVEL_ORDER.get(level, 20) < 30:
            return
        if LEVEL_ORDER.get(level, 20) < self.min_level:
            return
        ts = self._ts()
        if self._rich:
            style = LEVEL_STYLE.get(level, "white")
            self.console.print(
                f"[dim]{ts}[/dim] [{style}]{level:<5}[/{style}] {msg}"
            )
        else:
            print(f"{ts} {level:<5} {self._strip(msg)}", file=sys.stderr)

    @staticmethod
    def _strip(msg: str) -> str:
        # crude removal of rich markup for the plain fallback
        import re

        return re.sub(r"\[/?[a-zA-Z0-9_ =#]+\]", "", msg)

    # -- public levels -----------------------------------------------------
    def debug(self, msg: str) -> None:
        self._emit("DEBUG", msg)

    def info(self, msg: str) -> None:
        self._emit("INFO", msg)

    def good(self, msg: str) -> None:
        self._emit("GOOD", msg)

    def warn(self, msg: str) -> None:
        self._emit("WARN", msg)

    def error(self, msg: str) -> None:
        self._emit("ERROR", msg)

    def fatal(self, msg: str) -> None:
        self._emit("FATAL", msg)

    # -- structural --------------------------------------------------------
    def banner(self, text: str) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(
                Panel.fit(
                    Text(text, style="bold white"),
                    border_style="bright_blue",
                    box=box.DOUBLE,
                )
            )
        else:
            line = "=" * (len(text) + 4)
            print(f"\n{line}\n  {text}\n{line}", file=sys.stderr)

    def phase(self, index: int, total: int, name: str) -> None:
        if self.quiet:
            return
        label = f"PHASE {index}/{total}  ::  {name}"
        if self._rich:
            self.console.rule(f"[bold cyan]{label}[/bold cyan]", style="cyan")
        else:
            print(f"\n--- {label} ---", file=sys.stderr)

    def finding(self, f: Finding) -> None:
        if self.quiet:
            return
        if self._rich:
            sev = f"[{f.severity.color}]{f.severity.name:<8}[/{f.severity.color}]"
            score = f"[dim]CVSS {f.cvss_score:.1f}[/dim]" if f.cvss_score else ""
            self.console.print(f"  {sev} {f.title} {score}")
        else:
            print(f"  [{f.severity.name}] {f.title}", file=sys.stderr)

    def kv(self, key: str, value: Any) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(f"  [dim]{key:<22}[/dim] {value}")
        else:
            print(f"  {key:<22} {value}", file=sys.stderr)

    # -- tables ------------------------------------------------------------
    def table(self, title: str, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
        if self.quiet:
            return
        if self._rich:
            t = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold magenta")
            for c in columns:
                t.add_column(str(c))
            for row in rows:
                t.add_row(*[str(x) for x in row])
            self.console.print(t)
        else:
            print(f"\n{title}", file=sys.stderr)
            print("  " + " | ".join(columns), file=sys.stderr)
            for row in rows:
                print("  " + " | ".join(str(x) for x in row), file=sys.stderr)

    def summary_table(self, counts: Dict[str, int]) -> None:
        rows = []
        for sev in reversed(list(Severity)):
            rows.append((sev.name, counts.get(sev.name, 0)))
        self.table("Findings by severity", ["Severity", "Count"], rows)

    # -- progress ----------------------------------------------------------
    def progress(self):
        """Return a context-managed progress bar (rich) or a no-op shim."""
        if self._rich:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=self.console,
                transient=True,
            )
        return _NullProgress()


class _NullProgress:
    """A drop-in replacement for rich.Progress when rich is unavailable."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def add_task(self, description: str, total: int = 100) -> int:
        return 0

    def update(self, task_id: int, advance: int = 0, **kwargs) -> None:
        pass

    def advance(self, task_id: int, n: int = 1) -> None:
        pass


# Module-level default logger; main() replaces it with a configured one.
log = Logger()


def configure(level: str = "INFO", quiet: bool = False, no_color: bool = False) -> Logger:
    """Reconfigure the shared logger *in place*.

    Modules do ``from core.logger import log`` at import time, binding their
    name to the singleton instance. Rebinding the module global here would not
    propagate to them, so instead we mutate the existing instance's state.
    """
    global log
    fresh = Logger(level=level, quiet=quiet, no_color=no_color)
    log.__dict__.update(fresh.__dict__)
    return log


if __name__ == "__main__":
    lg = configure("DEBUG")
    lg.banner("APKOwl logger self-test")
    lg.phase(1, 12, "Extraction")
    lg.info("informational message")
    lg.good("something good happened")
    lg.warn("a warning")
    lg.error("an error")
    lg.kv("package", "com.example.app")
    lg.summary_table({"CRITICAL": 2, "HIGH": 5, "MEDIUM": 9, "LOW": 3, "INFO": 12})
    f = Finding("Hardcoded AWS key", "desc", "secrets",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cwe="CWE-798")
    lg.finding(f)
    print("logger self-test OK")
