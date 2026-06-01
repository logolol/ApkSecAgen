"""
APKOwl :: core.toolrunner
========================

Every external binary the tool depends on (apktool, jadx, adb, frida, ...) is
invoked through :class:`ToolRunner`. Centralising subprocess handling buys us:

* a single place to enforce timeouts and capture stderr,
* a capability map so modules can ask "is jadx available?" before relying on it,
* helpful, distro-aware install hints (Parrot/Debian/Kali use apt; we surface
  the right command),
* consistent logging of every command line that ran.

Nothing here raises on a missing tool — modules degrade gracefully and emit an
informational finding instead, so a partial toolchain still produces a report.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from core.logger import log


@dataclass
class ToolResult:
    """The outcome of running an external command."""

    command: List[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    def short(self, n: int = 400) -> str:
        out = (self.stdout or self.stderr or self.error).strip()
        return out[:n]


# Known tools: name -> (binary candidates, apt package, purpose)
KNOWN_TOOLS: Dict[str, Dict[str, object]] = {
    "apktool": {
        "bins": ["apktool"],
        "apt": "apktool",
        "purpose": "decode resources and smali",
    },
    "jadx": {
        "bins": ["jadx"],
        "apt": "jadx",
        "purpose": "decompile DEX to Java",
    },
    "d2j-dex2jar": {
        "bins": ["d2j-dex2jar", "d2j-dex2jar.sh", "dex2jar"],
        "apt": "dex2jar",
        "purpose": "convert DEX to JAR",
    },
    "adb": {
        "bins": ["adb"],
        "apt": "android-tools-adb",
        "purpose": "device communication",
    },
    "frida": {
        "bins": ["frida"],
        "apt": "pip install frida-tools",
        "purpose": "dynamic instrumentation",
    },
    "objection": {
        "bins": ["objection"],
        "apt": "pip install objection",
        "purpose": "runtime mobile exploration",
    },
    "mitmproxy": {
        "bins": ["mitmdump", "mitmproxy"],
        "apt": "pip install mitmproxy",
        "purpose": "TLS-intercepting proxy",
    },
    "keytool": {
        "bins": ["keytool"],
        "apt": "default-jdk-headless",
        "purpose": "keystore / certificate handling",
    },
    "jarsigner": {
        "bins": ["jarsigner"],
        "apt": "default-jdk-headless",
        "purpose": "re-sign APKs",
    },
    "apksigner": {
        "bins": ["apksigner"],
        "apt": "apksigner",
        "purpose": "v2/v3 APK signing",
    },
    "zipalign": {
        "bins": ["zipalign"],
        "apt": "zipalign",
        "purpose": "align repackaged APKs",
    },
    "strings": {
        "bins": ["strings"],
        "apt": "binutils",
        "purpose": "extract readable strings from binaries",
    },
    "readelf": {
        "bins": ["readelf"],
        "apt": "binutils",
        "purpose": "inspect ELF native libraries",
    },
    "objdump": {
        "bins": ["objdump"],
        "apt": "binutils",
        "purpose": "disassemble native libraries",
    },
    "nm": {
        "bins": ["nm"],
        "apt": "binutils",
        "purpose": "list native symbols",
    },
    "file": {
        "bins": ["file"],
        "apt": "file",
        "purpose": "identify file types",
    },
    "aapt": {
        "bins": ["aapt", "aapt2"],
        "apt": "aapt",
        "purpose": "dump APK badging",
    },
}


class ToolRunner:
    """Resolves and runs external tools, caching availability lookups."""

    def __init__(self, default_timeout: int = 300) -> None:
        self.default_timeout = default_timeout
        self._resolved: Dict[str, Optional[str]] = {}

    # -- resolution --------------------------------------------------------
    def resolve(self, tool: str) -> Optional[str]:
        """Return an absolute path to the first available binary for *tool*."""
        if tool in self._resolved:
            return self._resolved[tool]
        candidates: Sequence[str]
        if tool in KNOWN_TOOLS:
            candidates = KNOWN_TOOLS[tool]["bins"]  # type: ignore[index]
        else:
            candidates = [tool]
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                self._resolved[tool] = path
                return path
        self._resolved[tool] = None
        return None

    def available(self, tool: str) -> bool:
        return self.resolve(tool) is not None

    def install_hint(self, tool: str) -> str:
        info = KNOWN_TOOLS.get(tool)
        if not info:
            return f"Install '{tool}' and ensure it is on your PATH."
        apt = info["apt"]
        if isinstance(apt, str) and apt.startswith("pip "):
            return f"Run: {apt}"
        return f"On Parrot/Debian/Kali: sudo apt install {apt}"

    def capability_report(self) -> List[Dict[str, object]]:
        report = []
        for name, info in KNOWN_TOOLS.items():
            path = self.resolve(name)
            report.append(
                {
                    "tool": name,
                    "available": path is not None,
                    "path": path or "",
                    "purpose": info["purpose"],
                    "hint": "" if path else self.install_hint(name),
                }
            )
        return report

    # -- execution ---------------------------------------------------------
    def run(
        self,
        args: Sequence[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        input_text: Optional[str] = None,
        check: bool = False,
    ) -> ToolResult:
        """Run a command, resolving the first arg as a known tool if possible."""
        args = list(args)
        if not args:
            return ToolResult(command=[], error="empty command")

        resolved = self.resolve(args[0])
        if resolved:
            args[0] = resolved

        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)

        timeout = timeout if timeout is not None else self.default_timeout
        log.debug(f"exec: {' '.join(args)}")
        start = time.time()
        try:
            proc = subprocess.run(
                args,
                cwd=cwd,
                env=merged_env,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            result = ToolResult(
                command=args,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration=time.time() - start,
            )
        except subprocess.TimeoutExpired as exc:
            result = ToolResult(
                command=args,
                timed_out=True,
                duration=time.time() - start,
                stdout=exc.stdout.decode("utf-8", "ignore") if exc.stdout else "",
                stderr="timed out",
                error=f"timed out after {timeout}s",
            )
        except FileNotFoundError:
            result = ToolResult(command=args, error="binary not found")
        except Exception as exc:  # pragma: no cover - defensive
            result = ToolResult(command=args, error=str(exc))

        if check and not result.ok:
            log.warn(f"command failed ({result.returncode}): {' '.join(args)}")
        return result

    def run_tool(
        self,
        tool: str,
        extra_args: Sequence[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> ToolResult:
        """Run a named tool; if unavailable, return a result flagged with an
        install hint rather than raising."""
        if not self.available(tool):
            return ToolResult(
                command=[tool, *extra_args],
                error=f"{tool} not available. {self.install_hint(tool)}",
            )
        return self.run([tool, *extra_args], timeout=timeout, cwd=cwd)


# shared singleton; main() may replace timeout
tools = ToolRunner()


if __name__ == "__main__":
    from core.logger import configure

    configure("DEBUG")
    tr = ToolRunner()
    for row in tr.capability_report():
        mark = "yes" if row["available"] else "no "
        print(f"[{mark}] {row['tool']:<14} {row['purpose']}")
        if not row["available"]:
            print(f"        -> {row['hint']}")
    r = tr.run(["echo", "hello from toolrunner"])
    print("echo ->", r.stdout.strip(), "ok=", r.ok)
