"""
APKOwl :: modules.intents
=========================

Phase 8 — exercise the app's exported IPC surface: deep links, exported
activities/services/receivers and content providers.

Static analysis (always):
  * builds an attack matrix from the manifest's exported components and
    deep-link intent filters,
  * generates concrete ``adb shell am`` / ``content`` commands an operator can
    fire, with crafted payloads (path traversal, XSS, open-redirect, SQLi,
    oversized input) for each deep link,
  * flags structurally risky surfaces (exported providers, browsable links
    that take a URL parameter, etc.).

Dynamic testing (when a device is connected and ``enable_dynamic`` is set):
  * fires each generated command via adb,
  * watches logcat for crashes / exceptions / leaked data around each fire,
  * records which components actually launched.

All generated commands are saved as a runnable script regardless of device
availability, so the work is reusable.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


# payloads injected into deep-link path/query slots
PAYLOADS = {
    "path_traversal": "../../../../etc/passwd",
    "xss": "<script>alert(1)</script>",
    "open_redirect": "https://evil.example.com",
    "sqli": "1' OR '1'='1",
    "long": "A" * 5000,
    "null_byte": "%00",
    "format_string": "%n%n%n%s%s",
}


@dataclass
class IntentCommand:
    description: str
    command: List[str]
    component: str
    category: str  # deeplink | activity | service | receiver | provider
    payload: str = ""


@dataclass
class IntentsResult:
    commands: List[IntentCommand] = field(default_factory=list)
    script_path: str = ""
    fired: int = 0
    crashes: int = 0
    findings: List[Finding] = field(default_factory=list)
    device_serial: str = ""


class IntentTester:
    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir

    def run(
        self,
        package: str,
        components: List[Dict],
        deeplinks: List[Dict],
        enable_dynamic: bool = True,
    ) -> IntentsResult:
        result = IntentsResult()
        if not package:
            log.warn("intents: no package name; skipping")
            return result

        self._build_deeplink_commands(package, deeplinks, result)
        self._build_component_commands(package, components, result)
        self._write_script(package, result)
        self._emit_static_findings(components, deeplinks, result)

        if enable_dynamic:
            self._maybe_fire(package, result)
        else:
            log.info("intent dynamic firing disabled")

        self._persist(result)
        log.good(
            f"intents phase: {len(result.commands)} command(s) generated, "
            f"{result.fired} fired, {len(result.findings)} finding(s)"
        )
        return result

    # -- command generation ------------------------------------------------
    def _build_deeplink_commands(
        self, package: str, deeplinks: List[Dict], result: IntentsResult
    ) -> None:
        for dl in deeplinks:
            scheme = dl.get("scheme", "")
            host = dl.get("host", "")
            if not scheme:
                continue
            base = f"{scheme}://{host}" if host else f"{scheme}://"
            path = dl.get("path") or dl.get("pathPrefix") or "/test"
            # benign launch
            uri = base + path
            result.commands.append(
                IntentCommand(
                    description=f"Launch deep link {uri}",
                    command=["shell", "am", "start", "-a",
                             "android.intent.action.VIEW", "-d", uri, package],
                    component=dl.get("component", ""),
                    category="deeplink",
                )
            )
            # payload-laden variants
            for pname, payload in PAYLOADS.items():
                fuzzed = base + "/" + payload
                result.commands.append(
                    IntentCommand(
                        description=f"Deep link fuzz ({pname}) on {scheme}://",
                        command=["shell", "am", "start", "-a",
                                 "android.intent.action.VIEW", "-d", fuzzed, package],
                        component=dl.get("component", ""),
                        category="deeplink",
                        payload=pname,
                    )
                )

    def _build_component_commands(
        self, package: str, components: List[Dict], result: IntentsResult
    ) -> None:
        for comp in components:
            if not comp.get("exported"):
                continue
            ctype = comp.get("type", "")
            name = comp.get("name", "")
            if not name:
                continue
            full = name if name.startswith(".") is False and "." in name else package + name
            target = f"{package}/{name}" if not name.startswith(package) else name.replace(".", "/", 0)
            comp_arg = f"{package}/{name}"
            if ctype == "activity":
                result.commands.append(
                    IntentCommand(
                        description=f"Start exported activity {name}",
                        command=["shell", "am", "start", "-n", comp_arg],
                        component=name,
                        category="activity",
                    )
                )
            elif ctype == "service":
                result.commands.append(
                    IntentCommand(
                        description=f"Start exported service {name}",
                        command=["shell", "am", "startservice", "-n", comp_arg],
                        component=name,
                        category="service",
                    )
                )
            elif ctype == "receiver":
                for action in comp.get("actions", []) or ["android.intent.action.BOOT_COMPLETED"]:
                    result.commands.append(
                        IntentCommand(
                            description=f"Broadcast to receiver {name} ({action})",
                            command=["shell", "am", "broadcast", "-a", action,
                                     "-n", comp_arg],
                            component=name,
                            category="receiver",
                        )
                    )
            elif ctype == "provider":
                # content provider query attempts
                authority = comp.get("authority") or name
                result.commands.append(
                    IntentCommand(
                        description=f"Query content provider {name}",
                        command=["shell", "content", "query", "--uri",
                                 f"content://{authority}"],
                        component=name,
                        category="provider",
                    )
                )
                # traversal in provider path
                result.commands.append(
                    IntentCommand(
                        description=f"Provider path traversal probe {name}",
                        command=["shell", "content", "query", "--uri",
                                 f"content://{authority}/../../../../data/data/{package}/databases"],
                        component=name,
                        category="provider",
                        payload="path_traversal",
                    )
                )

    def _write_script(self, package: str, result: IntentsResult) -> None:
        path = os.path.join(self.workdir, "intent-attacks.sh")
        lines = [
            "#!/usr/bin/env bash",
            "# APKOwl generated intent/deeplink attack commands",
            f"# Target package: {package}",
            "# Review before running. Requires: adb + connected device.",
            "set -x",
            "",
        ]
        for cmd in result.commands:
            lines.append(f"# {cmd.description}")
            lines.append("adb " + " ".join(self._shell_quote(a) for a in cmd.command))
            lines.append("")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            os.chmod(path, 0o755)
            result.script_path = path
            log.good(f"intent attack script written: {path}")
        except OSError as exc:
            log.warn(f"could not write intent script: {exc}")

    @staticmethod
    def _shell_quote(arg: str) -> str:
        if re.search(r"[\s'\"<>|&;$()]", arg):
            return "'" + arg.replace("'", "'\\''") + "'"
        return arg

    # -- static findings ---------------------------------------------------
    def _emit_static_findings(
        self, components: List[Dict], deeplinks: List[Dict], result: IntentsResult
    ) -> None:
        # browsable deep links taking a URL-ish parameter -> redirect/inj risk
        for dl in deeplinks:
            scheme = dl.get("scheme", "")
            if scheme in ("http", "https") or dl.get("host"):
                result.findings.append(
                    Finding(
                        title=f"Browsable deep link exposes navigation: "
                        f"{scheme}://{dl.get('host','')}",
                        description="A browsable deep link is declared. If the "
                        "handling code trusts the incoming URI (e.g. loads it in "
                        "a WebView or uses it for redirection), it may enable "
                        "open redirect, XSS or local-file access.",
                        module="intents",
                        severity=Severity.LOW,
                        cwe="CWE-939",
                        owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                        remediation="Validate and all-list deep-link targets; "
                        "never load attacker-controlled URIs into a WebView with "
                        "JavaScript enabled.",
                        tags=["deeplink", "ipc"],
                    ).add_evidence(
                        file_path="AndroidManifest.xml",
                        snippet=f"{scheme}://{dl.get('host','')}{dl.get('path','')}",
                    )
                )

        # exported providers
        for comp in components:
            if comp.get("type") == "provider" and comp.get("exported"):
                result.findings.append(
                    Finding(
                        title=f"Exported content provider is queryable: "
                        f"{comp.get('name')}",
                        description="An exported content provider can be queried "
                        "by any app. If it lacks per-row authorization or is "
                        "vulnerable to path traversal / SQL injection in its "
                        "selection handling, it can leak or corrupt data.",
                        module="intents",
                        severity=Severity.HIGH,
                        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        cwe="CWE-926",
                        owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                        remediation="Set exported=false or enforce signature "
                        "permissions; parameterise all provider queries.",
                        tags=["provider", "ipc"],
                    ).add_evidence(
                        file_path="AndroidManifest.xml", snippet=comp.get("name", "")
                    )
                )

    # -- dynamic firing ----------------------------------------------------
    def _maybe_fire(self, package: str, result: IntentsResult) -> None:
        serial = self._first_device()
        if not serial:
            log.info("no device connected; intent commands generated for manual use")
            return
        result.device_serial = serial
        log.info(f"firing {len(result.commands)} intent(s) on {serial} ...")

        # clear logcat first
        self.tools.run_tool("adb", ["logcat", "-c"])

        for cmd in result.commands:
            r = self.tools.run_tool("adb", cmd.command, timeout=15)
            result.fired += 1
            time.sleep(0.3)
            crash = self._check_logcat_for_crash(package)
            if crash:
                result.crashes += 1
                result.findings.append(
                    Finding(
                        title=f"Crash triggered via {cmd.category}: {cmd.component}",
                        description=f"Firing '{cmd.description}'"
                        + (f" with the {cmd.payload} payload" if cmd.payload else "")
                        + " caused an unhandled exception, indicating missing "
                        "input validation on an exported surface.",
                        module="intents",
                        severity=Severity.MEDIUM,
                        cwe="CWE-20",
                        owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                        remediation="Validate all data received from Intents / "
                        "URIs; never assume well-formed input.",
                        tags=["ipc", "crash", cmd.category],
                    ).add_evidence(snippet=crash[:500])
                )

    def _check_logcat_for_crash(self, package: str) -> str:
        r = self.tools.run_tool("adb", ["logcat", "-d", "-t", "200"], timeout=10)
        if not r.ok:
            return ""
        crash_lines = []
        capture = False
        for line in r.stdout.splitlines():
            if "FATAL EXCEPTION" in line or "AndroidRuntime" in line and "E" in line[:40]:
                capture = True
            if capture:
                crash_lines.append(line)
                if len(crash_lines) > 15:
                    break
        # only count if it references our package
        text = "\n".join(crash_lines)
        if package and package in text:
            return text
        return ""

    def _first_device(self) -> str:
        if not self.tools.available("adb"):
            return ""
        r = self.tools.run_tool("adb", ["devices"])
        if not r.ok:
            return ""
        for line in r.stdout.splitlines()[1:]:
            line = line.strip()
            if line.endswith("device"):
                return line.split()[0]
        return ""

    # -- persistence -------------------------------------------------------
    def _persist(self, result: IntentsResult) -> None:
        if result.script_path:
            self.db.add_artifact(
                "intent_script", result.script_path, note="generated am/content commands"
            )
        self.db.set_kv(
            "intents_summary",
            {
                "commands": len(result.commands),
                "fired": result.fired,
                "crashes": result.crashes,
                "device": result.device_serial,
            },
        )
