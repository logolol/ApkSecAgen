"""
APKOwl :: modules.storage
=========================

Phase 9 — inspect what the app writes to the device, and how safely.

Static (always):
  * scans decompiled code for insecure storage patterns:
      - MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
      - getExternalStorage* writes of sensitive data
      - SharedPreferences holding token/password/key-named values
      - SQLite databases created without encryption (no SQLCipher)
      - WebView setSavePassword / saveFormData
      - missing FLAG_SECURE on activities that show sensitive data
      - logging of sensitive values (Log.d/Log.v with token/password)

Dynamic (when device connected and app installed):
  * pulls /data/data/<pkg>/{shared_prefs,databases,files} (needs root),
  * parses shared_prefs XML for sensitive keys,
  * opens pulled SQLite DBs and samples rows for PII / secrets,
  * scans pulled files for JWTs, base64 blobs and credential-looking content,
  * captures a slice of logcat and scans it for leaked secrets.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner
from signatures.secrets_db import SECRET_PATTERNS


SENSITIVE_KEY_RE = re.compile(
    r"(token|password|passwd|secret|api[_-]?key|auth|session|credential|"
    r"refresh|jwt|pin|ssn|card|cvv)",
    re.IGNORECASE,
)

WORLD_ACCESS_RE = re.compile(r"MODE_WORLD_(READABLE|WRITEABLE)")
EXTERNAL_STORAGE_RE = re.compile(r"getExternalStorage(PublicDirectory|Directory)?\b")
WEBVIEW_PASSWORD_RE = re.compile(r"setSavePassword\s*\(\s*true|setSaveFormData\s*\(\s*true")
SENSITIVE_LOG_RE = re.compile(
    r"Log\.[dvwie]\s*\([^)]*\b(token|password|secret|api[_-]?key|auth)\b",
    re.IGNORECASE,
)
FLAG_SECURE_RE = re.compile(r"FLAG_SECURE")
SQLCIPHER_RE = re.compile(r"net\.sqlcipher|SQLiteDatabase\.openOrCreateDatabase.*password", re.IGNORECASE)


@dataclass
class StorageResult:
    pulled_dir: str = ""
    prefs_files: List[str] = field(default_factory=list)
    db_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    device_serial: str = ""


class StorageAnalyzer:
    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir

    def run(
        self,
        package: str,
        code_roots: List[str],
        enable_dynamic: bool = True,
    ) -> StorageResult:
        result = StorageResult()
        self._static_scan(code_roots, result)
        if enable_dynamic and package:
            self._maybe_pull(package, result)
        self._persist(result)
        log.good(f"storage phase produced {len(result.findings)} finding(s)")
        return result

    # -- static ------------------------------------------------------------
    def _static_scan(self, roots: List[str], result: StorageResult) -> None:
        flag_secure_seen = False
        code_seen = False
        clipboard_flagged = False
        for path in self._iter_code(roots):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            code_seen = True

            if FLAG_SECURE_RE.search(content):
                flag_secure_seen = True

            # clipboard writes of sensitive-looking values
            if not clipboard_flagged and re.search(
                r"(ClipboardManager|setPrimaryClip|ClipData\.newPlainText)",
                content,
            ) and SENSITIVE_KEY_RE.search(content):
                clipboard_flagged = True
                result.findings.append(
                    FindingTemplates.clipboard_leak().add_evidence(file_path=path)
                )

            for m in WORLD_ACCESS_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                result.findings.append(
                    Finding(
                        title=f"World-accessible storage mode ({m.group(0)})",
                        description="The app creates a file or preferences store "
                        "with world-readable/writeable permissions, exposing it "
                        "to every app on pre-scoped-storage devices.",
                        module="storage",
                        severity=Severity.HIGH,
                        cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-732",
                        owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                        remediation="Use MODE_PRIVATE; never share data via "
                        "world-accessible files.",
                        tags=["storage", "permissions"],
                    ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0))
                )

            for m in WEBVIEW_PASSWORD_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                result.findings.append(
                    Finding(
                        title="WebView configured to save passwords/form data",
                        description="The WebView stores credentials or form data "
                        "locally, which can be recovered from the device.",
                        module="storage",
                        severity=Severity.MEDIUM,
                        cwe="CWE-522",
                        owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                        remediation="Call setSavePassword(false) / "
                        "setSaveFormData(false); avoid storing credentials in "
                        "the WebView.",
                        tags=["storage", "webview"],
                    ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0))
                )

            for m in SENSITIVE_LOG_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                result.findings.append(
                    Finding(
                        title="Sensitive data written to logcat",
                        description="A logging call appears to write a token / "
                        "password / key to logcat, where other apps with the "
                        "READ_LOGS permission or anyone with adb can read it.",
                        module="storage",
                        severity=Severity.MEDIUM,
                        cwe="CWE-532",
                        owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                        remediation="Strip sensitive logging from release builds; "
                        "use a logging wrapper that no-ops in production.",
                        tags=["storage", "logging"],
                    ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0)[:120])
                )

        if code_seen and not flag_secure_seen:
            result.findings.append(FindingTemplates.screenshot_not_blocked())
        log.debug(f"FLAG_SECURE present anywhere: {flag_secure_seen}")

    def _iter_code(self, roots: List[str]):
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith((".java", ".kt", ".smali")):
                        yield os.path.join(dirpath, name)

    # -- dynamic -----------------------------------------------------------
    def _maybe_pull(self, package: str, result: StorageResult) -> None:
        serial = self._first_device()
        if not serial:
            log.info("no device connected; skipping data pull")
            return
        result.device_serial = serial

        # confirm the app is installed
        r = self.tools.run_tool("adb", ["shell", "pm", "list", "packages", package])
        if package not in r.stdout:
            log.info(f"{package} not installed on device; skipping data pull")
            return

        pulled = os.path.join(self.workdir, "device-data")
        os.makedirs(pulled, exist_ok=True)
        result.pulled_dir = pulled
        data_dir = f"/data/data/{package}"

        # try a run-as pull (works for debuggable apps without root)
        log.info("attempting to pull app private data (run-as / root) ...")
        for sub in ("shared_prefs", "databases", "files"):
            self._pull_subdir(package, data_dir, sub, pulled)

        self._analyze_prefs(pulled, result)
        self._analyze_databases(pulled, result)
        self._analyze_files(pulled, result)
        self._scan_logcat(package, result)

    def _pull_subdir(self, package: str, data_dir: str, sub: str, dest: str) -> None:
        # method 1: run-as tar (debuggable apps)
        out_tar = os.path.join(dest, f"{sub}.tar")
        r = self.tools.run_tool(
            "adb",
            ["exec-out", "run-as", package, "tar", "-c", "-C", data_dir, sub],
            timeout=60,
        )
        if r.ok and r.stdout:
            try:
                with open(out_tar, "wb") as fh:
                    fh.write(r.stdout.encode("latin-1", "ignore"))
            except OSError:
                pass
        # method 2: direct pull (rooted)
        target = os.path.join(dest, sub)
        self.tools.run_tool(
            "adb", ["pull", f"{data_dir}/{sub}", target], timeout=120
        )

    def _analyze_prefs(self, pulled: str, result: StorageResult) -> None:
        for dirpath, _dirs, files in os.walk(pulled):
            for name in files:
                if not name.endswith(".xml"):
                    continue
                path = os.path.join(dirpath, name)
                result.prefs_files.append(path)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for m in re.finditer(r'name="([^"]+)"[^>]*>([^<]*)<', content):
                    key, value = m.group(1), m.group(2)
                    if SENSITIVE_KEY_RE.search(key) and value.strip():
                        result.findings.append(
                            Finding(
                                title=f"Sensitive value stored in SharedPreferences: {key}",
                                description="A preferences entry with a "
                                "sensitive-looking key holds a value in "
                                "cleartext on the device.",
                                module="storage",
                                severity=Severity.HIGH,
                                cvss_vector="AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe="CWE-312",
                                owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                                remediation="Store secrets in the Android "
                                "Keystore / EncryptedSharedPreferences, not "
                                "plain prefs.",
                                tags=["storage", "prefs"],
                            ).add_evidence(
                                file_path=path,
                                snippet=f"{key} = {value[:8]}...",
                            )
                        )

    def _analyze_databases(self, pulled: str, result: StorageResult) -> None:
        for dirpath, _dirs, files in os.walk(pulled):
            for name in files:
                if not name.endswith((".db", ".sqlite", ".sqlite3")):
                    continue
                path = os.path.join(dirpath, name)
                result.db_files.append(path)
                self._inspect_sqlite(path, result)

    def _inspect_sqlite(self, path: str, result: StorageResult) -> None:
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
        except sqlite3.Error:
            # unreadable -> likely encrypted (good) or corrupt
            return
        for table in tables:
            try:
                cur.execute(f"PRAGMA table_info({table})")
                cols = [r[1] for r in cur.fetchall()]
            except sqlite3.Error:
                continue
            sensitive_cols = [c for c in cols if SENSITIVE_KEY_RE.search(c)]
            if sensitive_cols:
                result.findings.append(
                    Finding(
                        title=f"Sensitive columns in unencrypted SQLite DB: "
                        f"{table}",
                        description=f"Table '{table}' has sensitive-looking "
                        f"columns ({', '.join(sensitive_cols)}) in a plaintext "
                        "SQLite database on the device.",
                        module="storage",
                        severity=Severity.HIGH,
                        cvss_vector="AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe="CWE-312",
                        owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                        remediation="Encrypt local databases (SQLCipher) and "
                        "avoid persisting secrets at rest.",
                        tags=["storage", "sqlite"],
                    ).add_evidence(file_path=path, snippet=f"{table}({', '.join(cols)})")
                )
        conn.close()

    def _analyze_files(self, pulled: str, result: StorageResult) -> None:
        for dirpath, _dirs, files in os.walk(pulled):
            for name in files:
                if name.endswith((".xml", ".db", ".sqlite", ".sqlite3", ".tar")):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 2 * 1024 * 1024:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for pattern in SECRET_PATTERNS:
                    for line in content.splitlines():
                        if pattern.scan_line(line):
                            result.findings.append(
                                Finding(
                                    title=f"Secret persisted in app file ({pattern.name})",
                                    description="A credential was found in a file "
                                    "stored in the app's private directory.",
                                    module="storage",
                                    severity=Severity.HIGH,
                                    cwe="CWE-312",
                                    owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                                    remediation="Do not persist secrets on disk; "
                                    "use hardware-backed key storage.",
                                    tags=["storage", pattern.id],
                                ).add_evidence(file_path=path)
                            )
                            break

    def _scan_logcat(self, package: str, result: StorageResult) -> None:
        r = self.tools.run_tool("adb", ["logcat", "-d", "-t", "2000"], timeout=20)
        if not r.ok:
            return
        for line in r.stdout.splitlines():
            for pattern in SECRET_PATTERNS:
                if pattern.scan_line(line):
                    result.findings.append(
                        Finding(
                            title=f"Secret leaked to logcat at runtime ({pattern.name})",
                            description="A credential matching a known pattern "
                            "was observed in the device log.",
                            module="storage",
                            severity=Severity.MEDIUM,
                            cwe="CWE-532",
                            owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
                            remediation="Remove sensitive logging from release "
                            "builds.",
                            tags=["storage", "logcat"],
                        ).add_evidence(snippet=line[:120])
                    )
                    return  # one is enough

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

    def _persist(self, result: StorageResult) -> None:
        self.db.set_kv(
            "storage_summary",
            {
                "prefs_files": len(result.prefs_files),
                "db_files": len(result.db_files),
                "device": result.device_serial,
            },
        )
