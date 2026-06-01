"""
APKOwl :: modules.secrets
=========================

Phase 3 — hunt for hardcoded secrets, credentials and the app's network
surface across the entire decompiled tree.

What it scans:
  * Java sources (jadx output)
  * smali (apktool output)
  * resources: strings.xml, arrays.xml, BuildConfig, *.properties, *.json,
    *.yaml/*.yml, *.xml, *.txt, AndroidManifest.xml
  * assets/ and raw/ of any text-ish type
  * google-services.json (Firebase) with config-specific checks

How it scans:
  * every :class:`SecretPattern` from the signature DB,
  * a generic high-entropy string sweep (catches bespoke tokens the named
    patterns miss),
  * URL / endpoint harvesting (feeds the dynamic phases),
  * IP-address harvesting.

Performance: files are streamed line-by-line; binary files are skipped by a
null-byte sniff; very large files are capped. Findings are de-duplicated by the
DB layer so the same key found in smali + Java only reports once per location.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from signatures.secrets_db import (
    SECRET_PATTERNS,
    URL_PATTERNS,
    IP_PATTERN,
    SecretPattern,
    shannon_entropy,
    is_noise_url,
    looks_base64,
)


TEXT_EXTENSIONS = {
    ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".txt",
    ".yaml", ".yml", ".js", ".html", ".gradle", ".cfg", ".conf", ".ini",
    ".pem", ".key", ".csv", ".md", ".sql", ".graphql", ".env", "",
}

# files / dirs that are pure noise and waste time
SKIP_DIR_NAMES = {".git", "node_modules", "META-INF"}
MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MB cap per file
ENTROPY_MIN_LEN = 24
ENTROPY_MIN_BITS = 4.5


@dataclass
class SecretsResult:
    findings: List[Finding] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    ip_addresses: Set[str] = field(default_factory=set)
    files_scanned: int = 0
    bytes_scanned: int = 0
    secrets_count: int = 0


class SecretScanner:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.patterns: List[SecretPattern] = SECRET_PATTERNS
        self._seen_secret_values: Set[str] = set()

    def run(self, roots: List[str]) -> SecretsResult:
        result = SecretsResult()
        scan_files = list(self._gather_files(roots))
        log.kv("files to scan", len(scan_files))

        with log.progress() as prog:
            task = prog.add_task("scanning for secrets", total=len(scan_files))
            for path in scan_files:
                self._scan_file(path, result)
                prog.advance(task, 1)

        # special-case structured config files
        self._scan_google_services(roots, result)

        self._persist(result)
        log.good(
            f"secrets scan: {result.secrets_count} secret finding(s), "
            f"{len(result.endpoints)} endpoint(s), "
            f"{len(result.ip_addresses)} IP(s)"
        )
        return result

    # -- file gathering ----------------------------------------------------
    def _gather_files(self, roots: List[str]) -> Iterable[str]:
        seen: Set[str] = set()
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
                for name in files:
                    ext = os.path.splitext(name)[1].lower()
                    if ext not in TEXT_EXTENSIONS:
                        continue
                    full = os.path.join(dirpath, name)
                    real = os.path.realpath(full)
                    if real in seen:
                        continue
                    seen.add(real)
                    yield full

    # -- per-file scanning -------------------------------------------------
    def _scan_file(self, path: str, result: SecretsResult) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size > MAX_FILE_BYTES:
            return
        try:
            with open(path, "rb") as fh:
                head = fh.read(2048)
                if b"\x00" in head:  # crude binary sniff
                    return
        except OSError:
            return

        result.files_scanned += 1
        result.bytes_scanned += size
        rel = path

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    if len(line) > 4000:
                        line = line[:4000]
                    self._scan_line(line, lineno, rel, result)
        except OSError:
            return

    def _scan_line(
        self, line: str, lineno: int, path: str, result: SecretsResult
    ) -> None:
        # 1. named patterns
        for pattern in self.patterns:
            hits = pattern.scan_line(line)
            for value in hits:
                if value in self._seen_secret_values and pattern.id != "private_key_pem":
                    continue
                self._seen_secret_values.add(value)
                self._emit_secret(pattern, value, line, lineno, path, result)

        # 2. endpoint harvesting
        for upat in URL_PATTERNS:
            for m in upat.finditer(line):
                url = m.group(0).rstrip('",;)\'')
                if not is_noise_url(url):
                    result.endpoints.add(url)

        # 3. IP harvesting
        for m in IP_PATTERN.finditer(line):
            ip = m.group(0)
            if not ip.startswith(("0.", "255.")) and ip not in ("127.0.0.1",):
                result.ip_addresses.add(ip)

        # 4. generic high-entropy sweep (only on assignment-looking lines)
        if "=" in line or ":" in line:
            self._entropy_sweep(line, lineno, path, result)

    def _entropy_sweep(
        self, line: str, lineno: int, path: str, result: SecretsResult
    ) -> None:
        for token in re.findall(r"['\"]([A-Za-z0-9_\-+/=]{24,})['\"]", line):
            if token in self._seen_secret_values:
                continue
            ent = shannon_entropy(token)
            if ent < ENTROPY_MIN_BITS or len(token) < ENTROPY_MIN_LEN:
                continue
            # skip things that are clearly not secrets
            low = token.lower()
            if low.endswith((".png", ".jpg", ".so", ".xml", ".json")):
                continue
            if token.count("/") > 4:  # looks like a path
                continue
            self._seen_secret_values.add(token)
            f = Finding(
                title="High-entropy string (possible secret)",
                description=(
                    "A high-entropy string was found in an assignment. It may "
                    "be an API key, token, or encryption key. Verify manually."
                ),
                module="secrets",
                severity=Severity.LOW,
                cwe="CWE-798",
                owasp=OWASPMobile.M1_IMPROPER_CREDENTIAL_USAGE,
                remediation="If this is a credential, remove it from the package "
                "and rotate it.",
                confidence="tentative",
                tags=["entropy"],
            )
            f.add_evidence(
                file_path=path,
                line_number=lineno,
                snippet=self._redact(token, line),
                entropy=round(ent, 2),
            )
            result.findings.append(f)
            result.secrets_count += 1

    def _emit_secret(
        self,
        pattern: SecretPattern,
        value: str,
        line: str,
        lineno: int,
        path: str,
        result: SecretsResult,
    ) -> None:
        f = FindingTemplates.hardcoded_secret(pattern.name)
        f.severity = pattern.severity
        f.cwe = pattern.cwe
        f.confidence = pattern.confidence
        f.tags = list(set(f.tags + [pattern.id]))
        f.add_evidence(
            file_path=path,
            line_number=lineno,
            snippet=self._redact(value, line),
            pattern=pattern.id,
        )
        result.findings.append(f)
        result.secrets_count += 1
        log.finding(f)

    @staticmethod
    def _redact(secret: str, line: str) -> str:
        """Show the line but mask the middle of the secret value."""
        if len(secret) <= 8:
            masked = secret[0] + "***"
        else:
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        return line.strip().replace(secret, masked)[:300]

    # -- structured config -------------------------------------------------
    def _scan_google_services(self, roots: List[str], result: SecretsResult) -> None:
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name == "google-services.json":
                        self._analyze_google_services(
                            os.path.join(dirpath, name), result
                        )

    def _analyze_google_services(self, path: str, result: SecretsResult) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return
        log.info(f"analysing {os.path.basename(path)}")
        # API keys
        try:
            for client in data.get("client", []):
                for key in client.get("api_key", []):
                    apikey = key.get("current_key", "")
                    if apikey:
                        f = FindingTemplates.hardcoded_secret("Firebase/GCP API key")
                        f.severity = Severity.MEDIUM
                        f.description += (
                            " Note: Firebase API keys are not strictly secret, "
                            "but combined with permissive Firebase rules they "
                            "can enable data access. Verify Firestore/RTDB rules."
                        )
                        f.add_evidence(
                            file_path=path,
                            snippet=f"current_key: {apikey[:8]}...",
                        )
                        result.findings.append(f)
                        result.secrets_count += 1
            project = data.get("project_info", {})
            db_url = project.get("firebase_url", "")
            if db_url:
                result.endpoints.add(db_url)
                result.findings.append(
                    Finding(
                        title="Firebase Realtime Database URL exposed",
                        description=f"Firebase RTDB endpoint '{db_url}' is "
                        "configured. Test for world-readable/writable rules.",
                        module="secrets",
                        severity=Severity.LOW,
                        cwe="CWE-285",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Audit Firebase security rules; deny by default.",
                        tags=["firebase"],
                    ).add_evidence(file_path=path, snippet=db_url)
                )
        except (AttributeError, TypeError):
            pass

    # -- persistence -------------------------------------------------------
    def _persist(self, result: SecretsResult) -> None:
        for url in sorted(result.endpoints):
            method = ""
            self.db.add_endpoint(url, method, source="static")
        self.db.set_kv("ip_addresses", sorted(result.ip_addresses))
        self.db.set_kv(
            "secrets_stats",
            {
                "files_scanned": result.files_scanned,
                "bytes_scanned": result.bytes_scanned,
                "secrets": result.secrets_count,
                "endpoints": len(result.endpoints),
            },
        )
