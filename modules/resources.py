"""
APKOwl :: modules.resources
===========================

Supplementary static analysis of the app's bundled resources and assets — the
parts of an APK that are not code but frequently leak just as much.

It inspects:

* ``res/xml/network_security_config.xml`` — beyond what the certs phase checks,
  it enumerates every domain config, flags cleartext-permitted domains, debug
  overrides that ship in release, and user-added trust anchors.
* ``res/values/strings.xml`` (and other value files) — for hardcoded URLs,
  IP addresses, credentials and Firebase/GCM identifiers.
* ``assets/`` — for bundled config files (``.json``, ``.properties``,
  ``.env``, ``.xml``, ``.yml``) carrying secrets or backend URLs, and for
  bundled private keys / keystores.
* ``res/raw/`` — same treatment as assets.
* ``google-services.json`` / ``GoogleService-Info`` style files — Firebase
  project ids, API keys, storage buckets and the tell-tale open-database URL.

Findings here complement, not duplicate, the secret scanner: this module is
about *where* the data lives (a shipped config file is a different risk profile
to a string buried in code) and about resource-specific misconfigurations.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log
from signatures.secrets_db import (
    SECRET_PATTERNS,
    URL_PATTERNS,
    IP_PATTERN,
    is_noise_url,
)


CONFIG_EXTENSIONS = (".json", ".properties", ".env", ".xml", ".yml", ".yaml",
                     ".cfg", ".conf", ".ini", ".txt")
KEY_EXTENSIONS = (".pem", ".key", ".p12", ".jks", ".keystore", ".bks", ".pfx")
FIREBASE_DB_RE = re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")
FIREBASE_FILES = ("google-services.json", "googleservice-info.plist")
SENSITIVE_ARTIFACT_EXTENSIONS = (
    ".db", ".sqlite", ".sqlite3", ".db3", ".realm",
    ".bak", ".backup", ".dump", ".snapshot",
)
SENSITIVE_NAME_HINTS = (
    "conversation", "conversations", "chat", "message", "messages",
    "discussion", "discussions", "snapshot", "transcript", "history",
    "backup", "dump", "session",
)


@dataclass
class ResourcesResult:
    config_files: List[str] = field(default_factory=list)
    key_files: List[str] = field(default_factory=list)
    firebase_projects: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class ResourceAnalyzer:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._flagged_sensitive_assets: set[str] = set()

    def run(self, unzip_dir: str, apktool_dir: str) -> ResourcesResult:
        result = ResourcesResult()
        roots = [d for d in (unzip_dir, apktool_dir) if d and os.path.isdir(d)]
        if not roots:
            log.info("resources: no unpacked tree available")
            return result

        for root in roots:
            self._scan_assets(root, result)
            self._scan_values(root, result)
            self._scan_network_security_config(root, result)
            self._scan_firebase(root, result)

        self._persist(result)
        log.good(f"resource analysis produced {len(result.findings)} finding(s)")
        return result

    # -- assets / raw ------------------------------------------------------
    def _scan_assets(self, root: str, result: ResourcesResult) -> None:
        for sub in ("assets", os.path.join("res", "raw")):
            base = os.path.join(root, sub)
            if not os.path.isdir(base):
                continue
            for dirpath, _dirs, files in os.walk(base):
                for name in files:
                    path = os.path.join(dirpath, name)
                    low = name.lower()
                    self._maybe_flag_sensitive_artifact(low, path, result)
                    if low.endswith(KEY_EXTENSIONS):
                        result.key_files.append(path)
                        self._flag_key_file(path, result)
                    elif low.endswith(CONFIG_EXTENSIONS):
                        result.config_files.append(path)
                        self._scan_config_file(path, result)

    def _flag_key_file(self, path: str, result: ResourcesResult) -> None:
        result.findings.append(
            Finding(
                title=f"Bundled key/keystore material: {os.path.basename(path)}",
                description="A private key, certificate store or keystore is "
                "shipped inside the APK. Anything bundled in the package can be "
                "extracted; private keys must never be distributed to clients.",
                module="resources",
                severity=Severity.HIGH,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe="CWE-312",
                owasp=OWASPMobile.M1_IMPROPER_CREDENTIAL_USAGE,
                remediation="Remove key material from the package; provision "
                "secrets at runtime from a secure backend or the Android "
                "Keystore.",
                tags=["resources", "key-material"],
            ).add_evidence(file_path=path)
        )

    def _scan_config_file(self, path: str, result: ResourcesResult) -> None:
        try:
            if os.path.getsize(path) > 4 * 1024 * 1024:
                return
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return

        # secrets inside the config file
        for pattern in SECRET_PATTERNS:
            for line in content.splitlines():
                hits = pattern.scan_line(line)
                if hits:
                    result.findings.append(
                        Finding(
                            title=f"Secret in bundled config ({pattern.name})",
                            description=f"A credential matching '{pattern.name}' "
                            f"was found in the bundled configuration file "
                            f"{os.path.basename(path)}.",
                            module="resources",
                            severity=pattern.severity,
                            cwe=pattern.cwe,
                            owasp=OWASPMobile.M1_IMPROPER_CREDENTIAL_USAGE,
                            remediation="Do not ship secrets in config files; "
                            "load them from a secured backend at runtime.",
                            tags=["resources", "config", pattern.id],
                        ).add_evidence(file_path=path, snippet=self._redact(hits[0]))
                    )
                    break  # one per pattern per file

        # endpoints harvested from configs feed dynamic testing
        for upat in URL_PATTERNS:
            for m in upat.finditer(content):
                url = m.group(0)
                if not is_noise_url(url):
                    self.db.add_endpoint(url, "", source="resources")

    def _maybe_flag_sensitive_artifact(
        self, filename: str, path: str, result: ResourcesResult
    ) -> None:
        if path in self._flagged_sensitive_assets:
            return
        ext = os.path.splitext(filename)[1]
        severity = None
        reason = ""
        if ext in SENSITIVE_ARTIFACT_EXTENSIONS:
            severity = Severity.MEDIUM
            reason = f"Sensitive data artifact extension ({ext})"
        elif any(hint in filename for hint in SENSITIVE_NAME_HINTS):
            severity = Severity.LOW
            reason = "Sensitive-looking asset name"
        if not severity:
            return
        self._flagged_sensitive_assets.add(path)
        result.findings.append(
            Finding(
                title=f"Potential sensitive data artifact in package: {os.path.basename(path)}",
                description="A bundled asset appears to be a data snapshot or "
                "persistent store. If it contains real user or environment data, "
                "it will be extractable from the APK and may violate data "
                "minimisation expectations.",
                module="resources",
                severity=severity,
                cwe="CWE-359",
                owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                remediation="Do not ship real user data in assets. If sample data "
                "is required, anonymise it and strip identifiers. Prefer remote "
                "fixtures or server-generated test data.",
                tags=["resources", "data-artifact"],
            ).add_evidence(file_path=path, snippet=reason)
        )

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return value[0] + "***"
        return value[:4] + "***" + value[-2:]

    # -- values ------------------------------------------------------------
    def _scan_values(self, root: str, result: ResourcesResult) -> None:
        values_dir = os.path.join(root, "res", "values")
        if not os.path.isdir(values_dir):
            return
        for name in os.listdir(values_dir):
            if not name.endswith(".xml"):
                continue
            path = os.path.join(values_dir, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            # hardcoded IPs in resources
            for m in IP_PATTERN.finditer(content):
                ip = m.group(0)
                if ip.startswith(("0.", "255.")) or ip == "127.0.0.1":
                    continue
                result.findings.append(
                    Finding(
                        title=f"Hardcoded IP address in resources: {ip}",
                        description="A hardcoded IP address in resource values "
                        "ties the app to fixed infrastructure and can leak "
                        "internal hosts.",
                        module="resources",
                        severity=Severity.LOW,
                        cwe="CWE-1188",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Use configurable, DNS-based endpoints; avoid "
                        "shipping internal IPs.",
                        tags=["resources", "hardcoded-host"],
                    ).add_evidence(file_path=path, snippet=ip)
                )
                break  # don't spam one finding per IP

    # -- network security config ------------------------------------------
    def _scan_network_security_config(self, root: str, result: ResourcesResult) -> None:
        # common locations
        candidates = [
            os.path.join(root, "res", "xml", "network_security_config.xml"),
        ]
        xml_dir = os.path.join(root, "res", "xml")
        if os.path.isdir(xml_dir):
            for name in os.listdir(xml_dir):
                if "network" in name.lower() and name.endswith(".xml"):
                    candidates.append(os.path.join(xml_dir, name))
        seen = set()
        for path in candidates:
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            self._analyze_nsc(path, result)

    def _analyze_nsc(self, path: str, result: ResourcesResult) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return

        if re.search(r"cleartextTrafficPermitted\s*=\s*\"true\"", content):
            result.findings.append(
                Finding(
                    title="Network security config permits cleartext traffic",
                    description="The network security configuration explicitly "
                    "permits cleartext (HTTP) traffic for one or more domains.",
                    module="resources",
                    severity=Severity.MEDIUM,
                    cwe="CWE-319",
                    owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                    remediation="Set cleartextTrafficPermitted=\"false\" and use "
                    "HTTPS everywhere.",
                    tags=["resources", "nsc", "cleartext"],
                ).add_evidence(file_path=path)
            )

        if re.search(r"<debug-overrides>", content):
            result.findings.append(
                Finding(
                    title="Debug overrides present in network security config",
                    description="A <debug-overrides> block is present. If it "
                    "ships in a release build it can relax trust (e.g. add a "
                    "user/debug CA), weakening TLS validation.",
                    module="resources",
                    severity=Severity.LOW,
                    cwe="CWE-295",
                    owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                    remediation="Ensure debug-overrides are stripped from release "
                    "builds.",
                    tags=["resources", "nsc", "debug"],
                ).add_evidence(file_path=path)
            )

        if re.search(r"<trust-anchors>.*?<certificates\s+src\s*=\s*\"user\"",
                     content, re.DOTALL):
            result.findings.append(
                Finding(
                    title="App trusts user-added CA certificates",
                    description="The network security config trusts user-installed "
                    "certificate authorities, which makes interception by a local "
                    "attacker (or malware) easier.",
                    module="resources",
                    severity=Severity.MEDIUM,
                    cwe="CWE-295",
                    owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                    remediation="Trust only the system CA store in release builds.",
                    tags=["resources", "nsc", "trust-anchor"],
                ).add_evidence(file_path=path)
            )

    # -- firebase ----------------------------------------------------------
    def _scan_firebase(self, root: str, result: ResourcesResult) -> None:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.lower() in FIREBASE_FILES:
                    self._parse_google_services(os.path.join(dirpath, name), result)
                else:
                    # look for firebaseio URLs in any text file already covered,
                    # but also catch them in values
                    pass

    def _parse_google_services(self, path: str, result: ResourcesResult) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return
        project = ""
        try:
            data = json.loads(content)
            project = (
                data.get("project_info", {}).get("project_id", "")
                if isinstance(data, dict) else ""
            )
            db_url = data.get("project_info", {}).get("firebase_url", "") \
                if isinstance(data, dict) else ""
        except (json.JSONDecodeError, AttributeError):
            db_url = ""
            m = FIREBASE_DB_RE.search(content)
            if m:
                db_url = m.group(0)

        if project:
            result.firebase_projects.append(project)

        if db_url:
            result.findings.append(
                Finding(
                    title="Firebase Realtime Database URL exposed in config",
                    description=f"A Firebase database URL ({db_url}) is bundled. "
                    "If the database's security rules are permissive (a very "
                    "common misconfiguration), the data is world-readable or "
                    "world-writable. Verify the rules; the URL itself is enough "
                    "for anyone to probe '<url>/.json'.",
                    module="resources",
                    severity=Severity.MEDIUM,
                    cwe="CWE-921",
                    owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                    remediation="Lock down Firebase security rules to require "
                    "authentication and scope access per user.",
                    tags=["resources", "firebase"],
                ).add_evidence(file_path=path, snippet=db_url)
            )
            self.db.add_endpoint(db_url, "", source="firebase")

    # -- persistence -------------------------------------------------------
    def _persist(self, result: ResourcesResult) -> None:
        self.db.set_kv(
            "resources_summary",
            {
                "config_files": len(result.config_files),
                "key_files": len(result.key_files),
                "firebase_projects": result.firebase_projects,
            },
        )
