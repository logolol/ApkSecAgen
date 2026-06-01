"""
APKOwl :: modules.manifest
==========================

Phase 2 — analyse ``AndroidManifest.xml``.

This module produces the structured picture of the application's components and
configuration that several later phases (intents, storage, patcher) rely on. It
prefers apktool's decoded manifest but transparently falls back to the in-house
AXML parser so it works even with a minimal toolchain.

It enumerates and risk-rates:

* package, version, SDK levels
* application-level flags: debuggable, allowBackup, usesCleartextTraffic,
  networkSecurityConfig, testOnly
* activities, services, receivers, providers — and which are *exported*
* exported components lacking a protecting permission (external attack surface)
* deep-link intent filters (scheme/host/path) for later fuzzing
* custom permissions and their protectionLevel
* content providers with grantUriPermissions
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from modules.axml import parse_axml_file


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass
class Component:
    type: str  # activity | service | receiver | provider
    name: str
    exported: Optional[bool] = None
    permission: str = ""
    enabled: bool = True
    intent_actions: List[str] = field(default_factory=list)
    deeplinks: List[Dict[str, str]] = field(default_factory=list)
    authorities: str = ""
    grant_uri: bool = False
    raw_attrs: Dict[str, str] = field(default_factory=dict)

    @property
    def effectively_exported(self) -> bool:
        if self.exported is True:
            return True
        if self.exported is None:
            # Components with intent-filters default to exported (pre-S behaviour)
            return bool(self.intent_actions or self.deeplinks)
        return False


@dataclass
class ManifestResult:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    cleartext: Optional[bool] = None
    network_security_config: str = ""
    test_only: bool = False
    permissions_used: List[str] = field(default_factory=list)
    custom_permissions: List[Dict[str, str]] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    deeplinks: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    xml_text: str = ""

    def by_type(self, t: str) -> List[Component]:
        return [c for c in self.components if c.type == t]

    @property
    def exported_components(self) -> List[Component]:
        return [c for c in self.components if c.effectively_exported]


# permissions considered dangerous / privacy sensitive
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
}


class ManifestAnalyzer:
    def __init__(self, db: Database) -> None:
        self.db = db

    def run(self, decoded_manifest: str, binary_manifest: str) -> ManifestResult:
        result = ManifestResult()
        xml_text = self._load_xml(decoded_manifest, binary_manifest)
        if not xml_text:
            log.error("could not obtain manifest XML")
            return result
        result.xml_text = xml_text

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            log.error(f"manifest parse error: {exc}")
            return result

        self._parse_root(root, result)
        self._parse_application(root, result)
        self._parse_permissions(root, result)
        self._evaluate(result)
        self._persist(result)
        return result

    # -- loading -----------------------------------------------------------
    def _load_xml(self, decoded: str, binary: str) -> str:
        if decoded and os.path.isfile(decoded):
            try:
                with open(decoded, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                if "<manifest" in text:
                    log.debug("manifest loaded from apktool output")
                    return text
            except OSError:
                pass
        if binary and os.path.isfile(binary):
            log.debug("manifest decoded via in-house AXML parser")
            xml = parse_axml_file(binary)
            if xml:
                return xml
        return ""

    # -- parsing -----------------------------------------------------------
    def _attr(self, el: ET.Element, name: str, default: str = "") -> str:
        return el.get(f"{ANDROID_NS}{name}", el.get(name, default))

    def _parse_root(self, root: ET.Element, result: ManifestResult) -> None:
        result.package = root.get("package", "")
        result.version_name = self._attr(root, "versionName")
        result.version_code = self._attr(root, "versionCode")
        for el in root.iter("uses-sdk"):
            result.min_sdk = self._attr(el, "minSdkVersion") or result.min_sdk
            result.target_sdk = self._attr(el, "targetSdkVersion") or result.target_sdk
            result.max_sdk = self._attr(el, "maxSdkVersion") or result.max_sdk
        log.kv("package", result.package or "(unknown)")
        log.kv("version", f"{result.version_name} ({result.version_code})")
        log.kv("SDK", f"min={result.min_sdk} target={result.target_sdk}")

    def _bool(self, value: str, default: Optional[bool] = None) -> Optional[bool]:
        if value == "":
            return default
        return value.strip().lower() == "true"

    def _parse_application(self, root: ET.Element, result: ManifestResult) -> None:
        app = root.find("application")
        if app is None:
            return
        result.debuggable = self._bool(self._attr(app, "debuggable"), False) or False
        result.allow_backup = self._bool(self._attr(app, "allowBackup"), True)
        result.cleartext = self._bool(self._attr(app, "usesCleartextTraffic"), None)
        result.network_security_config = self._attr(app, "networkSecurityConfig")
        result.test_only = self._bool(self._attr(app, "testOnly"), False) or False

        for tag, ctype in (
            ("activity", "activity"),
            ("activity-alias", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider"),
        ):
            for el in app.iter(tag):
                comp = self._parse_component(el, ctype)
                result.components.append(comp)
                for dl in comp.deeplinks:
                    result.deeplinks.append({**dl, "component": comp.name})

        counts = {
            "activity": len(result.by_type("activity")),
            "service": len(result.by_type("service")),
            "receiver": len(result.by_type("receiver")),
            "provider": len(result.by_type("provider")),
        }
        log.kv("components", ", ".join(f"{k}={v}" for k, v in counts.items()))
        log.kv("exported", len(result.exported_components))

    def _parse_component(self, el: ET.Element, ctype: str) -> Component:
        comp = Component(
            type=ctype,
            name=self._attr(el, "name"),
            exported=self._bool(self._attr(el, "exported"), None),
            permission=self._attr(el, "permission"),
            enabled=self._bool(self._attr(el, "enabled"), True),
            authorities=self._attr(el, "authorities"),
            grant_uri=self._bool(self._attr(el, "grantUriPermissions"), False) or False,
        )
        for intent in el.iter("intent-filter"):
            for action in intent.iter("action"):
                an = self._attr(action, "name")
                if an:
                    comp.intent_actions.append(an)
            for data in intent.iter("data"):
                dl = {
                    "scheme": self._attr(data, "scheme"),
                    "host": self._attr(data, "host"),
                    "port": self._attr(data, "port"),
                    "path": self._attr(data, "path"),
                    "pathPrefix": self._attr(data, "pathPrefix"),
                    "pathPattern": self._attr(data, "pathPattern"),
                    "mimeType": self._attr(data, "mimeType"),
                }
                if any(dl.values()):
                    comp.deeplinks.append(dl)
        return comp

    def _parse_permissions(self, root: ET.Element, result: ManifestResult) -> None:
        for el in root.iter("uses-permission"):
            name = self._attr(el, "name")
            if name:
                result.permissions_used.append(name)
        for el in root.iter("permission"):
            result.custom_permissions.append(
                {
                    "name": self._attr(el, "name"),
                    "protectionLevel": self._attr(el, "protectionLevel") or "normal",
                }
            )

    # -- evaluation --------------------------------------------------------
    def _evaluate(self, result: ManifestResult) -> None:
        if result.debuggable:
            result.findings.append(FindingTemplates.debuggable())
        if result.allow_backup:
            result.findings.append(FindingTemplates.backup_allowed())
        if result.cleartext is True:
            result.findings.append(FindingTemplates.cleartext_traffic())
        if result.test_only:
            result.findings.append(
                Finding(
                    title="Application marked testOnly",
                    description="android:testOnly is set; such builds are not "
                    "meant for production and relax certain protections.",
                    module="manifest",
                    severity=Severity.LOW,
                    cwe="CWE-489",
                    owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                    remediation="Remove android:testOnly from release builds.",
                    tags=["misconfig"],
                )
            )

        # exported components without protection
        for comp in result.exported_components:
            if comp.permission:
                continue
            # launcher activities are intentionally exported -> info only
            is_launcher = "android.intent.action.MAIN" in comp.intent_actions
            f = FindingTemplates.exported_component(comp.type, comp.name)
            f.add_evidence(file_path="AndroidManifest.xml",
                           snippet=f"<{comp.type} android:name=\"{comp.name}\" "
                                   f"android:exported=\"true\"/>")
            if is_launcher:
                f.severity = Severity.INFO
                f.title = f"Exported launcher {comp.type}: {comp.name}"
                f.description = ("This is the app's launcher entry point; being "
                                 "exported is expected. Listed for completeness.")
            if comp.type == "provider":
                f.severity = Severity.HIGH
                f.description += (" Exported content providers are especially "
                                  "risky and may leak or accept arbitrary data.")
            result.findings.append(f)

        # task hijacking: activities with risky launchMode / taskAffinity
        for comp in result.by_type("activity"):
            lm = (comp.raw_attrs.get("launchMode") or "").lower()
            affinity = comp.raw_attrs.get("taskAffinity")
            if lm in ("singletask", "singleinstance") or affinity:
                result.findings.append(
                    FindingTemplates.task_hijacking(lm or "taskAffinity set")
                    .add_evidence(file_path="AndroidManifest.xml",
                                  snippet=comp.name)
                )

        # exported services without a guarding permission
        for comp in result.by_type("service"):
            if comp.effectively_exported and not comp.permission:
                result.findings.append(
                    FindingTemplates.exported_service_no_permission(comp.name)
                    .add_evidence(file_path="AndroidManifest.xml",
                                  snippet=comp.name)
                )

        for comp in result.by_type("provider"):
            if comp.grant_uri and comp.effectively_exported:
                result.findings.append(
                    Finding(
                        title=f"Provider grants URI permissions: {comp.name}",
                        description="The exported provider sets "
                        "grantUriPermissions, which can be abused to access "
                        "files outside the intended scope if path handling is weak.",
                        module="manifest",
                        severity=Severity.MEDIUM,
                        cwe="CWE-926",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Constrain grant-uri-permission paths and "
                        "validate all incoming URIs.",
                        tags=["provider"],
                    ).add_evidence(file_path="AndroidManifest.xml",
                                   snippet=comp.authorities)
                )

        # weak custom permissions
        for perm in result.custom_permissions:
            level = perm["protectionLevel"].lower()
            if level in ("normal", "dangerous", ""):
                result.findings.append(
                    Finding(
                        title=f"Custom permission with weak protection level: "
                        f"{perm['name']}",
                        description=f"The custom permission uses protectionLevel="
                        f"'{perm['protectionLevel'] or 'normal'}'. Any app can "
                        "request normal/dangerous permissions; use 'signature' "
                        "to restrict to your own apps.",
                        module="manifest",
                        severity=Severity.MEDIUM,
                        cwe="CWE-280",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Use protectionLevel=\"signature\" for "
                        "inter-app permissions you control.",
                        tags=["permission"],
                    )
                )

        # dangerous permissions summary (info)
        dangerous = [p for p in result.permissions_used if p in DANGEROUS_PERMISSIONS]
        if dangerous:
            f = Finding(
                title=f"Application requests {len(dangerous)} dangerous permission(s)",
                description="The app requests permissions that grant access to "
                "sensitive user data or device capabilities. Verify each is "
                "actually required.",
                module="manifest",
                severity=Severity.INFO,
                cwe="CWE-250",
                owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                remediation="Apply least privilege; drop unused permissions.",
                tags=["permissions", "privacy"],
            )
            for p in dangerous:
                f.add_evidence(file_path="AndroidManifest.xml", snippet=p)
            result.findings.append(f)

        # cleartext via networkSecurityConfig handled in certs module
        log.good(f"manifest analysis produced {len(result.findings)} finding(s)")

    # -- persistence -------------------------------------------------------
    def _persist(self, result: ManifestResult) -> None:
        self.db.update_scan_meta(
            package_name=result.package,
            version_name=result.version_name,
            version_code=result.version_code,
            meta={
                "min_sdk": result.min_sdk,
                "target_sdk": result.target_sdk,
                "debuggable": result.debuggable,
                "allow_backup": result.allow_backup,
            },
        )
        self.db.set_kv("permissions", result.permissions_used)
        self.db.set_kv(
            "components",
            [
                {
                    "type": c.type,
                    "name": c.name,
                    "exported": c.effectively_exported,
                    "permission": c.permission,
                    "actions": c.intent_actions,
                }
                for c in result.components
            ],
        )
        self.db.set_kv("deeplinks", result.deeplinks)
