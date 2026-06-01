"""
APKOwl :: modules.privacy
=========================

Privacy and permission posture analysis.

The manifest phase records *which* permissions are declared. This phase goes
further and reasons about them:

* **Dangerous permission inventory** — classifies declared permissions into
  privacy-impacting groups (location, contacts, SMS, microphone, camera,
  storage, phone, calendar, body sensors) and reports the aggregate exposure.
* **Permission/SDK correlation** — when a privacy-sensitive permission is
  declared *and* a tracking/ads SDK is present, the combination is highlighted
  as a likely data-sharing pathway (e.g. fine location + an attribution SDK).
* **Over-privilege heuristics** — flags high-risk permissions that frequently
  indicate over-collection (READ_SMS, READ_CALL_LOG, QUERY_ALL_PACKAGES,
  ACCESS_BACKGROUND_LOCATION, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES).
* **Custom permission protection levels** — flags custom permissions defined
  with a "normal"/"dangerous" protection level (rather than "signature"), which
  lets other apps obtain them.

This module is purely static and derives everything from data already persisted
by earlier phases (permissions + components + sdks), so it is cheap and runs
even when no code is available to decompile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log


# permission -> (privacy group, human label)
PERMISSION_GROUPS: Dict[str, str] = {
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts",
    "android.permission.GET_ACCOUNTS": "contacts",
    "android.permission.READ_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.READ_CALL_LOG": "call_log",
    "android.permission.WRITE_CALL_LOG": "call_log",
    "android.permission.PROCESS_OUTGOING_CALLS": "call_log",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.CAMERA": "camera",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar",
    "android.permission.BODY_SENSORS": "sensors",
    "android.permission.ACTIVITY_RECOGNITION": "sensors",
    "android.permission.READ_EXTERNAL_STORAGE": "storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "storage",
    "android.permission.READ_PHONE_STATE": "phone",
    "android.permission.READ_PHONE_NUMBERS": "phone",
    "android.permission.CALL_PHONE": "phone",
    "android.permission.READ_MEDIA_IMAGES": "media",
    "android.permission.READ_MEDIA_VIDEO": "media",
    "android.permission.READ_MEDIA_AUDIO": "media",
}

# permissions whose mere presence is a notable over-privilege signal
HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

TRACKER_CATEGORIES = {"ads", "analytics", "attribution"}


@dataclass
class PrivacyResult:
    permission_groups: Dict[str, List[str]] = field(default_factory=dict)
    high_risk: List[str] = field(default_factory=list)
    tracker_sdks: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class PrivacyAnalyzer:
    def __init__(self, db: Database) -> None:
        self.db = db

    def run(
        self,
        permissions: List[str],
        custom_permissions: List[Dict[str, str]],
        sdks: Dict[str, str],
    ) -> PrivacyResult:
        result = PrivacyResult()
        self._classify(permissions, result)
        self._tracker_overlap(result, sdks)
        self._over_privilege(result)
        self._custom_permission_levels(custom_permissions, result)
        self._persist(result)
        log.good(f"privacy analysis produced {len(result.findings)} finding(s)")
        return result

    # -- classification ----------------------------------------------------
    def _classify(self, permissions: List[str], result: PrivacyResult) -> None:
        for perm in permissions:
            group = PERMISSION_GROUPS.get(perm)
            if group:
                result.permission_groups.setdefault(group, []).append(perm)
            if perm in HIGH_RISK_PERMISSIONS:
                result.high_risk.append(perm)
        if result.permission_groups:
            log.kv("privacy-sensitive groups",
                   ", ".join(sorted(result.permission_groups)))

        groups = sorted(result.permission_groups)
        if len(groups) >= 3:
            result.findings.append(
                Finding(
                    title=f"Broad privacy-sensitive permission footprint "
                    f"({len(groups)} groups)",
                    description="The app requests permissions spanning multiple "
                    "privacy-sensitive groups: " + ", ".join(groups) + ". A wide "
                    "footprint increases the impact of any compromise and the "
                    "burden of privacy disclosure.",
                    module="privacy",
                    severity=Severity.LOW,
                    cwe="CWE-250",
                    owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                    remediation="Apply least privilege: request only the "
                    "permissions actually used, and request at runtime with "
                    "clear justification.",
                    tags=["privacy", "permissions"],
                )
            )

    # -- tracker overlap ---------------------------------------------------
    def _tracker_overlap(self, result: PrivacyResult, sdks: Dict[str, str]) -> None:
        result.tracker_sdks = [n for n, c in sdks.items()
                               if c in TRACKER_CATEGORIES]
        if not result.tracker_sdks:
            return
        sensitive = sorted(result.permission_groups)
        if sensitive:
            result.findings.append(
                Finding(
                    title="Sensitive permissions combined with tracking SDKs",
                    description="The app declares privacy-sensitive permissions ("
                    + ", ".join(sensitive) + ") and bundles tracking/ad SDKs ("
                    + ", ".join(sorted(result.tracker_sdks)) + "). This is a "
                    "likely pathway for sensitive data to leave the device via "
                    "third parties.",
                    module="privacy",
                    severity=Severity.MEDIUM,
                    cwe="CWE-359",
                    owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                    remediation="Audit exactly what each SDK collects; ensure the "
                    "privacy policy discloses it; gate collection behind consent; "
                    "remove unused trackers.",
                    tags=["privacy", "tracking", "data-sharing"],
                )
            )

    # -- over-privilege ----------------------------------------------------
    def _over_privilege(self, result: PrivacyResult) -> None:
        for perm in result.high_risk:
            short = perm.rsplit(".", 1)[-1]
            sev = Severity.MEDIUM
            if perm in (
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            ):
                sev = Severity.HIGH
            result.findings.append(
                Finding(
                    title=f"High-risk permission declared: {short}",
                    description=f"The app declares {perm}, a permission commonly "
                    "associated with over-collection or abuse. Confirm it is "
                    "genuinely required and used.",
                    module="privacy",
                    severity=sev,
                    cwe="CWE-250",
                    owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                    remediation="Remove the permission if unused; otherwise "
                    "document the legitimate need and minimise its scope.",
                    tags=["privacy", "over-privilege"],
                ).add_evidence(file_path="AndroidManifest.xml", snippet=perm)
            )

    # -- custom permission protection levels ------------------------------
    def _custom_permission_levels(
        self, custom_permissions: List[Dict[str, str]], result: PrivacyResult
    ) -> None:
        for perm in custom_permissions or []:
            name = perm.get("name", "")
            level = (perm.get("protectionLevel") or perm.get("protection_level")
                     or "").lower()
            if level in ("", "normal", "dangerous"):
                result.findings.append(
                    Finding(
                        title=f"Custom permission with weak protection level: "
                        f"{name or '(unnamed)'}",
                        description="A custom permission is defined with a "
                        f"protection level of '{level or 'normal (default)'}'. "
                        "Any app can request a normal/dangerous custom permission, "
                        "so it provides little protection for the component it "
                        "guards.",
                        module="privacy",
                        severity=Severity.MEDIUM,
                        cwe="CWE-280",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Use protectionLevel=\"signature\" so only "
                        "apps signed with the same key can hold the permission.",
                        tags=["privacy", "custom-permission"],
                    ).add_evidence(file_path="AndroidManifest.xml", snippet=name)
                )

    # -- persistence -------------------------------------------------------
    def _persist(self, result: PrivacyResult) -> None:
        self.db.set_kv(
            "privacy_summary",
            {
                "groups": {g: len(p) for g, p in result.permission_groups.items()},
                "high_risk": result.high_risk,
                "tracker_sdks": result.tracker_sdks,
            },
        )
