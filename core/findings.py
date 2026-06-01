"""
APKOwl :: core.findings
========================

The central vulnerability/finding data model used by every analysis module.

A :class:`Finding` is the atomic unit of output for the entire tool. Every
module that discovers something interesting — a hardcoded secret, an exported
component, a weak cipher, an IDOR — produces one or more :class:`Finding`
objects and hands them to the orchestrator, which persists them to SQLite and
later renders them in the report.

The model carries everything a professional pentest report needs:

* a stable severity ladder (CRITICAL .. INFO)
* a CVSS v3.1 vector + computed base score
* a CWE identifier
* an OWASP Mobile Top 10 (2024) category mapping
* structured evidence (file, line, snippet)
* a remediation recommendation

Nothing here calls out to external tools; this module is pure data plumbing so
that it can be imported by anything without side effects.
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
class Severity(enum.IntEnum):
    """Ordered severity ladder.

    Implemented as ``IntEnum`` so findings sort naturally (highest first when
    reversed) and so the numeric value can be stored directly in SQLite.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        """Rich-compatible colour markup tag for terminal rendering."""
        return {
            Severity.INFO: "bright_blue",
            Severity.LOW: "cyan",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "orange3",
            Severity.CRITICAL: "bold red",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.INFO: "i",
            Severity.LOW: "-",
            Severity.MEDIUM: "!",
            Severity.HIGH: "!!",
            Severity.CRITICAL: "!!!",
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS base score onto our severity ladder (FIRST.org bands)."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        value = (value or "").strip().upper()
        for member in cls:
            if member.name == value:
                return member
        return cls.INFO


# ---------------------------------------------------------------------------
# OWASP Mobile Top 10 (2024)
# ---------------------------------------------------------------------------
class OWASPMobile(enum.Enum):
    """OWASP Mobile Top 10, 2024 edition."""

    M1_IMPROPER_CREDENTIAL_USAGE = ("M1", "Improper Credential Usage")
    M2_INADEQUATE_SUPPLY_CHAIN = ("M2", "Inadequate Supply Chain Security")
    M3_INSECURE_AUTH = ("M3", "Insecure Authentication/Authorization")
    M4_INSUFFICIENT_VALIDATION = ("M4", "Insufficient Input/Output Validation")
    M5_INSECURE_COMMUNICATION = ("M5", "Insecure Communication")
    M6_INADEQUATE_PRIVACY = ("M6", "Inadequate Privacy Controls")
    M7_INSUFFICIENT_BINARY_PROTECTION = ("M7", "Insufficient Binary Protections")
    M8_SECURITY_MISCONFIG = ("M8", "Security Misconfiguration")
    M9_INSECURE_DATA_STORAGE = ("M9", "Insecure Data Storage")
    M10_INSUFFICIENT_CRYPTO = ("M10", "Insufficient Cryptography")
    NONE = ("--", "Not categorized")

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def title(self) -> str:
        return self.value[1]

    def __str__(self) -> str:
        return f"{self.code}: {self.title}"


# ---------------------------------------------------------------------------
# CVSS v3.1 base score calculator
# ---------------------------------------------------------------------------
class CVSS31:
    """A self-contained CVSS v3.1 base-score calculator.

    We avoid pulling in a third-party CVSS library because the base-score math
    is well defined and small. A vector string like
    ``AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`` is parsed and scored exactly per the
    FIRST.org v3.1 specification.
    """

    # metric weightings ---------------------------------------------------
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _AC = {"L": 0.77, "H": 0.44}
    _UI = {"N": 0.85, "R": 0.62}
    _PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

    def __init__(self, vector: str) -> None:
        self.vector = vector.strip()
        self.metrics: Dict[str, str] = {}
        self._parse()

    def _parse(self) -> None:
        # vectors may optionally be prefixed with the CVSS version token
        body = self.vector
        if body.upper().startswith("CVSS:3"):
            parts = body.split("/", 1)
            body = parts[1] if len(parts) > 1 else ""
        for token in body.split("/"):
            if not token or ":" not in token:
                continue
            key, _, val = token.partition(":")
            self.metrics[key.strip().upper()] = val.strip().upper()

    @staticmethod
    def _roundup(value: float) -> float:
        """CVSS-specific round-up to one decimal place."""
        int_input = round(value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        return (int(int_input / 10000) + 1) / 10.0

    def base_score(self) -> float:
        try:
            av = self._AV[self.metrics.get("AV", "N")]
            ac = self._AC[self.metrics.get("AC", "L")]
            ui = self._UI[self.metrics.get("UI", "N")]
            scope_changed = self.metrics.get("S", "U") == "C"
            pr_table = self._PR_CHANGED if scope_changed else self._PR_UNCHANGED
            pr = pr_table[self.metrics.get("PR", "N")]
            c = self._CIA[self.metrics.get("C", "N")]
            i = self._CIA[self.metrics.get("I", "N")]
            a = self._CIA[self.metrics.get("A", "N")]
        except KeyError:
            # malformed vector -> conservative medium baseline
            return 5.0

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if scope_changed:
            raw = min(1.08 * (impact + exploitability), 10.0)
        else:
            raw = min(impact + exploitability, 10.0)

        return self._roundup(raw)

    def severity(self) -> Severity:
        return Severity.from_cvss(self.base_score())


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    """A concrete pointer to where a finding was observed."""

    file_path: str = ""
    line_number: int = 0
    snippet: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet[:2000],
            "extra": self.extra,
        }


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """A single security finding produced by an analysis module."""

    title: str
    description: str
    module: str
    severity: Severity = Severity.INFO
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    owasp: OWASPMobile = OWASPMobile.NONE
    remediation: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confidence: str = "firm"  # certain | firm | tentative
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        # If a CVSS vector was supplied but no score, compute it now and let
        # severity follow the score unless one was explicitly set above INFO.
        if self.cvss_vector and not self.cvss_score:
            calc = CVSS31(self.cvss_vector)
            self.cvss_score = calc.base_score()
            if self.severity == Severity.INFO:
                self.severity = calc.severity()
        # Coerce string severities (defensive — modules may pass strings).
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)
        if isinstance(self.owasp, str):
            self.owasp = self._owasp_from_code(self.owasp)

    @staticmethod
    def _owasp_from_code(code: str) -> OWASPMobile:
        code = code.strip().upper()
        for member in OWASPMobile:
            if member.code == code:
                return member
        return OWASPMobile.NONE

    # -- evidence helpers --------------------------------------------------
    def add_evidence(
        self,
        file_path: str = "",
        line_number: int = 0,
        snippet: str = "",
        **extra: Any,
    ) -> "Finding":
        self.evidence.append(
            Evidence(
                file_path=file_path,
                line_number=line_number,
                snippet=snippet,
                extra=dict(extra),
            )
        )
        return self

    # -- dedupe key --------------------------------------------------------
    def dedupe_key(self) -> str:
        """A stable hash used to avoid storing duplicate findings.

        Two findings that share the same title, module and primary evidence
        location are considered the same observation.
        """
        loc = ""
        if self.evidence:
            ev = self.evidence[0]
            loc = f"{ev.file_path}:{ev.line_number}"
        raw = f"{self.module}|{self.title}|{loc}".encode("utf-8", "ignore")
        return hashlib.sha256(raw).hexdigest()[:16]

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["owasp"] = str(self.owasp)
        d["owasp_code"] = self.owasp.code
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["dedupe_key"] = self.dedupe_key()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    # -- ordering ----------------------------------------------------------
    def sort_tuple(self) -> Tuple[int, float, str]:
        return (-int(self.severity), -self.cvss_score, self.title.lower())


# ---------------------------------------------------------------------------
# A small catalogue of reusable finding templates.
# ---------------------------------------------------------------------------
class FindingTemplates:
    """Factory helpers so modules emit consistent, well-formed findings.

    Each helper returns a fully populated :class:`Finding`; the calling module
    only needs to attach evidence. This keeps CWE/OWASP/remediation text
    centralised and consistent across the whole tool.
    """

    @staticmethod
    def hardcoded_secret(kind: str) -> Finding:
        return Finding(
            title=f"Hardcoded {kind} discovered in application package",
            description=(
                f"A {kind} was found embedded directly in the application's "
                "code or resources. Hardcoded credentials can be trivially "
                "extracted by anyone who decompiles the APK, leading to "
                "unauthorised access to the backing service."
            ),
            module="secrets",
            severity=Severity.HIGH,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe="CWE-798",
            owasp=OWASPMobile.M1_IMPROPER_CREDENTIAL_USAGE,
            remediation=(
                "Never ship secrets inside the application package. Move "
                "credentials server-side and exchange short-lived tokens at "
                "runtime. Rotate any key that has shipped in a binary."
            ),
            references=["https://cwe.mitre.org/data/definitions/798.html"],
            tags=["secret", kind.lower().replace(" ", "_")],
        )

    @staticmethod
    def exported_component(component_type: str, name: str) -> Finding:
        return Finding(
            title=f"Exported {component_type} without permission: {name}",
            description=(
                f"The {component_type} '{name}' is exported and reachable by "
                "any other application on the device without holding a "
                "protecting permission. Exported components form the app's "
                "external attack surface and may be abused for privilege "
                "escalation, data theft or denial of service."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            cwe="CWE-926",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation=(
                "Set android:exported=\"false\" unless the component must be "
                "public. If it must be exported, protect it with a "
                "signature-level permission and validate all incoming Intents."
            ),
            references=["https://cwe.mitre.org/data/definitions/926.html"],
            tags=["component", component_type.lower()],
        )

    @staticmethod
    def cleartext_traffic() -> Finding:
        return Finding(
            title="Cleartext (HTTP) network traffic permitted",
            description=(
                "The application permits unencrypted HTTP traffic. Data sent "
                "over cleartext can be intercepted or modified by a network "
                "attacker (e.g. on a shared Wi-Fi network)."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cwe="CWE-319",
            owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
            remediation=(
                "Disable cleartext traffic (android:usesCleartextTraffic="
                "\"false\") and enforce HTTPS everywhere via a strict "
                "network security configuration."
            ),
            references=["https://cwe.mitre.org/data/definitions/319.html"],
            tags=["network", "cleartext"],
        )

    @staticmethod
    def debuggable() -> Finding:
        return Finding(
            title="Application is debuggable in release build",
            description=(
                "The android:debuggable flag is enabled. This allows anyone "
                "with ADB access to attach a debugger, read memory and "
                "execute code in the application's context."
            ),
            module="manifest",
            severity=Severity.HIGH,
            cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cwe="CWE-489",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation="Remove android:debuggable or set it to false in release builds.",
            references=["https://cwe.mitre.org/data/definitions/489.html"],
            tags=["debuggable", "misconfig"],
        )

    @staticmethod
    def backup_allowed() -> Finding:
        return Finding(
            title="Application data backup is allowed",
            description=(
                "android:allowBackup is enabled, permitting extraction of the "
                "application's private data via 'adb backup' on devices where "
                "it is supported."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe="CWE-530",
            owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
            remediation="Set android:allowBackup=\"false\" for apps holding sensitive data.",
            references=["https://cwe.mitre.org/data/definitions/530.html"],
            tags=["backup", "misconfig"],
        )

    @staticmethod
    def weak_crypto(detail: str) -> Finding:
        return Finding(
            title=f"Weak or insecure cryptography: {detail}",
            description=(
                f"The application uses {detail}, which is considered weak or "
                "broken. Weak cryptography can allow attackers to recover "
                "plaintext or forge data."
            ),
            module="certs",
            severity=Severity.MEDIUM,
            cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe="CWE-327",
            owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
            remediation=(
                "Use modern, vetted algorithms (AES-GCM, SHA-256+, RSA-2048+ "
                "or ECDSA) and a cryptographically secure RNG (SecureRandom)."
            ),
            references=["https://cwe.mitre.org/data/definitions/327.html"],
            tags=["crypto"],
        )

    @staticmethod
    def ssl_pinning_absent() -> Finding:
        return Finding(
            title="No certificate/SSL pinning detected",
            description=(
                "No certificate or public-key pinning implementation was "
                "detected. Without pinning, a man-in-the-middle attacker who "
                "controls a trusted CA (or installs one) can intercept TLS."
            ),
            module="certs",
            severity=Severity.LOW,
            cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
            cwe="CWE-295",
            owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
            remediation="Implement certificate or public-key pinning for sensitive endpoints.",
            references=["https://cwe.mitre.org/data/definitions/295.html"],
            tags=["tls", "pinning"],
        )

    @staticmethod
    def idor(endpoint: str) -> Finding:
        return Finding(
            title=f"Possible IDOR / broken object-level authorization: {endpoint}",
            description=(
                "Substituting an object identifier in the request returned "
                "another principal's data, indicating broken object-level "
                "authorization."
            ),
            module="traffic",
            severity=Severity.HIGH,
            cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cwe="CWE-639",
            owasp=OWASPMobile.M3_INSECURE_AUTH,
            remediation="Enforce server-side authorization checks tied to the authenticated principal for every object access.",
            references=["https://cwe.mitre.org/data/definitions/639.html"],
            tags=["api", "idor", "authz"],
        )

    @staticmethod
    def insecure_native(func: str) -> Finding:
        return Finding(
            title=f"Use of dangerous native function: {func}",
            description=(
                f"The native library imports '{func}', a function commonly "
                "associated with memory-corruption vulnerabilities."
            ),
            module="native",
            severity=Severity.LOW,
            cvss_vector="AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            cwe="CWE-676",
            owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
            remediation="Replace unsafe C functions with bounded equivalents (strncpy, snprintf, fgets).",
            references=["https://cwe.mitre.org/data/definitions/676.html"],
            tags=["native", "memory-safety"],
        )

    @staticmethod
    def task_hijacking(launch_mode: str) -> Finding:
        return Finding(
            title="Activity vulnerable to task hijacking (StrandHogg)",
            description=(
                f"An activity uses launchMode='{launch_mode}' (or taskAffinity) "
                "in a way that allows a malicious app to insert itself into the "
                "task back stack and present spoofed UI over the legitimate app, "
                "enabling phishing and permission-prompt overlay attacks."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N",
            cwe="CWE-1021",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation="Set taskAffinity=\"\" on sensitive activities, avoid "
            "launchMode=singleTask/singleInstance where not required, and set "
            "android:taskReparenting=\"false\".",
            references=["https://cwe.mitre.org/data/definitions/1021.html"],
            tags=["manifest", "task-hijacking", "ui-redress"],
        )

    @staticmethod
    def pending_intent_mutable(component: str) -> Finding:
        return Finding(
            title=f"Mutable implicit PendingIntent: {component}",
            description=(
                "A PendingIntent is created mutable and/or implicit. A malicious "
                "app can intercept or modify it, potentially gaining the sending "
                "app's identity and permissions when the intent is delivered."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
            cwe="CWE-927",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation="Use FLAG_IMMUTABLE and set an explicit component on "
            "every PendingIntent unless mutability is strictly required.",
            references=["https://cwe.mitre.org/data/definitions/927.html"],
            tags=["pendingintent", "ipc"],
        )

    @staticmethod
    def janus_signature(scheme: str) -> Finding:
        return Finding(
            title=f"APK signed with {scheme} only (Janus exposure)",
            description=(
                f"The APK is signed using {scheme} only. v1 (JAR) signing is "
                "vulnerable to the Janus vulnerability (CVE-2017-13156) on "
                "older Android, allowing a crafted DEX to be prepended without "
                "invalidating the signature. Modern v2/v3 signing protects the "
                "whole archive."
            ),
            module="certs",
            severity=Severity.MEDIUM,
            cvss_vector="AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N",
            cwe="CWE-347",
            owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
            remediation="Sign with the APK Signature Scheme v2/v3 (and v4 for "
            "incremental) in addition to or instead of v1.",
            references=["https://cwe.mitre.org/data/definitions/347.html"],
            tags=["signing", "janus"],
        )

    @staticmethod
    def exported_service_no_permission(name: str) -> Finding:
        return Finding(
            title=f"Exported service without permission: {name}",
            description=(
                "An exported service is reachable by any app on the device and "
                "is not guarded by a permission. Depending on what it does, this "
                "can allow unauthorized actions or denial of service."
            ),
            module="manifest",
            severity=Severity.MEDIUM,
            cvss_vector="AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            cwe="CWE-926",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation="Set exported=\"false\" or guard the service with a "
            "signature-level permission.",
            references=["https://cwe.mitre.org/data/definitions/926.html"],
            tags=["service", "ipc"],
        )

    @staticmethod
    def tapjacking(name: str) -> Finding:
        return Finding(
            title=f"Activity may be vulnerable to tapjacking: {name}",
            description=(
                "A sensitive activity does not set filterTouchesWhenObscured or "
                "otherwise guard against overlay attacks. A malicious app drawing "
                "over it can trick the user into interacting with hidden UI."
            ),
            module="manifest",
            severity=Severity.LOW,
            cwe="CWE-1021",
            owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
            remediation="Set android:filterTouchesWhenObscured=\"true\" on views "
            "that perform sensitive actions.",
            references=["https://cwe.mitre.org/data/definitions/1021.html"],
            tags=["tapjacking", "ui-redress"],
        )

    @staticmethod
    def clipboard_leak() -> Finding:
        return Finding(
            title="Sensitive data copied to the system clipboard",
            description=(
                "The app writes sensitive data to the clipboard, which is "
                "readable by other apps (and, on older Android, monitorable in "
                "the background)."
            ),
            module="storage",
            severity=Severity.LOW,
            cwe="CWE-200",
            owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
            remediation="Avoid placing secrets on the clipboard; if unavoidable, "
            "mark the ClipData sensitive (EXTRA_IS_SENSITIVE) and clear it "
            "promptly.",
            references=["https://cwe.mitre.org/data/definitions/200.html"],
            tags=["clipboard", "leak"],
        )

    @staticmethod
    def screenshot_not_blocked() -> Finding:
        return Finding(
            title="Sensitive screens not protected from screenshots (FLAG_SECURE)",
            description=(
                "No FLAG_SECURE usage was detected. Screens displaying sensitive "
                "data may be captured in screenshots, the recent-apps thumbnail, "
                "or by screen recorders."
            ),
            module="storage",
            severity=Severity.INFO,
            cwe="CWE-200",
            owasp=OWASPMobile.M9_INSECURE_DATA_STORAGE,
            remediation="Apply WindowManager.LayoutParams.FLAG_SECURE on windows "
            "that display secrets.",
            references=["https://cwe.mitre.org/data/definitions/200.html"],
            tags=["screenshot", "flag-secure"],
        )


if __name__ == "__main__":
    # quick self-test of the CVSS engine
    samples = [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.3),
    ]
    for vec, expected in samples:
        got = CVSS31(vec).base_score()
        status = "OK" if abs(got - expected) < 0.2 else "MISMATCH"
        print(f"[{status}] {vec} -> {got} (expected ~{expected})")
