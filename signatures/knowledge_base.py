"""
APKOwl :: signatures.knowledge_base
===================================

A standards knowledge base that maps findings to the wider security-standards
ecosystem: the OWASP MASVS (Mobile Application Security Verification Standard),
the OWASP MASTG test ids, CWE descriptions and NIST references.

Most pentest tools stop at "here is a finding". A professional report links each
finding to the control it violates so an engineering team can (a) understand the
*category* of weakness, (b) find the relevant verification requirement, and
(c) track remediation against a recognised standard. This module supplies that
mapping in pure data form — no network, no dependencies.

The data here is deliberately self-contained and conservative; it reflects the
public MASVS v2 control groups and a curated subset of CWE entries that are
relevant to mobile applications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# MASVS v2 control groups
# ---------------------------------------------------------------------------
@dataclass
class MASVSControl:
    id: str
    group: str
    title: str
    description: str


MASVS_CONTROLS: Dict[str, MASVSControl] = {
    "MASVS-STORAGE-1": MASVSControl(
        id="MASVS-STORAGE-1",
        group="STORAGE",
        title="Secure storage of sensitive data",
        description="The app securely stores sensitive data and does not place "
        "it in locations that are world-readable or backed up insecurely.",
    ),
    "MASVS-STORAGE-2": MASVSControl(
        id="MASVS-STORAGE-2",
        group="STORAGE",
        title="No sensitive data leaks",
        description="The app prevents leakage of sensitive data through logs, "
        "the clipboard, IPC, the keyboard cache, screenshots and backups.",
    ),
    "MASVS-CRYPTO-1": MASVSControl(
        id="MASVS-CRYPTO-1",
        group="CRYPTO",
        title="Strong cryptography",
        description="The app employs current, strong cryptographic primitives "
        "and uses them according to industry best practice.",
    ),
    "MASVS-CRYPTO-2": MASVSControl(
        id="MASVS-CRYPTO-2",
        group="CRYPTO",
        title="Secure key management",
        description="The app performs key management (generation, storage, "
        "rotation) using secure, hardware-backed facilities where possible.",
    ),
    "MASVS-AUTH-1": MASVSControl(
        id="MASVS-AUTH-1",
        group="AUTH",
        title="Secure authentication and authorization",
        description="The app enforces authentication and authorization on the "
        "remote endpoints it consumes and does not trust the client.",
    ),
    "MASVS-AUTH-2": MASVSControl(
        id="MASVS-AUTH-2",
        group="AUTH",
        title="Stateful session management",
        description="The app manages sessions securely and invalidates them on "
        "the server when appropriate.",
    ),
    "MASVS-NETWORK-1": MASVSControl(
        id="MASVS-NETWORK-1",
        group="NETWORK",
        title="Secure network communication",
        description="The app secures all network traffic with TLS and validates "
        "the server certificate chain.",
    ),
    "MASVS-NETWORK-2": MASVSControl(
        id="MASVS-NETWORK-2",
        group="NETWORK",
        title="TLS configuration and pinning",
        description="The app uses an appropriate TLS configuration and, where "
        "warranted, pins the expected server identity.",
    ),
    "MASVS-PLATFORM-1": MASVSControl(
        id="MASVS-PLATFORM-1",
        group="PLATFORM",
        title="Secure IPC",
        description="The app exposes IPC mechanisms (activities, services, "
        "receivers, providers, deep links) safely and validates all input.",
    ),
    "MASVS-PLATFORM-2": MASVSControl(
        id="MASVS-PLATFORM-2",
        group="PLATFORM",
        title="Safe WebView and platform usage",
        description="The app uses WebViews and platform APIs securely, without "
        "enabling dangerous features or exposing native bridges.",
    ),
    "MASVS-PLATFORM-3": MASVSControl(
        id="MASVS-PLATFORM-3",
        group="PLATFORM",
        title="Safe handling of external sources",
        description="The app validates and sanitises data received from external "
        "sources and the user interface.",
    ),
    "MASVS-CODE-1": MASVSControl(
        id="MASVS-CODE-1",
        group="CODE",
        title="Up-to-date and securely configured",
        description="The app is built with current dependencies and secure "
        "compiler/build configuration (debuggable off, no test code).",
    ),
    "MASVS-CODE-2": MASVSControl(
        id="MASVS-CODE-2",
        group="CODE",
        title="No known-vulnerable components",
        description="The app does not bundle components with known "
        "vulnerabilities and validates the integrity of loaded code.",
    ),
    "MASVS-CODE-3": MASVSControl(
        id="MASVS-CODE-3",
        group="CODE",
        title="Hardened binaries",
        description="Native binaries are compiled with modern exploit "
        "mitigations (PIE, stack canaries, RELRO, NX, FORTIFY).",
    ),
    "MASVS-CODE-4": MASVSControl(
        id="MASVS-CODE-4",
        group="CODE",
        title="No debugging symbols / artefacts",
        description="Release builds contain no debugging artefacts, verbose "
        "logging or developer backdoors.",
    ),
    "MASVS-RESILIENCE-1": MASVSControl(
        id="MASVS-RESILIENCE-1",
        group="RESILIENCE",
        title="Anti-tampering and integrity",
        description="The app validates its own integrity and resists running in "
        "a tampered or repackaged state (defence in depth).",
    ),
    "MASVS-RESILIENCE-2": MASVSControl(
        id="MASVS-RESILIENCE-2",
        group="RESILIENCE",
        title="Anti-static-analysis / obfuscation",
        description="The app impedes static analysis through obfuscation and "
        "removes symbolic information from release builds.",
    ),
    "MASVS-RESILIENCE-3": MASVSControl(
        id="MASVS-RESILIENCE-3",
        group="RESILIENCE",
        title="Anti-dynamic-analysis",
        description="The app detects and resists dynamic instrumentation, "
        "debugging and emulation (defence in depth).",
    ),
    "MASVS-PRIVACY-1": MASVSControl(
        id="MASVS-PRIVACY-1",
        group="PRIVACY",
        title="Minimise sensitive data collection",
        description="The app collects only the data it needs and is transparent "
        "about third-party data sharing.",
    ),
}


# ---------------------------------------------------------------------------
# CWE -> MASVS mapping + short descriptions
# ---------------------------------------------------------------------------
@dataclass
class CWEEntry:
    id: str
    name: str
    masvs: List[str] = field(default_factory=list)
    mastg: List[str] = field(default_factory=list)
    summary: str = ""


CWE_DB: Dict[str, CWEEntry] = {
    "CWE-798": CWEEntry(
        "CWE-798", "Use of Hard-coded Credentials",
        ["MASVS-STORAGE-1", "MASVS-CRYPTO-2"], ["MASTG-TEST-0011"],
        "Credentials embedded in the app can be extracted by anyone who "
        "decompiles it.",
    ),
    "CWE-312": CWEEntry(
        "CWE-312", "Cleartext Storage of Sensitive Information",
        ["MASVS-STORAGE-1"], ["MASTG-TEST-0001", "MASTG-TEST-0003"],
        "Sensitive data is stored without encryption on the device.",
    ),
    "CWE-532": CWEEntry(
        "CWE-532", "Insertion of Sensitive Information into Log File",
        ["MASVS-STORAGE-2"], ["MASTG-TEST-0003"],
        "Sensitive data written to logs is readable by other apps or via adb.",
    ),
    "CWE-319": CWEEntry(
        "CWE-319", "Cleartext Transmission of Sensitive Information",
        ["MASVS-NETWORK-1"], ["MASTG-TEST-0019", "MASTG-TEST-0020"],
        "Data sent over an unencrypted channel can be intercepted.",
    ),
    "CWE-295": CWEEntry(
        "CWE-295", "Improper Certificate Validation",
        ["MASVS-NETWORK-1", "MASVS-NETWORK-2"], ["MASTG-TEST-0021"],
        "Improper validation of the server certificate enables MITM attacks.",
    ),
    "CWE-327": CWEEntry(
        "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
        ["MASVS-CRYPTO-1"], ["MASTG-TEST-0014"],
        "Weak ciphers/hashes provide little or no protection.",
    ),
    "CWE-328": CWEEntry(
        "CWE-328", "Use of Weak Hash",
        ["MASVS-CRYPTO-1"], ["MASTG-TEST-0014"],
        "A weak hash function is vulnerable to collision/preimage attacks.",
    ),
    "CWE-330": CWEEntry(
        "CWE-330", "Use of Insufficiently Random Values",
        ["MASVS-CRYPTO-1"], ["MASTG-TEST-0015"],
        "Predictable randomness undermines tokens, IVs and keys.",
    ),
    "CWE-89": CWEEntry(
        "CWE-89", "SQL Injection",
        ["MASVS-AUTH-1", "MASVS-PLATFORM-3"], ["MASTG-TEST-0025"],
        "Untrusted input is concatenated into a SQL query.",
    ),
    "CWE-22": CWEEntry(
        "CWE-22", "Path Traversal",
        ["MASVS-PLATFORM-1", "MASVS-PLATFORM-3"], ["MASTG-TEST-0027"],
        "Untrusted path input escapes the intended directory.",
    ),
    "CWE-20": CWEEntry(
        "CWE-20", "Improper Input Validation",
        ["MASVS-PLATFORM-3"], ["MASTG-TEST-0027"],
        "Input is used without sufficient validation.",
    ),
    "CWE-926": CWEEntry(
        "CWE-926", "Improper Export of Android Application Components",
        ["MASVS-PLATFORM-1"], ["MASTG-TEST-0024"],
        "An exported component is reachable by other apps without protection.",
    ),
    "CWE-939": CWEEntry(
        "CWE-939", "Improper Authorization in Handler for Custom URL Scheme",
        ["MASVS-PLATFORM-1"], ["MASTG-TEST-0028"],
        "A deep-link handler trusts attacker-controlled URIs.",
    ),
    "CWE-650": CWEEntry(
        "CWE-650", "Trusting HTTP Permission Methods on the Server Side",
        ["MASVS-AUTH-1"], [],
        "State-changing HTTP methods are improperly allowed.",
    ),
    "CWE-209": CWEEntry(
        "CWE-209", "Generation of Error Message Containing Sensitive Information",
        ["MASVS-CODE-4"], [],
        "Verbose errors leak implementation details.",
    ),
    "CWE-693": CWEEntry(
        "CWE-693", "Protection Mechanism Failure",
        ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"], [],
        "A relied-upon protection (e.g. a security header) is missing.",
    ),
    "CWE-1326": CWEEntry(
        "CWE-1326", "Missing Immutable Root of Trust in Hardware",
        ["MASVS-CODE-3"], ["MASTG-TEST-0046"],
        "Native binary lacks modern exploit mitigations.",
    ),
    "CWE-1277": CWEEntry(
        "CWE-1277", "Firmware Not Updateable / No PIE",
        ["MASVS-CODE-3"], ["MASTG-TEST-0046"],
        "Binary is not position-independent, weakening ASLR.",
    ),
    "CWE-919": CWEEntry(
        "CWE-919", "Weaknesses in Mobile Applications",
        ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-3"], [],
        "A mobile-specific protection is absent or bypassable.",
    ),
    "CWE-494": CWEEntry(
        "CWE-494", "Download of Code Without Integrity Check",
        ["MASVS-CODE-2"], ["MASTG-TEST-0044"],
        "Code is loaded dynamically without verifying its integrity.",
    ),
    "CWE-470": CWEEntry(
        "CWE-470", "Use of Externally-Controlled Input to Select Class (Reflection)",
        ["MASVS-CODE-2", "MASVS-RESILIENCE-2"], [],
        "Reflection driven by external input can alter control flow.",
    ),
    "CWE-522": CWEEntry(
        "CWE-522", "Insufficiently Protected Credentials",
        ["MASVS-STORAGE-1", "MASVS-AUTH-1"], ["MASTG-TEST-0011"],
        "Credentials are stored or transmitted without adequate protection.",
    ),
    "CWE-598": CWEEntry(
        "CWE-598", "Use of GET Request Method With Sensitive Query Strings",
        ["MASVS-NETWORK-1", "MASVS-STORAGE-2"], [],
        "Secrets in URLs are logged by intermediaries.",
    ),
    "CWE-320": CWEEntry(
        "CWE-320", "Key Management Errors",
        ["MASVS-CRYPTO-2"], ["MASTG-TEST-0013"],
        "Keys are handled insecurely (e.g. present in process memory).",
    ),
    "CWE-359": CWEEntry(
        "CWE-359", "Exposure of Private Personal Information",
        ["MASVS-PRIVACY-1"], [],
        "Private data is exposed, often to third-party SDKs.",
    ),
    "CWE-656": CWEEntry(
        "CWE-656", "Reliance on Security Through Obscurity",
        ["MASVS-RESILIENCE-2"], [],
        "Security depends on secrecy of implementation rather than real control.",
    ),
    "CWE-732": CWEEntry(
        "CWE-732", "Incorrect Permission Assignment for Critical Resource",
        ["MASVS-STORAGE-1", "MASVS-PLATFORM-1"], ["MASTG-TEST-0001"],
        "A resource is created with overly permissive access.",
    ),
}


def cwe_info(cwe_id: str) -> Optional[CWEEntry]:
    """Look up a CWE entry by id (e.g. 'CWE-798')."""
    if not cwe_id:
        return None
    return CWE_DB.get(cwe_id.strip().upper())


def masvs_for_cwe(cwe_id: str) -> List[MASVSControl]:
    """Return the MASVS controls associated with a CWE id."""
    entry = cwe_info(cwe_id)
    if not entry:
        return []
    return [MASVS_CONTROLS[m] for m in entry.masvs if m in MASVS_CONTROLS]


def mastg_for_cwe(cwe_id: str) -> List[str]:
    """Return MASTG test ids associated with a CWE id."""
    entry = cwe_info(cwe_id)
    return entry.mastg if entry else []


def enrich(cwe_id: str) -> Dict[str, object]:
    """Return a JSON-ready enrichment blob for a CWE id."""
    entry = cwe_info(cwe_id)
    if not entry:
        return {}
    return {
        "cwe": entry.id,
        "cwe_name": entry.name,
        "cwe_summary": entry.summary,
        "masvs": [
            {"id": c.id, "group": c.group, "title": c.title}
            for c in masvs_for_cwe(cwe_id)
        ],
        "mastg": entry.mastg,
    }


def coverage_summary(cwe_ids: List[str]) -> Dict[str, int]:
    """Given the CWE ids present in a scan, summarise MASVS group coverage."""
    groups: Dict[str, int] = {}
    for cwe in cwe_ids:
        for control in masvs_for_cwe(cwe):
            groups[control.group] = groups.get(control.group, 0) + 1
    return groups


if __name__ == "__main__":
    print(f"MASVS controls: {len(MASVS_CONTROLS)}")
    print(f"CWE entries: {len(CWE_DB)}")
    for cwe in ("CWE-798", "CWE-89", "CWE-295"):
        info = enrich(cwe)
        print(f"\n{cwe}: {info['cwe_name']}")
        for m in info["masvs"]:
            print(f"   -> {m['id']} ({m['group']}): {m['title']}")
        if info["mastg"]:
            print(f"   MASTG: {', '.join(info['mastg'])}")
    print("\ncoverage for [CWE-798, CWE-312, CWE-89]:",
          coverage_summary(["CWE-798", "CWE-312", "CWE-89"]))
