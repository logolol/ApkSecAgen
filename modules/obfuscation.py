"""
APKOwl :: modules.obfuscation
=============================

Phase 11 — characterise the app's code-protection posture and third-party
footprint.

It measures / detects:

* **Obfuscation intensity** — the proportion of 1-2 char class/method names in
  smali, plus marker artefacts, to classify the toolchain (none / R8 / DexGuard).
* **String encryption** — heuristic detection of decrypt-at-runtime patterns
  (large numbers of static byte[] -> String decode helpers).
* **Reflection** — Class.forName / getMethod / getDeclaredMethod / invoke usage,
  which can hide behaviour and frustrate static analysis.
* **Dynamic code loading** — DexClassLoader / PathClassLoader / loadDex /
  loadLibrary on downloaded files, a serious supply-chain / integrity risk.
* **Anti-debug / anti-tamper** — Debug.isDebuggerConnected, signature
  self-checks (PackageManager.GET_SIGNATURES), time-based anti-analysis.
* **Third-party SDKs** — by package-prefix fingerprinting (analytics, ads,
  crash reporting, auth, payments, social), feeding an OWASP M2 supply-chain
  view.

This phase is purely static and works off whatever code trees exist (jadx Java
preferred, smali fallback).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log


REFLECTION_RE = re.compile(
    r"\b(Class\.forName|getDeclaredMethod|getMethod|getDeclaredField|"
    r"\.invoke\(|Method\.invoke)\b"
)
DYNLOAD_RE = re.compile(
    r"\b(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadDex|"
    r"System\.load\(|System\.loadLibrary\()"
)
ANTIDEBUG_RE = re.compile(
    r"\b(isDebuggerConnected|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|"
    r"android\.os\.Debug|waitForDebugger)\b"
)
TIMING_RE = re.compile(r"\b(System\.currentTimeMillis|SystemClock\.elapsedRealtime|nanoTime)\b")
STRING_DECRYPT_RE = re.compile(r"\b(decrypt|deobfuscate|xor|unscramble)\w*\s*\(", re.IGNORECASE)

# package-prefix -> (category, friendly name)
SDK_FINGERPRINTS: Dict[str, tuple] = {
    "com/google/firebase": ("backend", "Firebase"),
    "com/google/android/gms/ads": ("ads", "Google AdMob"),
    "com/google/android/gms": ("backend", "Google Play Services"),
    "com/facebook": ("social", "Facebook SDK"),
    "com/facebook/ads": ("ads", "Facebook Audience Network"),
    "com/flurry": ("analytics", "Flurry Analytics"),
    "com/mixpanel": ("analytics", "Mixpanel"),
    "com/amplitude": ("analytics", "Amplitude"),
    "com/segment": ("analytics", "Segment"),
    "io/branch": ("attribution", "Branch"),
    "com/adjust/sdk": ("attribution", "Adjust"),
    "com/appsflyer": ("attribution", "AppsFlyer"),
    "com/crashlytics": ("crash", "Crashlytics"),
    "io/sentry": ("crash", "Sentry"),
    "com/bugsnag": ("crash", "Bugsnag"),
    "com/stripe": ("payments", "Stripe"),
    "com/braintreepayments": ("payments", "Braintree"),
    "com/paypal": ("payments", "PayPal"),
    "com/squareup/okhttp": ("network", "OkHttp"),
    "retrofit2": ("network", "Retrofit"),
    "com/squareup/retrofit": ("network", "Retrofit"),
    "com/android/billingclient": ("payments", "Play Billing"),
    "com/onesignal": ("push", "OneSignal"),
    "com/unity3d": ("ads", "Unity Ads"),
    "com/applovin": ("ads", "AppLovin"),
    "com/ironsource": ("ads", "ironSource"),
    "com/mopub": ("ads", "MoPub"),
    "com/tapjoy": ("ads", "Tapjoy"),
    "com/chartboost": ("ads", "Chartboost"),
    "com/vungle": ("ads", "Vungle"),
    "com/inmobi": ("ads", "InMobi"),
    "okhttp3": ("network", "OkHttp"),
    "com/google/gson": ("util", "Gson"),
    "com/bumptech/glide": ("util", "Glide"),
    "com/squareup/picasso": ("util", "Picasso"),
}


@dataclass
class ObfuscationResult:
    toolchain: str = "unknown"
    short_name_ratio: float = 0.0
    total_classes: int = 0
    reflection_hits: int = 0
    dynload_hits: int = 0
    antidebug_hits: int = 0
    timing_hits: int = 0
    string_decrypt_hits: int = 0
    sdks: Dict[str, str] = field(default_factory=dict)  # name -> category
    findings: List[Finding] = field(default_factory=list)


class ObfuscationAnalyzer:
    def __init__(self, db: Database) -> None:
        self.db = db

    def run(
        self,
        smali_dirs: List[str],
        java_root: str,
        precomputed_obfuscation: Dict = None,
    ) -> ObfuscationResult:
        result = ObfuscationResult()
        if precomputed_obfuscation:
            result.toolchain = precomputed_obfuscation.get("toolchain", "unknown")
            result.short_name_ratio = precomputed_obfuscation.get("short_name_ratio", 0.0)
            result.total_classes = precomputed_obfuscation.get("total_classes", 0)

        code_roots = [d for d in smali_dirs if d]
        if java_root:
            code_roots.append(java_root)

        self._scan_code(code_roots, result)
        self._fingerprint_sdks(smali_dirs, java_root, result)
        self._evaluate(result)
        self._persist(result)
        log.good(f"obfuscation phase produced {len(result.findings)} finding(s)")
        return result

    # -- scanning ----------------------------------------------------------
    def _scan_code(self, roots: List[str], result: ObfuscationResult) -> None:
        for path in self._iter_code(roots):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            result.reflection_hits += len(REFLECTION_RE.findall(content))
            result.dynload_hits += len(DYNLOAD_RE.findall(content))
            result.antidebug_hits += len(ANTIDEBUG_RE.findall(content))
            result.timing_hits += len(TIMING_RE.findall(content))
            result.string_decrypt_hits += len(STRING_DECRYPT_RE.findall(content))

    def _iter_code(self, roots: List[str]):
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith((".java", ".kt", ".smali")):
                        yield os.path.join(dirpath, name)

    def _fingerprint_sdks(
        self, smali_dirs: List[str], java_root: str, result: ObfuscationResult
    ) -> None:
        # Look at directory structure for known package prefixes
        roots = list(smali_dirs)
        if java_root:
            roots.append(java_root)
        found_paths: Set[str] = set()
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, _files in os.walk(root):
                rel = os.path.relpath(dirpath, root).replace("\\", "/")
                found_paths.add(rel)
        for prefix, (category, name) in SDK_FINGERPRINTS.items():
            for p in found_paths:
                if prefix in p:
                    result.sdks[name] = category
                    break

    # -- evaluation --------------------------------------------------------
    def _evaluate(self, result: ObfuscationResult) -> None:
        log.kv("obfuscation toolchain", result.toolchain)
        log.kv("reflection uses", result.reflection_hits)
        log.kv("dynamic-load uses", result.dynload_hits)
        log.kv("third-party SDKs", len(result.sdks))

        # dynamic code loading is the headline risk
        if result.dynload_hits > 0:
            result.findings.append(
                Finding(
                    title="Dynamic code loading detected",
                    description=f"The app references dynamic code-loading APIs "
                    f"({result.dynload_hits} site(s)). If code is loaded from "
                    "external/downloaded sources without integrity checks, an "
                    "attacker who controls that source achieves code execution.",
                    module="obfuscation",
                    severity=Severity.MEDIUM,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe="CWE-494",
                    owasp=OWASPMobile.M2_INADEQUATE_SUPPLY_CHAIN,
                    remediation="Only load code bundled in the signed APK, or "
                    "verify a strong signature on any dynamically loaded code.",
                    tags=["dynamic-loading", "supply-chain"],
                )
            )

        if result.string_decrypt_hits > 5:
            result.findings.append(
                Finding(
                    title="Runtime string decryption present",
                    description="Numerous decrypt/deobfuscate helpers suggest "
                    "string encryption. Good hygiene; noted as context (and as a "
                    "place to look for hidden secrets at runtime via Frida).",
                    module="obfuscation",
                    severity=Severity.INFO,
                    cwe="CWE-656",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="No action; informational.",
                    tags=["obfuscation", "string-encryption"],
                )
            )

        if result.reflection_hits > 20:
            result.findings.append(
                Finding(
                    title="Heavy use of reflection",
                    description=f"{result.reflection_hits} reflection call sites "
                    "were found. Reflection can conceal behaviour and is often "
                    "used to evade static analysis; review the targets.",
                    module="obfuscation",
                    severity=Severity.INFO,
                    cwe="CWE-470",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="No direct action; investigate reflective targets "
                    "for hidden sensitive operations.",
                    tags=["reflection"],
                )
            )

        if result.antidebug_hits > 0:
            result.findings.append(
                Finding(
                    title="Anti-debug / integrity self-check present",
                    description="The app performs debugger / signature integrity "
                    "checks. Useful but client-side and bypassable (see the "
                    "patcher and Frida phases).",
                    module="obfuscation",
                    severity=Severity.INFO,
                    cwe="CWE-919",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Treat as defence-in-depth only.",
                    tags=["anti-debug"],
                )
            )

        if result.toolchain in ("none / minimal", "unknown") and result.total_classes > 50:
            result.findings.append(
                Finding(
                    title="Little or no code obfuscation",
                    description="The bytecode does not appear meaningfully "
                    "obfuscated, making reverse engineering and secret discovery "
                    "straightforward.",
                    module="obfuscation",
                    severity=Severity.LOW,
                    cwe="CWE-656",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Enable R8/ProGuard with obfuscation for release "
                    "builds (defence in depth; not a substitute for server-side "
                    "controls).",
                    tags=["obfuscation"],
                )
            )

        # supply chain: lots of ad/analytics SDKs = privacy surface
        trackers = [n for n, c in result.sdks.items()
                    if c in ("ads", "analytics", "attribution")]
        if trackers:
            f = Finding(
                title=f"Third-party tracking/ad SDKs present ({len(trackers)})",
                description="The app bundles advertising / analytics / attribution "
                "SDKs: " + ", ".join(sorted(trackers)) + ". Each is a privacy and "
                "supply-chain consideration and may transmit user/device data.",
                module="obfuscation",
                severity=Severity.INFO,
                cwe="CWE-359",
                owasp=OWASPMobile.M6_INADEQUATE_PRIVACY,
                remediation="Audit each SDK's data collection; disclose in the "
                "privacy policy; remove unused SDKs.",
                tags=["supply-chain", "privacy"],
            )
            result.findings.append(f)

    def _persist(self, result: ObfuscationResult) -> None:
        self.db.set_kv(
            "obfuscation_detail",
            {
                "toolchain": result.toolchain,
                "short_name_ratio": result.short_name_ratio,
                "reflection_hits": result.reflection_hits,
                "dynload_hits": result.dynload_hits,
                "antidebug_hits": result.antidebug_hits,
                "string_decrypt_hits": result.string_decrypt_hits,
            },
        )
        self.db.set_kv("sdks", result.sdks)
