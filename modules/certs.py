"""
APKOwl :: modules.certs
======================

Phase 4 — certificate, signing, network-security and cryptography analysis.

Three strands:

1. **Signing certificate** — pull the certificate from ``META-INF/*.RSA|DSA|EC``
   (PKCS#7) and inspect subject/issuer/validity/serial/fingerprint, flagging
   debug certs, self-signed certs, expired certs and weak signature algorithms
   (MD5withRSA / SHA1withRSA).

2. **Network security config** — parse ``res/xml/network_security_config.xml``
   (or whatever ``networkSecurityConfig`` points at) for cleartext-permitted
   domains, custom trust anchors and pin sets.

3. **Cryptography in code** — grep the decompiled tree for weak ciphers
   (DES/RC4/ECB), insecure RNG (``java.util.Random`` / ``Math.random``) used for
   security, hardcoded IVs, and detect whether SSL pinning is implemented at
   all (OkHttp CertificatePinner, custom TrustManager, Conscrypt, etc.).
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


# -- regexes for code-level crypto checks ---------------------------------
WEAK_CIPHER_RE = re.compile(
    r'Cipher\.getInstance\(\s*"([^"]+)"', re.IGNORECASE
)
WEAK_DIGEST_RE = re.compile(
    r'MessageDigest\.getInstance\(\s*"(MD5|MD2|SHA-?1)"', re.IGNORECASE
)
INSECURE_RANDOM_RE = re.compile(r"\bnew\s+java\.util\.Random\b|\bMath\.random\(")
SECURE_RANDOM_RE = re.compile(r"\bSecureRandom\b")
HARDCODED_IV_RE = re.compile(r"IvParameterSpec\(\s*[\"']?[A-Za-z0-9+/=]{8,}")

# SSL pinning / trust handling indicators
PINNING_INDICATORS = [
    (re.compile(r"CertificatePinner"), "OkHttp CertificatePinner"),
    (re.compile(r"setCertificatePinner"), "OkHttp pinner installed"),
    (re.compile(r"network[_-]?security[_-]?config"), "network-security-config pinning"),
    (re.compile(r"\bpin-set\b|<pin\b"), "network-security-config pin set"),
    (re.compile(r"TrustManagerFactory"), "custom TrustManagerFactory"),
    (re.compile(r"X509TrustManager"), "custom X509TrustManager"),
    (re.compile(r"public-key-pinning|publicKeyPinning"), "public-key pinning"),
]

# dangerously permissive trust manager (accepts everything)
TRUSTALL_RE = re.compile(
    r"checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}",
)
TRUSTALL_HINT_RE = re.compile(
    r"(return\s+null;|//\s*trust\s+all|TrustAll|NullHostnameVerifier|"
    r"ALLOW_ALL_HOSTNAME_VERIFIER)",
    re.IGNORECASE,
)

WEAK_CIPHER_TOKENS = ("DES", "DESEDE", "RC4", "RC2", "BLOWFISH")
ECB_RE = re.compile(r"/ECB/", re.IGNORECASE)


@dataclass
class CertInfo:
    file: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    sig_algorithm: str = ""
    sha256_fingerprint: str = ""
    self_signed: bool = False
    expired: bool = False
    debug: bool = False


@dataclass
class CertsResult:
    certificates: List[CertInfo] = field(default_factory=list)
    pinning_found: List[str] = field(default_factory=list)
    cleartext_domains: List[str] = field(default_factory=list)
    trust_anchors: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class CertAnalyzer:
    def __init__(self, tools: ToolRunner, db: Database) -> None:
        self.tools = tools
        self.db = db

    def run(
        self,
        unzip_dir: str,
        apktool_dir: str,
        code_roots: List[str],
        network_security_config: str = "",
    ) -> CertsResult:
        result = CertsResult()
        self._analyze_signing(unzip_dir, result)
        self._analyze_network_config(apktool_dir, unzip_dir, network_security_config, result)
        self._analyze_code_crypto(code_roots, result)
        self._persist(result)
        log.good(f"cert/crypto analysis produced {len(result.findings)} finding(s)")
        return result

    # -- signing certificate ----------------------------------------------
    def _analyze_signing(self, unzip_dir: str, result: CertsResult) -> None:
        meta = os.path.join(unzip_dir, "META-INF")
        if not os.path.isdir(meta):
            log.debug("no META-INF directory; unsigned or stripped")
            return
        cert_files = [
            os.path.join(meta, f)
            for f in os.listdir(meta)
            if f.upper().endswith((".RSA", ".DSA", ".EC"))
        ]
        if not cert_files:
            log.warn("no signature block found (.RSA/.DSA/.EC)")
            return

        for cf in cert_files:
            info = self._parse_pkcs7(cf)
            if info:
                result.certificates.append(info)
                self._evaluate_cert(info, result)

        # Janus / signature-scheme check: v1 (JAR) signing leaves the .SF/.RSA
        # files in META-INF; v2+/v3 store the signature in the APK Signing Block
        # appended before the central directory. We can't parse the block here
        # without the whole APK, but a v1-only APK has the JAR signature files
        # and (crucially) the pipeline records the apk path for a deeper check.
        # As a static heuristic, flag presence of only v1 artefacts.
        has_v1 = any(
            f.upper().endswith(".SF") for f in os.listdir(meta)
        )
        v2_present = self._apk_has_v2_block(result)
        if has_v1 and not v2_present:
            result.findings.append(
                FindingTemplates.janus_signature("v1 (JAR)").add_evidence(
                    file_path="META-INF/", snippet="v1 signature files present, "
                    "no v2/v3 APK Signing Block detected"
                )
            )

    def _apk_has_v2_block(self, result: "CertsResult") -> bool:
        """Look for the APK Signing Block magic in the source APK if known."""
        apk = getattr(self, "_source_apk", "") or ""
        if not apk or not os.path.isfile(apk):
            # unknown -> assume present to avoid false positives
            return True
        try:
            with open(apk, "rb") as fh:
                # APK Signing Block magic is "APK Sig Block 42" near EOCD; a
                # cheap scan of the tail is sufficient for a heuristic.
                fh.seek(max(0, os.path.getsize(apk) - 1024 * 256))
                tail = fh.read()
            return b"APK Sig Block 42" in tail
        except OSError:
            return True

    def _parse_pkcs7(self, path: str) -> Optional[CertInfo]:
        """Extract the X.509 certificate from a PKCS#7 signature block.

        Prefers the `cryptography` library; falls back to `keytool -printcert`.
        """
        info = CertInfo(file=os.path.basename(path))
        try:
            with open(path, "rb") as fh:
                der = fh.read()
        except OSError:
            return None

        # try cryptography first
        cert = self._cert_via_cryptography(der)
        if cert is not None:
            self._fill_from_cryptography(cert, info)
            return info

        # fall back to keytool
        if self.tools.available("keytool"):
            r = self.tools.run_tool("keytool", ["-printcert", "-file", path])
            if r.ok:
                self._fill_from_keytool(r.stdout, info)
                return info
        log.debug(f"could not parse certificate: {path}")
        return None

    def _cert_via_cryptography(self, der: bytes):
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography import x509

            certs = pkcs7.load_der_pkcs7_certificates(der)
            if certs:
                return certs[0]
        except Exception:
            try:
                from cryptography import x509

                return x509.load_der_x509_certificate(der)
            except Exception:
                return None
        return None

    def _fill_from_cryptography(self, cert, info: CertInfo) -> None:
        import hashlib

        try:
            info.subject = cert.subject.rfc4514_string()
            info.issuer = cert.issuer.rfc4514_string()
            info.serial = format(cert.serial_number, "x")
            nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
            na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
            info.not_before = nb.isoformat()
            info.not_after = na.isoformat()
            info.sig_algorithm = cert.signature_algorithm_oid._name
            fp = hashlib.sha256(cert.public_bytes(_der_encoding())).hexdigest()
            info.sha256_fingerprint = ":".join(
                fp[i : i + 2] for i in range(0, len(fp), 2)
            ).upper()
            info.self_signed = info.subject == info.issuer
            now = datetime.now(timezone.utc)
            try:
                info.expired = na < now
            except TypeError:
                info.expired = na.replace(tzinfo=timezone.utc) < now
        except Exception as exc:
            log.debug(f"cert field extraction error: {exc}")

    def _fill_from_keytool(self, output: str, info: CertInfo) -> None:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Owner:"):
                info.subject = line.split(":", 1)[1].strip()
            elif line.startswith("Issuer:"):
                info.issuer = line.split(":", 1)[1].strip()
            elif line.startswith("Serial number:"):
                info.serial = line.split(":", 1)[1].strip()
            elif "Signature algorithm name:" in line:
                info.sig_algorithm = line.split(":", 1)[1].strip()
            elif "SHA256:" in line:
                info.sha256_fingerprint = line.split("SHA256:", 1)[1].strip()
        info.self_signed = bool(info.subject) and info.subject == info.issuer

    def _evaluate_cert(self, info: CertInfo, result: CertsResult) -> None:
        log.kv("cert subject", info.subject or "(unknown)")
        log.kv("cert sigalg", info.sig_algorithm or "(unknown)")
        if info.sha256_fingerprint:
            log.kv("cert sha256", info.sha256_fingerprint[:32] + "...")

        # debug certificate detection
        debug_markers = ("CN=Android Debug", "O=Android", "C=US, O=Android")
        if any(m.lower() in info.subject.lower() for m in debug_markers):
            info.debug = True
            result.findings.append(
                Finding(
                    title="Application signed with Android debug certificate",
                    description="The APK is signed with the well-known Android "
                    "debug key. Anyone can produce a matching signature; this "
                    "must never ship to production.",
                    module="certs",
                    severity=Severity.HIGH,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    cwe="CWE-321",
                    owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
                    remediation="Sign release builds with a securely stored "
                    "production keystore.",
                    tags=["signing", "debug-cert"],
                ).add_evidence(file_path=f"META-INF/{info.file}", snippet=info.subject)
            )

        # weak signature algorithm
        sig = info.sig_algorithm.lower()
        if "md5" in sig or "sha1with" in sig or sig.startswith("sha1"):
            result.findings.append(
                FindingTemplates.weak_crypto(
                    f"weak certificate signature algorithm ({info.sig_algorithm})"
                ).add_evidence(file_path=f"META-INF/{info.file}", snippet=info.sig_algorithm)
            )

        if info.self_signed and not info.debug:
            result.findings.append(
                Finding(
                    title="Self-signed signing certificate",
                    description="The signing certificate is self-signed (subject "
                    "equals issuer). Normal for Android app signing, but recorded "
                    "for completeness.",
                    module="certs",
                    severity=Severity.INFO,
                    cwe="CWE-295",
                    owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
                    remediation="No action required for standard app signing.",
                    tags=["signing"],
                )
            )

        if info.expired:
            result.findings.append(
                Finding(
                    title="Signing certificate has expired",
                    description=f"The signing certificate expired on "
                    f"{info.not_after}.",
                    module="certs",
                    severity=Severity.LOW,
                    cwe="CWE-298",
                    owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
                    remediation="Re-sign with a valid certificate.",
                    tags=["signing", "expired"],
                )
            )

    # -- network security config -------------------------------------------
    def _analyze_network_config(
        self,
        apktool_dir: str,
        unzip_dir: str,
        nsc_attr: str,
        result: CertsResult,
    ) -> None:
        nsc_path = self._find_nsc(apktool_dir, unzip_dir, nsc_attr)
        if not nsc_path:
            log.debug("no network security config found")
            return
        log.info(f"parsing network security config: {os.path.basename(nsc_path)}")
        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(nsc_path)
            root = tree.getroot()
        except Exception as exc:
            log.debug(f"NSC parse error: {exc}")
            return

        for domain_cfg in root.iter("domain-config"):
            cleartext = domain_cfg.get("cleartextTrafficPermitted", "")
            if cleartext.lower() == "true":
                for dom in domain_cfg.iter("domain"):
                    if dom.text:
                        result.cleartext_domains.append(dom.text.strip())
            for ta in domain_cfg.iter("trust-anchors"):
                for cert in ta.iter("certificates"):
                    src = cert.get("src", "")
                    if src and src not in ("system",):
                        result.trust_anchors.append(src)
            for pinset in domain_cfg.iter("pin-set"):
                result.pinning_found.append("network-security-config pin-set")

        base = root.find("base-config")
        if base is not None and base.get("cleartextTrafficPermitted", "").lower() == "true":
            result.cleartext_domains.append("* (base-config)")

        if result.cleartext_domains:
            result.findings.append(
                Finding(
                    title="Cleartext traffic permitted for specific domains",
                    description="The network security configuration explicitly "
                    "permits unencrypted HTTP to: "
                    + ", ".join(result.cleartext_domains[:10]),
                    module="certs",
                    severity=Severity.MEDIUM,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe="CWE-319",
                    owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                    remediation="Remove cleartextTrafficPermitted=\"true\"; "
                    "enforce TLS for all domains.",
                    tags=["network", "cleartext"],
                ).add_evidence(file_path=nsc_path)
            )

        if any("user" in ta.lower() for ta in result.trust_anchors):
            result.findings.append(
                Finding(
                    title="App trusts user-installed CA certificates",
                    description="The network security config adds the 'user' "
                    "trust anchor, meaning user-installed CAs are trusted. This "
                    "makes MITM interception trivial on a configured device.",
                    module="certs",
                    severity=Severity.MEDIUM,
                    cvss_vector="AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe="CWE-295",
                    owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                    remediation="Trust only the system CA store in production; "
                    "consider pinning.",
                    tags=["network", "trust-anchor"],
                ).add_evidence(file_path=nsc_path)
            )

    def _find_nsc(self, apktool_dir: str, unzip_dir: str, attr: str) -> str:
        candidates = []
        if attr:
            name = attr.split("/")[-1]
            if not name.endswith(".xml"):
                name += ".xml"
            for base in (apktool_dir, unzip_dir):
                if base:
                    candidates.append(os.path.join(base, "res", "xml", name))
        for base in (apktool_dir, unzip_dir):
            if base:
                candidates.append(
                    os.path.join(base, "res", "xml", "network_security_config.xml")
                )
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return ""

    # -- code-level crypto -------------------------------------------------
    def _analyze_code_crypto(self, roots: List[str], result: CertsResult) -> None:
        secure_random_seen = False
        insecure_random_locs: List[Tuple[str, int, str]] = []

        for path in self._iter_code(roots):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue

            # SSL pinning indicators
            for rx, label in PINNING_INDICATORS:
                if rx.search(content):
                    if label not in result.pinning_found:
                        result.pinning_found.append(label)

            # trust-all manager
            if TRUSTALL_HINT_RE.search(content) and (
                "checkServerTrusted" in content or "X509TrustManager" in content
            ):
                result.findings.append(
                    Finding(
                        title="Permissive TLS trust manager (accepts all certs)",
                        description="Code appears to implement a TrustManager / "
                        "HostnameVerifier that accepts any certificate, disabling "
                        "TLS validation entirely.",
                        module="certs",
                        severity=Severity.HIGH,
                        cvss_vector="AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-295",
                        owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                        remediation="Remove the permissive trust manager; rely on "
                        "the platform's certificate validation.",
                        tags=["tls", "trust-all"],
                    ).add_evidence(file_path=path)
                )

            for m in WEAK_CIPHER_RE.finditer(content):
                spec = m.group(1).upper()
                algo = spec.split("/")[0]
                lineno = content[: m.start()].count("\n") + 1
                if algo in WEAK_CIPHER_TOKENS:
                    result.findings.append(
                        FindingTemplates.weak_crypto(
                            f"weak cipher algorithm '{spec}'"
                        ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0))
                    )
                elif ECB_RE.search(spec) or "/ECB/" in m.group(1):
                    result.findings.append(
                        FindingTemplates.weak_crypto(
                            f"ECB mode cipher '{spec}' (no semantic security)"
                        ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0))
                    )

            for m in WEAK_DIGEST_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                result.findings.append(
                    FindingTemplates.weak_crypto(
                        f"weak hash function '{m.group(1)}'"
                    ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0))
                )

            if SECURE_RANDOM_RE.search(content):
                secure_random_seen = True
            for m in INSECURE_RANDOM_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                insecure_random_locs.append((path, lineno, m.group(0)))

            for m in HARDCODED_IV_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                result.findings.append(
                    FindingTemplates.weak_crypto(
                        "hardcoded initialization vector (IV)"
                    ).add_evidence(file_path=path, line_number=lineno, snippet=m.group(0)[:80])
                )

        # only flag insecure RNG if it co-occurs with crypto-ish context
        if insecure_random_locs and not secure_random_seen:
            f = FindingTemplates.weak_crypto(
                "use of non-cryptographic RNG (java.util.Random / Math.random)"
            )
            for path, lineno, snippet in insecure_random_locs[:5]:
                f.add_evidence(file_path=path, line_number=lineno, snippet=snippet)
            result.findings.append(f)

        # pinning summary
        if result.pinning_found:
            log.good("SSL pinning detected: " + ", ".join(sorted(set(result.pinning_found))))
        else:
            result.findings.append(FindingTemplates.ssl_pinning_absent())

    def _iter_code(self, roots: List[str]):
        exts = (".java", ".kt", ".smali")
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith(exts):
                        yield os.path.join(dirpath, name)

    # -- persistence -------------------------------------------------------
    def _persist(self, result: CertsResult) -> None:
        self.db.set_kv(
            "certificates",
            [c.__dict__ for c in result.certificates],
        )
        self.db.set_kv("pinning", sorted(set(result.pinning_found)))
        self.db.set_kv("cleartext_domains", result.cleartext_domains)


def _der_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER
