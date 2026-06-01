"""
APKOwl :: plugins.example_weak_prng_tokens
==========================================

A second bundled example plugin. It hunts for application-level token / nonce /
session-id generation that relies on weak randomness — a subtle issue the core
crypto phase (which focuses on Cipher/MessageDigest usage) does not specifically
target.

It flags code where a value that *looks* like a security token (variable or
method name containing token/nonce/session/otp/csrf/salt) is produced from a
non-cryptographic source:

  * ``java.util.Random`` / ``Math.random()``
  * ``System.currentTimeMillis()`` / ``nanoTime()`` used as a seed or id
  * ``UUID.randomUUID()`` is *not* flagged (it is acceptably random)

This is a template for writing correlation-style plugins: it looks at the
*pairing* of two signals in the same file rather than a single pattern.
"""

from __future__ import annotations

import os
import re
from typing import Any, List

from plugins.base import APKOwlPlugin
from core.findings import Finding, Severity, OWASPMobile


TOKEN_NAME_RE = re.compile(
    r"\b\w*(token|nonce|session|otp|csrf|salt|secret|apikey)\w*\b",
    re.IGNORECASE,
)
WEAK_RANDOM_RE = re.compile(
    r"\b(new\s+java\.util\.Random|new\s+Random\s*\(|Math\.random\s*\(|"
    r"System\.currentTimeMillis\s*\(|SystemClock\.\w+\s*\(|\.nanoTime\s*\()"
)


class WeakTokenRandomnessPlugin(APKOwlPlugin):
    name = "weak-token-randomness"
    description = "Flags security tokens generated from non-cryptographic " \
                  "randomness or timestamps."

    def analyze(self, context: Any) -> List[Finding]:
        findings: List[Finding] = []
        roots = getattr(context, "code_roots", []) or []
        flagged_files = set()

        for path in self._iter_code(roots):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue

            if path in flagged_files:
                continue

            # require both signals in the file: a token-ish name AND weak RNG
            if TOKEN_NAME_RE.search(content) and WEAK_RANDOM_RE.search(content):
                # find a representative line for evidence
                lineno = 0
                snippet = ""
                for i, line in enumerate(content.splitlines(), 1):
                    if WEAK_RANDOM_RE.search(line):
                        lineno = i
                        snippet = line.strip()[:120]
                        break
                flagged_files.add(path)
                findings.append(
                    Finding(
                        title="Security token derived from weak randomness",
                        description="This file both references a security-token-"
                        "like value and uses a non-cryptographic source of "
                        "randomness or a timestamp. Tokens, nonces, OTPs and "
                        "session ids built this way are predictable and can be "
                        "guessed or brute-forced.",
                        module="plugin:weak-token-randomness",
                        severity=Severity.HIGH,
                        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-330",
                        owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
                        remediation="Generate security-sensitive values with "
                        "java.security.SecureRandom (or the platform's CSPRNG); "
                        "never seed them from time or use java.util.Random.",
                        tags=["crypto", "prng", "plugin"],
                    ).add_evidence(file_path=path, line_number=lineno,
                                   snippet=snippet)
                )

        return findings

    def _iter_code(self, roots: List[str]):
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith((".java", ".kt", ".smali")):
                        yield os.path.join(dirpath, name)
