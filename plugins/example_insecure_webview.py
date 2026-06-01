"""
APKOwl :: plugins.example_insecure_webview
==========================================

An example plugin shipped to demonstrate the plugin contract. It performs a
focused check that complements the built-in phases: it looks for dangerous
WebView configurations in the decompiled/smali code that the storage phase does
not specifically flag, namely:

  * ``setJavaScriptEnabled(true)`` combined with ``addJavascriptInterface(...)``
    — the classic JS-to-native bridge that, on old targets or with reflection,
    can lead to remote code execution from loaded web content,
  * ``setAllowFileAccessFromFileURLs(true)`` / ``setAllowUniversalAccessFromFileURLs(true)``
    — which let file:// pages read arbitrary local files,
  * ``setWebContentsDebuggingEnabled(true)`` — remote WebView debugging left on.

Copy this file as a template for your own checks: subclass ``APKOwlPlugin`` and
implement ``analyze(context)``.
"""

from __future__ import annotations

import os
import re
from typing import Any, List

from plugins.base import APKOwlPlugin
from core.findings import Finding, Severity, OWASPMobile


JS_BRIDGE_RE = re.compile(r"addJavascriptInterface\s*\(")
JS_ENABLED_RE = re.compile(r"setJavaScriptEnabled\s*\(\s*true")
FILE_ACCESS_RE = re.compile(
    r"setAllow(?:File|UniversalAccessFromFile|FileAccessFromFile)\w*\s*\(\s*true"
)
WEBVIEW_DEBUG_RE = re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true")


class InsecureWebViewPlugin(APKOwlPlugin):
    name = "insecure-webview"
    description = "Detects dangerous WebView configurations (JS bridges, file " \
                  "access, remote debugging)."

    def analyze(self, context: Any) -> List[Finding]:
        findings: List[Finding] = []
        roots = getattr(context, "code_roots", []) or []
        bridge_files: List[str] = []
        js_enabled_files: List[str] = []

        for path in self._iter_code(roots):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue

            if JS_BRIDGE_RE.search(content):
                bridge_files.append(path)
            if JS_ENABLED_RE.search(content):
                js_enabled_files.append(path)

            for m in FILE_ACCESS_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        title="WebView allows file:// access to local files",
                        description="The WebView is configured to allow file "
                        "access from file URLs, letting a malicious local or "
                        "loaded page read arbitrary files in the app sandbox.",
                        module="plugin:insecure-webview",
                        severity=Severity.HIGH,
                        cvss_vector="AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cwe="CWE-22",
                        owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                        remediation="Call setAllowFileAccessFromFileURLs(false) "
                        "and setAllowUniversalAccessFromFileURLs(false).",
                        tags=["webview", "plugin"],
                    ).add_evidence(file_path=path, line_number=lineno,
                                   snippet=m.group(0))
                )

            for m in WEBVIEW_DEBUG_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        title="WebView remote debugging enabled",
                        description="setWebContentsDebuggingEnabled(true) leaves "
                        "the WebView open to inspection via chrome://inspect on "
                        "any connected machine.",
                        module="plugin:insecure-webview",
                        severity=Severity.MEDIUM,
                        cwe="CWE-489",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Disable WebView debugging in release builds.",
                        tags=["webview", "plugin"],
                    ).add_evidence(file_path=path, line_number=lineno,
                                   snippet=m.group(0))
                )

        # JS bridge + JS enabled in the same app is the high-value combination
        if bridge_files and js_enabled_files:
            f = Finding(
                title="JavaScript-to-native bridge exposed in WebView",
                description="The app registers a JavaScript interface "
                "(addJavascriptInterface) with JavaScript enabled. If untrusted "
                "content is ever loaded, it can call the exposed native methods; "
                "on API < 17 every public method (including getClass) is "
                "reachable, enabling reflection-based RCE.",
                module="plugin:insecure-webview",
                severity=Severity.HIGH,
                cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                cwe="CWE-749",
                owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                remediation="Only add JS interfaces when loading trusted content; "
                "annotate exposed methods with @JavascriptInterface; never load "
                "remote/attacker-controlled URLs into a bridged WebView.",
                tags=["webview", "rce", "plugin"],
            )
            for p in bridge_files[:5]:
                f.add_evidence(file_path=p)
            findings.append(f)

        return findings

    def _iter_code(self, roots: List[str]):
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith((".java", ".kt", ".smali")):
                        yield os.path.join(dirpath, name)
