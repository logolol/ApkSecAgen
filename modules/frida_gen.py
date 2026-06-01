"""
APKOwl :: modules.frida_gen
==========================

Phase 6 — generate a tailored Frida instrumentation toolkit for the target and,
when a device is connected, inject it.

Two halves:

1. **Generation (always runs).** Emits a set of ready-to-use Frida scripts into
   the output directory, customised with the target package name:
     * universal SSL/TLS unpinning (OkHttp3, TrustManager, Conscrypt,
       HostnameVerifier, WebView)
     * root-detection bypass
     * crypto API logger (logs Cipher/Mac/MessageDigest input & keys)
     * SharedPreferences / file I/O logger
     * network call tracer (HttpURLConnection / OkHttp)
     * JWT / token interceptor
     * generic class/method tracer scaffold
   These are genuinely useful artifacts even without a device.

2. **Injection (runs when adb + frida + a device are available).** Pushes the
   appropriate ``frida-server`` workflow expectations, spawns the app with the
   SSL-unpinning + crypto-logging scripts attached, collects console output for
   a bounded window, and saves the runtime log.

Everything degrades gracefully: no device → scripts are still written and the
user is told exactly how to run them.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


@dataclass
class FridaResult:
    scripts: Dict[str, str] = field(default_factory=dict)  # name -> path
    injected: bool = False
    runtime_log: str = ""
    findings: List[Finding] = field(default_factory=list)
    device_serial: str = ""


class FridaGenerator:
    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir
        self.scripts_dir = os.path.join(workdir, "frida-scripts")
        os.makedirs(self.scripts_dir, exist_ok=True)

    def run(
        self,
        package_name: str,
        enable_injection: bool = True,
        inject_seconds: int = 20,
    ) -> FridaResult:
        result = FridaResult()
        log.info("generating Frida instrumentation scripts ...")
        self._write_scripts(package_name, result)
        log.good(f"generated {len(result.scripts)} Frida script(s) in {self.scripts_dir}")

        if enable_injection:
            self._maybe_inject(package_name, inject_seconds, result)
        else:
            log.info("Frida injection disabled by configuration")

        self._emit_findings(result, package_name)
        self._persist(result)
        return result

    # -- script generation -------------------------------------------------
    def _write_scripts(self, pkg: str, result: FridaResult) -> None:
        scripts = {
            "ssl-unpinning.js": self._script_ssl_unpinning(),
            "root-bypass.js": self._script_root_bypass(),
            "crypto-logger.js": self._script_crypto_logger(),
            "prefs-file-logger.js": self._script_prefs_logger(),
            "network-tracer.js": self._script_network_tracer(),
            "jwt-interceptor.js": self._script_jwt_interceptor(),
            "class-tracer.js": self._script_class_tracer(pkg),
            "anti-debug-bypass.js": self._script_antidebug_bypass(),
        }
        for name, body in scripts.items():
            path = os.path.join(self.scripts_dir, name)
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                result.scripts[name] = path
            except OSError as exc:
                log.warn(f"could not write {name}: {exc}")

        # combined "kitchen sink" loader
        combined = os.path.join(self.scripts_dir, "apkowl-all.js")
        try:
            with open(combined, "w", encoding="utf-8") as fh:
                fh.write(self._script_combined(pkg))
            result.scripts["apkowl-all.js"] = combined
        except OSError:
            pass

        # a runnable helper shell script
        runner = os.path.join(self.scripts_dir, "run.sh")
        try:
            with open(runner, "w", encoding="utf-8") as fh:
                fh.write(self._runner_sh(pkg))
            os.chmod(runner, 0o755)
            result.scripts["run.sh"] = runner
        except OSError:
            pass

    def _script_ssl_unpinning(self) -> str:
        return r"""/*
 * APKOwl :: Universal SSL/TLS unpinning
 * Defeats common pinning implementations so traffic can be intercepted.
 */
Java.perform(function () {
    console.log('[APKOwl] SSL unpinning loaded');

    // 1. Default TrustManager override
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.apkowl.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var tms = [TrustManager.$new()];
        var initInject = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom');
        initInject.implementation = function (km, tm, sr) {
            console.log('[APKOwl] SSLContext.init() hijacked');
            initInject.call(this, km, tms, sr);
        };
    } catch (e) { console.log('[APKOwl] TrustManager hook failed: ' + e); }

    // 2. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (a, b) {
                console.log('[APKOwl] OkHttp CertificatePinner.check() bypassed: ' + a);
            };
    } catch (e) {}

    // 3. HostnameVerifier
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            console.log('[APKOwl] setDefaultHostnameVerifier bypassed');
        };
    } catch (e) {}

    // 4. Conscrypt / TrustManagerImpl (Android 7+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrusted, hb, host, clientAuth, ocsp, tlsSct) {
            console.log('[APKOwl] TrustManagerImpl.verifyChain bypassed: ' + host);
            return untrusted;
        };
    } catch (e) {}
});
"""

    def _script_root_bypass(self) -> str:
        return r"""/*
 * APKOwl :: Root detection bypass
 */
Java.perform(function () {
    console.log('[APKOwl] root-bypass loaded');
    var commonChecks = ['isRooted', 'isDeviceRooted', 'checkRootMethod1',
        'checkRootMethod2', 'checkRootMethod3', 'detectRootManagementApps',
        'detectPotentiallyDangerousApps', 'checkForBinary', 'isRootedExperimental'];

    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        commonChecks.forEach(function (m) {
            if (RootBeer[m]) {
                RootBeer[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        console.log('[APKOwl] RootBeer.' + m + ' -> false');
                        return false;
                    };
                });
            }
        });
    } catch (e) {}

    // File.exists() on known su paths
    try {
        var File = Java.use('java.io.File');
        var suPaths = ['su', 'magisk', 'superuser', 'busybox'];
        File.exists.implementation = function () {
            var p = this.getAbsolutePath();
            for (var i = 0; i < suPaths.length; i++) {
                if (p.toLowerCase().indexOf(suPaths[i]) !== -1) {
                    console.log('[APKOwl] File.exists(' + p + ') -> false');
                    return false;
                }
            }
            return this.exists.call(this);
        };
    } catch (e) {}

    // Runtime.exec("su")
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                console.log('[APKOwl] blocked Runtime.exec: ' + cmd);
                throw Java.use('java.io.IOException').$new('not found');
            }
            return this.exec(cmd);
        };
    } catch (e) {}
});
"""

    def _script_crypto_logger(self) -> str:
        return r"""/*
 * APKOwl :: Crypto API logger
 * Logs keys, IVs and plaintext passing through the crypto APIs.
 */
Java.perform(function () {
    console.log('[APKOwl] crypto-logger loaded');
    function b64(bytes) {
        try { return Java.use('android.util.Base64')
            .encodeToString(bytes, 0); } catch (e) { return '<?>'; }
    }
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            console.log('[APKOwl][Cipher] alg=' + this.getAlgorithm() +
                ' in=' + b64(input));
            var out = this.doFinal(input);
            console.log('[APKOwl][Cipher] out=' + b64(out));
            return out;
        };
    } catch (e) {}
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String')
            .implementation = function (key, alg) {
                console.log('[APKOwl][Key] alg=' + alg + ' key=' + b64(key));
                return this.$init(key, alg);
            };
    } catch (e) {}
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function (input) {
            console.log('[APKOwl][Digest] alg=' + this.getAlgorithm());
            return this.digest(input);
        };
    } catch (e) {}
});
"""

    def _script_prefs_logger(self) -> str:
        return r"""/*
 * APKOwl :: SharedPreferences + file I/O logger
 */
Java.perform(function () {
    console.log('[APKOwl] prefs-file-logger loaded');
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        ['putString', 'putInt', 'putBoolean', 'putLong', 'putFloat'].forEach(function (m) {
            if (Editor[m]) {
                Editor[m].implementation = function (k, v) {
                    console.log('[APKOwl][Prefs] ' + m + ' ' + k + '=' + v);
                    return this[m](k, v);
                };
            }
        });
    } catch (e) {}
    try {
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.io.File').implementation = function (f) {
            console.log('[APKOwl][File] write ' + f.getAbsolutePath());
            return this.$init(f);
        };
    } catch (e) {}
});
"""

    def _script_network_tracer(self) -> str:
        return r"""/*
 * APKOwl :: Network call tracer
 */
Java.perform(function () {
    console.log('[APKOwl] network-tracer loaded');
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            console.log('[APKOwl][URL] ' + this.toString());
            return this.openConnection();
        };
    } catch (e) {}
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('java.lang.String').implementation = function (u) {
            console.log('[APKOwl][OkHttp] ' + u);
            return this.url(u);
        };
    } catch (e) {}
});
"""

    def _script_jwt_interceptor(self) -> str:
        return r"""/*
 * APKOwl :: JWT / bearer token interceptor
 */
Java.perform(function () {
    console.log('[APKOwl] jwt-interceptor loaded');
    try {
        var String_ = Java.use('java.lang.String');
        // Hook header insertion via OkHttp
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.header.implementation = function (name, value) {
            if (name.toLowerCase() === 'authorization') {
                console.log('[APKOwl][Auth] ' + value);
            }
            return this.header(name, value);
        };
    } catch (e) {}
});
"""

    def _script_class_tracer(self, pkg: str) -> str:
        return r"""/*
 * APKOwl :: class/method tracer scaffold
 * Edit TARGET to trace a specific class in this app.
 */
var TARGET = '%s';
Java.perform(function () {
    console.log('[APKOwl] class-tracer loaded for ' + TARGET);
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf(TARGET) === 0) {
                // console.log('[APKOwl][class] ' + name);
            }
        },
        onComplete: function () {}
    });
});
""" % pkg

    def _script_antidebug_bypass(self) -> str:
        return r"""/*
 * APKOwl :: anti-debug bypass
 */
Java.perform(function () {
    console.log('[APKOwl] anti-debug-bypass loaded');
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            console.log('[APKOwl] Debug.isDebuggerConnected -> false');
            return false;
        };
    } catch (e) {}
});
"""

    def _script_combined(self, pkg: str) -> str:
        return (
            "/* APKOwl :: combined toolkit. Load with: frida -U -f %s "
            "-l apkowl-all.js --no-pause */\n" % pkg
            + self._script_ssl_unpinning()
            + "\n"
            + self._script_root_bypass()
            + "\n"
            + self._script_crypto_logger()
            + "\n"
            + self._script_network_tracer()
        )

    def _runner_sh(self, pkg: str) -> str:
        return f"""#!/usr/bin/env bash
# APKOwl Frida helper. Requires: frida-tools on host, frida-server on device.
set -e
PKG="{pkg}"
echo "[*] Make sure frida-server is running on the device:"
echo "    adb shell \\"su -c '/data/local/tmp/frida-server &'\\""
echo "[*] Spawning $PKG with the full APKOwl toolkit..."
frida -U -f "$PKG" -l apkowl-all.js --no-pause
"""

    # -- injection ---------------------------------------------------------
    def _maybe_inject(self, pkg: str, seconds: int, result: FridaResult) -> None:
        if not self.tools.available("adb"):
            log.info("adb not available; skipping live Frida injection")
            log.info(self.tools.install_hint("adb"))
            return
        if not self.tools.available("frida"):
            log.info("frida not available; scripts generated for manual use")
            log.info(self.tools.install_hint("frida"))
            return

        serial = self._first_device()
        if not serial:
            log.info("no connected device/emulator; skipping live injection")
            return
        result.device_serial = serial
        log.good(f"device detected: {serial}; attempting Frida injection")

        # check frida-server is reachable
        probe = self.tools.run_tool("frida", ["-U", "-q", "--version"], timeout=15)
        if not probe.ok:
            log.warn("frida cannot reach a device agent (frida-server). "
                     "Start frida-server on the device, then re-run.")
            return

        combined = result.scripts.get("apkowl-all.js")
        if not combined:
            return
        log_path = os.path.join(self.workdir, "frida-runtime.log")
        log.info(f"spawning {pkg} with instrumentation for {seconds}s ...")
        r = self.tools.run_tool(
            "frida",
            ["-U", "-f", pkg, "-l", combined, "--no-pause", "-o", log_path],
            timeout=seconds + 15,
        )
        if os.path.isfile(log_path):
            result.injected = True
            result.runtime_log = log_path
            log.good(f"runtime log captured: {log_path}")
            self._scan_runtime_log(log_path, result)
        else:
            log.warn(f"injection produced no log: {r.short(150)}")

    def _first_device(self) -> str:
        r = self.tools.run_tool("adb", ["devices"])
        if not r.ok:
            return ""
        for line in r.stdout.splitlines()[1:]:
            line = line.strip()
            if line and "device" in line.split("\t")[-1:]:
                return line.split("\t")[0].split()[0]
            if line.endswith("device"):
                return line.split()[0]
        return ""

    def _scan_runtime_log(self, log_path: str, result: FridaResult) -> None:
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return
        if "[APKOwl][Key]" in content or "[APKOwl][Cipher]" in content:
            result.findings.append(
                Finding(
                    title="Cryptographic keys/material observed at runtime",
                    description="Runtime instrumentation captured cryptographic "
                    "keys or plaintext passing through the crypto APIs, "
                    "confirming sensitive material is handled in-process and is "
                    "extractable on a compromised device.",
                    module="frida",
                    severity=Severity.MEDIUM,
                    cwe="CWE-320",
                    owasp=OWASPMobile.M10_INSUFFICIENT_CRYPTO,
                    remediation="Use the Android Keystore / hardware-backed keys "
                    "so key material never enters app memory in the clear.",
                    tags=["runtime", "crypto"],
                ).add_evidence(file_path=log_path)
            )

    # -- findings / persistence -------------------------------------------
    def _emit_findings(self, result: FridaResult, pkg: str) -> None:
        result.findings.append(
            Finding(
                title="Frida instrumentation toolkit generated",
                description=f"A customised Frida toolkit for '{pkg}' was "
                f"generated ({len(result.scripts)} scripts) including SSL "
                "unpinning, root bypass, crypto logging and network tracing. "
                "This documents the app's exposure to dynamic instrumentation.",
                module="frida",
                severity=Severity.INFO,
                cwe="CWE-919",
                owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                remediation="Consider runtime integrity checks / obfuscation to "
                "raise the cost of instrumentation (defence in depth only).",
                tags=["frida", "tooling"],
            ).add_evidence(file_path=self.scripts_dir)
        )

    def _persist(self, result: FridaResult) -> None:
        for name, path in result.scripts.items():
            self.db.add_artifact("frida_script", path, note=name)
        if result.runtime_log:
            self.db.add_artifact("frida_log", result.runtime_log, note="runtime capture")
        self.db.set_kv(
            "frida_summary",
            {
                "scripts": list(result.scripts.keys()),
                "injected": result.injected,
                "device": result.device_serial,
            },
        )
