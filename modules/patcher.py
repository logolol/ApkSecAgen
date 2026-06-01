"""
APKOwl :: modules.patcher
========================

Phase 5 — locate anti-analysis defences and produce a patched, re-signed APK
that neutralises them so the app can be run and inspected on a test device.

Concretely it:

* scans smali for **root detection** (su path checks, RootBeer, test-keys,
  Superuser/Magisk package checks) and **emulator detection** (Build.FINGERPRINT
  "generic", qemu props, etc.),
* scans smali for **SSL pinning** entry points (custom checkServerTrusted,
  OkHttp CertificatePinner.check),
* rewrites the offending smali methods so the detection returns the "safe"
  value (e.g. ``isRooted()`` returns false, ``checkServerTrusted`` becomes a
  no-op that returns void),
* repackages with ``apktool b`` and re-signs with a freshly generated debug
  keystore via ``apksigner`` (preferred) or ``jarsigner`` + ``zipalign``.

When the toolchain is incomplete it still records *what* it would patch and
emits the smali diffs as artifacts, so the work is never lost.

The smali rewriting is deliberately conservative: it only edits method bodies
whose signatures we recognise, replacing the body with a minimal valid stub
that returns the desired constant. This avoids corrupting the DEX.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


# -- detection signatures (smali-level) -----------------------------------
ROOT_STRING_INDICATORS = [
    "/system/app/Superuser.apk",
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/system/sd/xbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "test-keys",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.topjohnwu.magisk",
    "de.robv.android.xposed",
    "RootBeer",
    "isRooted",
    "isDeviceRooted",
]

EMULATOR_INDICATORS = [
    "goldfish",
    "ranchu",
    "generic_x86",
    "vbox86",
    "android_x86",
    "Genymotion",
    "15555215554",  # default emulator phone number
    "test-keys",
    "google_sdk",
    "sdk_gphone",
]

# smali method headers we know how to neutralise -> (return_kind, value)
# return_kind: 'boolean_false' | 'boolean_true' | 'void' | 'null'
PINNING_METHOD_PATTERNS = [
    # custom X509TrustManager.checkServerTrusted -> make it a no-op (void)
    (re.compile(r"\.method\s+public\s+checkServerTrusted\("), "void"),
    (re.compile(r"\.method\s+public\s+checkClientTrusted\("), "void"),
    # OkHttp CertificatePinner.check -> void no-op
    (re.compile(r"\.method\s+public\s+(?:final\s+)?check\(Ljava/lang/String;"), "void"),
]


@dataclass
class PatchAction:
    file: str
    method: str
    kind: str  # root | emulator | pinning
    strategy: str
    applied: bool = False
    diff: str = ""


@dataclass
class PatcherResult:
    patched_apk: str = ""
    signed: bool = False
    keystore: str = ""
    actions: List[PatchAction] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    root_detection_files: List[str] = field(default_factory=list)
    emulator_detection_files: List[str] = field(default_factory=list)
    pinning_files: List[str] = field(default_factory=list)


class Patcher:
    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir

    def run(
        self,
        apktool_dir: str,
        base_apk: str,
        enable_repackage: bool = True,
    ) -> PatcherResult:
        result = PatcherResult()
        if not apktool_dir or not os.path.isdir(apktool_dir):
            log.warn("patcher: no apktool output; cannot patch smali")
            log.info(self.tools.install_hint("apktool"))
            self._detect_only_from_apk(base_apk, result)
            return result

        smali_dirs = self._smali_dirs(apktool_dir)
        if not smali_dirs:
            log.warn("patcher: no smali directories found")
            return result

        log.info("scanning smali for anti-analysis defences ...")
        self._scan_and_plan(smali_dirs, result)

        # apply patches
        applied = 0
        for action in result.actions:
            if self._apply_patch(action):
                applied += 1
        log.kv("smali patches applied", applied)

        # emit findings about what was found
        self._emit_findings(result)

        # repackage + sign
        if enable_repackage and applied > 0:
            self._repackage_and_sign(apktool_dir, result)
        elif applied == 0:
            log.info("no patchable defences found; skipping repackage")

        self._persist(result)
        return result

    # -- discovery ---------------------------------------------------------
    def _smali_dirs(self, apktool_dir: str) -> List[str]:
        out = []
        for entry in os.listdir(apktool_dir):
            if entry.startswith("smali"):
                p = os.path.join(apktool_dir, entry)
                if os.path.isdir(p):
                    out.append(p)
        return out

    def _scan_and_plan(self, smali_dirs: List[str], result: PatcherResult) -> None:
        for smali_dir in smali_dirs:
            for dirpath, _dirs, files in os.walk(smali_dir):
                for name in files:
                    if not name.endswith(".smali"):
                        continue
                    path = os.path.join(dirpath, name)
                    self._plan_file(path, result)

    def _plan_file(self, path: str, result: PatcherResult) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return

        # root detection
        if any(ind in content for ind in ROOT_STRING_INDICATORS):
            result.root_detection_files.append(path)
            # find boolean methods likely to be root checks and plan to return 0
            for m in re.finditer(
                r"\.method\s+[^\n]*?(is[A-Za-z]*Root[A-Za-z]*|checkRoot|detectRoot)"
                r"[^\n]*\)Z",
                content,
            ):
                result.actions.append(
                    PatchAction(
                        file=path,
                        method=m.group(0).strip(),
                        kind="root",
                        strategy="return false (0x0)",
                    )
                )

        # emulator detection
        if any(ind in content for ind in EMULATOR_INDICATORS):
            result.emulator_detection_files.append(path)
            for m in re.finditer(
                r"\.method\s+[^\n]*?(is[A-Za-z]*Emulator[A-Za-z]*|detectEmulator|"
                r"checkEmulator)[^\n]*\)Z",
                content,
            ):
                result.actions.append(
                    PatchAction(
                        file=path,
                        method=m.group(0).strip(),
                        kind="emulator",
                        strategy="return false (0x0)",
                    )
                )

        # pinning
        for rx, return_kind in PINNING_METHOD_PATTERNS:
            for m in rx.finditer(content):
                result.pinning_files.append(path)
                result.actions.append(
                    PatchAction(
                        file=path,
                        method=m.group(0).strip(),
                        kind="pinning",
                        strategy=f"neutralise -> {return_kind} no-op",
                    )
                )

    # -- patch application -------------------------------------------------
    def _apply_patch(self, action: PatchAction) -> bool:
        try:
            with open(action.file, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return False

        # find the method block starting at the matched header
        start = self._find_method_start(lines, action.method)
        if start is None:
            return False
        end = self._find_method_end(lines, start)
        if end is None:
            return False

        header = lines[start].rstrip("\n")
        new_body = self._stub_for(header, action.kind)
        if new_body is None:
            return False

        before = "".join(lines[start : end + 1])
        replacement = header + "\n" + new_body + "\n.end method\n"
        action.diff = self._make_diff(before, replacement)

        new_lines = lines[:start] + [replacement] + lines[end + 1 :]
        try:
            with open(action.file, "w", encoding="utf-8") as fh:
                fh.writelines(new_lines)
        except OSError:
            return False
        action.applied = True
        return True

    def _find_method_start(self, lines: List[str], header_fragment: str) -> Optional[int]:
        # header_fragment is the matched substring; locate the .method line
        frag = header_fragment.split("\n")[0].strip()
        for i, line in enumerate(lines):
            if line.strip().startswith(".method") and frag.split()[-1] in line:
                return i
        # fallback: first line containing the fragment
        for i, line in enumerate(lines):
            if frag[:40] in line:
                # walk back to .method
                j = i
                while j >= 0 and not lines[j].strip().startswith(".method"):
                    j -= 1
                return j if j >= 0 else None
        return None

    def _find_method_end(self, lines: List[str], start: int) -> Optional[int]:
        for i in range(start + 1, len(lines)):
            if lines[i].strip() == ".end method":
                return i
        return None

    def _stub_for(self, header: str, kind: str) -> Optional[str]:
        """Return a minimal valid smali body for the patched method."""
        # determine return type from header
        ret = header.rsplit(")", 1)[-1].strip()
        # registers directive needed
        if ret == "Z":  # boolean
            value = "0x0"  # false for root/emulator checks
            if kind == "safe_true":
                value = "0x1"
            return f"    .registers 2\n    const/4 v0, {value}\n    return v0"
        if ret == "V":  # void (pinning no-op)
            return "    .registers 1\n    return-void"
        if ret.startswith("L") or ret.startswith("["):  # object -> null
            return "    .registers 1\n    const/4 v0, 0x0\n    return-object v0"
        if ret == "I":
            return "    .registers 2\n    const/4 v0, 0x0\n    return v0"
        return None

    @staticmethod
    def _make_diff(before: str, after: str) -> str:
        import difflib

        diff = difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="original.smali",
            tofile="patched.smali",
            n=1,
        )
        return "".join(diff)[:2000]

    # -- repackage + sign --------------------------------------------------
    def _repackage_and_sign(self, apktool_dir: str, result: PatcherResult) -> None:
        if not self.tools.available("apktool"):
            log.warn("apktool unavailable; cannot rebuild patched APK")
            return
        out_apk = os.path.join(self.workdir, "patched-unsigned.apk")
        log.info("rebuilding APK with apktool ...")
        r = self.tools.run_tool(
            "apktool", ["b", "-f", "-o", out_apk, apktool_dir], timeout=600
        )
        if not (r.ok and os.path.isfile(out_apk)):
            log.warn(f"apktool build failed: {r.short(200)}")
            return

        signed = self._sign_apk(out_apk, result)
        if signed:
            result.patched_apk = signed
            result.signed = True
            log.good(f"patched + signed APK: {os.path.basename(signed)}")
        else:
            result.patched_apk = out_apk
            log.warn("patched APK built but could not be signed")

    def _sign_apk(self, unsigned_apk: str, result: PatcherResult) -> str:
        keystore = self._ensure_keystore()
        result.keystore = keystore
        aligned = os.path.join(self.workdir, "patched-aligned.apk")
        final = os.path.join(self.workdir, "patched-signed.apk")

        # zipalign first if available
        src = unsigned_apk
        if self.tools.available("zipalign"):
            r = self.tools.run_tool(
                "zipalign", ["-f", "-p", "4", unsigned_apk, aligned]
            )
            if r.ok and os.path.isfile(aligned):
                src = aligned

        # prefer apksigner
        if self.tools.available("apksigner") and keystore:
            shutil.copyfile(src, final)
            r = self.tools.run_tool(
                "apksigner",
                [
                    "sign",
                    "--ks", keystore,
                    "--ks-pass", "pass:apkowl",
                    "--key-pass", "pass:apkowl",
                    final,
                ],
            )
            if r.ok:
                return final

        # fall back to jarsigner
        if self.tools.available("jarsigner") and keystore:
            shutil.copyfile(src, final)
            r = self.tools.run_tool(
                "jarsigner",
                [
                    "-keystore", keystore,
                    "-storepass", "apkowl",
                    "-keypass", "apkowl",
                    "-sigalg", "SHA256withRSA",
                    "-digestalg", "SHA-256",
                    final,
                    "apkowl",
                ],
            )
            if r.ok:
                return final
        return ""

    def _ensure_keystore(self) -> str:
        keystore = os.path.join(self.workdir, "apkowl-debug.keystore")
        if os.path.isfile(keystore):
            return keystore
        if not self.tools.available("keytool"):
            log.warn("keytool unavailable; cannot generate signing keystore")
            return ""
        log.info("generating debug keystore ...")
        r = self.tools.run_tool(
            "keytool",
            [
                "-genkeypair",
                "-keystore", keystore,
                "-alias", "apkowl",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-storepass", "apkowl",
                "-keypass", "apkowl",
                "-dname", "CN=APKOwl,O=APKOwl,C=US",
            ],
        )
        if r.ok and os.path.isfile(keystore):
            return keystore
        log.warn(f"keystore generation failed: {r.short(150)}")
        return ""

    # -- detect-only path (no apktool) ------------------------------------
    def _detect_only_from_apk(self, base_apk: str, result: PatcherResult) -> None:
        log.info("running string-level detection on raw APK ...")
        if not self.tools.available("strings"):
            return
        r = self.tools.run_tool("strings", [base_apk])
        if not r.ok:
            return
        found_root = [s for s in ROOT_STRING_INDICATORS if s in r.stdout]
        found_emu = [s for s in EMULATOR_INDICATORS if s in r.stdout]
        if found_root:
            result.root_detection_files.append(base_apk)
        if found_emu:
            result.emulator_detection_files.append(base_apk)
        self._emit_findings(result)

    # -- findings ----------------------------------------------------------
    def _emit_findings(self, result: PatcherResult) -> None:
        if result.root_detection_files:
            f = Finding(
                title="Root detection present (bypassable)",
                description="The app implements root-detection logic. While a "
                "useful defence-in-depth measure, it is client-side and can be "
                "bypassed by patching smali or hooking at runtime — as this tool "
                "demonstrates.",
                module="patcher",
                severity=Severity.INFO,
                cwe="CWE-919",
                owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                remediation="Do not rely on root detection as a security "
                "control; enforce sensitive checks server-side.",
                tags=["root", "anti-tamper"],
            )
            for p in result.root_detection_files[:5]:
                f.add_evidence(file_path=p)
            result.findings.append(f)

        if result.emulator_detection_files:
            f = Finding(
                title="Emulator detection present (bypassable)",
                description="The app implements emulator/sandbox detection, "
                "which is client-side and bypassable.",
                module="patcher",
                severity=Severity.INFO,
                cwe="CWE-919",
                owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                remediation="Treat emulator detection as anti-fraud telemetry, "
                "not a security boundary.",
                tags=["emulator", "anti-tamper"],
            )
            for p in result.emulator_detection_files[:5]:
                f.add_evidence(file_path=p)
            result.findings.append(f)

        if result.pinning_files:
            f = Finding(
                title="SSL pinning present (bypassable via patching)",
                description="Certificate/trust validation routines were located "
                "in smali and can be neutralised by repackaging, demonstrating "
                "that pinning alone does not stop a determined local attacker.",
                module="patcher",
                severity=Severity.INFO,
                cwe="CWE-295",
                owasp=OWASPMobile.M5_INSECURE_COMMUNICATION,
                remediation="Combine pinning with server-side anomaly detection; "
                "pinning raises the bar but is not absolute.",
                tags=["pinning", "anti-tamper"],
            )
            for p in set(result.pinning_files[:5]):
                f.add_evidence(file_path=p)
            result.findings.append(f)

    # -- persistence -------------------------------------------------------
    def _persist(self, result: PatcherResult) -> None:
        if result.patched_apk and os.path.isfile(result.patched_apk):
            self.db.add_artifact(
                "patched_apk",
                result.patched_apk,
                size=os.path.getsize(result.patched_apk),
                note="repackaged + re-signed with anti-analysis patches",
            )
        for action in result.actions:
            if action.applied and action.diff:
                diff_path = os.path.join(
                    self.workdir,
                    f"patch-{action.kind}-{os.path.basename(action.file)}.diff",
                )
                try:
                    with open(diff_path, "w", encoding="utf-8") as fh:
                        fh.write(action.diff)
                    self.db.add_artifact("smali_patch", diff_path, note=action.kind)
                except OSError:
                    pass
        self.db.set_kv(
            "patch_summary",
            {
                "root_files": len(result.root_detection_files),
                "emulator_files": len(result.emulator_detection_files),
                "pinning_files": len(set(result.pinning_files)),
                "patches_applied": sum(1 for a in result.actions if a.applied),
                "signed": result.signed,
            },
        )
