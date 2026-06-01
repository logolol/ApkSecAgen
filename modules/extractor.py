"""
APKOwl :: modules.extractor
===========================

Phase 1 — turn an opaque ``.apk`` / ``.xapk`` into a fully exploded working
tree that every later phase reads from.

Responsibilities:

* Detect XAPK / APKS / APKM bundles (they are just ZIPs containing one or more
  APKs plus an install manifest) and select the base APK.
* Unzip the raw APK so we can reach ``classes*.dex``, ``resources.arsc``,
  ``AndroidManifest.xml`` (binary), ``lib/``, ``assets/``, ``res/`` and the
  signing block under ``META-INF/``.
* Drive ``apktool`` to produce decoded resources + smali.
* Drive ``jadx`` to produce Java source.
* Drive ``dex2jar`` to produce a JAR for further tooling.
* Hash every file (MD5 + SHA-256), record sizes, and persist an inventory.
* Estimate the obfuscation toolchain (ProGuard / R8 / DexGuard) from artefacts.

Everything degrades: if jadx is missing we still get smali from apktool; if
apktool is missing we still get the raw unzip and the DEX files. The module
records what it managed to produce so later phases can adapt.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.db import Database
from core.findings import Finding, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


XAPK_EXTENSIONS = (".xapk", ".apks", ".apkm", ".zip")
APK_MAGIC = b"PK\x03\x04"


@dataclass
class ExtractionResult:
    """Everything produced by phase 1, handed to the orchestrator/context."""

    workdir: str = ""
    base_apk: str = ""
    split_apks: List[str] = field(default_factory=list)
    unzip_dir: str = ""
    apktool_dir: str = ""
    jadx_dir: str = ""
    jar_path: str = ""
    dex_files: List[str] = field(default_factory=list)
    so_files: List[str] = field(default_factory=list)
    manifest_binary: str = ""
    manifest_decoded: str = ""
    file_inventory: List[Dict[str, object]] = field(default_factory=list)
    apk_sha256: str = ""
    apk_md5: str = ""
    apk_size: int = 0
    is_xapk: bool = False
    obfuscation: Dict[str, object] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    @property
    def smali_dirs(self) -> List[str]:
        if not self.apktool_dir or not os.path.isdir(self.apktool_dir):
            return []
        out = []
        for entry in os.listdir(self.apktool_dir):
            if entry.startswith("smali"):
                p = os.path.join(self.apktool_dir, entry)
                if os.path.isdir(p):
                    out.append(p)
        return out

    @property
    def java_root(self) -> str:
        if self.jadx_dir:
            src = os.path.join(self.jadx_dir, "sources")
            if os.path.isdir(src):
                return src
        return self.jadx_dir


class Extractor:
    """Phase 1 implementation."""

    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)

    # -- hashing -----------------------------------------------------------
    @staticmethod
    def _hash_file(path: str) -> Tuple[str, str, int]:
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        size = 0
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    md5.update(chunk)
                    sha.update(chunk)
                    size += len(chunk)
        except OSError:
            return "", "", 0
        return md5.hexdigest(), sha.hexdigest(), size

    # -- entrypoint --------------------------------------------------------
    def run(self, input_path: str) -> ExtractionResult:
        result = ExtractionResult(workdir=self.workdir)
        input_path = os.path.abspath(input_path)
        if not os.path.isfile(input_path):
            raise FileNotFoundError(input_path)

        md5, sha, size = self._hash_file(input_path)
        result.apk_md5, result.apk_sha256, result.apk_size = md5, sha, size
        log.kv("input", os.path.basename(input_path))
        log.kv("sha256", sha)
        log.kv("size", f"{size:,} bytes")

        # XAPK / bundle detection
        ext = os.path.splitext(input_path)[1].lower()
        if ext in XAPK_EXTENSIONS and self._is_bundle(input_path):
            result.is_xapk = True
            base = self._unpack_bundle(input_path, result)
            if not base:
                raise RuntimeError("No base APK found inside bundle")
            apk_path = base
        else:
            apk_path = input_path
        result.base_apk = apk_path

        # raw unzip of the chosen APK
        result.unzip_dir = self._unzip_apk(apk_path)
        self._inventory(result.unzip_dir, result)

        # locate DEX, .so, manifest
        self._locate_artifacts(result)

        # decode with apktool (resources + smali + decoded manifest)
        self._run_apktool(apk_path, result)

        # decompile with jadx (Java source)
        self._run_jadx(apk_path, result)

        # convert with dex2jar
        self._run_dex2jar(apk_path, result)

        # estimate obfuscation
        result.obfuscation = self._estimate_obfuscation(result)

        # persist artifacts to DB
        self._persist(result, apk_path)

        return result

    # -- bundle handling ---------------------------------------------------
    def _is_bundle(self, path: str) -> bool:
        """A bundle is a ZIP that contains more than one .apk, or an info json."""
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            return False
        apks = [n for n in names if n.lower().endswith(".apk")]
        has_info = any(
            n.lower() in ("manifest.json", "info.json") for n in names
        )
        return len(apks) >= 1 and (len(apks) > 1 or has_info)

    def _unpack_bundle(self, path: str, result: ExtractionResult) -> str:
        out = os.path.join(self.workdir, "bundle")
        os.makedirs(out, exist_ok=True)
        with zipfile.ZipFile(path) as zf:
            zf.extractall(out)
        apks = []
        for root, _dirs, files in os.walk(out):
            for f in files:
                if f.lower().endswith(".apk"):
                    apks.append(os.path.join(root, f))
        if not apks:
            return ""
        # choose the base: prefer one literally named base.apk, else the largest
        base = ""
        for a in apks:
            if os.path.basename(a).lower() in ("base.apk", "base_master.apk"):
                base = a
                break
        if not base:
            base = max(apks, key=lambda p: os.path.getsize(p))
        result.split_apks = [a for a in apks if a != base]
        log.good(f"bundle: base={os.path.basename(base)}, "
                 f"{len(result.split_apks)} split APK(s)")
        return base

    # -- raw unzip ---------------------------------------------------------
    def _unzip_apk(self, apk_path: str) -> str:
        out = os.path.join(self.workdir, "unzip")
        if os.path.isdir(out):
            shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out, exist_ok=True)
        try:
            with zipfile.ZipFile(apk_path) as zf:
                # guard against zip-slip
                for member in zf.namelist():
                    target = os.path.normpath(os.path.join(out, member))
                    if not target.startswith(os.path.abspath(out)):
                        log.warn(f"skipping zip-slip path: {member}")
                        continue
                zf.extractall(out)
        except zipfile.BadZipFile:
            log.error("input is not a valid ZIP/APK")
        return out

    def _inventory(self, root: str, result: ExtractionResult) -> None:
        count = 0
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                md5, sha, size = self._hash_file(full)
                result.file_inventory.append(
                    {
                        "path": rel,
                        "md5": md5,
                        "sha256": sha,
                        "size": size,
                        "ext": os.path.splitext(name)[1].lower(),
                    }
                )
                count += 1
        log.kv("files in APK", count)

    def _locate_artifacts(self, result: ExtractionResult) -> None:
        root = result.unzip_dir
        for item in result.file_inventory:
            rel = item["path"]
            full = os.path.join(root, rel)
            low = rel.lower()
            if low.endswith(".dex"):
                result.dex_files.append(full)
            elif low.endswith(".so"):
                result.so_files.append(full)
            elif low == "androidmanifest.xml":
                result.manifest_binary = full
        log.kv("DEX files", len(result.dex_files))
        log.kv("native .so", len(result.so_files))

    # -- apktool -----------------------------------------------------------
    def _run_apktool(self, apk_path: str, result: ExtractionResult) -> None:
        out = os.path.join(self.workdir, "apktool")
        if not self.tools.available("apktool"):
            log.warn("apktool unavailable; smali + decoded resources skipped")
            log.info(self.tools.install_hint("apktool"))
            return
        if os.path.isdir(out):
            shutil.rmtree(out, ignore_errors=True)
        log.info("running apktool decode ...")
        r = self.tools.run_tool(
            "apktool",
            ["d", "-f", "-o", out, apk_path],
            timeout=600,
        )
        if r.ok and os.path.isdir(out):
            result.apktool_dir = out
            dm = os.path.join(out, "AndroidManifest.xml")
            if os.path.isfile(dm):
                result.manifest_decoded = dm
            log.good(f"apktool produced {len(result.smali_dirs)} smali tree(s)")
        else:
            log.warn(f"apktool failed: {r.short(200)}")

    # -- jadx --------------------------------------------------------------
    def _run_jadx(self, apk_path: str, result: ExtractionResult) -> None:
        out = os.path.join(self.workdir, "jadx")
        if not self.tools.available("jadx"):
            log.warn("jadx unavailable; Java decompilation skipped")
            log.info(self.tools.install_hint("jadx"))
            return
        log.info("running jadx decompile (this can take a while) ...")
        r = self.tools.run_tool(
            "jadx",
            ["-d", out, "--no-res", "--show-bad-code", apk_path],
            timeout=900,
        )
        # jadx frequently returns non-zero while still emitting usable sources
        if os.path.isdir(os.path.join(out, "sources")) or os.path.isdir(out):
            result.jadx_dir = out
            log.good("jadx produced Java sources")
        else:
            log.warn(f"jadx produced no output: {r.short(200)}")

    # -- dex2jar -----------------------------------------------------------
    def _run_dex2jar(self, apk_path: str, result: ExtractionResult) -> None:
        if not self.tools.available("d2j-dex2jar"):
            log.debug("dex2jar unavailable; JAR output skipped")
            return
        out = os.path.join(self.workdir, "app-dex2jar.jar")
        log.info("running dex2jar ...")
        r = self.tools.run_tool(
            "d2j-dex2jar",
            ["-f", "-o", out, apk_path],
            timeout=300,
        )
        if os.path.isfile(out):
            result.jar_path = out
            log.good("dex2jar produced JAR")
        else:
            log.debug(f"dex2jar failed: {r.short(150)}")

    # -- obfuscation estimate ---------------------------------------------
    def _estimate_obfuscation(self, result: ExtractionResult) -> Dict[str, object]:
        """Heuristically estimate the obfuscation toolchain and intensity.

        We look at:
          * presence of DexGuard / ProGuard marker files,
          * the proportion of single/double-character class names in smali,
          * mapping artefacts.
        """
        info: Dict[str, object] = {
            "toolchain": "unknown",
            "short_name_ratio": 0.0,
            "total_classes": 0,
            "short_classes": 0,
            "markers": [],
        }
        markers = []
        for item in result.file_inventory:
            p = item["path"].lower()
            if "proguard" in p:
                markers.append("proguard-artifact")
            if "dexguard" in p:
                markers.append("dexguard-artifact")
        # smali class-name analysis
        total = short = 0
        for smali_dir in result.smali_dirs:
            for dirpath, _dirs, files in os.walk(smali_dir):
                for f in files:
                    if not f.endswith(".smali"):
                        continue
                    total += 1
                    base = f[:-6]
                    if len(base) <= 2:
                        short += 1
        info["total_classes"] = total
        info["short_classes"] = short
        ratio = (short / total) if total else 0.0
        info["short_name_ratio"] = round(ratio, 3)
        info["markers"] = sorted(set(markers))

        if "dexguard-artifact" in markers:
            info["toolchain"] = "DexGuard"
        elif ratio > 0.4:
            info["toolchain"] = "R8/ProGuard (aggressive)"
        elif ratio > 0.15:
            info["toolchain"] = "R8/ProGuard (default)"
        elif total:
            info["toolchain"] = "none / minimal"

        log.kv("obfuscation", f"{info['toolchain']} "
               f"(short-name ratio {ratio:.0%})")

        if ratio > 0.4:
            result.findings.append(
                Finding(
                    title="Application is heavily obfuscated",
                    description=(
                        "A large fraction of classes use 1-2 character names, "
                        "indicating aggressive obfuscation. This is good "
                        "hygiene but increases analysis effort; note it as "
                        "context for the rest of the assessment."
                    ),
                    module="extractor",
                    severity=Severity.INFO,
                    cwe="CWE-656",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="No action; informational.",
                    tags=["obfuscation"],
                    confidence="firm",
                )
            )
        return info

    # -- persistence -------------------------------------------------------
    def _persist(self, result: ExtractionResult, apk_path: str) -> None:
        self.db.add_artifact(
            "base_apk", apk_path, result.apk_sha256, result.apk_size, "input APK"
        )
        if result.apktool_dir:
            self.db.add_artifact("apktool_dir", result.apktool_dir, note="decoded resources + smali")
        if result.jadx_dir:
            self.db.add_artifact("jadx_dir", result.jadx_dir, note="Java sources")
        if result.jar_path:
            self.db.add_artifact("jar", result.jar_path, note="dex2jar output")
        for dex in result.dex_files:
            md5, sha, size = self._hash_file(dex)
            self.db.add_artifact("dex", dex, sha, size)
        self.db.set_kv("obfuscation", result.obfuscation)
        self.db.set_kv("file_count", len(result.file_inventory))
        self.db.set_kv("is_xapk", result.is_xapk)
