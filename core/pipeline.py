"""
APKOwl :: core.pipeline
=======================

The orchestrator. It runs the twelve analysis phases in order, threading a
shared :class:`ScanContext` between them, persisting findings to the database as
they are discovered, and finishing with the report generator.

Phase map
---------
 1. Extraction          (modules.extractor)
 2. Manifest analysis   (modules.manifest)
 3. Secret scanning     (modules.secrets)
 4. Certs & crypto      (modules.certs)
 5. Smali patching      (modules.patcher)        [active]
 6. Frida toolkit       (modules.frida_gen)      [active]
 7. Traffic / API tests (modules.traffic)        [active]
 8. Intent / deeplink   (modules.intents)        [active]
 9. Device storage      (modules.storage)        [active]
10. Native libraries    (modules.native)
11. Obfuscation / SDKs  (modules.obfuscation)
12. Reporting           (modules.reporter)

"Active" phases interact with a device/network when one is available and the
relevant mode flags are set; otherwise they degrade to static output. Each phase
is wrapped so that an exception in one never aborts the whole run — it is logged,
recorded, and the pipeline continues.
"""

from __future__ import annotations

import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.db import Database
from core.findings import Finding
from core.logger import log
from core.toolrunner import ToolRunner

from modules.extractor import Extractor, ExtractionResult
from modules.manifest import ManifestAnalyzer, ManifestResult
from modules.secrets import SecretScanner, SecretsResult
from modules.certs import CertAnalyzer, CertsResult
from modules.resources import ResourceAnalyzer, ResourcesResult
from modules.patcher import Patcher, PatcherResult
from modules.frida_gen import FridaGenerator, FridaResult
from modules.traffic import TrafficAnalyzer, TrafficResult
from modules.intents import IntentTester, IntentsResult
from modules.storage import StorageAnalyzer, StorageResult
from modules.native import NativeAnalyzer, NativeResult
from modules.obfuscation import ObfuscationAnalyzer, ObfuscationResult
from modules.privacy import PrivacyAnalyzer, PrivacyResult
from modules.reporter import Reporter, ReportResult
from plugins.base import run_plugins


TOTAL_PHASES = 12


@dataclass
class PipelineConfig:
    """All the knobs the CLI can set."""

    output_dir: str
    workdir: str
    device_mode: bool = True          # allow adb/frida/device interaction
    allow_active_http: bool = False   # allow outbound HTTP endpoint testing
    enable_repackage: bool = True     # rebuild + sign patched APK
    inject_seconds: int = 20
    capture_seconds: int = 30
    proxy_port: int = 8080
    skip_phases: List[int] = field(default_factory=list)
    tool_version: str = "1.0.0"


@dataclass
class ScanContext:
    """Shared state handed from phase to phase."""

    input_path: str
    extraction: Optional[ExtractionResult] = None
    manifest: Optional[ManifestResult] = None
    secrets: Optional[SecretsResult] = None
    certs: Optional[CertsResult] = None
    resources: Optional[ResourcesResult] = None
    patcher: Optional[PatcherResult] = None
    frida: Optional[FridaResult] = None
    traffic: Optional[TrafficResult] = None
    intents: Optional[IntentsResult] = None
    storage: Optional[StorageResult] = None
    native: Optional[NativeResult] = None
    obfuscation: Optional[ObfuscationResult] = None
    privacy: Optional[PrivacyResult] = None
    report: Optional[ReportResult] = None
    errors: List[str] = field(default_factory=list)

    @property
    def package(self) -> str:
        if self.manifest and self.manifest.package:
            return self.manifest.package
        return ""

    @property
    def code_roots(self) -> List[str]:
        roots: List[str] = []
        if self.extraction:
            roots.extend(self.extraction.smali_dirs)
            jr = self.extraction.java_root
            if jr:
                roots.append(jr)
        return [r for r in roots if r]


class Pipeline:
    def __init__(self, tools: ToolRunner, db: Database, config: PipelineConfig) -> None:
        self.tools = tools
        self.db = db
        self.config = config

    # -- orchestration -----------------------------------------------------
    def run(self, input_path: str) -> ScanContext:
        ctx = ScanContext(input_path=input_path)
        start = time.time()

        self._phase(1, "Extraction", ctx, self._phase_extract)
        self._phase(2, "Manifest analysis", ctx, self._phase_manifest)
        self._phase(3, "Secret scanning", ctx, self._phase_secrets)
        self._phase(4, "Certificates & cryptography", ctx, self._phase_certs)
        self._phase(5, "Anti-analysis patching", ctx, self._phase_patch)
        self._phase(6, "Frida instrumentation", ctx, self._phase_frida)
        self._phase(7, "Traffic & API testing", ctx, self._phase_traffic)
        self._phase(8, "Intent & deeplink attacks", ctx, self._phase_intents)
        self._phase(9, "Device storage analysis", ctx, self._phase_storage)
        self._phase(10, "Native library analysis", ctx, self._phase_native)
        self._phase(11, "Obfuscation & SDKs", ctx, self._phase_obfuscation)
        self._run_plugins(ctx)
        self._phase(12, "Reporting", ctx, self._phase_report)

        elapsed = time.time() - start
        self.db.set_kv("scan_duration_seconds", round(elapsed, 1))
        self.db.set_kv("phase_errors", ctx.errors)
        status = "completed_with_errors" if ctx.errors else "completed"
        self.db.finish_scan(status)
        log.kv("total time", f"{elapsed:.1f}s")
        if ctx.errors:
            log.warn(f"{len(ctx.errors)} phase(s) reported errors; see report")
        return ctx

    def _phase(self, index: int, name: str, ctx: ScanContext, fn) -> None:
        if index in self.config.skip_phases:
            log.phase(index, TOTAL_PHASES, f"{name} (skipped)")
            return
        log.phase(index, TOTAL_PHASES, name)
        try:
            fn(ctx)
        except Exception as exc:  # never let one phase kill the run
            msg = f"phase {index} ({name}) failed: {exc}"
            ctx.errors.append(msg)
            log.error(msg)
            log.debug(traceback.format_exc())

    # -- helpers -----------------------------------------------------------
    def _commit(self, findings: List[Finding]) -> None:
        if findings:
            self.db.add_findings(findings)

    def _active(self) -> bool:
        return self.config.device_mode

    # -- phase implementations --------------------------------------------
    def _phase_extract(self, ctx: ScanContext) -> None:
        ex = Extractor(self.tools, self.db, self.config.workdir)
        ctx.extraction = ex.run(ctx.input_path)
        self._commit(ctx.extraction.findings)
        # record core scan metadata as soon as we know it
        self.db.update_scan_hashes(
            apk_sha256=ctx.extraction.apk_sha256,
            apk_md5=ctx.extraction.apk_md5,
            apk_size=ctx.extraction.apk_size,
        )

    def _phase_manifest(self, ctx: ScanContext) -> None:
        if not ctx.extraction:
            log.warn("no extraction result; skipping manifest")
            return
        an = ManifestAnalyzer(self.db)
        ctx.manifest = an.run(
            ctx.extraction.manifest_decoded,
            ctx.extraction.manifest_binary,
        )
        self._commit(ctx.manifest.findings)
        # persist profile metadata for the report
        self.db.update_scan_meta(
            package_name=ctx.manifest.package,
            version_name=ctx.manifest.version_name,
            version_code=ctx.manifest.version_code,
        )
        self.db.set_kv("permissions", ctx.manifest.permissions_used)
        self.db.set_kv(
            "components",
            [
                {
                    "name": c.name,
                    "type": c.type,
                    "exported": c.effectively_exported,
                    "permission": c.permission,
                    "authority": c.authorities,
                    "actions": c.intent_actions,
                }
                for c in ctx.manifest.components
            ],
        )
        self.db.set_kv("deeplinks", ctx.manifest.deeplinks)

    def _phase_secrets(self, ctx: ScanContext) -> None:
        roots = ctx.code_roots
        if ctx.extraction and ctx.extraction.unzip_dir:
            roots = roots + [ctx.extraction.unzip_dir]
        sc = SecretScanner(self.db)
        ctx.secrets = sc.run(roots)
        self._commit(ctx.secrets.findings)
        # resource/asset deep-scan rides along with the secret phase
        if ctx.extraction:
            ra = ResourceAnalyzer(self.db)
            ctx.resources = ra.run(
                ctx.extraction.unzip_dir,
                ctx.extraction.apktool_dir,
            )
            self._commit(ctx.resources.findings)

    def _phase_certs(self, ctx: ScanContext) -> None:
        if not ctx.extraction:
            return
        nsc = ctx.manifest.network_security_config if ctx.manifest else ""
        ca = CertAnalyzer(self.tools, self.db)
        ca._source_apk = ctx.extraction.base_apk
        ctx.certs = ca.run(
            ctx.extraction.unzip_dir,
            ctx.extraction.apktool_dir,
            ctx.code_roots,
            nsc,
        )
        self._commit(ctx.certs.findings)

    def _phase_patch(self, ctx: ScanContext) -> None:
        if not ctx.extraction:
            return
        pt = Patcher(self.tools, self.db, self.config.workdir)
        ctx.patcher = pt.run(
            ctx.extraction.apktool_dir,
            ctx.extraction.base_apk,
            enable_repackage=self.config.enable_repackage,
        )
        self._commit(ctx.patcher.findings)

    def _phase_frida(self, ctx: ScanContext) -> None:
        if not ctx.package:
            log.warn("no package name; skipping Frida generation")
            return
        fg = FridaGenerator(self.tools, self.db, self.config.workdir)
        ctx.frida = fg.run(
            ctx.package,
            enable_injection=self._active(),
            inject_seconds=self.config.inject_seconds,
        )
        self._commit(ctx.frida.findings)

    def _phase_traffic(self, ctx: ScanContext) -> None:
        static_endpoints: List[str] = []
        if ctx.secrets:
            static_endpoints = sorted(ctx.secrets.endpoints)
        ta = TrafficAnalyzer(self.tools, self.db, self.config.workdir)
        ctx.traffic = ta.run(
            static_endpoints,
            enable_intercept=self._active(),
            allow_active_http=self.config.allow_active_http,
            proxy_port=self.config.proxy_port,
            capture_seconds=self.config.capture_seconds,
        )
        self._commit(ctx.traffic.findings)

    def _phase_intents(self, ctx: ScanContext) -> None:
        if not ctx.package or not ctx.manifest:
            return
        components = [
            {
                "name": c.name,
                "type": c.type,
                "exported": c.effectively_exported,
                "authority": c.authorities,
                "actions": c.intent_actions,
            }
            for c in ctx.manifest.components
        ]
        it = IntentTester(self.tools, self.db, self.config.workdir)
        ctx.intents = it.run(
            ctx.package,
            components,
            ctx.manifest.deeplinks,
            enable_dynamic=self._active(),
        )
        self._commit(ctx.intents.findings)

    def _phase_storage(self, ctx: ScanContext) -> None:
        st = StorageAnalyzer(self.tools, self.db, self.config.workdir)
        ctx.storage = st.run(
            ctx.package,
            ctx.code_roots,
            enable_dynamic=self._active(),
        )
        self._commit(ctx.storage.findings)

    def _phase_native(self, ctx: ScanContext) -> None:
        so_files = ctx.extraction.so_files if ctx.extraction else []
        na = NativeAnalyzer(self.tools, self.db)
        ctx.native = na.run(so_files)
        self._commit(ctx.native.findings)

    def _phase_obfuscation(self, ctx: ScanContext) -> None:
        smali_dirs = ctx.extraction.smali_dirs if ctx.extraction else []
        java_root = ctx.extraction.java_root if ctx.extraction else ""
        precomputed = ctx.extraction.obfuscation if ctx.extraction else {}
        ob = ObfuscationAnalyzer(self.db)
        ctx.obfuscation = ob.run(smali_dirs, java_root, precomputed)
        self._commit(ctx.obfuscation.findings)
        # privacy/permission correlation uses the SDKs obfuscation just found
        sdks = self.db.get_kv("sdks", {})
        permissions = ctx.manifest.permissions_used if ctx.manifest else []
        custom = ctx.manifest.custom_permissions if ctx.manifest else []
        pa = PrivacyAnalyzer(self.db)
        ctx.privacy = pa.run(permissions, custom, sdks)
        self._commit(ctx.privacy.findings)

    def _phase_report(self, ctx: ScanContext) -> None:
        rep = Reporter(self.db, self.config.output_dir, self.config.tool_version)
        ctx.report = rep.run()

    def _run_plugins(self, ctx: ScanContext) -> None:
        """Discover and run user plugins, persisting their findings."""
        log.phase(11, TOTAL_PHASES, "User plugins")
        try:
            findings = run_plugins(ctx)
            self._commit(findings)
        except Exception as exc:
            msg = f"plugin stage failed: {exc}"
            ctx.errors.append(msg)
            log.error(msg)
