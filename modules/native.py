"""
APKOwl :: modules.native
========================

Phase 10 — analyse the native libraries (``lib/<abi>/*.so``) bundled with the
app.

For each ELF shared object it:

* identifies architecture and basic ELF metadata,
* runs ``strings`` and harvests URLs, secret-looking tokens and interesting
  paths embedded in the binary,
* lists imported symbols (via ``nm`` / ``readelf``) and flags dangerous libc
  functions (strcpy, strcat, sprintf, gets, system, popen, exec*, memcpy with
  no bound),
* performs a checksec-style hardening assessment: NX, stack canary
  (``__stack_chk_fail``), PIE (ET_DYN + ``DF_1_PIE``), RELRO (GNU_RELRO +
  BIND_NOW), FORTIFY (``*_chk`` symbols),
* detects JNI entry points (``JNI_OnLoad``, ``Java_*``) and anti-debug
  primitives (ptrace).

Everything is driven through binutils, which is almost always present on Parrot;
when a specific tool is missing the relevant sub-check is skipped and noted.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner
from signatures.secrets_db import SECRET_PATTERNS, URL_PATTERNS, is_noise_url


DANGEROUS_FUNCS = {
    "strcpy": "unbounded string copy",
    "strcat": "unbounded string concat",
    "sprintf": "unbounded formatted write",
    "vsprintf": "unbounded formatted write",
    "gets": "no bounds checking at all",
    "scanf": "can overflow without width specifier",
    "system": "command execution",
    "popen": "command execution",
    "execve": "command execution",
    "execl": "command execution",
    "dlopen": "dynamic code loading",
    "memcpy": "verify length is bounded",
    "strncpy": "verify NUL-termination",
}

ANTIDEBUG_SYMBOLS = {"ptrace", "PTRACE_TRACEME", "kill", "getppid"}


@dataclass
class NativeLib:
    path: str
    abi: str = ""
    arch: str = ""
    is_pie: bool = False
    has_canary: bool = False
    nx: bool = True
    relro: str = "none"  # none | partial | full
    fortified: bool = False
    dangerous: List[str] = field(default_factory=list)
    jni_entries: List[str] = field(default_factory=list)
    antidebug: List[str] = field(default_factory=list)
    strings_urls: List[str] = field(default_factory=list)


@dataclass
class NativeResult:
    libs: List[NativeLib] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class NativeAnalyzer:
    def __init__(self, tools: ToolRunner, db: Database) -> None:
        self.tools = tools
        self.db = db

    def run(self, so_files: List[str]) -> NativeResult:
        result = NativeResult()
        if not so_files:
            log.info("no native libraries present")
            return result
        log.kv("native libraries", len(so_files))
        # de-dup identical libs across ABIs by basename+size
        seen: Set[str] = set()
        for so in so_files:
            try:
                key = f"{os.path.basename(so)}:{os.path.getsize(so)}"
            except OSError:
                key = so
            if key in seen:
                continue
            seen.add(key)
            lib = self._analyze_lib(so)
            if lib:
                result.libs.append(lib)
                self._evaluate(lib, result)
        self._persist(result)
        log.good(f"native phase produced {len(result.findings)} finding(s)")
        return result

    # -- per-lib -----------------------------------------------------------
    def _analyze_lib(self, path: str) -> Optional[NativeLib]:
        lib = NativeLib(path=path)
        lib.abi = self._abi_from_path(path)
        self._parse_elf_header(path, lib)
        self._analyze_symbols(path, lib)
        self._analyze_strings(path, lib)
        self._analyze_hardening(path, lib)
        return lib

    def _abi_from_path(self, path: str) -> str:
        for abi in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "mips"):
            if f"/{abi}/" in path.replace("\\", "/"):
                return abi
        return ""

    def _parse_elf_header(self, path: str, lib: NativeLib) -> None:
        try:
            with open(path, "rb") as fh:
                hdr = fh.read(20)
        except OSError:
            return
        if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
            return
        ei_class = hdr[4]  # 1=32bit 2=64bit
        e_type = struct.unpack_from("<H", hdr, 16)[0]
        machine = struct.unpack_from("<H", hdr, 18)[0]
        lib.is_pie = e_type == 3  # ET_DYN (refined below by readelf)
        machines = {0x28: "ARM", 0xB7: "AArch64", 0x03: "x86", 0x3E: "x86-64", 0x08: "MIPS"}
        lib.arch = machines.get(machine, f"0x{machine:x}")
        if ei_class == 2 and not lib.arch:
            lib.arch = "64-bit"

    def _analyze_symbols(self, path: str, lib: NativeLib) -> None:
        symbols = self._symbols(path)
        if not symbols:
            return
        for sym in symbols:
            base = sym.lstrip("_")
            if base in DANGEROUS_FUNCS:
                if base not in lib.dangerous:
                    lib.dangerous.append(base)
            if sym == "JNI_OnLoad" or sym.startswith("Java_"):
                lib.jni_entries.append(sym)
            if base in ANTIDEBUG_SYMBOLS:
                lib.antidebug.append(base)
            if base == "__stack_chk_fail":
                lib.has_canary = True
            if base.endswith("_chk"):
                lib.fortified = True

    def _symbols(self, path: str) -> List[str]:
        """Return all dynamic symbols (imports + exports), version-stripped."""
        out: List[str] = []
        if self.tools.available("nm"):
            # -D = dynamic symbols; we want BOTH defined (exports) and
            # undefined (imports), since dangerous libc calls appear as imports.
            r = self.tools.run_tool("nm", ["-D", path])
            if r.ok:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if parts:
                        out.append(self._clean_symbol(parts[-1]))
        if not out and self.tools.available("readelf"):
            r = self.tools.run_tool("readelf", ["-W", "--dyn-syms", path])
            if r.ok:
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 8:
                        out.append(self._clean_symbol(parts[-1]))
        return out

    @staticmethod
    def _clean_symbol(sym: str) -> str:
        # strip GLIBC/version suffix: "strcpy@GLIBC_2.2.5" -> "strcpy"
        return sym.split("@")[0]

    def _analyze_strings(self, path: str, lib: NativeLib) -> None:
        if not self.tools.available("strings"):
            return
        r = self.tools.run_tool("strings", ["-n", "6", path], timeout=60)
        if not r.ok:
            return
        urls: Set[str] = set()
        for line in r.stdout.splitlines():
            for upat in URL_PATTERNS:
                for m in upat.finditer(line):
                    u = m.group(0)
                    if not is_noise_url(u):
                        urls.add(u)
            # secret scan on native strings (high value!)
            for pattern in SECRET_PATTERNS:
                hits = pattern.scan_line(line)
                for value in hits:
                    lib._secret = True  # marker; finding emitted in _evaluate
        lib.strings_urls = sorted(urls)[:50]

    def _analyze_hardening(self, path: str, lib: NativeLib) -> None:
        if not self.tools.available("readelf"):
            return
        r = self.tools.run_tool("readelf", ["-W", "-l", "-d", "-h", path], timeout=60)
        if not r.ok:
            return
        out = r.stdout
        # NX: GNU_STACK without RWE
        lib.nx = "GNU_STACK" in out and "RWE" not in out
        # PIE: ET_DYN + FLAGS_1 PIE, or Type: DYN
        if "Type:" in out:
            type_line = next((l for l in out.splitlines() if "Type:" in l), "")
            lib.is_pie = "DYN" in type_line
        if "PIE" in out:
            lib.is_pie = True
        # RELRO
        if "GNU_RELRO" in out:
            if "BIND_NOW" in out or "FLAGS" in out and "BIND_NOW" in out:
                lib.relro = "full"
            else:
                lib.relro = "partial"

    # -- evaluation --------------------------------------------------------
    def _evaluate(self, lib: NativeLib, result: NativeResult) -> None:
        name = os.path.basename(lib.path)
        log.kv(f"  {name}", f"{lib.arch or lib.abi} pie={lib.is_pie} "
               f"canary={lib.has_canary} nx={lib.nx} relro={lib.relro}")

        # dangerous functions
        high_risk = [f for f in lib.dangerous if f in
                     ("strcpy", "strcat", "sprintf", "gets", "system", "popen")]
        for func in high_risk:
            result.findings.append(
                FindingTemplates.insecure_native(func).add_evidence(
                    file_path=lib.path,
                    snippet=f"{func}: {DANGEROUS_FUNCS[func]}",
                )
            )

        # hardening gaps
        if not lib.has_canary:
            result.findings.append(
                Finding(
                    title=f"Native library lacks stack canaries: {name}",
                    description="No __stack_chk_fail symbol was found, suggesting "
                    "the library was built without stack-smashing protection.",
                    module="native",
                    severity=Severity.LOW,
                    cwe="CWE-1326",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Compile with -fstack-protector-strong.",
                    tags=["native", "hardening"],
                ).add_evidence(file_path=lib.path)
            )
        if not lib.is_pie:
            result.findings.append(
                Finding(
                    title=f"Native library not position-independent (no PIE): {name}",
                    description="The library is not built as PIE, weakening ASLR.",
                    module="native",
                    severity=Severity.LOW,
                    cwe="CWE-1277",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Build with -fPIE -pie.",
                    tags=["native", "hardening"],
                ).add_evidence(file_path=lib.path)
            )
        if lib.relro != "full":
            result.findings.append(
                Finding(
                    title=f"Native library has {lib.relro or 'no'} RELRO: {name}",
                    description="Partial or missing RELRO leaves the GOT writable, "
                    "easing certain exploitation techniques.",
                    module="native",
                    severity=Severity.INFO,
                    cwe="CWE-1326",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Link with -Wl,-z,relro,-z,now for full RELRO.",
                    tags=["native", "hardening"],
                ).add_evidence(file_path=lib.path)
            )

        # secrets in native strings
        if getattr(lib, "_secret", False):
            result.findings.append(
                FindingTemplates.hardcoded_secret("credential in native library").add_evidence(
                    file_path=lib.path,
                    snippet="secret-pattern match in .so strings",
                )
            )

        # urls
        for u in lib.strings_urls:
            self.db.add_endpoint(u, "", source="native")

        # anti-debug
        if "ptrace" in lib.antidebug:
            result.findings.append(
                Finding(
                    title=f"Native anti-debugging (ptrace) in {name}",
                    description="The library calls ptrace, commonly used as an "
                    "anti-debugging measure. Bypassable but recorded.",
                    module="native",
                    severity=Severity.INFO,
                    cwe="CWE-919",
                    owasp=OWASPMobile.M7_INSUFFICIENT_BINARY_PROTECTION,
                    remediation="Anti-debugging is defence-in-depth only.",
                    tags=["native", "anti-debug"],
                ).add_evidence(file_path=lib.path)
            )

    # -- persistence -------------------------------------------------------
    def _persist(self, result: NativeResult) -> None:
        self.db.set_kv(
            "native_libs",
            [
                {
                    "name": os.path.basename(l.path),
                    "abi": l.abi,
                    "arch": l.arch,
                    "pie": l.is_pie,
                    "canary": l.has_canary,
                    "nx": l.nx,
                    "relro": l.relro,
                    "dangerous": l.dangerous,
                    "jni": len(l.jni_entries),
                }
                for l in result.libs
            ],
        )
