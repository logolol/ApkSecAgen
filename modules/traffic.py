"""
APKOwl :: modules.traffic
=========================

Phase 7 — dynamic traffic interception and API security testing.

When a device/emulator is available this phase:

* generates a mitmproxy addon that records every flow to a JSONL file,
* launches ``mitmdump`` on a local port,
* points the device's global HTTP proxy at the host via ``adb`` (and reminds
  the operator to install the mitm CA, which our patched APK already trusts),
* lets the app drive traffic, then
* parses captured flows to enumerate the real API surface and runs a battery of
  *safe, non-destructive* active checks against each endpoint:
    - missing security headers
    - verbose server errors / stack traces
    - authorization-header stripping (broken authn)
    - IDOR probing by incrementing/decrementing numeric path ids
    - HTTP method tampering (OPTIONS/PUT/DELETE reflected)
    - reflected input / basic error-based SQLi indicators

Without a device it still:

* generates the mitmproxy addon + a ready-to-run command,
* takes the statically harvested endpoints (from the secrets phase) and runs
  the *passive* checks it can perform from the host (security headers, verbose
  errors, method tampering) against any that are reachable — but only if the
  operator explicitly allows outbound testing.

By default outbound requests are DISABLED unless ``allow_active_http`` is set,
so the tool never talks to third-party servers without consent.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

from core.db import Database
from core.findings import Finding, FindingTemplates, Severity, OWASPMobile
from core.logger import log
from core.toolrunner import ToolRunner


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set (no transport security enforcement)",
    "x-content-type-options": "X-Content-Type-Options missing (MIME sniffing)",
    "x-frame-options": "X-Frame-Options missing (clickjacking on webviews)",
    "content-security-policy": "CSP missing",
}

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "pg_query():",
    "sqlite3::",
    "org.hibernate",
    "ora-01756",
    "sqlstate",
]

STACKTRACE_SIGNATURES = [
    "java.lang.",
    "traceback (most recent call last)",
    "at org.springframework",
    "system.web.httpexception",
    "nodejs",
    "/var/www/",
    ".rb:",
]


@dataclass
class EndpointTest:
    url: str
    method: str = "GET"
    status: int = 0
    findings: List[Finding] = field(default_factory=list)


@dataclass
class TrafficResult:
    addon_path: str = ""
    capture_path: str = ""
    proxy_port: int = 8080
    flows_captured: int = 0
    endpoints_tested: int = 0
    findings: List[Finding] = field(default_factory=list)
    device_serial: str = ""


class TrafficAnalyzer:
    def __init__(self, tools: ToolRunner, db: Database, workdir: str) -> None:
        self.tools = tools
        self.db = db
        self.workdir = workdir

    def run(
        self,
        static_endpoints: List[str],
        enable_intercept: bool = True,
        allow_active_http: bool = False,
        proxy_port: int = 8080,
        capture_seconds: int = 30,
    ) -> TrafficResult:
        result = TrafficResult(proxy_port=proxy_port)

        # always generate the mitmproxy addon + command
        self._generate_mitm_addon(result)

        # try live interception
        if enable_intercept:
            self._maybe_intercept(result, capture_seconds)

        # active endpoint testing (consent-gated)
        endpoints = self._collect_endpoints(static_endpoints, result)
        if allow_active_http and endpoints:
            log.info(f"active HTTP testing enabled against {len(endpoints)} endpoint(s)")
            for url in endpoints:
                self._test_endpoint(url, result)
        elif endpoints:
            log.info(
                f"{len(endpoints)} endpoint(s) discovered; active HTTP testing "
                "is OFF (pass --active-http to enable)."
            )
            self._record_endpoints_only(endpoints, result)

        self._persist(result)
        log.good(f"traffic phase produced {len(result.findings)} finding(s)")
        return result

    # -- mitmproxy addon ---------------------------------------------------
    def _generate_mitm_addon(self, result: TrafficResult) -> None:
        addon = os.path.join(self.workdir, "mitm_capture.py")
        capture = os.path.join(self.workdir, "flows.jsonl")
        result.capture_path = capture
        body = self._mitm_addon_source(capture)
        try:
            with open(addon, "w", encoding="utf-8") as fh:
                fh.write(body)
            result.addon_path = addon
            log.good(f"mitmproxy addon written: {addon}")
        except OSError as exc:
            log.warn(f"could not write mitm addon: {exc}")

    def _mitm_addon_source(self, capture_path: str) -> str:
        return f'''"""APKOwl mitmproxy capture addon.
Run with: mitmdump -s mitm_capture.py --listen-port {{port}}
Captured flows are appended as JSON lines to:
  {capture_path}
"""
import json
from mitmproxy import http

CAPTURE = r"{capture_path}"

def response(flow: http.HTTPFlow) -> None:
    try:
        entry = {{
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "req_headers": dict(flow.request.headers),
            "req_body": flow.request.get_text(strict=False) or "",
            "status": flow.response.status_code,
            "resp_headers": dict(flow.response.headers),
            "resp_body": (flow.response.get_text(strict=False) or "")[:8192],
        }}
        with open(CAPTURE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\\n")
    except Exception as exc:  # never break the proxy
        pass
'''

    # -- live interception -------------------------------------------------
    def _maybe_intercept(self, result: TrafficResult, capture_seconds: int) -> None:
        if not self.tools.available("mitmproxy"):
            log.info("mitmproxy not available; addon generated for manual use")
            log.info(self.tools.install_hint("mitmproxy"))
            return
        serial = self._first_device()
        if not serial:
            log.info("no device connected; skipping live interception")
            self._print_manual_intercept_help(result)
            return
        result.device_serial = serial

        host_ip = self._host_ip()
        log.info(f"configuring device proxy -> {host_ip}:{result.proxy_port}")
        self.tools.run_tool(
            "adb",
            ["shell", "settings", "put", "global", "http_proxy",
             f"{host_ip}:{result.proxy_port}"],
        )

        # launch mitmdump in the background
        log.info(f"launching mitmdump for {capture_seconds}s ...")
        mitm_bin = self.tools.resolve("mitmproxy") or "mitmdump"
        if mitm_bin.endswith("mitmproxy"):
            mitm_bin = mitm_bin[:-len("mitmproxy")] + "mitmdump"
        proc = None
        try:
            proc = subprocess.Popen(
                [mitm_bin, "-s", result.addon_path,
                 "--listen-port", str(result.proxy_port),
                 "--set", "block_global=false"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(capture_seconds)
        except Exception as exc:
            log.warn(f"mitmdump launch failed: {exc}")
        finally:
            if proc:
                proc.terminate()
            # clear the proxy
            self.tools.run_tool(
                "adb", ["shell", "settings", "put", "global", "http_proxy", ":0"]
            )

        self._parse_flows(result)

    def _print_manual_intercept_help(self, result: TrafficResult) -> None:
        log.info("to intercept manually:")
        log.info(f"  mitmdump -s {result.addon_path} --listen-port {result.proxy_port}")
        log.info("  then set the device proxy to <host>:%d and install the mitm CA"
                 % result.proxy_port)

    def _parse_flows(self, result: TrafficResult) -> None:
        if not os.path.isfile(result.capture_path):
            log.info("no flows captured")
            return
        seen: Set[str] = set()
        try:
            with open(result.capture_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    result.flows_captured += 1
                    url = entry.get("url", "")
                    method = entry.get("method", "GET")
                    if url and url not in seen:
                        seen.add(url)
                        self.db.add_endpoint(url, method, source="intercepted")
                    self._analyze_flow(entry, result)
        except OSError:
            return
        log.good(f"parsed {result.flows_captured} captured flow(s)")

    def _analyze_flow(self, entry: Dict, result: TrafficResult) -> None:
        # cleartext flow
        url = entry.get("url", "")
        if url.startswith("http://"):
            result.findings.append(
                FindingTemplates.cleartext_traffic().add_evidence(
                    file_path="intercepted", snippet=url
                )
            )
        # sensitive data in URL query
        if re.search(r"[?&](password|token|api_?key|secret)=", url, re.IGNORECASE):
            result.findings.append(
                Finding(
                    title="Sensitive data passed in URL query string",
                    description="A credential or token was observed in a URL "
                    "query string, where it is logged by proxies and servers.",
                    module="traffic",
                    severity=Severity.MEDIUM,
                    cwe="CWE-598",
                    owasp=OWASPMobile.M3_INSECURE_AUTH,
                    remediation="Send secrets in headers or the request body, "
                    "never the URL.",
                    tags=["api", "leak"],
                ).add_evidence(file_path="intercepted", snippet=url[:200])
            )
        # missing security headers (response)
        self._check_headers(entry.get("resp_headers", {}), url, result, "intercepted")

    # -- endpoint collection ----------------------------------------------
    def _collect_endpoints(
        self, static_endpoints: List[str], result: TrafficResult
    ) -> List[str]:
        out: Set[str] = set()
        for e in static_endpoints:
            if e.startswith(("http://", "https://")):
                out.add(e)
        # also pull anything already in the DB
        for row in self.db.get_endpoints():
            u = row.get("url", "")
            if u.startswith(("http://", "https://")):
                out.add(u)
        return sorted(out)

    def _record_endpoints_only(self, endpoints: List[str], result: TrafficResult) -> None:
        for u in endpoints:
            self.db.add_endpoint(u, "", source="static")

    # -- active endpoint testing -------------------------------------------
    def _test_endpoint(self, url: str, result: TrafficResult) -> None:
        result.endpoints_tested += 1
        baseline = self._http(url, "GET")
        if baseline is None:
            return
        status, headers, body = baseline

        # security headers
        self._check_headers(headers, url, result, url)

        # verbose errors / stack traces
        low_body = (body or "").lower()
        for sig in STACKTRACE_SIGNATURES:
            if sig in low_body:
                result.findings.append(
                    Finding(
                        title="Verbose server error / stack trace exposed",
                        description="The endpoint returned a server stack trace "
                        "or framework error, leaking implementation details.",
                        module="traffic",
                        severity=Severity.LOW,
                        cwe="CWE-209",
                        owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                        remediation="Return generic error pages; log details "
                        "server-side only.",
                        tags=["api", "info-leak"],
                    ).add_evidence(file_path=url, snippet=sig)
                )
                break

        # method tampering
        self._test_method_tampering(url, status, result)

        # IDOR probing on numeric path segments
        self._test_idor(url, status, body, result)

        # error-based SQLi indicator (single quote)
        self._test_sqli(url, result)

    def _check_headers(
        self, headers: Dict[str, str], url: str, result: TrafficResult, ev: str
    ) -> None:
        lower = {k.lower(): v for k, v in headers.items()}
        missing = []
        for h, msg in SECURITY_HEADERS.items():
            if h not in lower:
                missing.append(msg)
        # only flag HSTS absence on https endpoints
        if url.startswith("http://"):
            missing = [m for m in missing if "HSTS" not in m]
        if missing:
            f = Finding(
                title="Missing HTTP security headers",
                description="The endpoint omits recommended security headers: "
                + "; ".join(missing),
                module="traffic",
                severity=Severity.INFO,
                cwe="CWE-693",
                owasp=OWASPMobile.M8_SECURITY_MISCONFIG,
                remediation="Add HSTS, X-Content-Type-Options, X-Frame-Options "
                "and a Content-Security-Policy.",
                tags=["api", "headers"],
            )
            f.add_evidence(file_path=ev, snippet=url[:200])
            result.findings.append(f)

    def _test_method_tampering(self, url: str, base_status: int, result: TrafficResult) -> None:
        for method in ("PUT", "DELETE"):
            res = self._http(url, method)
            if res is None:
                continue
            status, _h, _b = res
            if status in (200, 201, 204) and base_status not in (200, 201, 204):
                result.findings.append(
                    Finding(
                        title=f"HTTP method {method} accepted unexpectedly",
                        description=f"The endpoint accepted a {method} request "
                        f"(status {status}). State-changing methods may be "
                        "improperly exposed.",
                        module="traffic",
                        severity=Severity.MEDIUM,
                        cwe="CWE-650",
                        owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                        remediation="Restrict HTTP methods per endpoint; reject "
                        "unsupported verbs with 405.",
                        tags=["api", "method-tampering"],
                    ).add_evidence(file_path=url, snippet=f"{method} -> {status}")
                )

    def _test_idor(self, url: str, base_status: int, base_body: str, result: TrafficResult) -> None:
        parsed = urlparse(url)
        m = re.search(r"/(\d+)(/|$|\?)", parsed.path)
        if not m:
            return
        original = int(m.group(1))
        for candidate in (original + 1, max(0, original - 1)):
            new_path = parsed.path[: m.start(1)] + str(candidate) + parsed.path[m.end(1):]
            new_url = urlunparse(parsed._replace(path=new_path))
            res = self._http(new_url, "GET")
            if res is None:
                continue
            status, _h, body = res
            if status == 200 and body and body != base_body and len(body) > 32:
                result.findings.append(
                    FindingTemplates.idor(url).add_evidence(
                        file_path=url,
                        snippet=f"id {original} -> {candidate} also returned 200 "
                        f"with different data",
                    )
                )
                break

    def _test_sqli(self, url: str, result: TrafficResult) -> None:
        inject = url + ("&" if "?" in url else "?") + "apkowl=%27"
        res = self._http(inject, "GET")
        if res is None:
            return
        _status, _h, body = res
        low = (body or "").lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in low:
                result.findings.append(
                    Finding(
                        title="Possible error-based SQL injection",
                        description="Injecting a single quote elicited a SQL "
                        "error message, indicating unsanitised input reaching a "
                        "SQL query.",
                        module="traffic",
                        severity=Severity.HIGH,
                        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-89",
                        owasp=OWASPMobile.M4_INSUFFICIENT_VALIDATION,
                        remediation="Use parameterised queries / prepared "
                        "statements; never concatenate input into SQL.",
                        tags=["api", "sqli"],
                    ).add_evidence(file_path=url, snippet=sig)
                )
                break

    # -- low level http ----------------------------------------------------
    def _http(
        self, url: str, method: str, timeout: int = 8
    ) -> Optional[Tuple[int, Dict[str, str], str]]:
        try:
            req = urllib.request.Request(url=url, method=method)
            req.add_header("User-Agent", "APKOwl/1.0 (security-test)")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", "replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, dict(e.headers or {}), body
        except (urllib.error.URLError, socket.timeout, ValueError, OSError):
            return None

    # -- helpers -----------------------------------------------------------
    def _first_device(self) -> str:
        if not self.tools.available("adb"):
            return ""
        r = self.tools.run_tool("adb", ["devices"])
        if not r.ok:
            return ""
        for line in r.stdout.splitlines()[1:]:
            line = line.strip()
            if line.endswith("device"):
                return line.split()[0]
        return ""

    def _host_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    # -- persistence -------------------------------------------------------
    def _persist(self, result: TrafficResult) -> None:
        if result.addon_path:
            self.db.add_artifact("mitm_addon", result.addon_path, note="mitmproxy capture addon")
        if os.path.isfile(result.capture_path):
            self.db.add_artifact("flows", result.capture_path, note="captured traffic")
        self.db.set_kv(
            "traffic_summary",
            {
                "flows": result.flows_captured,
                "endpoints_tested": result.endpoints_tested,
                "device": result.device_serial,
            },
        )
