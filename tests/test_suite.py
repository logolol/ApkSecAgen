"""
APKOwl :: tests.test_suite
=========================

A self-contained regression suite. It uses only the standard library's
``unittest`` so it runs anywhere APKOwl runs, with no extra dependencies.

Run it with:

    python -m tests.test_suite           # from the apkowl/ directory
    python -m unittest tests.test_suite  # equivalent

The suite builds small in-memory / temp fixtures and asserts the behaviour of
each analysis component: the CVSS engine, the secret signatures, the binary AXML
parser, the database de-duplication, the crypto detector, the smali patcher, the
native analyser, the storage scanner, the obfuscation/SDK detector, the resource
analyser, the privacy analyser, the knowledge base, the plugin system and the
reporter. It is deliberately fast and hermetic.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from core.logger import configure
from core.db import Database
from core.toolrunner import ToolRunner
from core.findings import (
    Finding,
    FindingTemplates,
    Severity,
    OWASPMobile,
    CVSS31,
)

# keep test output quiet
configure("ERROR")


def _tmpdb() -> Database:
    db = Database(tempfile.mktemp(suffix=".db"))
    db.begin_scan("test.apk", "deadbeef", "test")
    return db


# ---------------------------------------------------------------------------
class TestCVSS(unittest.TestCase):
    def test_known_scores(self):
        cases = [
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
        ]
        for vector, expected in cases:
            score = CVSS31(vector).base_score()
            self.assertAlmostEqual(score, expected, delta=0.3,
                                   msg=f"{vector} -> {score} (want {expected})")

    def test_severity_from_cvss(self):
        self.assertEqual(Severity.from_cvss(9.8), Severity.CRITICAL)
        self.assertEqual(Severity.from_cvss(7.5), Severity.HIGH)
        self.assertEqual(Severity.from_cvss(5.0), Severity.MEDIUM)
        self.assertEqual(Severity.from_cvss(2.0), Severity.LOW)
        self.assertEqual(Severity.from_cvss(0.0), Severity.INFO)


# ---------------------------------------------------------------------------
class TestSecrets(unittest.TestCase):
    def test_pattern_count(self):
        from signatures.secrets_db import SECRET_PATTERNS
        self.assertGreaterEqual(len(SECRET_PATTERNS), 60)

    def test_detects_common_secrets(self):
        from signatures.secrets_db import SECRET_PATTERNS
        samples = {
            'AKIAIOSFODNN7EXAMPLE': "aws_access_key",
            'sk_live_NOT_A_REAL_STRIPE_KEY_XXXXXXXXXXXXXXXX': "stripe_live",
            'ghp_1234567890abcdefghijklmnopqrstuvwxyz': "github_pat",
            'glpat-abcdefghij1234567890': "gitlab_pat_v2",
            'whsec_abcdefghij1234567890ABCDEFGHIJ12': "stripe_webhook",
        }
        for value, expected_id in samples.items():
            matched = []
            for p in SECRET_PATTERNS:
                if p.scan_line(f'key = "{value}"'):
                    matched.append(p.id)
            self.assertIn(expected_id, matched,
                          f"{value} should match {expected_id}, got {matched}")

    def test_ignores_placeholders(self):
        from signatures.secrets_db import SECRET_PATTERNS
        junk = 'password = "your_password_here"'
        for p in SECRET_PATTERNS:
            if p.id == "generic_secret_assign":
                self.assertFalse(p.scan_line(junk))

    def test_entropy(self):
        from signatures.secrets_db import shannon_entropy
        self.assertLess(shannon_entropy("aaaaaaaa"), 1.0)
        self.assertGreater(shannon_entropy("a8Fk2Lp9Qx"), 2.5)


# ---------------------------------------------------------------------------
class TestAXML(unittest.TestCase):
    def _build_minimal_axml(self) -> bytes:
        """Build a tiny but valid AXML doc: <manifest package="com.t"/>."""
        strings = ["android",
                   "http://schemas.android.com/apk/res/android",
                   "manifest", "package", "com.t"]

        def pool(strs):
            data = b""
            offsets = []
            for s in strs:
                offsets.append(len(data))
                b = s.encode("utf-8")
                data += bytes([len(s), len(b)]) + b + b"\x00"
            while len(data) % 4:
                data += b"\x00"
            body = struct.pack("<IIIII", len(strs), 0, 0x100,
                               28 + len(strs) * 4, 0)
            body += b"".join(struct.pack("<I", o) for o in offsets)
            body += data
            return struct.pack("<HHI", 0x0001, 28, 8 + len(body)) + body

        S = {s: i for i, s in enumerate(strings)}

        def start_el(name_idx, attrs):
            body = struct.pack("<Ii", 1, -1)
            body += struct.pack("<ii", -1, name_idx)
            body += struct.pack("<HH", 20, 20)
            body += struct.pack("<HH", len(attrs), 0)
            body += struct.pack("<HH", 0, 0)
            for ans, anm, raw, typ, data in attrs:
                body += struct.pack("<ii", ans, anm)
                body += struct.pack("<i", raw)
                body += struct.pack("<HBB", 8, 0, typ)
                body += struct.pack("<I", data)
            return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body

        def end_el(name_idx):
            body = struct.pack("<Iiii", 1, -1, -1, name_idx)
            return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body

        tree = start_el(S["manifest"], [
            (-1, S["package"], S["com.t"], 0x03, S["com.t"]),
        ])
        tree += end_el(S["manifest"])
        body = pool(strings) + tree
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body

    def test_parse_minimal(self):
        from modules.axml import AXMLParser
        data = self._build_minimal_axml()
        parser = AXMLParser(data)
        parser.parse()
        xml = parser.to_xml()
        self.assertIn("manifest", xml)
        self.assertIn("com.t", xml)


# ---------------------------------------------------------------------------
class TestDatabase(unittest.TestCase):
    def test_dedup(self):
        db = _tmpdb()
        f1 = FindingTemplates.debuggable()
        f2 = FindingTemplates.debuggable()
        id1 = db.add_finding(f1)
        id2 = db.add_finding(f2)  # identical -> deduped
        self.assertIsNotNone(id1)
        self.assertIsNone(id2)
        self.assertEqual(len(db.get_findings()), 1)

    def test_counts(self):
        db = _tmpdb()
        db.add_finding(Finding(title="a", description="d", severity=Severity.CRITICAL, module="m"))
        db.add_finding(Finding(title="b", description="d", severity=Severity.LOW, module="m"))
        counts = db.severity_counts()
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["LOW"], 1)

    def test_endpoint_dedup(self):
        db = _tmpdb()
        db.add_endpoint("https://a.com/x", "GET", "static")
        db.add_endpoint("https://a.com/x", "GET", "static")
        self.assertEqual(len(db.get_endpoints()), 1)

    def test_kv_roundtrip(self):
        db = _tmpdb()
        db.set_kv("foo", {"a": 1, "b": [2, 3]})
        self.assertEqual(db.get_kv("foo"), {"a": 1, "b": [2, 3]})
        self.assertEqual(db.get_kv("missing", "default"), "default")


# ---------------------------------------------------------------------------
class TestCrypto(unittest.TestCase):
    def test_weak_crypto_detection(self):
        from modules.certs import CertAnalyzer, CertsResult
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "C.java"), "w") as fh:
            fh.write('Cipher.getInstance("DES/ECB/PKCS5Padding");\n'
                     'MessageDigest.getInstance("MD5");\n'
                     'new java.util.Random();\n')
        ca = CertAnalyzer(ToolRunner(), _tmpdb())
        res = CertsResult()
        ca._analyze_code_crypto([d], res)
        titles = " ".join(f.title.lower() for f in res.findings)
        self.assertIn("weak", titles)
        self.assertTrue(any("md5" in f.title.lower() or "weak hash" in f.title.lower()
                            for f in res.findings))


# ---------------------------------------------------------------------------
class TestPatcher(unittest.TestCase):
    def test_root_method_stub(self):
        from modules.patcher import Patcher
        p = Patcher(ToolRunner(), _tmpdb(), tempfile.mkdtemp())
        header = ".method public isRooted()Z"
        stub = p._stub_for(header, "root")
        self.assertIn("const/4 v0, 0x0", stub)
        self.assertIn("return v0", stub)

    def test_void_stub(self):
        from modules.patcher import Patcher
        p = Patcher(ToolRunner(), _tmpdb(), tempfile.mkdtemp())
        stub = p._stub_for(".method public checkServerTrusted(...)V", "pinning")
        self.assertIn("return-void", stub)


# ---------------------------------------------------------------------------
class TestNative(unittest.TestCase):
    def test_clean_symbol(self):
        from modules.native import NativeAnalyzer
        self.assertEqual(NativeAnalyzer._clean_symbol("strcpy@GLIBC_2.2.5"),
                         "strcpy")
        self.assertEqual(NativeAnalyzer._clean_symbol("JNI_OnLoad"), "JNI_OnLoad")

    def test_abi_detection(self):
        from modules.native import NativeAnalyzer
        na = NativeAnalyzer(ToolRunner(), _tmpdb())
        self.assertEqual(na._abi_from_path("/x/lib/arm64-v8a/libfoo.so"),
                         "arm64-v8a")


# ---------------------------------------------------------------------------
class TestStorage(unittest.TestCase):
    def test_world_access_and_log(self):
        from modules.storage import StorageAnalyzer
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "S.java"), "w") as fh:
            fh.write('getSharedPreferences("x", MODE_WORLD_READABLE);\n'
                     'Log.d("T", "token=" + authToken);\n')
        sa = StorageAnalyzer(ToolRunner(), _tmpdb(), tempfile.mkdtemp())
        res = sa.run("com.t", [d], enable_dynamic=False)
        titles = [f.title for f in res.findings]
        self.assertTrue(any("World-accessible" in t for t in titles))
        self.assertTrue(any("logcat" in t for t in titles))


# ---------------------------------------------------------------------------
class TestObfuscation(unittest.TestCase):
    def test_sdk_and_dynload(self):
        from modules.obfuscation import ObfuscationAnalyzer
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "com", "google", "firebase"))
        with open(os.path.join(d, "M.java"), "w") as fh:
            fh.write("DexClassLoader cl = new DexClassLoader(a,b,c,d);\n")
        ob = ObfuscationAnalyzer(_tmpdb())
        res = ob.run([], d, {"toolchain": "none / minimal", "total_classes": 100})
        self.assertIn("Firebase", res.sdks)
        self.assertTrue(any("Dynamic code loading" in f.title for f in res.findings))


# ---------------------------------------------------------------------------
class TestResources(unittest.TestCase):
    def test_firebase_and_key(self):
        from modules.resources import ResourceAnalyzer
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "res", "raw"))
        os.makedirs(os.path.join(d, "assets"))
        with open(os.path.join(d, "google-services.json"), "w") as fh:
            fh.write('{"project_info":{"project_id":"p1",'
                     '"firebase_url":"https://p1.firebaseio.com"}}')
        with open(os.path.join(d, "res", "raw", "k.pem"), "w") as fh:
            fh.write("-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----")
        with open(os.path.join(d, "assets", "discussions.snapshot"), "w") as fh:
            fh.write("seed data")
        ra = ResourceAnalyzer(_tmpdb())
        res = ra.run(d, "")
        titles = " ".join(f.title for f in res.findings)
        self.assertIn("Firebase", titles)
        self.assertIn("key", titles.lower())
        self.assertIn("artifact", titles.lower())
        self.assertIn("p1", res.firebase_projects)


# ---------------------------------------------------------------------------
class TestPrivacy(unittest.TestCase):
    def test_tracker_overlap(self):
        from modules.privacy import PrivacyAnalyzer
        pa = PrivacyAnalyzer(_tmpdb())
        res = pa.run(
            ["android.permission.ACCESS_FINE_LOCATION",
             "android.permission.READ_CONTACTS"],
            [],
            {"AppsFlyer": "attribution"},
        )
        self.assertTrue(any("tracking" in f.title.lower()
                            or "tracking SDKs" in f.title for f in res.findings))

    def test_high_risk(self):
        from modules.privacy import PrivacyAnalyzer
        pa = PrivacyAnalyzer(_tmpdb())
        res = pa.run(["android.permission.READ_SMS"], [], {})
        self.assertTrue(any("READ_SMS" in f.title for f in res.findings))


# ---------------------------------------------------------------------------
class TestKnowledgeBase(unittest.TestCase):
    def test_enrich(self):
        from signatures.knowledge_base import enrich, masvs_for_cwe
        info = enrich("CWE-798")
        self.assertEqual(info["cwe"], "CWE-798")
        self.assertTrue(len(info["masvs"]) >= 1)
        controls = masvs_for_cwe("CWE-89")
        self.assertTrue(any(c.group == "PLATFORM" for c in controls))

    def test_coverage(self):
        from signatures.knowledge_base import coverage_summary
        cov = coverage_summary(["CWE-798", "CWE-312", "CWE-89"])
        self.assertIn("STORAGE", cov)


# ---------------------------------------------------------------------------
class TestPlugins(unittest.TestCase):
    def test_discovery(self):
        from plugins.base import discover_plugins
        names = [p.name for p in discover_plugins()]
        self.assertIn("insecure-webview", names)
        self.assertIn("weak-token-randomness", names)

    def test_webview_plugin(self):
        from plugins.example_insecure_webview import InsecureWebViewPlugin
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "W.java"), "w") as fh:
            fh.write("webView.getSettings().setJavaScriptEnabled(true);\n"
                     "webView.addJavascriptInterface(new B(), \"a\");\n"
                     "settings.setAllowFileAccessFromFileURLs(true);\n")

        class Ctx:
            code_roots = [d]

        findings = InsecureWebViewPlugin().analyze(Ctx())
        self.assertTrue(len(findings) >= 2)

    def test_prng_plugin(self):
        from plugins.example_weak_prng_tokens import WeakTokenRandomnessPlugin
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "T.java"), "w") as fh:
            fh.write("String sessionToken = String.valueOf(new java.util.Random().nextInt());\n")

        class Ctx:
            code_roots = [d]

        findings = WeakTokenRandomnessPlugin().analyze(Ctx())
        self.assertTrue(len(findings) >= 1)


# ---------------------------------------------------------------------------
class TestReporter(unittest.TestCase):
    def test_full_report(self):
        from modules.reporter import Reporter
        db = _tmpdb()
        db.update_scan_meta(package_name="com.test", version_name="1.0",
                            version_code="1")
        db.add_finding(FindingTemplates.hardcoded_secret("AWS key"))
        db.add_finding(FindingTemplates.cleartext_traffic())
        db.add_endpoint("https://api.test.com/v1", "GET", "static")
        out = tempfile.mkdtemp()
        res = Reporter(db, out, "test").run()
        self.assertTrue(os.path.exists(res.html_path))
        self.assertTrue(os.path.exists(res.json_path))
        self.assertTrue(os.path.exists(res.md_path))
        self.assertTrue(os.path.exists(res.summary_path))
        # html should be parseable and contain the package
        html_text = open(res.html_path).read()
        self.assertIn("com.test", html_text)
        self.assertIn("MASVS", html_text)


# ---------------------------------------------------------------------------
class TestFindingTemplates(unittest.TestCase):
    def test_all_templates_build(self):
        templates = [
            FindingTemplates.hardcoded_secret("x"),
            FindingTemplates.exported_component("activity", ".A"),
            FindingTemplates.cleartext_traffic(),
            FindingTemplates.debuggable(),
            FindingTemplates.backup_allowed(),
            FindingTemplates.weak_crypto("DES"),
            FindingTemplates.ssl_pinning_absent(),
            FindingTemplates.idor("https://x/1"),
            FindingTemplates.insecure_native("strcpy"),
            FindingTemplates.task_hijacking("singleTask"),
            FindingTemplates.pending_intent_mutable("x"),
            FindingTemplates.janus_signature("v1"),
            FindingTemplates.exported_service_no_permission(".S"),
            FindingTemplates.tapjacking(".P"),
            FindingTemplates.clipboard_leak(),
            FindingTemplates.screenshot_not_blocked(),
        ]
        for t in templates:
            self.assertIsInstance(t, Finding)
            self.assertTrue(t.title)
            self.assertTrue(t.dedupe_key())


if __name__ == "__main__":
    unittest.main(verbosity=2)
