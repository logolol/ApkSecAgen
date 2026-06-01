# APKOwl 🦉

**Autonomous mobile-app penetration-testing toolkit for Android.**

APKOwl takes a single `.apk` or `.xapk` file and runs a complete, twelve-phase
security assessment against it — static *and* dynamic — then produces an
interactive HTML report, a machine-readable JSON report, a Markdown report and a
plain-text executive summary. It is pure deterministic Python: there is no AI,
no machine learning, and no telephone-home. Every finding is the result of
explicit, auditable logic.

It is designed to run on a pentester's workstation (developed and tested against
**Parrot OS**, and equally at home on Kali or any Debian derivative). When a
device or emulator is connected and the relevant toolchain is installed, the
active phases will patch, instrument, intercept and probe the live app. When
those tools or devices are absent, every phase degrades gracefully to its static
equivalent and tells you exactly what to install to unlock the rest.

---

## What it does

| #  | Phase                         | Highlights |
|----|-------------------------------|------------|
| 1  | **Extraction**                | XAPK/APKS/APKM bundle handling, unzip with zip-slip protection, drives `apktool`/`jadx`/`dex2jar`, hashes everything, estimates the obfuscation toolchain. |
| 2  | **Manifest analysis**         | Self-contained binary-AXML parser (no `apktool` dependency), exported-component evaluation, debuggable/backup/cleartext flags, dangerous permissions, task-hijacking & exported-service checks. |
| 3  | **Secret scanning**           | 68 credential signatures (AWS, GCP, Azure, Stripe, Twilio, GitHub, GitLab, Discord, Telegram, private keys, JWTs, …) with entropy gating, plus endpoint/IP harvesting. Also deep-scans `assets/`, `res/`, `network_security_config.xml`, and `google-services.json` (Firebase). |
| 4  | **Certificates & crypto**     | PKCS#7/X.509 parsing, debug-cert/weak-sig/expiry checks, Janus (v1-only signing) detection, NSC analysis, and code-level weak-crypto detection (DES/RC4/ECB/MD5/SHA1, insecure RNG, hardcoded IVs, trust-all managers, pinning presence). |
| 5  | **Anti-analysis patching**    | Locates and neutralises root/emulator/SSL-pinning checks in smali, rebuilds with `apktool`, re-signs with a generated keystore (`apksigner`/`jarsigner` + `zipalign`). Emits unified diffs. |
| 6  | **Frida instrumentation**     | Generates a tailored 10-script Frida toolkit (SSL unpinning, root bypass, crypto logger, prefs/file logger, network tracer, JWT interceptor, class tracer, anti-debug bypass, combined loader, runner). Injects live when a device is present. |
| 7  | **Traffic & API testing**     | Generates a `mitmproxy` capture addon, configures the device proxy, captures flows, and runs *consent-gated* active checks (security headers, verbose errors, method tampering, IDOR, error-based SQLi). |
| 8  | **Intent & deeplink attacks** | Builds an `adb am`/`content` attack matrix with fuzzing payloads (traversal, XSS, redirect, SQLi, oversize, null-byte, format-string), fires them on-device and watches logcat for crashes. |
| 9  | **Device storage analysis**   | Static insecure-storage detection (world-access, WebView password save, sensitive logging, clipboard, FLAG_SECURE) plus on-device pull of `shared_prefs`/`databases`/`files` and logcat secret scanning. |
| 10 | **Native library analysis**   | ELF parsing of `lib/*/*.so`: arch, dangerous libc imports, JNI entry points, anti-debug (`ptrace`), and a checksec-style hardening assessment (NX/PIE/RELRO/canary/FORTIFY). |
| 11 | **Obfuscation, SDKs & privacy** | Obfuscation intensity, reflection/dynamic-loading/anti-debug detection, ~35 third-party SDK fingerprints, and a permission↔SDK privacy correlation pass. **User plugins also run here.** |
| 12 | **Reporting**                 | HTML (interactive, severity-filterable, MASVS coverage), JSON, Markdown, and a plain-text executive summary. |

Every finding carries a **severity**, a **CVSS v3.1 vector + score** (computed by
a self-contained engine), a **CWE**, an **OWASP Mobile Top 10 (2024)** category,
and an **OWASP MASVS** control mapping, plus evidence and concrete remediation.

---

## Installation

APKOwl itself needs only Python 3.9+ and three small libraries:

```bash
pip install -r requirements.txt
```

For the full active-analysis capability, install the external toolchain. On
**Parrot / Debian / Kali**:

```bash
sudo apt install apktool jadx dex2jar android-tools-adb \
                 default-jdk-headless apksigner zipalign binutils file
pip install frida-tools objection mitmproxy
```

APKOwl works without these — it will run all static phases and tell you which
tools to install for the rest. Check what it can see on your box with:

```bash
python -m apkowl --list-tools
```

---

## Usage

```bash
# Full scan, reports written to ./apkowl-output
python -m apkowl target.apk

# Choose an output directory
python -m apkowl target.xapk -o ./reports/target

# Static only — no device interaction at all
python -m apkowl target.apk --no-device

# Enable OUTBOUND HTTP endpoint testing (IDOR/SQLi/method tampering).
# Off by default so the tool never contacts third-party servers without consent.
python -m apkowl target.apk --active-http

# Skip the active phases entirely (5,6,7,8,9)
python -m apkowl target.apk --skip 5,6,7,8,9

# Verbose logging
python -m apkowl target.apk -v
```

### Useful flags

| Flag | Meaning |
|------|---------|
| `-o, --output-dir` | Where reports + artifacts go (default `./apkowl-output`). |
| `--device / --no-device` | Toggle live device interaction (default on, auto-degrades). |
| `--active-http` | Allow outbound HTTP probing of discovered endpoints (off by default). |
| `--no-repackage` | Plan smali patches but don't rebuild/sign a patched APK. |
| `--inject-seconds N` | How long to keep Frida attached when injecting. |
| `--capture-seconds N` | How long to capture traffic via mitmproxy. |
| `--proxy-port N` | Local interception proxy port (default 8080). |
| `--skip 5,6,7` | Comma-separated phase numbers to skip. |
| `--list-tools` | Print the host toolchain capability report and exit. |
| `-v / -q` | Verbose / quiet logging. |

The process exit code reflects the worst severity found (3=critical, 2=high,
1=medium, 0=clean), which makes APKOwl easy to wire into CI gates.

---

## Output

A scan produces, in the output directory:

```
report.html      interactive report (open in a browser)
report.json      full machine-readable result (CI / diffing)
report.md        Markdown report (tickets / PRs)
summary.txt      plain-text executive summary
apkowl.db        SQLite database of the scan (queryable)
work/            generated artifacts:
  frida-scripts/   the 10-script Frida toolkit + run.sh
  intent-attacks.sh
  mitm_capture.py
  patched-signed.apk   (when patching + signing succeeded)
  *.diff               (smali patch diffs)
```

---

## Writing a plugin

APKOwl is extensible. Drop a `.py` file into `plugins/` that subclasses
`APKOwlPlugin` and implements `analyze(context)`:

```python
from plugins.base import APKOwlPlugin
from core.findings import Finding, Severity, OWASPMobile

class MyCheck(APKOwlPlugin):
    name = "my-check"
    description = "Looks for our internal secret format."

    def analyze(self, context):
        findings = []
        for path in self._iter_code(context.code_roots):
            ...  # your logic
            findings.append(Finding(title="...", severity=Severity.HIGH, ...))
        return findings
```

The plugin runs automatically in phase 11 and its findings flow into every
report exactly like the built-in ones. See the two bundled examples:
`plugins/example_insecure_webview.py` and `plugins/example_weak_prng_tokens.py`.

---

## Architecture

```
apkowl/
  __main__.py            CLI entrypoint (click)
  core/
    findings.py          Finding model, CVSS v3.1 engine, severity, templates
    db.py                SQLite persistence (WAL, thread-safe)
    logger.py            rich-backed logger with plain fallback
    toolrunner.py        external tool resolution + safe subprocess runner
    pipeline.py          the 12-phase orchestrator
  modules/               one module per phase (extractor, manifest, secrets,
                         certs, patcher, frida_gen, traffic, intents, storage,
                         native, obfuscation, resources, privacy, reporter)
  signatures/
    secrets_db.py        68 credential patterns + URL/IP harvesting
    knowledge_base.py    OWASP MASVS controls + CWE/MASTG mappings
  plugins/
    base.py              plugin base class + loader
    example_*.py         worked example plugins
```

Design principles: every external call is wrapped with a timeout and never
raises; a failure in one phase never aborts the run; everything discovered is
persisted to SQLite immediately; and the tool is fully functional offline,
becoming more capable as you install the optional toolchain.

---

## Legal

APKOwl is for **authorised security testing only**. Only analyse applications you
own or have explicit, written permission to test. The active phases modify and
instrument applications and interact with devices and networks; you are
responsible for using them lawfully.

---

*APKOwl — pure-logic mobile security analysis. No AI, no cloud, no nonsense.*
