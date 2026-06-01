"""
APKOwl :: signatures.secrets_db
==============================

A curated library of detection patterns for credentials, tokens and other
secrets that frequently get shipped inside Android packages.

Each :class:`SecretPattern` carries:

* a human name and a unique id,
* a compiled regular expression,
* an optional secondary "keyword" requirement (the regex only counts if a
  nearby keyword is present — cuts false positives on generic blobs),
* a confidence and severity hint,
* an optional validator callable for extra checks (length, Luhn, base64-decode).

The patterns here are the real backbone of the secret scanner. They are written
to match the *format* of credentials, not any particular vendor's live keys.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern

from core.findings import Severity


# ---------------------------------------------------------------------------
# helpers used by validators
# ---------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits per char) of *data*."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def looks_base64(value: str) -> bool:
    if len(value) < 16 or len(value) % 4 != 0:
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def high_entropy(min_bits: float = 4.0, min_len: int = 20) -> Callable[[str], bool]:
    def _v(value: str) -> bool:
        return len(value) >= min_len and shannon_entropy(value) >= min_bits
    return _v


def not_placeholder(value: str) -> bool:
    """Reject obvious placeholder strings."""
    low = value.lower()
    placeholders = (
        "your", "example", "placeholder", "xxxx", "0000", "1234",
        "abcd", "test", "dummy", "sample", "changeme", "todo", "fixme",
        "aaaa", "ffff", "<", "{",
    )
    return not any(p in low for p in placeholders)


@dataclass
class SecretPattern:
    id: str
    name: str
    regex: Pattern
    severity: Severity = Severity.HIGH
    confidence: str = "firm"
    keywords: List[str] = field(default_factory=list)
    validator: Optional[Callable[[str], bool]] = None
    cwe: str = "CWE-798"
    capture_group: int = 0

    def scan_line(self, line: str) -> List[str]:
        """Return all matched secret strings in *line* that pass validation."""
        hits: List[str] = []
        if self.keywords:
            low = line.lower()
            if not any(k in low for k in self.keywords):
                return hits
        for m in self.regex.finditer(line):
            value = m.group(self.capture_group) if self.capture_group else m.group(0)
            if self.validator and not self.validator(value):
                continue
            hits.append(value)
        return hits


def _c(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# The pattern library.
# ---------------------------------------------------------------------------
SECRET_PATTERNS: List[SecretPattern] = [
    # --- cloud providers ------------------------------------------------
    SecretPattern(
        id="aws_access_key",
        name="AWS Access Key ID",
        regex=_c(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b"),
        severity=Severity.CRITICAL,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="aws_secret_key",
        name="AWS Secret Access Key",
        regex=_c(r"(?i)aws.{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        severity=Severity.CRITICAL,
        keywords=["aws", "secret"],
        validator=high_entropy(4.2, 40),
        capture_group=1,
    ),
    SecretPattern(
        id="gcp_api_key",
        name="Google API Key",
        regex=_c(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="gcp_oauth",
        name="Google OAuth Client ID",
        regex=_c(r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b"),
        severity=Severity.MEDIUM,
        capture_group=1,
    ),
    SecretPattern(
        id="firebase_db",
        name="Firebase Database URL",
        regex=_c(r"\bhttps://[a-z0-9\-]+\.firebaseio\.com\b"),
        severity=Severity.MEDIUM,
        confidence="firm",
    ),
    SecretPattern(
        id="firebase_cloud_msg",
        name="Firebase Cloud Messaging legacy server key",
        regex=_c(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="azure_storage",
        name="Azure Storage account key",
        regex=_c(r"(?i)AccountKey=([A-Za-z0-9/+=]{86}==)"),
        severity=Severity.CRITICAL,
        keywords=["accountkey", "core.windows.net"],
        capture_group=1,
    ),

    # --- payment / comms providers --------------------------------------
    SecretPattern(
        id="stripe_live",
        name="Stripe live secret key",
        regex=_c(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        severity=Severity.CRITICAL,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="stripe_test",
        name="Stripe test secret key",
        regex=_c(r"\b(sk_test_[0-9a-zA-Z]{24,})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="stripe_restricted",
        name="Stripe restricted key",
        regex=_c(r"\b(rk_live_[0-9a-zA-Z]{24,})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="twilio_sid",
        name="Twilio Account SID",
        regex=_c(r"\b(AC[0-9a-fA-F]{32})\b"),
        severity=Severity.MEDIUM,
        keywords=["twilio", "ac"],
        capture_group=1,
    ),
    SecretPattern(
        id="twilio_key",
        name="Twilio API Key",
        regex=_c(r"\b(SK[0-9a-fA-F]{32})\b"),
        severity=Severity.HIGH,
        keywords=["twilio"],
        capture_group=1,
    ),
    SecretPattern(
        id="sendgrid",
        name="SendGrid API Key",
        regex=_c(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="mailgun",
        name="Mailgun API Key",
        regex=_c(r"\b(key-[0-9a-zA-Z]{32})\b"),
        severity=Severity.HIGH,
        keywords=["mailgun", "key-"],
        capture_group=1,
    ),
    SecretPattern(
        id="square_access",
        name="Square access token",
        regex=_c(r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="square_oauth",
        name="Square OAuth secret",
        regex=_c(r"\b(sq0csp-[0-9A-Za-z\-_]{43})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="paypal_braintree",
        name="PayPal Braintree access token",
        regex=_c(r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b"),
        severity=Severity.CRITICAL,
        capture_group=1,
    ),

    # --- source control / CI --------------------------------------------
    SecretPattern(
        id="github_pat",
        name="GitHub Personal Access Token",
        regex=_c(r"\b(ghp_[0-9A-Za-z]{36})\b"),
        severity=Severity.CRITICAL,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="github_oauth",
        name="GitHub OAuth token",
        regex=_c(r"\b(gho_[0-9A-Za-z]{36})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="github_app",
        name="GitHub App token",
        regex=_c(r"\b((?:ghu|ghs)_[0-9A-Za-z]{36})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="github_refresh",
        name="GitHub refresh token",
        regex=_c(r"\b(ghr_[0-9A-Za-z]{36,})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="gitlab_pat",
        name="GitLab Personal Access Token",
        regex=_c(r"\b(glpat-[0-9A-Za-z\-_]{20})\b"),
        severity=Severity.CRITICAL,
        capture_group=1,
    ),
    SecretPattern(
        id="slack_token",
        name="Slack token",
        regex=_c(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="slack_webhook",
        name="Slack webhook URL",
        regex=_c(r"\b(https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24})\b"),
        severity=Severity.MEDIUM,
        capture_group=1,
    ),
    SecretPattern(
        id="npm_token",
        name="npm access token",
        regex=_c(r"\b(npm_[0-9A-Za-z]{36})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),

    # --- generic tokens & keys ------------------------------------------
    SecretPattern(
        id="jwt",
        name="JSON Web Token (JWT)",
        regex=_c(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        severity=Severity.MEDIUM,
        confidence="firm",
        capture_group=1,
    ),
    SecretPattern(
        id="bearer",
        name="Bearer token in header",
        regex=_c(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})"),
        severity=Severity.MEDIUM,
        keywords=["bearer", "authorization"],
        validator=not_placeholder,
        capture_group=1,
    ),
    SecretPattern(
        id="basic_auth_url",
        name="Credentials embedded in URL",
        regex=_c(r"\b([a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+)\b"),
        severity=Severity.HIGH,
        confidence="firm",
        capture_group=1,
    ),
    SecretPattern(
        id="private_key_pem",
        name="Private key (PEM) block",
        regex=_c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        confidence="certain",
    ),
    SecretPattern(
        id="generic_api_key",
        name="Generic API key assignment",
        regex=_c(r"""(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]"""),
        severity=Severity.MEDIUM,
        keywords=["key", "secret", "token", "pass"],
        validator=lambda v: high_entropy(3.2, 16)(v) and not_placeholder(v),
        capture_group=1,
    ),
    SecretPattern(
        id="generic_password",
        name="Hardcoded password assignment",
        regex=_c(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"\s]{6,})['"]"""),
        severity=Severity.MEDIUM,
        keywords=["password", "passwd", "pwd"],
        validator=not_placeholder,
        capture_group=1,
    ),
    SecretPattern(
        id="rsa_id",
        name="SSH private key id",
        regex=_c(r"\b(ssh-rsa\s+AAAA[0-9A-Za-z+/]{100,})\b"),
        severity=Severity.MEDIUM,
        capture_group=1,
    ),
    SecretPattern(
        id="algolia_admin",
        name="Algolia admin key (heuristic)",
        regex=_c(r"(?i)algolia.{0,20}?['\"]([a-f0-9]{32})['\"]"),
        severity=Severity.MEDIUM,
        keywords=["algolia"],
        capture_group=1,
    ),
    SecretPattern(
        id="mapbox",
        name="Mapbox secret token",
        regex=_c(r"\b(sk\.eyJ[A-Za-z0-9_\-]{50,})\b"),
        severity=Severity.MEDIUM,
        capture_group=1,
    ),
    SecretPattern(
        id="heroku",
        name="Heroku API key (UUID heuristic)",
        regex=_c(r"(?i)heroku.{0,20}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
        severity=Severity.MEDIUM,
        keywords=["heroku"],
        capture_group=1,
    ),
    # --- additional cloud / infra ---------------------------------------
    SecretPattern(
        id="aws_session_token",
        name="AWS session token (heuristic)",
        regex=_c(r"(?i)(?:session[_-]?token|x-amz-security-token).{0,8}?['\"]([A-Za-z0-9/+=]{100,})['\"]"),
        severity=Severity.HIGH,
        keywords=["token", "amz", "session"],
        validator=high_entropy(4.0, 100),
        capture_group=1,
    ),
    SecretPattern(
        id="gcp_service_account",
        name="GCP service-account private key block",
        regex=_c(r'"type":\s*"service_account"'),
        severity=Severity.CRITICAL,
        confidence="certain",
        keywords=["service_account", "private_key"],
    ),
    SecretPattern(
        id="azure_sas",
        name="Azure Shared Access Signature token",
        regex=_c(r"(?i)(sig=[A-Za-z0-9%]{40,}&?se=)"),
        severity=Severity.HIGH,
        keywords=["sig=", "sv=", "sas"],
        capture_group=1,
    ),
    SecretPattern(
        id="azure_ad_client_secret",
        name="Azure AD client secret (heuristic)",
        regex=_c(r"(?i)client[_-]?secret.{0,8}?['\"]([A-Za-z0-9\-_~.]{34,40})['\"]"),
        severity=Severity.HIGH,
        keywords=["client_secret", "clientsecret"],
        validator=high_entropy(4.0, 30),
        capture_group=1,
    ),
    SecretPattern(
        id="digitalocean_pat",
        name="DigitalOcean personal access token",
        regex=_c(r"\b(dop_v1_[a-f0-9]{64})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="cloudflare_api_token",
        name="Cloudflare API token (heuristic)",
        regex=_c(r"(?i)cloudflare.{0,16}?['\"]([A-Za-z0-9_-]{40})['\"]"),
        severity=Severity.HIGH,
        keywords=["cloudflare"],
        validator=high_entropy(4.0, 40),
        capture_group=1,
    ),
    SecretPattern(
        id="linode_token",
        name="Linode API token (heuristic)",
        regex=_c(r"(?i)linode.{0,16}?['\"]([a-f0-9]{64})['\"]"),
        severity=Severity.MEDIUM,
        keywords=["linode"],
        capture_group=1,
    ),
    SecretPattern(
        id="alibaba_access_key",
        name="Alibaba Cloud AccessKey ID",
        regex=_c(r"\b(LTAI[A-Za-z0-9]{12,20})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    # --- payment / commerce ---------------------------------------------
    SecretPattern(
        id="stripe_webhook",
        name="Stripe webhook signing secret",
        regex=_c(r"\b(whsec_[A-Za-z0-9]{32,})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="braintree_token",
        name="Braintree access token",
        regex=_c(r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b"),
        severity=Severity.CRITICAL,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="razorpay_key",
        name="Razorpay live key id",
        regex=_c(r"\b(rzp_live_[A-Za-z0-9]{14,})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="adyen_key",
        name="Adyen API key (heuristic)",
        regex=_c(r"(?i)adyen.{0,16}?['\"]([A-Za-z0-9+/]{40,})['\"]"),
        severity=Severity.HIGH,
        keywords=["adyen"],
        validator=high_entropy(4.2, 40),
        capture_group=1,
    ),
    # --- comms / messaging ----------------------------------------------
    SecretPattern(
        id="twilio_account_sid",
        name="Twilio Account SID",
        regex=_c(r"\b(AC[a-f0-9]{32})\b"),
        severity=Severity.MEDIUM,
        keywords=["twilio", "ac"],
        capture_group=1,
    ),
    SecretPattern(
        id="twilio_api_key",
        name="Twilio API key SID",
        regex=_c(r"\b(SK[a-f0-9]{32})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="discord_token",
        name="Discord bot token",
        regex=_c(r"\b([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="discord_webhook",
        name="Discord webhook URL",
        regex=_c(r"\b(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)\b"),
        severity=Severity.MEDIUM,
        capture_group=1,
    ),
    SecretPattern(
        id="telegram_bot",
        name="Telegram bot token",
        regex=_c(r"\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b"),
        severity=Severity.HIGH,
        capture_group=1,
    ),
    SecretPattern(
        id="onesignal_key",
        name="OneSignal REST API key (heuristic)",
        regex=_c(r"(?i)onesignal.{0,20}?['\"]([A-Za-z0-9]{48})['\"]"),
        severity=Severity.MEDIUM,
        keywords=["onesignal"],
        capture_group=1,
    ),
    # --- analytics / SaaS -----------------------------------------------
    SecretPattern(
        id="datadog_key",
        name="Datadog API key (heuristic)",
        regex=_c(r"(?i)datadog.{0,20}?['\"]([a-f0-9]{32})['\"]"),
        severity=Severity.MEDIUM,
        keywords=["datadog", "dd_api"],
        capture_group=1,
    ),
    SecretPattern(
        id="newrelic_key",
        name="New Relic license/API key",
        regex=_c(r"\b(NRAK-[A-Z0-9]{27})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="sentry_dsn",
        name="Sentry DSN (contains secret)",
        regex=_c(r"\b(https://[a-f0-9]{32}@[a-z0-9.\-]+/[0-9]+)\b"),
        severity=Severity.LOW,
        keywords=["sentry", "@"],
        capture_group=1,
    ),
    SecretPattern(
        id="segment_write_key",
        name="Segment write key (heuristic)",
        regex=_c(r"(?i)segment.{0,20}?['\"]([A-Za-z0-9]{32})['\"]"),
        severity=Severity.LOW,
        keywords=["segment", "writekey"],
        capture_group=1,
    ),
    SecretPattern(
        id="mixpanel_token",
        name="Mixpanel project token (heuristic)",
        regex=_c(r"(?i)mixpanel.{0,20}?['\"]([a-f0-9]{32})['\"]"),
        severity=Severity.LOW,
        keywords=["mixpanel"],
        capture_group=1,
    ),
    # --- source control / CI --------------------------------------------
    SecretPattern(
        id="github_fine_grained",
        name="GitHub fine-grained PAT",
        regex=_c(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="gitlab_pat_v2",
        name="GitLab personal access token",
        regex=_c(r"\b(glpat-[A-Za-z0-9_-]{20})\b"),
        severity=Severity.HIGH,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="gitlab_pipeline",
        name="GitLab CI/CD pipeline trigger token",
        regex=_c(r"\b(glptt-[0-9a-f]{40})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="dockerhub_pat",
        name="Docker Hub personal access token",
        regex=_c(r"\b(dckr_pat_[A-Za-z0-9_-]{27,})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="npm_token_v2",
        name="npm access token",
        regex=_c(r"\b(npm_[A-Za-z0-9]{36})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    SecretPattern(
        id="pypi_token",
        name="PyPI upload token",
        regex=_c(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"),
        severity=Severity.MEDIUM,
        confidence="certain",
        capture_group=1,
    ),
    # --- generic / cryptographic ----------------------------------------
    SecretPattern(
        id="private_key_block",
        name="Private key PEM block",
        regex=_c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        confidence="certain",
    ),
    SecretPattern(
        id="generic_secret_assign",
        name="Generic secret/password assignment",
        regex=_c(r"(?i)(?:secret|passwd|password|pwd|apikey|api_key|token|auth)\s*[=:]\s*['\"]([^'\"\s]{8,64})['\"]"),
        severity=Severity.LOW,
        confidence="tentative",
        keywords=["secret", "password", "passwd", "pwd", "apikey", "api_key", "token", "auth"],
        validator=not_placeholder,
        capture_group=1,
    ),
    SecretPattern(
        id="basic_auth_header",
        name="HTTP Basic auth credentials (base64)",
        regex=_c(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/]{16,}={0,2})"),
        severity=Severity.MEDIUM,
        keywords=["authorization", "basic"],
        capture_group=1,
    ),
    SecretPattern(
        id="oauth_refresh_generic",
        name="OAuth refresh token (heuristic)",
        regex=_c(r"(?i)refresh[_-]?token.{0,8}?['\"]([A-Za-z0-9._\-/+]{20,})['\"]"),
        severity=Severity.MEDIUM,
        keywords=["refresh_token", "refreshtoken"],
        validator=high_entropy(3.5, 20),
        capture_group=1,
    ),
]


# patterns that match URLs / endpoints (used by the secrets module to harvest
# the app's API surface for later dynamic testing)
URL_PATTERNS: List[Pattern] = [
    _c(r"\bhttps?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./%?#=&+~:@!$'()*,;]*)?"),
    _c(r"\bwss?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./%?#=&+~:@!$'()*,;]*)?"),
    _c(r"\bgrpc[s]?://[A-Za-z0-9\.\-]+(?::\d+)?"),
]

IP_PATTERN = _c(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# domains we don't care about as "endpoints"
URL_NOISE = (
    "schemas.android.com",
    "w3.org",
    "apache.org",
    "android.com/apk",
    "xmlpull.org",
    "java.sun.com",
    "localhost",
    "127.0.0.1",
    "example.com",
)


def is_noise_url(url: str) -> bool:
    return any(n in url for n in URL_NOISE)


if __name__ == "__main__":
    tests = [
        ('String k = "AKIAIOSFODNN7EXAMPLE";', "aws_access_key"),
        ('apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";', "gcp_api_key"),
        ('stripe = "sk_live_NOT_A_REAL_STRIPE_KEY_XXXXXXXXXXXXXXXX";', "stripe_live"),
        ('token = "ghp_1234567890abcdefghij1234567890abcdef";', "github_pat"),
        ('auth: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456";', "jwt"),
    ]
    total = sum(1 for p in SECRET_PATTERNS)
    print(f"loaded {total} secret patterns\n")
    for line, expected in tests:
        matched = []
        for p in SECRET_PATTERNS:
            if p.scan_line(line):
                matched.append(p.id)
        status = "OK" if expected in matched else "MISS"
        print(f"[{status}] expected={expected:<18} matched={matched}")
