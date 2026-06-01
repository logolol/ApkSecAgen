"""
APKOwl :: core.db
=================

A thin, dependency-free SQLite persistence layer.

Everything the tool discovers is written here immediately so that:

* a crash mid-scan still leaves you with partial results,
* runs can be compared over time (the same package scanned twice),
* the reporter reads from a single source of truth.

The schema is intentionally simple and denormalised where it helps query
ergonomics. All access goes through the :class:`Database` facade so the rest of
the codebase never touches raw SQL.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from core.findings import Evidence, Finding, OWASPMobile, Severity


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    apk_path        TEXT NOT NULL,
    apk_sha256      TEXT,
    package_name    TEXT,
    version_name    TEXT,
    version_code    TEXT,
    started_at      REAL,
    finished_at     REAL,
    status          TEXT DEFAULT 'running',
    tool_version    TEXT,
    meta_json       TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    finding_id      TEXT,
    dedupe_key      TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    module          TEXT,
    severity        INTEGER,
    severity_label  TEXT,
    cvss_vector     TEXT,
    cvss_score      REAL,
    cwe             TEXT,
    owasp_code      TEXT,
    owasp_title     TEXT,
    remediation     TEXT,
    confidence      TEXT,
    references_json TEXT,
    tags_json       TEXT,
    created_at      REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_db_id   INTEGER NOT NULL,
    file_path       TEXT,
    line_number     INTEGER,
    snippet         TEXT,
    extra_json      TEXT,
    FOREIGN KEY (finding_db_id) REFERENCES findings (id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    kind            TEXT,
    path            TEXT,
    sha256          TEXT,
    size            INTEGER,
    note            TEXT,
    created_at      REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    url             TEXT,
    method          TEXT,
    source          TEXT,
    note            TEXT,
    created_at      REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS kv (
    scan_id         INTEGER NOT NULL,
    key             TEXT,
    value_json      TEXT,
    PRIMARY KEY (scan_id, key)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_dedupe ON findings (scan_id, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence (finding_db_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints (scan_id);
"""


class Database:
    """Facade over a single SQLite file.

    Thread-safe for the access patterns used by the orchestrator: a global
    lock guards writes, while reads use short-lived cursors. SQLite is opened
    with ``check_same_thread=False`` so the async pipeline's thread-pool
    workers can persist findings as they go.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._lock = threading.RLock()
        self._scan_id: Optional[int] = None
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- context management ------------------------------------------------
    @contextmanager
    def _cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    # -- scan lifecycle ----------------------------------------------------
    def begin_scan(
        self,
        apk_path: str,
        apk_sha256: str = "",
        tool_version: str = "",
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO scans (apk_path, apk_sha256, started_at,
                                      status, tool_version)
                   VALUES (?, ?, ?, 'running', ?)""",
                (apk_path, apk_sha256, time.time(), tool_version),
            )
            self._scan_id = cur.lastrowid
        return self._scan_id

    @property
    def scan_id(self) -> int:
        if self._scan_id is None:
            raise RuntimeError("No active scan; call begin_scan() first.")
        return self._scan_id

    def update_scan_meta(
        self,
        package_name: str = "",
        version_name: str = "",
        version_code: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._cursor() as cur:
            cur.execute(
                """UPDATE scans
                   SET package_name=COALESCE(NULLIF(?,''), package_name),
                       version_name=COALESCE(NULLIF(?,''), version_name),
                       version_code=COALESCE(NULLIF(?,''), version_code),
                       meta_json=COALESCE(?, meta_json)
                   WHERE id=?""",
                (
                    package_name,
                    version_name,
                    version_code,
                    json.dumps(meta) if meta is not None else None,
                    self.scan_id,
                ),
            )

    def update_scan_hashes(
        self, apk_sha256: str = "", apk_md5: str = "", apk_size: int = 0
    ) -> None:
        """Persist the APK hash to its column and md5/size into kv."""
        if apk_sha256:
            with self._cursor() as cur:
                cur.execute(
                    "UPDATE scans SET apk_sha256=? WHERE id=?",
                    (apk_sha256, self.scan_id),
                )
        if apk_md5:
            self.set_kv("apk_md5", apk_md5)
        if apk_size:
            self.set_kv("apk_size", apk_size)

    def finish_scan(self, status: str = "completed") -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE scans SET finished_at=?, status=? WHERE id=?",
                (time.time(), status, self.scan_id),
            )

    # -- findings ----------------------------------------------------------
    def finding_exists(self, dedupe_key: str) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "SELECT 1 FROM findings WHERE scan_id=? AND dedupe_key=? LIMIT 1",
                (self.scan_id, dedupe_key),
            )
            return cur.fetchone() is not None

    def add_finding(self, finding: Finding) -> Optional[int]:
        """Persist a finding (and its evidence). Returns the row id or None if
        it was a duplicate within this scan."""
        key = finding.dedupe_key()
        if self.finding_exists(key):
            return None
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO findings
                   (scan_id, finding_id, dedupe_key, title, description, module,
                    severity, severity_label, cvss_vector, cvss_score, cwe,
                    owasp_code, owasp_title, remediation, confidence,
                    references_json, tags_json, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    self.scan_id,
                    finding.finding_id,
                    key,
                    finding.title,
                    finding.description,
                    finding.module,
                    int(finding.severity),
                    finding.severity.name,
                    finding.cvss_vector,
                    finding.cvss_score,
                    finding.cwe,
                    finding.owasp.code,
                    finding.owasp.title,
                    finding.remediation,
                    finding.confidence,
                    json.dumps(finding.references),
                    json.dumps(finding.tags),
                    finding.created_at,
                ),
            )
            fid = cur.lastrowid
            for ev in finding.evidence:
                cur.execute(
                    """INSERT INTO evidence
                       (finding_db_id, file_path, line_number, snippet, extra_json)
                       VALUES (?,?,?,?,?)""",
                    (
                        fid,
                        ev.file_path,
                        ev.line_number,
                        ev.snippet[:4000],
                        json.dumps(ev.extra),
                    ),
                )
        return fid

    def add_findings(self, findings: Iterable[Finding]) -> int:
        count = 0
        for f in findings:
            if self.add_finding(f) is not None:
                count += 1
        return count

    def get_findings(self, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sid = scan_id if scan_id is not None else self.scan_id
        with self._cursor() as cur:
            cur.execute(
                """SELECT * FROM findings WHERE scan_id=?
                   ORDER BY severity DESC, cvss_score DESC, title ASC""",
                (sid,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            for row in rows:
                cur.execute(
                    "SELECT * FROM evidence WHERE finding_db_id=?", (row["id"],)
                )
                row["evidence"] = [dict(e) for e in cur.fetchall()]
                row["references"] = json.loads(row.get("references_json") or "[]")
                row["tags"] = json.loads(row.get("tags_json") or "[]")
        return rows

    def severity_counts(self, scan_id: Optional[int] = None) -> Dict[str, int]:
        sid = scan_id if scan_id is not None else self.scan_id
        counts = {s.name: 0 for s in Severity}
        with self._cursor() as cur:
            cur.execute(
                """SELECT severity_label, COUNT(*) AS n FROM findings
                   WHERE scan_id=? GROUP BY severity_label""",
                (sid,),
            )
            for r in cur.fetchall():
                counts[r["severity_label"]] = r["n"]
        return counts

    # -- artifacts ---------------------------------------------------------
    def add_artifact(
        self,
        kind: str,
        path: str,
        sha256: str = "",
        size: int = 0,
        note: str = "",
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO artifacts (scan_id, kind, path, sha256, size, note, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (self.scan_id, kind, path, sha256, size, note, time.time()),
            )
            return cur.lastrowid

    def get_artifacts(self, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sid = scan_id if scan_id is not None else self.scan_id
        with self._cursor() as cur:
            cur.execute("SELECT * FROM artifacts WHERE scan_id=?", (sid,))
            return [dict(r) for r in cur.fetchall()]

    # -- endpoints ---------------------------------------------------------
    def add_endpoint(
        self, url: str, method: str = "", source: str = "", note: str = ""
    ) -> None:
        with self._cursor() as cur:
            cur.execute(
                "SELECT 1 FROM endpoints WHERE scan_id=? AND url=? AND method=? LIMIT 1",
                (self.scan_id, url, method),
            )
            if cur.fetchone():
                return
            cur.execute(
                """INSERT INTO endpoints (scan_id, url, method, source, note, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (self.scan_id, url, method, source, note, time.time()),
            )

    def get_endpoints(self, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sid = scan_id if scan_id is not None else self.scan_id
        with self._cursor() as cur:
            cur.execute("SELECT * FROM endpoints WHERE scan_id=? ORDER BY url", (sid,))
            return [dict(r) for r in cur.fetchall()]

    # -- arbitrary key/value blobs ----------------------------------------
    def set_kv(self, key: str, value: Any) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO kv (scan_id, key, value_json) VALUES (?,?,?)
                   ON CONFLICT(scan_id, key) DO UPDATE SET value_json=excluded.value_json""",
                (self.scan_id, key, json.dumps(value, default=str)),
            )

    def get_kv(self, key: str, default: Any = None) -> Any:
        with self._cursor() as cur:
            cur.execute(
                "SELECT value_json FROM kv WHERE scan_id=? AND key=?",
                (self.scan_id, key),
            )
            row = cur.fetchone()
            if not row:
                return default
            return json.loads(row["value_json"])

    def get_scan(self, scan_id: Optional[int] = None) -> Dict[str, Any]:
        sid = scan_id if scan_id is not None else self.scan_id
        with self._cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=?", (sid,))
            row = cur.fetchone()
            return dict(row) if row else {}

    def list_scans(self) -> List[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.commit()
            self._conn.close()


if __name__ == "__main__":
    import tempfile

    tmp = tempfile.mktemp(suffix=".db")
    db = Database(tmp)
    sid = db.begin_scan("test.apk", "deadbeef", "0.1")
    f = Finding(
        title="Test secret",
        description="A test finding",
        module="secrets",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-798",
    ).add_evidence("a/b/c.java", 42, "String key = \"AKIA...\";")
    db.add_finding(f)
    assert db.add_finding(f) is None, "dedupe should suppress duplicate"
    db.add_endpoint("https://api.example.com/v1/users", "GET", "static")
    db.finish_scan()
    print("findings:", len(db.get_findings()))
    print("severity counts:", db.severity_counts())
    print("endpoints:", len(db.get_endpoints()))
    db.close()
    os.remove(tmp)
    print("db self-test OK")
