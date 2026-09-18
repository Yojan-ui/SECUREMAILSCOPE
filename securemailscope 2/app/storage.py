"""SQLite scan history.

Stores the full assessment as JSON alongside indexed columns for listing. Also
backs the result cache: repeat scans of the same domain inside the cache window
are served from here rather than re-querying the target's DNS.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Assessment

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "scans.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,
    domain      TEXT NOT NULL,
    score       INTEGER,
    grade       TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    narrative_source TEXT,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
"""


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def save(self, assessment: Assessment) -> str:
        payload = json.dumps(assessment.to_dict(), default=str)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans "
                "(scan_id, domain, score, grade, started_at, finished_at, "
                " narrative_source, payload) VALUES (?,?,?,?,?,?,?,?)",
                (
                    assessment.scan_id,
                    assessment.domain,
                    assessment.score.score if assessment.score else None,
                    assessment.score.grade if assessment.score else None,
                    assessment.started_at,
                    assessment.finished_at,
                    assessment.narrative.source if assessment.narrative else None,
                    payload,
                ),
            )
        return assessment.scan_id or ""

    def get(self, scan_id: str) -> dict[str, Any] | None:
        row = self._conn().execute(
            "SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT scan_id, domain, score, grade, started_at, narrative_source "
            "FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def history_for(self, domain: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT scan_id, domain, score, grade, started_at "
            "FROM scans WHERE domain = ? ORDER BY started_at DESC LIMIT ?",
            (domain, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def cached_scan(self, domain: str, max_age_minutes: int = 15) -> dict[str, Any] | None:
        """Return a recent scan of this domain, if one exists inside the window.

        This is what keeps repeated scans of the same domain from generating
        repeated DNS traffic against the target.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)).isoformat()
        row = self._conn().execute(
            "SELECT payload FROM scans WHERE domain = ? AND started_at >= ? "
            "ORDER BY started_at DESC LIMIT 1",
            (domain, cutoff),
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def stats(self) -> dict[str, Any]:
        row = self._conn().execute(
            "SELECT COUNT(*) AS total, COUNT(DISTINCT domain) AS domains, "
            "AVG(score) AS avg_score FROM scans WHERE score >= 0"
        ).fetchone()
        return {
            "total_scans": row["total"] or 0,
            "unique_domains": row["domains"] or 0,
            "average_score": round(row["avg_score"], 1) if row["avg_score"] else None,
        }
