"""SQLite storage for scans and findings (stdlib only; swap for MySQL later if needed)."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    module_id TEXT NOT NULL,
    status TEXT NOT NULL,
    progress REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    input_name TEXT,
    input_path TEXT,
    options TEXT NOT NULL DEFAULT '{}',
    rows_scanned INTEGER,
    error TEXT,
    log TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    host TEXT,
    asset TEXT NOT NULL DEFAULT '{}',
    score REAL,
    confidence REAL,
    mitre TEXT,
    evidence TEXT NOT NULL DEFAULT '[]',
    top_features TEXT NOT NULL DEFAULT '[]',
    recommendation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    feedback_note TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def connect():
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Scans interrupted by a server restart can never finish.
        conn.execute(
            "UPDATE scans SET status='failed', error='Interrupted by server restart', finished_at=? "
            "WHERE status IN ('queued', 'running')", (now(),))


# ── scans ────────────────────────────────────────────────────────────────────

def create_scan(scan: dict) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, name, module_id, status, created_at, input_name, input_path, options) "
            "VALUES (:id, :name, :module_id, 'queued', :created_at, :input_name, :input_path, :options)",
            {**scan, "options": json.dumps(scan.get("options", {}))})


def update_scan(scan_id: str, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with connect() as conn:
        conn.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*fields.values(), scan_id))


def append_log(scan_id: str, line: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    with _lock, connect() as conn:
        row = conn.execute("SELECT log FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return
        log = json.loads(row["log"])
        log.append(f"[{stamp}] {line}")
        conn.execute("UPDATE scans SET log = ? WHERE id = ?", (json.dumps(log[-2000:]), scan_id))


def _counts(conn, where: str = "", params: tuple = ()) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    for r in conn.execute(f"SELECT severity, COUNT(*) n FROM findings {where} GROUP BY severity", params):
        counts[r["severity"]] = r["n"]
    return counts


def _scan_dict(conn, row: sqlite3.Row, with_log: bool = False) -> dict:
    from .modules import BY_ID
    module = BY_ID.get(row["module_id"])
    d = {k: row[k] for k in ("id", "name", "module_id", "status", "progress", "created_at",
                             "started_at", "finished_at", "input_name", "rows_scanned", "error")}
    d["module_name"] = module.name if module else row["module_id"]
    d["options"] = json.loads(row["options"])
    d["counts"] = _counts(conn, "WHERE scan_id = ?", (row["id"],))
    if with_log:
        d["log"] = json.loads(row["log"])
    return d


def list_scans() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
        return [_scan_dict(conn, r) for r in rows]


def get_scan(scan_id: str, with_log: bool = True) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan_dict(conn, row, with_log) if row else None


def get_scan_input(scan_id: str) -> tuple[str, dict] | None:
    with connect() as conn:
        row = conn.execute("SELECT input_path, options FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return (row["input_path"], json.loads(row["options"])) if row else None


def delete_scan(scan_id: str) -> bool:
    with connect() as conn:
        return conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0


# ── findings ─────────────────────────────────────────────────────────────────

JSON_FIELDS = ("asset", "mitre", "evidence", "top_features")


def insert_findings(scan_id: str, module_id: str, findings: list[dict]) -> None:
    created = now()
    rows = []
    for f in findings:
        severity = str(f.get("severity", "info")).lower()
        rows.append((
            scan_id, module_id, severity if severity in SEVERITY_RANK else "info",
            f.get("title") or "Finding", f.get("description"), f.get("host"),
            json.dumps(f.get("asset") or {}), f.get("score"), f.get("confidence"),
            json.dumps(f["mitre"]) if f.get("mitre") else None,
            json.dumps(f.get("evidence") or []), json.dumps(f.get("top_features") or []),
            f.get("recommendation"), created,
        ))
    with connect() as conn:
        conn.executemany(
            "INSERT INTO findings (scan_id, module_id, severity, title, description, host, asset, score, "
            "confidence, mitre, evidence, top_features, recommendation, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)


def _finding_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in JSON_FIELDS:
        d[k] = json.loads(d[k]) if d[k] else None
    d["evidence"] = d["evidence"] or []
    d["top_features"] = d["top_features"] or []
    d["asset"] = d["asset"] or {}
    return d


def _filters(scan_id=None, severity=None, module_id=None, status=None, host=None, q=None):
    clauses, params = [], []
    for col, val in (("scan_id", scan_id), ("severity", severity), ("module_id", module_id),
                     ("status", status), ("host", host)):
        if val:
            values = val.split(",")
            clauses.append(f"{col} IN ({','.join('?' * len(values))})")
            params += values
    if q:
        clauses.append("(title LIKE ? OR description LIKE ? OR host LIKE ?)")
        params += [f"%{q}%"] * 3
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", tuple(params)


SEVERITY_ORDER_SQL = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                      "WHEN 'low' THEN 3 ELSE 4 END")


def list_findings(limit: int = 50, offset: int = 0, **filters) -> dict:
    where, params = _filters(**filters)
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM findings {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY {SEVERITY_ORDER_SQL}, score DESC, id "
            f"LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
    return {"total": total, "items": [_finding_dict(r) for r in rows]}


def finding_groups(scan_id: str | None = None) -> list[dict]:
    where, params = _filters(scan_id=scan_id)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT title, module_id, MIN({SEVERITY_ORDER_SQL}) sev, COUNT(*) count, "
            f"COUNT(DISTINCT host) hosts FROM findings {where} GROUP BY title, module_id "
            f"ORDER BY sev, count DESC", params).fetchall()
    return [{"title": r["title"], "module_id": r["module_id"], "severity": SEVERITIES[r["sev"]],
             "count": r["count"], "hosts": r["hosts"]} for r in rows]


def update_finding(finding_id: int, status: str | None, note: str | None) -> dict | None:
    fields = {}
    if status is not None:
        fields["status"] = status
    if note is not None:
        fields["feedback_note"] = note
    with connect() as conn:
        if fields:
            cols = ", ".join(f"{k} = ?" for k in fields)
            conn.execute(f"UPDATE findings SET {cols} WHERE id = ?", (*fields.values(), finding_id))
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return _finding_dict(row) if row else None


def hosts(scan_id: str | None = None, limit: int | None = None) -> list[dict]:
    where, params = _filters(scan_id=scan_id)
    where = (where + " AND " if where else "WHERE ") + "host IS NOT NULL"
    with connect() as conn:
        rows = conn.execute(
            f"SELECT host, COUNT(*) findings, MIN({SEVERITY_ORDER_SQL}) sev, MAX(created_at) last_seen, "
            f"GROUP_CONCAT(DISTINCT module_id) modules, "
            + ", ".join(f"SUM(severity = '{s}') {s}" for s in SEVERITIES)
            + f" FROM findings {where} GROUP BY host ORDER BY sev, findings DESC"
            + (f" LIMIT {int(limit)}" if limit else ""), params).fetchall()
    return [{"host": r["host"], "findings": r["findings"], "max_severity": SEVERITIES[r["sev"]],
             "counts": {s: r[s] for s in SEVERITIES}, "modules": (r["modules"] or "").split(","),
             "last_seen": r["last_seen"]} for r in rows]


def stats() -> dict:
    from .modules import BY_ID
    with connect() as conn:
        scans_total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        running = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        open_ch = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status IN ('open','confirmed') "
            "AND severity IN ('critical','high')").fetchone()[0]
        by_module = [{"module_id": r["module_id"], "name": BY_ID[r["module_id"]].name
                      if r["module_id"] in BY_ID else r["module_id"], "count": r["n"]}
                     for r in conn.execute(
                         "SELECT module_id, COUNT(*) n FROM findings GROUP BY module_id ORDER BY n DESC")]
        timeline = []
        for r in conn.execute(
                "SELECT substr(created_at, 1, 10) date, "
                + ", ".join(f"SUM(severity = '{s}') {s}" for s in SEVERITIES)
                + " FROM findings GROUP BY date ORDER BY date"):
            timeline.append({"date": r["date"], **{s: r[s] for s in SEVERITIES}})
        feedback = dict.fromkeys(["open", "confirmed", "false_positive", "resolved"], 0)
        for r in conn.execute("SELECT status, COUNT(*) n FROM findings GROUP BY status"):
            feedback[r["status"]] = r["n"]
        recent = [_finding_dict(r) for r in conn.execute(
            f"SELECT * FROM findings ORDER BY created_at DESC, {SEVERITY_ORDER_SQL}, score DESC LIMIT 8")]
        by_severity = _counts(conn)
    return {"scans_total": scans_total, "scans_running": running, "findings_total": total,
            "open_critical_high": open_ch, "by_severity": by_severity, "by_module": by_module,
            "top_hosts": hosts(limit=8), "timeline": timeline, "feedback": feedback,
            "recent_findings": recent}
