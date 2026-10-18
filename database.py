"""Local SQLite persistence for traps and triggered alerts."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "spectresync.db"


def _connect() -> sqlite3.Connection:
    """Return a connection with row-factory enabled."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS traps (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                trap_name    TEXT    NOT NULL,
                trap_type    TEXT    NOT NULL,
                target_path  TEXT    NOT NULL,
                endpoint_url TEXT    NOT NULL UNIQUE,
                created_at   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                trap_id    INTEGER NOT NULL REFERENCES traps(id),
                timestamp  TEXT    NOT NULL,
                source_ip  TEXT    NOT NULL,
                user_agent TEXT    NOT NULL DEFAULT '',
                status     TEXT    NOT NULL DEFAULT 'Triggered'
            );
        """)


# -- Trap helpers --------------------------------------------------------------

def save_trap(
    trap_name: str,
    trap_type: str,
    target_path: str,
    endpoint_url: str,
) -> int:
    """Insert a trap and return its row id."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO traps (trap_name, trap_type, target_path, endpoint_url, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (trap_name, trap_type, target_path, endpoint_url, now),
        )
        return cur.lastrowid


def get_all_traps() -> list[dict[str, Any]]:
    """Return every trap as a list of dicts."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, trap_name, trap_type, target_path, endpoint_url, created_at "
            "FROM traps ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# -- Alert helpers -------------------------------------------------------------

def record_alert(
    trap_id: int,
    source_ip: str,
    user_agent: str = "",
    status: str = "Triggered",
) -> int:
    """Log an alert against a trap and return the alert row id."""
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (trap_id, timestamp, source_ip, user_agent, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (trap_id, now, source_ip, user_agent, status),
        )
        return cur.lastrowid


def get_all_alerts() -> list[dict[str, Any]]:
    """Return every alert joined with its trap name."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT a.id, a.trap_id, t.trap_name, a.timestamp, "
            "       a.source_ip, a.user_agent, a.status "
            "FROM alerts a JOIN traps t ON a.trap_id = t.id "
            "ORDER BY a.timestamp DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# Auto-initialize on import
init_db()

