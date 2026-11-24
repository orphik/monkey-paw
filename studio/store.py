"""Thread-safe SQLite WAL session store for Monkey's Paw Studio.

Stores PRD refinement sessions, surface summaries, referee findings, parked tangents,
and editable Epic/Capability/Feature/User Story trees under unguessable shareable IDs.
Never persists API keys, GitHub tokens, or passcodes.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENSITIVE_STATE_KEYS: frozenset[str] = frozenset(
    {"api_key", "apiKey", "github_token", "githubToken", "passcode", "authorization"}
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strip_transient_secrets(obj: Any) -> Any:
    """Recursively strip any transient credential keys before SQLite persistence."""
    if isinstance(obj, dict):
        return {
            k: _strip_transient_secrets(v)
            for k, v in obj.items()
            if k not in SENSITIVE_STATE_KEYS
        }
    if isinstance(obj, list):
        return [_strip_transient_secrets(item) for item in obj]
    return obj


class StudioSessionStore:
    """Lightweight concurrent SQLite store backed by WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS studio_sessions (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'greenfield',
                    hierarchy_preset TEXT NOT NULL DEFAULT 'enterprise_4tier',
                    repo_label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    state_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_studio_sessions_updated ON studio_sessions(updated_at DESC);"
            )
            conn.commit()

    def create_session(self, initial_state: dict[str, Any]) -> dict[str, Any]:
        session_id = "s_" + secrets.token_urlsafe(12)
        now = _utc_now()
        clean_state = _strip_transient_secrets(initial_state)
        clean_state["id"] = session_id
        clean_state["created_at"] = now
        clean_state["updated_at"] = now

        title = str(clean_state.get("title") or "Untitled PRD Session").strip()[:160]
        mode = str(clean_state.get("mode") or "greenfield").strip()
        preset = str(clean_state.get("hierarchy_preset") or "enterprise_4tier").strip()
        repo_label = str(clean_state.get("repo_label") or "").strip()[:200]

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO studio_sessions (id, title, mode, hierarchy_preset, repo_label, created_at, updated_at, state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    title,
                    mode,
                    preset,
                    repo_label,
                    now,
                    now,
                    json.dumps(clean_state, ensure_ascii=False),
                ),
            )
            conn.commit()
        return clean_state

    def save_session(self, session_id: str, state: dict[str, Any]) -> dict[str, Any]:
        if not session_id or not session_id.startswith("s_"):
            raise ValueError("Invalid session ID format.")

        now = _utc_now()
        clean_state = _strip_transient_secrets(state)
        clean_state["id"] = session_id
        clean_state["updated_at"] = now

        existing = self.get_session(session_id)
        created_at = existing["created_at"] if existing else now
        clean_state["created_at"] = created_at

        title = str(clean_state.get("title") or "Untitled PRD Session").strip()[:160]
        mode = str(clean_state.get("mode") or "greenfield").strip()
        preset = str(clean_state.get("hierarchy_preset") or "enterprise_4tier").strip()
        repo_label = str(clean_state.get("repo_label") or "").strip()[:200]

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO studio_sessions (id, title, mode, hierarchy_preset, repo_label, created_at, updated_at, state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    mode = excluded.mode,
                    hierarchy_preset = excluded.hierarchy_preset,
                    repo_label = excluded.repo_label,
                    updated_at = excluded.updated_at,
                    state_json = excluded.state_json
                """,
                (
                    session_id,
                    title,
                    mode,
                    preset,
                    repo_label,
                    created_at,
                    now,
                    json.dumps(clean_state, ensure_ascii=False),
                ),
            )
            conn.commit()
        return clean_state

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state_json FROM studio_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["state_json"])

    def list_sessions(self, limit: int = 25) -> list[dict[str, Any]]:
        capped = max(1, min(int(limit), 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, title, mode, hierarchy_preset, repo_label, created_at, updated_at
                FROM studio_sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (capped,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, session_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM studio_sessions WHERE id = ?", (session_id,))
            conn.commit()
            return cur.rowcount > 0
