"""Transactional cache and append-only event records."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def cache_key(configuration: dict) -> str:
    serialized = json.dumps(configuration, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


class ArtifactStore:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=30)
        try:
            self.connection.execute('PRAGMA journal_mode=WAL')
            self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS artifacts (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL, stage TEXT NOT NULL,
                payload TEXT NOT NULL, created_at TEXT NOT NULL
            );
            ''')
        except sqlite3.Error:
            self.connection.close()
            raise ValueError('Cache SQLite non valida o non accessibile') from None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.connection.close()

    def get(self, key: str) -> dict | None:
        row = self.connection.execute('SELECT value FROM artifacts WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, value: dict) -> None:
        serialized = json.dumps(value, sort_keys=True, allow_nan=False)
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            self.connection.execute('INSERT OR REPLACE INTO artifacts VALUES (?, ?, ?)', (key, serialized, now))

    def record(self, job_id: str, stage: str, payload: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            self.connection.execute('INSERT INTO events(job_id,stage,payload,created_at) VALUES (?,?,?,?)',
                                    (job_id, stage, json.dumps(payload, allow_nan=False), now))

    def events(self, job_id: str) -> list[dict]:
        rows = self.connection.execute('SELECT stage,payload,created_at FROM events WHERE job_id=? ORDER BY sequence', (job_id,)).fetchall()
        return [{'stage': stage, 'payload': json.loads(payload), 'created_at': timestamp} for stage, payload, timestamp in rows]
