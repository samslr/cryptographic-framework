import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import g
from core.crypto_vault import compute_fingerprint, decrypt_secret
from core.security import hash_password, ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER

INSTANCE_DIR = Path(__file__).resolve().parent.parent / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DB_PATH = INSTANCE_DIR / "framework.sqlite3"


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    """Get or establish a thread-safe connection to the SQLite database for the current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_and_migrate_db():
    """
    Safely initialize and migrate SQLite database tables.
    Preserves all existing records and schema columns.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with conn:
        # 1. Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # 2. Keys table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                secret_enc BLOB,
                public_pem TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                rotated_from INTEGER,
                FOREIGN KEY(rotated_from) REFERENCES keys(id) ON DELETE SET NULL
            )
        """)

        # Check existing columns in keys to safely migrate
        key_cols = {row["name"] for row in conn.execute("PRAGMA table_info(keys)").fetchall()}
        if "fingerprint" not in key_cols:
            conn.execute("ALTER TABLE keys ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        if "usage_count" not in key_cols:
            conn.execute("ALTER TABLE keys ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0")
        if "created_by" not in key_cols:
            conn.execute("ALTER TABLE keys ADD COLUMN created_by TEXT NOT NULL DEFAULT 'system'")

        # 3. Audit logs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Check existing columns in audit_logs to safely migrate
        audit_cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_logs)").fetchall()}
        if "operation_id" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN operation_id TEXT DEFAULT ''")
        if "user_id" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN user_id TEXT DEFAULT 'system'")
        if "algorithm" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN algorithm TEXT DEFAULT 'SYSTEM'")
        if "status" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN status TEXT DEFAULT 'SUCCESS'")
        if "duration_ms" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN duration_ms REAL DEFAULT 0.0")

        # Indexes for fast search and query performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")

        # Ensure any existing keys have computed fingerprints
        existing_keys = conn.execute("SELECT id, key_type, secret_enc, public_pem, fingerprint FROM keys").fetchall()
        for k in existing_keys:
            if not k["fingerprint"]:
                fp = "SHA256:UNKNOWN"
                try:
                    if k["key_type"] == "ASYMMETRIC" and k["public_pem"]:
                        fp = compute_fingerprint(k["public_pem"].encode("utf-8"))
                    elif k["secret_enc"]:
                        raw_key = decrypt_secret(k["secret_enc"])
                        fp = compute_fingerprint(raw_key)
                except Exception:
                    pass
                conn.execute("UPDATE keys SET fingerprint = ? WHERE id = ?", (fp, k["id"]))

    # Seed initial default accounts if none exist
    seed_default_users(conn)
    conn.close()


def seed_default_users(conn: sqlite3.Connection):
    """Seed initial administrative and operational accounts if empty."""
    cursor = conn.cursor()
    count = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        now = utc_now_iso()
        default_accounts = [
            ("admin", "Admin@SecVault2026!", ROLE_ADMIN),
            ("operator", "Operator@SecVault2026!", ROLE_OPERATOR),
            ("auditor", "Auditor@SecVault2026!", ROLE_VIEWER)
        ]
        for uname, pwd, role in default_accounts:
            cursor.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (uname, hash_password(pwd), role, now)
            )
        conn.commit()
