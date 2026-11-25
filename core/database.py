import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import g
from core.crypto_vault import compute_fingerprint, decrypt_secret
from core.security import hash_password, verify_password, ROLE_ADMIN

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

    revoke_legacy_default_users(conn)
    seed_configured_admin(conn)
    conn.close()


def revoke_legacy_default_users(conn: sqlite3.Connection):
    """Remove built-in demo accounts left behind by older versions."""
    legacy_accounts = (
        ("admin", "Admin@SecVault2026!"),
        ("operator", "Operator@SecVault2026!"),
        ("auditor", "Auditor@SecVault2026!"),
    )
    for username, password in legacy_accounts:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if row and verify_password(password, row["password_hash"]):
            conn.execute("DELETE FROM users WHERE id = ?", (row["id"],))
    conn.commit()


def seed_configured_admin(conn: sqlite3.Connection):
    """Create an initial administrator only when explicitly configured."""
    username = os.environ.get("APP_ADMIN_USERNAME", "").strip()
    password = os.environ.get("APP_ADMIN_PASSWORD", "")
    if not username and not password:
        return
    if not username or not password:
        raise RuntimeError("Set both APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD to provision an administrator.")
    if len(password) < 12:
        raise RuntimeError("APP_ADMIN_PASSWORD must contain at least 12 characters.")
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return

    conn.execute(
        "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), ROLE_ADMIN, utc_now_iso())
    )
    conn.commit()
