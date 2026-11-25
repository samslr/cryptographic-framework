import sqlite3

from core import database
from core.security import hash_password


def test_fresh_database_has_no_default_login_and_supports_explicit_admin(
    client, monkeypatch, tmp_path
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "fresh.sqlite3")
    monkeypatch.delenv("APP_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("APP_ADMIN_PASSWORD", raising=False)

    database.init_and_migrate_db()
    failed_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@SecVault2026!"},
    )
    assert failed_login.status_code == 401

    with sqlite3.connect(database.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    monkeypatch.setenv("APP_ADMIN_USERNAME", "site-admin")
    monkeypatch.setenv("APP_ADMIN_PASSWORD", "Unique-Test-Admin-Password")
    database.init_and_migrate_db()

    successful_login = client.post(
        "/api/auth/login",
        json={"username": "site-admin", "password": "Unique-Test-Admin-Password"},
    )
    assert successful_login.status_code == 200
    assert successful_login.get_json()["user"]["role"] == "Administrator"


def test_legacy_demo_accounts_and_their_existing_sessions_are_revoked(
    client, monkeypatch, tmp_path
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "legacy.sqlite3")
    monkeypatch.delenv("APP_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("APP_ADMIN_PASSWORD", raising=False)

    with sqlite3.connect(database.DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (
                "admin",
                hash_password("Admin@SecVault2026!"),
                "Administrator",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    with client.session_transaction() as session:
        session["user"] = {"id": 1, "username": "admin", "role": "Administrator"}

    database.init_and_migrate_db()

    identity = client.get("/api/auth/me").get_json()
    assert identity["authenticated"] is False
    failed_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@SecVault2026!"},
    )
    assert failed_login.status_code == 401
