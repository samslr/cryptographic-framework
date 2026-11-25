import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app
from core.database import DB_PATH, init_and_migrate_db
from core.security import hash_password, ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    init_and_migrate_db()
    accounts = (
        ("admin", "Admin@SecVault2026!", ROLE_ADMIN),
        ("operator", "Operator@SecVault2026!", ROLE_OPERATOR),
        ("auditor", "Auditor@SecVault2026!", ROLE_VIEWER),
    )
    with sqlite3.connect(DB_PATH) as conn:
        for username, password, role in accounts:
            conn.execute(
                """
                INSERT INTO users(username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash,
                    role = excluded.role
                """,
                (username, hash_password(password), role, datetime.now(timezone.utc).isoformat())
            )

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

@pytest.fixture
def admin_client():
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/api/auth/login", json={"username": "admin", "password": "Admin@SecVault2026!"})
    return c

@pytest.fixture
def operator_client():
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/api/auth/login", json={"username": "operator", "password": "Operator@SecVault2026!"})
    return c

@pytest.fixture
def auditor_client():
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/api/auth/login", json={"username": "auditor", "password": "Auditor@SecVault2026!"})
    return c
