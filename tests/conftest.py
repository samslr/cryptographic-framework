import os
import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app
from core.database import init_and_migrate_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    init_and_migrate_db()

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
