import pytest
from core.security import hash_password, verify_password, ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER

def test_password_hashing():
    pwd = "SuperSecretPassword123!"
    hashed = hash_password(pwd)
    assert hashed.startswith("scrypt$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False

def test_auth_login_success(client):
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "Admin@SecVault2026!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == ROLE_ADMIN
    assert "csrf_token" in data

def test_auth_login_failure(client):
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "BadPassword123"
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data["code"] == "INVALID_CREDENTIALS"

def test_auth_me_authenticated(client):
    client.post("/api/auth/login", json={
        "username": "operator",
        "password": "Operator@SecVault2026!"
    })
    client.get("/")
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    data = res.get_json()
    assert data["authenticated"] is True
    assert data["user"]["username"] == "operator"
    assert data["user"]["role"] == ROLE_OPERATOR

def test_auth_logout(client):
    client.post("/api/auth/login", json={
        "username": "auditor",
        "password": "Auditor@SecVault2026!"
    })
    res_logout = client.post("/api/auth/logout")
    assert res_logout.status_code == 200

    res_me = client.get("/api/auth/me")
    data = res_me.get_json()
    assert data["authenticated"] is False
    assert data["user"]["username"] == "guest"


def test_rbac_role_enforcement(client, admin_client, operator_client, auditor_client):
    # 1. Auditor (Viewer) cannot generate keys (Requires Administrator)
    res_key_viewer = auditor_client.post("/api/keys/aes", json={"name": "Viewer Key Attempt"})
    assert res_key_viewer.status_code == 403
    assert res_key_viewer.get_json()["code"] == "FORBIDDEN"

    # 2. Auditor (Viewer) cannot execute symmetric encryption (Requires Operator or Administrator)
    res_enc_viewer = auditor_client.post("/api/symmetric/encrypt", json={"key_id": 1, "text": "secret"})
    assert res_enc_viewer.status_code == 403
    assert res_enc_viewer.get_json()["code"] == "FORBIDDEN"

    # 3. Operator CAN encrypt
    # First admin generates key
    res_key = admin_client.post("/api/keys/aes", json={"name": "RBAC Test Key"})
    key_id = res_key.get_json()["key_id"]

    res_enc_operator = operator_client.post("/api/symmetric/encrypt", json={"key_id": key_id, "text": "operator payload"})
    assert res_enc_operator.status_code == 200

    # 4. Operator CANNOT delete key (Requires Administrator)
    res_del_operator = operator_client.delete(f"/api/keys/{key_id}")
    assert res_del_operator.status_code == 403
    assert res_del_operator.get_json()["code"] == "FORBIDDEN"

    # 5. Admin CAN delete key
    res_del_admin = admin_client.delete(f"/api/keys/{key_id}")
    assert res_del_admin.status_code == 200


def test_homepage_does_not_authenticate_or_authorize_anonymous_visitors(client):
    assert client.get("/").status_code == 200

    identity = client.get("/api/auth/me").get_json()
    assert identity["authenticated"] is False
    assert identity["user"]["username"] == "guest"
    assert identity["user"]["role"] == ROLE_VIEWER

    result = client.post("/api/keys/aes", json={"name": "Unauthenticated Key"})
    assert result.status_code == 401
    assert result.get_json()["code"] == "UNAUTHORIZED"

