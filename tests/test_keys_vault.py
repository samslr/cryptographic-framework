import pytest

def test_aes_key_lifecycle(admin_client):
    # 1. Generate AES key
    res = admin_client.post("/api/keys/aes", json={"name": "Test AES Key"})
    assert res.status_code == 201
    data = res.get_json()
    key_id = data["key_id"]
    assert "fingerprint" in data
    assert data["fingerprint"].startswith("SHA256:")

    # 2. Verify key in inventory
    res_list = admin_client.get("/api/keys")
    assert res_list.status_code == 200
    keys = res_list.get_json()["keys"]
    found = [k for k in keys if k["id"] == key_id]
    assert len(found) == 1
    assert found[0]["status"] == "ACTIVE"
    assert found[0]["key_type"] == "SYMMETRIC"
    assert "secret_enc" not in found[0]  # Verify secrets are NEVER exposed in inventory!

    # 3. Rotate key
    res_rot = admin_client.post(f"/api/keys/{key_id}/rotate")
    assert res_rot.status_code == 200
    new_key_id = res_rot.get_json()["new_key_id"]

    # Verify old key is ROTATED, new is ACTIVE
    res_list2 = admin_client.get("/api/keys")
    keys2 = res_list2.get_json()["keys"]
    old_key = next(k for k in keys2 if k["id"] == key_id)
    new_key = next(k for k in keys2 if k["id"] == new_key_id)
    assert old_key["status"] == "ROTATED"
    assert new_key["status"] == "ACTIVE"
    assert new_key["rotated_from"] == key_id

    # 4. Delete key
    res_del = admin_client.delete(f"/api/keys/{new_key_id}")
    assert res_del.status_code == 200


def test_rsa_key_lifecycle_and_export(admin_client):
    # 1. Generate RSA key pair
    res = admin_client.post("/api/keys/rsa", json={"name": "Test RSA Key Pair"})
    assert res.status_code == 201
    key_id = res.get_json()["key_id"]

    # 2. Export public key PEM
    res_pub = admin_client.get(f"/api/keys/{key_id}/public")
    assert res_pub.status_code == 200
    pub_data = res_pub.get_json()
    assert "-----BEGIN PUBLIC KEY-----" in pub_data["public_pem"]
    assert pub_data["fingerprint"].startswith("SHA256:")
    assert "secret" not in pub_data
    assert "private" not in pub_data
