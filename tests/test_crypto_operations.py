import io
import base64
import pytest

def test_aes_gcm_roundtrip_and_tamper_rejection(operator_client):
    # 1. Create AES key
    res_key = operator_client.post("/api/keys/aes", json={"name": "AES Test"})
    key_id = res_key.get_json()["key_id"]

    # 2. Encrypt plaintext
    plaintext = "Confidential Capstone Project Data - Top Secret"
    res_enc = operator_client.post("/api/symmetric/encrypt", json={
        "key_id": key_id,
        "text": plaintext
    })
    assert res_enc.status_code == 200
    enc_data = res_enc.get_json()
    assert "ciphertext" in enc_data
    assert "nonce" in enc_data
    assert enc_data["algorithm"] == "AES-256-GCM"
    assert "duration_ms" in enc_data

    # 3. Decrypt ciphertext
    res_dec = operator_client.post("/api/symmetric/decrypt", json={
        "key_id": key_id,
        "nonce": enc_data["nonce"],
        "ciphertext": enc_data["ciphertext"]
    })
    assert res_dec.status_code == 200
    assert res_dec.get_json()["plaintext"] == plaintext

    # 4. Tamper with ciphertext and verify failure
    raw_ct = bytearray(base64.b64decode(enc_data["ciphertext"]))
    raw_ct[0] ^= 0xFF  # Flip bits in ciphertext
    tampered_b64 = base64.b64encode(raw_ct).decode("ascii")

    res_tamper = operator_client.post("/api/symmetric/decrypt", json={
        "key_id": key_id,
        "nonce": enc_data["nonce"],
        "ciphertext": tampered_b64
    })
    assert res_tamper.status_code == 400
    assert "Decryption failed" in res_tamper.get_json()["error"]


def test_rsa_hybrid_and_signatures(operator_client):
    # 1. Generate RSA key
    res_key = operator_client.post("/api/keys/rsa", json={"name": "RSA Test Pair"})
    key_id = res_key.get_json()["key_id"]

    # 2. Hybrid encryption
    message = "Sensitive asymmetric payload for college demonstration."
    res_enc = operator_client.post("/api/asymmetric/encrypt", json={
        "key_id": key_id,
        "text": message
    })
    assert res_enc.status_code == 200
    enc_data = res_enc.get_json()
    assert "wrapped_key" in enc_data
    assert "nonce" in enc_data
    assert "ciphertext" in enc_data

    # 3. Hybrid decryption
    res_dec = operator_client.post("/api/asymmetric/decrypt", json={
        "key_id": key_id,
        "wrapped_key": enc_data["wrapped_key"],
        "nonce": enc_data["nonce"],
        "ciphertext": enc_data["ciphertext"]
    })
    assert res_dec.status_code == 200
    assert res_dec.get_json()["plaintext"] == message

    # 4. Sign message
    res_sign = operator_client.post("/api/sign", json={
        "key_id": key_id,
        "text": message
    })
    assert res_sign.status_code == 200
    sig_data = res_sign.get_json()
    assert "signature" in sig_data

    # 5. Verify valid signature
    res_ver = operator_client.post("/api/verify", json={
        "key_id": key_id,
        "text": message,
        "signature": sig_data["signature"]
    })
    assert res_ver.status_code == 200
    assert res_ver.get_json()["valid"] is True

    # 6. Verify tampered message signature rejection
    res_tampered_ver = operator_client.post("/api/verify", json={
        "key_id": key_id,
        "text": message + " [Tampered]",
        "signature": sig_data["signature"]
    })
    assert res_tampered_ver.status_code == 200
    assert res_tampered_ver.get_json()["valid"] is False


def test_hashing_and_integrity(client):
    # 1. Known SHA-256 vector test
    # SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    res_hash = client.post("/api/hash", json={
        "text": "abc",
        "algorithm": "SHA-256"
    })
    assert res_hash.status_code == 200
    expected_abc_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert res_hash.get_json()["hash"] == expected_abc_hash

    # 2. Verify integrity match
    res_verify = client.post("/api/hash/verify", json={
        "text": "abc",
        "expected_hash": expected_abc_hash,
        "algorithm": "SHA-256"
    })
    assert res_verify.status_code == 200
    assert res_verify.get_json()["valid"] is True

    # 3. Verify integrity mismatch on alteration
    res_verify_bad = client.post("/api/hash/verify", json={
        "text": "abcd",
        "expected_hash": expected_abc_hash,
        "algorithm": "SHA-256"
    })
    assert res_verify_bad.status_code == 200
    assert res_verify_bad.get_json()["valid"] is False

    # 4. Streamed file hashing test
    file_bytes = b"Sample dataset content for cryptographic file hashing verification."
    data = {
        "file": (io.BytesIO(file_bytes), "sample.txt"),
        "algorithm": "SHA-256"
    }
    res_file = client.post("/api/hash/file", data=data, content_type="multipart/form-data")
    assert res_file.status_code == 200
    file_data = res_file.get_json()
    assert file_data["filename"] == "sample.txt"
    assert file_data["size_bytes"] == len(file_bytes)
    assert len(file_data["hash"]) == 64
