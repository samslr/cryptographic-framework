import io
import pytest

def test_file_encryption_and_decryption_roundtrip(operator_client):
    # 1. Create AES Key
    res_key = operator_client.post("/api/keys/aes", json={"name": "File Enc Key"})
    key_id = res_key.get_json()["key_id"]

    # 2. Encrypt sample file
    original_content = b"This is a confidential capstone project dataset file with high security requirements."
    data = {
        "file": (io.BytesIO(original_content), "report.pdf"),
        "key_id": str(key_id)
    }
    res_enc = operator_client.post("/api/symmetric/encrypt-file", data=data, content_type="multipart/form-data")
    assert res_enc.status_code == 200
    assert "report.pdf.enc" in res_enc.headers.get("Content-Disposition", "")
    encrypted_bytes = res_enc.data
    assert len(encrypted_bytes) > len(original_content)

    # 3. Decrypt the file
    dec_data = {
        "file": (io.BytesIO(encrypted_bytes), "report.pdf.enc"),
        "key_id": str(key_id)
    }
    res_dec = operator_client.post("/api/symmetric/decrypt-file", data=dec_data, content_type="multipart/form-data")
    assert res_dec.status_code == 200
    assert res_dec.data == original_content

    # 4. Tamper with encrypted bytes and ensure rejection
    tampered_bytes = bytearray(encrypted_bytes)
    tampered_bytes[20] ^= 0xAA  # Corrupt a ciphertext byte

    bad_data = {
        "file": (io.BytesIO(tampered_bytes), "report.pdf.enc"),
        "key_id": str(key_id)
    }
    res_bad = operator_client.post("/api/symmetric/decrypt-file", data=bad_data, content_type="multipart/form-data")
    assert res_bad.status_code == 400
    assert "File decryption failed" in res_bad.get_json()["error"]
