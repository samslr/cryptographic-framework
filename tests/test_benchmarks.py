import pytest

def test_crypto_benchmarking_endpoints(operator_client):
    # 1. Fetch latest or cached benchmark
    res = operator_client.get("/api/benchmarks/latest")
    assert res.status_code == 200
    data = res.get_json()
    assert "symmetric_aes_gcm" in data
    assert "asymmetric_rsa" in data
    assert "signatures_rsa_pss" in data
    assert "hashing" in data

    # 2. Verify symmetric benchmark has measurements
    aes_metrics = data["symmetric_aes_gcm"]
    assert len(aes_metrics) == 4
    for m in aes_metrics:
        assert m["encrypt_ms"] >= 0
        assert m["encrypt_mb_s"] >= 0

    # 3. Verify asymmetric RSA metrics
    rsa_metrics = data["asymmetric_rsa"]
    assert "keygen_ms" in rsa_metrics
    assert "hybrid_encrypt_ms" in rsa_metrics
    assert "hybrid_decrypt_ms" in rsa_metrics

    # 4. Verify signatures metrics
    sig_metrics = data["signatures_rsa_pss"]
    assert "sign_ms" in sig_metrics
    assert "verify_ms" in sig_metrics
    assert sig_metrics["sign_ops_per_sec"] > 0
