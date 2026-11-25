import pytest

def test_avalanche_analysis_endpoint(client):
    # Test strict avalanche with 1-bit perturbation
    res = client.post("/api/hash/avalanche", json={
        "input_a": "CryptographicFramework2026",
        "algorithm": "SHA-256"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["algorithm"] == "SHA-256"
    assert data["total_bits"] == 256
    assert "changed_bits" in data
    assert "change_percentage" in data
    # The avalanche effect should flip roughly 50% of the bits (35% to 65% in practice for single small sample)
    assert 30.0 <= data["change_percentage"] <= 70.0
    assert len(data["bit_map"]) == 128
    assert "hash_a" in data
    assert "hash_b" in data
    assert data["hash_a"] != data["hash_b"]
