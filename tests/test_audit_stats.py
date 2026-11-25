import pytest

def test_audit_logging_and_filtering(admin_client):
    # Perform an action to create an audit log
    admin_client.post("/api/keys/aes", json={"name": "Audit Test Key"})

    # Query audit logs
    res = admin_client.get("/api/audit?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "logs" in data
    assert len(data["logs"]) > 0

    first_log = data["logs"][0]
    assert "operation_id" in first_log
    assert "action" in first_log
    assert "status" in first_log
    assert "duration_ms" in first_log

    # Test filtering by status
    res_filtered = admin_client.get("/api/audit?status=SUCCESS")
    assert res_filtered.status_code == 200
    for item in res_filtered.get_json()["logs"]:
        assert item["status"] == "SUCCESS"

    # Test CSV export
    res_csv = admin_client.get("/api/audit/export")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.content_type
    csv_text = res_csv.get_data(as_text=True)
    assert "Operation ID" in csv_text
    assert "Action" in csv_text


def test_stats_telemetry(admin_client):
    res = admin_client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "active_keys" in data
    assert "operations" in data
    assert "success_rate" in data
    assert data["operations"] > 0
