"""
Flask API tests. The real scanner is always mocked - these tests never make
network calls to third-party sites.
"""
import time
from unittest.mock import patch

import pytest


def test_index_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"VulnScan" in r.data or b"Scan" in r.data


def test_healthz_reports_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok"
    assert body["report_storage_writable"] is True


def test_start_scan_requires_url(client):
    r = client.post("/api/scan", json={})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_start_scan_rejects_empty_body(client):
    r = client.post("/api/scan", data="not json", content_type="application/json")
    assert r.status_code == 400


def test_start_scan_rejects_private_ip_target(client):
    with patch("security.resolve_host", return_value=["127.0.0.1"]):
        r = client.post("/api/scan", json={"url": "internal-service"})
    assert r.status_code == 400
    assert "private" in r.get_json()["error"].lower() or "loopback" in r.get_json()["error"].lower()


def test_start_scan_rejects_non_http_scheme(client):
    r = client.post("/api/scan", json={"url": "ftp://example.com"})
    assert r.status_code == 400


def test_start_scan_succeeds_for_mocked_target(client):
    with patch("app.VulnScanner") as MockScanner, \
         patch("security.resolve_host", return_value=["93.184.216.34"]):
        MockScanner.return_value.run.return_value = []
        r = client.post("/api/scan", json={"url": "example.com", "full_scan": False})
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "started"
    assert len(body["scan_id"]) == 16


def test_scan_status_unknown_id_returns_404(client):
    r = client.get("/api/status/" + "a" * 16)
    assert r.status_code == 404


def test_scan_status_malformed_id_returns_404(client):
    r = client.get("/api/status/../../etc/passwd")
    assert r.status_code == 404


def test_full_scan_lifecycle_reaches_completed_status(client):
    findings = [{"type": "XSS", "url": "http://x/a", "severity": "HIGH",
                "details": "d", "evidence": "e"}]
    with patch("app.VulnScanner") as MockScanner, \
         patch("security.resolve_host", return_value=["93.184.216.34"]):
        MockScanner.return_value.run.return_value = findings
        r = client.post("/api/scan", json={"url": "example.com", "full_scan": False})
        scan_id = r.get_json()["scan_id"]

        for _ in range(20):
            status = client.get(f"/api/status/{scan_id}").get_json()
            if status["done"]:
                break
            time.sleep(0.1)

    assert status["status"] == "completed"
    assert status["findings_count"] == 1
    assert status["counts"]["high"] == 1


def test_report_download_404_before_scan_completes(client):
    r = client.get("/report/" + "a" * 16 + "/html")
    assert r.status_code == 404


def test_report_download_rejects_bad_format(client):
    with patch("app.VulnScanner") as MockScanner, \
         patch("security.resolve_host", return_value=["93.184.216.34"]):
        MockScanner.return_value.run.return_value = []
        r = client.post("/api/scan", json={"url": "example.com", "full_scan": False})
        scan_id = r.get_json()["scan_id"]
        time.sleep(0.3)
    r = client.get(f"/report/{scan_id}/exe")
    assert r.status_code == 404


def test_threads_and_timeout_are_clamped_to_safe_ranges(client):
    with patch("app.VulnScanner") as MockScanner, \
         patch("security.resolve_host", return_value=["93.184.216.34"]):
        MockScanner.return_value.run.return_value = []
        client.post("/api/scan", json={"url": "example.com", "threads": 9999, "timeout": 9999})
        _, kwargs = MockScanner.call_args
        assert kwargs["threads"] <= 20
        assert kwargs["timeout"] <= 30


def test_capacity_limit_returns_429(app, client):
    app.config["MAX_CONCURRENT_SCANS"] = 0
    with patch("security.resolve_host", return_value=["93.184.216.34"]):
        r = client.post("/api/scan", json={"url": "example.com"})
    assert r.status_code == 429
