"""Tests for HTML/JSON report generation and the disk-backed ScanStore."""
import json
import os

from scanner_core import generate_html_report, generate_json_report
from scan_store import ScanStore, valid_scan_id

SAMPLE_FINDINGS = [
    {"type": "SQL Injection", "url": "http://t/a?id=1", "severity": "CRITICAL",
     "details": "Parameter: id", "evidence": "' OR 1=1--"},
    {"type": "Missing Security Header", "url": "http://t/", "severity": "MEDIUM",
     "details": "HSTS not set", "evidence": ""},
]


def test_generate_json_report_contains_all_findings(tmp_path):
    path = generate_json_report(SAMPLE_FINDINGS, "http://t", str(tmp_path))
    assert os.path.exists(path)
    with open(path) as fh:
        data = json.load(fh)
    assert data["target"] == "http://t"
    assert data["total_findings"] == 2
    assert len(data["findings"]) == 2


def test_generate_json_report_empty_findings(tmp_path):
    path = generate_json_report([], "http://t", str(tmp_path))
    with open(path) as fh:
        data = json.load(fh)
    assert data["total_findings"] == 0
    assert data["findings"] == []


def test_generate_html_report_includes_findings_table(tmp_path):
    path = generate_html_report(SAMPLE_FINDINGS, "http://t", str(tmp_path))
    with open(path, encoding="utf-8") as fh:
        html = fh.read()
    assert "SQL Injection" in html
    assert "CRITICAL" in html
    assert "<table>" in html


def test_generate_html_report_shows_no_findings_message(tmp_path):
    path = generate_html_report([], "http://t", str(tmp_path))
    with open(path, encoding="utf-8") as fh:
        html = fh.read()
    assert "No vulnerabilities detected" in html
    assert "<table>" not in html


def test_generate_html_report_creates_output_dir_if_missing(tmp_path):
    out_dir = tmp_path / "nested" / "reports"
    path = generate_html_report([], "http://t", str(out_dir))
    assert os.path.exists(path)


# ── ScanStore ──────────────────────────────────────────────
def test_valid_scan_id_accepts_only_hex16():
    assert valid_scan_id("a" * 16) is True
    assert valid_scan_id("not-valid") is False
    assert valid_scan_id("../../etc/passwd") is False
    assert valid_scan_id("") is False


def test_scan_store_create_and_get_roundtrip(tmp_path):
    store = ScanStore(str(tmp_path))
    meta = store.create("a" * 16, "http://t", {"full_scan": True})
    assert meta["status"] == "running"
    fetched = store.get("a" * 16)
    assert fetched["target"] == "http://t"


def test_scan_store_complete_persists_to_disk(tmp_path):
    store = ScanStore(str(tmp_path))
    scan_id = "b" * 16
    store.create(scan_id, "http://t", {})
    store.complete(scan_id, SAMPLE_FINDINGS, {"total": 2})
    store.forget_live(scan_id)  # simulate process restart (drop in-memory state)
    meta = store.get(scan_id)
    assert meta["status"] == "completed"
    assert meta["counts"]["total"] == 2
    assert len(meta["findings"]) == 2


def test_scan_store_report_path_rejects_path_traversal(tmp_path):
    store = ScanStore(str(tmp_path))
    assert store.report_path("../../etc", "html") is None
    assert store.report_path("a" * 16, "exe") is None


def test_scan_store_report_path_none_when_file_missing(tmp_path):
    store = ScanStore(str(tmp_path))
    store.create("c" * 16, "http://t", {})
    assert store.report_path("c" * 16, "html") is None


def test_scan_store_get_returns_none_for_unknown_id(tmp_path):
    store = ScanStore(str(tmp_path))
    assert store.get("d" * 16) is None


def test_scan_store_purge_removes_old_scan_dirs(tmp_path):
    import time
    store = ScanStore(str(tmp_path))
    scan_id = "e" * 16
    store.create(scan_id, "http://t", {})
    store.forget_live(scan_id)  # purge only applies to finished scans dropped from memory
    old_time = time.time() - 40 * 86400
    os.utime(store.scan_dir(scan_id), (old_time, old_time))
    removed = store.purge_older_than(30)
    assert removed == 1
    assert store.get(scan_id) is None
