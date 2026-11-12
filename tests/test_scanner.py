"""
Unit tests for scanner_core.VulnScanner.

No requests ever leave the machine: every HTTP call goes through `responses`,
which intercepts at the `requests` layer, or through a mocked session.
"""
import json
import re
from urllib.parse import urlparse

import pytest
import responses

from scanner_core import (SENSITIVE_FILES, VulnScanner, generate_html_report,
                          generate_json_report)

TARGET = "http://testsite.local"


def make_scanner(**kwargs):
    kwargs.setdefault("threads", 2)
    kwargs.setdefault("timeout", 2)
    return VulnScanner(target=TARGET, **kwargs)


# ── Security headers ───────────────────────────────────────
@responses.activate
def test_check_security_headers_flags_missing_headers():
    responses.add(responses.GET, TARGET, body="<html></html>", status=200, headers={})
    scanner = make_scanner()
    scanner.check_security_headers()
    types = [f["type"] for f in scanner.findings]
    assert "Missing Security Header" in types
    # HSTS specifically should be flagged when absent
    assert any("Strict-Transport-Security" in f["details"] for f in scanner.findings)


@responses.activate
def test_check_security_headers_no_finding_when_all_present():
    good_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    responses.add(responses.GET, TARGET, body="ok", status=200, headers=good_headers)
    scanner = make_scanner()
    scanner.check_security_headers()
    assert not any(f["type"] == "Missing Security Header" for f in scanner.findings)


@responses.activate
def test_check_security_headers_flags_server_banner_disclosure():
    responses.add(responses.GET, TARGET, body="ok", status=200,
                  headers={"Server": "Apache/2.4.1 (CentOS)"})
    scanner = make_scanner()
    scanner.check_security_headers()
    assert any(f["type"] == "Information Disclosure" for f in scanner.findings)


# ── SQL injection (error-based) ─────────────────────────────
@responses.activate
def test_check_sqli_url_detects_known_error_pattern():
    url = TARGET + "/item?id=1"

    def responder(request):
        if "'" in request.url or "%27" in request.url:
            return (200, {}, "You have an error in your SQL syntax near ...")
        return (200, {}, "normal page")

    responses.add_callback(responses.GET, re.compile(re.escape(TARGET) + r"/item.*"), callback=responder)
    scanner = make_scanner()
    scanner.check_sqli_url(url)
    assert any(f["type"] == "SQL Injection" for f in scanner.findings)
    assert scanner.findings[0]["severity"] == "CRITICAL"


@responses.activate
def test_check_sqli_url_no_finding_on_clean_response():
    url = TARGET + "/item?id=1"
    responses.add(responses.GET, re.compile(re.escape(TARGET) + r"/item.*"),
                  body="all good, nothing here", status=200)
    scanner = make_scanner()
    scanner.check_sqli_url(url)
    assert scanner.findings == []


def test_check_sqli_url_skips_urls_without_query_params():
    scanner = make_scanner()
    # No query string -> function should return immediately, no HTTP calls made
    scanner.check_sqli_url(TARGET + "/about")
    assert scanner.findings == []


# ── Reflected XSS ───────────────────────────────────────────
@responses.activate
def test_check_xss_url_detects_reflected_payload():
    url = TARGET + "/search?q=test"

    def responder(request):
        from urllib.parse import parse_qs, unquote
        qs = parse_qs(urlparse(request.url).query)
        value = unquote(qs.get("q", [""])[0])
        return (200, {}, f"Results for: {value}")

    responses.add_callback(responses.GET, re.compile(re.escape(TARGET) + r"/search.*"), callback=responder)
    scanner = make_scanner()
    scanner.check_xss_url(url)
    assert any(f["type"] == "Reflected XSS" for f in scanner.findings)


@responses.activate
def test_check_xss_url_no_finding_when_payload_is_escaped():
    url = TARGET + "/search?q=test"
    responses.add(responses.GET, re.compile(re.escape(TARGET) + r"/search.*"),
                  body="Results for: &lt;script&gt;", status=200)
    scanner = make_scanner()
    scanner.check_xss_url(url)
    assert scanner.findings == []


# ── Sensitive file exposure ──────────────────────────────────
@responses.activate
def test_check_sensitive_files_flags_exposed_env():
    for path in SENSITIVE_FILES:
        if path == "/.env":
            responses.add(responses.GET, TARGET + path, body="SECRET_KEY=abc123", status=200)
        else:
            responses.add(responses.GET, TARGET + path, body="", status=404)
    scanner = make_scanner()
    scanner.check_sensitive_files()
    exposed = [f for f in scanner.findings if f["type"] == "Sensitive File Exposed"]
    assert len(exposed) == 1
    assert exposed[0]["severity"] == "CRITICAL"
    assert "/.env" in exposed[0]["url"]


@responses.activate
def test_check_sensitive_files_ignores_tiny_or_404_responses():
    for path in SENSITIVE_FILES:
        responses.add(responses.GET, TARGET + path, body="", status=404)
    scanner = make_scanner()
    scanner.check_sensitive_files()
    assert scanner.findings == []


# ── CSRF ──────────────────────────────────────────────────────
def test_check_csrf_flags_post_form_without_token():
    scanner = make_scanner()
    scanner.forms_found = [{
        "action": TARGET + "/update", "method": "post",
        "inputs": [{"name": "email", "type": "text", "value": "test"}],
        "page": TARGET + "/account",
    }]
    scanner.check_csrf()
    assert any(f["type"] == "Missing CSRF Token" for f in scanner.findings)


def test_check_csrf_ignores_form_with_token():
    scanner = make_scanner()
    scanner.forms_found = [{
        "action": TARGET + "/update", "method": "post",
        "inputs": [{"name": "csrf_token", "type": "hidden", "value": "abc"}],
        "page": TARGET + "/account",
    }]
    scanner.check_csrf()
    assert scanner.findings == []


def test_check_csrf_ignores_get_forms():
    scanner = make_scanner()
    scanner.forms_found = [{
        "action": TARGET + "/search", "method": "get",
        "inputs": [{"name": "q", "type": "text", "value": "test"}],
        "page": TARGET + "/",
    }]
    scanner.check_csrf()
    assert scanner.findings == []


# ── Open Redirect ───────────────────────────────────────────
@responses.activate
def test_check_open_redirect_detects_redirect_to_payload_domain():
    url = TARGET + "/go?redirect=/home"
    responses.add(responses.GET, re.compile(re.escape(TARGET) + r"/go.*"),
                  status=302, headers={"Location": "https://evil.com"})
    scanner = make_scanner()
    scanner.check_open_redirect(url)
    assert any(f["type"] == "Open Redirect" for f in scanner.findings)


def test_check_open_redirect_skips_non_redirect_params():
    scanner = make_scanner()
    scanner.check_open_redirect(TARGET + "/page?id=5")
    assert scanner.findings == []


# ── LFI ──────────────────────────────────────────────────────
@responses.activate
def test_check_lfi_detects_leaked_passwd_file():
    url = TARGET + "/view?file=report.txt"
    responses.add(responses.GET, re.compile(re.escape(TARGET) + r"/view.*"),
                  body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::...", status=200)
    scanner = make_scanner()
    scanner.check_lfi(url)
    assert any(f["type"] == "Local File Inclusion (LFI)" for f in scanner.findings)


@responses.activate
def test_check_lfi_no_finding_on_normal_file_content():
    url = TARGET + "/view?file=report.txt"
    responses.add(responses.GET, re.compile(re.escape(TARGET) + r"/view.*"),
                  body="Quarterly report contents here.", status=200)
    scanner = make_scanner()
    scanner.check_lfi(url)
    assert scanner.findings == []


# ── Finding deduplication ───────────────────────────────────
def test_add_finding_deduplicates_same_type_and_url():
    scanner = make_scanner()
    scanner.add_finding("XSS", TARGET + "/a", "HIGH", "first")
    scanner.add_finding("XSS", TARGET + "/a", "HIGH", "duplicate")
    assert len(scanner.findings) == 1
    assert scanner.findings[0]["details"] == "first"


def test_add_finding_calls_finding_callback():
    received = []
    scanner = make_scanner(finding_callback=received.append)
    scanner.add_finding("XSS", TARGET + "/a", "HIGH", "details")
    assert len(received) == 1
    assert received[0]["type"] == "XSS"


# ── HTTPS check ──────────────────────────────────────────────
def test_check_https_flags_plain_http_target():
    scanner = make_scanner()
    scanner.check_https()
    assert any(f["type"] == "No HTTPS" for f in scanner.findings)
