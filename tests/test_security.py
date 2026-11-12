"""Tests for the SSRF / input-validation guard in security.py."""
from unittest.mock import patch

import pytest

import security


def _with_dns(ips):
    return patch.object(security, "resolve_host", return_value=ips)


def test_accepts_plain_public_hostname():
    with _with_dns(["93.184.216.34"]):
        assert security.validate_target_url("example.com") == "https://example.com"


def test_adds_https_scheme_when_missing():
    with _with_dns(["93.184.216.34"]):
        assert security.validate_target_url("example.com").startswith("https://")


def test_preserves_explicit_http_scheme():
    with _with_dns(["93.184.216.34"]):
        assert security.validate_target_url("http://example.com") == "http://example.com"


@pytest.mark.parametrize("host,ip", [
    ("localhost", "127.0.0.1"),
    ("metadata.internal", "169.254.169.254"),   # cloud metadata endpoint
    ("corp-server", "10.0.0.5"),                 # RFC1918
    ("corp-server2", "172.16.0.5"),
    ("corp-server3", "192.168.1.5"),
    ("cgnat-host", "100.64.0.1"),                 # carrier-grade NAT
])
def test_blocks_private_and_reserved_targets(host, ip):
    with _with_dns([ip]):
        with pytest.raises(security.TargetNotAllowed):
            security.validate_target_url(f"http://{host}/")


def test_allows_private_targets_when_explicitly_enabled():
    with _with_dns(["127.0.0.1"]):
        # Should not raise when the operator opts in (e.g. local lab testing)
        assert security.validate_target_url("http://localhost/", allow_private=True)


@pytest.mark.parametrize("bad_url", [
    "",
    "   ",
    "ftp://example.com",
    "javascript:alert(1)",
    "http://user:pass@example.com/",
    "http://example.com:999999/",
    "http://exa mple.com/",
])
def test_rejects_malformed_or_disallowed_urls(bad_url):
    with pytest.raises(security.TargetNotAllowed):
        security.validate_target_url(bad_url)


def test_rejects_non_string_input():
    with pytest.raises(security.TargetNotAllowed):
        security.validate_target_url(None)


def test_rejects_unresolvable_hostname():
    with patch.object(security, "resolve_host", side_effect=OSError("no dns")):
        with pytest.raises(security.TargetNotAllowed):
            security.validate_target_url("this-does-not-resolve.invalid")


def test_is_public_ip_blocks_ipv4_mapped_loopback():
    # ::ffff:127.0.0.1 must not slip through as "global"
    assert security.is_public_ip("::ffff:127.0.0.1") is False


def test_is_public_ip_accepts_real_public_address():
    assert security.is_public_ip("93.184.216.34") is True


def test_env_flag_parses_truthy_values(monkeypatch):
    for val in ("1", "true", "True", "yes", "on"):
        monkeypatch.setenv("X_FLAG", val)
        assert security.env_flag("X_FLAG") is True
    monkeypatch.setenv("X_FLAG", "0")
    assert security.env_flag("X_FLAG") is False
