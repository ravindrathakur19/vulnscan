"""
Security helpers for VulnScan Pro.

* validate_target_url()  - scheme / port / credentials validation + SSRF guard
* is_public_ip()         - blocks private, loopback, link-local (cloud metadata),
                           multicast, reserved and carrier-grade-NAT addresses

IMPORTANT LIMITATION: DNS is resolved at validation time and again by the HTTP
client at request time (classic DNS-rebinding TOCTOU window). The scanner
re-validates every redirect hop, which closes the most common bypass, but a
hostile DNS server could still race the two lookups. For a hardened public
deployment add an egress NetworkPolicy / security-group rule that denies the
instance metadata endpoint and the VPC CIDR.
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class TargetNotAllowed(ValueError):
    """Raised when a URL fails validation. The message is safe to show users."""


def env_flag(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def allow_private_targets():
    """Private targets are blocked unless explicitly enabled (local lab use)."""
    return env_flag("ALLOW_PRIVATE_TARGETS", False)


def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) so it cannot bypass the check
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip in _CGNAT:
        return False
    return ip.is_global and not ip.is_multicast


def resolve_host(host):
    """Return every IP the hostname resolves to (separate function = mockable)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def is_allowed_redirect_target(url, allow_private=None):
    """Cheap boolean check used while following redirects mid-scan."""
    try:
        validate_target_url(url, allow_private=allow_private)
        return True
    except TargetNotAllowed:
        return False


def validate_target_url(raw_url, allow_private=None):
    """
    Normalise and validate a user-supplied target URL.
    Returns the normalised URL, or raises TargetNotAllowed.
    """
    if allow_private is None:
        allow_private = allow_private_targets()
    if not isinstance(raw_url, str):
        raise TargetNotAllowed("URL must be a string")
    url = raw_url.strip()
    if not url:
        raise TargetNotAllowed("URL is required")
    if len(url) > MAX_URL_LENGTH:
        raise TargetNotAllowed("URL is too long")
    if any(c in url for c in ("\r", "\n", "\x00", " ")):
        raise TargetNotAllowed("URL contains illegal characters")
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        port = parsed.port  # raises ValueError for invalid ports
    except ValueError:
        raise TargetNotAllowed("URL is malformed")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise TargetNotAllowed("Only http:// and https:// URLs are allowed")
    if not parsed.hostname:
        raise TargetNotAllowed("URL has no hostname")
    if parsed.username or parsed.password:
        raise TargetNotAllowed("Credentials inside the URL are not allowed")
    if port is not None and not (1 <= port <= 65535):
        raise TargetNotAllowed("Invalid port")

    if not allow_private:
        try:
            ips = resolve_host(parsed.hostname)
        except (socket.gaierror, UnicodeError, OSError):
            raise TargetNotAllowed("Hostname could not be resolved")
        if not ips:
            raise TargetNotAllowed("Hostname could not be resolved")
        for ip in ips:
            if not is_public_ip(ip):
                raise TargetNotAllowed(
                    "Target resolves to a private, loopback or reserved address; "
                    "scanning internal networks is disabled"
                )
    return url
