"""Network utilities for BAS Engine."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def resolve_host(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    """Normalize a URL for consistent comparison."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path.rstrip("/") or "/"

    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        return f"{scheme}://{host}:{port}{path}"
    return f"{scheme}://{host}{path}"


def extract_host(target: str) -> str:
    """Extract hostname from a target string (URL or host:port)."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0]
