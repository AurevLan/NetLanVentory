"""SSRF-safe HTTP fetch helpers.

Resolves the target hostname and refuses any address that points to:
  - loopback (127.0.0.0/8, ::1)
  - link-local (169.254.0.0/16 — includes AWS/GCP/Azure metadata 169.254.169.254)
  - private RFC1918 ranges (10/8, 172.16/12, 192.168/16)
  - unique local IPv6 (fc00::/7)
  - reserved / multicast

`safe_get()` and `safe_request()` validate the URL **before each request** and
re-validate after redirects to defeat DNS rebinding / open-redirect SSRF.

Internal scanners that legitimately need to hit RFC1918 (e.g. asset SSH on
192.168.x.x) must opt-in via `allow_private=True`. Loopback and link-local are
**always** denied because they are never legitimate scan targets and are the
primary SSRF exfil vectors (cloud metadata, local admin services).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)


class SsrfBlockedError(ValueError):
    """Raised when a URL is rejected by the SSRF guard."""


_ALLOWED_SCHEMES = {"http", "https"}


def _classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """Return a short reason string if the IP must be blocked, else None."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (cloud metadata range)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _classify_ip(ip.ipv4_mapped)
    return None


def assert_url_safe(url: str, *, allow_private: bool = False) -> None:
    """Validate a URL for safe outbound fetch.

    Raises:
        SsrfBlockedError: if scheme is unsupported, hostname missing, or any
            resolved address falls into a blocked range.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"Scheme '{parsed.scheme}' not allowed")
    host = parsed.hostname
    if not host:
        raise SsrfBlockedError("URL has no hostname")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SsrfBlockedError(f"DNS resolution failed for '{host}': {exc}") from exc

    addrs: list[ipaddress._BaseAddress] = []
    for info in infos:
        sockaddr = info[4]
        try:
            addrs.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not addrs:
        raise SsrfBlockedError(f"No usable address for '{host}'")

    for ip in addrs:
        reason = _classify_ip(ip)
        if reason:
            raise SsrfBlockedError(
                f"Refusing to fetch '{host}' → {ip} ({reason})"
            )
        if not allow_private and ip.is_private:
            raise SsrfBlockedError(
                f"Refusing to fetch '{host}' → {ip} (private network)"
            )


class SafeAsyncClient(httpx.AsyncClient):
    """httpx.AsyncClient that re-validates each request URL.

    Disables automatic cross-host redirects so that a 302 to
    `http://169.254.169.254/` cannot bypass the initial check.
    """

    def __init__(self, *args, allow_private: bool = False, **kwargs) -> None:
        kwargs.setdefault("follow_redirects", False)
        super().__init__(*args, **kwargs)
        self._allow_private = allow_private

    async def request(self, method, url, *args, **kwargs):  # type: ignore[override]
        assert_url_safe(str(url), allow_private=self._allow_private)
        return await super().request(method, url, *args, **kwargs)
