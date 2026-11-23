"""
SSRF guard for playbook outbound HTTP steps.

Playbooks let analysts configure ``http`` and ``notify`` steps that make
outbound HTTP requests to arbitrary URLs. Without validation, a playbook
author can target cloud instance metadata services (e.g. AWS
``169.254.169.254``, GCP ``metadata.google.internal``), loopback / private
RFC1918 addresses, or non-HTTP schemes like ``file://`` — a classic
Server-Side Request Forgery (SSRF) class of bug.

This module provides :func:`validate_outbound_url`, called by playbook step
handlers before they hand a URL to ``httpx``. It rejects:

* Schemes other than ``http`` / ``https`` (overridable via
  ``AISOC_SSRF_ALLOWED_SCHEMES``).
* URLs with userinfo (``http://user:pw@host/...``) — these are a common
  credential-smuggling and host-spoofing vector.
* Hostnames or IP literals that resolve to loopback, link-local, private,
  reserved, unspecified, or multicast ranges.
* A blocklist of well-known cloud metadata endpoints (AWS, GCP, Azure,
  Alibaba, Oracle) even if their hostnames happen to resolve to a public IP.
* Hostnames where *any* of the returned addresses is unsafe (defence in
  depth against DNS records that mix one public and one private answer).

Operators can:

* Set ``AISOC_SSRF_ALLOW_PRIVATE=1`` to relax the **private-range** check
  for on-prem deployments where playbooks must reach internal services.
  It does not relax loopback, and this header used to say it did —
  directly contradicting :func:`_is_disallowed_address`'s own docstring
  two hundred lines below, which has always said loopback is rejected
  either way. The code is the correct half: a playbook that can reach
  ``127.0.0.1`` can reach every unauthenticated service on the host
  running the engine, which is a larger hole than the one the flag
  exists to open. Link-local, multicast, reserved, unspecified and
  cloud-metadata literals are likewise always rejected.
* Set ``AISOC_SSRF_EXTRA_BLOCKED_HOSTS=foo.internal,bar.svc`` to extend
  the metadata host blocklist.
* Set ``AISOC_SSRF_ALLOW_HOSTS=127.0.0.1,splunk.tunnel.local`` to admit
  exact hostnames that would otherwise be refused by IP classification —
  the escape for a vendor appliance reachable only through a local
  tunnel (an SSH port-forward lands the "remote" SIEM on loopback, which
  ``AISOC_SSRF_ALLOW_PRIVATE`` deliberately never admits). Exact,
  case-insensitive hostname matches only, no wildcards — and the
  **blocklist always wins**: listing a metadata literal here changes
  nothing, because the blocklist is consulted first.

Failures raise :class:`SSRFError`, which propagates up to the engine and
marks the step as failed via the normal exception path.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit


class SSRFError(ValueError):
    """Raised when an outbound URL is blocked by the SSRF guard."""


# ---------------------------------------------------------------------------
# Static blocklists
# ---------------------------------------------------------------------------

# Hostnames that must never be reached regardless of DNS resolution, e.g.
# operators sometimes wire ``metadata.google.internal`` to a public proxy.
# Comparison is case-insensitive against the URL's hostname (no port).
_DEFAULT_BLOCKED_HOSTS: frozenset[str] = frozenset(
    {
        # AWS / Alibaba IMDS literal
        "169.254.169.254",
        # GCP IMDS
        "metadata.google.internal",
        "metadata",
        # Azure IMDS — its IP literal is the same as AWS; hostname forms vary.
        "metadata.azure.com",
        # Alibaba Cloud
        "100.100.100.200",
        # Oracle Cloud Infrastructure
        "169.254.169.254.nip.io",
    }
)

_DEFAULT_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _env_set(name: str) -> frozenset[str]:
    """Read a comma-separated env var into a lowercase frozenset."""
    raw = os.getenv(name, "") or ""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _allowed_schemes() -> frozenset[str]:
    extra = _env_set("AISOC_SSRF_ALLOWED_SCHEMES")
    return extra or _DEFAULT_ALLOWED_SCHEMES


def _blocked_hosts() -> frozenset[str]:
    return _DEFAULT_BLOCKED_HOSTS | _env_set("AISOC_SSRF_EXTRA_BLOCKED_HOSTS")


def _allowed_hosts() -> frozenset[str]:
    """Operator-named hosts admitted without IP classification.

    Consulted *after* the blocklist, so a metadata literal placed here is
    still refused. Exact hostname matches only: an allowlist that took
    suffixes or wildcards would quietly admit ``evil-metadata.google.internal``
    shapes, and an operator who means one tunneled appliance can name it.
    """
    return _env_set("AISOC_SSRF_ALLOW_HOSTS")


def _allow_private_by_default() -> bool:
    return os.getenv("AISOC_SSRF_ALLOW_PRIVATE", "").strip().lower() in {"1", "true", "yes"}


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------


def _is_disallowed_address(ip: ipaddress._BaseAddress, *, allow_private: bool) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` for an IP address.

    When ``allow_private`` is True we still reject loopback, link-local,
    unspecified, multicast, and reserved addresses — only the
    private/RFC1918 + ULA bands are loosened.
    """
    if ip.is_loopback:
        return True, "loopback address"
    if ip.is_link_local:
        return True, "link-local address (cloud metadata range)"
    if ip.is_unspecified:
        return True, "unspecified address"
    if ip.is_multicast:
        return True, "multicast address"
    if ip.is_reserved:
        return True, "reserved address"
    # Block IPv4-mapped/IPv4-compatible IPv6 against private v4 ranges.
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            return _is_disallowed_address(mapped, allow_private=allow_private)
    if not allow_private and ip.is_private:
        return True, "private/RFC1918 address"
    return False, ""


def _coerce_ip(value: str) -> ipaddress._BaseAddress | None:
    """Try to parse ``value`` as an IP address (v4 or v6), return None if not."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _resolve_host_addresses(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve ``host`` via ``getaddrinfo`` and return all unique IP objects.

    Raises :class:`SSRFError` if the host cannot be resolved.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SSRFError(f"could not resolve hostname {host!r}: {exc}") from exc

    addrs: list[ipaddress._BaseAddress] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        addr_str = sockaddr[0] if sockaddr else ""
        # IPv6 sockaddrs can include zone IDs ("fe80::1%eth0"); strip them.
        addr_str = addr_str.split("%", 1)[0]
        if not addr_str or addr_str in seen:
            continue
        seen.add(addr_str)
        ip = _coerce_ip(addr_str)
        if ip is not None:
            addrs.append(ip)
    if not addrs:
        raise SSRFError(f"hostname {host!r} resolved to no usable addresses")
    return addrs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_outbound_url(url: str, *, allow_private: bool | None = None) -> str:
    """Validate ``url`` for outbound HTTP calls from playbook steps.

    Parameters
    ----------
    url:
        The candidate URL string.
    allow_private:
        Override the env-driven default. ``True`` permits private/RFC1918
        addresses (still blocks loopback, link-local, metadata literals,
        and explicit blocklist entries). ``None`` falls back to
        ``AISOC_SSRF_ALLOW_PRIVATE``.

    Returns
    -------
    str
        The original URL on success.

    Raises
    ------
    SSRFError
        If the URL is blocked for any reason.
    """
    if not isinstance(url, str) or not url.strip():
        raise SSRFError("URL is empty")

    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise SSRFError(f"could not parse URL: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in _allowed_schemes():
        raise SSRFError(f"scheme {scheme!r} is not allowed (must be one of {sorted(_allowed_schemes())})")

    # Reject userinfo to avoid credential smuggling and host-confusion attacks.
    if parts.username or parts.password:
        raise SSRFError("URL must not include userinfo (user:password@host)")

    host = (parts.hostname or "").strip().lower()
    if not host:
        raise SSRFError("URL has no hostname")

    # Explicit blocklist takes precedence over IP / DNS checks — and over the
    # operator allowlist below, so a metadata literal cannot be re-admitted.
    blocked = _blocked_hosts()
    if host in blocked:
        raise SSRFError(f"hostname {host!r} is on the SSRF blocklist (cloud metadata or operator-blocked)")

    # An operator-named exact host (AISOC_SSRF_ALLOW_HOSTS) skips IP
    # classification: the escape for a vendor appliance that is only
    # reachable through a local tunnel, where the destination genuinely is
    # loopback and AISOC_SSRF_ALLOW_PRIVATE deliberately does not help.
    if host in _allowed_hosts():
        return url

    if allow_private is None:
        allow_private = _allow_private_by_default()

    # If host is an IP literal, validate it directly.
    literal_ip = _coerce_ip(host)
    if literal_ip is not None:
        blocked_flag, reason = _is_disallowed_address(literal_ip, allow_private=allow_private)
        if blocked_flag:
            raise SSRFError(f"host {host!r} is blocked: {reason}")
        return url

    # Otherwise, resolve the hostname and validate every returned address.
    addresses = _resolve_host_addresses(host)
    for ip in addresses:
        blocked_flag, reason = _is_disallowed_address(ip, allow_private=allow_private)
        if blocked_flag:
            raise SSRFError(f"hostname {host!r} resolves to a blocked address {ip} ({reason})")

    return url


# Addresses that are cloud metadata even when they are not link-local.
# 169.254.169.254 is both; the others are the ECS and Alibaba endpoints.
_METADATA_ADDRESSES: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)


# The deployment's own LLM endpoints. These come from the process
# environment, which only an operator controls, so they are configuration
# rather than a destination a tenant chose. The bundled Ollama smoke run and
# local model servers live on loopback and are reached through these.
_OPERATOR_LLM_BASE_ENV: tuple[str, ...] = ("OPENAI_BASE_URL", "LLM_BASE_URL", "LLM_GATEWAY_URL")

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str, int] | None:
    """``(scheme, host, port)`` for ``url``, or ``None`` when it has none."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").strip().lower()
    if not scheme or not host:
        return None
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        return None
    return scheme, host, port


def _operator_llm_origins() -> frozenset[tuple[str, str, int]]:
    """Origins of the LLM endpoints the operator configured in the environment."""
    origins: set[tuple[str, str, int]] = set()
    for name in _OPERATOR_LLM_BASE_ENV:
        raw = (os.getenv(name, "") or "").strip()
        if not raw:
            continue
        origin = _origin(raw)
        if origin is not None:
            origins.add(origin)
    return frozenset(origins)


def guard_runtime_llm_url(url: str) -> str:
    """Validate a URL before a runtime LLM call.

    Private LAN hosts stay reachable (``allow_private=True``), which is what
    local model servers need. Loopback, link-local and metadata destinations
    are refused. An operator allow-list can still name an exact loopback host
    for a tunnel; it cannot re-open link-local or metadata, including a DNS
    name that resolves to one of those addresses.

    The deployment's own endpoint (``OPENAI_BASE_URL``, ``LLM_BASE_URL`` or
    ``LLM_GATEWAY_URL``) is exempt from the loopback refusal when the URL has
    the same scheme, host and port. Those values are operator configuration,
    and a local Ollama or recorded gateway on ``127.0.0.1`` is the supported
    way to run without a hosted provider. The guard exists for destinations
    a tenant saved; any other loopback origin is still refused, and
    link-local and metadata stay blocked for every destination.
    """
    origin = _origin(url)
    if origin is None or origin not in _operator_llm_origins():
        validate_outbound_url(url, allow_private=True)
    _reject_link_local_and_metadata(url)
    return url


def _reject_link_local_and_metadata(url: str) -> None:
    """Refuse link-local and metadata even when the allow-list skipped classification.

    ``validate_outbound_url`` already rejects those addresses for a host it
    classifies. ``AISOC_SSRF_ALLOW_HOSTS`` returns before that classification,
    which is the escape hatch for a tunneled loopback appliance. A name on
    that list that resolves to a metadata address must still be refused.
    """
    host = (urlsplit(url.strip()).hostname or "").strip().lower()
    if not host:
        raise SSRFError("URL has no hostname")

    literal = _coerce_ip(host)
    # A name the shared guard already resolved is not looked up again. The
    # allow-list and IP literals are the paths that skipped that lookup.
    if literal is None and host not in _allowed_hosts():
        return

    raw = [literal] if isinstance(literal, ipaddress.IPv4Address | ipaddress.IPv6Address) else _resolve_host_addresses(host)
    for ip in raw:
        if not isinstance(ip, ipaddress.IPv4Address | ipaddress.IPv6Address):
            continue
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None else ip
        if mapped.is_link_local or str(mapped) in _METADATA_ADDRESSES:
            raise SSRFError(f"host {host!r} is blocked: link-local or metadata address {mapped}")


__all__ = ["SSRFError", "guard_runtime_llm_url", "validate_outbound_url"]
