"""Tenant routes and credentials must be resolved as one destination.

Mirrored in the other Python service, which ships in a separate image.
Provider defaults are the same ones used by the BYOK connection probe.
"""

from __future__ import annotations

from urllib.parse import urlsplit

PROVIDER_DEFAULTS: dict[str, tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
    "anthropic": ("https://api.anthropic.com/v1", "claude-3-5-haiku-20241022"),
}


def same_endpoint(left: str, right: str) -> bool:
    """Match a complete API base, ignoring only a trailing slash.

    A different path or port can be a different gateway or credential scope.
    In particular, matching just the hostname is not sufficient.
    """
    try:
        a, b = urlsplit(left), urlsplit(right)
        if any((a.username, a.password, a.fragment, b.username, b.password, b.fragment)):
            return False
        if a.scheme.lower() not in {"http", "https"} or b.scheme.lower() not in {"http", "https"}:
            return False
        a_host, b_host = a.hostname, b.hostname
        if not a_host or not b_host:
            return False
        return (a.scheme.lower(), a_host.lower(), a.port, a.path.rstrip("/"), a.query) == (
            b.scheme.lower(),
            b_host.lower(),
            b.port,
            b.path.rstrip("/"),
            b.query,
        )
    except ValueError:
        return False


def public_provider_host(hostname: str) -> str | None:
    """Return a known public provider host that air-gap mode must refuse."""
    hostname = hostname.lower().rstrip(".")
    for public_host in ("api.openai.com", "api.anthropic.com"):
        if hostname == public_host or hostname.endswith("." + public_host):
            return public_host
    return None


def tenant_route(
    *, provider: str, base_url: str | None, model: str | None, env_base: str, env_model: str
) -> tuple[str, str, bool, bool, bool]:
    """Return endpoint/model, their provenance, and whether an env key fits.

    A hosted provider with no explicit endpoint means that provider's default,
    not the bundled gateway. Its default model is likewise provider-specific.
    For other providers, preserve the existing explicit override semantics.
    """
    default_base, default_model = PROVIDER_DEFAULTS.get(provider, ("", ""))
    tenant_base = base_url or default_base
    tenant_model = model or default_model
    base = tenant_base or env_base
    resolved_model = tenant_model or env_model
    # An unset baseline is the OpenAI client's default endpoint. This is the
    # only implicit destination whose credential can be inherited safely.
    baseline = env_base or PROVIDER_DEFAULTS["openai"][0]
    return base, resolved_model, bool(tenant_base), bool(tenant_model), same_endpoint(base or baseline, baseline)
