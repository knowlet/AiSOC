"""Refuse connector egress to destinations inside the deployment.

GHSA-cq4g-g6wp-4m2w. The central SSRF guard (``validate_outbound_url``) was
applied across ``services/api`` and ``services/agents`` and nowhere in this
service — yet this is the service whose whole job is opening outbound HTTP to
tenant-controlled base URLs. Reproduced live: a **viewer-role** console JWT
posted ``POST /connectors/splunk/test`` with ``base_url`` pointing at a
loopback listener, and the service fetched ``/services/server/info`` from it
and reflected the parsed response — an authenticated tenant user could reach
cloud metadata (169.254.169.254), internal services, and loopback from this
service's network position, with the test response as an oracle.

What is validated
-----------------
Every **value** in the merged constructor kwargs that is an ``http(s)://``
URL, under whatever key the connector's schema chose (``base_url``,
``api_url``, ``instance_url``, ``gitlab_url``, ``spool_url``, …). Matching on
the value's shape rather than a list of key names is deliberate: the census
found 18 connectors declaring ``base_url`` and a dozen other spellings, and a
key-name list is the kind of one-directional check that silently misses the
next connector. Lists are walked for their string items.

Known residual, stated rather than hidden: a connector that assembles its URL
from a bare host/subdomain field (``host``, ``domain``, ``api_hostname``,
``subdomain``) is not covered by the value-shape rule — synthesizing URLs from
those would refuse legitimate values like a bare vendor subdomain. Those
fields are tenant-vendor hostnames rather than full destinations, and the
vendors' own TLS endpoints bound what they can reach.

Two refusal classes, deliberately (same split as the outbound-webhook
delivery path): a *policy* refusal — metadata endpoint, loopback, private
range without ``AISOC_SSRF_ALLOW_PRIVATE``, bad scheme — raises
:class:`EgressRefused`, while a hostname that merely fails to resolve is let
through: the connector cannot connect to it either, and its own "DNS lookup
failed" diagnostic is the message the setup wizard should show.

``AISOC_SSRF_ALLOW_PRIVATE=1`` relaxes the private-range check for on-prem
deployments whose SIEM genuinely lives on RFC 1918 space; the cloud-metadata
blocklist holds regardless, exactly as it does for playbook HTTP steps.
"""

from __future__ import annotations

import socket
from typing import Any

from app.security.ssrf_guard import SSRFError, validate_outbound_url

__all__ = ["EgressRefused", "refuse_internal_destinations"]


class EgressRefused(ValueError):
    """A connector config named a destination inside the deployment."""

    def __init__(self, field_name: str, reason: str) -> None:
        self.field_name = field_name
        self.reason = reason
        super().__init__(f"{field_name}: destination refused: {reason}")


def refuse_internal_destinations(kwargs: dict[str, Any]) -> None:
    """Validate every URL-shaped value in a connector's constructor kwargs.

    Raises :class:`EgressRefused` naming the offending field on a policy
    refusal. A resolution failure (the guard chains ``socket.gaierror``) is
    not a refusal — see the module docstring.
    """
    for field_name, value in kwargs.items():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, str) or not item.startswith(("http://", "https://")):
                continue
            try:
                validate_outbound_url(item)
            except SSRFError as exc:
                if isinstance(exc.__cause__, socket.gaierror):
                    continue
                raise EgressRefused(field_name, str(exc)) from exc
