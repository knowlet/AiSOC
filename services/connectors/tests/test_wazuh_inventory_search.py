"""Inventory routing against a disposable, loopback-only OpenSearch index.

Set WAZUH_TEST_OPENSEARCH_URL to an unauthenticated local test node to run.
No production endpoint or credentials are accepted. Every test writes synthetic
fixtures to a unique index and deletes only that index on completion.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest
from app.connectors.wazuh import WazuhConnector, is_vulnerability_source


@pytest.fixture
def search_index():
    url = os.environ.get("WAZUH_TEST_OPENSEARCH_URL")
    if not url:
        pytest.skip("requires a disposable local OpenSearch node")
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username or parsed.password:
        pytest.fail("WAZUH_TEST_OPENSEARCH_URL must be an unauthenticated loopback HTTP endpoint")
    index = f"wazuh-routing-test-{uuid4().hex}"
    with httpx.Client(base_url=url, trust_env=False) as client:
        response = client.put(
            f"/{index}",
            json={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "rule": {"properties": {"groups": {"type": "keyword"}, "level": {"type": "integer"}}},
                    }
                },
            },
        )
        response.raise_for_status()
        try:
            yield url, index, client
        finally:
            client.delete(f"/{index}").raise_for_status()


def _source(groups, data):
    return {
        "@timestamp": datetime.now(UTC).isoformat(),
        "agent": {"id": "001", "name": "synthetic-test-host"},
        "rule": {"id": "100001", "level": 12, "groups": groups, "description": "Synthetic CVE-2026-1234 fixture"},
        "data": data,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "groups,data",
    [
        (["vulnerability-detector"], {"vulnerability": {"cve": "CVE-2026-1234"}}),
        (["vulnerability"], {"vulnerability": {"cve": "CVE-2026-1234"}}),
        (["custom-detector"], {"vulnerability": {"cve": "CVE-2026-1234"}}),
        (["custom-detector"], {"vulnerability": {}, "cve": "CVE-2026-1234"}),
    ],
    ids=["detector-group", "vulnerability-group", "custom-payload", "custom-fallback-cve"],
)
async def test_inventory_search_conserves_classified_findings(search_index, groups, data):
    url, index, client = search_index
    vulnerability = _source(groups, data)
    # A real detection can mention a CVE, including in data.cve, without
    # being an inventory event. The wider candidate query must not claim it.
    exploit = _source(["exploit_attempt"], {"cve": "CVE-2026-1234"})
    assert is_vulnerability_source(vulnerability)
    assert not is_vulnerability_source(exploit)
    for doc_id, source in (("inventory", vulnerability), ("exploit", exploit)):
        client.put(f"/{index}/_doc/{doc_id}", json=source).raise_for_status()
    client.post(f"/{index}/_refresh").raise_for_status()

    connector = WazuhConnector(url, "", "", index_pattern=index)
    alerts = await connector.fetch_alerts()
    findings = await connector.fetch_vulnerability_findings()
    assert len(alerts) == 1
    assert alerts[0]["raw_event"]["data"] == exploit["data"]
    assert [finding["external_id"] for finding in findings] == ["inventory"]
    assert findings[0]["hostname"] == "synthetic-test-host"
    assert findings[0]["cve_id"] == "CVE-2026-1234"

    legacy = WazuhConnector(url, "", "", index_pattern=index, vuln_mode="alerts")
    assert len(await legacy.fetch_alerts()) == 2
    assert await legacy.fetch_vulnerability_findings() == []
