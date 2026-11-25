"""Literal SQL must reach the driver without a second binding pass.

The driver itself performs substitution here; only its network transport is
replaced. Passing an empty dict is observably different from passing None.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.db import clickhouse
from clickhouse_driver import Client


@pytest.fixture
def sent_sql(monkeypatch: pytest.MonkeyPatch):
    driver = Client(host="127.0.0.1")
    driver.connection.context.client_settings = {"server_side_params": False}
    sent = []
    monkeypatch.setattr(driver.connection, "send_query", lambda sql, **kwargs: sent.append(sql))
    monkeypatch.setattr(driver.connection, "send_external_tables", lambda *args, **kwargs: None)
    monkeypatch.setattr(driver, "receive_result", lambda **kwargs: ([], [("value", "String")]))

    def execute(sql, params=None, **kwargs):
        return driver.process_ordinary_query(sql, params=params, with_column_types=kwargs["with_column_types"])

    async def client():
        return SimpleNamespace(execute=execute)

    monkeypatch.setattr(clickhouse, "get_clickhouse_client", client)
    return sent


@pytest.mark.asyncio
@pytest.mark.parametrize("sql", ["SELECT '100%' AS value", "SELECT '%(missing)s' AS value", "SELECT 7 % 3 AS value"])
async def test_literal_sql_is_not_interpreted_as_a_driver_template(sent_sql, sql):
    await clickhouse.execute_lake_query(sql)
    assert sent_sql == [sql]


@pytest.mark.asyncio
async def test_explicit_bindings_still_use_the_drivers_escaping(sent_sql):
    await clickhouse.execute_lake_query("SELECT %(value)s AS value", params={"value": "O'Reilly 100%"})
    assert sent_sql == ["SELECT 'O\\'Reilly 100%' AS value"]


@pytest.mark.asyncio
async def test_an_explicit_empty_mapping_retains_the_driver_contract(sent_sql):
    await clickhouse.execute_lake_query("SELECT '100%%' AS value", params={})
    assert sent_sql == ["SELECT '100%' AS value"]
