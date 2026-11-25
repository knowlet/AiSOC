"""Compiled hunts must retain their filters when replayed as standalone SQL."""

from __future__ import annotations

import json
import uuid
from dataclasses import replace

import pytest
import sqlglot
from app._vendor.nl_query import QueryIntents
from app.services.lake_hunt import HuntCompileError, compile_hunt, render_replayable_sql
from app.services.lake_sql import LakeSqlForbiddenError, rewrite_for_tenant
from sqlglot import exp

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
OTHER_TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000002")


def _replay_tree(intents: QueryIntents, *, hours: int = 24, limit: int = 500) -> exp.Expression:
    compiled = compile_hunt(intents, tenant_id=str(TENANT), hours=hours, limit=limit)
    rendered = render_replayable_sql(compiled, tenant_id=TENANT)
    # /lake/sql applies this same policy again when the editor submits SQL.
    replayed = rewrite_for_tenant(rendered, TENANT)
    statements = sqlglot.parse(replayed.sql, read="clickhouse")
    assert len(statements) == 1
    assert isinstance(statements[0], exp.Select)
    return statements[0]


@pytest.mark.parametrize(
    "value",
    [
        "O'Reilly\\bin",
        "100% %(missing)s 台灣",
        "alice' OR 1 = 1; --",
        "line\n\t\0\b\f\r\a\v",
    ],
)
def test_string_filters_survive_rendering_and_replay(value: str):
    tree = _replay_tree(QueryIntents(filters=[("user.name", "==", value)]))
    predicates = [predicate for predicate in tree.find_all(exp.EQ) if predicate.this.name == "user_name"]
    assert len(predicates) == 1
    assert isinstance(predicates[0].expression, exp.Literal)
    assert predicates[0].expression.is_string
    assert predicates[0].expression.this == value
    assert not list(tree.find_all(exp.Or))


def test_replay_preserves_arrays_numeric_filters_payload_filters_and_bounds():
    users = ["O'Reilly", "C:\\台灣\\100%", "%(f0)s"]
    techniques = ["T1059", "T1059.001"]
    pattern = "%powershell%"
    tree = _replay_tree(
        QueryIntents(
            filters=[
                ("user.name", "IN", json.dumps(users)),
                ("threat.technique.id", "IN", json.dumps(techniques)),
                ("process.name", "LIKE", pattern),
                ("destination.port", ">=", "443"),
                ("EventID", "==", "4688"),
            ],
        ),
        hours=6,
        limit=25,
    )
    arrays = [[item.this for item in array.expressions] for array in tree.find_all(exp.Array)]
    assert techniques in arrays
    user_filter = tree.find(exp.In)
    assert user_filter.this.name == "user_name"
    assert [item.this for item in user_filter.expressions] == users
    assert tree.find(exp.ILike).expression.this == pattern
    port_filter = next(predicate for predicate in tree.find_all(exp.GTE) if predicate.this.name == "dst_port")
    assert port_filter.expression.this == "443"
    assert not port_filter.expression.is_string
    payload_filter = next(predicate for predicate in tree.find_all(exp.EQ) if isinstance(predicate.this, exp.Coalesce))
    assert payload_filter.expression.this == "4688"
    payload_keys = [key.this for key in payload_filter.this.find_all(exp.JSONPathKey)]
    assert payload_keys.count("EventID") == 3
    assert "EventData" in payload_keys
    assert "System" in payload_keys
    assert tree.find(exp.Interval).this.this == "6"
    assert tree.args["limit"].expression.this == "25"
    assert tree.args["order"].expressions[0].this.name == "event_time"
    assert tree.args["order"].expressions[0].args["desc"]


def test_grouped_and_distinct_projections_remain_replayable():
    grouped = _replay_tree(QueryIntents(group_by=["user.name"]))
    assert [column.name for column in grouped.args["group"].expressions] == ["user_name"]
    assert grouped.find(exp.Count) is not None
    distinct = _replay_tree(QueryIntents(distinct="user.name"))
    assert distinct.args["distinct"] is not None
    assert [column.name for column in distinct.expressions] == ["user_name"]


def test_replay_is_bound_to_the_authenticated_tenant():
    compiled = compile_hunt(QueryIntents(), tenant_id=str(TENANT))
    with pytest.raises(HuntCompileError, match="authenticated tenant"):
        render_replayable_sql(compiled, tenant_id=OTHER_TENANT)

    rendered = render_replayable_sql(compiled, tenant_id=TENANT)
    replayed = rewrite_for_tenant(rendered, OTHER_TENANT)
    tree = sqlglot.parse_one(replayed.sql, read="clickhouse")
    tenants = {predicate.expression.this for predicate in tree.find_all(exp.EQ) if predicate.this.name == "tenant_id"}
    assert tenants == {str(TENANT), str(OTHER_TENANT)}
    assert not list(tree.find_all(exp.Or))


@pytest.mark.parametrize("value", [True, 1.5, {"value": "alice"}, ["alice", 1]])
def test_renderer_refuses_types_the_compiler_does_not_emit(value):
    compiled = compile_hunt(QueryIntents(filters=[("user.name", "==", "alice")]), tenant_id=str(TENANT))
    compiled = replace(compiled, params={**compiled.params, "f0": value})
    with pytest.raises(HuntCompileError, match="unsupported parameter type"):
        render_replayable_sql(compiled, tenant_id=TENANT)


@pytest.mark.parametrize("mutation", ["missing", "extra", "unexpected_placeholder"])
def test_renderer_refuses_incomplete_or_unexpected_bindings(mutation):
    compiled = compile_hunt(QueryIntents(), tenant_id=str(TENANT))
    if mutation == "missing":
        compiled = replace(compiled, params={"tenant_id": str(TENANT)})
    elif mutation == "extra":
        compiled = replace(compiled, params={**compiled.params, "unused": "alice"})
    else:
        compiled = replace(compiled, sql=compiled.sql.replace("%(hours)s", "%(hours)d"))
    with pytest.raises(HuntCompileError, match="parameter bindings"):
        render_replayable_sql(compiled, tenant_id=TENANT)


def test_renderer_keeps_the_existing_lake_table_policy():
    compiled = compile_hunt(QueryIntents(), tenant_id=str(TENANT))
    compiled = replace(compiled, sql=compiled.sql.replace("aisoc.raw_events", "system.users"))
    with pytest.raises(LakeSqlForbiddenError):
        render_replayable_sql(compiled, tenant_id=TENANT)
