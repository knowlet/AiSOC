#!/usr/bin/env python3
"""Exercise Copilot queue tools over real HTTP and migrated PostgreSQL.

The external model is a controlled OpenAI-compatible HTTP server. Tool
selection is scripted; authentication, permissions, SQL, tool dispatch,
grounding, and conversation persistence use the production applications.
Run only against a disposable database: the harness inserts synthetic fixtures.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import asyncpg
import httpx


@dataclass
class Scenario:
    tools: list[tuple[str, dict[str, Any]]]
    reply: str
    required: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()
    requests: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evidence: str = ""


class ModelServer(ThreadingHTTPServer):
    scenario: Scenario | None = None


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        scenario = self.server.scenario
        try:
            assert self.path == "/v1/chat/completions", self.path
            assert scenario is not None, "No model scenario is active"
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            scenario.requests.append(payload)
            available = {item["function"]["name"] for item in payload.get("tools", [])}
            for name, _ in scenario.tools:
                assert name in available, f"Copilot did not advertise {name}"
            if len(scenario.requests) == 1:
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"queue-call-{index}",
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(arguments)},
                        }
                        for index, (name, arguments) in enumerate(scenario.tools)
                    ],
                }
            else:
                assert len(scenario.requests) == 2, "Copilot exceeded the scripted two-completion exchange"
                messages = [item for item in payload["messages"] if item["role"] == "tool"]
                assert len(messages) == len(scenario.tools), "A selected tool did not return a result"
                scenario.evidence = "\n".join(item["content"] for item in messages)
                for expected in scenario.required:
                    assert expected in scenario.evidence, f"Missing evidence: {expected}"
                for forbidden in scenario.forbidden:
                    assert forbidden not in scenario.evidence, f"Forbidden evidence: {forbidden}"
                message = {"role": "assistant", "content": scenario.reply}
            result = {
                "id": "queue-model-response",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "aisoc-copilot",
                "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
            }
            self.send_response(200)
        except Exception as exc:
            if scenario is not None:
                scenario.errors.append(str(exc))
            result = {"error": {"message": str(exc), "type": "fixture_contract_error"}}
            self.send_response(500)
        body = json.dumps(result).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def token(secret: str, tenant_id: uuid.UUID, user_id: uuid.UUID, role: str) -> str:
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "role": role,
        "type": "access",
        "iat": int(time.time()),
        "exp": int(time.time()) + 900,
    }
    signing = encode({"alg": "HS256", "typ": "JWT"}) + b"." + encode(payload)
    signature = base64.urlsafe_b64encode(hmac.digest(secret.encode(), signing, hashlib.sha256)).rstrip(b"=")
    return (signing + b"." + signature).decode()


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def dsn(value: str) -> str:
    return value.replace("postgresql+asyncpg://", "postgresql://")


@asynccontextmanager
async def connect(value: str):
    connection = await asyncpg.connect(dsn(value))
    try:
        yield connection
    finally:
        await connection.close()


async def seed(connection) -> dict[str, Any]:
    ids = {
        key: uuid.uuid4()
        for key in ("tenant_a", "tenant_b", "analyst_a", "analyst_b", "denied", "case_a", "case_b", "approval_a", "approval_b")
    }
    suffix = uuid.uuid4().hex[:10]
    for letter in ("a", "b"):
        await connection.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            ids[f"tenant_{letter}"],
            f"Synthetic Copilot queue tenant {letter}",
            f"copilot-queue-{letter}-{suffix}",
        )
    for name, letter, role in (
        ("analyst_a", "a", "soc_analyst"),
        ("analyst_b", "b", "soc_analyst"),
        ("denied", "a", "queue_no_permissions"),
    ):
        await connection.execute(
            "INSERT INTO users (id, tenant_id, email, username, hashed_password, role) VALUES ($1,$2,$3,$4,$5,$6)",
            ids[name],
            ids[f"tenant_{letter}"],
            f"{name}-{suffix}@example.invalid",
            name,
            "not-a-login-credential",
            role,
        )
    for letter, indicator in (("a", "198.51.100.42"), ("b", "203.0.113.77")):
        await connection.execute(
            """
            INSERT INTO aisoc_cases (id, tenant_id, case_number, title, description, status, severity)
            VALUES ($1,$2,$3,$4,$5,'investigating','high')
            """,
            ids[f"case_{letter}"],
            ids[f"tenant_{letter}"],
            f"INC-QUEUE-{letter}-{suffix}",
            f"Synthetic needle%_ case {indicator}",
            "Synthetic transport-test evidence; no real incident.",
        )
        await connection.execute(
            """
            INSERT INTO agent_approvals
                (id,tenant_id,case_id,required_user_id,title,summary,risk_level,action,status)
            VALUES ($1,$2,$3,$4,$5,$6,'high',$7::jsonb,'pending')
            """,
            ids[f"approval_{letter}"],
            ids[f"tenant_{letter}"],
            str(ids[f"case_{letter}"]),
            ids[f"analyst_{letter}"],
            f"Synthetic review {indicator}",
            f"Review requested for {indicator}; no action has executed.",
            json.dumps({"kind": "isolate_host", "secret": "DO_NOT_SEND_ACTION_PAYLOAD", "target": "fixture-host"}),
        )
    for index in range(22):
        await connection.execute(
            """
            INSERT INTO aisoc_cases (tenant_id,case_number,title,description,status,severity,created_at)
            VALUES ($1,$2,$3,'Synthetic pagination fixture','new','low',now() - make_interval(secs => $4))
            """,
            ids["tenant_a"],
            f"INC-PAGE-{suffix}-{index}",
            f"Synthetic queue-page {index:02}",
            index + 1,
        )
    # A wildcard-shaped near match proves '%' and '_' are treated literally.
    await connection.execute(
        """
        INSERT INTO aisoc_cases (tenant_id,case_number,title,status,severity)
        VALUES ($1,$2,'Synthetic needleXY near-match','investigating','high')
        """,
        ids["tenant_a"],
        f"INC-DECOY-{suffix}",
    )
    await connection.execute(
        """
        INSERT INTO agent_approvals (tenant_id,title,summary,risk_level,action,status)
        VALUES ($1,'Synthetic decided review','Already decided','high','{}','approved')
        """,
        ids["tenant_a"],
    )
    return ids


async def snapshot(connection, tenant_ids) -> dict[str, Any]:
    state: dict[str, Any] = {}
    for table in ("aisoc_cases", "agent_approvals"):
        rows = await connection.fetch(
            f"SELECT row_to_json(row) AS value FROM {table} row WHERE tenant_id = ANY($1::uuid[]) ORDER BY id", tenant_ids
        )
        state[table] = [row["value"] for row in rows]
    state["action_count"] = await connection.fetchval("SELECT count(*) FROM aisoc_action_records")
    return state


async def wait_for_http(client, url: str, process, log: Path) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"Service exited before accepting requests: {log.read_text()[-6000:]}")
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.1)
    raise AssertionError(f"Service did not accept HTTP requests: {log.read_text()[-6000:]}")


def stop(process) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


async def run(args) -> None:
    assert os.environ.get("DATABASE_URL"), "DATABASE_URL must name a migrated disposable PostgreSQL database"
    assert os.environ.get("DATABASE_MIGRATION_URL"), "DATABASE_MIGRATION_URL is required to insert isolated fixtures"
    assert args.disposable_database, "Pass --disposable-database to confirm this is a disposable test database"
    secret = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(48)
    async with connect(os.environ["DATABASE_MIGRATION_URL"]) as owner:
        ids = await seed(owner)
        tenants = [ids["tenant_a"], ids["tenant_b"]]
        before = await snapshot(owner, tenants)
        async with connect(os.environ["DATABASE_URL"]) as application_db:
            row = await application_db.fetchrow("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
            assert not row["rolsuper"] and not row["rolbypassrls"], "Application must use a non-superuser NOBYPASSRLS role"

        with ExitStack() as stack:
            work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="copilot-queues-")))
            model = ModelServer(("127.0.0.1", 0), ModelHandler)
            stack.callback(model.server_close)
            thread = threading.Thread(target=model.serve_forever, daemon=True)
            thread.start()
            stack.callback(model.shutdown)
            model_url = f"http://127.0.0.1:{model.server_port}/v1"
            api_port, agents_port = unused_port(), unused_port()
            api_url, agents_url = f"http://127.0.0.1:{api_port}", f"http://127.0.0.1:{agents_port}"
            trace = work / "http.jsonl"
            env = {key: value for key, value in os.environ.items() if key not in {"ALL_PROXY", "all_proxy"}}
            env.update(
                {
                    "SECRET_KEY": secret,
                    "ENV": "test",
                    "ENVIRONMENT": "test",
                    "DEMO_MODE": "false",
                    "AISOC_DEV_AUTH_BYPASS": "0",
                    "AISOC_API_URL": api_url,
                    "OPENAI_BASE_URL": model_url,
                    "LLM_GATEWAY_URL": model_url,
                    "LITELLM_MASTER_KEY": "queue-test-local-gateway",
                    "OPENAI_API_KEY": "queue-test-local-gateway",
                    "AISOC_MODEL_PIN_COPILOT": "aisoc-copilot",
                    "COPILOT_QUEUE_HTTP_TRACE": str(trace),
                    "NO_PROXY": "127.0.0.1,localhost",
                    "no_proxy": "127.0.0.1,localhost",
                }
            )
            processes = []
            for service, executable, port in (("api", args.api_python, api_port), ("agents", args.agents_python, agents_port)):
                log = work / f"{service}.log"
                handle = stack.enter_context(log.open("w"))
                process = subprocess.Popen(
                    [str(executable), str(Path(__file__).with_name("serve.py")), service, "--repo", str(args.repo), "--port", str(port)],
                    cwd=args.repo,
                    env=env,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                )
                stack.callback(stop, process)
                processes.append((process, log))
            async with httpx.AsyncClient(timeout=100, trust_env=False) as client:
                await wait_for_http(client, api_url + "/api/openapi.json", *processes[0])
                await wait_for_http(client, agents_url + "/openapi.json", *processes[1])
                auth = {
                    name: {"Authorization": "Bearer " + token(secret, ids[f"tenant_{letter}"], ids[name], role)}
                    for name, letter, role in (
                        ("analyst_a", "a", "soc_analyst"),
                        ("analyst_b", "b", "soc_analyst"),
                        ("denied", "a", "queue_no_permissions"),
                    )
                }

                async def chat(scenario, actor="analyst_a", stream=False):
                    model.scenario = scenario
                    response = await client.post(
                        agents_url + "/api/v1/copilot/chat" + ("/stream" if stream else ""),
                        headers=auth[actor],
                        json={
                            "message": "Find the matching cases and pending review work.",
                            "context": {"tenant_id": str(ids["tenant_b"])},
                        },
                    )
                    assert response.status_code == 200, response.text
                    payload = json.loads(response.text.splitlines()[0]) if stream else response.json()
                    assert not scenario.errors, scenario.errors
                    assert payload["source"] == "llm", payload
                    assert len(scenario.requests) == 2, "Expected one tool round and one final answer"
                    assert len(payload["data_access"]) == len(scenario.tools), payload
                    return payload

                case_ref, approval_ref = f"case:{ids['case_a']}", f"approval:{ids['approval_a']}"
                scenario = Scenario(
                    [("copilot_cases", {"query": "needle%_", "status": "investigating", "severity": "high"})],
                    f"198.51.100.42 appears in {case_ref}.",
                    required=(case_ref, "198.51.100.42"),
                    forbidden=(str(ids["case_b"]), "203.0.113.77", "needleXY"),
                )
                payload = await chat(scenario)
                assert payload["data_access"][0]["records"] == 1, payload
                assert payload["grounding"]["citations"] == [{"claim": "198.51.100.42", "refs": [case_ref]}], payload
                persisted = await client.get(
                    agents_url + "/api/v1/copilot/conversations/" + payload["conversationId"], headers=auth["analyst_a"]
                )
                assert persisted.status_code == 200, persisted.text
                assert persisted.json()["messages"][-1]["grounding"] == payload["grounding"]
                print("[PASS] authenticated literal case search, tenant isolation, citation and persisted conversation", flush=True)

                scenario = Scenario(
                    [("copilot_pending_approvals", {"mine": True, "risk_level": "high"})],
                    f"198.51.100.42 is awaiting review in {approval_ref}.",
                    required=(approval_ref, "198.51.100.42"),
                    forbidden=(str(ids["approval_b"]), "DO_NOT_SEND_ACTION_PAYLOAD", "isolate_host", "Synthetic decided review"),
                )
                payload = await chat(scenario, stream=True)
                assert payload["data_access"][0]["records"] == 1, payload
                assert payload["grounding"]["citations"] == [{"claim": "198.51.100.42", "refs": [approval_ref]}], payload
                print("[PASS] streamed pending approvals, personal assignment, safe projection and citation", flush=True)

                scenario = Scenario(
                    [("copilot_cases", {"query": "needle%_"}), ("copilot_pending_approvals", {})],
                    "Both bounded queues were inspected.",
                    required=(str(ids["case_b"]), str(ids["approval_b"]), "203.0.113.77"),
                    forbidden=(str(ids["case_a"]), str(ids["approval_a"]), "198.51.100.42"),
                )
                payload = await chat(scenario, actor="analyst_b")
                assert all(item["status"] == "ok" and item["records"] == 1 for item in payload["data_access"]), payload
                print("[PASS] second tenant sees only its own cases and approvals", flush=True)

                scenario = Scenario(
                    [("copilot_cases", {"query": "not-present-in-fixtures"}), ("copilot_pending_approvals", {"risk_level": "critical"})],
                    "No matching rows were returned in these bounded reads.",
                    required=('"outcome": "ok"', '"records": []'),
                )
                payload = await chat(scenario)
                assert all(item["status"] == "ok" and item["records"] == 0 for item in payload["data_access"]), payload
                assert payload["notice"] is None, payload
                print("[PASS] successful empty queues remain distinguishable from unavailable reads", flush=True)

                scenario = Scenario(
                    [("copilot_cases", {"query": "needle%_"})],
                    "Permission denied; the case queue could not be checked.",
                    required=("HTTP 403", "could_not_check"),
                    forbidden=(case_ref, "198.51.100.42"),
                )
                payload = await chat(scenario, actor="denied")
                assert payload["data_access"][0]["status"] == "could_not_check", payload
                assert payload["notice"], payload
                print("[PASS] denied case permission is reported as unavailable, never an empty queue", flush=True)

                scenario = Scenario(
                    [("copilot_cases", {"query": "queue-page", "page": 1})],
                    "This is one bounded page; more matching cases may exist.",
                    required=("Synthetic queue-page",),
                )
                payload = await chat(scenario)
                assert 0 < payload["data_access"][0]["records"] <= 20, payload
                page = json.loads(scenario.evidence)
                assert page["has_more"] is True and page["next_page"] == 2, page
                if len(page["records"]) < 20:
                    assert page["truncated"] and page["truncation_notice"], page
                scenario = Scenario(
                    [("copilot_cases", {"query": "queue-page", "page": 2})],
                    "The second page contains the remaining matching cases.",
                    required=("Synthetic queue-page 20", "Synthetic queue-page 21"),
                )
                payload = await chat(scenario)
                assert payload["data_access"][0]["records"] == 2, payload
                print("[PASS] case pagination remains bounded at 20 records per request", flush=True)

                response = await client.post(agents_url + "/api/v1/copilot/chat", json={"message": "Read all queues"})
                assert response.status_code == 401, response.text
                print("[PASS] anonymous Copilot requests are refused", flush=True)

            after = await snapshot(owner, tenants)
            assert after == before, "Queue reads changed cases, approval decisions, payloads, or action records"
            requests = [json.loads(line) for line in trace.read_text().splitlines()]
            reads = [row for row in requests if row["service"] == "api" and row["path"] != "/api/openapi.json"]
            assert reads and all(row["method"] == "GET" and row["path"] in {"/api/v1/cases", "/api/v1/approvals"} for row in reads), reads
            assert any(row["status"] == 403 for row in reads), reads
            for row in reads:
                query = parse_qs(row["query"])
                if row["path"] == "/api/v1/cases":
                    assert query["limit"] == ["21"], row
                else:
                    assert query["status"] == ["pending"] and query["page_size"] == ["20"], row
            print("[PASS] only bounded GET calls reached the API; no case, approval or action writes occurred", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--api-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--agents-python", type=Path, required=True)
    parser.add_argument("--disposable-database", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
