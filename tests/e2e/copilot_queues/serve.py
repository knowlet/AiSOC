"""Run the production ASGI applications without unrelated background workers."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=("api", "agents"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo / "services" / args.service))
    application = importlib.import_module("app.main").app
    if args.service == "agents":
        # This production security hook normally registers during lifespan.
        # Keep it active while omitting schedulers and external corpus loading.
        scope = importlib.import_module("app.security.tenant_scope")
        revocation = importlib.import_module("app.security.session_revocation")
        scope.set_revocation_check(revocation.check)

    class TraceRequests:
        async def __call__(self, scope, receive, send):
            async def traced_send(message):
                if scope["type"] == "http" and message["type"] == "http.response.start":
                    trace_path = os.environ.get("COPILOT_QUEUE_HTTP_TRACE")
                    if trace_path:
                        with Path(trace_path).open("a") as trace:
                            trace.write(
                                json.dumps(
                                    {
                                        "service": args.service,
                                        "method": scope["method"],
                                        "path": scope["path"],
                                        "query": scope.get("query_string", b"").decode(),
                                        "status": message["status"],
                                    }
                                )
                                + "\n"
                            )
                await send(message)

            await application(scope, receive, traced_send)

    uvicorn.run(TraceRequests(), host="127.0.0.1", port=args.port, lifespan="off", log_level="warning")


if __name__ == "__main__":
    main()
