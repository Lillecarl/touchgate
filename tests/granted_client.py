"""
A broker run from a process of its own, for the grant tests: the broker
reads which process asks, so the client cannot be the test process.

    python granted_client.py SOCKET SECRET GRANT COMMAND...

GRANT is JSON terms or `null`; an anchor of `"parent"` names this
process's parent. Each challenge goes to stdout as a JSON line, and the
signature comes back on stdin as one. The last line is the exit code or
the error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import anyio

from touchgate.approval import ApprovalError
from touchgate.client import run_in_broker


async def main() -> None:
    socket, secret, terms, *command = sys.argv[1:]
    grant = json.loads(terms)
    if grant is not None and grant.get("anchor") == "parent":
        grant["anchor"] = os.getppid()

    async def sign(challenge: bytes) -> str:
        print(json.dumps({"challenge": challenge.decode()}), flush=True)
        return json.loads(await anyio.to_thread.run_sync(sys.stdin.readline))["signature"]

    null = os.open(os.devnull, os.O_RDWR)
    try:
        code = await run_in_broker(
            Path(socket),
            secret,
            command,
            sign,
            cwd="/",
            requester=None,
            env={},
            environ={},
            announce=lambda line: None,
            stdio=(null, null, null),
            grant=grant,
        )
        print(json.dumps({"exit": code}), flush=True)
    except ApprovalError as error:
        print(json.dumps({"error": str(error)}), flush=True)


if __name__ == "__main__":
    anyio.run(main)
