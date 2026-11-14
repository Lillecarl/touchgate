"""
The broker's watch and what reads it: `touchgate show` and the loop the
pymux plugin runs. A display shows what the broker holds, never values.
"""

from __future__ import annotations

import os
import sys

import anyio
import pytest

from approving import ARGV, DEADLINE, PASSWORD
from touchgate import approval
from touchgate.approval import ApprovalError, ExecMode, Outcome
from touchgate.broker import ask
from touchgate.client import request
from touchgate.display import events, show

SERVER = "/run/user/1000/pymux-1000/pymux.sock.test.0"


async def _ask(socket, requester=None):
    return await request(socket, "database", ARGV, cwd="/srv", requester=requester, mode=ExecMode.CLIENT, env={})


async def test_the_watch_replays_then_follows(socket, approver):
    with anyio.fail_after(DEADLINE):
        waiting, _ = await _ask(socket)
        watch = events(socket)
        replayed = await anext(watch)
        assert (await anext(watch))["event"] == "listening"
        fresh, challenge = await _ask(socket)
        announced = await anext(watch)
        await ask(socket, {"op": "approve", "id": fresh, "signature": approver.sign(challenge)})
        approved = await anext(watch)
        await ask(socket, {"op": "approve", "id": waiting, "signature": "nonsense"})
        refused = await anext(watch)
        await watch.aclose()
    assert replayed["event"] == "request" and replayed["id"] == waiting
    assert announced == {"event": "request", "id": fresh, "challenge": challenge.decode()}
    assert approved == {"event": "done", "id": fresh, "outcome": "approved"}
    assert refused == {"event": "done", "id": waiting, "outcome": "refused"}
    assert "s3cr3t" not in str([replayed, announced, approved])


async def test_locking_ends_what_waits(socket, broker):
    with anyio.fail_after(DEADLINE):
        id, _ = await _ask(socket)
        watch = events(socket)
        await anext(watch)
        await anext(watch)
        await ask(socket, {"op": "lock"})
        try:
            ended = await anext(watch)
        finally:
            await watch.aclose()
            await broker.unlock(PASSWORD)
    assert ended == {"event": "done", "id": id, "outcome": "locked"}


async def test_show_prints_the_request_and_its_end(socket, approver):
    lines: list[str] = []
    shown = anyio.Event()

    def out(line: str) -> None:
        lines.append(line)
        shown.set()

    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket, requester="%s,3" % SERVER)
        async with anyio.create_task_group() as tasks:

            async def approve_when_shown() -> None:
                await shown.wait()
                await ask(socket, {"op": "approve", "id": id, "signature": approver.sign(challenge)})

            tasks.start_soon(approve_when_shown)
            outcome = await show(socket, id, out)
    assert outcome is Outcome.APPROVED
    assert "psql --host db" in lines[0] and "%s,3" % SERVER in lines[0]
    assert lines[-1] == "request %s: approved" % id


async def test_show_ends_at_expiry_and_refuses_an_unknown_id(socket, monkeypatch):
    monkeypatch.setattr(approval, "LIFETIME", 1)
    lines: list[str] = []
    with anyio.fail_after(DEADLINE):
        id, _ = await _ask(socket)
        assert await show(socket, id, lines.append) is None
        with pytest.raises(ApprovalError, match="no request"):
            await show(socket, "0123456789abcdef", lines.append)
    assert lines[-1] == "request %s: expired" % id


async def test_touchgate_show_runs_as_a_module(socket, approver):
    "What the popup runs: `python -m touchgate show <id>`."
    environment = {**os.environ, "TOUCHGATE_SOCKET": str(socket)}
    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket)
        async with await anyio.open_process(
            [sys.executable, "-m", "touchgate", "show", id], env=environment
        ) as process:
            assert process.stdout is not None
            shown = await process.stdout.receive()
            await ask(socket, {"op": "approve", "id": id, "signature": approver.sign(challenge)})
            code = await process.wait()
            rest = b"".join([chunk async for chunk in process.stdout])
    assert b"touch the key to approve request %s" % id.encode() in shown
    assert b"approved" in shown + rest
    assert code == 0
