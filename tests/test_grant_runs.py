"""
Grants through a broker: one touch, then runs with none, for the
processes under the anchor and for nobody else.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from pathlib import Path

import anyio
import pytest

from approving import DEADLINE, PASSWORD
from touchgate import processes
from touchgate.approval import GRANT_NAMESPACE, ApprovalError
from touchgate.broker import Ask, GrantAsk, ask

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="a grant reads /proc")

SH = shutil.which("sh") or "/bin/sh"
CLIENT = Path(__file__).with_name("granted_client.py")


@pytest.fixture(autouse=True)
def no_grants_after(broker):
    "The broker is the module's; a grant one test leaves must not reach the next."
    yield
    broker.grants.clear()


def _client(socket: Path, out: Path, grant: dict[str, object] | None) -> list[str]:
    "The argv of one client run; its command appends the token to `out`."
    command = [SH, "-c", 'echo "$API_TOKEN" >> %s' % shlex.quote(str(out))]
    return [sys.executable, str(CLIENT), str(socket), "database", json.dumps(grant), *command]


async def _drive(argv: list[str], sign) -> list[dict[str, object]]:
    "Runs `argv`, answers each challenge it shows with `sign`, and answers every line it printed."
    lines: list[dict[str, object]] = []
    async with await anyio.open_process(argv, stderr=None) as process:
        assert process.stdin is not None and process.stdout is not None
        buffer = b""
        async for chunk in process.stdout:
            buffer += chunk
            while b"\n" in buffer:
                line, _, buffer = buffer.partition(b"\n")
                message = json.loads(line)
                lines.append(message)
                if "challenge" in message:
                    signature = sign(str(message["challenge"]).encode())
                    await process.stdin.send(json.dumps({"signature": signature}).encode() + b"\n")
        await process.wait()
    return lines


async def test_one_touch_then_runs_with_none_under_the_anchor(socket, approver, tmp_path):
    out = tmp_path / "out"
    grant: dict[str, object] = {"seconds": 60, "anchor": "parent"}
    # sh is the anchor and stays the parent of both clients: `; true` stops it exec'ing the last.
    script = "%s; %s; true" % (shlex.join(_client(socket, out, grant)), shlex.join(_client(socket, out, None)))
    with anyio.fail_after(DEADLINE):
        lines = await _drive([SH, "-c", script], lambda challenge: approver.sign(challenge, GRANT_NAMESPACE))
        # sh has exited, and the grant with it.
        held = (await ask(socket, {"op": "grants"}))["grants"]
    challenge = json.loads(str(lines[0]["challenge"]))
    assert challenge["grant"]["seconds"] == 60 and challenge["grant"]["anchor"]["name"] == "sh"
    assert lines[1:] == [{"exit": 0}, {"exit": 0}]
    assert out.read_text() == "t0ken\n" * 2
    assert held == []


async def test_a_grant_signed_as_a_plain_run_is_refused(socket, approver, tmp_path):
    out = tmp_path / "out"
    script = "%s; true" % shlex.join(_client(socket, out, {"seconds": 60, "anchor": "parent"}))
    with anyio.fail_after(DEADLINE):
        # An old signer signs under the plain namespace and shows no grant.
        lines = await _drive([SH, "-c", script], lambda challenge: approver.sign(challenge))
        held = (await ask(socket, {"op": "grants"}))["grants"]
    assert "refused" in str(lines[-1].get("error"))
    assert held == [] and not out.exists()


async def _tree() -> tuple[anyio.abc.Process, processes.Process, processes.Process]:
    "sh, which stays, and under it a sleep that says its pid: an anchor and a process under it."
    tree = await anyio.open_process([SH, "-c", "sh -c 'echo $$; exec sleep 30'; true"])
    assert tree.stdout is not None
    child = int((await tree.stdout.receive()).decode())
    anchor, under = processes.read(tree.pid), processes.read(child)
    assert anchor is not None and under is not None
    return tree, anchor, under


async def test_only_the_process_that_asked_runs_under_the_grant(socket, approver, broker, stdio):
    argv = [SH, "-c", "true"]
    with anyio.fail_after(DEADLINE):
        tree, anchor, under = await _tree()
        try:
            granting = Ask(
                op="request", secret="database", argv=argv, cwd="/", grant=GrantAsk(seconds=60, anchor=anchor.pid)
            )
            asked = await broker.ask(granting, under)
            signature = approver.sign(str(asked["challenge"]).encode(), GRANT_NAMESPACE)
            # The touch approves from anywhere; the broker checks the signature.
            assert await _approve(socket, str(asked["id"]), signature, stdio) == {"ok": True, "exit": 0}
            later = await broker.ask(Ask(op="request", secret="database", argv=argv, cwd="/"), under)
            assert "grant" in later
            # This test process holds the id, but it did not ask, and is not under the anchor.
            refused = await _approve(socket, str(later["id"]), None, stdio)
            assert "only the process that asked" in str(refused["error"])
            assert "grant" not in await broker.ask(Ask(op="request", secret="database", argv=argv, cwd="/"), _me())
            listed = (await ask(socket, {"op": "grants"}))["grants"]
            assert isinstance(listed, list) and [each["anchor"]["pid"] for each in listed] == [anchor.pid]
            assert (await ask(socket, {"op": "revoke", "id": None}))["revoked"] == [later["grant"]]
            assert "grant" not in await broker.ask(Ask(op="request", secret="database", argv=argv, cwd="/"), under)
        finally:
            tree.kill()
            await tree.aclose()


async def test_the_anchor_is_a_parent_and_not_one_of_the_brokers(broker):
    argv = [SH, "-c", "true"]
    with anyio.fail_after(DEADLINE):
        tree, _, under = await _tree()
        try:
            with pytest.raises(ApprovalError, match="not a parent"):
                await broker.ask(
                    Ask(
                        op="request",
                        secret="database",
                        argv=argv,
                        cwd="/",
                        grant=GrantAsk(seconds=60, anchor=under.pid),
                    ),
                    under,
                )
            # This test process runs the broker, and is a parent of the tree.
            with pytest.raises(ApprovalError, match="parent of the broker"):
                await broker.ask(
                    Ask(
                        op="request",
                        secret="database",
                        argv=argv,
                        cwd="/",
                        grant=GrantAsk(seconds=60, anchor=os.getpid()),
                    ),
                    under,
                )
        finally:
            tree.kill()
            await tree.aclose()


async def test_locking_ends_the_grants(socket, approver, broker, stdio):
    argv = [SH, "-c", "true"]
    with anyio.fail_after(DEADLINE):
        tree, anchor, under = await _tree()
        try:
            asked = await broker.ask(
                Ask(op="request", secret="database", argv=argv, cwd="/", grant=GrantAsk(seconds=60, anchor=anchor.pid)),
                under,
            )
            signature = approver.sign(str(asked["challenge"]).encode(), GRANT_NAMESPACE)
            await _approve(socket, str(asked["id"]), signature, stdio)
            assert broker.grants.listed()
            broker.lock()
            assert broker.grants.listed() == []
        finally:
            tree.kill()
            await tree.aclose()
            if broker.vault is None:
                await broker.unlock(PASSWORD)


def _me() -> processes.Process:
    me = processes.read(os.getpid())
    assert me is not None
    return me


async def _approve(socket: Path, id: str, signature: str | None, stdio: tuple[int, int, int]) -> dict[str, object]:
    async with await anyio.connect_unix(socket) as stream:
        await stream.send_fds(json.dumps({"op": "approve", "id": id, "signature": signature}).encode() + b"\n", stdio)
        return json.loads(await stream.receive())


@pytest.fixture
def stdio(tmp_path):
    created = os.O_WRONLY | os.O_CREAT
    fds = (os.open(os.devnull, os.O_RDONLY), os.open(tmp_path / "out", created), os.open(tmp_path / "err", created))
    yield fds
    for fd in fds:
        os.close(fd)
