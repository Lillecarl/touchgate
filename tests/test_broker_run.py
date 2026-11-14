"""
Broker runs: the broker starts the approved command on the client's stdio,
so the values reach that command and never the client.
"""

from __future__ import annotations

import json
import os
import shutil
import signal

import anyio
import pytest

from approving import ARGV, DEADLINE, signer
from touchgate.approval import ExecMode
from touchgate.broker import Lines, ask
from touchgate.client import request, run_in_broker

SH = shutil.which("sh") or "/bin/sh"


@pytest.fixture
def stdio(tmp_path):
    "stdin from /dev/null, stdout and stderr to tmp_path/out and tmp_path/err."
    created = os.O_WRONLY | os.O_CREAT
    fds = (os.open(os.devnull, os.O_RDONLY), os.open(tmp_path / "out", created), os.open(tmp_path / "err", created))
    yield fds
    for fd in fds:
        os.close(fd)


async def test_the_broker_runs_the_approved_command(socket, approver, stdio, tmp_path):
    script = 'printf "%s|%s|%s|%s" "$API_TOKEN" "$PGPASSWORD" "${LD_PRELOAD-unset}" "$KEEP"; pwd >&2; exit 3'
    with anyio.fail_after(DEADLINE):
        code = await run_in_broker(
            socket,
            "database",
            [SH, "-c", script],
            signer(approver),
            cwd=str(tmp_path),
            requester=None,
            env={"PGPASSWORD": "password"},
            environ={"KEEP": "kept", "LD_PRELOAD": "/tmp/evil.so"},
            announce=lambda line: None,
            stdio=stdio,
        )
    assert code == 3
    assert (tmp_path / "out").read_text() == "t0ken|s3cr3t|unset|kept"
    assert (tmp_path / "err").read_text().strip() == str(tmp_path)


async def test_a_signal_reaches_the_command(socket, approver, stdio):
    script = 'trap "exit 7" TERM; echo ready; while :; do sleep 0.05; done'
    read, write = os.pipe()
    try:
        with anyio.fail_after(DEADLINE):
            id, challenge = await request(
                socket, "database", [SH, "-c", script], cwd="/", requester=None, mode=ExecMode.BROKER, env={}
            )
            approve = {"op": "approve", "id": id, "signature": approver.sign(challenge)}
            async with await anyio.connect_unix(socket) as stream:
                await stream.send_fds(json.dumps(approve).encode() + b"\n", [stdio[0], write, write])
                os.close(write)
                write = -1
                # The trap is set once the command says so; a signal before it would kill sh outright.
                assert await anyio.to_thread.run_sync(os.read, read, 16) == b"ready\n"
                await stream.send(json.dumps({"signal": int(signal.SIGTERM)}).encode() + b"\n")
                answer = json.loads(await Lines(stream).next())
    finally:
        os.close(read)
        if write != -1:
            os.close(write)
    assert answer == {"ok": True, "exit": 7}


async def test_a_broker_run_on_a_terminal(socket, approver):
    "A person runs this on a terminal: the command sees one, though not as its controlling terminal."
    controller, terminal = os.openpty()
    try:
        with anyio.fail_after(DEADLINE):
            code = await run_in_broker(
                socket,
                "database",
                [SH, "-c", "test -t 0 && test -t 1 && echo on-a-tty"],
                signer(approver),
                cwd="/",
                requester=None,
                env={},
                environ={},
                announce=lambda line: None,
                stdio=(terminal, terminal, terminal),
            )
            seen = await anyio.to_thread.run_sync(os.read, controller, 64)
    finally:
        os.close(controller)
        os.close(terminal)
    assert code == 0
    assert b"on-a-tty" in seen


async def test_a_broker_run_needs_the_stdio(socket, approver):
    with anyio.fail_after(DEADLINE):
        id, challenge = await request(socket, "database", ARGV, cwd="/", requester=None, mode=ExecMode.BROKER, env={})
        answer = await ask(socket, {"op": "approve", "id": id, "signature": approver.sign(challenge)})
    assert answer["ok"] is False and "stdin, stdout and stderr" in str(answer["error"])
