"""
The pymux plugin against a stand-in for `pymux.plugin_api`: pymux is not
in this environment. It checks touchgate's side of the contract: the
commands it sends, the pane it names, what it asks a linked server and
what it answers one. The real server is a live test.
"""

from __future__ import annotations

import importlib
import json
import logging
import shlex
import sys
import types
from collections.abc import Callable
from dataclasses import dataclass

import anyio
import anyio.abc
import pytest

from approving import ARGV, DEADLINE, PASSWORD
from touchgate import config
from touchgate.approval import ExecMode
from touchgate.broker import ask
from touchgate.client import approved_env, request

SERVER = "/run/user/1000/pymux-1000/pymux.sock.test.0"


class _Plugin:
    def __init__(self, host) -> None:
        self.host = host


class _PeerUnanswered(LookupError):
    pass


@dataclass(frozen=True)
class _PeerMessage:
    peer: str
    dialled: bool
    data: object


@dataclass
class _Result:
    ok: bool = True
    stderr: str = ""


class _Host:
    "Records each command, and answers `ask_peer` with `answer(data)`."

    def __init__(
        self,
        socket_name: str | None,
        tasks: anyio.abc.TaskGroup | None = None,
        answer: Callable[[dict[str, object]], dict[str, object]] | None = None,
    ) -> None:
        self.pymux = types.SimpleNamespace(socket_name=socket_name)
        self.log = logging.getLogger("test.plugin")
        self.commands: list[tuple[str, int | None]] = []
        self.asked: list[dict[str, object]] = []
        self.commanded = anyio.Event()
        self._tasks = tasks
        self._answer = answer

    async def command(self, command: str, pane_id: int | None = None) -> _Result:
        self.commands.append((command, pane_id))
        self.commanded.set()
        return _Result()

    def start_soon(self, func, *args) -> None:
        assert self._tasks is not None
        self._tasks.start_soon(func, *args)

    def peers(self) -> list[str]:
        return ["without", "mac"]

    async def ask_peer(self, peer: str, data: object, timeout: float) -> object:
        if peer == "without":
            raise _PeerUnanswered("without: it runs no plugin touchgate")
        assert self._answer is not None and isinstance(data, dict)
        self.asked.append(data)
        return self._answer(data)


@pytest.fixture
def glue(monkeypatch):
    api = types.ModuleType("pymux.plugin_api")
    api.Plugin = _Plugin  # pyrefly: ignore[missing-attribute]
    api.PeerUnanswered = _PeerUnanswered  # pyrefly: ignore[missing-attribute]
    api.PeerMessage = _PeerMessage  # pyrefly: ignore[missing-attribute]
    monkeypatch.setitem(sys.modules, "pymux", types.ModuleType("pymux"))
    monkeypatch.setitem(sys.modules, "pymux.plugin_api", api)
    monkeypatch.delitem(sys.modules, "touchgate.pymux_plugin", raising=False)
    return importlib.import_module("touchgate.pymux_plugin")


def _until_done(plugin) -> anyio.Event:
    """
    Set once the plugin has read the broker's `done` event. A test that
    cancels the plugin while that event arrives meets a race in anyio
    4.15.1: the read's future is cancelled, then its reader callback sets it.
    """
    done = anyio.Event()
    event_of = plugin._event

    async def recording(socket, event) -> None:
        await event_of(socket, event)
        if event.get("event") == "done":
            done.set()

    plugin._event = recording
    return done


@pytest.fixture
def fresh(broker, socket, monkeypatch):
    "The module shares one broker, and its watch replays what still waits there."
    broker.requests.clear()
    monkeypatch.setenv("TOUCHGATE_SOCKET", str(socket))
    return socket


async def test_the_plugin_asks_pymux_for_a_popup_in_the_requesting_pane(glue, fresh):
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            host = _Host(SERVER, tasks)
            tasks.start_soon(glue.plugin(host).run)
            id, _ = await request(
                fresh, "database", ARGV, cwd="/", requester="%s,9" % SERVER, mode=ExecMode.CLIENT, env={}
            )
            await host.commanded.wait()
            tasks.cancel_scope.cancel()
    [(command, pane)] = host.commands
    assert shlex.split(command)[:7] == ["display-popup", "-T", "touchgate approval", "-w", "100", "-h", "16"]
    assert shlex.split(command)[-2:] == ["show", id]
    assert pane == 9
    assert host.asked == []


async def test_only_its_own_panes_get_a_popup(glue, fresh):
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            host = _Host(SERVER, tasks)
            tasks.start_soon(glue.plugin(host).run)
            for requester in ("/elsewhere.sock,4", None):
                await request(fresh, "database", ARGV, cwd="/", requester=requester, mode=ExecMode.CLIENT, env={})
            ours, _ = await request(
                fresh, "database", ARGV, cwd="/", requester="%s,7" % SERVER, mode=ExecMode.CLIENT, env={}
            )
            await host.commanded.wait()
            tasks.cancel_scope.cancel()
    assert [(shlex.split(command)[-1], pane) for command, pane in host.commands] == [(ours, 7)]


async def test_a_linked_server_signs_a_request_approved_elsewhere(glue, fresh, approver):
    def sign(data: dict[str, object]) -> dict[str, object]:
        return {"signature": approver.sign(str(data["challenge"]).encode())}

    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            host = _Host(SERVER, tasks, sign)
            plugin = glue.plugin(host)
            done = _until_done(plugin)
            tasks.start_soon(plugin.run)
            values = await approved_env(
                fresh, "database", ARGV, None, cwd="/srv", requester=None, env={}, announce=lambda line: None
            )
            await done.wait()
            tasks.cancel_scope.cancel()
    assert values == {"API_TOKEN": "t0ken"}
    [asked] = host.asked
    assert asked["op"] == "sign" and json.loads(str(asked["challenge"]))["argv"] == ARGV


async def test_a_linked_server_unlocks_a_broker_a_request_waits_on(glue, fresh, broker, approver):
    def answer(data: dict[str, object]) -> dict[str, object]:
        if data["op"] == "unlock":
            return {"password": PASSWORD}
        return {"signature": approver.sign(str(data["challenge"]).encode())}

    with anyio.fail_after(DEADLINE):
        await ask(fresh, {"op": "lock"})
        try:
            async with anyio.create_task_group() as tasks:
                host = _Host(SERVER, tasks, answer)
                plugin = glue.plugin(host)
                done = _until_done(plugin)
                tasks.start_soon(plugin.run)
                values = await approved_env(
                    fresh, "database", ARGV, None, cwd="/srv", requester=None, env={}, announce=lambda line: None
                )
                await done.wait()
                tasks.cancel_scope.cancel()
        finally:
            await broker.unlock(PASSWORD)
    assert values == {"API_TOKEN": "t0ken"}
    assert [data["op"] for data in host.asked] == ["unlock", "sign"]


async def test_the_key_side_answers_only_a_server_it_dialled(glue):
    plugin = glue.plugin(_Host(SERVER))
    with anyio.fail_after(DEADLINE), pytest.raises(glue.Refused, match="dialled"):
        await plugin.on_peer_message(_PeerMessage("dynhetz", False, {"op": "unlock"}))
    with anyio.fail_after(DEADLINE), pytest.raises(glue.Refused, match="nothing else"):
        await plugin.on_peer_message(_PeerMessage("ssh://dynhetz", True, {"op": "run"}))


@pytest.mark.parametrize(
    ("reply", "expected"),
    [({"signature": "SSHSIG"}, {"signature": "SSHSIG"}), ({"error": "no key"}, "no key"), (None, "no answer")],
    ids=["answers", "refuses", "closes"],
)
async def test_the_key_side_answers_through_its_popup(glue, reply, expected):
    "The popup is `touchgate popup`: it reads the question and writes one answer."
    heard: list[dict[str, object]] = []
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:

            async def open_popup(path) -> None:
                async def answer() -> None:
                    async with await anyio.connect_unix(path) as stream:
                        heard.append(json.loads(await stream.receive()))
                        if reply is not None:
                            await stream.send(json.dumps(reply).encode() + b"\n")

                tasks.start_soon(answer)

            asked = glue.answered_in_popup("ssh://dynhetz", {"op": "sign", "challenge": "{}"}, open_popup)
            if isinstance(expected, dict):
                assert await asked == expected
            else:
                with pytest.raises(glue.Refused, match=expected):
                    await asked
    assert heard == [{"op": "sign", "challenge": "{}", "peer": "ssh://dynhetz"}]


def test_requester_panes(glue):
    assert glue.requester_pane("%s,12" % SERVER, SERVER) == 12
    assert glue.requester_pane("/other,12", SERVER) is None
    assert glue.requester_pane("%s,x" % SERVER, SERVER) is None
    assert glue.requester_pane(None, SERVER) is None


def test_the_plugin_finds_the_socket_as_touchgate_does(glue):
    for environ in ({"TOUCHGATE_SOCKET": "/x.sock"}, {"XDG_RUNTIME_DIR": "/run/user/7"}):
        assert glue.socket_path(environ) == config.socket_path(environ)
    assert glue.socket_path({}) is None


async def test_a_server_without_a_broker_socket_follows_nothing(glue, monkeypatch):
    monkeypatch.delenv("TOUCHGATE_SOCKET", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    host = _Host(SERVER)
    with anyio.fail_after(DEADLINE):
        await glue.plugin(host).run()
    assert host.commands == []
