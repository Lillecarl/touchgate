"""
The pymux plugin against a stand-in for `pymux.plugin_api`: pymux is not
in this environment. It checks touchgate's side of the contract, the
command it sends and the pane it names; the real server is a live test.
"""

from __future__ import annotations

import importlib
import logging
import shlex
import sys
import types
from dataclasses import dataclass

import anyio
import pytest

from approving import ARGV, DEADLINE
from touchgate import config
from touchgate.approval import ExecMode
from touchgate.client import request

SERVER = "/run/user/1000/pymux-1000/pymux.sock.test.0"


class _Plugin:
    def __init__(self, host) -> None:
        self.host = host


@dataclass
class _Result:
    ok: bool = True
    stderr: str = ""


class _Host:
    def __init__(self, socket_name: str | None, done: anyio.Event) -> None:
        self.pymux = types.SimpleNamespace(socket_name=socket_name)
        self.log = logging.getLogger("test.plugin")
        self.commands: list[tuple[str, int]] = []
        self.done = done

    async def command(self, command: str, pane_id: int | None = None) -> _Result:
        assert pane_id is not None
        self.commands.append((command, pane_id))
        self.done.set()
        return _Result()


@pytest.fixture
def glue(monkeypatch):
    api = types.ModuleType("pymux.plugin_api")
    api.Plugin = _Plugin  # pyrefly: ignore[missing-attribute]
    monkeypatch.setitem(sys.modules, "pymux", types.ModuleType("pymux"))
    monkeypatch.setitem(sys.modules, "pymux.plugin_api", api)
    monkeypatch.delitem(sys.modules, "touchgate.pymux_plugin", raising=False)
    return importlib.import_module("touchgate.pymux_plugin")


async def test_the_plugin_asks_pymux_for_a_popup_in_the_requesting_pane(glue, socket, monkeypatch):
    monkeypatch.setenv("TOUCHGATE_SOCKET", str(socket))
    done = anyio.Event()
    host = _Host(SERVER, done)
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(glue.plugin(host).run)
            id, _ = await request(
                socket, "database", ARGV, cwd="/", requester="%s,9" % SERVER, mode=ExecMode.CLIENT, env={}
            )
            await done.wait()
            tasks.cancel_scope.cancel()
    [(command, pane)] = host.commands
    assert shlex.split(command)[:7] == ["display-popup", "-T", "touchgate approval", "-w", "100", "-h", "16"]
    assert shlex.split(command)[-2:] == ["show", id]
    assert pane == 9


async def test_follow_opens_a_popup_for_its_own_panes_only(glue, broker, socket):
    # The module shares one broker, and the watch replays what still waits there.
    broker.requests.clear()
    opened: list[tuple[str, int]] = []
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:

            async def open_popup(id: str, pane: int) -> None:
                opened.append((id, pane))
                tasks.cancel_scope.cancel()

            tasks.start_soon(glue.follow, socket, SERVER, open_popup)
            for requester in ("/elsewhere.sock,4", None):
                await request(socket, "database", ARGV, cwd="/", requester=requester, mode=ExecMode.CLIENT, env={})
            ours, _ = await request(
                socket, "database", ARGV, cwd="/", requester="%s,7" % SERVER, mode=ExecMode.CLIENT, env={}
            )
    assert opened == [(ours, 7)]


def test_requester_panes(glue):
    assert glue.requester_pane("%s,12" % SERVER, SERVER) == 12
    assert glue.requester_pane("/other,12", SERVER) is None
    assert glue.requester_pane("%s,x" % SERVER, SERVER) is None
    assert glue.requester_pane(None, SERVER) is None


def test_the_plugin_finds_the_socket_as_touchgate_does(glue):
    for environ in ({"TOUCHGATE_SOCKET": "/x.sock"}, {"XDG_RUNTIME_DIR": "/run/user/7"}):
        assert glue.socket_path(environ) == config.socket_path(environ)
    assert glue.socket_path({}) is None


async def test_a_server_without_a_socket_shows_nothing(glue):
    host = _Host(None, anyio.Event())
    with anyio.fail_after(DEADLINE):
        await glue.plugin(host).run()
    assert host.commands == []
