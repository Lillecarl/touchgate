"""
The pymux plugin: a popup in the requesting pane's session for each
touchgate request, showing what the broker holds.

It imports nothing of touchgate, only the standard library, anyio and
pymux, so pymux loads it as a file plugin without touchgate in its
environment: link this file to `$XDG_CONFIG_HOME/pymux/plugins/touchgate.py`.
The popup runs `touchgate show` from PATH.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from pathlib import Path

import anyio
from pymux.plugin_api import Plugin

#: Seconds between attempts to reach a broker that is not running.
RETRY = 5
POPUP_TITLE = "touchgate approval"


def socket_path(environ: Mapping[str, str] = os.environ) -> Path | None:
    "The broker's socket, as touchgate's own configuration finds it."
    if environ.get("TOUCHGATE_SOCKET"):
        return Path(environ["TOUCHGATE_SOCKET"])
    if environ.get("XDG_RUNTIME_DIR"):
        return Path(environ["XDG_RUNTIME_DIR"]) / "touchgate" / "broker.sock"
    return None


async def events(socket: Path) -> AsyncGenerator[dict[str, object]]:
    "The broker's watch, one event at a time, until the broker goes."
    async with await anyio.connect_unix(socket) as stream:
        await stream.send(b'{"op": "watch"}\n')
        buffer = b""
        while True:
            while b"\n" not in buffer:
                try:
                    buffer += await stream.receive()
                except anyio.EndOfStream:
                    return
            line, _, buffer = buffer.partition(b"\n")
            yield json.loads(line)


def requester_pane(requester: object, socket_name: str) -> int | None:
    "The pane in `$PYMUX` (`socket,pane`) when it belongs to the server at `socket_name`."
    if not isinstance(requester, str):
        return None
    socket, _, pane = requester.rpartition(",")
    if socket != socket_name or not pane.isdigit():
        return None
    return int(pane)


def popup(id: str, touchgate: str = "touchgate") -> list[str]:
    "The pymux command that shows request `id`."
    return ["display-popup", "-T", POPUP_TITLE, "-w", "100", "-h", "16", touchgate, "show", id]


async def follow(
    socket: Path,
    socket_name: str,
    open_popup: Callable[[str, int], Awaitable[None]],
    *,
    retry: float = RETRY,
) -> None:
    "Opens a popup for each request from a pane of the server at `socket_name`. Runs until cancelled."
    while True:
        with contextlib.suppress(OSError, anyio.BrokenResourceError):
            async for event in events(socket):
                if event.get("event") != "request":
                    continue
                challenge = json.loads(str(event["challenge"]))
                pane = requester_pane(challenge.get("requester"), socket_name)
                if pane is not None:
                    await open_popup(str(event["id"]), pane)
        # A broker that starts announces nothing, so the plugin asks again.
        await anyio.sleep(retry)


class Touchgate(Plugin):
    async def run(self) -> None:
        socket_name = self.host.pymux.socket_name
        socket = socket_path()
        if socket_name is None or socket is None:
            self.host.log.info("no socket for pymux or for touchgate, so no pane can ask touchgate")
            return
        await follow(socket, socket_name, self._open)

    async def _open(self, id: str, pane: int) -> None:
        command = popup(id, shutil.which("touchgate") or "touchgate")
        result = await self.host.command(shlex.join(command), pane_id=pane)
        if not result.ok:
            self.host.log.warning("no popup for request %s: %s", id, result.stderr)


plugin = Touchgate
