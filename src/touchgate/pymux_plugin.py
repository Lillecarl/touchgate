"""
The pymux plugin. It has two jobs, and every pymux server with it does
whichever its machine allows.

Where the broker runs, it follows the broker's requests. It opens a
popup in the requesting pane's session for each one. For a request
approved elsewhere, it asks the touchgate plugin on each linked pymux
server in turn to sign it, and passes the signature to the broker. A
locked broker that such a request waits on, it asks the same way to
unlock.

Where the security key is plugged in, it answers those questions, and
only from a server this pymux dialled. Each question opens a popup that
shows what is asked and waits for the touch (`touchgate popup`).

It imports nothing of touchgate, only the standard library, anyio and
pymux, so pymux loads it as a file plugin without touchgate in its
environment: link this file to `$XDG_CONFIG_HOME/pymux/plugins/touchgate.py`.
The popups run `touchgate` from PATH.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from pathlib import Path

import anyio
import anyio.abc
from pymux.plugin_api import PeerMessage, PeerUnanswered, Plugin

#: Seconds between attempts to reach a broker that is not running.
RETRY = 5
#: Seconds a linked server has to answer: a request's lifetime at the broker.
ANSWER_SECONDS = 120
POPUP_TITLE = "touchgate approval"


class Refused(Exception):
    "The machine with the key did not answer what a linked server asked."


def socket_path(environ: Mapping[str, str] = os.environ) -> Path | None:
    "The broker's socket, as touchgate's own configuration finds it."
    if environ.get("TOUCHGATE_SOCKET"):
        return Path(environ["TOUCHGATE_SOCKET"])
    if environ.get("XDG_RUNTIME_DIR"):
        return Path(environ["XDG_RUNTIME_DIR"]) / "touchgate" / "broker.sock"
    return None


class _Lines:
    "Newline-ended messages off a stream."

    def __init__(self, stream: anyio.abc.ByteReceiveStream) -> None:
        self.stream = stream
        self.buffer = b""

    async def next(self) -> bytes | None:
        "The next message, or None once the stream ends."
        while b"\n" not in self.buffer:
            try:
                self.buffer += await self.stream.receive()
            except anyio.EndOfStream:
                return None
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line


async def events(socket: Path) -> AsyncGenerator[dict[str, object]]:
    "The broker's watch, one event at a time, until the broker goes."
    async with await anyio.connect_unix(socket) as stream:
        await stream.send(b'{"op": "watch"}\n')
        lines = _Lines(stream)
        while (line := await lines.next()) is not None:
            yield json.loads(line)


async def broker_ask(socket: Path, request: dict[str, object]) -> dict[str, object]:
    "One request to the broker, and its answer."
    async with await anyio.connect_unix(socket) as stream:
        await stream.send(json.dumps(request).encode() + b"\n")
        line = await _Lines(stream).next()
    if line is None:
        return {"ok": False, "error": "the broker closed the connection"}
    return json.loads(line)


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


def answer_popup(peer: str, socket: Path, touchgate: str = "touchgate") -> list[str]:
    "The pymux command that answers what `peer` asks, over `socket`."
    return [
        "display-popup",
        "-T",
        "touchgate: %s asks" % peer,
        "-w",
        "100",
        "-h",
        "20",
        touchgate,
        "popup",
        str(socket),
    ]


async def follow(
    socket: Path,
    handle: Callable[[dict[str, object]], Awaitable[None]],
    *,
    retry: float = RETRY,
) -> None:
    "Hands each of the broker's events to `handle`. Runs until cancelled."
    while True:
        with contextlib.suppress(OSError, anyio.BrokenResourceError):
            async for event in events(socket):
                await handle(event)
        # A broker that starts announces nothing, so the plugin asks again.
        await anyio.sleep(retry)


async def answered_in_popup(
    peer: str,
    asked: dict[str, object],
    open_popup: Callable[[Path], Awaitable[None]],
    *,
    timeout: float = ANSWER_SECONDS,
) -> dict[str, object]:
    """
    What the popup answers to `asked`. The plugin listens on a socket in a
    directory only this user reads, and the popup connects to it.
    """
    line: bytes | None = None
    with tempfile.TemporaryDirectory(prefix="touchgate-") as directory:
        path = Path(directory) / "popup.sock"
        async with await anyio.create_unix_listener(path) as listener:
            await open_popup(path)
            with anyio.fail_after(timeout):
                async with await listener.accept() as stream:
                    await stream.send(json.dumps(asked | {"peer": peer}).encode() + b"\n")
                    line = await _Lines(stream).next()
    if line is None:
        raise Refused("the popup closed with no answer")
    answer = json.loads(line)
    if not isinstance(answer, dict) or "error" in answer:
        raise Refused(str(answer.get("error") if isinstance(answer, dict) else answer))
    return answer


class Touchgate(Plugin):
    def __init__(self, host) -> None:
        super().__init__(host)
        self._unlocking = False

    async def run(self) -> None:
        socket = socket_path()
        if socket is None:
            self.host.log.info("no socket for touchgate, so this server follows no broker")
            return

        async def handle(event: dict[str, object]) -> None:
            await self._event(socket, event)

        await follow(socket, handle)

    async def _event(self, socket: Path, event: dict[str, object]) -> None:
        match event.get("event"):
            case "request":
                id = str(event["id"])
                challenge = str(event["challenge"])
                socket_name = self.host.pymux.socket_name
                pane = (
                    None if socket_name is None else requester_pane(json.loads(challenge).get("requester"), socket_name)
                )
                if pane is not None:
                    await self._open(id, pane)
                if event.get("elsewhere"):
                    self.host.start_soon(self._sign_elsewhere, socket, id, challenge)
            case "locked" if not self._unlocking:
                self._unlocking = True
                self.host.start_soon(self._unlock_elsewhere, socket)

    async def _open(self, id: str, pane: int) -> None:
        command = popup(id, shutil.which("touchgate") or "touchgate")
        result = await self.host.command(shlex.join(command), pane_id=pane)
        if not result.ok:
            self.host.log.warning("no popup for request %s: %s", id, result.stderr)

    async def _ask_linked(self, asked: dict[str, object]) -> dict[str, object] | None:
        "The first answer of a linked server's touchgate plugin, asked one after another."
        for peer in self.host.peers():
            try:
                answer = await self.host.ask_peer(peer, asked, ANSWER_SECONDS)
            except PeerUnanswered as why:
                self.host.log.info("touchgate: %s", why)
                continue
            if isinstance(answer, dict):
                return answer
        self.host.log.warning("no linked server answered touchgate's %s", asked.get("op"))
        return None

    async def _sign_elsewhere(self, socket: Path, id: str, challenge: str) -> None:
        answer = await self._ask_linked({"op": "sign", "challenge": challenge})
        if answer is None:
            return
        reply = await broker_ask(socket, {"op": "signed", "id": id, "signature": answer.get("signature")})
        if not reply.get("ok"):
            self.host.log.warning("the broker refused the signature for %s: %s", id, reply.get("error"))

    async def _unlock_elsewhere(self, socket: Path) -> None:
        try:
            answer = await self._ask_linked({"op": "unlock"})
            if answer is None:
                return
            reply = await broker_ask(socket, {"op": "unlock", "password": answer.get("password")})
            if not reply.get("ok"):
                self.host.log.warning("the broker refused the unlock: %s", reply.get("error"))
        finally:
            self._unlocking = False

    async def on_peer_message(self, message: PeerMessage) -> object:
        # Any server linked to this one can send a message. Only one this
        # pymux dialled is a server the person here chose.
        if not message.dialled:
            raise Refused("touchgate answers only a server this pymux dialled")
        if not isinstance(message.data, dict) or message.data.get("op") not in ("sign", "unlock"):
            raise Refused("touchgate signs and unlocks, and nothing else")
        peer = message.peer

        async def open_popup(socket: Path) -> None:
            command = answer_popup(peer, socket, shutil.which("touchgate") or "touchgate")
            result = await self.host.command(shlex.join(command))
            if not result.ok:
                raise Refused("no popup to ask the person: %s" % result.stderr)

        return await answered_in_popup(peer, message.data, open_popup)


plugin = Touchgate
