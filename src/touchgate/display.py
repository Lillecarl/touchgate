"""
Shows a request where the person sees it, read from the broker's watch
and not from the requester: `touchgate show` prints one. The pymux
plugin (pymux_plugin.py) opens it in a popup in the requesting pane's
session.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import anyio

from .approval import ApprovalError, Outcome
from .broker import Lines
from .client import describe

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable
    from pathlib import Path


async def events(socket: Path) -> AsyncGenerator[dict[str, object]]:
    "The broker's watch, one event at a time, until the broker goes."
    async with await anyio.connect_unix(socket) as stream:
        await stream.send(json.dumps({"op": "watch"}).encode() + b"\n")
        lines = Lines(stream)
        while True:
            try:
                line = await lines.next()
            except anyio.EndOfStream:
                return
            yield json.loads(line)


async def show(socket: Path, id: str, out: Callable[[str], None]) -> Outcome | None:
    """
    Prints request `id` and then how it ends. Answers None when it expires
    unanswered, which the broker learns only at the next approve attempt.
    """
    seen = False
    with anyio.CancelScope() as scope:
        async for event in events(socket):
            kind, event_id = event.get("event"), event.get("id")
            if kind == "request" and event_id == id:
                fields = json.loads(str(event["challenge"]))
                out(describe(str(event["challenge"]).encode()))
                scope.deadline = anyio.current_time() + max(0, int(fields["expires"]) - time.time())
                seen = True
            elif kind == "listening" and not seen:
                raise ApprovalError("no request %r waits for a touch" % id)
            elif kind == "done" and event_id == id:
                outcome = Outcome(str(event["outcome"]))
                out("request %s: %s" % (id, outcome))
                return outcome
    if seen:
        out("request %s: expired" % id)
    return None
