"""
Grants: one touch approves a secret for a process tree, for a while.

A grant holds for the processes under one anchor process, named by pid
and start time. A request runs under a grant, with no touch, when the
anchor is one of its sender's parents and the request matches the
grant's item, variables and argv. A grant ends at its time limit, after
its last use, when the anchor exits, when the broker locks, or on revoke.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import processes
from .approval import ApprovalError, ExecMode

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from .approval import Anchor, Request
    from .processes import Process

#: The longest grant one touch gives.
MAX_SECONDS = 24 * 3600
MAX_GRANTS = 16

DURATION = re.compile(r"(\d+)([smhd])\Z")
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    "Seconds in `90s`, `30m`, `8h` or `1d`."
    match = DURATION.match(text.strip())
    if match is None:
        raise ApprovalError("%r is no duration such as 30m or 8h" % text)
    seconds = int(match[1]) * UNIT[match[2]]
    if not 0 < seconds <= MAX_SECONDS:
        raise ApprovalError("a grant lasts more than 0 seconds and at most %d hours" % (MAX_SECONDS // 3600))
    return seconds


def under(anchor: Anchor, chain: list[Process]) -> bool:
    "Whether the anchor is a parent in `chain`, the sender first."
    return processes.among(anchor.pid, anchor.start, chain[1:])


@dataclass(slots=True)
class Grant:
    id: str
    secret: str
    item_id: str
    #: The argv a run matches: the whole argv, or its first words when `prefix`.
    argv: tuple[str, ...]
    prefix: bool
    sources: Mapping[str, str]
    anchor: Anchor
    expires: int
    deadline: float
    #: Runs left. None: no count.
    uses: int | None

    def covers(self, request: Request, chain: list[Process]) -> bool:
        argv = request.argv[: len(self.argv)] if self.prefix else request.argv
        return (
            request.grant is None
            and request.mode is ExecMode.BROKER
            and request.item_id == self.item_id
            and dict(request.sources) == dict(self.sources)
            and argv == self.argv
            and under(self.anchor, chain)
        )

    def live(self, reader: Callable[[int], Process | None] = processes.read) -> bool:
        return (
            time.monotonic() <= self.deadline
            and self.uses != 0
            and processes.alive(self.anchor.pid, self.anchor.start, reader)
        )

    def described(self) -> dict[str, object]:
        return {
            "id": self.id,
            "secret": self.secret,
            "item": self.item_id,
            "argv": list(self.argv),
            "prefix": self.prefix,
            "variables": dict(self.sources),
            "anchor": {"pid": self.anchor.pid, "name": self.anchor.name, "cwd": self.anchor.cwd},
            "expires": self.expires,
            "uses": self.uses,
        }


class Grants:
    def __init__(self, reader: Callable[[int], Process | None] = processes.read) -> None:
        self.held: dict[str, Grant] = {}
        self.reader = reader

    def add(self, request: Request) -> Grant:
        "The grant a request asked for, once its signature verifies."
        terms = request.grant
        if terms is None:
            raise ApprovalError("request %r asks for no grant" % request.id)
        self._prune()
        if len(self.held) >= MAX_GRANTS:
            raise ApprovalError("%d grants already hold; revoke one" % MAX_GRANTS)
        grant = Grant(
            id=secrets.token_hex(8),
            secret=request.secret,
            item_id=request.item_id,
            argv=request.argv if terms.prefix is None else request.argv[: terms.prefix],
            prefix=terms.prefix is not None,
            sources=dict(request.sources),
            anchor=terms.anchor,
            expires=int(time.time()) + terms.seconds,
            deadline=time.monotonic() + terms.seconds,
            uses=terms.uses,
        )
        self.held[grant.id] = grant
        return grant

    def find(self, request: Request, chain: list[Process]) -> Grant | None:
        self._prune()
        return next((grant for grant in self.held.values() if grant.covers(request, chain)), None)

    def use(self, id: str, request: Request, chain: list[Process]) -> Grant:
        "The grant `id`, one use spent, if it still holds and covers `request`."
        self._prune()
        grant = self.held.get(id)
        if grant is None or not grant.covers(request, chain):
            raise ApprovalError("grant %s ended" % id)
        if grant.uses is not None:
            grant.uses -= 1
        return grant

    def revoke(self, id: str | None) -> list[str]:
        "Ends grant `id`, or every grant for None, and answers which ended."
        ended = list(self.held) if id is None else [id] if id in self.held else []
        for each in ended:
            del self.held[each]
        return ended

    def clear(self) -> None:
        self.held.clear()

    def listed(self) -> list[dict[str, object]]:
        self._prune()
        return [grant.described() for grant in self.held.values()]

    def _prune(self) -> None:
        for id in [id for id, grant in self.held.items() if not grant.live(self.reader)]:
            del self.held[id]
