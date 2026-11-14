"""
Requests that wait for a touch.

A request names a vault item, the exact command and who asks. The
broker turns it into a challenge, keeps the challenge bytes, and
releases the item's values only for a security key signature over
those bytes from a key the vault lists. A request is used once: the
first approve attempt removes it, pass or fail.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from .sshsig import BadSignature, SkPublicKey

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .vault import Item, Secret, Vault

log = logging.getLogger(__name__)

#: The SSHSIG namespace: a signature for git or for a file never approves a run.
NAMESPACE = "touchgate"
#: The vault item whose notes list the approver keys, one OpenSSH public key per line.
#: It lives in the vault because a local agent cannot write there.
APPROVERS_ITEM = "touchgate-approvers"
#: Seconds a request waits for its touch.
LIFETIME = 120
MAX_PENDING = 8

ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ApprovalError(Exception):
    pass


class ExecMode(StrEnum):
    #: The broker starts the command, so the values reach only the approved argv.
    BROKER = "broker"
    #: The client gets the values and starts the command: the argv is its claim.
    CLIENT = "client"


class Source(StrEnum):
    USERNAME = "username"
    PASSWORD = "password"
    NOTES = "notes"


def approvers(vault: Vault) -> tuple[SkPublicKey, ...]:
    try:
        item = vault.find(APPROVERS_ITEM)
    except KeyError:
        log.warning("the vault has no %r item, so no request can be approved", APPROVERS_ITEM)
        return ()
    keys = []
    for number, line in enumerate((item.notes.value if item.notes else "").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            keys.append(SkPublicKey.from_line(line))
        except BadSignature as error:
            log.warning("%s line %d is no approver: %s", APPROVERS_ITEM, number, error)
    return tuple(keys)


def variables(item: Item, explicit: Mapping[str, str]) -> dict[str, Secret]:
    """
    Every custom field whose name is a variable name, plus each
    `NAME: source` in `explicit`, where a source is `username`,
    `password`, `notes` or a field name.
    """
    values = {name: value for name, value in item.fields.items() if ENV_NAME.match(name)}
    for name, source in explicit.items():
        if not ENV_NAME.match(name):
            raise ApprovalError("%r is not a variable name" % name)
        match source:
            case Source.USERNAME:
                value = item.username
            case Source.PASSWORD:
                value = item.password
            case Source.NOTES:
                value = item.notes
            case _:
                value = item.fields.get(source)
        if value is None:
            raise ApprovalError("%r has no %s" % (item.name, source))
        values[name] = value
    return values


@dataclass(frozen=True, slots=True)
class Request:
    id: str
    secret: str
    item_id: str
    argv: tuple[str, ...]
    cwd: str
    requester: str | None
    mode: ExecMode
    explicit: Mapping[str, str]
    names: tuple[str, ...]
    expires: int
    deadline: float = field(repr=False)
    challenge: bytes = field(repr=False)


def challenge(
    id: str,
    nonce: str,
    expires: int,
    secret: str,
    item_id: str,
    argv: tuple[str, ...],
    cwd: str,
    requester: str | None,
    mode: ExecMode,
    names: tuple[str, ...],
) -> bytes:
    "What the person signs. Canonical JSON, so the same request is the same bytes."
    return json.dumps(
        {
            "touchgate": 1,
            "id": id,
            "nonce": nonce,
            "expires": expires,
            "secret": secret,
            "item": item_id,
            "argv": list(argv),
            "cwd": cwd,
            "requester": requester,
            "exec": mode,
            "variables": list(names),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


class Requests:
    def __init__(self) -> None:
        self.pending: dict[str, Request] = {}

    def add(
        self,
        vault: Vault,
        secret: str,
        argv: tuple[str, ...],
        cwd: str,
        requester: str | None,
        mode: ExecMode,
        explicit: Mapping[str, str],
    ) -> Request:
        self._expire()
        if len(self.pending) >= MAX_PENDING:
            raise ApprovalError("%d requests already wait for a touch" % MAX_PENDING)
        if not argv:
            raise ApprovalError("a request names a command")
        try:
            item = vault.find(secret)
        except KeyError as error:
            raise ApprovalError(str(error.args[0])) from None
        if item.name == APPROVERS_ITEM:
            raise ApprovalError("the approver list is not a secret to hand out")
        names = tuple(sorted(variables(item, explicit)))
        id, nonce = secrets.token_hex(8), secrets.token_hex(16)
        expires = int(time.time()) + LIFETIME
        request = Request(
            id=id,
            secret=secret,
            item_id=item.id,
            argv=argv,
            cwd=cwd,
            requester=requester,
            mode=mode,
            explicit=dict(explicit),
            names=names,
            expires=expires,
            deadline=time.monotonic() + LIFETIME,
            challenge=challenge(id, nonce, expires, secret, item.id, argv, cwd, requester, mode, names),
        )
        self.pending[id] = request
        return request

    def take(self, id: str) -> Request:
        "The request, removed: whatever the approve attempt does next, it does it once."
        request = self.pending.pop(id, None)
        if request is None:
            raise ApprovalError("no request %r waits for a touch" % id)
        if time.monotonic() > request.deadline:
            raise ApprovalError("request %r expired" % id)
        return request

    def clear(self) -> None:
        self.pending.clear()

    def _expire(self) -> None:
        now = time.monotonic()
        for id in [id for id, request in self.pending.items() if now > request.deadline]:
            del self.pending[id]
