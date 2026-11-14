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
import os
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
#: The namespace for a challenge that also asks for a grant. A signer that cannot show a
#: grant signs under NAMESPACE, and the broker refuses that signature for a grant.
GRANT_NAMESPACE = "touchgate-grant"
#: The vault item whose notes list the approver keys, one OpenSSH public key per line.
#: It lives in the vault because a local agent cannot write there.
APPROVERS_ITEM = "touchgate-approvers"
#: Seconds a request waits for its touch.
LIFETIME = 120
MAX_PENDING = 8

ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ApprovalError(Exception):
    pass


class Expired(ApprovalError):
    pass


class Outcome(StrEnum):
    APPROVED = "approved"
    REFUSED = "refused"
    EXPIRED = "expired"
    LOCKED = "locked"


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


def sources(item: Item, explicit: Mapping[str, str]) -> dict[str, str]:
    """
    Each variable and where its value comes from: every custom field whose
    name is a variable name, plus each `NAME: source` in `explicit`, where
    a source is `username`, `password`, `notes` or a field name.
    """
    chosen = {name: name for name in item.fields if ENV_NAME.match(name)}
    for name, source in explicit.items():
        if not ENV_NAME.match(name):
            raise ApprovalError("%r is not a variable name" % name)
        _value(item, source)
        chosen[name] = source
    return chosen


def variables(item: Item, explicit: Mapping[str, str]) -> dict[str, Secret]:
    return {name: _value(item, source) for name, source in sources(item, explicit).items()}


def _value(item: Item, source: str) -> Secret:
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
    return value


@dataclass(frozen=True, slots=True)
class Anchor:
    "The process a grant holds for, and every process under it. The broker reads each fact from /proc."

    pid: int
    start: int
    name: str
    cwd: str


@dataclass(frozen=True, slots=True)
class GrantTerms:
    "What one touch approves beyond the run it signs."

    seconds: int
    #: Runs the grant allows. None: any number, until it ends otherwise.
    uses: int | None
    #: How many argv words a run must match. None: the whole argv.
    prefix: int | None
    anchor: Anchor

    def described(self) -> dict[str, object]:
        return {
            "seconds": self.seconds,
            "uses": self.uses,
            "prefix": self.prefix,
            "anchor": {
                "pid": self.anchor.pid,
                "start": self.anchor.start,
                "name": self.anchor.name,
                "cwd": self.anchor.cwd,
            },
        }


def namespace_of(challenge: bytes) -> str:
    "The namespace a challenge is signed under. It comes from the bytes signed, never from who asks."
    return GRANT_NAMESPACE if "grant" in json.loads(challenge) else NAMESPACE


@dataclass(frozen=True, slots=True)
class Peer:
    "The process that sent a request, by pid and start time."

    pid: int
    start: int


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
    sources: Mapping[str, str]
    expires: int
    deadline: float = field(repr=False)
    challenge: bytes = field(repr=False)
    #: The client does not sign: it waits for a signature someone else delivers (`Signed`).
    elsewhere: bool = False
    #: The grant this request asks for, signed with it.
    grant: GrantTerms | None = None
    #: The grant this request runs under, with no touch: only its sender may approve it.
    granted: str | None = None
    sender: Peer | None = None


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
    sources: Mapping[str, str],
    grant: GrantTerms | None = None,
) -> bytes:
    "What the person signs. Canonical JSON, so the same request is the same bytes."
    fields: dict[str, object] = {
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
        "variables": dict(sources),
    }
    if grant is not None:
        fields["grant"] = grant.described()
    return json.dumps(
        fields,
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
        elsewhere: bool = False,
        grant: GrantTerms | None = None,
    ) -> Request:
        self._expire()
        if grant is not None and mode is not ExecMode.BROKER:
            raise ApprovalError("a grant runs its commands in the broker, never in the client")
        if len(self.pending) >= MAX_PENDING:
            raise ApprovalError("%d requests already wait for a touch" % MAX_PENDING)
        if not argv:
            raise ApprovalError("a request names a command")
        # A bare name would be looked up on a PATH the client chooses, after the touch.
        if not os.path.isabs(argv[0]) or not os.path.isabs(cwd):
            raise ApprovalError("a request names its command and directory by absolute path")
        try:
            item = vault.find(secret)
        except KeyError as error:
            raise ApprovalError(str(error.args[0])) from None
        if item.name == APPROVERS_ITEM:
            raise ApprovalError("the approver list is not a secret to hand out")
        chosen = dict(sorted(sources(item, explicit).items()))
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
            sources=chosen,
            expires=expires,
            deadline=time.monotonic() + LIFETIME,
            challenge=challenge(id, nonce, expires, secret, item.id, argv, cwd, requester, mode, chosen, grant),
            elsewhere=elsewhere,
            grant=grant,
        )
        self.pending[id] = request
        return request

    def take(self, id: str) -> Request:
        "The request, removed: whatever the approve attempt does next, it does it once."
        request = self.pending.pop(id, None)
        if request is None:
            raise ApprovalError("no request %r waits for a touch" % id)
        if time.monotonic() > request.deadline:
            raise Expired("request %r expired" % id)
        return request

    def clear(self) -> None:
        self.pending.clear()

    def _expire(self) -> None:
        now = time.monotonic()
        for id in [id for id, request in self.pending.items() if now > request.deadline]:
            del self.pending[id]
