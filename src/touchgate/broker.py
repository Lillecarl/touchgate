"""
The broker: a user service that holds the unlocked vault in memory and
answers on a unix socket, one JSON request per connection.

The socket's directory is private to the user. Every process of the user
can still connect, agents included, so nothing the socket answers may
give a secret away without an approval the broker verifies itself.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import logging
import os
import signal
import sys
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Annotated, Literal

import anyio
import anyio.abc
from anyio.abc import SocketAttribute, UNIXSocketStream
from anyio.streams.memory import MemoryObjectSendStream
from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from . import processes
from .approval import (
    LIFETIME,
    Anchor,
    ApprovalError,
    ExecMode,
    Expired,
    GrantTerms,
    Outcome,
    Peer,
    Requests,
    approvers,
    namespace_of,
    variables,
)
from .grants import MAX_SECONDS, Grants
from .sshsig import BadSignature, SkPublicKey, verify
from .vault import LoginFailed, Vault, open_vault

if TYPE_CHECKING:
    from pathlib import Path

    import httpx2

    from .approval import Request as Pending
    from .config import Config
    from .processes import Process
    from .vault import Device

log = logging.getLogger(__name__)

#: One request is small; a client that sends more is not a client.
MAX_REQUEST = 64 * 1024
#: A connection that says nothing for this long is closed.
IDLE = 10
#: Events a watcher may fall behind by before the broker drops it.
WATCH_BUFFER = 64

PR_SET_DUMPABLE = 4

#: stdin, stdout and stderr, which a broker run receives from its client.
STDIO = 3
#: The signals a client passes on to the command the broker runs for it.
RELAYED = frozenset({signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGWINCH})
#: Variables that load code into the command. The client's environment is its own claim,
#: and these would let it run its code inside the approved command.
LOADER_PREFIXES = ("LD_", "DYLD_")


class Unlock(BaseModel):
    op: Literal["unlock"]
    password: str = Field(repr=False)


class Status(BaseModel):
    op: Literal["status"]


class Lock(BaseModel):
    op: Literal["lock"]


class GrantAsk(BaseModel):
    "The grant a run asks for besides itself. The broker reads the anchor's facts itself."

    seconds: int = Field(gt=0, le=MAX_SECONDS)
    uses: int | None = Field(None, ge=1)
    prefix: int | None = Field(None, ge=1)
    #: A parent of the asking process, by pid.
    anchor: int


class Ask(BaseModel):
    "Asks for a secret. The answer is a challenge to sign, never a value."

    op: Literal["request"]
    secret: str
    argv: list[str] = Field(min_length=1)
    cwd: str
    requester: str | None = None
    exec: ExecMode = ExecMode.BROKER
    env: dict[str, str] = {}
    #: Approved elsewhere, through a linked pymux: a locked broker waits for
    #: an unlock, and the approve waits for a delivered signature (`Signed`).
    elsewhere: bool = False
    grant: GrantAsk | None = None


class Approve(BaseModel):
    op: Literal["approve"]
    id: str
    #: None waits for the signature `Signed` delivers, until the request expires.
    signature: str | None = Field(None, repr=False)
    #: A broker run's base environment, from the client. The fds come with the message.
    environ: dict[str, str] = Field({}, repr=False)


class Signed(BaseModel):
    """
    A signature for a request whose client waits for one, from whoever
    holds the key: the pymux plugin. The broker verifies it on arrival, so
    a bad one never consumes the request.
    """

    op: Literal["signed"]
    id: str
    signature: str = Field(repr=False)


class Relay(BaseModel):
    "Sent during a broker run: a signal for the command."

    signal: int


class ListGrants(BaseModel):
    op: Literal["grants"]


class Revoke(BaseModel):
    op: Literal["revoke"]
    #: None ends every grant.
    id: str | None = None


class Watch(BaseModel):
    """
    Follows the requests: each one waiting when it connects, then each new
    one, and how each ends. A display reads this, so what it shows comes
    from the broker and not from the requester. No value is ever in it.
    """

    op: Literal["watch"]


Request = Annotated[
    Unlock | Status | Lock | Ask | Approve | Signed | ListGrants | Revoke | Watch, Field(discriminator="op")
]
REQUEST: TypeAdapter[Request] = TypeAdapter(Request)


def not_dumpable() -> None:
    """
    Agents run as the same user, and ptrace would read the vault out of
    this process. A process that is not dumpable cannot be attached by
    an unprivileged process of the same user.
    """
    if sys.platform != "linux":
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


class Broker:
    def __init__(self, config: Config, device: Device, transport: httpx2.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self.device = device
        self.transport = transport
        self.vault: Vault | None = None
        self.approvers: tuple[SkPublicKey, ...] = ()
        self.requests = Requests()
        self.grants = Grants()
        self.watchers: set[MemoryObjectSendStream[dict[str, object]]] = set()
        self._unlocking = anyio.Lock()
        #: Set while the vault is open, for an `elsewhere` request that waits for an unlock.
        self._unlocked = anyio.Event()
        #: How many of those wait now: a watcher that connects meanwhile hears `locked` too.
        self._awaiting_unlock = 0
        #: Verified signatures that `Signed` delivered, and the events their approves wait on, by request id.
        self._signatures: dict[str, str] = {}
        self._delivered: dict[str, anyio.Event] = {}

    async def unlock(self, password: str) -> None:
        async with self._unlocking:
            self.vault = await open_vault(
                self.config.endpoints, self.config.email, password, self.device, transport=self.transport
            )
            self.approvers = approvers(self.vault)
        self._unlocked.set()
        log.info("unlocked: %d items, %d approver keys", len(self.vault.items), len(self.approvers))

    def lock(self) -> None:
        for id in list(self.requests.pending):
            self._done(id, Outcome.LOCKED)
        self.vault = None
        self.approvers = ()
        self.requests.clear()
        self.grants.clear()
        self._unlocked = anyio.Event()
        self._signatures.clear()
        # Each approve that waits wakes, and finds its request gone.
        for delivered in self._delivered.values():
            delivered.set()

    def _notify(self, event: dict[str, object]) -> None:
        for watcher in list(self.watchers):
            try:
                watcher.send_nowait(event)
            except (anyio.WouldBlock, anyio.BrokenResourceError, anyio.ClosedResourceError):
                # A watcher that does not keep up misses events it would show late; it goes.
                self.watchers.discard(watcher)
                watcher.close()

    def _done(self, id: str, outcome: Outcome) -> None:
        self._notify({"event": "done", "id": id, "outcome": outcome})

    async def watch(self, stream: anyio.abc.ByteStream) -> None:
        send, receive = anyio.create_memory_object_stream[dict[str, object]](WATCH_BUFFER)
        self.watchers.add(send)
        try:
            if self._awaiting_unlock:
                await _send(stream, {"event": "locked"})
            for pending in list(self.requests.pending.values()):
                await _send(stream, _requested(pending))
            await _send(stream, {"event": "listening"})
            async with receive:
                async for event in receive:
                    await _send(stream, event)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
            pass
        finally:
            self.watchers.discard(send)
            send.close()

    async def ask(self, request: Ask, sender: Process | None = None) -> dict[str, object]:
        if self.vault is None and request.elsewhere:
            # A watcher that holds the sealed password unlocks on this.
            self._notify({"event": "locked"})
            self._awaiting_unlock += 1
            try:
                with anyio.move_on_after(LIFETIME):
                    await self._unlocked.wait()
            finally:
                self._awaiting_unlock -= 1
        if self.vault is None:
            raise ApprovalError("the broker is locked")
        chain = [] if sender is None else processes.ancestry(sender.pid)
        terms = None if request.grant is None else _terms(request.grant, request.argv, chain)
        pending = self.requests.add(
            self.vault,
            request.secret,
            tuple(request.argv),
            request.cwd,
            request.requester,
            request.exec,
            request.env,
            request.elsewhere,
            terms,
        )
        grant = None if terms is not None or not chain else self.grants.find(pending, chain)
        if grant is not None:
            # No event: the plugin would ask for a touch. The watch hears `run` at the approve.
            pending = replace(pending, granted=grant.id, sender=Peer(chain[0].pid, chain[0].start))
            self.requests.pending[pending.id] = pending
            log.info("request %s: %s for %s, under grant %s", pending.id, pending.secret, pending.argv[0], grant.id)
            return {"ok": True, "id": pending.id, "challenge": pending.challenge.decode(), "grant": grant.id}
        log.info("request %s: %s for %s", pending.id, pending.secret, pending.argv[0])
        self._notify(_requested(pending))
        return {"ok": True, "id": pending.id, "challenge": pending.challenge.decode(), "expires": pending.expires}

    def signed(self, request: Signed) -> dict[str, object]:
        pending = self.requests.pending.get(request.id)
        if pending is None or not pending.elsewhere:
            raise ApprovalError("no request %r waits for a delivered signature" % request.id)
        self._verify(pending, request.signature)
        for id in [id for id in self._signatures if id not in self.requests.pending]:
            del self._signatures[id]
        self._signatures[pending.id] = request.signature
        self._delivered.setdefault(pending.id, anyio.Event()).set()
        return {"ok": True}

    async def _delivered_signature(self, id: str) -> str | None:
        "The signature `Signed` delivers for request `id`, or None once the request expires or the broker locks."
        pending = self.requests.pending.get(id)
        if pending is None or not pending.elsewhere:
            raise ApprovalError("no request %r waits for a delivered signature" % id)
        delivered = self._delivered.setdefault(id, anyio.Event())
        try:
            with anyio.move_on_after(pending.deadline - time.monotonic()):
                await delivered.wait()
        finally:
            self._delivered.pop(id, None)
        return self._signatures.pop(id, None)

    async def approve(
        self, request: Approve, lines: Lines, fds: list[int], sender: Process | None = None
    ) -> dict[str, object]:
        waiting = self.requests.pending.get(request.id)
        if waiting is not None and waiting.granted is not None:
            return await self._approve_granted(request, lines, fds, sender)
        signature = request.signature
        if signature is None:
            signature = await self._delivered_signature(request.id)
        try:
            pending = self.requests.take(request.id)
        except Expired:
            self._done(request.id, Outcome.EXPIRED)
            raise
        if signature is None:
            self._done(pending.id, Outcome.EXPIRED)
            raise Expired("no signature arrived for request %r" % pending.id)
        try:
            self._verify(pending, signature)
            values = self._values(pending, fds)
            grant = None if pending.grant is None else self.grants.add(pending)
        except ApprovalError:
            self._done(pending.id, Outcome.REFUSED)
            raise
        if grant is not None:
            log.info(
                "request %s: grant %s holds for %ds under process %d",
                pending.id,
                grant.id,
                grant.deadline - time.monotonic(),
                grant.anchor.pid,
            )
            self._notify({"event": "granted", "id": pending.id, "grant": grant.id})
        self._done(pending.id, Outcome.APPROVED)
        return await self._start(pending, request, values, lines, fds)

    async def _approve_granted(
        self, request: Approve, lines: Lines, fds: list[int], sender: Process | None
    ) -> dict[str, object]:
        "A run under a grant. The process that asked approves it, and the grant must still cover it."
        pending = self.requests.take(request.id)
        try:
            if pending.granted is None or sender is None or Peer(sender.pid, sender.start) != pending.sender:
                raise ApprovalError("only the process that asked may run under its grant")
            grant = self.grants.use(pending.granted, pending, processes.ancestry(sender.pid))
            values = self._values(pending, fds)
        except ApprovalError:
            self._done(pending.id, Outcome.REFUSED)
            raise
        log.info("request %s runs under grant %s", pending.id, grant.id)
        self._notify({"event": "run", "id": pending.id, "grant": grant.id})
        self._done(pending.id, Outcome.APPROVED)
        return await self._start(pending, request, values, lines, fds)

    async def _start(
        self, pending: Pending, request: Approve, values: dict[str, str], lines: Lines, fds: list[int]
    ) -> dict[str, object]:
        match pending.mode:
            case ExecMode.CLIENT:
                return {"ok": True, "env": values}
            case ExecMode.BROKER:
                environment = {
                    name: value for name, value in request.environ.items() if not name.startswith(LOADER_PREFIXES)
                }
                code = await _run(pending.argv, pending.cwd, environment | values, fds, lines)
                log.info("request %s: the command exited %d", pending.id, code)
                return {"ok": True, "exit": code}

    def _verify(self, pending: Pending, signature: str) -> None:
        try:
            verify(signature, pending.challenge, namespace_of(pending.challenge), self.approvers)
        except BadSignature as refused:
            log.warning("request %s refused: %s", pending.id, refused)
            raise ApprovalError("refused: %s" % refused) from None

    def _values(self, pending: Pending, fds: list[int]) -> dict[str, str]:
        "The values for an approved request."
        if self.vault is None:
            raise ApprovalError("the broker is locked")
        if pending.mode is ExecMode.BROKER and len(fds) != STDIO:
            raise ApprovalError("a broker run passes stdin, stdout and stderr with its approve")
        try:
            item = self.vault.find(pending.item_id)
        except KeyError:
            raise ApprovalError("%r left the vault" % pending.secret) from None
        values = {name: value.value for name, value in variables(item, pending.explicit).items()}
        log.info("request %s approved", pending.id)
        return values

    async def answer(
        self, request: Request, lines: Lines, fds: list[int], sender: Process | None = None
    ) -> dict[str, object]:
        match request:
            case Unlock(password=password):
                try:
                    await self.unlock(password)
                except LoginFailed as refused:
                    return {"ok": False, "error": str(refused)}
                return {"ok": True}
            case Status():
                items = None if self.vault is None else len(self.vault.items)
                return {"ok": True, "unlocked": self.vault is not None, "items": items}
            case Lock():
                self.lock()
                return {"ok": True}
            case Ask():
                return await self.ask(request, sender)
            case Approve():
                return await self.approve(request, lines, fds, sender)
            case Signed():
                return self.signed(request)
            case ListGrants():
                return {"ok": True, "grants": self.grants.listed()}
            case Revoke(id=id):
                ended = self.grants.revoke(id)
                for each in ended:
                    self._notify({"event": "revoked", "grant": each})
                return {"ok": True, "revoked": ended}
            case Watch():
                raise ApprovalError("a watch streams, and has no single answer")

    async def serve_one(self, stream: anyio.abc.ByteStream) -> None:
        fds: list[int] = []
        async with stream:
            try:
                with anyio.fail_after(IDLE):
                    first = b""
                    if isinstance(stream, UNIXSocketStream):
                        first, fds = await stream.receive_fds(MAX_REQUEST, STDIO)
                    lines = Lines(stream, first)
                    data = await lines.next()
                request = REQUEST.validate_json(data)
                if isinstance(request, Watch):
                    await self.watch(stream)
                    return
                reply = await self.answer(request, lines, fds, _sender(stream))
            except (TimeoutError, anyio.EndOfStream, anyio.BrokenResourceError):
                return
            except ValidationError as error:
                # The error names fields, never their values: `input` is dropped.
                reply = {"ok": False, "error": "a request this broker does not read: %s" % _fields(error)}
            except (ApprovalError, ValueError) as error:
                reply = {"ok": False, "error": str(error)}
            except Exception:
                # An exception here would end the listener, and every later client with it.
                log.exception("a request failed")
                reply = {"ok": False, "error": "the broker failed; its log says why"}
            finally:
                for fd in fds:
                    os.close(fd)
            with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                await stream.send(json.dumps(reply).encode() + b"\n")

    async def serve(self, path: Path, *, task_status: anyio.abc.TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        path.unlink(missing_ok=True)
        listener = await anyio.create_unix_listener(path)
        os.chmod(path, 0o600)
        async with listener:
            task_status.started()
            await listener.serve(self.serve_one)


def _sender(stream: anyio.abc.ByteStream) -> Process | None:
    raw = stream.extra(SocketAttribute.raw_socket, None)
    return None if raw is None else processes.peer(raw)


def _terms(asked: GrantAsk, argv: list[str], chain: list[Process]) -> GrantTerms:
    "The grant terms, with the anchor's facts read from /proc and checked against the sender's parents."
    if not chain:
        raise ApprovalError("a grant needs the asking process, which the broker reads on Linux only")
    anchor = next((process for process in chain[1:] if process.pid == asked.anchor), None)
    if anchor is None:
        raise ApprovalError("process %d is not a parent of the process that asks" % asked.anchor)
    # A parent of the broker too, such as the user's service manager, would cover every process of the user.
    if processes.among(anchor.pid, anchor.start, processes.ancestry(os.getpid())):
        raise ApprovalError("process %d (%s) is a parent of the broker too" % (anchor.pid, anchor.name))
    if asked.prefix is not None and asked.prefix > len(argv):
        raise ApprovalError("a prefix of %d words is longer than the command" % asked.prefix)
    return GrantTerms(
        seconds=asked.seconds,
        uses=asked.uses,
        prefix=asked.prefix,
        anchor=Anchor(anchor.pid, anchor.start, anchor.name, processes.cwd(anchor.pid)),
    )


def _requested(pending: Pending) -> dict[str, object]:
    return {
        "event": "request",
        "id": pending.id,
        "challenge": pending.challenge.decode(),
        "elsewhere": pending.elsewhere,
    }


async def _send(stream: anyio.abc.ByteStream, message: dict[str, object]) -> None:
    await stream.send(json.dumps(message).encode() + b"\n")


def _fields(error: ValidationError) -> str:
    return ", ".join(".".join(str(part) for part in each["loc"]) or "(the request)" for each in error.errors())


class Lines:
    "Newline-ended messages from a stream. A line over MAX_REQUEST is an error."

    def __init__(self, stream: anyio.abc.ByteReceiveStream, buffered: bytes = b"") -> None:
        self.stream = stream
        self.buffer = buffered

    async def next(self) -> bytes:
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_REQUEST:
                raise ValueError("a request over %d bytes" % MAX_REQUEST)
            self.buffer += await self.stream.receive()
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line


async def _run(argv: tuple[str, ...], cwd: str, environment: dict[str, str], fds: list[int], lines: Lines) -> int:
    """
    Runs the approved command on the client's stdio, and relays the
    client's signals to it. A client that goes away ends the command.
    The child execs, so it shares none of the broker's memory.
    """
    async with await anyio.open_process(
        list(argv), stdin=fds[0], stdout=fds[1], stderr=fds[2], cwd=cwd, env=environment
    ) as process:

        def end() -> None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()

        async def relay() -> None:
            try:
                while True:
                    number = Relay.model_validate_json(await lines.next()).signal
                    if number in RELAYED:
                        with contextlib.suppress(ProcessLookupError):
                            process.send_signal(signal.Signals(number))
            except (anyio.EndOfStream, anyio.BrokenResourceError, ValidationError, ValueError):
                end()

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(relay)
            code = await process.wait()
            tasks.cancel_scope.cancel()
    return code


async def ask(path: Path, request: dict[str, object]) -> dict[str, object]:
    "One request to the broker at `path`, and its answer."
    async with await anyio.connect_unix(path) as stream:
        await stream.send(json.dumps(request).encode() + b"\n")
        return json.loads(await Lines(stream).next())
